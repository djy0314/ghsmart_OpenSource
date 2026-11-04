//go:build windows

package sysproxy

import (
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const regPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// WinINET 选项号。改注册表后必须广播这两项，浏览器/系统设置才会刷新；
// 但光广播还不够——Windows 10/11 的「代理」页面还看 DefaultConnectionSettings
// 这个二进制块，所以真正可靠的做法是直接用 PER_CONNECTION_OPTION 写（见 setPerConn）。
const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
	internetOptionPerConnOption   = 75
)

// INTERNET_PER_CONN_* 选项与标志位（wininet.h）
const (
	perConnFlags       = 1
	perConnProxyServer = 2
	perConnProxyBypass = 3
	proxyTypeDirect    = 0x00000001
	proxyTypeProxy     = 0x00000002
)

// defaultStore 返回真实注册表实现。
// defaultStoreFn 可被测试替换（app 层测 SetDeepAccel 时用内存桩隔离注册表）。
var defaultStoreFn = func() Store { return registryStore{} }

func defaultStore() Store { return defaultStoreFn() }

type registryStore struct{}

// Read 读取当前 Internet Settings 的三个值。
func (registryStore) Read() (Values, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.QUERY_VALUE)
	if err != nil {
		return Values{}, err
	}
	defer k.Close()

	var v Values
	if d, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
		v.Enable = uint32(d)
	}
	if s, _, err := k.GetStringValue("ProxyServer"); err == nil {
		v.Server = s
	}
	if s, _, err := k.GetStringValue("ProxyOverride"); err == nil {
		v.Override = s
		v.HasOverride = true
	}
	return v, nil
}

// Write 写入系统代理并广播刷新，最后回读校验。
// 顺序很关键：先落注册表值（备份/回读的一致性来源），
// 再用 WinINET 的 PER_CONNECTION_OPTION 写一次（它同时更新连接配置二进制块
// 并立即生效），最后广播 SETTINGS_CHANGED + REFRESH。
func (registryStore) Write(v Values) error {
	if err := writeRegistry(v); err != nil {
		return err
	}
	if err := setPerConn(v.Enable == 1, v.Server, v.Override, v.HasOverride); err != nil {
		return fmt.Errorf("应用代理设置失败: %w", err)
	}
	notifyChange()

	// 回读校验：写没写进去必须当场知道，绝不允许「界面显示已开启、系统其实没接管」
	got, err := (registryStore{}).Read()
	if err != nil {
		return fmt.Errorf("代理写入后回读失败: %w", err)
	}
	if v.Enable == 1 {
		if got.Enable != 1 || got.Server != v.Server {
			return fmt.Errorf("系统代理未生效（回读 ProxyEnable=%d ProxyServer=%q，期望 1/%q）",
				got.Enable, got.Server, v.Server)
		}
		// 回读 bypass：GitHub 域名只要还在里面，浏览器就会绕过代理去直连
		// （表现就是 ERR_CONNECTION_CLOSED）。这里必须硬失败，不能假装成功。
		if left := BypassHasGitHub(got.Override); len(left) > 0 {
			return fmt.Errorf("代理例外列表（bypass）未被清理，仍残留 %s —— 浏览器会绕过代理直连，"+
				"请在「Windows 设置 → 网络 → 代理 → 请勿对以下列条目开头的地址使用代理服务器」里手动删掉",
				strings.Join(left, ", "))
		}
	} else if got.Enable != 0 {
		return fmt.Errorf("关闭系统代理未生效（回读 ProxyEnable=%d）", got.Enable)
	}
	return nil
}

// writeRegistry 只落三个注册表值。
func writeRegistry(v Values) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	// 先写地址、最后写开关：某些系统只在 ProxyEnable 变化时才整体刷新
	if v.Server == "" {
		_ = k.DeleteValue("ProxyServer")
	} else if err := k.SetStringValue("ProxyServer", v.Server); err != nil {
		return fmt.Errorf("写 ProxyServer 失败: %w", err)
	}
	// ProxyOverride：接管时写的是「已剔除 GitHub 系域名」的列表；
	// 还原时按备份原样写回（备份里 HasOverride=false 表示原本没这个值 → 删掉，
	// 否则我们写进去的清理结果会残留在用户设置里）。
	if v.HasOverride {
		if err := k.SetStringValue("ProxyOverride", v.Override); err != nil {
			return fmt.Errorf("写 ProxyOverride 失败: %w", err)
		}
	} else {
		_ = k.DeleteValue("ProxyOverride")
	}
	if err := k.SetDWordValue("ProxyEnable", v.Enable); err != nil {
		return fmt.Errorf("写 ProxyEnable 失败: %w", err)
	}
	return k.Close() // 显式关闭以刷盘
}

// internetPerConnOption 对应 C 里的 INTERNET_PER_CONN_OPTIONW：
// DWORD dwOption + union{ DWORD dwValue; LPWSTR pszValue; FILETIME ftValue; }。
// Go 会自动按 uintptr 对齐补 padding，amd64 下 size=16、386 下 size=8，与 C 一致。
type internetPerConnOption struct {
	dwOption uint32
	value    uintptr
}

// internetPerConnOptionList 对应 INTERNET_PER_CONN_OPTION_LISTW。
type internetPerConnOptionList struct {
	dwSize        uint32
	pszConnection uintptr // NULL = LAN 设置
	dwOptionCount uint32
	dwOptionError uint32
	pOptions      uintptr
}

var (
	wininetDLL             = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOptionW = wininetDLL.NewProc("InternetSetOptionW")
)

// setPerConn 用 WinINET 的 PER_CONNECTION_OPTION 直接下发 LAN 代理设置。
// pszConnection 传 NULL 表示「LAN 设置」这一项，正是「设置 → 网络 → 代理」看到的那个开关。
func setPerConn(enable bool, server, override string, hasOverride bool) error {
	opts := make([]internetPerConnOption, 0, 3)
	keep := make([]*uint16, 0, 2)

	flags := uintptr(proxyTypeDirect)
	if enable {
		flags |= proxyTypeProxy
	}
	opts = append(opts, internetPerConnOption{dwOption: perConnFlags, value: flags})

	if enable && server != "" {
		sp, err := windows.UTF16PtrFromString(server)
		if err != nil {
			return err
		}
		keep = append(keep, sp)
		opts = append(opts, internetPerConnOption{dwOption: perConnProxyServer, value: uintptr(unsafe.Pointer(sp))})

		if hasOverride && override != "" {
			bp, err := windows.UTF16PtrFromString(override)
			if err != nil {
				return err
			}
			keep = append(keep, bp)
			opts = append(opts, internetPerConnOption{dwOption: perConnProxyBypass, value: uintptr(unsafe.Pointer(bp))})
		}
	}

	list := internetPerConnOptionList{
		dwSize:        uint32(unsafe.Sizeof(internetPerConnOptionList{})),
		pszConnection: 0,
		dwOptionCount: uint32(len(opts)),
		pOptions:      uintptr(unsafe.Pointer(&opts[0])),
	}
	r, _, callErr := procInternetSetOptionW.Call(
		0,
		uintptr(internetOptionPerConnOption),
		uintptr(unsafe.Pointer(&list)),
		uintptr(unsafe.Sizeof(list)),
	)
	runtime.KeepAlive(opts)
	runtime.KeepAlive(keep)
	if r == 0 {
		return fmt.Errorf("InternetSetOption(PER_CONNECTION_OPTION) 失败: %v", callErr)
	}
	return nil
}

// notifyChange 广播「设置已改」，让运行中的浏览器/系统设置页面立刻感知。
func notifyChange() {
	for _, opt := range []uintptr{internetOptionSettingsChanged, internetOptionRefresh} {
		_, _, _ = procInternetSetOptionW.Call(0, opt, 0, 0)
	}
}
