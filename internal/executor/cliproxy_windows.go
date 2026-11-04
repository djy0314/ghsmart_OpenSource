//go:build windows

// 命令行工具代理接管：让 git / gh / curl 这些**不读 Windows 系统代理**的
// 工具也能吃到本地加速代理。
//
// # 为什么必须绕这么一圈
//
// Windows 的「系统代理」写在 WinINET 注册表里，只有浏览器、Electron 应用
// 这类走 WinHTTP/WinINET 的客户端会读它。git-for-windows 的 libcurl、
// gh（Go 的 net/http）、curl.exe 都不读注册表，只认：
//
//	git  : http.proxy / http.<url>.proxy 配置，或 http_proxy 环境变量
//	gh   : HTTPS_PROXY / HTTP_PROXY 环境变量
//	curl : 同上
//
// 所以只设系统代理时，用户会发现「浏览器快了、终端没变」。
//
// # 两个关键的安全约束（v1.0.8）
//
//  1. git 绝不用裸 http.proxy。裸键会把**所有**仓库（含公司内网 GitLab、
//     私有 registry）的流量都推给本地代理，代理一挂用户所有 git 操作全断。
//     这里用 git 的按 URL 限定写法 http.https://github.com.proxy，
//     只有 github.com 的请求经过我们，其他仓库一个字节都不碰。
//
//  2. 环境变量只在「用户原本没有代理设置」时才写。用户机器上很可能
//     已经有 Clash/v2ray 设的 HTTP_PROXY，覆盖它等于把人家的代理搞坏。
//     检测到非我们写的值就整体跳过，并如实回报给界面。
package executor

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

// ApplyCLIProxy 让 git / gh / curl 走本地代理。
//
// addr 形如 "127.0.0.1:18080"；withEnv 决定是否同时写用户级环境变量
// （影响 gh、curl 等所有进程，属于重手段，必须由用户显式开启）。
func ApplyCLIProxy(addr string, withEnv bool) (CLIProxyResult, error) {
	res := CLIProxyResult{}
	proxyURL := toProxyURL(addr)
	if proxyURL == "" {
		return res, fmt.Errorf("代理地址为空，无法接管命令行流量")
	}

	// ---- 1) git：按 URL 限定的代理（只影响 github.com）----
	if _, err := exec.LookPath("git"); err != nil {
		res.Detail = "未检测到 git，已跳过 git 代理设置"
	} else {
		// 先清一次同键旧值，避免上次写入的端口残留（幂等）
		_, _ = runGit("config", "--global", "--unset-all", "--fixed-value", gitProxyKey, envProxyValue)
		if out, err := runGit("config", "--global", "--add", gitProxyKey, proxyURL); err != nil {
			res.Detail = "git 代理写入失败: " + strings.TrimSpace(out)
		} else {
			res.GitApplied = true
		}
	}

	// ---- 2) 用户级环境变量：gh / curl 等（可选，风险更高）----
	if withEnv {
		applied, skipped, err := applyUserEnvProxy(proxyURL)
		if err != nil {
			// 环境变量失败不推翻 git 部分，把原因回报给界面
			res.Detail = strings.TrimSpace(res.Detail + " " + err.Error())
		}
		res.EnvApplied = applied
		if skipped != "" {
			res.Skipped = skipped
		}
	}
	return res, nil
}

// RemoveCLIProxy 精确撤销命令行代理：只删「值等于我们写的值」的条目。
//
// 用户在软件运行期间自己改过代理设置（值变了）时一律不动——
// 绝不能把用户新配的代理删掉。
func RemoveCLIProxy() error {
	if _, err := exec.LookPath("git"); err == nil {
		_, _ = runGit("config", "--global", "--unset-all", "--fixed-value", gitProxyKey, envProxyValue)
	}
	removeUserEnvProxy()
	return nil
}

// ---------- 用户级环境变量（HKCU\Environment）----------

const envKeyPath = `Environment`

// envStore 抽象「用户级环境变量」的读写。
//
// 抽出来的唯一目的是让单测能注入内存实现：这些函数直接写
// HKCU\Environment，测试一旦碰真实注册表就会污染开发机。
type envStore interface {
	Get(name string) (string, bool)
	Set(name, value string) error
	Del(name string) error
}

// envStoreFn 是 envStore 的提供者（测试替换）。
var envStoreFn = func() (envStore, error) { return registryEnvStore{}, nil }

// registryEnvStore 是真实实现（HKCU\Environment）。
type registryEnvStore struct{}

func openEnvKey() (registry.Key, error) {
	return registry.OpenKey(registry.CURRENT_USER, envKeyPath, registry.QUERY_VALUE|registry.SET_VALUE)
}

func (registryEnvStore) Get(name string) (string, bool) {
	k, err := openEnvKey()
	if err != nil {
		return "", false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return "", false
	}
	return v, true
}

func (registryEnvStore) Set(name, value string) error {
	k, err := openEnvKey()
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(name, value)
}

func (registryEnvStore) Del(name string) error {
	k, err := openEnvKey()
	if err != nil {
		return err
	}
	defer k.Close()
	return k.DeleteValue(name)
}

// applyUserEnvProxy 写入 HTTP_PROXY / HTTPS_PROXY / NO_PROXY。
//
// 保护逻辑：目标变量已存在且值不是我们写的 → 整体跳过，一个都不改。
// 返回值 applied=是否写入，skipped=跳过原因。
func applyUserEnvProxy(proxyURL string) (bool, string, error) {
	st, err := envStoreFn()
	if err != nil {
		return false, "", fmt.Errorf("打开用户环境变量注册表失败: %w", err)
	}

	// 先体检：任何一个已有非我方值时，整体放弃（不写一半）
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY"} {
		if v, ok := st.Get(name); ok {
			if !strings.EqualFold(strings.TrimSpace(v), proxyURL) {
				return false, "检测到您已有 " + name + " 代理设置（可能是其他代理软件），已跳过环境变量接管，原有配置一个字都没动", nil
			}
		}
	}

	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY"} {
		if err := st.Set(name, proxyURL); err != nil {
			return false, "", fmt.Errorf("写入 %s 失败: %w", name, err)
		}
	}
	// NO_PROXY 只在用户没配过时补上，绝不覆盖别人的直连白名单
	if v, ok := st.Get("NO_PROXY"); !ok || strings.TrimSpace(v) == "" {
		if err := st.Set("NO_PROXY", envNoProxyValue); err != nil {
			return false, "", fmt.Errorf("写入 NO_PROXY 失败: %w", err)
		}
	}
	broadcastEnv()
	return true, "", nil
}

// removeUserEnvProxy 撤销环境变量：只删值仍等于我方值的项。
func removeUserEnvProxy() {
	st, err := envStoreFn()
	if err != nil {
		return
	}
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY"} {
		if v, ok := st.Get(name); ok && strings.EqualFold(strings.TrimSpace(v), envProxyValue) {
			_ = st.Del(name)
		}
	}
	if v, ok := st.Get("NO_PROXY"); ok && strings.TrimSpace(v) == envNoProxyValue {
		_ = st.Del("NO_PROXY")
	}
	broadcastEnv()
}

// broadcastEnv 是广播的注入点（单测替换成空实现，避免在测试里给系统发消息）。
var broadcastEnv = broadcastEnvChange

// broadcastEnvChange 通知系统「环境变量变了」，让之后新开的进程能读到。
// 已在运行的程序（含当前终端）不会更新，这是 Windows 的既定行为。
func broadcastEnvChange() {
	const (
		hwndBroadcast   = 0xffff
		wmSettingChange = 0x001A
		smtoAbortIfHung = 0x0002
	)
	user32 := syscall.NewLazyDLL("user32.dll")
	proc := user32.NewProc("SendMessageTimeoutW")
	name, err := syscall.UTF16PtrFromString("Environment")
	if err != nil {
		return
	}
	var out uintptr
	_, _, _ = proc.Call(hwndBroadcast, wmSettingChange, 0, uintptr(unsafe.Pointer(name)),
		smtoAbortIfHung, 1000, uintptr(unsafe.Pointer(&out)))
}
