// Package sysproxy 负责接管 / 还原 Windows 系统代理（HKCU Internet Settings）。
//
// 安全原则：改之前先把「原值」落到磁盘备份文件，还原时按备份写回；
// 进程被强杀来不及还原时，下次启动 Recover() 会按备份自动兜底，
// 绝不让用户出现「关掉软件就上不了网」。
package sysproxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Values 是系统代理相关的三个注册表值。
type Values struct {
	Enable      uint32 `json:"enable"`       // ProxyEnable
	Server      string `json:"server"`       // ProxyServer
	Override    string `json:"override"`     // ProxyOverride
	HasOverride bool   `json:"has_override"` // ProxyOverride 是否存在
}

// Backup 是接管前的原值快照。
type Backup struct {
	Version  int    `json:"version"`
	Original Values `json:"original"`
	Target   string `json:"target"` // 我们写入的代理地址，用于判断当前是否仍归我们管
	At       string `json:"at"`
}

// Store 抽象注册表读写，便于单测用内存实现（绝不碰真实系统代理）。
type Store interface {
	Read() (Values, error)
	Write(Values) error
}

// SetStoreForTest 仅供单元测试替换注册表存储，返回恢复函数。
// 生产代码绝不调用——系统代理的读写只有注册表这一个真实来源。
func SetStoreForTest(st Store) (restore func()) {
	old := defaultStoreFn
	defaultStoreFn = func() Store { return st }
	return func() { defaultStoreFn = old }
}

// BackupPath 返回备份文件路径（默认 ~/.ghsmart/sysproxy.bak.json）。
// 环境变量 GHSMART_SYSPROXY_FILE 可覆盖（单测隔离用）。
func BackupPath() string {
	if p := os.Getenv("GHSMART_SYSPROXY_FILE"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "ghsmart-sysproxy.bak.json")
	}
	return filepath.Join(home, ".ghsmart", "sysproxy.bak.json")
}

// DefaultTarget 是 ghsmart 深度加速的标准监听地址。
const DefaultTarget = "127.0.0.1:18080"

// ApplyResult 描述一次接管实际做了什么（供日志与 UI 回显）。
type ApplyResult struct {
	Target        string   `json:"target"`         // 写入的代理地址
	Bypass        string   `json:"bypass"`         // 实际写入的 ProxyOverride
	RemovedBypass []string `json:"removed_bypass"` // 被剔除的 GitHub 系 bypass 条目
}

// Apply 把系统代理指向 target（例如 127.0.0.1:18080）。
// 首次调用会先备份原值；重复调用不会用「已改过的值」覆盖备份。
//
// 关键：写 ProxyOverride 前必须剔除 GitHub 系域名，否则浏览器命中 bypass
// 直接绕过代理去直连 → ERR_CONNECTION_CLOSED（本次实锤的根因）。
func Apply(target string) (ApplyResult, error) {
	return applyWith(defaultStore(), BackupPath(), target)
}

// Restore 精准还原系统代理，返回是否真的动了注册表：
//   - 当前 ProxyServer 指向我们 → 按备份还原（无备份则关闭代理）
//   - 当前是第三方代理（如 Clash 的 7890）→ **绝对不修改**，只清理陈旧备份
//
// 这是「一键还原网络」与崩溃兜底共用的唯一清理入口。
func Restore(target string) (bool, error) {
	return restoreWith(defaultStore(), BackupPath(), target)
}

// Recover 启动时兜底：等价于精准 Restore，用于上次异常退出后的自愈。
func Recover(target string) (bool, error) {
	return restoreWith(defaultStore(), BackupPath(), target)
}

// IsOn 判断系统代理当前是否指向 target。
func IsOn(target string) bool {
	v, err := defaultStore().Read()
	if err != nil {
		return false
	}
	return ownedBy(v, target)
}

// Disable 无条件关闭系统代理（ProxyEnable=0），不查备份、不看归属。
//
// 仅供「🩺 网络急救」这类用户显式要求恢复直连的场景使用：常规流程请一律用
// Restore（精准还原）或 DisableIfOwned（只关自己的），避免误杀第三方代理。
func Disable() (bool, error) {
	return disableWith(defaultStore())
}

func disableWith(st Store) (bool, error) {
	cur, err := st.Read()
	if err != nil {
		return false, fmt.Errorf("读取系统代理失败: %w", err)
	}
	if cur.Enable != 1 {
		return false, nil // 本来就没开，不写注册表
	}
	if err := st.Write(Values{Enable: 0}); err != nil {
		return false, fmt.Errorf("关闭系统代理失败: %w", err)
	}
	return true, nil
}

// DisableIfOwned 在系统代理仍指向 target 时强制关闭（ProxyEnable=0，不查备份）。
//
// 用于「僵尸代理」清理：进程被强杀后系统代理还指着本机死端口，此时还原备份
// 已无意义（端口都没人监听了），直接关掉代理恢复直连，绝不让用户一开机就断网。
// 只处理「指向我们」的状态，第三方代理（Clash 等）绝不误杀。
func DisableIfOwned(target string) (bool, error) {
	return disableIfOwnedWith(defaultStore(), target)
}

func disableIfOwnedWith(st Store, target string) (bool, error) {
	cur, err := st.Read()
	if err != nil {
		return false, fmt.Errorf("读取系统代理失败: %w", err)
	}
	if !ownedBy(cur, target) {
		return false, nil // 不是我们的状态，不动
	}
	if err := st.Write(Values{Enable: 0}); err != nil {
		return false, fmt.Errorf("关闭系统代理失败: %w", err)
	}
	return true, nil
}

// Current 返回当前系统代理设置（UI 展示用）。
func Current() Values {
	v, err := defaultStore().Read()
	if err != nil {
		return Values{}
	}
	return v
}

// ownedBy 判断当前系统代理是不是我们设的那个（容忍大小写、http:// 前缀、多协议串）。
func ownedBy(v Values, target string) bool {
	if v.Enable != 1 || target == "" {
		return false
	}
	server := strings.ToLower(strings.TrimSpace(v.Server))
	t := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(target, "http://"), "https://"))
	return strings.Contains(server, t)
}

func applyWith(st Store, path, target string) (ApplyResult, error) {
	var res ApplyResult
	cur, err := st.Read()
	if err != nil {
		return res, fmt.Errorf("读取系统代理失败: %w", err)
	}
	// 备份只在「第一次接管」时写，防止二次开启把我们的值当原值存下来。
	// 备份里保存的是**原封不动**的 ProxyOverride，还原时原样写回。
	if readBackup(path) == nil {
		b := Backup{
			Version:  1,
			Original: cur,
			Target:   target,
			At:       time.Now().Format("2006-01-02 15:04:05"),
		}
		if err := writeBackup(path, b); err != nil {
			return res, fmt.Errorf("备份系统代理失败（为避免无法还原，已中止）: %w", err)
		}
	}
	// 清理 bypass 列表里的 GitHub 系域名（保留 <local> 与用户其它自定义项）
	bypass, removed := SanitizeOverride(cur.Override)
	res = ApplyResult{Target: target, Bypass: bypass, RemovedBypass: removed}

	want := Values{Enable: 1, Server: target, Override: bypass, HasOverride: true}
	if cur.Enable == 1 && cur.Server == target && cur.HasOverride && cur.Override == bypass {
		return res, nil // 地址与 bypass 都已是期望值，无需重复写注册表
	}
	if err := st.Write(want); err != nil {
		return res, fmt.Errorf("写入系统代理失败: %w", err)
	}
	return res, nil
}

// restoreWith 是精准还原的核心实现：
// 只有「当前系统代理确实指向我们」时才动手，第三方代理一律跳过。
func restoreWith(st Store, path, target string) (bool, error) {
	cur, err := st.Read()
	if err != nil {
		return false, fmt.Errorf("读取系统代理失败: %w", err)
	}
	b := readBackup(path)

	// 有备份：先确认现在还是我们接管的状态
	if b != nil {
		if !ownedBy(cur, b.Target) {
			// 已被用户/其他代理软件改走 → 绝不覆盖，只清理陈旧备份
			_ = os.Remove(path)
			return false, nil
		}
		if err := st.Write(b.Original); err != nil {
			return false, fmt.Errorf("还原系统代理失败: %w", err)
		}
		_ = os.Remove(path)
		return true, nil
	}

	// 没有备份（备份被删/上次没写成）：只处理「指向我们」的脏状态，直接关掉代理
	if ownedBy(cur, target) {
		if err := st.Write(Values{Enable: 0}); err != nil {
			return false, fmt.Errorf("关闭遗留代理失败: %w", err)
		}
		return true, nil
	}
	return false, nil
}

func recoverWith(st Store, path, target string) (bool, error) {
	return restoreWith(st, path, target)
}

func readBackup(path string) *Backup {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var b Backup
	if err := json.Unmarshal(data, &b); err != nil || b.Version <= 0 {
		return nil
	}
	return &b
}

func writeBackup(path string, b Backup) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
