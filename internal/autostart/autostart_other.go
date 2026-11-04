//go:build !windows

// Package autostart 负责「开机静默自启」。
// 非 Windows 平台不提供该能力，保持接口一致以便跨平台编译。
package autostart

// Mode 描述当前自启用的是哪种机制。
type Mode string

const (
	// ModeTask 计划任务（本平台不支持）。
	ModeTask Mode = "task"
	// ModeRun 注册表 Run 键（本平台不支持）。
	ModeRun Mode = "run"
	// ModeNone 未启用。
	ModeNone Mode = "none"
)

// Status 是自启的当前状态。
type Status struct {
	Enabled  bool   `json:"enabled"`
	Mode     Mode   `json:"mode"`
	NeedsUAC bool   `json:"needsUAC"`
	Detail   string `json:"detail"`
}

// Enable 本平台不支持开机自启。
func Enable(string) (Status, error) {
	return Status{Mode: ModeNone}, nil
}

// Disable 本平台无需清理。
func Disable() error { return nil }

// Query 本平台恒为未启用。
func Query() Status { return Status{Mode: ModeNone, Detail: "本平台不支持"} }
