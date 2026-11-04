//go:build windows

// Package autostart 负责「开机静默自启」。
//
// # 为什么不用注册表 Run 键
//
// ghsmart 的 manifest 是 requireAdministrator（要改 Hosts、要写系统代理），
// 而 Run 键启动的程序会**原样**走 UAC——每次开机都要用户点一次「是」。
// 这和「无感」完全相反。
//
// # 计划任务方案
//
// Windows 任务计划程序支持「以最高权限运行」的任务，登录时触发时
// **不经过 UAC 弹窗**（这是系统的既定行为，任务本身已由管理员创建并授权）。
// 所以：
//
//	创建任务需要管理员 → 我们本来就在管理员进程里，创建时不再额外弹窗
//	之后每次登录 → 静默以管理员启动，窗口直接隐藏到托盘
//
// 计划任务创建失败（组策略禁用、企业管控等）时降级到 Run 键，
// 并如实告诉界面「这个模式开机会弹一次 UAC」，绝不假装成功。
package autostart

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

// TaskName 是计划任务名（固定值，便于幂等覆盖与精确删除）。
const TaskName = "ghsmart-autostart"

// RunValueName 是降级方案里注册表 Run 键的值名。
const RunValueName = "ghsmart"

// Mode 描述当前自启用的是哪种机制。
type Mode string

const (
	// ModeTask 计划任务：免 UAC，静默启动（首选）。
	ModeTask Mode = "task"
	// ModeRun 注册表 Run 键：开机会弹一次 UAC（降级方案）。
	ModeRun Mode = "run"
	// ModeNone 未启用。
	ModeNone Mode = "none"
)

// Status 是自启的当前状态。
type Status struct {
	Enabled  bool `json:"enabled"`
	Mode     Mode `json:"mode"`
	NeedsUAC bool `json:"needsUAC"` // 该机制启动时是否还需要用户点 UAC
	Detail   string `json:"detail"`
}

// silentArg 是静默启动参数：主程序据此 StartHidden 到托盘。
const silentArg = "--silent"

// Enable 开启开机自启，优先计划任务，失败降级 Run 键。
//
// 返回的 Status 是"实际生效的机制"，调用方必须按它渲染界面——
// 降级成 Run 键时要明确告知用户"开机会弹一次 UAC"。
func Enable(exePath string) (Status, error) {
	exePath = strings.TrimSpace(exePath)
	if exePath == "" {
		return Status{Mode: ModeNone}, fmt.Errorf("程序路径为空，无法设置开机自启")
	}
	if _, err := os.Stat(exePath); err != nil {
		return Status{Mode: ModeNone}, fmt.Errorf("程序文件不存在，无法设置开机自启: %w", err)
	}

	// 先清干净两种机制，避免「任务 + Run 键」双份启动
	_ = disableTask()
	_ = disableRun()

	if err := enableTask(exePath); err == nil {
		return Status{Enabled: true, Mode: ModeTask, NeedsUAC: false,
			Detail: "已通过计划任务注册，开机静默以管理员启动，不会弹 UAC"}, nil
	} else {
		taskErr := err
		if rerr := enableRun(exePath); rerr == nil {
			return Status{Enabled: true, Mode: ModeRun, NeedsUAC: true,
				Detail: "计划任务不可用（" + taskErr.Error() + "），已改用注册表启动项：开机时会弹一次 UAC 确认"}, nil
		} else {
			return Status{Mode: ModeNone}, fmt.Errorf("计划任务与注册表启动项均设置失败: %v / %v", taskErr, rerr)
		}
	}
}

// Disable 关闭开机自启（两种机制都清，幂等）。
func Disable() error {
	errTask := disableTask()
	errRun := disableRun()
	if errTask != nil && errRun != nil {
		return fmt.Errorf("关闭开机自启失败: %v / %v", errTask, errRun)
	}
	return nil
}

// Query 查询当前自启状态（以计划任务优先）。
func Query() Status {
	if taskExists() {
		return Status{Enabled: true, Mode: ModeTask, NeedsUAC: false,
			Detail: "计划任务已就绪，开机静默启动"}
	}
	if runExists() {
		return Status{Enabled: true, Mode: ModeRun, NeedsUAC: true,
			Detail: "使用注册表启动项，开机会弹一次 UAC 确认"}
	}
	return Status{Enabled: false, Mode: ModeNone, Detail: "未开启"}
}

// ---------- 计划任务 ----------

// currentUserSID 返回当前用户的 SID（计划任务用 SID 标识用户最稳，
// 不受域名/用户名变更影响）。
func currentUserSID() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(u.Uid, "S-") {
		return u.Uid, nil
	}
	return "", fmt.Errorf("无法获取当前用户 SID")
}

// enableTask 用 schtasks 创建登录触发、最高权限的计划任务。
func enableTask(exePath string) error {
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	xml := taskXML(exePath, sid)
	// schtasks 对 XML 编码挑剔：必须是 Unicode（UTF-16LE + BOM）
	tmp, err := os.CreateTemp("", "ghsmart-task-*.xml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	// UTF-16LE BOM + 内容
	content := []byte{0xFF, 0xFE}
	for _, r := range xml {
		content = append(content, byte(r), byte(r>>8))
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	out, err := runHidden("schtasks.exe", "/Create", "/TN", TaskName,
		"/XML", tmp.Name(), "/F")
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(out))
	}
	if !taskExists() {
		return fmt.Errorf("创建后回读不到计划任务")
	}
	return nil
}

// taskXML 生成计划任务定义。
//
// 关键字段：
//   - LogonTrigger + Delay PT15S：登录后等 15 秒（避开开机登录瞬间的资源争抢）
//   - RunLevel HighestAvailable：以最高权限运行，且**不触发 UAC 提示**
//   - ExecutionTimeLimit PT0S：不限制运行时长（常驻托盘程序）
func taskXML(exePath, sid string) string {
	esc := func(s string) string {
		r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
		return r.Replace(s)
	}
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>ghsmart 开机静默自启（以管理员权限运行，不弹 UAC）</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>` + esc(sid) + `</UserId>
      <Delay>PT15S</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>` + esc(sid) + `</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>` + esc(exePath) + `</Command>
      <Arguments>` + silentArg + `</Arguments>
    </Exec>
  </Actions>
</Task>`
}

// disableTask 删除计划任务（不存在视为成功）。
func disableTask() error {
	if !taskExists() {
		return nil
	}
	out, err := runHidden("schtasks.exe", "/Delete", "/TN", TaskName, "/F")
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// taskExists 查询计划任务是否存在（只看退出码，避开中文输出解析）。
func taskExists() bool {
	_, err := runHidden("schtasks.exe", "/Query", "/TN", TaskName)
	return err == nil
}

// ---------- 注册表 Run 键（降级方案）----------

const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`

// enableRun 写 HKCU Run 键。
func enableRun(exePath string) error {
	k, err := openRunKey()
	if err != nil {
		return err
	}
	defer k.Close()
	// 路径带空格必须加引号，否则 Windows 会把路径截断到第一个空格
	cmdline := `"` + exePath + `" ` + silentArg
	return k.SetStringValue(RunValueName, cmdline)
}

// disableRun 删除 Run 键值（不存在视为成功）。
func disableRun() error {
	k, err := openRunKey()
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.DeleteValue(RunValueName); err != nil {
		if isNotExist(err) {
			return nil // 本来就没有这一项，属正常情形
		}
		return err
	}
	return nil
}

// openRunKey 打开（必要时创建）HKCU 的 Run 键。
func openRunKey() (registry.Key, error) {
	return registry.OpenKey(registry.CURRENT_USER, runKeyPath,
		registry.QUERY_VALUE|registry.SET_VALUE)
}

// isNotExist 判断注册表错误是否为「值/键不存在」。
func isNotExist(err error) bool {
	return errors.Is(err, registry.ErrNotExist) || errors.Is(err, syscall.ERROR_FILE_NOT_FOUND)
}

// runExists 判断 Run 键里是否有我们的项。
func runExists() bool {
	k, err := openRunKey()
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(RunValueName)
	return err == nil
}

// runHidden 执行命令并隐藏控制台窗口（托盘程序里绝不能闪黑框）。
func runHidden(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}
