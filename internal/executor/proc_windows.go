//go:build windows

// Windows 专用：隐藏子进程控制台窗口。
// GUI 程序调用 ipconfig / git 等控制台命令时，若不设置 HideWindow，
// 每次调用都会闪出一个黑色 CMD 窗口。

package executor

import (
	"os/exec"
	"syscall"
)

// hideConsole 让被调用的控制台子进程不弹窗口（仅 Windows 有效）。
func hideConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
