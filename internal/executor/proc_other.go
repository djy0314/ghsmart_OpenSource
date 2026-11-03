//go:build !windows

// 非 Windows 平台无需隐藏控制台窗口，空实现保持调用方代码统一。

package executor

import "os/exec"

// hideConsole 非 Windows 平台的空实现。
func hideConsole(_ *exec.Cmd) {}
