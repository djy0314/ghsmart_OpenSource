// Package executor 内的 DNS 缓存刷新：按操作系统调用系统命令。
package executor

import (
	"os/exec"
	"runtime"
)

// FlushDNS 刷新系统 DNS 缓存。
// Windows: ipconfig /flushdns；
// macOS: dscacheutil -flushcache，再尝试 killall -HUP mDNSResponder（需要权限）；
// Linux: 尝试 resolvectl flush-caches，失败则忽略（许多发行版无此服务）。
// 所有子进程都隐藏控制台窗口，避免 GUI 下黑框闪现。
func FlushDNS() error {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("ipconfig", "/flushdns")
		hideConsole(cmd)
		if out, err := cmd.CombinedOutput(); err != nil {
			return wrapOut(out, err)
		}
	case "darwin":
		cmd := exec.Command("dscacheutil", "-flushcache")
		hideConsole(cmd)
		if out, err := cmd.CombinedOutput(); err != nil {
			return wrapOut(out, err)
		}
		// 刷新 mDNSResponder 需要权限，失败时仅返回提示
		cmd = exec.Command("sudo", "killall", "-HUP", "mDNSResponder")
		hideConsole(cmd)
		if out, err := cmd.CombinedOutput(); err != nil {
			return wrapOut(out, err)
		}
	case "linux":
		cmd := exec.Command("resolvectl", "flush-caches")
		hideConsole(cmd)
		if out, err := cmd.CombinedOutput(); err != nil {
			return wrapOut(out, err)
		}
	}
	return nil
}

// wrapOut 把命令输出与错误合并成带超时提示的错误信息。
func wrapOut(out []byte, err error) error {
	if len(out) == 0 {
		return err
	}
	return &combinedError{out: string(out), err: err}
}

type combinedError struct {
	out string
	err error
}

func (e *combinedError) Error() string {
	return e.err.Error() + ": " + e.out
}
