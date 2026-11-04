package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMain 把「强制退出」的默认实现换成空操作。
// 否则任何调用 QuitApp 的测试都会在 watchdog 到点时被 os.Exit(0) 打死
// （真实实现是给托盘退出兜底的，测试进程不需要）。
//
// 同时**必须隔离 git 全局配置**：app 层测试会走 startDeep → syncCLIProxy，
// 也就是真的往 git 里写 http.https://github.com.proxy。不隔离的话，
// 每跑一次测试就往开发机的 ~/.gitconfig 里塞一条指向随机端口的代理，
// 跑几次之后 git 就彻底连不上网（这是 v1.0.8 开发中真实踩到的坑）。
func TestMain(m *testing.M) {
	origForce := forceQuit
	forceQuit = func() {}

	dir, err := os.MkdirTemp("", "ghsmart-apptest-")
	if err == nil {
		os.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(dir, "gitconfig"))
		os.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	}

	code := m.Run()
	forceQuit = origForce
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
	os.Exit(code)
}

// TestQuitAppIdempotentAndWatchdog 是号主报障的回归：
// 「托盘点了退出，窗口还在；再点 ✕，托盘里的退出就关不掉了」。
//
// 根因是旧实现先 systray.Quit() 再请求关闭——托盘消息循环一停，
// 一旦进程没立刻结束就再也点不动退出。现在要求：
//  1. QuitApp 只执行一次（重复点击 no-op，不再重复清场/重启 watchdog）
//  2. 退出流程必须带 watchdog 兜底：Wails 没关掉窗口时也要强制结束进程
func TestQuitAppIdempotentAndWatchdog(t *testing.T) {
	oldDelay, oldForce := quitWatchdogDelay, forceQuit
	quitWatchdogDelay = 30 * time.Millisecond
	fired := make(chan struct{}, 8)
	forceQuit = func() { fired <- struct{}{} }
	t.Cleanup(func() { quitWatchdogDelay, forceQuit = oldDelay, oldForce })

	a := NewApp()
	a.ctx = nil // 无 Wails 运行时：QuitApp 跳过 runtime.Quit，专测兜底逻辑
	a.quitting.Store(false)

	a.QuitApp()
	if !a.quitting.Load() {
		t.Fatal("退出后 quitting 必须为 true（否则 ✕ 仍会被拦成隐藏）")
	}

	// 重复点击退出（用户会连点）：必须被 CAS 挡掉，不得再起第二个 watchdog
	a.QuitApp()

	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog 未触发：点了退出却退不掉，正是号主遇到的死局")
	}

	time.Sleep(150 * time.Millisecond)
	select {
	case <-fired:
		t.Fatal("重复点击不应再触发一次强制退出")
	default:
	}
}

// TestAllowCloseOnX 锁定 ✕ 的语义：平时隐藏到托盘，退出流程中必须放行关闭。
// 放行这一步缺了，托盘退出就会卡在 OnBeforeClose，窗口永远关不掉。
func TestAllowCloseOnX(t *testing.T) {
	a := NewApp()
	a.quitting.Store(false)
	if a.allowCloseOnX() {
		t.Fatal("平时点 ✕ 必须只隐藏到托盘，不能直接退出")
	}
	a.quitting.Store(true)
	if !a.allowCloseOnX() {
		t.Fatal("退出流程中必须放行关闭，否则「点了退出退不掉」")
	}
}

// TestQuitAppCleansProxyBeforeExit 确认退出前一定走了清场（还原代理/停自愈），
// 而不是只把进程杀掉——否则用户会断网。
func TestQuitAppCleansProxyBeforeExit(t *testing.T) {
	oldDelay, oldForce := quitWatchdogDelay, forceQuit
	quitWatchdogDelay = 20 * time.Millisecond
	done := make(chan struct{})
	forceQuit = func() { close(done) }
	t.Cleanup(func() { quitWatchdogDelay, forceQuit = oldDelay, oldForce })

	a := NewApp()
	a.ctx = nil
	a.quitting.Store(false)
	a.healOn.Store(true) // 假装自愈还在跑
	a.deepOn.Store(true) // 假装深度加速开着

	a.QuitApp()

	if a.healOn.Load() {
		t.Fatal("退出时自愈循环必须被停掉")
	}
	if a.deepOn.Load() {
		t.Fatal("退出时深度加速必须被关掉（否则系统代理指向死端口，用户断网）")
	}
	// 等 watchdog 跑完，避免它晚到一步撞上 cleanup 后的实现
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("退出兜底未执行")
	}
}
