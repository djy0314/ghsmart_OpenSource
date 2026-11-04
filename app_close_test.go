package main

// 「异步丝滑关闭」回归：点关闭后界面必须立刻有结果，注册表还原在后台完成，
// 完成时发 deep:closed 事件。这套测试把「慢还原」「还原失败」「关了又立刻开」
// 三种最容易翻车的情形全部钉死。

import (
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// closeHarness 隔离授权文件与日志，并替换还原/事件两个注入点。
type closeHarness struct {
	restoreCalls atomic.Int32
	restoreDelay time.Duration
	restoreErr   error

	mu      sync.Mutex
	payload []map[string]any
}

func newCloseHarness(t *testing.T) *closeHarness {
	t.Helper()
	t.Setenv("GHSMART_LICENSE_FILE", filepath.Join(t.TempDir(), "license.json"))
	t.Setenv("GHSMART_LOG_FILE", filepath.Join(t.TempDir(), "ghsmart.log"))

	h := &closeHarness{}

	oldRestore := restoreProxyFn
	restoreProxyFn = func(target string) (bool, error) {
		h.restoreCalls.Add(1)
		if h.restoreDelay > 0 {
			time.Sleep(h.restoreDelay)
		}
		return true, h.restoreErr
	}
	t.Cleanup(func() { restoreProxyFn = oldRestore })

	oldEmit := emitDeepClosedEvent
	emitDeepClosedEvent = func(a *App, payload map[string]any) {
		h.mu.Lock()
		defer h.mu.Unlock()
		cp := make(map[string]any, len(payload))
		for k, v := range payload {
			cp[k] = v
		}
		h.payload = append(h.payload, cp)
	}
	t.Cleanup(func() { emitDeepClosedEvent = oldEmit })

	return h
}

func (h *closeHarness) events() []map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]map[string]any, len(h.payload))
	copy(out, h.payload)
	return out
}

// TestStopDeepReturnsBeforeRestoreFinishes 是本次重构的核心断言：
// 还原还在慢慢做（模拟被 VPN 卡住的注册表写入），stopDeep 必须已经返回。
func TestStopDeepReturnsBeforeRestoreFinishes(t *testing.T) {
	h := newCloseHarness(t)
	h.restoreDelay = 1200 * time.Millisecond // 模拟卡住的 InternetSetOptionW

	a := NewApp()
	t.Cleanup(a.closeLog)
	a.deepOn.Store(true)

	start := time.Now()
	done := a.stopDeep()
	elapsed := time.Since(start)

	if elapsed > 100*time.Millisecond {
		t.Fatalf("stopDeep 同步段耗时 %v，前端会明显卡顿（要求 <100ms）", elapsed)
	}
	if a.deepOn.Load() {
		t.Fatal("stopDeep 返回时 deepOn 必须已经是 false（UI 靠它立刻变灰）")
	}

	// 还原还没做完
	select {
	case <-done:
		t.Fatal("done 提前关闭了，说明 stopDeep 仍在同步等待还原")
	case <-time.After(200 * time.Millisecond):
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("等待还原完成超时")
	}
	if got := h.restoreCalls.Load(); got != 1 {
		t.Fatalf("还原应被调用 1 次，实际 %d 次", got)
	}

	ev := h.events()
	if len(ev) != 1 {
		t.Fatalf("应发 1 个 deep:closed 事件，实际 %d 个", len(ev))
	}
	if ev[0]["ok"] != true || ev[0]["skipped"] != false {
		t.Fatalf("事件内容不对: %+v", ev[0])
	}
	if ms, _ := ev[0]["ms"].(int64); ms < 1000 {
		t.Fatalf("事件里的耗时 %dms 不对（应如实反映慢还原）", ms)
	}
	t.Logf("同步段 %v 返回，还原耗时 %v，事件: %+v", elapsed, ev[0]["ms"], ev[0])
}

// TestStopDeepSkipsStaleRestoreWhenReopened：关闭过程中用户又点开了，
// 那次「迟到的还原」必须作废，否则会把刚接管好的系统代理写回直连。
func TestStopDeepSkipsStaleRestoreWhenReopened(t *testing.T) {
	h := newCloseHarness(t)
	h.restoreDelay = 400 * time.Millisecond

	a := NewApp()
	t.Cleanup(a.closeLog)
	a.deepOn.Store(true)

	// 确定性复现竞态：先占住「写注册表」临界区，让后台还原排队；
	// 期间模拟「用户又点开了」（代际 +1、状态置真），再放锁。
	// 真实场景里这正是 startDeep 的 Apply 与上一轮还原撞车的顺序。
	a.restoreMu.Lock()
	done := a.stopDeep()
	a.deepGen.Add(1)
	a.deepOn.Store(true)
	a.restoreMu.Unlock()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("等待还原流程结束超时")
	}

	if got := h.restoreCalls.Load(); got != 0 {
		t.Fatalf("过期还原不应写注册表，实际调用了 %d 次（会把刚开好的代理写回直连）", got)
	}
	ev := h.events()
	if len(ev) != 1 || ev[0]["skipped"] != true {
		t.Fatalf("应发 skipped=true 的事件，实际 %+v", ev)
	}
}

// TestStopDeepReportsRestoreFailure：还原失败必须带 err 上报，UI 才好明说
// 「网络环境还原失败」。静默吞掉会让用户断网还不知道原因。
func TestStopDeepReportsRestoreFailure(t *testing.T) {
	h := newCloseHarness(t)
	h.restoreErr = errors.New("InternetSetOption 被安全软件拦截")

	a := NewApp()
	t.Cleanup(a.closeLog)
	a.deepOn.Store(true)

	select {
	case <-a.stopDeep():
	case <-time.After(2 * time.Second):
		t.Fatal("等待还原流程结束超时")
	}

	ev := h.events()
	if len(ev) != 1 {
		t.Fatalf("应发 1 个事件，实际 %d 个", len(ev))
	}
	if ev[0]["ok"] != false {
		t.Fatalf("失败时 ok 必须为 false，实际 %+v", ev[0])
	}
	if msg, _ := ev[0]["err"].(string); msg == "" {
		t.Fatalf("失败时必须带 err 文案，实际 %+v", ev[0])
	}
}

// TestStopDeepWaitHonoursTimeout：退出路径用同步版，但绝不能无限等。
func TestStopDeepWaitHonoursTimeout(t *testing.T) {
	h := newCloseHarness(t)
	h.restoreDelay = 3 * time.Second

	a := NewApp()
	t.Cleanup(a.closeLog)
	a.deepOn.Store(true)

	start := time.Now()
	a.stopDeepWait(150 * time.Millisecond)
	elapsed := time.Since(start)

	if elapsed > 600*time.Millisecond {
		t.Fatalf("stopDeepWait 应在超时后放弃等待，实际耗时 %v", elapsed)
	}
	if a.deepOn.Load() {
		t.Fatal("超时也应保证 deepOn 已置 false")
	}
}
