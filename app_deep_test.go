package main

// 深度加速「极简交互」的后端回归：点开关 = 直接开，无预检、无模式、无兼容。
// 注册表与守卫进程全部打桩，绝不写真机。

import (
	"path/filepath"
	"sync/atomic"
	"testing"

	"ghsmart/internal/jobobj"
	"ghsmart/internal/proxyguard"
	"ghsmart/internal/sysproxy"
)

// spyStore 记录每次写入，用于断言「开了之后注册表指向我们 / 关了之后还原」。
type spyStore struct {
	v      sysproxy.Values
	writes atomic.Int32
}

func (m *spyStore) Read() (sysproxy.Values, error) { return m.v, nil }
func (m *spyStore) Write(v sysproxy.Values) error  { m.v = v; m.writes.Add(1); return nil }

// stubGuardAndStore 隔离注册表与守卫派生；返回守卫派生计数。
func stubGuardAndStore(t *testing.T) *atomic.Int32 {
	t.Helper()
	t.Setenv("GHSMART_LICENSE_FILE", filepath.Join(t.TempDir(), "license.json"))
	t.Setenv("GHSMART_SYSPROXY_FILE", filepath.Join(t.TempDir(), "sysproxy.bak.json"))
	spawned := &atomic.Int32{}
	oldSpawn := guardSpawn
	guardSpawn = func(_ *jobobj.Job, _ string) (*proxyguard.Guard, error) {
		spawned.Add(1)
		return nil, nil
	}
	t.Cleanup(func() { guardSpawn = oldSpawn })
	return spawned
}

// TestSetDeepAccelOpensDirectly：点开关 = 直接开启。
// 不做任何预检：哪怕网络全断，开启动作本身也必须成功（连不上是代理层的事）。
func TestSetDeepAccelOpensDirectly(t *testing.T) {
	spawned := stubGuardAndStore(t)
	st := &spyStore{}
	restore := sysproxy.SetStoreForTest(st)
	defer restore()

	a := NewApp()
	a.pro.Store(true)
	res, err := a.SetDeepAccel(true)
	if err != nil {
		t.Fatalf("直接开启必须成功（预检已废除）: %v", err)
	}
	if res["deepAccel"] != true {
		t.Fatalf("开启后状态应为 true，实际 %v", res["deepAccel"])
	}
	if st.v.Enable != 1 {
		t.Fatalf("开启后应接管系统代理，实际 %+v", st.v)
	}
	if a.deepListenAddr() == "" {
		t.Fatal("开启后应有本地监听端口")
	}
	if spawned.Load() != 1 {
		t.Fatalf("开启深度加速时应派生恰好 1 个守卫进程，实际 %d", spawned.Load())
	}
	a.stopDeep()
}

// TestSetDeepAccelOffRestores：关闭 = 精准还原系统代理 + 关端口。
func TestSetDeepAccelOffRestores(t *testing.T) {
	stubGuardAndStore(t)
	st := &spyStore{v: sysproxy.Values{Enable: 1, Server: "127.0.0.1:7890", Override: "*.cn", HasOverride: true}}
	restore := sysproxy.SetStoreForTest(st)
	defer restore()

	a := NewApp()
	a.pro.Store(true)
	if _, err := a.SetDeepAccel(true); err != nil {
		t.Fatalf("开启失败: %v", err)
	}
	if _, err := a.SetDeepAccel(false); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}
	if a.deepOn.Load() {
		t.Fatal("关闭后 deepOn 必须为 false")
	}
	if st.v.Enable != 1 || st.v.Server != "127.0.0.1:7890" {
		t.Fatalf("关闭后必须还原到用户原值（Clash 7890），实际 %+v", st.v)
	}
	if a.deepListenAddr() != "" {
		t.Fatal("关闭后不应保留监听端口")
	}
}

// TestDeepDegradeMarksState：代理层降级回调 → 状态置位 + proState 可见。
func TestDeepDegradeMarksState(t *testing.T) {
	a := NewApp()
	a.deepOn.Store(true)
	a.onDeepDegrade("TLS 握手被重置") // ctx 为 nil：不 emit，只改状态

	res := a.proState()
	if res["deepDegraded"] != true {
		t.Fatalf("降级后 deepDegraded 必须为 true，实际 %v", res["deepDegraded"])
	}
	if !a.proxyDegraded() {
		t.Fatal("proxyDegraded 应与 deepDegraded 一致")
	}
	// 关闭后状态必须复位
	a.stopDeep()
	if a.proState()["deepDegraded"] != false {
		t.Fatal("关闭深度加速后降级状态必须复位")
	}
}

// proxyDegraded 是给测试用的状态读取口（与 proState 的 deepDegraded 同源）。
func (a *App) proxyDegraded() bool {
	a.deepMu.Lock()
	defer a.deepMu.Unlock()
	return a.deepDegraded
}
