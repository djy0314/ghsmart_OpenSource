package main

// 僵尸代理清理（启动自检）测试。
// 与看门狗无关：这是「下次启动兜底」，和守卫进程（强杀即时还原）互补。

import (
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"

	"ghsmart/internal/sysproxy"
)

// stubZombie 替换僵尸清理的系统触点：绝不碰真实注册表。
func stubZombie(t *testing.T, isOn bool, disableErr error, disabled *atomic.Bool) {
	t.Helper()
	oldIsOn, oldDisable := zombieIsOn, zombieDisable
	zombieIsOn = func(string) bool { return isOn }
	zombieDisable = func(string) (bool, error) {
		if disabled != nil {
			disabled.Store(true)
		}
		return true, disableErr
	}
	t.Cleanup(func() { zombieIsOn, zombieDisable = oldIsOn, oldDisable })
}

// memValues 是注册表的内存桩（Read/Write 实现见 sysproxy.Store 接口）。
type memValues struct{ v sysproxy.Values }

func (m *memValues) Read() (sysproxy.Values, error) { return m.v, nil }
func (m *memValues) Write(v sysproxy.Values) error  { m.v = v; return nil }

// TestCleanZombieProxyForcesDisable：注册表指向我们 + 本程序没监听 →
// 必须强制 ProxyEnable=0（「强杀后全系统断网」的启动兜底）。
func TestCleanZombieProxyForcesDisable(t *testing.T) {
	var disabled atomic.Bool
	stubZombie(t, true, nil, &disabled)

	a := NewApp() // 没启动深度代理，端口必然无人监听
	a.cleanZombieProxy(sysproxy.DefaultTarget)

	if !disabled.Load() {
		t.Fatal("僵尸代理（指向我们但无人监听）必须被强制关闭")
	}
}

// TestCleanZombieProxySkipsThirdParty：系统代理指向第三方（Clash 等）→ 绝不动。
func TestCleanZombieProxySkipsThirdParty(t *testing.T) {
	var disabled atomic.Bool
	stubZombie(t, false, nil, &disabled)

	a := NewApp()
	a.cleanZombieProxy(sysproxy.DefaultTarget)

	if disabled.Load() {
		t.Fatal("第三方代理绝不能被误杀")
	}
}

// TestCleanZombieProxySkipsWhenServing：我们自己正在监听 → 不误杀自己的代理。
// 注册表用内存桩隔离，绝不写真机。
func TestCleanZombieProxySkipsWhenServing(t *testing.T) {
	var disabled atomic.Bool
	stubZombie(t, true, nil, &disabled)
	t.Setenv("GHSMART_LICENSE_FILE", filepath.Join(t.TempDir(), "license.json"))
	t.Setenv("GHSMART_SYSPROXY_FILE", filepath.Join(t.TempDir(), "sysproxy.bak.json"))
	restore := sysproxy.SetStoreForTest(&memValues{})
	defer restore()

	a := NewApp()
	cfg := a0Config(t)
	if err := a.startDeep(cfg); err != nil {
		t.Fatalf("启动本地代理失败: %v", err)
	}
	defer a.stopDeep()

	a.cleanZombieProxy(cfg.WebProxy.Listen)
	if disabled.Load() {
		t.Fatal("本程序正在监听时绝不能关闭系统代理")
	}
}

// TestCleanZombieProxyErrorSurfaces：清理失败必须让用户看见，不能静默吞掉。
func TestCleanZombieProxyErrorSurfaces(t *testing.T) {
	var disabled atomic.Bool
	stubZombie(t, true, errors.New("拒绝访问"), &disabled)

	a := NewApp()
	a.cleanZombieProxy(sysproxy.DefaultTarget)
	if !disabled.Load() {
		t.Fatal("失败路径也应先尝试关闭")
	}
}
