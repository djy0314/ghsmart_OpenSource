package main

import (
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"ghsmart/internal/config"
	"ghsmart/internal/sysproxy"
)

// ---------- 僵尸代理清理（启动自检） ----------

// stubZombie 替换僵尸清理的系统触点：绝不碰真实注册表。
// isOn：注册表是否指向我们；disable 调用会被记录到 *disabled。
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

// TestCleanZombieProxyForcesDisable：注册表指向我们 + 本程序没监听 →
// 必须强制 ProxyEnable=0（号主「强杀后全系统断网」的核心修复）。
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
func TestCleanZombieProxySkipsWhenServing(t *testing.T) {
	var disabled atomic.Bool
	stubZombie(t, true, nil, &disabled)
	t.Setenv("GHSMART_LICENSE_FILE", filepath.Join(t.TempDir(), "license.json"))

	a := NewApp()
	cfg := a0Config(t)
	if err := a.startDeep(cfg, DeepModeManual, false); err != nil {
		t.Fatalf("启动本地代理失败: %v", err)
	}
	defer a.stopDeep()

	a.cleanZombieProxy(cfg.WebProxy.Listen)
	if disabled.Load() {
		t.Fatal("本程序正在监听时绝不能关闭系统代理")
	}
}

// TestCleanZombieProxyErrorSurfaces：清理失败必须暴露，不能静默吞掉。
func TestCleanZombieProxyErrorSurfaces(t *testing.T) {
	var disabled atomic.Bool
	stubZombie(t, true, os.ErrPermission, &disabled)

	a := NewApp()
	a.cleanZombieProxy(sysproxy.DefaultTarget) // 不 panic、不误报成功即为通过
	if !disabled.Load() {
		t.Fatal("disable 应被调用过")
	}
}

// ---------- 看门狗：代理失效捕捉 ----------

// TestCheckDeepAliveRecoversProxy：deepOn 时代理端口死了 → 看门狗必须
// 用同样模式自动重启成功（不弹「代理已失效」，因为自愈成功了）。
func TestCheckDeepAliveRecoversProxy(t *testing.T) {
	t.Setenv("GHSMART_LICENSE_FILE", filepath.Join(t.TempDir(), "license.json"))

	a := NewApp()
	cfg := a0Config(t)
	if err := a.startDeep(cfg, DeepModeManual, false); err != nil {
		t.Fatalf("启动深度代理失败: %v", err)
	}
	addr := a.deepListenAddr()
	if addr == "" {
		t.Fatal("代理应已监听")
	}
	// 模拟「端口死了」：探活必然失败，且把连败阈值降到 1
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close() // 立刻关掉：这个地址必然连不上
	oldProbe, oldLimit := deepAliveProbe, wdDeadStreakLimit
	deepAliveProbe = func(string, time.Duration) bool { return false }
	wdDeadStreakLimit = 1
	t.Cleanup(func() { deepAliveProbe, wdDeadStreakLimit = oldProbe, oldLimit })

	a.checkDeepAlive()

	if !a.deepOn.Load() {
		t.Fatal("自动恢复成功后 deepOn 必须仍为 true")
	}
	if a.deepListenAddr() == "" {
		t.Fatal("自动恢复后必须有新监听地址")
	}
	a.stopDeep()
	_ = addr
}

// TestCheckDeepAliveDeadEmitsUI：代理死且自动恢复也失败 → 必须广播
// deep:proxydead 事件、置 deepOn=false，绝不静默。
func TestCheckDeepAliveDeadEmitsUI(t *testing.T) {
	t.Setenv("GHSMART_LICENSE_FILE", filepath.Join(t.TempDir(), "license.json"))

	a := NewApp()
	// 手工制造 deepOn=true + 无监听 的僵死态（正常只会由外部强杀/崩溃产生）
	a.stopDeep()
	a.deepOn.Store(true)
	a.deepMu.Lock()
	a.proxy = nil
	a.deepAddr = ""
	a.deepMu.Unlock()

	oldProbe, oldLimit := deepAliveProbe, wdDeadStreakLimit
	deepAliveProbe = func(string, time.Duration) bool { return false }
	wdDeadStreakLimit = 1
	t.Cleanup(func() { deepAliveProbe, wdDeadStreakLimit = oldProbe, oldLimit })

	// 重启也必然失败：把监听地址钉在一个不可绑定端口上
	oldRecoverCfg := deepRecoverCfg
	deepRecoverCfg = func(*App) *config.Config {
		c := a0Config(t)
		c.WebProxy.Listen = "256.256.256.256:18080"
		return c
	}
	t.Cleanup(func() { deepRecoverCfg = oldRecoverCfg })

	var emitted atomic.Bool
	oldEmit := emitProxyDead
	emitProxyDead = func(*App, string, string) { emitted.Store(true) }
	t.Cleanup(func() { emitProxyDead = oldEmit })

	a.checkDeepAlive()

	if !emitted.Load() {
		t.Fatal("自动恢复失败必须广播 deep:proxydead 事件（UI 提示要求）")
	}
	if a.deepOn.Load() {
		t.Fatal("恢复失败后 deepOn 必须为 false（前端据此显示已关闭）")
	}
}

// TestCheckHealStallResetsBusy：自愈 busy 卡住超过阈值 → 必须复位，
// 让下一轮自愈不再被永久跳过。
func TestCheckHealStallResetsBusy(t *testing.T) {
	oldStall := healStallTimeout
	healStallTimeout = 10 * time.Millisecond
	t.Cleanup(func() { healStallTimeout = oldStall })

	a := NewApp()
	a.healOn.Store(true)
	a.busy.Store(true)
	a.healBusySince.Store(time.Now().Add(-time.Hour).Unix())

	a.checkHealStall()

	if a.busy.Load() {
		t.Fatal("卡死的 busy 必须被复位")
	}
	if a.healBusySince.Load() != 0 {
		t.Fatal("复位后繁忙起点应清零")
	}
}

// TestCheckHealStallIgnoresFreshBusy：刚开始的繁忙是正常巡检，绝不能复位。
func TestCheckHealStallIgnoresFreshBusy(t *testing.T) {
	a := NewApp()
	a.healOn.Store(true)
	a.busy.Store(true)
	a.healBusySince.Store(time.Now().Unix())

	a.checkHealStall()

	if !a.busy.Load() {
		t.Fatal("正常巡检中绝不能被复位")
	}
}

// TestOnWakeDropsConnsAndCache：唤醒处理必须清 IP 缓存 + 断开在途连接。
func TestOnWakeDropsConnsAndCache(t *testing.T) {
	t.Setenv("GHSMART_LICENSE_FILE", filepath.Join(t.TempDir(), "license.json"))

	a := NewApp()
	a.ipMu.Lock()
	a.ipCache = make(map[string]ipEntry)
	a.ipCache["github.com"] = ipEntry{ips: []string{"20.205.243.166"}, at: time.Now()}
	a.ipMu.Unlock()

	cfg := a0Config(t)
	if err := a.startDeep(cfg, DeepModeManual, false); err != nil {
		t.Fatalf("启动深度代理失败: %v", err)
	}
	defer a.stopDeep()

	a.onWake(2 * time.Hour)

	a.ipMu.Lock()
	n := len(a.ipCache)
	a.ipMu.Unlock()
	if n != 0 {
		t.Fatalf("唤醒后 IP 缓存必须清空，还剩 %d 条", n)
	}
	if !a.deepOn.Load() || a.deepListenAddr() == "" {
		t.Fatal("唤醒复核不应误杀健康的代理")
	}
}

// TestStartWatchdogStops：看门狗必须能被 stop 干净地停掉（不泄漏 goroutine 死循环）。
func TestStartWatchdogStops(t *testing.T) {
	oldInterval := wdInterval
	wdInterval = 10 * time.Millisecond
	t.Cleanup(func() { wdInterval = oldInterval })

	a := NewApp()
	a.startWatchdog()
	a.stopWatchdog()
	a.stopWatchdog() // 幂等
}
