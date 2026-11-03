package main

import (
	"testing"
	"time"

	"ghsmart/internal/cache"
)

// withTempProbeReport 把探测报告隔离到临时目录并写入指定内容。
func withTempProbeReport(t *testing.T, report map[string][]cache.ProbeRecord, savedAt time.Time) {
	t.Helper()
	t.Setenv("GHSMART_PROBE_FILE", t.TempDir()+"/lastprobe.json")
	if report != nil {
		// 直接落盘（SaveProbeReport 会用当前时间，这里手工构造以控制 savedAt）
		if err := cache.SaveProbeReport(report); err != nil {
			t.Fatalf("写入探测报告失败: %v", err)
		}
	}
}

// TestDeepPrecheckNoReport：没有探测报告时绝不拦截（缺证据不误杀）。
func TestDeepPrecheckNoReport(t *testing.T) {
	withTempProbeReport(t, nil, time.Time{})
	a := NewApp()
	ok, reason, checked := a.deepPrecheck("github.com", time.Now())
	if !ok || reason != "" || checked != 0 {
		t.Fatalf("无报告应放行: ok=%v reason=%q checked=%d", ok, reason, checked)
	}
}

// TestDeepPrecheckAllUnreachable：主域名全部候选不可达且证据新鲜 → 拦截。
func TestDeepPrecheckAllUnreachable(t *testing.T) {
	withTempProbeReport(t, map[string][]cache.ProbeRecord{
		"github.com": {
			{IP: "20.205.243.166", OK: false, Err: "TCP 失败: i/o timeout"},
			{IP: "140.82.112.3", OK: false, Err: "TCP 失败: i/o timeout"},
		},
	}, time.Time{})
	a := NewApp()
	ok, reason, checked := a.deepPrecheck("github.com", time.Now())
	if ok {
		t.Fatal("全部候选不可达时应拦截")
	}
	if reason == "" {
		t.Fatal("拦截时必须带提示文案")
	}
	if checked != 2 {
		t.Fatalf("checked 应为 2，实际 %d", checked)
	}
}

// TestDeepPrecheckOneAlive：只要有任一候选可用就放行。
func TestDeepPrecheckOneAlive(t *testing.T) {
	withTempProbeReport(t, map[string][]cache.ProbeRecord{
		"github.com": {
			{IP: "20.205.243.166", OK: false, Err: "timeout"},
			{IP: "140.82.112.3", OK: true},
		},
	}, time.Time{})
	a := NewApp()
	if ok, _, _ := a.deepPrecheck("github.com", time.Now()); !ok {
		t.Fatal("有可用候选时应放行")
	}
}

// TestDeepPrecheckStaleEvidence：证据过期（超过 6 小时）不拦截。
func TestDeepPrecheckStaleEvidence(t *testing.T) {
	report := map[string][]cache.ProbeRecord{
		"github.com": {{IP: "20.205.243.166", OK: false, Err: "timeout"}},
	}
	withTempProbeReport(t, report, time.Time{})
	a := NewApp()
	stale := time.Now().Add(deepPrecheckFreshWindow + time.Minute)
	if ok, _, _ := a.deepPrecheck("github.com", stale); !ok {
		t.Fatal("证据过期时应放行")
	}
}

// TestDeepPrecheckOtherDomain：报告里只有其他域名时不拦截主域名判断。
func TestDeepPrecheckOtherDomain(t *testing.T) {
	withTempProbeReport(t, map[string][]cache.ProbeRecord{
		"raw.githubusercontent.com": {{IP: "10.0.0.1", OK: false, Err: "timeout"}},
	}, time.Time{})
	a := NewApp()
	if ok, _, _ := a.deepPrecheck("github.com", time.Now()); !ok {
		t.Fatal("主域名无记录时应放行")
	}
}

// TestSetDeepAccelPrecheckGate：预检拦截时 SetDeepAccel 必须报错且不开启。
func TestSetDeepAccelPrecheckGate(t *testing.T) {
	withTempProbeReport(t, map[string][]cache.ProbeRecord{
		"github.com": {{IP: "20.205.243.166", OK: false, Err: "TCP 失败: i/o timeout"}},
	}, time.Time{})
	a := NewApp()
	a.pro.Store(true) // 绕过 Pro 闸，专测预检闸
	_, err := a.SetDeepAccel(true, DeepModeAuto, false)
	if err == nil {
		t.Fatal("预检拦截时应返回错误")
	}
	if a.GetProState()["deepAccel"].(bool) {
		t.Fatal("被拦截后深度加速不应开启")
	}
	if a.GetProState()["deepListen"].(string) != "" {
		t.Fatal("被拦截后不应有监听端口")
	}
}
