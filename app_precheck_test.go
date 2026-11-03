package main

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"ghsmart/internal/cache"
	"ghsmart/internal/config"
	"ghsmart/internal/probe"
)

// withTempProbeReport 把探测报告与优选缓存隔离到临时目录，
// 并按需写入一份「上一轮全失败」的历史报告。
func withTempProbeReport(t *testing.T, report map[string][]cache.ProbeRecord) {
	t.Helper()
	t.Setenv("GHSMART_PROBE_FILE", t.TempDir()+"/lastprobe.json")
	t.Setenv("GHSMART_CACHE_FILE", t.TempDir()+"/cache.json")
	if report != nil {
		if err := cache.SaveProbeReport(report); err != nil {
			t.Fatalf("写入探测报告失败: %v", err)
		}
	}
}

// a0Config 返回默认配置（用于直连兜底测试，不依赖外部文件）。
func a0Config(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("加载默认配置失败: %v", err)
	}
	return cfg
}

// staleFailureReport 模拟号主遇到的情形：VPN 期间探测全失败的历史报告。
func staleFailureReport() map[string][]cache.ProbeRecord {
	return map[string][]cache.ProbeRecord{
		"github.com": {
			{IP: "20.205.243.166", OK: false, Err: "TCP 失败: dial tcp 20.205.243.166:443: i/o timeout"},
			{IP: "140.82.112.3", OK: false, Err: "TCP 失败: i/o timeout"},
		},
	}
}

// stubProbe 替换实时微测实现，返回统一结果（不回真实网络）。
func stubProbe(t *testing.T, ok bool) {
	t.Helper()
	oldProbe, oldDirect := deepProbeFn, directTLSCheck
	deepProbeFn = func(_ context.Context, ips []string, domain string, _ time.Duration) []probe.ProbeResult {
		res := make([]probe.ProbeResult, len(ips))
		for i, ip := range ips {
			if ok {
				res[i] = probe.ProbeResult{IP: ip, OK: true}
			} else {
				res[i] = probe.ProbeResult{IP: ip, OK: false, Err: "TCP 失败: dial tcp " + ip + ":443: i/o timeout"}
			}
		}
		return res
	}
	directTLSCheck = func(string, time.Duration) (bool, error) {
		if ok {
			return true, nil
		}
		return false, &net.OpError{Op: "dial", Err: errors.New("i/o timeout")}
	}
	t.Cleanup(func() { deepProbeFn, directTLSCheck = oldProbe, oldDirect })
}

// TestLiveCheckPassesDespiteStaleFailureReport：核心回归——旧报告全失败，
// 但此刻实时微测成功（VPN 已关），必须放行，且旧报告要被清掉。
func TestLiveCheckPassesDespiteStaleFailureReport(t *testing.T) {
	withTempProbeReport(t, staleFailureReport())
	stubProbe(t, true)

	a := NewApp()
	ok, reason, _, _ := a.deepPrecheckLive("github.com")
	if !ok {
		t.Fatalf("实时微测成功必须放行，实际被拦截: reason=%q", reason)
	}
	if reason != "" {
		t.Fatalf("放行时不应带拦截文案: %q", reason)
	}
	// checked 可能为 0：候选 IP 全空时走了系统 DNS 直连 TLS 兜底
	p, err := cache.ProbePath()
	if err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
		t.Fatalf("放行后旧探测报告必须被清空，实际仍存在（statErr=%v）", statErr)
	}
}

// TestLiveCheckBlocksWhenReallyOffline：实时微测全失败才拦截，文案必须与定稿一致。
func TestLiveCheckBlocksWhenReallyOffline(t *testing.T) {
	withTempProbeReport(t, staleFailureReport())
	stubProbe(t, false)

	a := NewApp()
	ok, reason, _, _ := a.deepPrecheckLive("github.com")
	if ok {
		t.Fatal("实时微测全失败应拦截")
	}
	if reason != deepRestrictedMsg {
		t.Fatalf("拦截文案不符：\n  want %q\n  got  %q", deepRestrictedMsg, reason)
	}
	want := "当前网络环境依然受限，请确保已彻底关闭公司 VPN 后重试。若仍不行，请仅使用「一键智能加速」。"
	if deepRestrictedMsg != want {
		t.Fatalf("定稿文案被改动：%q", deepRestrictedMsg)
	}
}

// TestLiveCheckPassesWithoutAnyReport：没有历史报告、微测成功 → 放行。
func TestLiveCheckPassesWithoutAnyReport(t *testing.T) {
	withTempProbeReport(t, nil)
	stubProbe(t, true)
	a := NewApp()
	if ok, reason, _, _ := a.deepPrecheckLive("github.com"); !ok {
		t.Fatalf("无报告且微测成功应放行: %q", reason)
	}
}

// TestLiveCheckDirectTLSFallback：拿不到任何候选 IP 时退回系统 DNS 直连 TLS，
// 直连成功即放行（不能让「DoH 挂了」误判成「网络受限」）。
func TestLiveCheckDirectTLSFallback(t *testing.T) {
	withTempProbeReport(t, nil)
	cfg := a0Config(t)
	oldDirect, oldCands := directTLSCheck, deepCandidatesFn
	directTLSCheck = func(string, time.Duration) (bool, error) { return true, nil }
	// 强制「候选为空」：否则本机 DoH 若能解析出 IP 就不会走直连兜底分支，
	// 这条测试会变成依赖真实网络的随机结果。
	deepCandidatesFn = func(*App, context.Context, *config.Config, string, time.Duration, *[]string) []string {
		return nil
	}
	t.Cleanup(func() { directTLSCheck, deepCandidatesFn = oldDirect, oldCands })
	a := NewApp()
	if res := a.deepLiveCheck(cfg, "github.com"); !res.OK {
		t.Fatal("无候选 IP 时直连 TLS 成功应放行")
	}
}

// TestCheckDeepPreconditionReturnsLive：前端调用必须返回 live=true 的真实结果。
func TestCheckDeepPreconditionReturnsLive(t *testing.T) {
	withTempProbeReport(t, staleFailureReport())
	stubProbe(t, true)
	a := NewApp()
	res := a.CheckDeepPrecondition()
	if res["ok"] != true {
		t.Fatalf("实时微测成功应返回 ok=true，实际 %v", res)
	}
	if res["live"] != true {
		t.Fatalf("必须标记 live=true，实际 %v", res["live"])
	}
	if res["domain"] != "github.com" {
		t.Fatalf("domain 应为 github.com，实际 %v", res["domain"])
	}
}

// TestSetDeepAccelGateUsesLiveProbe：后端闸同样只认实时结果——
// 旧报告全失败 + 现场通 → 必须能开启（用 manual 模式测，绝不碰注册表）。
func TestSetDeepAccelGateUsesLiveProbe(t *testing.T) {
	withTempProbeReport(t, staleFailureReport())
	stubProbe(t, true)

	a := NewApp()
	a.pro.Store(true) // 绕过 Pro 闸，专测预检闸
	if _, err := a.SetDeepAccel(true, DeepModeManual, false, false); err != nil {
		t.Fatalf("现场可通时必须允许开启，实际: %v", err)
	}
	if !a.GetProState()["deepAccel"].(bool) {
		t.Fatal("预检放行后深度加速应已开启")
	}
	a.stopDeep()
}

// TestSetDeepAccelBlockedWhenOffline：现场不通 → 拒绝开启且不留监听端口。
func TestSetDeepAccelBlockedWhenOffline(t *testing.T) {
	withTempProbeReport(t, staleFailureReport())
	stubProbe(t, false)
	a := NewApp()
	a.pro.Store(true)
	if _, err := a.SetDeepAccel(true, DeepModeAuto, false, false); err == nil {
		t.Fatal("现场不通时应返回错误")
	} else if err.Error() != deepRestrictedMsg {
		t.Fatalf("错误文案应为定稿拦截文案，实际 %q", err.Error())
	}
	if a.GetProState()["deepAccel"].(bool) {
		t.Fatal("被拦截后深度加速不应开启")
	}
	if a.GetProState()["deepListen"].(string) != "" {
		t.Fatal("被拦截后不应有监听端口")
	}
}

// TestStartApplyClearsProbeReport：点「一键智能加速」必须立刻清空旧探测报告。
func TestStartApplyClearsProbeReport(t *testing.T) {
	withTempProbeReport(t, staleFailureReport())
	p, err := cache.ProbePath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("前置条件：旧报告应存在: %v", err)
	}
	a := NewApp() // ctx 为 nil：StartApply 会提前返回「未就绪」，但清空动作必须已经发生
	if err := a.StartApply(); err == nil {
		t.Fatal("ctx 为空时 StartApply 应报未就绪")
	}
	if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
		t.Fatalf("点击一键加速后旧报告必须被清空（statErr=%v）", statErr)
	}
}

// TestLiveCheckDetailTransparency：微测失败时必须带「卡在哪一步」的明细，
// 且错误分类正确（TCP 超时不能笼统写成「网络受限」）。
// 候选 IP 用缓存种进去，保证不依赖真实 DoH 网络的确定性。
func TestLiveCheckDetailTransparency(t *testing.T) {
	withTempProbeReport(t, staleFailureReport())
	if err := cache.Save(map[string]string{"github.com": "20.205.243.166"}); err != nil {
		t.Fatalf("种缓存候选失败: %v", err)
	}
	stubProbe(t, false)

	a := NewApp()
	ok, reason, _, detail := a.deepPrecheckLive("github.com")
	if ok {
		t.Fatal("全失败应拦截")
	}
	if reason != deepRestrictedMsg {
		t.Fatalf("拦截文案不符: %q", reason)
	}
	if len(detail) == 0 {
		t.Fatal("失败时必须返回诊断明细（透明化要求）")
	}
	joined := strings.Join(detail, "\n")
	if !strings.Contains(joined, "TCP 连接超时") {
		t.Fatalf("明细应包含分类后的失败原因，实际:\n%s", joined)
	}
	// 明细必须逐候选列出（每个失败 IP 一行「候选 x.x.x.x: 原因」）
	if !strings.Contains(joined, "候选 ") {
		t.Fatalf("明细应逐候选列 IP，实际:\n%s", joined)
	}
}

// TestCheckDeepPreconditionCarriesDetail：前端拿到的结果必须带 detail 字段。
func TestCheckDeepPreconditionCarriesDetail(t *testing.T) {
	withTempProbeReport(t, staleFailureReport())
	stubProbe(t, false)
	a := NewApp()
	res := a.CheckDeepPrecondition()
	detail, ok := res["detail"].([]string)
	if !ok || len(detail) == 0 {
		t.Fatalf("CheckDeepPrecondition 必须带非空 detail，实际 %v", res["detail"])
	}
}

// TestSetDeepAccelForceBypassesGate：现场不通时 force=true 是逃生通道——
// 必须放行并真正开启深度加速（manual 模式，不碰注册表）。
func TestSetDeepAccelForceBypassesGate(t *testing.T) {
	withTempProbeReport(t, staleFailureReport())
	stubProbe(t, false) // 微测全失败

	a := NewApp()
	a.pro.Store(true)
	if _, err := a.SetDeepAccel(true, DeepModeManual, false, true); err != nil {
		t.Fatalf("强制开启必须放行，实际: %v", err)
	}
	if !a.GetProState()["deepAccel"].(bool) {
		t.Fatal("强制开启后深度加速应已开启")
	}
	a.stopDeep()
}

// TestRefreshDeepPrecondition：网络体检必须强制清空探测报告后重测，
// 且无论结果如何都不带陈旧状态。
func TestRefreshDeepPrecondition(t *testing.T) {
	withTempProbeReport(t, staleFailureReport())
	stubProbe(t, false)

	a := NewApp()
	res := a.RefreshDeepPrecondition()
	p, err := cache.ProbePath()
	if err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
		t.Fatalf("网络体检后旧报告必须被清空（statErr=%v）", statErr)
	}
	if res["live"] != true {
		t.Fatalf("重测结果必须标记 live=true: %v", res)
	}
	if res["ok"] != false {
		t.Fatal("stub 全失败时重测结果应为 ok=false（证明没被旧状态放过）")
	}
}
