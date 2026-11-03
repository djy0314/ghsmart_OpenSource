package engine

import (
	"testing"

	"ghsmart/internal/decision"
	"ghsmart/internal/probe"
)

// TestPickChosenAllFailed：某域名所有候选 IP 均失败时必须返回 ok=false（剔除），
// 即使该域名在 Hosts 中已有旧记录，也绝不能沿用失效 IP。
func TestPickChosenAllFailed(t *testing.T) {
	best := probe.ProbeResult{IP: "1.2.3.4", Err: "所有候选 IP 均失败或处于冷却期"}
	_, ok := PickChosen(best, false, "5.6.7.8")
	if ok {
		t.Fatal("全部失败时应剔除该域名，而不是沿用旧 IP")
	}
}

// TestPickChosenSwitch：有可用 IP 且建议切换时选新最优。
func TestPickChosenSwitch(t *testing.T) {
	best := probe.ProbeResult{IP: "1.2.3.4", OK: true, Score: 100}
	ip, ok := PickChosen(best, true, "5.6.7.8")
	if !ok || ip != "1.2.3.4" {
		t.Fatalf("应切换到新最优 IP，got %q ok=%v", ip, ok)
	}
}

// TestPickChosenHysteresis：迟滞区间内保留当前在用 IP。
func TestPickChosenHysteresis(t *testing.T) {
	best := probe.ProbeResult{IP: "1.2.3.4", OK: true, Score: 100}
	ip, ok := PickChosen(best, false, "5.6.7.8")
	if !ok || ip != "5.6.7.8" {
		t.Fatalf("迟滞区间内应保留当前 IP，got %q ok=%v", ip, ok)
	}
}

// TestPickChosenNoCurrent：无在用 IP 时直接采用新最优。
func TestPickChosenNoCurrent(t *testing.T) {
	best := probe.ProbeResult{IP: "1.2.3.4", OK: true, Score: 100}
	ip, ok := PickChosen(best, true, "")
	if !ok || ip != "1.2.3.4" {
		t.Fatalf("无在用 IP 应采用新最优，got %q ok=%v", ip, ok)
	}
}

// TestDecideSwitchForceOnCurrentFailed：复现实机 Bug——
// 在用 IP 111.133 本轮 TLS 超时失败、新最优 110.133 正常时，
// 迟滞必须失效强制切换，绝不让失效 IP 赖在 Hosts 里。
func TestDecideSwitchForceOnCurrentFailed(t *testing.T) {
	results := []probe.ProbeResult{
		{IP: "185.199.110.133", OK: true, Score: 164.4},
		{IP: "185.199.111.133", OK: false, Score: 1999.6},
	}
	// switchTo=false（历史分数迟滞），但 cur 本轮失败 → 必须强制切换
	if !decideSwitch(false, "185.199.111.133", results) {
		t.Fatal("当前 IP 本轮已失败，迟滞应失效强制切换")
	}
	// 当前 IP 本轮仍然 OK → 迟滞生效，不切换（decideSwitch 返回 false）
	if decideSwitch(false, "185.199.110.133", results) {
		t.Fatal("当前 IP 本轮 OK 且迟滞生效，不应切换")
	}
	// 无在用 IP → 直接采用新最优
	if !decideSwitch(false, "", results) {
		t.Fatal("无在用 IP 时应切换")
	}
	// 明确建议切换 → 切换
	if !decideSwitch(true, "anything", results) {
		t.Fatal("switchTo=true 时应切换")
	}
}

// TestTruncateIPs：候选池截断——只探测 DoH 前 n 个候选，长尾直接放弃。
func TestTruncateIPs(t *testing.T) {
	ips := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"}
	if got := TruncateIPs(ips, 3); len(got) != 3 || got[2] != "3.3.3.3" {
		t.Fatalf("应截断为前 3 个: %v", got)
	}
	if got := TruncateIPs(ips, 0); len(got) != 5 {
		t.Fatalf("n<=0 应原样返回: %v", got)
	}
	if got := TruncateIPs(ips, 10); len(got) != 5 {
		t.Fatalf("n 超长应原样返回: %v", got)
	}
	if got := TruncateIPs(nil, 3); got != nil {
		t.Fatalf("空切片应原样返回: %v", got)
	}
}

// TestStateForDomain：多域名共享 IP 时状态互不干扰（域名前缀键隔离）。
func TestStateForDomain(t *testing.T) {
	state := map[string]*decision.Candidate{
		"a.com|1.1.1.1": {IP: "1.1.1.1", Domain: "a.com", InUse: true},
		"b.com|2.2.2.2": {IP: "2.2.2.2", Domain: "b.com", InUse: true},
	}
	sub := stateForDomain(state, "a.com")
	if len(sub) != 1 || sub["1.1.1.1"] == nil {
		t.Fatalf("应只取到 a.com 的候选: %v", sub)
	}
	if currentIPInDomain(state, "a.com") != "1.1.1.1" || currentIPInDomain(state, "b.com") != "2.2.2.2" {
		t.Fatal("currentIPInDomain 跨域名串扰")
	}
	clearInUseForDomain(state, "a.com")
	if currentIPInDomain(state, "a.com") != "" || currentIPInDomain(state, "b.com") != "2.2.2.2" {
		t.Fatal("clearInUseForDomain 影响了其他域名")
	}
}
