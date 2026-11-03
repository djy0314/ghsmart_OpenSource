package main

import (
	"net"
	"testing"

	"ghsmart/internal/config"
)

// TestEffectiveCompat：兼容模式取值规则——用户勾选记录（license.json）优先，
// 未记录过时回落到配置文件 web_proxy.compat_mode。
func TestEffectiveCompat(t *testing.T) {
	a := NewApp()
	cfg := &config.Config{}
	if a.effectiveCompat(licenseState{}, cfg) {
		t.Fatal("两者都未设置时应为 false")
	}
	cfg.WebProxy.CompatMode = true
	if !a.effectiveCompat(licenseState{}, cfg) {
		t.Fatal("配置文件开启且无用户记录时应为 true")
	}
	if a.effectiveCompat(licenseState{DeepCompat: true}, cfg) {
		// 用户明确勾选过 → 恒为 true（这条与上一行同值，主要为可读性）
		_ = a
	}
	cfg.WebProxy.CompatMode = false
	if !a.effectiveCompat(licenseState{DeepCompat: true}, cfg) {
		t.Fatal("用户明确勾选过时必须优先于配置文件")
	}
}

// TestPhysicalNICIPs：物理网卡探测只应产出合法 IPv4，最多 2 个。
// 不断言非空（无网卡/纯虚拟化环境也应不 panic）。
func TestPhysicalNICIPs(t *testing.T) {
	ips := physicalNICIPs()
	if len(ips) > 2 {
		t.Fatalf("最多 2 个，实际 %d: %v", len(ips), ips)
	}
	for _, ip := range ips {
		p := net.ParseIP(ip)
		if p == nil || p.To4() == nil {
			t.Fatalf("探测结果必须是 IPv4: %q", ip)
		}
		if p.IsLoopback() || p.IsLinkLocalUnicast() {
			t.Fatalf("不应包含回环/链路本地地址: %q", ip)
		}
	}
}
