package main

import (
	"path/filepath"
	"testing"

)

// TestAutoHealToggle：自愈开关必须能真正开、真正关，状态与返回值严格一致。
// 这正是「点了关闭却仍显示开启」的回归测试。
func TestAutoHealToggle(t *testing.T) {
	t.Setenv("GHSMART_LICENSE_FILE", filepath.Join(t.TempDir(), "license.json"))

	a := NewApp()
	if st := a.GetProState(); st["autoHeal"].(bool) {
		t.Fatal("初始状态不应为开启")
	}

	// 未解锁：开启必须被拒绝，且状态保持关闭
	if _, err := a.SetAutoHeal(true); err == nil {
		t.Fatal("未解锁时应拒绝开启自愈")
	}
	if a.GetProState()["autoHeal"].(bool) {
		t.Fatal("拒绝后状态不应变为开启")
	}

	// 解锁后开启
	a.pro.Store(true)
	st, err := a.SetAutoHeal(true)
	if err != nil {
		t.Fatalf("开启失败: %v", err)
	}
	if !st["autoHeal"].(bool) || !a.GetProState()["autoHeal"].(bool) {
		t.Fatal("开启后返回值与内部状态都应为 true")
	}

	// 关键：关闭必须生效
	st, err = a.SetAutoHeal(false)
	if err != nil {
		t.Fatalf("关闭失败: %v", err)
	}
	if st["autoHeal"].(bool) {
		t.Fatal("关闭后返回值必须为 false")
	}
	if a.GetProState()["autoHeal"].(bool) {
		t.Fatal("关闭后内部状态必须为 false")
	}
	if a.healOn.Load() {
		t.Fatal("关闭后 healOn 必须为 false")
	}

	// 幂等：重复关闭不报错、不重复 close 通道
	if _, err := a.SetAutoHeal(false); err != nil {
		t.Fatalf("重复关闭不应报错: %v", err)
	}

	// 再开启一次，验证双向可切换
	st, err = a.SetAutoHeal(true)
	if err != nil || !st["autoHeal"].(bool) {
		t.Fatalf("二次开启失败: %v", err)
	}
	a.stopHeal()
}

// TestAutoHealNoDoubleLoop：重复开启走幂等路径（先停旧循环），关闭后彻底清空。
func TestAutoHealNoDoubleLoop(t *testing.T) {
	t.Setenv("GHSMART_LICENSE_FILE", filepath.Join(t.TempDir(), "license.json"))
	a := NewApp()
	a.pro.Store(true)

	if _, err := a.SetAutoHeal(true); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SetAutoHeal(true); err != nil { // 幂等：重复开启不应报错
		t.Fatal(err)
	}
	if !a.healOn.Load() {
		t.Fatal("重复开启后仍应为开启状态")
	}
	a.stopHeal()
	if a.healCancel != nil {
		t.Fatal("stopHeal 后 cancel 应置空")
	}
	if a.healOn.Load() {
		t.Fatal("stopHeal 后 healOn 应为 false")
	}
	if _, err := a.SetAutoHeal(false); err != nil {
		t.Fatalf("停止后再次关闭应为安全空操作: %v", err)
	}
}

// TestClearLicenseStopsHeal：清除授权必须同时关掉自愈并回到 Free。
func TestClearLicenseStopsHeal(t *testing.T) {
	t.Setenv("GHSMART_LICENSE_FILE", filepath.Join(t.TempDir(), "license.json"))
	a := NewApp()
	a.pro.Store(true)
	if _, err := a.SetAutoHeal(true); err != nil {
		t.Fatal(err)
	}
	if err := a.ClearLicense(); err != nil {
		t.Fatalf("ClearLicense 失败: %v", err)
	}
	st := a.GetProState()
	if st["pro"].(bool) || st["autoHeal"].(bool) {
		t.Fatalf("清除后必须回到 Free 且自愈关闭，实际 %v", st)
	}
}

// TestDeepAccelGating：深度网页加速是 Pro 专属；Free 点击必须被拒绝且状态不变。
// 关闭路径必须幂等且安全（没有代理在跑、没有备份文件时不得碰注册表）。
func TestDeepAccelGating(t *testing.T) {
	t.Setenv("GHSMART_LICENSE_FILE", filepath.Join(t.TempDir(), "license.json"))
	t.Setenv("GHSMART_SYSPROXY_FILE", filepath.Join(t.TempDir(), "sysproxy.bak.json"))

	a := NewApp()
	if _, err := a.SetDeepAccel(true); err == nil {
		t.Fatal("Free 版应拒绝开启深度加速")
	}
	if a.GetProState()["deepAccel"].(bool) {
		t.Fatal("被拒绝后不应变为开启")
	}
	if a.GetProState()["deepListen"].(string) != "" {
		t.Fatal("未启动时不应有监听地址")
	}

	// 未开启状态下关闭：安全空操作
	a.pro.Store(true)
	st, err := a.SetDeepAccel(false)
	if err != nil {
		t.Fatalf("关闭失败: %v", err)
	}
	if st["deepAccel"].(bool) {
		t.Fatal("关闭后 deepAccel 应为 false")
	}
}

