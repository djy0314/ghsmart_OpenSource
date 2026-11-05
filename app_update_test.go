package main

// app_update_test.go 验证 v1.0.9 两条「告知类」功能的接线：
//   1. Hosts 共存冲突只提示一次（去重）——重复弹窗比不弹更招人烦
//   2. 版本号与更新状态由后端统一给出——前端写死版本号迟早会撒谎

import (
	"path/filepath"
	"testing"

	"ghsmart/internal/executor"
	"ghsmart/internal/updater"
)

// updTestApp 返回一个隔离的 App：授权状态写临时文件，不碰真实 ~/.ghsmart。
func updTestApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("GHSMART_LICENSE_FILE", filepath.Join(dir, "license.json"))
	return NewApp()
}

func TestReportHostsConflictDedup(t *testing.T) {
	a := updTestApp(t)
	rep := executor.HostsReport{Commented: 2, ForeignTools: []string{"FastGithub"}}

	// 一轮加速里主域名提前写入 + 收尾写入会各回报一次，用户只应看到一条提示
	if !a.reportHostsConflict(rep) {
		t.Fatal("第一次应报告")
	}
	if a.reportHostsConflict(rep) {
		t.Fatal("同一轮内第二次不应重复报告")
	}
}

func TestReportHostsConflictResetNextRound(t *testing.T) {
	a := updTestApp(t)
	rep := executor.HostsReport{Commented: 1}

	if !a.reportHostsConflict(rep) {
		t.Fatal("第一次应报告")
	}
	// 新一轮加速开始时 StartApply 会重置这个标记
	a.hostsRepOnce.Store(false)
	if !a.reportHostsConflict(rep) {
		t.Fatal("新一轮应能再次报告")
	}
}

func TestReportHostsConflictEmptyIsNoop(t *testing.T) {
	a := updTestApp(t)
	// 什么都没动时不提示——否则每次加速都弹一条「没碰到任何东西」，纯噪音
	if a.reportHostsConflict(executor.HostsReport{}) {
		t.Fatal("空报告不应触发提示")
	}
	// 且不能占用「一次机会」：紧接着的真实冲突仍要能提示
	if !a.reportHostsConflict(executor.HostsReport{Commented: 3}) {
		t.Fatal("空报告不应消耗去重标记")
	}
}

func TestUpdatePayloadWithoutInfo(t *testing.T) {
	a := updTestApp(t)
	m := a.updatePayload()
	if m["version"] != appVersion {
		t.Fatalf("版本号应为 %q，实际 %v", appVersion, m["version"])
	}
	if m["updateAvailable"] != false {
		t.Fatal("未检查过时不能声称有新版本")
	}
	// 没检查过就不该有 latest/url，否则前端会渲染出一个空壳提示
	if _, ok := m["latest"]; ok {
		t.Fatal("未检查过不应返回 latest")
	}
}

func TestUpdatePayloadWithInfo(t *testing.T) {
	a := updTestApp(t)
	a.updateInfo = &updater.Info{
		HasUpdate: true,
		Current:   appVersion,
		Latest:    "9.9.9",
		Tag:       "v9.9.9",
		URL:       "https://example.com/rel",
	}
	m := a.updatePayload()
	if m["updateAvailable"] != true || m["latest"] != "9.9.9" || m["tag"] != "v9.9.9" {
		t.Fatalf("更新信息映射错误: %+v", m)
	}
	if m["url"] != "https://example.com/rel" {
		t.Fatalf("下载页地址错误: %v", m["url"])
	}
}

func TestSkipUpdatePersists(t *testing.T) {
	a := updTestApp(t)
	a.updateInfo = &updater.Info{HasUpdate: true, Latest: "9.9.9"}

	a.SkipUpdate()

	st := a.loadLicenseState()
	if st.SkippedVersion != "9.9.9" {
		t.Fatalf("跳过版本未落盘，实际 %q", st.SkippedVersion)
	}
	// 落盘后要能回读——跳过是持久的，不是「本次会话有效」
	if again := a.loadLicenseState().SkippedVersion; again != "9.9.9" {
		t.Fatalf("回读失败: %q", again)
	}
}

func TestAppVersionIsComparable(t *testing.T) {
	// 发版手滑把版本号写成 "v1.0.9 " 或 "1.0.9-beta" 时，更新提示会一直弹或永不弹。
	// 这里钉死格式：必须是纯数字点分版本，且比上一个正式版新。
	if updater.Normalize(appVersion) != appVersion {
		t.Fatalf("版本号不应带 v 前缀或空白: %q", appVersion)
	}
	if updater.Compare(appVersion, "1.0.8") <= 0 {
		t.Fatalf("版本号 %q 应大于 v1.0.8", appVersion)
	}
	for _, r := range appVersion {
		if (r < '0' || r > '9') && r != '.' {
			t.Fatalf("版本号含非数字字符 %q: %q", string(r), appVersion)
		}
	}
}
