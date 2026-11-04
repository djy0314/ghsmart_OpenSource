//go:build windows

// autostart_windows_test.go 只验证「生成的计划任务定义是否正确」，
// 不真的创建任务——创建需要管理员权限，且不该在测试里动开发机的任务计划。
package autostart

import (
	"strings"
	"testing"
)

// TestTaskXMLUsesHighestAvailable 是免 UAC 的关键断言：
// RunLevel 必须是 HighestAvailable，否则开机仍会弹 UAC。
func TestTaskXMLUsesHighestAvailable(t *testing.T) {
	xml := taskXML(`C:\Program Files\ghsmart\ghsmart.exe`, "S-1-5-21-1-2-3-1001")
	if !strings.Contains(xml, "<RunLevel>HighestAvailable</RunLevel>") {
		t.Fatalf("RunLevel 必须是 HighestAvailable（免 UAC 的前提），实际:\n%s", xml)
	}
}

// TestTaskXMLUsesLogonTrigger：登录时触发，带延迟避免开机争抢。
func TestTaskXMLUsesLogonTrigger(t *testing.T) {
	xml := taskXML(`C:\ghsmart.exe`, "S-1-5-21-1-2-3-1001")
	if !strings.Contains(xml, "<LogonTrigger>") {
		t.Fatalf("缺少登录触发器:\n%s", xml)
	}
	if !strings.Contains(xml, "<Delay>PT15S</Delay>") {
		t.Fatalf("应带 15 秒延迟，避免登录瞬间与其它启动项抢资源:\n%s", xml)
	}
}

// TestTaskXMLPassesSilentArg：自启必须带 --silent，否则开机就弹窗口。
func TestTaskXMLPassesSilentArg(t *testing.T) {
	xml := taskXML(`C:\ghsmart.exe`, "S-1-5-21-1-2-3-1001")
	if !strings.Contains(xml, "<Arguments>--silent</Arguments>") {
		t.Fatalf("缺少 --silent 参数:\n%s", xml)
	}
}

// TestTaskXMLNoTimeLimit：常驻托盘程序不能被 3 天后自动结束。
func TestTaskXMLNoTimeLimit(t *testing.T) {
	xml := taskXML(`C:\ghsmart.exe`, "S-1-5-21-1-2-3-1001")
	if !strings.Contains(xml, "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>") {
		t.Fatalf("ExecutionTimeLimit 应为 PT0S（不限时长）:\n%s", xml)
	}
	// 电池供电时也要启动：笔记本用户占大多数
	if !strings.Contains(xml, "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>") {
		t.Fatalf("不应禁止电池供电时启动:\n%s", xml)
	}
}

// TestTaskXMLEscapesPath：路径里的 XML 特殊字符必须转义，否则任务创建会失败。
func TestTaskXMLEscapesPath(t *testing.T) {
	xml := taskXML(`C:\a & b\<ghsmart>.exe`, "S-1-5-21-1-2-3-1001")
	if strings.Contains(xml, `C:\a & b\<ghsmart>`) {
		t.Fatalf("路径未转义:\n%s", xml)
	}
	if !strings.Contains(xml, "&amp;") || !strings.Contains(xml, "&lt;") {
		t.Fatalf("应出现转义后的实体:\n%s", xml)
	}
}

// TestTaskXMLUsesSID：用 SID 标识用户，避免域名/用户名变更导致任务失效。
func TestTaskXMLUsesSID(t *testing.T) {
	const sid = "S-1-5-21-1630325289-4193393152-3375486167-1001"
	xml := taskXML(`C:\ghsmart.exe`, sid)
	if strings.Count(xml, sid) != 2 {
		t.Fatalf("SID 应同时出现在触发器与 Principal 中，实际 %d 次:\n%s",
			strings.Count(xml, sid), xml)
	}
}

// TestQueryNeverPanics：查询接口在任务不存在时应安全返回未启用。
func TestQueryNeverPanics(t *testing.T) {
	st := Query()
	if st.Enabled && st.Mode == ModeNone {
		t.Fatalf("状态自相矛盾: %+v", st)
	}
	if st.Mode == ModeTask && st.NeedsUAC {
		t.Fatalf("计划任务模式不应标记需要 UAC: %+v", st)
	}
	if st.Mode == ModeRun && !st.NeedsUAC {
		t.Fatalf("Run 键模式必须标记需要 UAC: %+v", st)
	}
}
