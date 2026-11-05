package executor

import (
	"strings"
	"testing"
)

// 共存检测的核心承诺：**压住了别人的记录就必须报出来**。
// 这里验证「报了」和「真的动了」两件事同时成立，避免报告与实际行为脱节。

func TestReportCountsConflicts(t *testing.T) {
	// 用户在别处（多半是另一款加速工具）已经写过 github.com
	userContent := "# Steam++ 加速记录\n140.82.112.3 github.com\n140.82.112.3 api.github.com\n1.2.3.4 my.example.com\n"
	path, backup := writeTempHosts(t, userContent)

	// 本次要写两个域名，用户那边两个都已存在 → 应报 2 行
	entries := map[string]string{
		"github.com":     "20.205.243.166",
		"api.github.com": "20.205.243.168",
	}
	rep, err := mutateHostsReport(path, backup, entries)
	if err != nil {
		t.Fatal(err)
	}

	if rep.Commented != 2 {
		t.Fatalf("应报告 2 行冲突，实际 %d 行: %+v", rep.Commented, rep.CommentedLines)
	}
	if len(rep.CommentedLines) != 2 {
		t.Fatalf("样本数量不对: %+v", rep.CommentedLines)
	}
	if !strings.Contains(rep.CommentedLines[0], "github.com") {
		t.Fatalf("样本内容不对: %+v", rep.CommentedLines)
	}
	// 不冲突的用户内容绝不能被注释
	if strings.Contains(mustRead(t, path), CommentPrefix+"1.2.3.4") {
		t.Fatal("未冲突的用户行被误注释")
	}
	if !strings.Contains(mustRead(t, path), "1.2.3.4 my.example.com") {
		t.Fatal("未冲突的用户行被破坏")
	}
}

func TestReportZeroWhenClean(t *testing.T) {
	// 干净文件：Commented 必须为 0，否则界面会凭空弹警告
	path, backup := writeTempHosts(t, "127.0.0.1 localhost\n1.2.3.4 my.example.com\n")

	rep, err := mutateHostsReport(path, backup, map[string]string{"github.com": "20.205.243.166"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Commented != 0 || len(rep.CommentedLines) != 0 {
		t.Fatalf("干净文件不该报冲突: %+v", rep)
	}
}

func TestReportDetectsForeignTools(t *testing.T) {
	// 品牌字样来自各工具自己写进 hosts 的注释行，均为真实存在
	userContent := "# Watt Toolkit (Steam++) 生成\n# GitHub520 加速\n127.0.0.1 localhost\n"
	path, backup := writeTempHosts(t, userContent)

	rep, err := mutateHostsReport(path, backup, map[string]string{"github.com": "20.205.243.166"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.ForeignTools) != 2 {
		t.Fatalf("应识别出 2 款外来工具，实际: %+v", rep.ForeignTools)
	}
	joined := strings.Join(rep.ForeignTools, "|")
	if !strings.Contains(joined, "Watt Toolkit") || !strings.Contains(joined, "GitHub520") {
		t.Fatalf("工具名识别错误: %+v", rep.ForeignTools)
	}
	// 注意：只报告，不改写别人的注释行
	if !strings.Contains(mustRead(t, path), "Watt Toolkit") {
		t.Fatal("外来工具的注释行不应被删除")
	}
}

func TestDetectForeignToolsCaseInsensitiveAndNoFalsePositive(t *testing.T) {
	if got := detectForeignTools("# FASTGITHUB\n"); len(got) != 1 || got[0] != "FastGithub" {
		t.Fatalf("大小写不敏感匹配失败: %+v", got)
	}
	// 普通 hosts 内容不能误判成外来工具
	if got := detectForeignTools("# 我的自建服务\n10.0.0.1 gitlab.corp.example\n"); len(got) != 0 {
		t.Fatalf("普通内容被误判: %+v", got)
	}
	// 同名子串不能算命中（steam++ 之外的 "steam" 不算）
	if got := detectForeignTools("# steam 游戏服务器\n"); len(got) != 0 {
		t.Fatalf("相似词被误判: %+v", got)
	}
}

func TestReportConflictsRestoredOnRemove(t *testing.T) {
	// 关键闭环：注释掉的行在「一键还原」时必须原样回来，
	// 否则用户卸载 ghsmart 后自己的加速记录就永久丢了
	userContent := "140.82.112.3 github.com\n"
	path, backup := writeTempHosts(t, userContent)

	entries := map[string]string{"github.com": "20.205.243.166"}
	if _, err := mutateHostsReport(path, backup, entries); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(mustRead(t, path), CommentPrefix) {
		t.Fatal("冲突行未被注释，加速记录会被首条匹配规则压住")
	}

	if _, err := mutateHostsReport(path, backup, nil); err != nil {
		t.Fatal(err)
	}
	got := mustRead(t, path)
	if strings.Contains(got, CommentPrefix) {
		t.Fatalf("还原后仍残留注释前缀:\n%s", got)
	}
	if !strings.Contains(got, "140.82.112.3 github.com") {
		t.Fatalf("用户原有记录未恢复:\n%s", got)
	}
}

func TestSampleLinesTruncation(t *testing.T) {
	// 样本必须限量限长：界面不能因为一份超长 hosts 而卡死
	long := "1.1.1.1 " + strings.Repeat("a", 300)
	s := sampleLines([]string{long, "b", "c", "d", "e", "f", "g"}, 5)
	if len(s) != 5 {
		t.Fatalf("样本应被限制为 5 条，实际 %d", len(s))
	}
	if r := []rune(s[0]); len(r) > 121 {
		t.Fatalf("单行未被截断，长度 %d", len(r))
	}
	if !strings.HasSuffix(s[0], "…") {
		t.Fatal("截断行应带省略号，让用户知道被截了")
	}
	if sampleLines(nil, 5) != nil {
		t.Fatal("无样本时应返回 nil")
	}
}
