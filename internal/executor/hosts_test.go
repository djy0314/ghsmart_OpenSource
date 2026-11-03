package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTempHosts 生成一个带用户内容的临时 Hosts 文件，返回其路径。
func writeTempHosts(t *testing.T, content string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	backup := filepath.Join(dir, "hosts.bak")
	if content != "" {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return path, backup
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestApplyOnFreshHosts：无区块文件首次写入，用户内容必须原样保留。
func TestApplyOnFreshHosts(t *testing.T) {
	userContent := "# 我的自定义 hosts\n127.0.0.1 localhost\n1.2.3.4 my.example.com\n"
	path, backup := writeTempHosts(t, userContent)

	entries := map[string]string{"github.com": "140.82.112.3"}
	if err := mutateHosts(path, backup, entries); err != nil {
		t.Fatal(err)
	}

	got := mustRead(t, path)
	if !strings.Contains(got, "140.82.112.3 github.com") {
		t.Fatalf("缺少 ghsmart 条目:\n%s", got)
	}
	if !strings.Contains(got, "1.2.3.4 my.example.com") {
		t.Fatalf("用户内容被破坏:\n%s", got)
	}
	if strings.Count(got, BlockBegin) != 1 || strings.Count(got, BlockEnd) != 1 {
		t.Fatalf("区块标记数量异常:\n%s", got)
	}
	// 备份文件应为原始内容
	if bak := mustRead(t, backup); bak != userContent {
		t.Fatalf("备份内容与原文件不一致:\n%s", bak)
	}
}

// TestApplyIdempotent：重复 apply 不产生重复区块，旧 IP 被替换。
func TestApplyIdempotent(t *testing.T) {
	path, backup := writeTempHosts(t, "127.0.0.1 localhost\n")

	first := map[string]string{"github.com": "140.82.112.3"}
	if err := mutateHosts(path, backup, first); err != nil {
		t.Fatal(err)
	}
	second := map[string]string{
		"github.com":                "140.82.113.4",
		"raw.githubusercontent.com": "185.199.108.133",
	}
	if err := mutateHosts(path, backup, second); err != nil {
		t.Fatal(err)
	}

	got := mustRead(t, path)
	if strings.Count(got, BlockBegin) != 1 || strings.Count(got, BlockEnd) != 1 {
		t.Fatalf("重复 apply 产生了重复区块:\n%s", got)
	}
	if strings.Contains(got, "140.82.112.3") {
		t.Fatalf("旧 IP 未被替换:\n%s", got)
	}
	if !strings.Contains(got, "140.82.113.4 github.com") ||
		!strings.Contains(got, "185.199.108.133 raw.githubusercontent.com") {
		t.Fatalf("新条目缺失:\n%s", got)
	}
	if !strings.HasPrefix(got, "127.0.0.1 localhost") {
		t.Fatalf("用户内容丢失或顺序异常:\n%s", got)
	}
}

// TestRemoveHosts：删除区块后用户内容完好，无区块时是幂等 no-op。
func TestRemoveHosts(t *testing.T) {
	userContent := "127.0.0.1 localhost\n10.0.0.1 intranet.local\n"
	path, backup := writeTempHosts(t, userContent)

	entries := map[string]string{"github.com": "140.82.112.3"}
	if err := mutateHosts(path, backup, entries); err != nil {
		t.Fatal(err)
	}
	if err := mutateHosts(path, backup, nil); err != nil {
		t.Fatal(err)
	}
	got := mustRead(t, path)
	if strings.Contains(got, "github.com") || strings.Contains(got, BlockBegin) {
		t.Fatalf("区块未被清除:\n%s", got)
	}
	if !strings.Contains(got, "10.0.0.1 intranet.local") {
		t.Fatalf("用户内容被破坏:\n%s", got)
	}

	// 再删一次应当是 no-op
	if err := mutateHosts(path, backup, nil); err != nil {
		t.Fatalf("重复 remove 应为 no-op，却返回错误: %v", err)
	}
}

// TestStaleDomainLineRemoved：某域名无可用 IP 被剔除后，
// 原区块中该域名的旧记录必须被清理干净，其余条目不受影响。
func TestStaleDomainLineRemoved(t *testing.T) {
	path, backup := writeTempHosts(t, "127.0.0.1 localhost\n")

	first := map[string]string{
		"github.com":                    "140.82.112.3",
		"objects.githubusercontent.com": "185.199.108.133",
	}
	if err := mutateHosts(path, backup, first); err != nil {
		t.Fatal(err)
	}
	// 第二轮 objects.githubusercontent.com 无可用 IP，entries 中不再包含它
	second := map[string]string{"github.com": "140.82.112.3"}
	if err := mutateHosts(path, backup, second); err != nil {
		t.Fatal(err)
	}

	got := mustRead(t, path)
	if strings.Contains(got, "objects.githubusercontent.com") {
		t.Fatalf("被剔除域名的旧记录未清理:\n%s", got)
	}
	if !strings.Contains(got, "140.82.112.3 github.com") {
		t.Fatalf("正常域名的条目丢失:\n%s", got)
	}
	if strings.Count(got, BlockBegin) != 1 || strings.Count(got, BlockEnd) != 1 {
		t.Fatalf("区块标记数量异常:\n%s", got)
	}
}

// TestRemoveAllEntries：所有域名被剔除时，区块应被清空但用户内容保留。
func TestRemoveAllEntries(t *testing.T) {
	path, backup := writeTempHosts(t, "127.0.0.1 localhost\n")

	first := map[string]string{"github.com": "140.82.112.3"}
	if err := mutateHosts(path, backup, first); err != nil {
		t.Fatal(err)
	}
	// 全部剔除：传空 map（区别于 nil=remove 整个区块）
	if err := mutateHosts(path, backup, map[string]string{}); err != nil {
		t.Fatal(err)
	}

	got := mustRead(t, path)
	if strings.Contains(got, "github.com") || strings.Contains(got, "140.82.112.3") {
		t.Fatalf("失效记录未清理:\n%s", got)
	}
	if !strings.Contains(got, "127.0.0.1 localhost") {
		t.Fatalf("用户内容被破坏:\n%s", got)
	}
}

// TestReadHostsBlockParse：区块解析必须拿全条目——覆盖 \r\n 行尾、
// 注释行、行内注释、多空白分隔等真实 Windows hosts 场景。
func TestReadHostsBlockParse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	content := "# 用户注释\r\n" +
		"36.63.163.34 raw.githubusercontent.com\r\n" +
		"# ghsmart begin\n" +
		"# 由 ghsmart 自动生成，请勿手工编辑此区块\n" +
		"# 更新时间: 2026-11-03 10:38:25\n" +
		"20.205.243.166    github.com\n" +
		"185.199.109.133\tobjects.githubusercontent.com\r\n" +
		"185.199.108.133 raw.githubusercontent.com\n" +
		"# ghsmart end\n" +
		"127.0.0.1 ads.example.com\r\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readHostsBlockFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("应解析出 3 条，实得 %d: %v", len(got), got)
	}
	want := map[string]string{
		"github.com":                    "20.205.243.166",
		"objects.githubusercontent.com": "185.199.109.133",
		"raw.githubusercontent.com":     "185.199.108.133",
	}
	for d, ip := range want {
		if got[d] != ip {
			t.Fatalf("%s 应为 %s，实得 %q", d, ip, got[d])
		}
	}
}

// TestReadHostsBlockNoBlock：无区块时返回空 map 而非错误。
func TestReadHostsBlockNoBlock(t *testing.T) {
	path, _ := writeTempHosts(t, "127.0.0.1 localhost\n")
	got, err := readHostsBlockFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("无区块应返回空 map，实得 %v", got)
	}
}

// TestApplyCommentsConflictingUserLines：区块外用户已有的同域名行
// 必须被注释掉（Windows hosts 首条匹配优先，否则加速记录被覆盖失效）。
func TestApplyCommentsConflictingUserLines(t *testing.T) {
	userContent := "127.0.0.1 www.cr-soft.net\n" +
		"36.63.163.34 raw.githubusercontent.com\n" +
		"124.108.22.138 srv.codefusion.technology #UHE_\n"
	path, backup := writeTempHosts(t, userContent)

	entries := map[string]string{"raw.githubusercontent.com": "185.199.108.133"}
	if err := mutateHosts(path, backup, entries); err != nil {
		t.Fatal(err)
	}

	got := mustRead(t, path)
	// 冲突行被注释
	if !strings.Contains(got, CommentPrefix+"36.63.163.34 raw.githubusercontent.com") {
		t.Fatalf("冲突的用户行未被注释:\n%s", got)
	}
	// 无冲突的用户行原样保留（未被注释）
	if !strings.Contains(got, "127.0.0.1 www.cr-soft.net") ||
		strings.Contains(got, CommentPrefix+"127.0.0.1") {
		t.Fatalf("无冲突的用户行被误改:\n%s", got)
	}
	if !strings.Contains(got, "124.108.22.138 srv.codefusion.technology #UHE_") {
		t.Fatalf("带行内注释的用户行被误改:\n%s", got)
	}
	// 区块条目正常写入
	if !strings.Contains(got, "185.199.108.133 raw.githubusercontent.com") {
		t.Fatalf("区块条目缺失:\n%s", got)
	}

	// 重复 apply 不得双重注释
	if err := mutateHosts(path, backup, entries); err != nil {
		t.Fatal(err)
	}
	got = mustRead(t, path)
	if strings.Count(got, CommentPrefix+"36.63.163.34") != 1 {
		t.Fatalf("重复 apply 产生了双重注释:\n%s", got)
	}
}

// TestRemoveRestoresCommentedLines：remove 时被注释的用户行必须原样恢复。
func TestRemoveRestoresCommentedLines(t *testing.T) {
	userContent := "36.63.163.34 raw.githubusercontent.com\n"
	path, backup := writeTempHosts(t, userContent)

	entries := map[string]string{"raw.githubusercontent.com": "185.199.108.133"}
	if err := mutateHosts(path, backup, entries); err != nil {
		t.Fatal(err)
	}
	if err := mutateHosts(path, backup, nil); err != nil {
		t.Fatal(err)
	}

	got := mustRead(t, path)
	if !strings.Contains(got, "36.63.163.34 raw.githubusercontent.com") {
		t.Fatalf("用户原始行未恢复:\n%s", got)
	}
	if strings.Contains(got, CommentPrefix) {
		t.Fatalf("还原后仍残留 ghsmart 注释前缀:\n%s", got)
	}
	if strings.Contains(got, "ghsmart") {
		t.Fatalf("还原后仍残留 ghsmart 区块:\n%s", got)
	}
}

// TestLineDomains：域名提取需跳过 IP 列与行内注释。
func TestLineDomains(t *testing.T) {
	got := lineDomains("124.108.22.138 srv.codefusion.technology #UHE_")
	if len(got) != 1 || got[0] != "srv.codefusion.technology" {
		t.Fatalf("行内注释应被排除: %v", got)
	}
	got = lineDomains("1.2.3.4 a.com b.com")
	if len(got) != 2 {
		t.Fatalf("应提取两个域名: %v", got)
	}
}

// TestSplitBlockBroken：只有 begin 没有 end 的残缺区块必须报错，绝不静默破坏。
func TestSplitBlockBroken(t *testing.T) {
	_, _, _, _, err := splitBlock("# ghsmart begin\n1.2.3.4 github.com\n")
	if err == nil {
		t.Fatal("残缺区块应返回错误")
	}
}

// TestRenderBlockStable：同一 entries 多次渲染输出一致（除时间戳行外）。
func TestRenderBlockStable(t *testing.T) {
	entries := map[string]string{
		"b.com": "2.2.2.2",
		"a.com": "1.1.1.1",
	}
	r1 := renderBlock(entries)
	r2 := renderBlock(entries)
	// 去掉时间戳行后比较
	strip := func(s string) string {
		var out []string
		for _, line := range strings.Split(s, "\n") {
			if !strings.HasPrefix(line, "# 更新时间:") {
				out = append(out, line)
			}
		}
		return strings.Join(out, "\n")
	}
	if strip(r1) != strip(r2) {
		t.Fatalf("渲染输出不稳定:\n--1--\n%s\n--2--\n%s", r1, r2)
	}
	if !strings.Contains(r1, "1.1.1.1 a.com") || !strings.Contains(r1, "2.2.2.2 b.com") {
		t.Fatalf("渲染缺少条目:\n%s", r1)
	}
}
