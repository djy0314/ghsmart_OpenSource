// git_test.go 用 GIT_CONFIG_GLOBAL 环境变量把测试隔离到临时文件，
// 绝不触碰真实的 ~/.gitconfig。
package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isolatedGit 把 git 全局配置指向临时文件并返回其路径。
func isolatedGit(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "gitconfig")
	t.Setenv("GIT_CONFIG_GLOBAL", p)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	return p
}

// readGitConfig 读回隔离配置文件内容。
func readGitConfig(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("读配置失败: %v", err)
	}
	return string(data)
}

// TestDefaultLevelNeverRewritesSSH 是 v1.0.8 的核心安全断言：
// 默认档绝不能出现 git@github.com: 或 ssh:// 的改写——
// 那会把用户的 git push 从 SSH 偷偷改道到 HTTPS。
func TestDefaultLevelNeverRewritesSSH(t *testing.T) {
	p := isolatedGit(t)
	if err := ApplyGit(GitRewriteGitOnly); err != nil {
		t.Fatalf("ApplyGit 失败: %v", err)
	}
	got := readGitConfig(t, p)

	for _, forbidden := range gitInsteadOfSSH {
		if strings.Contains(got, forbidden) {
			t.Fatalf("默认档不应写入 %q，实际配置:\n%s", forbidden, got)
		}
	}
	if !strings.Contains(got, "git://github.com/") {
		t.Fatalf("默认档应写入 git:// 改写，实际配置:\n%s", got)
	}
}

// TestSSHLevelWritesAllThree：用户主动选择 HTTPS 模式时才写三条。
func TestSSHLevelWritesAllThree(t *testing.T) {
	p := isolatedGit(t)
	if err := ApplyGit(GitRewriteSSH); err != nil {
		t.Fatalf("ApplyGit 失败: %v", err)
	}
	got := readGitConfig(t, p)
	for _, want := range allGitValues() {
		if !strings.Contains(got, want) {
			t.Fatalf("缺少 insteadOf 条目 %q，配置为:\n%s", want, got)
		}
	}
}

// TestDowngradeRemovesSSHImmediately：从 HTTPS 模式切回默认档时，
// SSH 两条必须被删掉——用户取消勾选后要能立刻恢复 SSH 推送。
func TestDowngradeRemovesSSHImmediately(t *testing.T) {
	p := isolatedGit(t)
	if err := ApplyGit(GitRewriteSSH); err != nil {
		t.Fatalf("升档失败: %v", err)
	}
	if err := ApplyGit(GitRewriteGitOnly); err != nil {
		t.Fatalf("降档失败: %v", err)
	}
	got := readGitConfig(t, p)
	for _, gone := range gitInsteadOfSSH {
		if strings.Contains(got, gone) {
			t.Fatalf("降档后 %q 仍残留:\n%s", gone, got)
		}
	}
	if !strings.Contains(got, "git://github.com/") {
		t.Fatalf("降档后默认档条目应保留:\n%s", got)
	}
}

// TestApplyGitIdempotent：重复 ApplyGit 不产生重复条目。
func TestApplyGitIdempotent(t *testing.T) {
	p := isolatedGit(t)
	for i := 0; i < 2; i++ {
		if err := ApplyGit(GitRewriteSSH); err != nil {
			t.Fatalf("第 %d 次 ApplyGit 失败: %v", i+1, err)
		}
	}
	got := readGitConfig(t, p)
	if n := strings.Count(got, "git@github.com:"); n != 1 {
		t.Fatalf("git@github.com: 应恰好出现 1 次，实际 %d 次:\n%s", n, got)
	}
}

// TestRemoveGitOnlyRemovesOwnValues：清理只删 ghsmart 的值，
// 用户自己配置的 insteadOf 原样保留。
func TestRemoveGitOnlyRemovesOwnValues(t *testing.T) {
	p := isolatedGit(t)
	if err := ApplyGit(GitRewriteSSH); err != nil {
		t.Fatalf("ApplyGit 失败: %v", err)
	}
	// 模拟用户自己的一条 insteadOf（不同 base，ghsmart 不应触碰）
	if out, err := runGit("config", "--global",
		"url.https://ghfast.example/.insteadOf", "https://mirror-user.com/"); err != nil {
		t.Fatalf("预置用户配置失败: %v %s", err, out)
	}

	if err := RemoveGit(); err != nil {
		t.Fatalf("RemoveGit 失败: %v", err)
	}

	got := readGitConfig(t, p)
	for _, v := range allGitValues() {
		if strings.Contains(got, "\t"+v) {
			t.Fatalf("ghsmart 的 insteadOf %q 未被清理:\n%s", v, got)
		}
	}
	if !strings.Contains(got, "https://mirror-user.com/") {
		t.Fatalf("用户自己的 insteadOf 被误删:\n%s", got)
	}
}

// TestRemoveGitIdempotent：没有 ghsmart 条目时 RemoveGit 静默成功。
func TestRemoveGitIdempotent(t *testing.T) {
	p := isolatedGit(t)
	if err := RemoveGit(); err != nil {
		t.Fatalf("空配置 RemoveGit 不应报错: %v", err)
	}
	if err := RemoveGit(); err != nil {
		t.Fatalf("重复 RemoveGit 不应报错: %v", err)
	}
	if got := readGitConfig(t, p); got != "" {
		t.Fatalf("空配置清理后应为空文件，实际:\n%s", got)
	}
}

// TestNormalizeGitRewrite：非法/空档位一律回落到最安全的默认档。
func TestNormalizeGitRewrite(t *testing.T) {
	cases := map[string]string{
		"":                 GitRewriteGitOnly,
		"   ":              GitRewriteGitOnly,
		"ssh":              GitRewriteSSH,
		"SSH":              GitRewriteSSH,
		" ssh ":            GitRewriteSSH,
		"all":              GitRewriteGitOnly, // 未知值不许放大权限
		"git@github.com":   GitRewriteGitOnly,
		"https":            GitRewriteGitOnly,
	}
	for in, want := range cases {
		if got := NormalizeGitRewrite(in); got != want {
			t.Fatalf("NormalizeGitRewrite(%q) = %q，期望 %q", in, got, want)
		}
	}
}
