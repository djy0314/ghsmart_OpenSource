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

// TestApplyGitWritesInsteadOf：ApplyGit 写入三条精确的 insteadOf 改写。
func TestApplyGitWritesInsteadOf(t *testing.T) {
	p := isolatedGit(t)
	if err := ApplyGit(nil); err != nil {
		t.Fatalf("ApplyGit 失败: %v", err)
	}
	got := readGitConfig(t, p)
	for _, want := range gitInsteadOfValues {
		if !strings.Contains(got, gitInsteadOfBase+"\n\t"+want) &&
			!strings.Contains(got, want) {
			t.Fatalf("缺少 insteadOf 条目 %q，配置为:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "[url") || !strings.Contains(got, "https://github.com/") {
		t.Fatalf("缺少 url 小节，配置为:\n%s", got)
	}
}

// TestApplyGitIdempotent：重复 ApplyGit 不产生重复条目。
func TestApplyGitIdempotent(t *testing.T) {
	p := isolatedGit(t)
	if err := ApplyGit(nil); err != nil {
		t.Fatalf("第一次 ApplyGit 失败: %v", err)
	}
	if err := ApplyGit(nil); err != nil {
		t.Fatalf("第二次 ApplyGit 失败: %v", err)
	}
	got := readGitConfig(t, p)
	if n := strings.Count(got, "git@github.com:"); n != 1 {
		t.Fatalf("git@github.com: 应恰好出现 1 次，实际 %d 次:\n%s", n, got)
	}
}

// TestRemoveGitOnlyRemovesOwnValues：清理只删 ghsmart 的三条值，
// 用户自己配置的 insteadOf 原样保留。
func TestRemoveGitOnlyRemovesOwnValues(t *testing.T) {
	p := isolatedGit(t)
	if err := ApplyGit(nil); err != nil {
		t.Fatalf("ApplyGit 失败: %v", err)
	}
	// 模拟用户自己的一条 insteadOf（不同 base，ghsmart 不应触碰）
	if out, err := runGit("config", "--global",
		"url.https://ghfast.example/.insteadOf", "https://mirror-user.com/"); err != nil {
		t.Fatalf("预置用户配置失败: %v %s", err, out)
	}

	if err := RemoveGit(nil); err != nil {
		t.Fatalf("RemoveGit 失败: %v", err)
	}

	got := readGitConfig(t, p)
	for _, v := range gitInsteadOfValues {
		if strings.Contains(got, "\t"+v+"\n") || strings.Contains(got, "\t"+v) {
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
	if err := RemoveGit(nil); err != nil {
		t.Fatalf("空配置 RemoveGit 不应报错: %v", err)
	}
	if err := RemoveGit(nil); err != nil {
		t.Fatalf("重复 RemoveGit 不应报错: %v", err)
	}
	if got := readGitConfig(t, p); got != "" {
		t.Fatalf("空配置清理后应为空文件，实际:\n%s", got)
	}
}
