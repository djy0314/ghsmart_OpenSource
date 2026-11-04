package main

// app_opt_test.go 验证 v1.0.8 三个设置开关的「接线」：
// 前端点一下开关，后端必须真的把 git 配置写下去/撤回来，
// 而不是只把状态存进 json 就完事。

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"ghsmart/internal/executor"
)

// executorApplyGitSSH 预置「旧版行为」：三条 insteadOf 全写。
func executorApplyGitSSH() error {
	return executor.ApplyGit(executor.GitRewriteSSH)
}

// runGitCmd 直接跑 git 命令（测试里造外部改动用）。
func runGitCmd(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// optTestApp 准备一个隔离的 App：git 配置与授权状态文件都指向临时目录。
func optTestApp(t *testing.T) (*App, string) {
	t.Helper()
	dir := t.TempDir()
	gitCfg := filepath.Join(dir, "gitconfig")
	t.Setenv("GIT_CONFIG_GLOBAL", gitCfg)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	t.Setenv("GHSMART_LICENSE_FILE", filepath.Join(dir, "license.json"))
	// 日志写到一个不参与 TempDir 清理的位置：后台 goroutine 可能在
	// 测试结束瞬间仍在 logf，句柄来不及关会让 TempDir 删不掉（Windows 文件占用）。
	logDir := filepath.Join(os.TempDir(), "ghsmart-test-logs")
	_ = os.MkdirAll(logDir, 0o755)
	t.Setenv("GHSMART_LOG_FILE", filepath.Join(logDir, "app_opt.log"))
	a := NewApp()
	t.Cleanup(a.closeLog)
	return a, gitCfg
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("读取 %s 失败: %v", p, err)
	}
	return string(b)
}

// TestSetGitHTTPSWritesAndReverts 是本次最重要的回归断言：
// 打开开关必须写 git@github.com: 改写，关掉必须立刻删掉。
// 这两个方向任何一边错了，用户的 git push 都会遭殃。
func TestSetGitHTTPSWritesAndReverts(t *testing.T) {
	a, gitCfg := optTestApp(t)

	if _, err := a.SetGitHTTPS(true); err != nil {
		t.Fatalf("开启 Git HTTPS 模式失败: %v", err)
	}
	on := readFile(t, gitCfg)
	if !strings.Contains(on, "git@github.com:") {
		t.Fatalf("开启后应写入 SSH 改写，实际配置:\n%s", on)
	}

	if _, err := a.SetGitHTTPS(false); err != nil {
		t.Fatalf("关闭 Git HTTPS 模式失败: %v", err)
	}
	off := readFile(t, gitCfg)
	if strings.Contains(off, "git@github.com:") {
		t.Fatalf("关闭后 SSH 改写必须被删除，实际配置:\n%s", off)
	}
	// 默认档的 git:// 改写可以留着（对 SSH 无影响）
}

// TestSetGitHTTPSPersists 验证状态持久化：下次启动能按上次选择恢复。
func TestSetGitHTTPSPersists(t *testing.T) {
	a, _ := optTestApp(t)
	if _, err := a.SetGitHTTPS(true); err != nil {
		t.Fatalf("开启失败: %v", err)
	}
	st := a.loadLicenseState()
	if !st.GitHTTPS {
		t.Fatalf("GitHTTPS 未持久化，状态为: %+v", st)
	}
	if a.gitLevel() != "ssh" {
		t.Fatalf("档位应为 ssh，实际 %q", a.gitLevel())
	}
}

// TestDefaultGitLevelIsSafe 验证「从没点过开关」的默认状态不会改写 SSH。
func TestDefaultGitLevelIsSafe(t *testing.T) {
	a, _ := optTestApp(t)
	if a.gitLevel() != "git" {
		t.Fatalf("默认档位必须是 git（不改 SSH），实际 %q", a.gitLevel())
	}
}

// TestSetCLIProxyEnvPersists：环境变量开关只记意愿，不该在深度加速未开时乱写注册表。
func TestSetCLIProxyEnvPersists(t *testing.T) {
	a, _ := optTestApp(t)
	if _, err := a.SetCLIProxyEnv(true); err != nil {
		t.Fatalf("开启命令行加速失败: %v", err)
	}
	if !a.loadLicenseState().CLIProxyEnv {
		t.Fatalf("CLIProxyEnv 未持久化")
	}
	// 深度加速没开 → syncCLIProxy 走 RemoveCLIProxy 分支，不该 panic
	if _, err := a.SetCLIProxyEnv(false); err != nil {
		t.Fatalf("关闭命令行加速失败: %v", err)
	}
	if a.loadLicenseState().CLIProxyEnv {
		t.Fatalf("关闭后状态应回到 false")
	}
}

// TestProStateExposesNewSwitches：界面靠这几个字段渲染，少一个开关就永远显示关闭。
func TestProStateExposesNewSwitches(t *testing.T) {
	a, _ := optTestApp(t)
	st := a.proState()
	for _, k := range []string{"gitHTTPS", "cliProxyEnv", "autoStart", "autoStartMode", "autoStartNeedsUAC"} {
		if _, ok := st[k]; !ok {
			t.Fatalf("proState 缺少字段 %q（前端将无法渲染该开关），实际字段: %v", k, keysOf(st))
		}
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestMigrateGit108RemovesLegacySSH 是老用户升级路径的关键断言：
// 旧版遗留的 SSH 改写必须被清掉，否则「修了 bug 但用户的 push 还是坏的」。
func TestMigrateGit108RemovesLegacySSH(t *testing.T) {
	a, gitCfg := optTestApp(t)

	// 模拟 v1.0.7 的遗留：三条 insteadOf 全在
	if err := executorApplyGitSSH(); err != nil {
		t.Fatalf("预置旧版配置失败: %v", err)
	}
	if !strings.Contains(readFile(t, gitCfg), "git@github.com:") {
		t.Fatalf("预置失败：旧版配置里应有 SSH 改写")
	}

	// 模拟升级后首次启动：license 里没有 migrated_108，也没有 git_https
	st := a.migrateGit108(licenseState{})
	if !st.Migrated108 {
		t.Fatalf("迁移后应写入标记")
	}
	got := readFile(t, gitCfg)
	if strings.Contains(got, "git@github.com:") {
		t.Fatalf("旧版遗留的 SSH 改写未被清除，用户 push 依旧是坏的:\n%s", got)
	}
}

// TestMigrateGit108KeepsOptInSSH：用户确实勾选了 HTTPS 模式时，迁移后要保留。
func TestMigrateGit108KeepsOptInSSH(t *testing.T) {
	a, gitCfg := optTestApp(t)
	st := a.migrateGit108(licenseState{GitHTTPS: true})
	if !st.Migrated108 {
		t.Fatalf("迁移后应写入标记")
	}
	if !strings.Contains(readFile(t, gitCfg), "git@github.com:") {
		t.Fatalf("用户选择 HTTPS 模式时不应被迁移逻辑清掉")
	}
}

// TestMigrateGit108RunsOnce：已迁移过且未开 HTTPS 时，不该再动 git 配置。
func TestMigrateGit108RunsOnce(t *testing.T) {
	a, gitCfg := optTestApp(t)
	// 先迁移一次
	a.migrateGit108(licenseState{})
	before := readFile(t, gitCfg)

	// 用户后来自己手工配了一条（模拟外部改动）
	if out, err := runGitCmd("config", "--global", "user.marker", "keep-me"); err != nil {
		t.Fatalf("预置失败: %v %s", err, out)
	}
	mid := readFile(t, gitCfg)

	// 再次启动：已迁移过，不应重写 git 配置
	a.migrateGit108(licenseState{Migrated108: true})
	after := readFile(t, gitCfg)
	if mid != after {
		t.Fatalf("已迁移过时不应再改动 git 配置\n之前:\n%s\n之后:\n%s", mid, after)
	}
	if !strings.Contains(before, "git://github.com/") && !strings.Contains(before, "insteadOf") {
		t.Logf("首次迁移后的配置: %q", before)
	}
}
