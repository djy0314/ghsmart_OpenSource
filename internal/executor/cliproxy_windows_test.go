//go:build windows

// cliproxy_windows_test.go 用注入的内存 envStore 隔离，
// 绝不读写真实的 HKCU\Environment。
package executor

import (
	"strings"
	"testing"
)

// memEnv 是内存版用户环境变量。
type memEnv map[string]string

func (m memEnv) Get(name string) (string, bool) {
	v, ok := m[name]
	return v, ok
}
func (m memEnv) Set(name, value string) error { m[name] = value; return nil }
func (m memEnv) Del(name string) error        { delete(m, name); return nil }

// useMemEnv 把环境变量与广播都换成内存实现。
func useMemEnv(t *testing.T) (memEnv, *int) {
	t.Helper()
	m := memEnv{}
	n := 0
	oldStore, oldBcast := envStoreFn, broadcastEnv
	envStoreFn = func() (envStore, error) { return m, nil }
	broadcastEnv = func() { n++ }
	t.Cleanup(func() { envStoreFn, broadcastEnv = oldStore, oldBcast })
	return m, &n
}

// TestApplyCLIProxyUsesURLScopedGitKey 是最关键的安全断言：
// git 代理必须写成 http.https://github.com.proxy（只影响 github.com），
// 绝不能是裸 http.proxy——裸键会把公司内网仓库也推给本地代理。
func TestApplyCLIProxyUsesURLScopedGitKey(t *testing.T) {
	p := isolatedGit(t)
	useMemEnv(t)

	res, err := ApplyCLIProxy("127.0.0.1:18080", false)
	if err != nil {
		t.Fatalf("ApplyCLIProxy 失败: %v", err)
	}
	if !res.GitApplied {
		t.Fatalf("git 代理应写入成功，结果: %+v", res)
	}
	got := readGitConfig(t, p)
	if !strings.Contains(got, "[http \"https://github.com\"]") {
		t.Fatalf("应写入按 URL 限定的 http 小节，实际:\n%s", got)
	}
	if !strings.Contains(got, "http://127.0.0.1:18080") {
		t.Fatalf("缺少代理地址，实际:\n%s", got)
	}
	// 裸 http.proxy 会匹配所有 URL，必须确保没被写成这种形式
	if hasBareHTTPProxy(t, got) {
		t.Fatalf("绝不能写裸 http.proxy（会劫持内网仓库），实际:\n%s", got)
	}
}

// hasBareHTTPProxy 判断配置里是否存在不带 URL 限定的 http.proxy 键。
func hasBareHTTPProxy(t *testing.T, cfg string) bool {
	t.Helper()
	out, err := runGit("config", "--global", "--get-all", "http.proxy")
	if err != nil {
		return false // 键不存在正是我们要的结果
	}
	return strings.TrimSpace(out) != ""
}

// TestApplyCLIProxyEnvGuardSkipsExisting：
// 用户已有别的代理环境变量时，必须整体跳过，一个都不改。
func TestApplyCLIProxyEnvGuardSkipsExisting(t *testing.T) {
	isolatedGit(t)
	m, _ := useMemEnv(t)
	m["HTTP_PROXY"] = "http://127.0.0.1:7890" // 模拟 Clash

	res, err := ApplyCLIProxy("127.0.0.1:18080", true)
	if err != nil {
		t.Fatalf("ApplyCLIProxy 失败: %v", err)
	}
	if res.EnvApplied {
		t.Fatalf("检测到用户已有代理时不应写环境变量")
	}
	if res.Skipped == "" {
		t.Fatalf("跳过原因必须如实回报给界面")
	}
	if m["HTTP_PROXY"] != "http://127.0.0.1:7890" {
		t.Fatalf("用户原有 HTTP_PROXY 被覆盖: %v", m["HTTP_PROXY"])
	}
	if _, ok := m["HTTPS_PROXY"]; ok {
		t.Fatalf("跳过后不应写入 HTTPS_PROXY")
	}
}

// TestApplyCLIProxyEnvWritesWhenClean：干净环境下写入三个变量。
func TestApplyCLIProxyEnvWritesWhenClean(t *testing.T) {
	isolatedGit(t)
	m, n := useMemEnv(t)

	res, err := ApplyCLIProxy("127.0.0.1:18080", true)
	if err != nil {
		t.Fatalf("ApplyCLIProxy 失败: %v", err)
	}
	if !res.EnvApplied {
		t.Fatalf("干净环境应写入环境变量，结果: %+v", res)
	}
	if m["HTTP_PROXY"] != "http://127.0.0.1:18080" || m["HTTPS_PROXY"] != "http://127.0.0.1:18080" {
		t.Fatalf("HTTP(S)_PROXY 写入不正确: %v", m)
	}
	if !strings.Contains(m["NO_PROXY"], "127.0.0.1") {
		t.Fatalf("NO_PROXY 应包含本机，实际: %q", m["NO_PROXY"])
	}
	if *n != 1 {
		t.Fatalf("应广播一次环境变量变更，实际 %d 次", *n)
	}
}

// TestRemoveCLIProxyRestoresUserEnv：清理只删我方值，用户后改的值不动。
func TestRemoveCLIProxyRestoresUserEnv(t *testing.T) {
	p := isolatedGit(t)
	m, _ := useMemEnv(t)

	if _, err := ApplyCLIProxy("127.0.0.1:18080", true); err != nil {
		t.Fatalf("ApplyCLIProxy 失败: %v", err)
	}
	// 用户中途自己改成了别的代理
	m["HTTPS_PROXY"] = "http://127.0.0.1:7890"

	if err := RemoveCLIProxy(); err != nil {
		t.Fatalf("RemoveCLIProxy 失败: %v", err)
	}
	if _, ok := m["HTTP_PROXY"]; ok {
		t.Fatalf("我方写入的 HTTP_PROXY 应被删除")
	}
	if m["HTTPS_PROXY"] != "http://127.0.0.1:7890" {
		t.Fatalf("用户后来自己改的 HTTPS_PROXY 被误删: %v", m["HTTPS_PROXY"])
	}
	if got := readGitConfig(t, p); strings.Contains(got, "127.0.0.1:18080") {
		t.Fatalf("git 代理未清理:\n%s", got)
	}
}

// TestRemoveCLIProxyKeepsUserOwnGitProxy：用户自己配的 https://github.com 代理不能被删。
func TestRemoveCLIProxyKeepsUserOwnGitProxy(t *testing.T) {
	p := isolatedGit(t)
	useMemEnv(t)

	// 用户自己配的（不同值）
	if out, err := runGit("config", "--global", gitProxyKey, "http://127.0.0.1:7890"); err != nil {
		t.Fatalf("预置用户配置失败: %v %s", err, out)
	}
	_ = RemoveCLIProxy()

	got := readGitConfig(t, p)
	if !strings.Contains(got, "http://127.0.0.1:7890") {
		t.Fatalf("用户自己的代理被误删:\n%s", got)
	}
}

// TestToProxyURL：地址归一化。
func TestToProxyURL(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1:18080":        "http://127.0.0.1:18080",
		"http://127.0.0.1:18080": "http://127.0.0.1:18080",
		"  127.0.0.1:1  ":        "http://127.0.0.1:1",
		"":                       "",
	}
	for in, want := range cases {
		if got := toProxyURL(in); got != want {
			t.Fatalf("toProxyURL(%q) = %q，期望 %q", in, got, want)
		}
	}
}
