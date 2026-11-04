//go:build windows

// cliproxy_windows_test.go 用注入的内存 envStore 隔离，
// 绝不读写真实的 HKCU\Environment。
package executor

import (
	"path/filepath"
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

// useMemEnv 把环境变量与广播都换成内存实现，
// 并把「写入记录文件」也重定向到临时目录（否则测试会写真实 ~/.ghsmart）。
func useMemEnv(t *testing.T) (memEnv, *int) {
	t.Helper()
	t.Setenv("GHSMART_CLIPROXY_FILE", filepath.Join(t.TempDir(), "cliproxy_git.json"))
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

// TestRemoveCLIProxyClearsStalePorts 是 v1.0.8 开发中真实踩坑的回归：
// 旧实现按「端口等于固定值」删除，端口一变旧条目就永久残留，
// 结果 ~/.gitconfig 里累积了 6 条指向已关闭端口的代理，git 彻底连不上。
// 现在必须做到：不管端口是多少，只要是本机回环就清掉。
func TestRemoveCLIProxyClearsStalePorts(t *testing.T) {
	p := isolatedGit(t)
	useMemEnv(t)

	stale := []string{
		"http://127.0.0.1:42649",
		"http://127.0.0.1:30970",
		"http://localhost:18080",
		"http://[::1]:12000",
	}
	for _, v := range stale {
		if out, err := runGit("config", "--global", "--add", gitProxyKey, v); err != nil {
			t.Fatalf("预置 %s 失败: %v %s", v, err, out)
		}
	}
	got := readGitConfig(t, p)
	if !strings.Contains(got, "42649") {
		t.Fatalf("预置失败，配置里应有残留:\n%s", got)
	}

	if err := RemoveCLIProxy(); err != nil {
		t.Fatalf("RemoveCLIProxy 失败: %v", err)
	}
	after := readGitConfig(t, p)
	for _, v := range stale {
		if strings.Contains(after, v) {
			t.Fatalf("残留条目 %s 未被清除（会导致 git 全不可用）:\n%s", v, after)
		}
	}
}

// TestRemoveCLIProxyKeepsRemoteProxy：用户自己配置的「公网/公司」代理必须保留，
// 只有指向本机的才算我们的。
func TestRemoveCLIProxyKeepsRemoteProxy(t *testing.T) {
	p := isolatedGit(t)
	useMemEnv(t)

	const userProxy = "http://proxy.corp.example:8080"
	if out, err := runGit("config", "--global", "--add", gitProxyKey, userProxy); err != nil {
		t.Fatalf("预置用户代理失败: %v %s", err, out)
	}
	// 同时存在我们写的一条
	if out, err := runGit("config", "--global", "--add", gitProxyKey, "http://127.0.0.1:18080"); err != nil {
		t.Fatalf("预置我方代理失败: %v %s", err, out)
	}

	_ = RemoveCLIProxy()
	after := readGitConfig(t, p)
	if strings.Contains(after, "127.0.0.1:18080") {
		t.Fatalf("我方回环代理应被清除:\n%s", after)
	}
	if !strings.Contains(after, userProxy) {
		t.Fatalf("用户自己的公网代理被误删:\n%s", after)
	}
}

// TestIsLoopbackProxy：回环识别（含 IPv6、用户名密码、大小写）。
func TestIsLoopbackProxy(t *testing.T) {
	yes := []string{
		"http://127.0.0.1:18080",
		"127.0.0.1:18080",
		"http://localhost:7890",
		"HTTP://LOCALHOST:1",
		"http://[::1]:8080",
		"http://user:pass@127.0.0.1:3128",
	}
	no := []string{
		"http://proxy.corp.example:8080",
		"http://10.0.0.5:3128",
		"http://192.168.1.1:8080",
		"socks5://127.0.0.2:1080",
		"",
	}
	for _, v := range yes {
		if !isLoopbackProxy(v) {
			t.Fatalf("%q 应判定为本机回环", v)
		}
	}
	for _, v := range no {
		if isLoopbackProxy(v) {
			t.Fatalf("%q 不应判定为本机回环（会被误删）", v)
		}
	}
}
