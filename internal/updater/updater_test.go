package updater

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 版本比较是本包唯一的「判断逻辑」，因此覆盖得比网络路径更密：
// 这里判错的后果是「误报有新版本」或「永远不提示」，两种都很烦人。
func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.9", "1.0.8", 1},
		{"1.0.8", "1.0.9", -1},
		{"v1.0.8", "1.0.8", 0},
		{"V1.0.8", "v1.0.8", 0},
		{"1.1", "1.0.9", 1},
		{"1.0.10", "1.0.9", 1},  // 数字比较，不是字符串比较
		{"1.0.8.1", "1.0.8", 1}, // 补零后 1.0.8.1 > 1.0.8.0
		{"2", "1.9.9", 1},
		{"", "", 0},
		{"", "1.0.0", -1},
		{"1.0.0", "", 1},
		{"1.0.9-beta", "1.0.9", -1}, // 预发布低于正式版
		{"1.0.9", "1.0.9-beta", 1},
		{"junk", "0.0.0", 0}, // 脏数据按 0 处理，不误报
		{"1.0.8rc1", "1.0.8", 0},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, 期望 %d", c.a, c.b, got, c.want)
		}
	}
}

func TestNormalize(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"v1.0.8", "1.0.8"},
		{" V1.0.8 ", "1.0.8"},
		{"1.0.8", "1.0.8"},
		{"", ""},
	} {
		if got := Normalize(c.in); got != c.want {
			t.Errorf("Normalize(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

// fakeRelease 启动一个假的 GitHub API，返回给定的状态码与响应体。
func fakeRelease(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			// GitHub 真实行为：没有 UA 直接 403。这里跟着校验，防止以后删掉这行头
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("GHSMART_UPDATE_API", srv.URL)
	return srv
}

func TestCheckHasUpdate(t *testing.T) {
	fakeRelease(t, http.StatusOK, `{
		"tag_name": "v1.0.9",
		"html_url": "https://github.com/djy0314/ghsmart_OpenSource/releases/tag/v1.0.9",
		"body": "修复若干问题",
		"published_at": "2026-11-05T00:00:00Z",
		"draft": false,
		"prerelease": false
	}`)

	info, err := Check(context.Background(), "1.0.8")
	if err != nil {
		t.Fatalf("Check 失败: %v", err)
	}
	if !info.HasUpdate {
		t.Fatal("1.0.8 对比 v1.0.9 应判定为有新版本")
	}
	if info.Latest != "1.0.9" || info.Tag != "v1.0.9" {
		t.Errorf("版本解析错误: latest=%q tag=%q", info.Latest, info.Tag)
	}
	if !strings.Contains(info.URL, "v1.0.9") {
		t.Errorf("Release 链接错误: %q", info.URL)
	}
}

func TestCheckSameVersionNoUpdate(t *testing.T) {
	fakeRelease(t, http.StatusOK, `{"tag_name":"v1.0.8","html_url":"https://x","draft":false,"prerelease":false}`)

	info, err := Check(context.Background(), "v1.0.8")
	if err != nil {
		t.Fatalf("Check 失败: %v", err)
	}
	if info.HasUpdate {
		t.Fatal("版本相同绝不能提示有新版本")
	}
}

func TestCheckRemoteOlderNoUpdate(t *testing.T) {
	// 典型场景：本地是测试/内测版，比线上新——不能提示「有新版」让用户降级
	fakeRelease(t, http.StatusOK, `{"tag_name":"v1.0.7","html_url":"https://x","draft":false,"prerelease":false}`)

	info, err := Check(context.Background(), "1.0.8")
	if err != nil {
		t.Fatalf("Check 失败: %v", err)
	}
	if info.HasUpdate {
		t.Fatal("远端版本更旧时不能提示更新（否则引导用户降级）")
	}
}

func TestCheckPrereleaseIgnored(t *testing.T) {
	fakeRelease(t, http.StatusOK, `{"tag_name":"v2.0.0","html_url":"https://x","draft":false,"prerelease":true}`)

	info, err := Check(context.Background(), "1.0.8")
	if err != nil {
		t.Fatalf("Check 失败: %v", err)
	}
	if info.HasUpdate {
		t.Fatal("预发布版不应提示给普通用户")
	}
}

func TestCheckHTTPError(t *testing.T) {
	// 403 限流是最常见的情况：必须返回错误由调用方静默吞掉，不能 panic
	fakeRelease(t, http.StatusForbidden, `{"message":"API rate limit exceeded"}`)

	if _, err := Check(context.Background(), "1.0.8"); err == nil {
		t.Fatal("非 200 应返回 error")
	}
}

func TestCheckBadJSON(t *testing.T) {
	fakeRelease(t, http.StatusOK, `not json at all`)
	if _, err := Check(context.Background(), "1.0.8"); err == nil {
		t.Fatal("非法 JSON 应返回 error")
	}
}

func TestCheckMissingTag(t *testing.T) {
	fakeRelease(t, http.StatusOK, `{"html_url":"https://x"}`)
	if _, err := Check(context.Background(), "1.0.8"); err == nil {
		t.Fatal("缺少 tag_name 应返回 error")
	}
}

func TestCheckDisabledByEnv(t *testing.T) {
	t.Setenv("GHSMART_NO_UPDATE_CHECK", "1")
	if _, err := Check(context.Background(), "1.0.8"); err == nil {
		t.Fatal("环境变量关闭后应直接返回 error")
	}
}

func TestCheckEmptyCurrent(t *testing.T) {
	// 本地版本号是空的时候无法比较，必须拒绝而不是当成 0 去比
	if _, err := Check(context.Background(), "  "); err == nil {
		t.Fatal("本地版本为空应返回 error")
	}
}

func TestCheckTimeout(t *testing.T) {
	// 慢服务：函数必须按 ctx 超时返回，不能挂住启动流程
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		_, _ = w.Write([]byte(`{"tag_name":"v9.9.9"}`))
	}))
	defer srv.Close()
	t.Setenv("GHSMART_UPDATE_API", srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := Check(ctx, "1.0.8"); err == nil {
		t.Fatal("超时应返回 error")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("超时未被遵守，耗时 %v", d)
	}
}

func TestEnabled(t *testing.T) {
	t.Setenv("GHSMART_NO_UPDATE_CHECK", "")
	if !Enabled() {
		t.Fatal("未设置时默认应启用")
	}
	t.Setenv("GHSMART_NO_UPDATE_CHECK", "0")
	if !Enabled() {
		t.Fatal("0 视为启用")
	}
	t.Setenv("GHSMART_NO_UPDATE_CHECK", "1")
	if Enabled() {
		t.Fatal("1 应关闭")
	}
}

func TestTruncateRunes(t *testing.T) {
	// 中文按 rune 截断，不能切出半个字（否则界面出现乱码方块）
	s := strings.Repeat("中", 10)
	got := truncate(s, 3)
	if []rune(got)[0] != '中' || !strings.HasSuffix(got, "…") {
		t.Fatalf("截断结果异常: %q", got)
	}
	if truncate("ab", 10) != "ab" {
		t.Fatal("短文本不应被改动")
	}
}
