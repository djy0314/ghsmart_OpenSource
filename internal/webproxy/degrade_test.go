package webproxy

// 「静默降级」回归：分片被中间设备连续掐断时代理自己切隧道，
// 用户无感；一次成功就把连败清零，绝不允许抖动误降级。

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// resetServer 模拟「TLS 握手被中间设备重置」：接受 TCP 后立刻关闭。
func resetServer(t *testing.T) (ip string, port string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动重置服务器失败: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close() // 立即断开 = 握手被 RST
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return "127.0.0.1", portOf(ln.Addr().String())
}

func portOf(addr string) string {
	_, p, _ := net.SplitHostPort(addr)
	return p
}

// degradeProxy 起一个指向 127.0.0.1 的代理（所有候选都是本机，端口由 CONNECT 决定）。
func degradeProxy(t *testing.T, degradeAfter int, onDegrade func(string)) (*Server, string) {
	t.Helper()
	srv := New(Options{
		Listen:            "127.0.0.1:0",
		Hosts:             []string{"github.com"},
		Resolve:           func(string) []string { return []string{"127.0.0.1"} },
		DialTimeout:       300 * time.Millisecond,
		DegradeAfter:      degradeAfter,
		OnDegrade:         onDegrade,
		HandshakeWait:     200 * time.Millisecond,
		HandshakeBudget:   600 * time.Millisecond,
		PlainFallbackWait: 100 * time.Millisecond,
	})
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}
	return srv, addr
}

// httpsClient 走本地代理；CONNECT 的目标端口由 URL 决定（代理按该端口拨候选 IP）。
func httpsClient(t *testing.T, addr string) *http.Client {
	t.Helper()
	pu, _ := url.Parse("http://" + addr)
	return &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(pu),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// TestDegradeAfterConsecutiveHandshakeResets：连续 3 次「TCP 能连上但握手被重置」
// → 触发一次 OnDegrade、Degraded 置位，之后的连接不再尝试分片。
func TestDegradeAfterConsecutiveHandshakeResets(t *testing.T) {
	ip, port := resetServer(t)
	_ = ip
	fired := make(chan string, 1)
	srv, addr := degradeProxy(t, 3, func(reason string) {
		select {
		case fired <- reason:
		default:
		}
	})
	defer srv.Stop()

	client := httpsClient(t, addr)
	for i := 0; i < 3; i++ {
		c := httpsClient(t, addr)
		resp, err := c.Get("https://github.com:"+port+"/")
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("第 %d 个请求不应成功（握手必被重置）", i+1)
		}
		_ = client
	}

	select {
	case reason := <-fired:
		if reason == "" {
			t.Fatal("降级回调 reason 不应为空")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("连续握手失败达阈值后未触发降级回调")
	}
	if !srv.Degraded() {
		t.Fatal("降级后 Degraded() 必须为 true")
	}
	splitBefore := srv.Stats().Split

	// 降级后再来一条：即使上游还是那个 reset 服务，也不许再碰分片
	c := httpsClient(t, addr)
	resp, err := c.Get("https://github.com:" + port + "/")
	if err == nil {
		_ = resp.Body.Close()
	}
	if got := srv.Stats().Split; got != splitBefore {
		t.Fatalf("降级后不应再尝试分片：之前 %d，之后 %d", splitBefore, got)
	}
}

// TestDegradeResetsOnSuccess：失败 2 次 → 成功 1 次 → 再失败 2 次，
// 连败被成功清零，绝不能触发降级（防偶发抖动误判）。
func TestDegradeResetsOnSuccess(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	upPort := portOf(upstream.Listener.Addr().String())
	resetIP, resetPort := resetServer(t)
	_ = resetIP

	// good 控制候选里是否有真上游（真上游端口与 reset 端口不同，
	// 通过 CONNECT 目标端口区分：good 用 upstream 端口，fail 用 reset 端口）
	var fired int
	srv, addr := degradeProxy(t, 3, func(string) { fired++ })
	defer srv.Stop()

	fail := func(port, tag string) {
		c := httpsClient(t, addr)
		defer c.CloseIdleConnections()
		resp, err := c.Get("https://github.com:" + port + "/")
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("全败场景不应成功（%s）", tag)
		}
	}

	fail(resetPort, "pre-1")
	fail(resetPort, "pre-2")

	// 成功一次：真 TLS 上游，握手能走通
	okClient := httpsClient(t, addr)
	resp, err := okClient.Get("https://github.com:" + upPort + "/")
	if err != nil {
		t.Fatalf("成功场景请求失败: %v", err)
	}
	_ = resp.Body.Close()

	fail(resetPort, "post-1")
	fail(resetPort, "post-2")

	if srv.Degraded() {
		t.Fatal("成功清零后不应触发降级")
	}
	if fired != 0 {
		t.Fatalf("降级回调不应触发，实际 %d 次", fired)
	}
}
