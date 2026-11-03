package webproxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// deadIP 是不可路由的占位 IP：拨号必然挂起直到超时（模拟「全部候选被拦/超时」）。
const deadIP = "10.255.255.1"

// proxiedClient 构造走本地代理的 HTTPS 客户端。
func proxiedClient(addr string) *http.Client {
	pu, _ := url.Parse("http://" + addr)
	return &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(pu),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// TestAutoFallbackFiresAfterConsecutiveAllFail：管辖域名连续 3 条 CONNECT
// 全部候选失败 → OnAutoFallback 恰好触发一次，reason 非空。
func TestAutoFallbackFiresAfterConsecutiveAllFail(t *testing.T) {
	fired := make(chan string, 1)
	srv := New(Options{
		Listen:      "127.0.0.1:0",
		Hosts:       []string{"github.com"},
		Resolve:     func(string) []string { return []string{deadIP} },
		DialTimeout: 200 * time.Millisecond,
		OnAutoFallback: func(reason string) {
			select {
			case fired <- reason:
			default:
			}
		},
	})
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}
	defer srv.Stop()

	client := proxiedClient(addr)
	for i := 0; i < autoFallbackThreshold; i++ {
		resp, err := client.Get("https://github.com/") // 端口无所谓：候选全是死 IP，连哪个端口都失败
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("第 %d 个请求不应成功（候选是死 IP）", i+1)
		}
	}

	select {
	case reason := <-fired:
		if reason == "" {
			t.Fatal("回调 reason 不应为空")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("连续全败达阈值后未触发自动避让回调")
	}

	// 只触发一次：再补两条全败请求，不得重复回调
	for i := 0; i < 2; i++ {
		resp, _ := client.Get("https://github.com/")
		if resp != nil {
			_ = resp.Body.Close()
		}
	}
	select {
	case r := <-fired:
		t.Fatalf("自动避让不应重复触发，却收到了: %q", r)
	case <-time.After(300 * time.Millisecond):
	}
}

// TestAutoFallbackResetsOnSuccess：失败 2 次 → 成功 1 次 → 再失败 2 次，
// 连败计数被成功清零，绝不能触发自动避让（防误杀偶发抖动）。
func TestAutoFallbackResetsOnSuccess(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	upIP, upPort, _ := net3(upstream)
	// 必须带上 upstream 的真实端口：CONNECT github.com:443 会让代理拨 <IP>:443，
	// 而沙箱本机 443 上恰好有别的服务在听，测试会「假成功」。带上端口才真正指向 upstream。
	upHostPort := "github.com:" + upPort

	var useGood bool
	setGood := func(v bool) { useGood = v }

	fired := make(chan string, 1)
	var logMu sync.Mutex
	var logBuf []string
	srv := New(Options{
		Listen: "127.0.0.1:0",
		Hosts:  []string{"github.com"},
		Logf: func(f string, a ...any) {
			logMu.Lock()
			logBuf = append(logBuf, fmt.Sprintf(f, a...))
			logMu.Unlock()
		},
		Resolve: func(string) []string {
			if useGood {
				return []string{deadIP, upIP} // 死 IP 在前也该由竞速兜住
			}
			return []string{deadIP}
		},
		DialTimeout: 300 * time.Millisecond,
		OnAutoFallback: func(reason string) {
			select {
			case fired <- reason:
			default:
			}
		},
	})
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}
	defer srv.Stop()

	client := proxiedClient(addr)
	// fail 每次都用全新 client：强制走一条新 CONNECT，
	// 避免连接池复用已建好的隧道而根本不触发代理拨号。
	fail := func(tag string) {
		c := proxiedClient(addr)
		defer c.CloseIdleConnections()
		resp, err := c.Get("https://" + upHostPort + "/")
		if err == nil {
			_ = resp.Body.Close()
			logMu.Lock()
			for _, l := range logBuf {
				t.Logf("PROXY: %s", l)
			}
			logMu.Unlock()
			t.Fatalf("全败场景下请求不应成功（%s）", tag)
		}
	}

	fail("pre-1")
	fail("pre-2")

	setGood(true)
	resp, err := client.Get("https://" + upHostPort + "/")
	if err != nil {
		t.Fatalf("成功场景请求失败: %v", err)
	}
	_ = resp.Body.Close()

	// 关掉 upstream：让 good 记忆里的 127.0.0.1 也连不上，之后的请求才是真「全败」
	setGood(false)
	upstream.Close()
	fail("post-1")
	fail("post-2")

	select {
	case r := <-fired:
		t.Fatalf("成功清零后不应触发自动避让，却收到了: %q", r)
	case <-time.After(500 * time.Millisecond):
	}
	logMu.Lock()
	defer logMu.Unlock()
	for _, l := range logBuf {
		t.Logf("PROXY: %s", l)
	}
}

// net3 从 httptest server 取 host/port（IP 字面量形式）。
func net3(s *httptest.Server) (string, string, error) {
	addr := s.Listener.Addr().String()
	host, port, err := net.SplitHostPort(addr)
	return host, port, err
}
