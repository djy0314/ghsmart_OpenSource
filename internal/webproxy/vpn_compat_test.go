package webproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// contains 是测试里的小工具（避免为了一处断言引入 strings 依赖混乱）。
func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

// TestCompatModeDisablesSplit：兼容模式（DisableSplit）下，
// 命中分片名单的域名也不做 TLS 分片，纯 CONNECT 隧道直通；
// 且管辖判定不受影响（isManaged 仍为 true，拨号规则保持「只按优选 IP」）。
func TestCompatModeDisablesSplit(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "compat-ok")
	}))
	defer upstream.Close()

	srv, addr, rec := startProxy(t, []string{"github.com"}, upstream.Listener.Addr().String(), Splitter{Window: 0})
	srv.opts.DisableSplit = true // 请求期读取，启动后打开即模拟「兼容模式」
	client := newClient(t, addr, upstream)

	resp, err := client.Get("https://github.com/")
	if err != nil {
		t.Fatalf("兼容模式下经代理请求失败: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "compat-ok" {
		t.Fatalf("响应异常: %d %q", resp.StatusCode, body)
	}

	st := srv.Stats()
	if st.Split != 0 {
		t.Fatalf("兼容模式绝不能分片，实际 split=%d", st.Split)
	}
	if st.Pass == 0 {
		t.Fatalf("兼容模式应按直通计数，实际 pass=%d", st.Pass)
	}
	for _, n := range rec.snapshot() {
		if n == 1 {
			t.Fatalf("兼容模式出现了 1 字节写入，说明仍在分片: %v", rec.snapshot())
		}
	}
	// 管辖判定必须与分片开关解耦
	if !srv.isManaged("github.com") {
		t.Fatal("兼容模式不得改变管辖判定（否则退回系统解析会踩失效 hosts）")
	}
	if srv.shouldSplit("github.com") {
		t.Fatal("兼容模式应关闭分片")
	}
}

// TestDialRaceBoundEntrants：LocalAddrs 绑定源地址的竞速入口——
// loopback 绑定能正常建连（证明绑定拨号路径本身是通的）。
func TestDialRaceBoundEntrants(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close() // 只需建连成功，无需通信
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	s := New(Options{DialTimeout: 2 * time.Second, LocalAddrs: []string{host}})
	conn, via, _ := s.dialRace(context.Background(), []string{host}, portStr)
	if conn == nil {
		t.Fatal("绑定 127.0.0.1 源地址的竞速入口应能建连")
	}
	defer conn.Close()
	if !contains(via, host) {
		t.Fatalf("via 应包含候选 IP %q，实际 %q", host, via)
	}
}

// TestDialRaceBogusLocalAddr：非法源地址（TEST-NET，不可能是本机地址）的
// 绑定入口必须立即失败并被竞速淘汰，整体仍由普通入口建连成功——
// 这证明绑定机制对健康机器零副作用。
func TestDialRaceBogusLocalAddr(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	s := New(Options{DialTimeout: 2 * time.Second, LocalAddrs: []string{"203.0.113.99"}})
	start := time.Now()
	conn, _, _ := s.dialRace(context.Background(), []string{host}, portStr)
	if conn == nil {
		t.Fatal("非法源地址入口失败后，普通入口应照常建连")
	}
	defer conn.Close()
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("竞速被非法源地址拖慢: %v", elapsed)
	}
}

// TestVpnCompatEndToEnd：兼容模式 + 绑定源地址全链路——
// 普通 Dial 被整体拒死，只有「绑定源地址」的真实拨号入口能到达上游，
// 证明 VPN 劫持场景下绑定路径能独立撑起整条隧道。
func TestVpnCompatEndToEnd(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "e2e-ok")
	}))
	defer upstream.Close()

	upAddr := upstream.Listener.Addr().String()
	upHost, upPort, _ := net.SplitHostPort(upAddr)

	srv := New(Options{
		Listen:       "127.0.0.1:0",
		Split:        Splitter{Window: 0},
		Hosts:        []string{"github.com"},
		DisableSplit: true,
		LocalAddrs:   []string{"127.0.0.1"},
		Resolve: func(host string) []string {
			return []string{upHost} // 候选只放 IP 字面量（上游 loopback）
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// 普通拨号入口全部拒绝：模拟「默认路由被 VPN 虚拟网卡劫持」，
			// 只有绑定源地址的入口（dialIPBound 走真实 Dialer）能连上
			return nil, errors.New("模拟被 VPN 劫持的普通路径")
		},
	})
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	pu, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(pu),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	// CONNECT 目标是 IP 字面量 + 上游端口，命中 dialIP 竞速路径
	resp, err := client.Get("https://" + net.JoinHostPort(upHost, upPort) + "/")
	if err != nil {
		t.Fatalf("绑定竞速端到端请求失败: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "e2e-ok" {
		t.Fatalf("响应体异常: %q", body)
	}
}
