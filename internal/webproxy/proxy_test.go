package webproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// writeRecorder 记录代理写往「上游」的每次 Write 长度与内容，
// 用来实证「ClientHello 确实被拆成了多次写」。
type writeRecorder struct {
	mu    sync.Mutex
	sizes []int
	data  []byte
}

func (r *writeRecorder) wrap(c net.Conn) net.Conn { return &recConn{Conn: c, r: r} }

func (r *writeRecorder) snapshot() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]int, len(r.sizes))
	copy(out, r.sizes)
	return out
}

func (r *writeRecorder) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]byte, len(r.data))
	copy(out, r.data)
	return out
}

type recConn struct {
	net.Conn
	r *writeRecorder
}

func (c *recConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.r.mu.Lock()
	c.r.sizes = append(c.r.sizes, n)
	c.r.data = append(c.r.data, p...)
	c.r.mu.Unlock()
	return n, err
}

// startProxy 启动一个监听随机端口的代理，Dial 全部映射到 upstreamAddr。
func startProxy(t *testing.T, hosts []string, upstreamAddr string, split Splitter) (*Server, string, *writeRecorder) {
	t.Helper()
	rec := &writeRecorder{}
	srv := New(Options{
		Listen: "127.0.0.1:0",
		Split:  split,
		Hosts:  hosts,
		Logf:   t.Logf,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := net.Dial("tcp", upstreamAddr)
			if err != nil {
				return nil, err
			}
			return rec.wrap(c), nil
		},
	})
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })
	return srv, addr, rec
}

// newClient 构造一个走本地代理的 HTTPS 客户端。
// httptest 的自签证书只签了 example.com，本用例只验证「隧道搬运与分片」，
// 因此跳过证书校验（SNI 仍是真的 github.com，已在断言里核对）。
func newClient(t *testing.T, proxyAddr string, upstream *httptest.Server) *http.Client {
	t.Helper()
	pu, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("代理地址非法: %v", err)
	}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(pu),
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: false, // 测试只看单条 TLS 隧道
			DisableKeepAlives: true,
		},
	}
}

// 命中分片名单：CONNECT 隧道里必须把 ClientHello 拆成多段，且首段为 1 字节。
func TestConnectTunnelSplitsClientHello(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "from-upstream")
	}))
	defer upstream.Close()

	srv, addr, rec := startProxy(t, []string{"github.com"}, upstream.Listener.Addr().String(), Splitter{Window: 0})
	client := newClient(t, addr, upstream)

	resp, err := client.Get("https://github.com/")
	if err != nil {
		t.Fatalf("经代理请求失败: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "from-upstream" {
		t.Fatalf("响应异常: %d %q", resp.StatusCode, body)
	}

	sizes := rec.snapshot()
	if len(sizes) < 3 {
		t.Fatalf("ClientHello 应被拆成 >=3 次写，实际 %d 次: %v", len(sizes), sizes)
	}
	if sizes[0] != 1 {
		t.Fatalf("首段应为 1 字节，实际 %d（整表 %v）", sizes[0], sizes)
	}
	if st := srv.Stats(); st.Split != 1 {
		t.Fatalf("分片计数应为 1，实际 %d", st.Split)
	}

	// 实证：SNI 确实是 github.com，且拆分后没有任何一片包含完整域名
	raw := rec.bytes()
	if !bytes.Contains(raw, []byte("github.com")) {
		t.Fatal("上行数据里没看到 SNI=github.com，隧道搬运有问题")
	}
	from := 0
	for i, n := range sizes {
		if from+n > len(raw) {
			break
		}
		if bytes.Contains(raw[from:from+n], []byte("github.com")) {
			t.Fatalf("第 %d 片（%d 字节）仍含完整域名，分片无效", i, n)
		}
		from += n
	}
}

// 未命中名单：不拆包，原样直通（避免给所有网站增加无谓开销）。
func TestNonListedHostPassThrough(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	srv, addr, rec := startProxy(t, []string{"example.com"}, upstream.Listener.Addr().String(), Splitter{Window: 0})
	client := newClient(t, addr, upstream)

	resp, err := client.Get("https://github.com/")
	if err != nil {
		t.Fatalf("经代理请求失败: %v", err)
	}
	resp.Body.Close()

	if st := srv.Stats(); st.Split != 0 || st.Pass == 0 {
		t.Fatalf("不该分片：split=%d pass=%d", st.Split, st.Pass)
	}
	for _, n := range rec.snapshot() {
		if n == 1 {
			t.Fatalf("非名单域名出现了 1 字节写入，说明误分片: %v", rec.snapshot())
		}
	}
}

// 明文 HTTP 也要能走代理（非 CONNECT 的绝对 URI 请求）。
func TestPlainHTTPForward(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "plain-ok")
	}))
	defer upstream.Close()

	_, addr, _ := startProxy(t, nil, upstream.Listener.Addr().String(), Splitter{})
	pu, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
	}
	resp, err := client.Get("http://github.com/")
	if err != nil {
		t.Fatalf("明文 HTTP 经代理失败: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "plain-ok" {
		t.Fatalf("响应体异常: %q", body)
	}
}

func TestShouldSplitRules(t *testing.T) {
	s := New(Options{Hosts: []string{"github.com", "fastly.net"}})
	cases := map[string]bool{
		"github.com":                    true,
		"api.github.com":                true,
		"objects.githubusercontent.com": false, // 不在名单
		"github.global.ssl.fastly.net":  true,
		"evilgithub.com":                false,
		"github.com.evil.cn":            false,
	}
	for host, want := range cases {
		if got := s.shouldSplit(host); got != want {
			t.Fatalf("shouldSplit(%q) = %v, 期望 %v", host, got, want)
		}
	}

	all := New(Options{}) // 空名单 = 除本地地址外全分片
	if !all.shouldSplit("github.com") {
		t.Fatal("空名单时普通域名应分片")
	}
	if all.shouldSplit("127.0.0.1") || all.shouldSplit("localhost") {
		t.Fatal("本地地址不应分片")
	}
}
