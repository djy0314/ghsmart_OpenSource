package webproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// readerConn 让上层继续复用 bufio.Reader 里可能残留的字节
// （CONNECT 的 200 响应有可能和后续数据一起到达）。
type readerConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *readerConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// dialProxyConnect 建立到本地代理的 CONNECT 隧道，返回 200 之后的连接。
// 顺手断言代理确实先返回了 200 Connection Established。
func dialProxyConnect(t *testing.T, proxyAddr, target string) (net.Conn, *http.Response) {
	t.Helper()
	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("连接代理失败: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if _, err := fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("发 CONNECT 失败: %v", err)
	}
	br := bufio.NewReader(raw)
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("读 CONNECT 响应失败: %v", err)
	}
	_ = raw.SetReadDeadline(time.Time{})
	return &readerConn{Conn: raw, r: br}, resp
}

// ===== 一、200 之前的失败必须是标准 502 =====
//
// 这是浏览器能看到「正常错误页」的唯一窗口：只要回过 200，这条 TCP 就是裸 TLS 流，
// 再往里写 HTTP 头会被当作 TLS 记录解析。
func TestConnectReturns502WhenAllDialsFail(t *testing.T) {
	srv := New(Options{
		Listen: "127.0.0.1:0",
		Hosts:  []string{"github.com"},
		Resolve: func(string) []string {
			return []string{"10.255.255.1", "10.255.255.2"} // 全是不可达地址
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, fmt.Errorf("模拟拨号失败: %s", addr)
		},
		Logf: t.Logf,
	})
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}
	defer srv.Stop()

	c, resp := dialProxyConnect(t, addr, "github.com:443")
	defer c.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("拨号全失败时应返回 502，实际 %d %s", resp.StatusCode, resp.Status)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "无法连接") {
		t.Fatalf("502 响应体应带上失败原因，实际 %q", body)
	}
	t.Logf("502 body = %q", strings.TrimSpace(string(body)))
}

// ===== 二、200 之后的失败：TLS alert + 干净收尾，不能是 RST =====
//
// 上游只接受 TCP、永远不回 ServerHello（模拟 SNI 被 RST / IP 假活）。
// 期望：客户端拿到 TLS 的 handshake_failure 告警（说明代理优雅收尾），
// 而不是 ECONNRESET（那会被 Chrome 报成 ERR_CONNECTION_CLOSED）。
func TestHandshakeTotalFailureSendsTLSAlert(t *testing.T) {
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起假上游失败: %v", err)
	}
	defer silent.Close()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				} // 只吞不回：永远不给 ServerHello
			}(c)
		}
	}()

	srv := New(Options{
		Listen: "127.0.0.1:0",
		Hosts:  []string{"github.com"},
		Split:  Splitter{},
		Resolve: func(string) []string {
			return []string{"10.255.255.1", "10.255.255.2", "10.255.255.3"}
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial("tcp", silent.Addr().String()) // 一律连到「只吞不回」的假上游
		},
		HandshakeWait:     80 * time.Millisecond,
		HandshakeBudget:   400 * time.Millisecond,
		PlainFallbackWait: 80 * time.Millisecond,
		Logf:              t.Logf,
	})
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}
	defer srv.Stop()

	conn, resp := dialProxyConnect(t, addr, "github.com:443")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT 应返回 200（先建隧道），实际 %d", resp.StatusCode)
	}

	tc := tls.Client(conn, &tls.Config{ServerName: "github.com", InsecureSkipVerify: true})
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	herr := tc.Handshake()
	if herr == nil {
		t.Fatal("上游不给 ServerHello，客户端握手不该成功")
	}
	t.Logf("客户端握手错误: %v", herr)

	msg := strings.ToLower(herr.Error())
	if strings.Contains(msg, "reset") {
		t.Fatalf("代理是硬断（RST），浏览器会报 ERR_CONNECTION_CLOSED；应发 TLS alert 再收尾: %v", herr)
	}
	if !strings.Contains(msg, "handshake failure") && !strings.Contains(msg, "alert") &&
		!strings.Contains(msg, "eof") && !strings.Contains(msg, "connection was closed") {
		t.Fatalf("期望收到 TLS 告警/正常关闭，实际: %v", herr)
	}
	if st := srv.Stats(); st.Split != 0 {
		t.Fatalf("握手失败不该计入分片成功数: %+v", st)
	}
}

// ===== 三、分片全挂时不分片直发能救回来（middlebox 重组异常的兜底）=====
//
// 假上游：读到「首包只有 1 字节」（= 我们的分片特征）就立刻关连接；
// 读到完整 ClientHello（一次性写）就回一段字节。期望代理走 plain 兜底成功。
func TestPlainFallbackRescuesWhenFragmentationBreaks(t *testing.T) {
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起假上游失败: %v", err)
	}
	defer up.Close()
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 8192)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				if n <= 1 {
					return // 分片特征 → 直接掐断
				}
				_, _ = c.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00})
				// 假上游不能一直挂着：否则代理的隧道要等满收尾宽限期，用例变慢
				time.Sleep(300 * time.Millisecond)
			}(c)
		}
	}()

	srv := New(Options{
		Listen: "127.0.0.1:0",
		Hosts:  []string{"github.com"},
		Split:  Splitter{},
		Resolve: func(string) []string {
			return []string{"10.255.255.1"}
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial("tcp", up.Addr().String())
		},
		HandshakeWait:     150 * time.Millisecond,
		HandshakeBudget:   800 * time.Millisecond,
		PlainFallbackWait: 150 * time.Millisecond,
		Logf:              t.Logf,
	})
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}
	defer srv.Stop()

	conn, resp := dialProxyConnect(t, addr, "github.com:443")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT 应返回 200，实际 %d", resp.StatusCode)
	}
	// 发一条真实 ClientHello（用 crypto/tls 生成），随后它必然会握手失败，
	// 但代理侧应该已经用「不分片直发」把 hello 送出去了。
	tc := tls.Client(conn, &tls.Config{ServerName: "github.com", InsecureSkipVerify: true})
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	_ = tc.Handshake()

	deadline := time.Now().Add(3 * time.Second)
	for {
		st := srv.Stats()
		if st.Plain >= 1 {
			t.Logf("统计: plain=%d retry=%d split=%d", st.Plain, st.Retry, st.Split)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("分片全失败后没有走「不分片直发」兜底: %+v", st)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
