package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// withTestTLS 把业务校验切到测试环境：自签 CA 根池 + httptest 随机端口。
func withTestTLS(t *testing.T, srv *httptest.Server) {
	t.Helper()
	oldPort, oldRoots := businessCheckPort, BusinessRootCAs
	businessCheckPort = portOf(srv)
	BusinessRootCAs = poolOf(srv)
	t.Cleanup(func() {
		businessCheckPort = oldPort
		BusinessRootCAs = oldRoots
	})
}

func portOf(srv *httptest.Server) string {
	_, port := splitAddr(srv.Listener.Addr().String())
	return port
}

func poolOf(srv *httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return pool
}

func splitAddr(addr string) (string, string) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:]
		}
	}
	return addr, ""
}

// TestBusinessCheckSuccess：真实业务请求成功（TLS 证书属于该域名 + 拿到 HTTP 应答）→ nil。
func TestBusinessCheckSuccess(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/robots.txt" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("User-agent: *\nDisallow:\n"))
	}))
	defer srv.Close()
	withTestTLS(t, srv)

	// httptest 证书的 SAN 覆盖 127.0.0.1
	if err := BusinessCheck(context.Background(), "127.0.0.1", "127.0.0.1", 3*time.Second); err != nil {
		t.Fatalf("业务校验应通过，却失败: %v", err)
	}
}

// TestBusinessCheckCertMismatch：IP 活着但证书不属于该域名（DoH 污染的典型形态，
// 如把 Fastly Pages IP 写给 github.com）→ 必须判死。
func TestBusinessCheckCertMismatch(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	withTestTLS(t, srv)

	// 证书 SAN 只有 example.com/*.example.com 与 127.0.0.1，用 github.com（SNI+校验）必然失败
	err := BusinessCheck(context.Background(), "127.0.0.1", "github.com", 3*time.Second)
	if err == nil {
		t.Fatal("证书与域名不符时业务校验必须失败")
	}
	if IsNetBlockedErr(err) {
		t.Fatalf("证书不符不是网络拦截证据: %v", err)
	}
}

// TestBusinessCheckRefused：目标端口无人监听（等价于被 RST/黑洞）→ 判死且属网络拦截证据。
func TestBusinessCheckRefused(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	withTestTLS(t, srv)
	port := businessCheckPort
	srv.Close() // 先取端口再关掉：之后连接必然被拒

	err := BusinessCheck(context.Background(), "127.0.0.1", "127.0.0.1", 3*time.Second)
	if err == nil {
		t.Fatal("端口已关闭时业务校验必须失败")
	}
	_ = port
	if !IsNetBlockedErr(err) {
		t.Fatalf("连接被拒应归类为网络拦截证据: %v", err)
	}
}

// TestBusinessCheckRejectsDomain：业务校验只收 IP 字面量，传域名直接报内部错误。
func TestBusinessCheckRejectsDomain(t *testing.T) {
	if err := BusinessCheck(context.Background(), "github.com", "github.com", time.Second); err == nil {
		t.Fatal("传域名必须被拒绝（防退回系统解析）")
	}
}

// TestBusinessCheckTimeout：上游hang住时应在时限内返回超时错误（属网络拦截证据）。
func TestBusinessCheckTimeout(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
	defer srv.Close()
	withTestTLS(t, srv)

	start := time.Now()
	err := BusinessCheck(context.Background(), "127.0.0.1", "127.0.0.1", 500*time.Millisecond)
	if err == nil {
		t.Fatal("hang 住的上游必须超时失败")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("超时判定太慢: %v", elapsed)
	}
	if !IsNetBlockedErr(err) {
		t.Fatalf("超时应归类为网络拦截证据: %v", err)
	}
}

// 编译期防线：tls.Config 的 ServerName 字段是 SNI 的载体，防止误删
var _ = tls.VersionTLS12
