// doh_test.go 用 httptest 模拟 DoH 端点，验证「主端点故障自动降级到备用端点」。
package doh

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miekg/dns"
)

// dohAnswer 构造一个返回指定 A 记录的合法 DoH（wire-format）应答。
func dohAnswer(t *testing.T, query []byte, ip string) []byte {
	t.Helper()
	q := new(dns.Msg)
	if err := q.Unpack(query); err != nil {
		t.Fatalf("解不开查询报文: %v", err)
	}
	m := new(dns.Msg)
	m.SetReply(q)
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP(ip),
	})
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("构造应答失败: %v", err)
	}
	return wire
}

// TestResolveWithFailsOverOnHTTPError：主端点 5xx，自动降级到备用端点成功。
func TestResolveWithFailsOverOnHTTPError(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()

	var hitGood bool
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitGood = true
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(dohAnswer(t, mustReadAll(t, r), "140.82.112.3"))
	}))
	defer good.Close()

	ips, err := ResolveWith(context.Background(), "github.com", []string{bad.URL, good.URL})
	if err != nil {
		t.Fatalf("降级后应成功: %v", err)
	}
	if !hitGood {
		t.Fatal("未降级尝试备用端点")
	}
	if len(ips) == 0 || ips[0].String() != "140.82.112.3" {
		t.Fatalf("解析结果不对: %v", ips)
	}
}

// TestResolveWithFailsOverOnEmptyAnswer：主端点 200 但无应答记录（如污染/无记录），
// 同样必须降级到备用端点。
func TestResolveWithFailsOverOnEmptyAnswer(t *testing.T) {
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(mustEmptyReply(t, mustReadAll(t, r)))
	}))
	defer empty.Close()

	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(dohAnswer(t, mustReadAll(t, r), "20.205.243.166"))
	}))
	defer good.Close()

	ips, err := ResolveWith(context.Background(), "github.com", []string{empty.URL, good.URL})
	if err != nil {
		t.Fatalf("降级后应成功: %v", err)
	}
	if len(ips) == 0 || ips[0].String() != "20.205.243.166" {
		t.Fatalf("解析结果不对: %v", ips)
	}
}

// TestResolveWithAllFail：全部端点失败时报错（调用方保留旧记录）。
func TestResolveWithAllFail(t *testing.T) {
	bad1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer bad1.Close()
	bad2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer bad2.Close()

	_, err := ResolveWith(context.Background(), "github.com", []string{bad1.URL, bad2.URL})
	if err == nil {
		t.Fatal("全部端点失败应返回错误")
	}
}

func mustReadAll(t *testing.T, r *http.Request) []byte {
	t.Helper()
	defer r.Body.Close()
	buf := make([]byte, 4096)
	n, _ := r.Body.Read(buf)
	if n == 0 {
		t.Fatal("查询报文为空")
	}
	return buf[:n]
}

// mustEmptyReply 返回无 Answer 记录的应答报文。
func mustEmptyReply(t *testing.T, query []byte) []byte {
	t.Helper()
	q := new(dns.Msg)
	if err := q.Unpack(query); err != nil {
		t.Fatalf("解不开查询报文: %v", err)
	}
	m := new(dns.Msg)
	m.SetReply(q)
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("构造空应答失败: %v", err)
	}
	return wire
}
