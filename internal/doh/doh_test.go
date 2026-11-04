// doh_test.go 用 httptest 模拟 DoH 端点，验证「主端点故障自动降级到备用端点」。
package doh

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

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

// ---------- v1.0.5 并发竞速 + 健康记忆 ----------

// TestResolveWithRaces：并发竞速必须拿最快的——慢端点 1.5s、快端点 30ms，
// 串行实现（先撞慢端点）总耗时必超 1.5s，竞速实现应 < 1s。
func TestResolveWithRaces(t *testing.T) {
	oldStagger := raceStagger
	raceStagger = 0 // 本测试关心「同时齐发」，无记忆场景
	defer func() { raceStagger = oldStagger; goodEndpoint.Store(""); goodFails.Store(0) }()

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1500 * time.Millisecond)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(dohAnswer(t, mustReadAll(t, r), "1.1.1.1"))
	}))
	defer slow.Close()

	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(30 * time.Millisecond)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(dohAnswer(t, mustReadAll(t, r), "140.82.112.3"))
	}))
	defer fast.Close()

	t0 := time.Now()
	ips, err := ResolveWith(context.Background(), "github.com", []string{slow.URL, fast.URL})
	el := time.Since(t0)
	if err != nil {
		t.Fatalf("竞速应成功: %v", err)
	}
	if len(ips) == 0 || ips[0].String() != "140.82.112.3" {
		t.Fatalf("应取快端点结果: %v", ips)
	}
	if el >= 1000*time.Millisecond {
		t.Fatalf("并发竞速却等了 %v（>1s），疑似退化为串行", el)
	}
}

// TestEndpointHealthMemory：上次赢家先发——记忆端点 30ms 响应时，
// 其余端点（错峰 400ms 起跑）根本不该收到请求。
func TestEndpointHealthMemory(t *testing.T) {
	oldStagger := raceStagger
	raceStagger = 400 * time.Millisecond
	defer func() { raceStagger = oldStagger; goodEndpoint.Store(""); goodFails.Store(0) }()

	var slowHits atomic.Int32
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond) // 记忆端点 30ms 就赢，它不该被等到
		slowHits.Add(1)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(dohAnswer(t, mustReadAll(t, r), "2.2.2.2"))
	}))
	defer slow.Close()

	var fastHits atomic.Int32
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fastHits.Add(1)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(dohAnswer(t, mustReadAll(t, r), "20.205.243.166"))
	}))
	defer fast.Close()

	// 第一次：无记忆，齐发（stagger=0 场景由上测覆盖；此处 fast 30ms 内响应，
	// 而 slow 睡 300ms —— 但齐发下 slow 也收到请求，没关系），赢家 = fast
	if _, err := ResolveWith(context.Background(), "github.com", []string{slow.URL, fast.URL}); err != nil {
		t.Fatalf("首次解析应成功: %v", err)
	}
	if got := fastHits.Load(); got < 1 {
		t.Fatal("首次解析 fast 端点应被请求过")
	}
	hitsBefore := slowHits.Load()

	// 第二次：fast 是记忆赢家，0ms 先发 30ms 内返回；slow 错峰 400ms 起跑
	if _, err := ResolveWith(context.Background(), "github.com", []string{slow.URL, fast.URL}); err != nil {
		t.Fatalf("第二次解析应成功: %v", err)
	}
	// slow 在 400ms 错峰窗口内已没必要起跑（赢家已出，ctx 已取消）。
	// 容忍竞态：最多 0 次（严格断言），若偶发起跑也会被立刻取消拿不到结果。
	if n := slowHits.Load() - hitsBefore; n > 0 {
		t.Fatalf("健康记忆生效时慢端点不该收到请求（实收 %d 次）", n)
	}
}

// TestGoodEndpointFailsRemoved：记忆赢家翻脸连续失败 2 次应被摘除记忆，
// 摘除后所有端点恢复齐发（无先发优势），由健康端点兜底成功。
func TestGoodEndpointFailsRemoved(t *testing.T) {
	oldStagger := raceStagger
	raceStagger = 0 // 齐发即可验证摘除后的行为；记忆淘汰逻辑不依赖 stagger
	defer func() { raceStagger = oldStagger; goodEndpoint.Store(""); goodFails.Store(0) }()

	var mode atomic.Bool // false=正常应答 true=翻脸 500
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode.Load() {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(dohAnswer(t, mustReadAll(t, r), "20.205.243.166"))
	}))
	defer endpoint.Close()

	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond) // 保证第 1 轮 endpoint（更快）赢得记忆
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(dohAnswer(t, mustReadAll(t, r), "140.82.113.3"))
	}))
	defer backup.Close()

	// 第 1 轮：endpoint 成功成为记忆赢家
	if _, err := ResolveWith(context.Background(), "github.com", []string{endpoint.URL, backup.URL}); err != nil {
		t.Fatalf("第 1 轮应成功: %v", err)
	}
	if got, _ := goodEndpoint.Load().(string); got != endpoint.URL {
		t.Fatalf("记忆赢家应是 endpoint，实为 %q", got)
	}

	// 翻脸：endpoint 连续失败 2 轮，backup 兜底成功
	mode.Store(true)
	for i := 0; i < 2; i++ {
		ips, err := ResolveWith(context.Background(), "github.com", []string{endpoint.URL, backup.URL})
		if err != nil {
			t.Fatalf("翻脸第 %d 轮应由 backup 兜底成功: %v", i+1, err)
		}
		if ips[0].String() != "140.82.113.3" {
			t.Fatalf("应取 backup 结果: %v", ips)
		}
	}
	// 连续失败 2 次后记忆应已摘除（赢家换成 backup 属于正常重建，关键是
	// 老赢家不霸位 + goodFails 清零）
	if got, _ := goodEndpoint.Load().(string); got == endpoint.URL {
		t.Fatal("翻脸端点连续失败 2 次后仍霸占记忆")
	}
	if goodFails.Load() != 0 {
		t.Fatalf("记忆摘除后连败计数应清零，实为 %d", goodFails.Load())
	}
}
