package webproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// addrLog 记录代理每次拨号实际传下来的地址，用来实证「只拨 IP、不拨域名」。
type addrLog struct {
	mu    sync.Mutex
	addrs []string
}

func (l *addrLog) add(addr string) {
	l.mu.Lock()
	l.addrs = append(l.addrs, addr)
	l.mu.Unlock()
}

func (l *addrLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.addrs))
	copy(out, l.addrs)
	return out
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// 这是本轮重构的核心回归：管辖域名（github.com 等）的拨号**绝不能**落到域名上。
//
// 一旦落下去，Go 的内置解析器就会读系统 hosts —— 而 hosts 里那条正是我们自己
// 用「一键智能加速」写进去的优选 IP。那条 IP 失效时，浏览器就是一直转圈到
// ERR_CONNECTION_TIMED_OUT（号主实机复现的原现象）。
func TestManagedHostNeverDialsByName(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起假上游失败: %v", err)
	}
	defer upstream.Close()
	go func() {
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			_, _ = io.Copy(c, c) // echo
			_ = c.Close()
		}
	}()
	upAddr := upstream.Addr().String()
	upHost, upPort, _ := net.SplitHostPort(upAddr)

	var log addrLog
	srv := New(Options{
		Listen: "127.0.0.1:0",
		Hosts:  []string{"github.com"},
		Resolve: func(host string) []string {
			return []string{upHost}
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			log.add(addr)
			return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(upHost, upPort))
		},
		Logf: t.Logf,
	})
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}
	defer srv.Stop()

	c, resp := dialProxyConnect(t, addr, "github.com:443")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("期望 200，实际 %d", resp.StatusCode)
	}
	// 不是 TLS 握手 → 直通，正好用来验证隧道是通的
	if _, err := c.Write([]byte("PING")); err != nil {
		t.Fatalf("写隧道失败: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("读回显失败: %v", err)
	}
	if string(buf) != "PING" {
		t.Fatalf("回显不对: %q", buf)
	}

	for _, a := range log.snapshot() {
		if net.ParseIP(hostOf(a)) == nil {
			t.Fatalf("管辖域名竟然按域名拨号了: %q（会读系统 hosts → 死 IP 卡死）", a)
		}
	}
	t.Logf("实际拨号地址: %v", log.snapshot())
}

// hosts 里那条死 IP 排在最前面时，不能拖慢建连：并发竞速应该让活的 IP 立刻胜出。
func TestDeadIPDoesNotBlockRace(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起假上游失败: %v", err)
	}
	defer upstream.Close()
	go func() {
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			_, _ = io.Copy(c, c)
			_ = c.Close()
		}
	}()
	upHost, upPort, _ := net.SplitHostPort(upstream.Addr().String())

	const deadIP = "10.255.255.1" // 假死不回 RST 的地址
	srv := New(Options{
		Listen: "127.0.0.1:0",
		Hosts:  []string{"github.com"},
		Resolve: func(string) []string {
			return []string{deadIP, upHost} // 死 IP 故意排第一（模拟 hosts 里的旧记录）
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if hostOf(addr) == deadIP {
				<-ctx.Done() // 模拟 SYN 被丢：一直不返回，直到超时
				return nil, ctx.Err()
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(upHost, upPort))
		},
		DialTimeout: 3 * time.Second,
		Logf:        t.Logf,
	})
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}
	defer srv.Stop()

	start := time.Now()
	c, resp := dialProxyConnect(t, addr, "github.com:443")
	elapsed := time.Since(start)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("期望 200（活 IP 应赢得竞速），实际 %d %s", resp.StatusCode, resp.Status)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("死 IP 把建连拖慢了：%v（应靠并发竞速在 1s 内胜出）", elapsed)
	}
	if _, err := c.Write([]byte("OK")); err != nil {
		t.Fatalf("写隧道失败: %v", err)
	}
	t.Logf("死 IP 在前，建连耗时 %v", elapsed)
}

// 所有候选都拨不通时：必须在 200 之前给出 502（浏览器显示错误页），
// 而不是让浏览器一直转圈；且耗时必须被 3s 上限兜住。
func TestAllCandidatesDeadReturns502Fast(t *testing.T) {
	var log addrLog
	srv := New(Options{
		Listen: "127.0.0.1:0",
		Hosts:  []string{"github.com"},
		Resolve: func(string) []string {
			return []string{"10.255.255.1", "10.255.255.2", "10.255.255.3"}
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			log.add(addr)
			<-ctx.Done()
			return nil, ctx.Err()
		},
		DialTimeout: 400 * time.Millisecond, // 单测压到 400ms，验证「上限生效」而不是死等
		Logf:        t.Logf,
	})
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}
	defer srv.Stop()

	start := time.Now()
	c, resp := dialProxyConnect(t, addr, "github.com:443")
	elapsed := time.Since(start)
	defer c.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("全挂时应返回 502，实际 %d %s", resp.StatusCode, resp.Status)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("502 给得太慢：%v（应受 3s/次的上限约束）", elapsed)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "候选 IP 全部建连失败") {
		t.Fatalf("502 响应体应说明失败原因，实际 %q", body)
	}
	for _, a := range log.snapshot() {
		if net.ParseIP(hostOf(a)) == nil {
			t.Fatalf("不应按域名拨号: %q", a)
		}
	}
	t.Logf("全挂 502 耗时 %v，尝试地址: %v", elapsed, log.snapshot())
}

// 普通域名（不在 split_hosts 里）：允许按域名拨号，否则接管系统代理后全网都打不开。
func TestUnmanagedHostUsesSystemDial(t *testing.T) {
	var log addrLog
	srv := New(Options{
		Listen: "127.0.0.1:0",
		Hosts:  []string{"github.com"},
		Resolve: func(host string) []string {
			return nil // 宿主对非管辖域名返回 nil
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			log.add(addr)
			return nil, errors.New("模拟：只是想看拨号地址")
		},
		DialTimeout: 300 * time.Millisecond,
		Logf:        t.Logf,
	})
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}
	defer srv.Stop()

	_, resp := dialProxyConnect(t, addr, "example.com:443")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("连不上应是 502，实际 %d", resp.StatusCode)
	}
	got := log.snapshot()
	if len(got) == 0 || hostOf(got[0]) != "example.com" {
		t.Fatalf("非管辖域名应按域名拨号，实际 %v", got)
	}
}

// 没有 Resolve（CLI/裸代理模式）时必须退回按域名拨号，不能被「只拨 IP」挡死。
func TestNoResolverFallsBackToNameDial(t *testing.T) {
	var log addrLog
	srv := New(Options{
		Listen: "127.0.0.1:0",
		Hosts:  []string{"github.com"},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			log.add(addr)
			return nil, fmt.Errorf("不连")
		},
		DialTimeout: 300 * time.Millisecond,
		Logf:        t.Logf,
	})
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}
	defer srv.Stop()

	_, resp := dialProxyConnect(t, addr, "github.com:443")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("应 502，实际 %d", resp.StatusCode)
	}
	got := log.snapshot()
	if len(got) == 0 || hostOf(got[0]) != "github.com" {
		t.Fatalf("无解析器时应按域名拨号，实际 %v", got)
	}
}
