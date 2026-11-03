//go:build live

// 实网验收（默认不参与 go test ./...，需显式 -tags live）：
// 真机跑一遍「浏览器式」请求，验证本地 TLS 分片代理能正常把 GitHub 页面取回来，
// 并且**即使 hosts 里那条优选 IP 已经失效**，也不会把浏览器卡到超时。
//
//	go test -tags live ./internal/webproxy -run TestLive -v
package webproxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"ghsmart/internal/config"
	"ghsmart/internal/doh"
)

// dohIPv4 用项目自带的 DoH 客户端取一组 IPv4（多端点自动降级，绕开本机被污染的 DNS）。
// 实网偶尔抖动，所以重试几次。
func dohIPv4(t *testing.T, host string) []string {
	t.Helper()
	var lastErr error
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		list, err := doh.ResolveWith(ctx, host, doh.DefaultEndpoints)
		cancel()
		if err == nil {
			var out []string
			for _, ip := range list {
				if v4 := ip.To4(); v4 != nil {
					out = append(out, v4.String())
				}
			}
			if len(out) > 0 {
				return out
			}
			lastErr = fmt.Errorf("无 A 记录")
		} else {
			lastErr = err
		}
		t.Logf("DoH 第 %d 次失败: %v", i+1, lastErr)
	}
	t.Fatalf("DoH 查询 %s 失败: %v", host, lastErr)
	return nil
}

// liveResolver 与生产环境 resolveHosts 同构：优选池（这里用预取结果模拟）+ 应急 IP 池。
// 关键点：DoH **不在连接热路径上**，否则测到的是解析耗时，不是竞速逻辑。
func liveResolver(managed []string, prefetched map[string][]string) func(host string) []string {
	isManaged := func(host string) bool {
		for _, s := range managed {
			if host == s || strings.HasSuffix(host, "."+s) {
				return true
			}
		}
		return false
	}
	var mu sync.Mutex
	cache := map[string][]string{}
	return func(host string) []string {
		if !isManaged(host) {
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		if v, ok := cache[host]; ok {
			return v
		}
		ips := append([]string(nil), prefetched[host]...)
		for _, g := range config.DefaultFallbackIPs {
			if host == g.Suffix || strings.HasSuffix(host, "."+g.Suffix) {
				for _, ip := range g.IPs {
					dup := false
					for _, got := range ips {
						if got == ip {
							dup = true
							break
						}
					}
					if !dup {
						ips = append(ips, ip)
					}
				}
			}
		}
		cache[host] = ips
		return ips
	}
}

func proxyClient(addr string) *http.Client {
	pu, _ := url.Parse("http://" + addr)
	return &http.Client{
		Timeout: 25 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(pu),
			ForceAttemptHTTP2: false,
		},
	}
}

func TestLiveGitHub(t *testing.T) {
	hosts := []string{"github.com", "githubusercontent.com", "githubassets.com", "github.io"}
	prefetched := map[string][]string{
		"github.com":                dohIPv4(t, "github.com"),
		"raw.githubusercontent.com": dohIPv4(t, "raw.githubusercontent.com"),
	}
	t.Logf("预取候选: %v", prefetched)

	srv := New(Options{
		Listen:  "127.0.0.1:0",
		Split:   Splitter{Window: 0, Delay: 10 * time.Millisecond},
		Hosts:   hosts,
		Resolve: liveResolver(hosts, prefetched),
		Logf:    t.Logf,
	})
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}
	defer srv.Stop()

	client := proxyClient(addr)
	for _, u := range []string{
		"https://github.com/",
		"https://raw.githubusercontent.com/git/git/master/README.md",
	} {
		start := time.Now()
		resp, err := client.Get(u)
		if err != nil {
			t.Fatalf("%s 经代理请求失败: %v", u, err)
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		t.Logf("%s -> %d, %d 字节, %v", u, resp.StatusCode, n, time.Since(start).Round(time.Millisecond))
		if resp.StatusCode >= 400 {
			t.Fatalf("%s 返回 %d", u, resp.StatusCode)
		}
		if n < 100 {
			t.Fatalf("%s 响应体过小: %d 字节", u, n)
		}
	}

	st := srv.Stats()
	t.Logf("统计: total=%d split=%d pass=%d lastHost=%s", st.Total, st.Split, st.Pass, st.LastHost)
	if st.Split == 0 {
		t.Fatal("没有发生任何 TLS 分片，代理路径没走对")
	}
}

// 号主实机那个故障的复刻：hosts（= 候选列表首位）里躺着一条已经失效的 IP，
// 后面才是活的 IP。旧代码会在这条死 IP 上死等到超时（ERR_CONNECTION_TIMED_OUT）；
// 现在必须靠并发竞速绕过它，正常拿到 200 且耗时接近「只用活 IP」的水平。
func TestLiveDeadIPInFrontStillFast(t *testing.T) {
	const deadIP = "10.255.255.1" // 未路由地址：SYN 无人应答，只能靠超时
	hosts := []string{"github.com"}
	live := dohIPv4(t, "github.com")
	prefetched := map[string][]string{"github.com": append([]string{deadIP}, live...)} // 死 IP 排第一
	t.Logf("候选（首位是死 IP）: %v", prefetched["github.com"])

	srv := New(Options{
		Listen:      "127.0.0.1:0",
		Split:       Splitter{Window: 0, Delay: 10 * time.Millisecond},
		Hosts:       hosts,
		Resolve:     liveResolver(hosts, prefetched),
		DialTimeout: 3 * time.Second,
		Logf:        t.Logf,
	})
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}
	defer srv.Stop()

	start := time.Now()
	resp, err := proxyClient(addr).Get("https://github.com/")
	if err != nil {
		t.Fatalf("死 IP 在前时请求失败（说明没绕过死 IP）: %v", err)
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(start)
	t.Logf("死 IP 在前：HTTP %d，%d 字节，耗时 %v", resp.StatusCode, n, elapsed.Round(time.Millisecond))
	if resp.StatusCode != 200 {
		t.Fatalf("期望 200，实际 %d", resp.StatusCode)
	}
	// 死 IP 的代价应该只是「多起一个 goroutine」；串行等超时会直接 3s+
	if elapsed > 6*time.Second {
		t.Fatalf("建连被死 IP 拖慢到 %v（并发竞速没生效）", elapsed)
	}
	if got := srv.Stats().Split; got == 0 {
		t.Fatal("没有发生 TLS 分片")
	}
}
