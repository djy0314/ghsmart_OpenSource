// speedtest 是 ghsmart 的性能回归工具：量化 DoH 解析耗时、完整探测流程耗时、
// 代理建链延迟与直连对比，供每次解析层/代理层改动后跑前后对比。
// 注意：必须在干净 shell（无 HTTP_PROXY 等代理变量）下运行——
// Go 的 ProxyFromEnvironment 会读这些变量，污染后 DoH 会全部超时，得出假结论。
// 分四段计时：
//  1. DoH 解析各域名耗时
//  2. 探测+决策+业务校验耗时（engine.ApplyOnce，不动 Hosts？会动——见注释）
//  3. 本地代理建链延迟：代理启动后 curl CONNECT 到 github.com 的各阶段耗时
//  4. 直连（走 hosts）vs 走代理的 HTTPS TTFB 对比
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"

	"ghsmart/internal/config"
	"ghsmart/internal/doh"
	"ghsmart/internal/engine"
	"ghsmart/internal/webproxy"
)

func main() {
	// 排除代理环境变量污染：真实用户双击 exe 时没有这些变量，
	// 测试进程必须模拟同样的干净环境，否则 DoH 全走本地代理，结论全错。
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"} {
		os.Unsetenv(k)
	}
	cfg, err := config.Load("configs/default.yaml")
	if err != nil {
		fmt.Println("配置加载失败:", err)
		os.Exit(1)
	}
	engine.Configure(cfg)

	fmt.Println("========== 1) DoH 解析耗时（每域名） ==========")
	totalDoH := time.Duration(0)
	for _, d := range cfg.Domains {
		t0 := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := doh.ResolveWith(ctx, d, cfg.DoHEndpoints)
		cancel()
		el := time.Since(t0)
		totalDoH += el
		if err != nil {
			fmt.Printf("  %-32s %8v  失败: %v\n", d, el, err)
		} else {
			fmt.Printf("  %-32s %8v  %d 个IP: %v\n", d, el, len(ips), ips)
		}
	}
	fmt.Printf("  DoH 串行总耗时（引擎是并发的，此处仅为参考）: %v\n\n", totalDoH)

	fmt.Println("========== 2) 完整探测流程（DoH+探测+决策+业务校验+写Hosts） ==========")
	t0 := time.Now()
	primaryAt := time.Duration(0)
	written, lines, restricted, err := engine.ApplyOnceOpts(cfg, engine.NopReporter{}, engine.Options{
		OnPrimary: func(entries map[string]string) {
			primaryAt = time.Since(t0)
		},
	})
	total := time.Since(t0)
	fmt.Printf("  主域名提前生效: %v\n", primaryAt)
	fmt.Printf("  全流程完成:     %v（硬超时 10s）\n", total)
	fmt.Printf("  写入 %d 条, restricted=%v, err=%v\n", len(written), restricted, err)
	for _, l := range lines {
		fmt.Println("   ", l)
	}

	fmt.Println("\n========== 3) 代理建链延迟拆解（每域名首条 CONNECT） ==========")
	// 起一个和正式版同参的本地代理（临时端口，不动系统代理）
	resolver := makeResolver(cfg)
	srv := webproxy.New(webproxy.Options{
		Listen: "127.0.0.1:0",
		Split:  webproxy.Splitter{Window: cfg.WebProxy.SplitWindow, Delay: time.Duration(cfg.WebProxy.SplitDelayMS) * time.Millisecond},
		Hosts:  cfg.WebProxy.SplitHosts,
		Resolve: resolver,
		DialTimeout: time.Duration(cfg.WebProxy.DialTimeoutMS) * time.Millisecond,
		DegradeAfter: 3,
		Logf: func(f string, a ...any) { fmt.Printf("    [proxy] "+f+"\n", a...) },
	})
	addr, err := srv.Start()
	if err != nil {
		fmt.Println("代理启动失败:", err)
		os.Exit(1)
	}
	defer srv.Stop()

	for _, host := range []string{"github.com", "raw.githubusercontent.com"} {
		for round := 0; round < 2; round++ {
			el := connectViaProxy(addr, host)
			tag := "首次"
			if round == 1 {
				tag = "第二次(缓存热)"
			}
			fmt.Printf("  %-28s %-14s CONNECT到TLS就绪: %v\n", host, tag, el)
		}
	}

	fmt.Println("\n========== 4) 直连（hosts优选IP）vs 走代理 的 TTFB 对比 ==========")
	for _, host := range []string{"github.com", "raw.githubusercontent.com"} {
		d := directTTFB(host, resolver)
		p := proxyTTFB(addr, host)
		fmt.Printf("  %-28s 直连: %v   走代理: %v   代理引入: %v\n", host, d, p, p-d)
	}
	fmt.Println("\n完成。")
}

// makeResolver 复刻 app.go resolveHosts 的核心：Hosts 区块 + DoH + 应急池
func makeResolver(cfg *config.Config) func(string) []string {
	cache := map[string][]string{}
	return func(host string) []string {
		if ips, ok := cache[host]; ok {
			return ips
		}
		var ips []string
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		list, err := doh.ResolveWith(ctx, host, cfg.DoHEndpoints)
		cancel()
		if err == nil {
			for _, v := range list {
				if v.To4() != nil {
					ips = append(ips, v.String())
				}
			}
		}
		cache[host] = ips
		return ips
	}
}

// connectViaProxy 量「CONNECT 请求 → 代理回 200 → TLS 握手完成」的总耗时
func connectViaProxy(proxyAddr, host string) time.Duration {
	t0 := time.Now()
	c, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		fmt.Println("    连代理失败:", err)
		return 0
	}
	defer c.Close()
	fmt.Fprintf(c, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host)
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		fmt.Println("    读代理响应失败:", err)
		return 0
	}
	if line == "" {
		return 0
	}
	// 读掉剩余响应头
	for {
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" {
			break
		}
	}
	// TLS 握手（验证代理转发的隧道可用）
	tc := tls.Client(c, &tls.Config{ServerName: host})
	if err := tc.Handshake(); err != nil {
		fmt.Println("    TLS 握手失败:", err)
		return time.Since(t0)
	}
	return time.Since(t0)
}

func directTTFB(host string, resolver func(string) []string) time.Duration {
	ips := resolver(host)
	if len(ips) == 0 {
		fmt.Printf("    [%s] 无可用 IP 直连跳过\n", host)
		return 0
	}
	t0 := time.Now()
	c, err := net.DialTimeout("tcp", net.JoinHostPort(ips[0], "443"), 3*time.Second)
	if err != nil {
		fmt.Printf("    [%s] 直连拨号失败: %v\n", host, err)
		return 0
	}
	defer c.Close()
	tc := tls.Client(c, &tls.Config{ServerName: host})
	if err := tc.Handshake(); err != nil {
		fmt.Printf("    [%s] 直连 TLS 失败: %v\n", host, err)
		return time.Since(t0)
	}
	return time.Since(t0)
}

func proxyTTFB(proxyAddr, host string) time.Duration {
	return connectViaProxy(proxyAddr, host)
}
