// Package probe 实现对候选 IP 的多维并发探测：
// TCP 连接耗时、TLS 握手耗时、HTTP HEAD 首字节耗时，并按加权公式评分。
package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// BusinessRootCAs 是业务校验的自定义证书根池：nil（默认）用系统根。
// 仅供单测注入自签 CA；生产代码绝不赋值。
var BusinessRootCAs *x509.CertPool

// businessCheckPort 是业务校验的目标端口：生产恒为 443，单测可覆盖。
var businessCheckPort = "443"

// Concurrency 是探测的默认最大并发数，可由配置覆盖。
var Concurrency = 10

// httpTimeout 是 HTTP HEAD 探测的硬超时：连不上 2 秒内判死，不死等 5 秒。
const httpTimeout = 2 * time.Second

// ProbeResult 是单个 IP 的探测结果。
type ProbeResult struct {
	IP     string
	TCPMs  int64
	TLSMs  int64
	HTTPMs int64
	Score  float64
	OK     bool
	Err    string
}

// score 按加权公式计算评分：TCP 40% + TLS 40% + HTTP 20%，数值越低越好。
func score(r *ProbeResult) float64 {
	return 0.4*float64(r.TCPMs) + 0.4*float64(r.TLSMs) + 0.2*float64(r.HTTPMs)
}

// reachableWithoutHTTP 在 TCP+TLS 已通、但 HTTP 层失败时的兜底判定：
// TLS 握手成功即证明该 IP 网络可达（纯 CDN 域名对根路径超时/拒答很常见），
// 标记 OK=true，并按 httpTimeout 计入评分，避免 0ms 造成假高分。
func reachableWithoutHTTP(r *ProbeResult, reason string) {
	r.HTTPMs = httpTimeout.Milliseconds()
	r.Err = reason
	r.OK = true
	r.Score = score(r)
}

// probeOne 对单个 IP 执行完整探测流程：TCP -> TLS(校验证书 SAN) -> HTTP HEAD。
func probeOne(ctx context.Context, ip, domain string, timeout time.Duration) ProbeResult {
	r := ProbeResult{IP: ip}
	dialer := &net.Dialer{Timeout: timeout}
	deadline := time.Now().Add(timeout)

	// 1. TCP 连接
	start := time.Now()
	nc, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	r.TCPMs = time.Since(start).Milliseconds()
	if err != nil {
		r.Err = fmt.Sprintf("TCP 失败: %v", err)
		return r
	}
	defer nc.Close()

	// 2. TLS 握手：SNI 指向目标域名，正常校验证书链与 SAN
	start = time.Now()
	conn := tls.Client(nc, &tls.Config{
		ServerName: domain,
		MinVersion: tls.VersionTLS12,
	})
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = nc.SetDeadline(deadline)
	if err := conn.HandshakeContext(ctx); err != nil {
		r.TLSMs = time.Since(start).Milliseconds()
		r.Err = fmt.Sprintf("TLS 失败: %v", err)
		return r
	}
	r.TLSMs = time.Since(start).Milliseconds()
	defer conn.Close()

	// 3. HTTP HEAD：复用已建立的 TLS 连接，独立 2 秒硬超时（不再沿用 5 秒总预算）
	req, err := http.NewRequest(http.MethodHead, "https://"+domain+"/", nil)
	if err != nil {
		reachableWithoutHTTP(&r, "构造请求失败（TLS 已通，按可达处理）")
		return r
	}
	req.Host = domain
	req.Header.Set("User-Agent", "ghsmart/0.1")

	_ = nc.SetDeadline(time.Now().Add(httpTimeout))
	start = time.Now()
	if err := req.Write(conn); err != nil {
		r.HTTPMs = time.Since(start).Milliseconds()
		reachableWithoutHTTP(&r, fmt.Sprintf("发送请求失败但 TLS 已通: %v", err))
		return r
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	r.HTTPMs = time.Since(start).Milliseconds()
	if err != nil {
		reachableWithoutHTTP(&r, fmt.Sprintf("读取响应超时/失败但 TLS 已通: %v", err))
		return r
	}
	defer resp.Body.Close()

	// 收到任意 HTTP 应答（含 4xx/5xx）即证明该 IP 网络可达：
	// 纯 CDN 域名（如 objects.githubusercontent.com、github.global.ssl.fastly.net）
	// 对根路径 HEAD / 常返回 403/404，这不代表 IP 不通，
	// 因此不按状态码判定失败，只有 TCP/TLS 层错误才标记失败。
	r.OK = true
	r.Score = score(&r)
	return r
}

// partialScore 在探测失败但有部分耗时数据时，也给出评分便于对照展示。
func partialScore(r *ProbeResult) {
	if r.TCPMs > 0 || r.TLSMs > 0 || r.HTTPMs > 0 {
		r.Score = score(r)
	}
}

// ProbeIPs 并发探测 ips 中的每个地址，返回顺序与输入一致的探测结果。
// 并发数由包级变量 Concurrency（默认 10）控制，可通过配置覆盖。
func ProbeIPs(ctx context.Context, ips []string, domain string, timeout time.Duration) []ProbeResult {
	results := make([]ProbeResult, len(ips))
	sem := make(chan struct{}, Concurrency)
	var wg sync.WaitGroup

	for i, ip := range ips {
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
				results[i] = probeOne(ctx, ip, domain, timeout)
				if !results[i].OK {
					partialScore(&results[i])
				}
			case <-ctx.Done():
				results[i] = ProbeResult{IP: ip, Err: "已取消: " + ctx.Err().Error()}
			}
		}(i, ip)
	}
	wg.Wait()
	return results
}

// BusinessCheck 模拟「真实业务」请求：用带 SNI（ServerName=domain）与
// 严格证书校验的 HTTPS GET https://<domain>/robots.txt 直连 ip:443。
//
// 为什么必须有这一关：TCP/TLS 握手成功 ≠ 网页能用。深信服等 VPN 会在
// TLS 层代答握手（握手看似成功，业务流量却被 RST/黑洞），DoH 污染也会
// 返回「TCP/TLS 都通但根本不是这个域名」的 IP（如把 Fastly Pages IP 写给
// github.com）。只有「真发一个业务请求并拿到 HTTP 应答 + 证书属于该域名」
// 才算数。connection reset / 超时 / 证书不符 → 该 IP 判死，禁止写入 Hosts。
func BusinessCheck(ctx context.Context, ip, domain string, timeout time.Duration) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("内部错误：业务校验必须用 IP 字面量，收到 %q", ip)
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: timeout}
	tlsCfg := &tls.Config{
		ServerName: domain, // SNI 指向真实域名，严格校验证书链与 SAN
		MinVersion: tls.VersionTLS12,
	}
	if BusinessRootCAs != nil {
		tlsCfg.RootCAs = BusinessRootCAs
	}
	tr := &http.Transport{
		// 强制拨 ip:<port>，绝不按域名解析（否则 DNS 会把请求引去别处，校验失真）。
		// DialTLSContext 契约要求返回「已完成 TLS 握手」的连接：
		// 手动 tls.Client + SNI(domain) + 严格证书校验。
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			nc, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, businessCheckPort))
			if err != nil {
				return nil, err
			}
			tc := tls.Client(nc, tlsCfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				_ = nc.Close()
				return nil, err
			}
			return tc, nil
		},
		ResponseHeaderTimeout: timeout,
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+"/robots.txt", nil)
	if err != nil {
		return fmt.Errorf("构造业务请求失败: %w", err)
	}
	req.Header.Set("User-Agent", "ghsmart-businesscheck/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("业务请求失败: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 4<<10)
	// 拿到任意 HTTP 应答（含 404）即代表「TCP + TLS(SNI+证书) + HTTP」全链路真实可用
	return nil
}

// IsNetBlockedErr 判断业务校验错误是否为「网络层拦截」证据
//（连接被重置/超时/握手被掐），而非证书不符（那属于 IP 与域名对不上）。
// 两类都会让 IP 判死；此分类只影响「受限网络」结论的取证口径。
func IsNetBlockedErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, kw := range []string{"reset", "timeout", "超时", "eof", "broken pipe", "i/o", "refused"} {
		if strings.Contains(msg, kw) {
			return true
		}
	}
	return false
}
