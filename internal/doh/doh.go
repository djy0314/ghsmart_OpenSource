// Package doh 提供基于 DoH（DNS over HTTPS）的域名解析能力。
// 通过构造标准 DNS wire-format 报文 POST 到公共 DoH 端点完成解析，
// 不内置任何写死的 GitHub IP，全部结果来自实时解析。
package doh

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// requestTimeout 是单次 DoH 请求的超时时间。
const requestTimeout = 5 * time.Second

// DefaultEndpoints 是未显式配置时可用的公共 DoH 端点。
var DefaultEndpoints = []string{
	"https://cloudflare-dns.com/dns-query",
	"https://dns.google/dns-query",
	"https://dns.alidns.com/dns-query",
}

// queryOne 向单个 DoH 端点发送 wire-format DNS 查询，返回解析到的 IP 列表。
func queryOne(ctx context.Context, endpoint, domain string) ([]net.IP, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true
	wire, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("构造 DNS 查询失败: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	client := &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH 端点 %s 返回 %d", endpoint, resp.StatusCode)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	reply := new(dns.Msg)
	body := new(bytes.Buffer)
	if _, err := body.ReadFrom(resp.Body); err != nil {
		return nil, err
	}
	if err := reply.Unpack(body.Bytes()); err != nil {
		return nil, fmt.Errorf("解析 DoH 应答失败: %w", err)
	}

	var ips []net.IP
	for _, rr := range reply.Answer {
		switch v := rr.(type) {
		case *dns.A:
			ips = append(ips, v.A)
		case *dns.AAAA:
			ips = append(ips, v.AAAA)
		}
	}
	return ips, nil
}

// ResolveWith 使用给定的端点列表依次尝试解析 domain，
// 任一端点成功即返回；全部失败时返回最后一个错误。
func ResolveWith(ctx context.Context, domain string, endpoints []string) ([]net.IP, error) {
	if len(endpoints) == 0 {
		endpoints = DefaultEndpoints
	}
	// 随机起点轮询端点，避免固定打到第一个。
	start := rand.Intn(len(endpoints))
	var lastErr error
	for i := range endpoints {
		ep := endpoints[(start+i)%len(endpoints)]
		ips, err := queryOne(ctx, ep, domain)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("DoH 端点 %s 无应答记录", ep)
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("无可用的 DoH 端点")
	}
	return nil, fmt.Errorf("解析 %s 失败: %w", domain, lastErr)
}

// Resolve 使用默认端点解析 domain，返回去重后的 IPv4/IPv6 地址列表。
func Resolve(ctx context.Context, domain string) ([]net.IP, error) {
	return ResolveWith(ctx, domain, DefaultEndpoints)
}

// DedupIPStrings 对 IP 字符串去重并保持首次出现的顺序。
func DedupIPStrings(ips []net.IP) []string {
	seen := make(map[string]struct{}, len(ips))
	var out []string
	for _, ip := range ips {
		s := ip.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
