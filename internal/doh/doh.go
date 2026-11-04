// Package doh 提供基于 DoH（DNS over HTTPS）的域名解析能力。
// 通过构造标准 DNS wire-format 报文 POST 到公共 DoH 端点完成解析，
// 不内置任何写死的 GitHub IP，全部结果来自实时解析。
package doh

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// requestTimeout 是单次 DoH 请求的超时时间。
// 并发竞速下它只是单个端点的兜底闸：慢端点不会拖住整体，
// 赢家一出现其余请求立刻被 ctx 取消，根本等不到这个超时。
const requestTimeout = 5 * time.Second

// DefaultEndpoints 是可用的公共 DoH 端点。
// 国内双保险在前（阿里 + 腾讯），Cloudflare/Google 留给海外用户——
// 并发竞速下顺序不影响延迟，只影响「同样快时优先采信谁」。
var DefaultEndpoints = []string{
	"https://dns.alidns.com/dns-query",
	"https://doh.pub/dns-query",
	"https://cloudflare-dns.com/dns-query",
	"https://dns.google/dns-query",
}

// 端点健康记忆：上次赢家下次先发（raceStagger 的提前量），其余端点错峰兜底。
// 这样正常情况只有一个请求在飞（省流量、结果稳定不抖动），
// 赢家一旦变慢/被墙，错峰大军 150ms 后自动压上，用户无感。
var (
	goodEndpoint atomic.Value // string：上次解析成功的端点
	goodFails    atomic.Int32 // 记忆端点连续失败次数（>=2 清除记忆）

	// raceStagger 是非记忆端点相对记忆端点的起跑延迟；无记忆时全部 0ms 齐发。
	// 包级变量以便单测调小/调大。
	raceStagger = 150 * time.Millisecond
)

// noteGood 记录赢家端点，并清零其连败计数。
func noteGood(ep string) {
	goodFails.Store(0)
	goodEndpoint.Store(ep)
}

// noteGoodFail 给记忆端点记一次失败；连续失败 2 次就摘除记忆，
// 避免一个已死的端点长期霸占先发位（每次白送它 raceStagger 的提前量）。
func noteGoodFail() {
	if goodFails.Add(1) >= 2 {
		goodEndpoint.Store("")
		goodFails.Store(0)
	}
}

// dohClient 是包级共享的 HTTP 客户端：DoH 端点都是固定几个域名，
// 复用 TLS 连接后第二次起的解析免掉完整握手（80~300ms → ~30ms 级）。
var dohClient = &http.Client{
	Timeout: requestTimeout,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	},
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

	resp, err := dohClient.Do(req)
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

// ResolveWith 并发竞速解析 domain：所有端点同时发请求，
// 谁先返回完整的 A 记录就用谁，其余立刻取消——
// 绝不串行等死人的 5 秒超时（v1.0.4 之前的老毛病：
// Cloudflare/Google 国内被墙，随机起点落在它们头上每个域名白等 5~10s）。
//
// 健康记忆：上次赢家下次先发（提前 raceStagger），其余端点错峰兜底；
// 无记忆（首次/记忆被清除）时全部齐发。
func ResolveWith(ctx context.Context, domain string, endpoints []string) ([]net.IP, error) {
	if len(endpoints) == 0 {
		endpoints = DefaultEndpoints
	}
	good, _ := goodEndpoint.Load().(string)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type res struct {
		ep  string
		ips []net.IP
		err error
	}
	ch := make(chan res, len(endpoints)) // 缓冲足够大，协程不会因发送阻塞而泄漏
	for _, ep := range endpoints {
		wait := time.Duration(0)
		if good != "" && ep != good {
			wait = raceStagger
		}
		go func(ep string, wait time.Duration) {
			if wait > 0 {
				select {
				case <-time.After(wait):
				case <-ctx.Done():
					ch <- res{ep: ep, err: ctx.Err()}
					return
				}
			}
			ips, err := queryOne(ctx, ep, domain)
			ch <- res{ep: ep, ips: ips, err: err}
		}(ep, wait)
	}

	var lastErr error
	for range endpoints {
		r := <-ch
		if r.err == nil && len(r.ips) > 0 {
			cancel() // 赢家出现，其余请求立刻作废
			noteGood(r.ep)
			return r.ips, nil
		}
		if r.err != nil {
			lastErr = r.err
			if r.ep == good && ctx.Err() == nil {
				noteGoodFail()
			}
		} else {
			lastErr = fmt.Errorf("DoH 端点 %s 无应答记录", r.ep)
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
