// Package config 负责 YAML 配置的加载与默认值填充。
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// WebProxy 是「深度网页加速」（本地 TLS 分片代理）的配置。
type WebProxy struct {
	// Listen 是本地代理监听地址（系统代理会指向它）。
	Listen string `yaml:"listen"`
	// SplitWindow 是每个分片的字节数；<=0 表示智能分片
	// （首字节 1 片 + SNI 主机名中点再切一刀，保证任何单段都不含完整域名）。
	SplitWindow int `yaml:"split_window"`
	// SplitDelayMS 是分片之间的间隔毫秒数，给 DPI 制造「分属不同流」的错觉。
	SplitDelayMS int `yaml:"split_delay_ms"`
	// SplitHosts 是需要做 TLS 分片的域名后缀（其余域名纯隧道直通，不分片）。
	SplitHosts []string `yaml:"split_hosts"`
	// DialTimeoutMS 是代理连接单个候选 IP 的时限（毫秒，默认 3000）。
	// 3s 内连不上就换下一个候选，避免一个假活 IP 把浏览器卡到 ERR_CONNECTION_TIMED_OUT。
	DialTimeoutMS int `yaml:"dial_timeout_ms"`
	// FallbackIPs 是「应急 IP 池」：当 Hosts 优选 IP 与 DoH 解析全部拨不通时，
	// 按后缀逐个试这些官方 IP（DoH 被污染/单条 A 记录失效时的最后一道保险）。
	FallbackIPs []FallbackGroup `yaml:"fallback_ips"`
	// CompatMode 是「兼容模式」默认值：true 时深度加速不做 TLS 分片，
	// 只做基础 HTTP CONNECT 隧道（深信服 aTrust 等公司 VPN 场景，
	// 分片的握手会被公司防火墙判为异常流量并重置连接）。
	// UI 勾选项会把它持久化到 license.json，两者取「用户明确选择」优先。
	CompatMode bool `yaml:"compat_mode"`
}

// FallbackGroup 是一组同后缀域名共用的应急 IP。
type FallbackGroup struct {
	Suffix string   `yaml:"suffix"`
	IPs    []string `yaml:"ips"`
}

// DefaultFallbackIPs 是 GitHub 官方公布的常用入口 IP（2026-11 实测可用性会变，
// 仅作为「主候选全挂」时的兜底，绝不优先于探测结果）。
var DefaultFallbackIPs = []FallbackGroup{
	{Suffix: "github.com", IPs: []string{
		"140.82.112.3", "140.82.113.3", "20.27.177.113", "20.200.245.247",
	}},
	{Suffix: "githubusercontent.com", IPs: []string{
		"185.199.108.133", "185.199.109.133", "185.199.110.133", "185.199.111.133",
	}},
}

// Config 是 ghsmart 的顶层配置结构，对应 configs/default.yaml。
type Config struct {
	DoHEndpoints  []string `yaml:"doh_endpoints"`
	Domains       []string `yaml:"domains"`
	ProbeTimeout  string   `yaml:"probe_timeout"`
	Interval      string   `yaml:"interval"`
	MaxConcurrent int      `yaml:"max_concurrent"`
	// MaxProbeIPs 是每个域名最多探测的候选 IP 数（DoH 返回顺序即权威顺序）。
	// 截断候选池是探测提速的关键之一：测完前 3 个就出决策，不再等长尾 IP。
	// <=0 时按默认 3 处理。
	MaxProbeIPs int      `yaml:"max_probe_ips"`
	WebProxy    WebProxy `yaml:"web_proxy"`
}

// DefaultSplitHosts 是默认需要 TLS 分片的域名后缀。
// 覆盖 GitHub 主站、静态资源、raw/objects 下载、Pages、包仓库。
var DefaultSplitHosts = []string{
	"github.com",
	"githubusercontent.com",
	"githubassets.com",
	"github.io",
	"githubapp.com",
	"ghcr.io",
	"github.blog",
	"fastly.net",
}

// DefaultEndpoints 是未配置 DoH 时的内置端点（均为公共 DoH 服务，非自建代理）。
var DefaultEndpoints = []string{
	"https://cloudflare-dns.com/dns-query",
	"https://dns.google/dns-query",
	"https://dns.alidns.com/dns-query",
}

// DefaultDomains 是未配置域名时的默认目标域名。
var DefaultDomains = []string{
	"github.com",
	"github.global.ssl.fastly.net",
	"raw.githubusercontent.com",
	"objects.githubusercontent.com",
	"release-assets.githubusercontent.com",
}

// Load 从 path 读取 YAML 配置；文件不存在或字段缺失时使用内置默认值。
// path 为空时使用默认路径 configs/default.yaml（相对当前工作目录）。
func Load(path string) (*Config, error) {
	if path == "" {
		path = "configs/default.yaml"
	}

	cfg := &Config{}
	data, err := os.ReadFile(path)
	if err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("解析配置 %s 失败: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("读取配置 %s 失败: %w", path, err)
	}

	fillDefaults(cfg)
	if _, err := cfg.ProbeTimeoutDuration(); err != nil {
		return nil, err
	}
	if _, err := cfg.IntervalDuration(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// fillDefaults 为空缺字段填充默认值。
func fillDefaults(cfg *Config) {
	if len(cfg.DoHEndpoints) == 0 {
		cfg.DoHEndpoints = append([]string(nil), DefaultEndpoints...)
	}
	if len(cfg.Domains) == 0 {
		cfg.Domains = append([]string(nil), DefaultDomains...)
	}
	if cfg.ProbeTimeout == "" {
		cfg.ProbeTimeout = "5s"
	}
	if cfg.Interval == "" {
		cfg.Interval = "10m"
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 10
	}
	if cfg.MaxProbeIPs <= 0 {
		cfg.MaxProbeIPs = 3 // 每个域名只探测 DoH 前 3 个候选，先到先决策
	}
	if cfg.WebProxy.Listen == "" {
		cfg.WebProxy.Listen = "127.0.0.1:18080"
	}
	if cfg.WebProxy.SplitDelayMS < 0 {
		cfg.WebProxy.SplitDelayMS = 0
	}
	if cfg.WebProxy.SplitDelayMS == 0 && cfg.WebProxy.SplitWindow == 0 {
		cfg.WebProxy.SplitDelayMS = 10 // 智能分片默认 10ms 间隔
	}
	if cfg.WebProxy.DialTimeoutMS <= 0 {
		cfg.WebProxy.DialTimeoutMS = 3000 // 单个候选 IP 3s 建连上限
	}
	if len(cfg.WebProxy.SplitHosts) == 0 {
		cfg.WebProxy.SplitHosts = append([]string(nil), DefaultSplitHosts...)
	}
	if len(cfg.WebProxy.FallbackIPs) == 0 {
		cfg.WebProxy.FallbackIPs = append([]FallbackGroup(nil), DefaultFallbackIPs...)
	}
}

// ProbeTimeoutDuration 返回探测超时时长。
func (c *Config) ProbeTimeoutDuration() (time.Duration, error) {
	d, err := time.ParseDuration(c.ProbeTimeout)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("非法 probe_timeout %q", c.ProbeTimeout)
	}
	return d, nil
}

// IntervalDuration 返回 daemon 轮询间隔时长。
func (c *Config) IntervalDuration() (time.Duration, error) {
	d, err := time.ParseDuration(c.Interval)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("非法 interval %q", c.Interval)
	}
	return d, nil
}
