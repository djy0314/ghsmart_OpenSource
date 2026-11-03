package sysproxy

import (
	"strings"
)

// <local> 是 Windows 默认的「本地地址不走代理」项，必须保留。
const localBypass = "<local>"

// bypassDropSuffixes 是「绝不能出现在 ProxyOverride 里」的域名后缀。
//
// 为什么必须删：ProxyOverride（「请勿对以下列条目开头的地址使用代理服务器」）
// 里的域名会**直接绕过**我们 127.0.0.1:18080 的代理去直连，而 GitHub 直连必被墙
// → 浏览器报 ERR_CONNECTION_CLOSED。历史残留（换过各种加速镜像的用户机器上很常见）
// 里往往有 *.github.com、*.ghproxy.net 之类，必须强制清掉。
//
// 命中规则：条目去掉 * / 前导点 / 端口 后，等于后缀或以 "."+后缀 结尾。
var bypassDropSuffixes = []string{
	// GitHub 官方域（浏览、API、静态资源、容器、Pages）
	"github.com",
	"githubusercontent.com",
	"githubassets.com",
	"github.io",
	"githubapp.com",
	"github.blog",
	"ghcr.io",
	"github.dev",
	// 常见的第三方 GitHub 加速镜像（用户装了旧工具后留在 bypass 里的残留）
	"ghproxy.net",
	"ghproxy.com",
	"ghproxy.cc",
	"gh-proxy.com",
	"ghp.ci",
	"ghfast.top",
	"ghps.cc",
	"kkgithub.com",
	"gitclone.com",
	"github.moeyy.xyz",
	"hub.fastgit.org",
	"hub.gitmirror.com",
	"gitmirror.com",
	"gh.api.99988866.xyz",
	"gh.api.99988866.xyz.cdn.cloudflare.net",
	"download.fastgit.org",
	"shrill-shape.com",
}

// SanitizeOverride 清理 Windows 的 ProxyOverride 列表：
//   - 剔除所有 GitHub 系域名（含 *.github.com 这类通配写法）
//   - 保留 <local>、内网 IP/CIDR、其他用户自定义项，顺序不变
//   - 去重（大小写不敏感）
//
// 返回清理后的字符串（分号分隔）和实际被剔除的原始条目（用于日志/UI 提示）。
// 清理后为空时补回 <local>，保持 Windows 默认语义（否则本地回环也会走代理）。
func SanitizeOverride(raw string) (string, []string) {
	parts := strings.Split(raw, ";")
	kept := make([]string, 0, len(parts))
	removed := make([]string, 0, 4)
	seen := make(map[string]struct{}, len(parts))

	for _, p := range parts {
		entry := strings.TrimSpace(p)
		if entry == "" {
			continue
		}
		if isProxyBypassDropped(entry) {
			removed = append(removed, entry)
			continue
		}
		key := strings.ToLower(entry)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		kept = append(kept, entry)
	}

	if len(kept) == 0 {
		kept = append(kept, localBypass)
	}
	return strings.Join(kept, ";"), removed
}

// isProxyBypassDropped 判断单条 bypass 是否属于「必须删掉」的 GitHub 系域名。
func isProxyBypassDropped(entry string) bool {
	h := normalizeBypassEntry(entry)
	if h == "" {
		return false
	}
	if h == localBypass {
		return false
	}
	for _, suffix := range bypassDropSuffixes {
		if h == suffix || strings.HasSuffix(h, "."+suffix) {
			return true
		}
	}
	return false
}

// normalizeBypassEntry 把 "*.github.com"、"*github.com"、"github.com:443"、
// "https://github.com" 统一成 "github.com"，便于后缀比较。
func normalizeBypassEntry(entry string) string {
	h := strings.ToLower(strings.TrimSpace(entry))
	if h == "" || h == localBypass {
		return h
	}
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	h = strings.TrimPrefix(h, "*")
	h = strings.TrimPrefix(h, ".")
	h = strings.TrimSuffix(h, ".")
	// 去掉 host:port（IPv6 的 [::1] 不动）
	if strings.HasPrefix(h, "[") {
		return h
	}
	if i := strings.LastIndex(h, ":"); i > 0 {
		h = h[:i]
	}
	return strings.TrimPrefix(h, ".")
}

// BypassHasGitHub 用于自检/诊断：判断一段 ProxyOverride 里是否还残留 GitHub 域名。
func BypassHasGitHub(raw string) []string {
	out := make([]string, 0, 4)
	for _, p := range strings.Split(raw, ";") {
		if entry := strings.TrimSpace(p); entry != "" && isProxyBypassDropped(entry) {
			out = append(out, entry)
		}
	}
	return out
}
