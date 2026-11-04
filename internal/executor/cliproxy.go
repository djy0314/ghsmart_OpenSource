// 命令行工具代理接管的共享定义（跨平台）。
//
// Windows 实现见 cliproxy_windows.go，其他平台见 cliproxy_other.go。
// 常量与 URL 归一化放在这里，避免两套实现各写一份而漂移。
package executor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

const (
	// gitProxyKey 是「只对 github.com 生效」的 git 代理键。
	// git 的 http.<url>.* 段按 URL 前缀匹配，因此这一条不会影响
	// 任何非 github.com 的远端（公司内网仓库、私有 Gitea 等）。
	gitProxyKey = "http.https://github.com.proxy"

	// envProxyValue 是我们写入的默认局部代理值。
	envProxyValue = "http://127.0.0.1:18080"

	// envNoProxyValue 是配套的直连白名单：本机与局域网后缀不走代理。
	envNoProxyValue = "localhost,127.0.0.1,::1,*.local,*.internal"
)

// CLIProxyResult 描述一次命令行加速的实际落地情况，供界面如实回显。
// 字段都带 json tag，前端拿到的就是这几个名字。
type CLIProxyResult struct {
	GitApplied bool   `json:"gitApplied"` // git 按 URL 代理已写入
	EnvApplied bool   `json:"envApplied"` // 用户级环境变量已写入
	Skipped    string `json:"skipped"`    // 非空 = 因用户已有配置而跳过，原因为此
	Detail     string `json:"detail"`     // 给日志/提示用的补充说明
}

// toProxyURL 把 "127.0.0.1:18080" 归一成 "http://127.0.0.1:18080"。
func toProxyURL(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if strings.Contains(addr, "://") {
		return addr
	}
	return "http://" + addr
}

// removeGitProxyEntries 撤销我们写入的 github.com 专用代理条目。
//
// 难点：我们写的地址是 http://127.0.0.1:<随机端口>，而用户自己的 Clash /
// v2ray 也可能是回环地址。一律按「回环就删」会误删用户配置，
// 一律按「固定端口删」又会漏掉历史残留（实测漏了 6 条，导致 git 全不可用）。
//
// 所以按这个优先级处理：
//  1. 有写入记录（cliproxy_git.json）→ 精确删除记录里的值，然后清空记录
//  2. 没有记录，但同一键下有多条 → 判定为「历史残留」（我们多次写入留下的），
//     把其中的回环条目全清掉
//  3. 没有记录，且只有一条 → 视为用户自己配的，一个字都不动
func removeGitProxyEntries() {
	vals := gitProxyValues()
	if len(vals) == 0 {
		return
	}

	if recorded := loadProxyRecord(); len(recorded) > 0 {
		for _, v := range recorded {
			_, _ = runGit("config", "--global", "--unset-all", "--fixed-value", gitProxyKey, v)
		}
		clearProxyRecord()
		return
	}

	if len(vals) >= 2 {
		for _, v := range vals {
			if isLoopbackProxy(v) {
				_, _ = runGit("config", "--global", "--unset-all", "--fixed-value", gitProxyKey, v)
			}
		}
	}
}

// gitProxyValues 读取当前该键下的全部值。
func gitProxyValues() []string {
	out, err := runGit("config", "--global", "--get-all", gitProxyKey)
	if err != nil {
		return nil
	}
	var vals []string
	for _, line := range strings.Split(out, "\n") {
		if v := strings.TrimSpace(line); v != "" {
			vals = append(vals, v)
		}
	}
	return vals
}

// ---------- 写入记录（保证「只删自己写的」）----------

// proxyRecordPath 返回记录文件路径（GHSMART_CLIPROXY_FILE 可覆盖，单测隔离用）。
func proxyRecordPath() string {
	if p := os.Getenv("GHSMART_CLIPROXY_FILE"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ghsmart", "cliproxy_git.json")
}

// loadProxyRecord 读取我们写过、尚未撤销的值。
func loadProxyRecord() []string {
	p := proxyRecordPath()
	if p == "" {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var vals []string
	if err := json.Unmarshal(b, &vals); err != nil {
		return nil
	}
	return vals
}

// saveProxyRecord 记录写入的值。
func saveProxyRecord(vals []string) {
	p := proxyRecordPath()
	if p == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return
	}
	if b, err := json.Marshal(vals); err == nil {
		_ = os.WriteFile(p, b, 0o600)
	}
}

// clearProxyRecord 删除记录文件。
func clearProxyRecord() {
	if p := proxyRecordPath(); p != "" {
		_ = os.Remove(p)
	}
}

// isLoopbackProxy 判断代理地址是否指向本机回环（= 大概率是我们写的）。
func isLoopbackProxy(raw string) bool {
	host := proxyHost(raw)
	switch host {
	case "127.0.0.1", "localhost", "::1", "[::1]":
		return true
	}
	return false
}

// proxyHost 从 "http://127.0.0.1:18080" 这类字符串里取出主机部分。
func proxyHost(raw string) string {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	// 去掉 user:pass@
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	// IPv6 带方括号：[::1]:8080
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i >= 0 {
			return s[:i+1]
		}
		return s
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}
