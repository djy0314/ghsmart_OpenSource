// 命令行工具代理接管的共享定义（跨平台）。
//
// Windows 实现见 cliproxy_windows.go，其他平台见 cliproxy_other.go。
// 常量与 URL 归一化放在这里，避免两套实现各写一份而漂移。
package executor

import "strings"

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
