//go:build !windows

package executor

// 非 Windows 平台只实现 git 按 URL 代理（git 配置本身跨平台）；
// 环境变量接管依赖 Windows 注册表，这里保持"只做 git"的最小实现。

// ApplyCLIProxy 让 git 走本地代理（非 Windows 下不碰环境变量）。
func ApplyCLIProxy(addr string, _ bool) (CLIProxyResult, error) {
	res := CLIProxyResult{}
	proxyURL := toProxyURL(addr)
	if proxyURL == "" {
		return res, nil
	}
	_, _ = runGit("config", "--global", "--unset-all", "--fixed-value", gitProxyKey, envProxyValue)
	if _, err := runGit("config", "--global", "--add", gitProxyKey, proxyURL); err == nil {
		res.GitApplied = true
	}
	return res, nil
}

// RemoveCLIProxy 精确撤销命令行代理。
func RemoveCLIProxy() error {
	_, _ = runGit("config", "--global", "--unset-all", "--fixed-value", gitProxyKey, envProxyValue)
	return nil
}
