// Package executor 内的 Git 配置实现（Phase 2）。
//
// ghsmart 是纯本地加速，不走任何镜像/中转；git 侧的加速点是：
// 国内对 GitHub 的 SSH（22 端口）与 git://（9418 端口）经常不可达，
// 而 HTTPS 走的正是 Hosts 优选过的 IP。因此写入三条 insteadOf 改写，
// 把 SSH/git 协议的 clone/fetch 自动改走 HTTPS：
//
//	git@github.com:owner/repo.git      -> https://github.com/owner/repo.git
//	ssh://git@github.com/owner/repo    -> https://github.com/owner/repo
//	git://github.com/owner/repo.git    -> https://github.com/owner/repo.git
//
// 写入与清理都只针对下面这三个「精确值」，绝不增删用户自己的其他配置。
package executor

import (
	"fmt"
	"os/exec"
	"strings"
)

// gitInsteadOfBase 是 insteadOf 写入的目标 base。
const gitInsteadOfBase = "url.https://github.com/.insteadOf"

// GitSettings 保留原占位接口的参数类型（Phase 1 定义），当前实现不使用其内容。
type GitSettings map[string]string

// gitInsteadOfValues 是 ghsmart 管理的三条改写来源（精确值，用于幂等写入与精确清理）。
var gitInsteadOfValues = []string{
	"git@github.com:",
	"ssh://git@github.com/",
	"git://github.com/",
}

// CommentPrefix 之外的又一个管理标记：git 配置无注释能力，靠「精确值」圈定管理范围。
// ApplyGit 幂等写入三条 insteadOf（已存在则跳过）。
// git 未安装时返回可读错误，由调用方决定降级（加速主流程不依赖 git）。
func ApplyGit(_ GitSettings) error {
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("未检测到 git，跳过 git 加速配置: %w", err)
	}
	for _, v := range gitInsteadOfValues {
		exists, err := gitConfigHas(gitInsteadOfBase, v)
		if err != nil {
			return fmt.Errorf("读取 git 配置失败: %w", err)
		}
		if exists {
			continue // 幂等：已存在不重复写
		}
		// --add 追加条目（不带它 git config 是「替换」语义，多条 insteadOf 会互相覆盖）
		if out, err := runGit("config", "--global", "--add", gitInsteadOfBase, v); err != nil {
			return fmt.Errorf("写入 git insteadOf 失败 (%s): %w: %s", v, err, strings.TrimSpace(out))
		}
	}
	return nil
}

// RemoveGit 精确清理 ghsmart 写入的三条 insteadOf。
// 使用 --fixed-value 做字面量匹配（git >= 2.30），只删 ghsmart 的值，
// 用户手工配置的其他 insteadOf 一律不动；值不存在时静默跳过。
func RemoveGit(_ GitSettings) error {
	if _, err := exec.LookPath("git"); err != nil {
		return nil // 没有 git 就没有可清理的东西，不算错误
	}
	for _, v := range gitInsteadOfValues {
		exists, err := gitConfigHas(gitInsteadOfBase, v)
		if err != nil {
			return fmt.Errorf("读取 git 配置失败: %w", err)
		}
		if !exists {
			continue
		}
		if out, err := runGit("config", "--global", "--unset-all", "--fixed-value", gitInsteadOfBase, v); err != nil {
			return fmt.Errorf("清理 git insteadOf 失败 (%s): %w: %s", v, err, strings.TrimSpace(out))
		}
	}
	return nil
}

// gitConfigHas 检查 git config --global 中指定键下是否已有精确等于 value 的条目。
func gitConfigHas(key, value string) (bool, error) {
	out, err := runGit("config", "--global", "--get-all", key)
	if err != nil {
		// exit code 1 = 键不存在，属正常情形
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return false, nil
		}
		return false, err
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == value {
			return true, nil
		}
	}
	return false, nil
}

// runGit 执行 git 子命令，返回标准输出合并输出。
// 隐藏控制台窗口，避免 GUI 下每条 git 命令闪一个黑框。
func runGit(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	hideConsole(cmd)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
