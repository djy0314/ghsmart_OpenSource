// Package executor 内的 Git 协议配置实现。
//
// # v1.0.8 重构背景（重要）
//
// 旧版无条件把 git@github.com: 与 ssh://git@github.com/ 全量改写成 HTTPS。
// 对「用 SSH key 推送」的用户这是破坏性的：insteadOf 是 URL 级改写，
// **push 同样生效**，所以开一次加速后 git push 会突然改走 HTTPS，
// 轻则弹凭据框、重则 403 或者推到没权限的账号；而且是全局配置，
// 用户几乎不可能想到是一个加速器改的。
//
// 新策略按档位管理，默认档对 SSH 零影响：
//
//	GitRewriteGitOnly（默认）：只改写 git://github.com/
//	    GitHub 早在 2021 年就停用了 git:// 协议，这条实际上是零风险的
//	    历史兼容，不会改变任何人的 SSH / HTTPS 工作流。
//	GitRewriteSSH（可选）：用户显式勾选「Git 加速（HTTPS 模式）」后，
//	    才追加 git@github.com: 与 ssh://git@github.com/ 两条改写。
//
// 清理永远按「所有已知精确值」全量撤销，绝不留半档状态（换档、关功能、
// 一键还原网络三条路径都走同一个 RemoveGit）。
package executor

import (
	"fmt"
	"os/exec"
	"strings"
)

// gitInsteadOfBase 是 insteadOf 写入的目标 base。
const gitInsteadOfBase = "url.https://github.com/.insteadOf"

// Git 加速档位。
const (
	// GitRewriteGitOnly 默认档：只处理已停用的 git:// 协议，对 SSH 零影响。
	GitRewriteGitOnly = "git"
	// GitRewriteSSH 用户显式选择：额外把 SSH 与 ssh:// 改写成 HTTPS。
	GitRewriteSSH = "ssh"
)

// gitInsteadOfGitOnly 是默认档管理的改写来源。
var gitInsteadOfGitOnly = []string{
	"git://github.com/",
}

// gitInsteadOfSSH 是「HTTPS 模式」额外管理的改写来源。
// 注意 git@github.com: 落在 push 路径上——这正是必须让用户主动勾选的原因。
var gitInsteadOfSSH = []string{
	"git@github.com:",
	"ssh://git@github.com/",
}

// NormalizeGitRewrite 把外部传入的档位收敛成合法值，非法值回落到默认档。
// 默认档是「最安全」的那一个，任何意外输入都不该让 SSH 被改写。
func NormalizeGitRewrite(level string) string {
	if strings.EqualFold(strings.TrimSpace(level), GitRewriteSSH) {
		return GitRewriteSSH
	}
	return GitRewriteGitOnly
}

// gitValuesFor 返回某档位应当存在的全部改写值。
func gitValuesFor(level string) []string {
	vals := append([]string(nil), gitInsteadOfGitOnly...)
	if NormalizeGitRewrite(level) == GitRewriteSSH {
		vals = append(vals, gitInsteadOfSSH...)
	}
	return vals
}

// allGitValues 返回我们可能写过的全部值（清理用，必须覆盖所有档位）。
func allGitValues() []string {
	vals := append([]string(nil), gitInsteadOfGitOnly...)
	vals = append(vals, gitInsteadOfSSH...)
	return vals
}

// ApplyGit 按档位幂等写入 insteadOf 改写。
//
// 升档（git -> ssh）只追加；降档（ssh -> git）会先把多出来的 SSH 两条删掉，
// 保证「用户取消勾选」后立即恢复 SSH 推送能力，不需要重启。
// git 未安装时返回可读错误，由调用方决定降级（加速主流程不依赖 git）。
func ApplyGit(level string) error {
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("未检测到 git，跳过 git 加速配置: %w", err)
	}
	level = NormalizeGitRewrite(level)

	// 降档：SSH 档不再需要，先精确撤销那两条
	if level != GitRewriteSSH {
		for _, v := range gitInsteadOfSSH {
			if err := removeGitEntry(v); err != nil {
				return err
			}
		}
	}

	for _, v := range gitValuesFor(level) {
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

// RemoveGit 精确清理所有档位可能写入的 insteadOf 条目（幂等）。
//
// 这是「一键还原网络」与「关闭 Git 加速」共用的清理入口：不管用户之前
// 选的是哪一档，三条值全部按字面量精确删除，用户手工配置的其他
// insteadOf 一律不动。
func RemoveGit() error {
	if _, err := exec.LookPath("git"); err != nil {
		return nil // 没有 git 就没有可清理的东西，不算错误
	}
	for _, v := range allGitValues() {
		if err := removeGitEntry(v); err != nil {
			return err
		}
	}
	return nil
}

// removeGitEntry 删除单条 insteadOf 值（不存在时静默跳过）。
func removeGitEntry(value string) error {
	exists, err := gitConfigHas(gitInsteadOfBase, value)
	if err != nil {
		return fmt.Errorf("读取 git 配置失败: %w", err)
	}
	if !exists {
		return nil
	}
	// --fixed-value 做字面量匹配（git >= 2.30），只删我们写的那一条
	if out, err := runGit("config", "--global", "--unset-all", "--fixed-value", gitInsteadOfBase, value); err != nil {
		return fmt.Errorf("清理 git insteadOf 失败 (%s): %w: %s", value, err, strings.TrimSpace(out))
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
