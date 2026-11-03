// Package executor 负责落盘动作：Hosts 原子化管理、DNS 缓存刷新与 Git 配置（预留）。
package executor

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// BlockBegin / BlockEnd 是 ghsmart 在 Hosts 文件中管理的区块标记。
const (
	BlockBegin = "# ghsmart begin"
	BlockEnd   = "# ghsmart end"
	// CommentPrefix 是 ghsmart 注释用户冲突行时加的前缀，remove 时据此原样恢复。
	CommentPrefix = "# [ghsmart 已注释] "
)

// HostsPath 返回当前系统的 Hosts 文件路径。
func HostsPath() string {
	if runtime.GOOS == "windows" {
		return `C:\Windows\System32\drivers\etc\hosts`
	}
	return "/etc/hosts"
}

// StateDir 返回 ghsmart 的工作目录 ~/.ghsmart，并确保其存在。
func StateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".ghsmart")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// splitBlock 把 Hosts 内容拆成 [区块前内容, 区块内内容, 区块后内容]。
// inside 是 BlockBegin 行尾到 BlockEnd 行首之间的原始文本（不含两端标记行）。
// found 为 false 表示文件中尚无区块标记。
func splitBlock(content string) (before, inside, after string, found bool, err error) {
	bi := strings.Index(content, BlockBegin)
	if bi < 0 {
		return content, "", "", false, nil
	}
	ei := strings.Index(content, BlockEnd)
	if ei < 0 || ei < bi {
		return "", "", "", true, fmt.Errorf("Hosts 文件存在 %q 但缺少 %q，请手工修复", BlockBegin, BlockEnd)
	}
	// inside：BlockBegin 所在行的行尾之后、BlockEnd 行首之前
	beginLineEnd := bi + len(BlockBegin)
	if idx := strings.IndexAny(content[beginLineEnd:ei], "\r\n"); idx >= 0 {
		beginLineEnd += idx
	}
	inside = content[beginLineEnd:ei]
	// after：BlockEnd 所在行的下一行开始
	lineEnd := len(content)
	if idx := strings.IndexAny(content[ei:], "\r\n"); idx >= 0 {
		lineEnd = ei + idx
		lineEnd++ // 跳过行尾换行符
		if lineEnd <= len(content) && content[lineEnd-1] == '\r' && lineEnd < len(content) && content[lineEnd] == '\n' {
			lineEnd++
		}
	}
	return content[:bi], inside, content[lineEnd:], true, nil
}

// renderBlock 生成新的 ghsmart 区块文本。
func renderBlock(entries map[string]string) string {
	var b bytes.Buffer
	b.WriteString(BlockBegin + "\n")
	b.WriteString("# 由 ghsmart 自动生成，请勿手工编辑此区块\n")
	b.WriteString("# 更新时间: " + time.Now().Format("2006-01-02 15:04:05") + "\n")
	// 按 IP 排序输出，保证同一 IP 的多个域名写在一行附近，且输出稳定
	ips := make([]string, 0, len(entries))
	for _, ip := range entries {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	// 按域名排序保证每次输出顺序一致
	domains := make([]string, 0, len(entries))
	for d := range entries {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	written := make(map[string]struct{}, len(entries))
	for _, d := range domains {
		ip := entries[d]
		key := ip + "\x00" + d
		if _, ok := written[key]; ok {
			continue
		}
		written[key] = struct{}{}
		b.WriteString(fmt.Sprintf("%s %s\n", ip, d))
	}
	b.WriteString(BlockEnd + "\n")
	return b.String()
}

// writeHostsAtomic 用「临时文件 + 重命名」方式写入 Hosts；
// Windows 下若重命名失败（目标被占用等），回退为直接覆盖并返回提示。
func writeHostsAtomic(path string, content []byte) (fallbackNote string, err error) {
	tmp := path + ".ghsmart.tmp"
	if err := os.WriteFile(tmp, content, 0o644); err != nil {
		return "", fmt.Errorf("写临时文件失败: %w", err)
	}
	if err := os.Rename(tmp, path); err == nil {
		return "", nil
	}
	// Windows 上目标文件可能被占用，回退为直接覆盖
	if err := os.WriteFile(path, content, 0o644); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("写入 Hosts 失败（若为 Windows 请以管理员身份运行）: %w", err)
	}
	_ = os.Remove(tmp)
	return "注意: 原子重命名失败，已回退为直接覆盖", nil
}

// backupHosts 把 Hosts 文件备份到指定路径。
func backupHosts(path, backupPath string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Hosts 不存在（极少见），无需备份
		}
		return err
	}
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(backupPath, data, 0o644)
}

// lineDomains 从一行 hosts 记录中提取域名集合（跳过 IP 列与行内注释）。
// 例："1.2.3.4 a.com b.com # 注释" → {"a.com", "b.com"}。
func lineDomains(line string) []string {
	var out []string
	for _, f := range strings.Fields(line)[1:] {
		if strings.HasPrefix(f, "#") {
			break // 行内注释及其后内容不算域名
		}
		out = append(out, f)
	}
	return out
}

// commentOutConflicts 把 content 中与待写入域名冲突的用户行注释掉
// （Windows hosts 首条匹配优先，不注释会覆盖区块里的加速 IP）。
// 已是注释的行不处理，天然幂等、绝不双重注释。
func commentOutConflicts(content string, domains map[string]struct{}) string {
	if len(domains) == 0 {
		return content
	}
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, d := range lineDomains(trimmed) {
			if _, hit := domains[d]; hit {
				lines[i] = CommentPrefix + line
				break
			}
		}
	}
	return strings.Join(lines, "\n")
}

// restoreCommented 把 ghsmart 注释过的用户行原样恢复（去掉前缀）。
func restoreCommented(content string) string {
	return strings.ReplaceAll(content, CommentPrefix, "")
}

// ReadHostsBlock 返回当前 ghsmart 区块中生效的 域名 -> IP 映射。
// 没有区块时返回空 map 和 nil。
func ReadHostsBlock() (map[string]string, error) {
	return readHostsBlockFrom(HostsPath())
}

// readHostsBlockFrom 从指定路径解析 ghsmart 区块内容，供测试复用。
func readHostsBlockFrom(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("读取 Hosts 失败: %w", err)
	}
	_, inside, _, found, err := splitBlock(string(data))
	if err != nil {
		return nil, err
	}
	entries := map[string]string{}
	if !found {
		return entries, nil
	}
	for _, line := range strings.Split(inside, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			entries[fields[1]] = fields[0]
		}
	}
	return entries, nil
}

// ApplyHosts 把 entries（域名 -> IP）写入系统 Hosts 的 ghsmart 区块，
// 绝不触碰区块之外的用户内容。写入前先备份，写入后刷新 DNS 缓存。
func ApplyHosts(entries map[string]string) error {
	backup, err := backupPath()
	if err != nil {
		return err
	}
	if err := mutateHosts(HostsPath(), backup, entries); err != nil {
		return err
	}
	if err := FlushDNS(); err != nil {
		fmt.Fprintf(os.Stderr, "警告: 刷新 DNS 缓存失败: %v\n", err)
	}
	return nil
}

// RemoveHosts 删除系统 Hosts 中的 ghsmart 区块并刷新 DNS 缓存。
// 没有区块时不做任何写入，直接返回 nil。
func RemoveHosts() error {
	backup, err := backupPath()
	if err != nil {
		return err
	}
	if err := mutateHosts(HostsPath(), backup, nil); err != nil {
		return err
	}
	if err := FlushDNS(); err != nil {
		fmt.Fprintf(os.Stderr, "警告: 刷新 DNS 缓存失败: %v\n", err)
	}
	return nil
}

// backupPath 返回 Hosts 备份文件路径 ~/.ghsmart/hosts.bak。
func backupPath() (string, error) {
	dir, err := StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "hosts.bak"), nil
}

// mutateHosts 对指定路径的 Hosts 文件执行区块替换：
// entries 非空时写入新区块，nil 时删除区块。供 ApplyHosts/RemoveHosts 与测试共用。
func mutateHosts(path, backupPath string, entries map[string]string) error {
	if err := backupHosts(path, backupPath); err != nil {
		return fmt.Errorf("备份 Hosts 失败: %w", err)
	}

	var old []byte
	old, readErr := os.ReadFile(path)
	if readErr != nil && !os.IsNotExist(readErr) {
		return fmt.Errorf("读取 Hosts 失败: %w", readErr)
	}

	before, _, after, found, err := splitBlock(string(old))
	if err != nil {
		return err
	}

	var newContent string
	if entries == nil {
		if !found {
			return nil // 无区块，无需处理
		}
		// 删除区块，并恢复之前被 ghsmart 注释的用户行
		newContent = strings.TrimLeft(restoreCommented(before)+restoreCommented(after), "\n\r")
	} else {
		// 写入区块前，把区块外与待写入域名冲突的用户行注释掉，
		// 否则 Windows hosts「首条匹配优先」会让加速记录失效
		domains := make(map[string]struct{}, len(entries))
		for d := range entries {
			domains[d] = struct{}{}
		}
		newContent = strings.TrimLeft(
			commentOutConflicts(before, domains)+renderBlock(entries)+commentOutConflicts(after, domains),
			"\n\r")
	}

	note, err := writeHostsAtomic(path, []byte(newContent))
	if err != nil {
		return err
	}
	if note != "" {
		fmt.Fprintln(os.Stderr, note)
	}
	return nil
}
