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
//
// ★ 为什么要重试（v1.0.11 实机事故）：
// 一键加速会写两次 Hosts——主域名探测成功时先写一次让用户秒生效，收尾再全量写一次。
// 实测第二写入会偶发失败：安全软件正在扫描刚刚变动的 hosts、或 DNS 客户端握着句柄，
// 重命名与直接覆盖同时被拒（日志里目录 mtime 更新了、hosts 本体却没更新，就是这一下）。
// 以前失败只往上抛错误、不重试也不写日志，用户看到的是「按钮点了没反应 / 报错」，
// 而磁盘上其实还留着第一次的半套记录——最难查的一类现场。
// 现在：最多尝试 3 次，间隔 150ms/300ms，给扫描器让路；仍失败才报错，且错误带尝试次数。
func writeHostsAtomic(path string, content []byte) (fallbackNote string, err error) {
	const attempts = 3
	var lastErr error
	for i := 1; i <= attempts; i++ {
		note, e := writeHostsOnce(path, content)
		if e == nil {
			if i > 1 {
				return note, nil // 重试成功：对用户就是成功，不必惊动
			}
			return note, nil
		}
		lastErr = e
		if i < attempts {
			// 第一次 150ms、第二次 300ms：给实时扫描/句柄释放留窗口
			time.Sleep(time.Duration(i) * 150 * time.Millisecond)
		}
	}
	return "", fmt.Errorf("%w（已自动重试 %d 次仍失败，通常是安全软件正在占用 hosts 文件，请稍后再点一次）",
		lastErr, attempts)
}

// writeHostsOnce 是单次写入尝试：先原子重命名，失败回退直接覆盖。
func writeHostsOnce(path string, content []byte) (fallbackNote string, err error) {
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
	out, _ := commentOutConflictsReport(content, domains)
	return out
}

// commentOutConflictsReport 是 commentOutConflicts 的带报告版本：
// 额外返回被注释掉的行（去重后限量），供界面如实告知用户「动了什么」。
//
// 为什么要报告：这些行往往不是用户手写的，而是**另一款加速工具**写的
// （Watt Toolkit / FastGithub / GitHub520 等）。以前的实现默默把它们注释掉，
// 用户完全不知道——于是「装了两款加速器，其中一款突然不灵了」这种事
// 永远查不出原因，最后两边都被骂。
func commentOutConflictsReport(content string, domains map[string]struct{}) (string, []string) {
	if len(domains) == 0 {
		return content, nil
	}
	var hits []string
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, d := range lineDomains(trimmed) {
			if _, hit := domains[d]; hit {
				lines[i] = CommentPrefix + line
				hits = append(hits, trimmed)
				break
			}
		}
	}
	return strings.Join(lines, "\n"), hits
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
	_, err := ApplyHostsReport(entries)
	return err
}

// ApplyHostsReport 与 ApplyHosts 相同，但额外返回本次对区块外内容的影响
// （注释掉了几行冲突记录、检测到哪些其他加速工具）。
//
// 调用方应当在 Commented > 0 时提示用户：
// 我们为了让自己生效，压住了别人的记录，这件事必须让用户知道。
func ApplyHostsReport(entries map[string]string) (HostsReport, error) {
	var rep HostsReport
	backup, err := backupPath()
	if err != nil {
		return rep, err
	}
	rep, err = mutateHostsReport(HostsPath(), backup, entries)
	if err != nil {
		return rep, err
	}
	if err := FlushDNS(); err != nil {
		fmt.Fprintf(os.Stderr, "警告: 刷新 DNS 缓存失败: %v\n", err)
	}
	return rep, nil
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

// HostsReport 描述一次写入对「区块外内容」的影响，供界面如实告知用户。
//
// 这个结构存在的理由：hosts 加速工具之间会抢同一批域名。ghsmart 写入前必须
// 把冲突行注释掉（否则 Windows「首条匹配优先」会让自己的记录失效），
// 但**不能默默做**——用户需要知道自己的另一款工具被压住了，否则
// 「装了两个加速器，其中一个突然失效」永远查不出原因。
type HostsReport struct {
	// Commented 是本次被注释掉的区块外冲突行数（0 表示没碰任何用户内容）。
	Commented int `json:"commented"`
	// CommentedLines 是被注释行的样本（最多 5 条，每条已截断）。
	CommentedLines []string `json:"commentedLines,omitempty"`
	// ForeignTools 是检测到的其他 Hosts 加速工具（按区块注释里的品牌特征识别）。
	ForeignTools []string `json:"foreignTools,omitempty"`
}

// foreignToolMarks 是已知 Hosts 加速工具的「指纹」。
//
// 只认各家工具自己写进 hosts 的品牌字样（注释行里的产品名），
// 不去猜 IP 段——猜 IP 会把用户自己的内网解析误判成外来工具。
var foreignToolMarks = []struct {
	Name  string
	Marks []string
}{
	{"Watt Toolkit（Steam++）", []string{"steam++", "watt toolkit"}},
	{"FastGithub", []string{"fastgithub"}},
	{"UsbEAm Hosts Editor", []string{"usbeam"}},
	{"SwitchHosts", []string{"switchhosts"}},
	{"GitHub520", []string{"github520"}},
	{"dev-sidecar", []string{"dev-sidecar"}},
	{"fetch-github-hosts", []string{"fetch-github-hosts"}},
}

// detectForeignTools 扫描 hosts 区块外的文本，返回识别到的其他加速工具名（去重保序）。
func detectForeignTools(outside string) []string {
	if outside == "" {
		return nil
	}
	lower := strings.ToLower(outside)
	var out []string
	for _, t := range foreignToolMarks {
		for _, m := range t.Marks {
			if strings.Contains(lower, m) {
				out = append(out, t.Name)
				break
			}
		}
	}
	return out
}

// sampleLines 取前 n 条样本，每条按字符截断，避免把整份 hosts 塞进界面。
func sampleLines(lines []string, n int) []string {
	if len(lines) == 0 {
		return nil
	}
	if len(lines) > n {
		lines = lines[:n]
	}
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		r := []rune(strings.TrimSpace(l))
		if len(r) > 120 {
			l = string(r[:120]) + "…"
		}
		out = append(out, l)
	}
	return out
}

// mutateHosts 对指定路径的 Hosts 文件执行区块替换：
// entries 非空时写入新区块，nil 时删除区块。供 ApplyHosts/RemoveHosts 与测试共用。
func mutateHosts(path, backupPath string, entries map[string]string) error {
	_, err := mutateHostsReport(path, backupPath, entries)
	return err
}

// mutateHostsReport 是 mutateHosts 的带报告版本，返回本次对区块外内容的影响。
func mutateHostsReport(path, backupPath string, entries map[string]string) (HostsReport, error) {
	var rep HostsReport
	if err := backupHosts(path, backupPath); err != nil {
		return rep, fmt.Errorf("备份 Hosts 失败: %w", err)
	}

	var old []byte
	old, readErr := os.ReadFile(path)
	if readErr != nil && !os.IsNotExist(readErr) {
		return rep, fmt.Errorf("读取 Hosts 失败: %w", readErr)
	}

	before, _, after, found, err := splitBlock(string(old))
	if err != nil {
		return rep, err
	}

	var newContent string
	if entries == nil {
		if !found {
			return rep, nil // 无区块，无需处理
		}
		// 删除区块，并恢复之前被 ghsmart 注释的用户行
		newContent = strings.TrimLeft(restoreCommented(before)+restoreCommented(after), "\n\r")
	} else {
		// 写入区块前，把区块外与待写入域名冲突的用户行注释掉，
		// 否则 Windows hosts「首条匹配优先」会让加速记录失效。
		// 同时把这些行记进报告——动了用户的内容就必须说出来。
		domains := make(map[string]struct{}, len(entries))
		for d := range entries {
			domains[d] = struct{}{}
		}
		beforeOut, hitsBefore := commentOutConflictsReport(before, domains)
		afterOut, hitsAfter := commentOutConflictsReport(after, domains)
		hits := append(hitsBefore, hitsAfter...)
		rep.Commented = len(hits)
		rep.CommentedLines = sampleLines(hits, 5)
		// 外来工具只在「区块外」找：我们自己的区块头里没有这些品牌字样，
		// 但只扫区块外更保险，也避免将来改了区块头文案就误报。
		rep.ForeignTools = detectForeignTools(before + "\n" + after)
		newContent = strings.TrimLeft(beforeOut+renderBlock(entries)+afterOut, "\n\r")
	}

	note, err := writeHostsAtomic(path, []byte(newContent))
	if err != nil {
		return rep, err
	}
	if note != "" {
		fmt.Fprintln(os.Stderr, note)
	}
	return rep, nil
}
