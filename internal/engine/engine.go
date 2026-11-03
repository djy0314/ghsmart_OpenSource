// Package engine 是 ghsmart 的编排内核：
// 解析 -> 探测 -> 决策 -> 写 Hosts 的完整流程。
// CLI 与 Wails GUI 两种前端都复用本包，不重写底层探测与决策代码。
package engine

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"ghsmart/internal/cache"
	"ghsmart/internal/config"
	"ghsmart/internal/decision"
	"ghsmart/internal/doh"
	"ghsmart/internal/executor"
	"ghsmart/internal/probe"
)

// applyTimeout 是单轮 apply 的整体硬超时。
// 10 秒是产品级硬约束：探测/业务校验 10 秒内必须出结论，绝不卡前端一分钟。
const applyTimeout = 10 * time.Second

// businessCheckTimeout 是单个 IP 真实业务校验（GET robots.txt）的时限。
const businessCheckTimeout = 3 * time.Second

// Reporter 接收引擎运行事件。CLI 用它打印表格，GUI 用它推送到前端。
type Reporter interface {
	// DomainStart 单个域名开始处理。
	DomainStart(domain string)
	// DomainProbed 单个域名探测完成；bestIP 为空表示无可用 IP。
	DomainProbed(domain string, results []probe.ProbeResult, bestIP string)
	// DomainSkipped 域名本轮无可用 IP，旧记录已从区块剔除。
	DomainSkipped(domain string)
	// Warn 非致命警告。
	Warn(msg string)
}

// NopReporter 丢弃所有事件，供测试或静默运行使用。
type NopReporter struct{}

func (NopReporter) DomainStart(string)                               {}
func (NopReporter) DomainProbed(string, []probe.ProbeResult, string) {}
func (NopReporter) DomainSkipped(string)                             {}
func (NopReporter) Warn(string)                                      {}

// Configure 把配置应用到引擎（探测并发数等）。
func Configure(cfg *config.Config) {
	probe.Concurrency = cfg.MaxConcurrent
}

// TruncateIPs 截断候选池：最多只探测前 n 个 IP。
// DoH 应答里 A 记录的顺序就是权威解析顺序，前几个最可信，
// 长尾候选只会拖慢整体决策（探测提速手段之一）。
func TruncateIPs(ips []string, n int) []string {
	if n <= 0 || len(ips) <= n {
		return ips
	}
	return ips[:n]
}

// ResolveAndProbe 对单个域名完成 DoH 解析与 IP 探测，返回探测结果。
// 候选池按 cfg.MaxProbeIPs 截断（默认 3），测完即决策，不等长尾 IP。
func ResolveAndProbe(ctx context.Context, cfg *config.Config, domain string) ([]probe.ProbeResult, error) {
	timeout, err := cfg.ProbeTimeoutDuration()
	if err != nil {
		return nil, err
	}
	ips, err := doh.ResolveWith(ctx, domain, cfg.DoHEndpoints)
	if err != nil {
		return nil, err
	}
	ipStrs := TruncateIPs(doh.DedupIPStrings(ips), cfg.MaxProbeIPs)
	if len(ipStrs) == 0 {
		return nil, fmt.Errorf("域名 %s 未解析到任何 IP", domain)
	}
	return probe.ProbeIPs(ctx, ipStrs, domain, timeout), nil
}

// PickChosen 根据决策结果决定该域名写入 Hosts 的 IP。
// 返回 ok=false 表示该域名本轮无可用 IP，应从区块中剔除旧记录，
// 避免把用户导向已失效的 IP（迟滞规则不变：分数差小于 15% 不切换）。
func PickChosen(best probe.ProbeResult, switchTo bool, cur string) (string, bool) {
	switch {
	case best.OK && switchTo:
		return best.IP, true
	case best.OK && !switchTo && cur != "":
		return cur, true // 迟滞：差异小于 15%，不切换
	case best.OK:
		return best.IP, true
	default:
		return "", false
	}
}

// roundOK 返回本轮探测结果中指定 IP 是否探测成功。
func roundOK(results []probe.ProbeResult, ip string) bool {
	for _, r := range results {
		if r.IP == ip {
			return r.OK
		}
	}
	return false
}

// decideSwitch 计算是否切换到新最优 IP。
// 关键修正：迟滞只对「本轮仍然探测成功」的在用 IP 生效；
// 当前在用 IP 本轮已经失败（超时/TLS 错误）时，迟滞必须失效，强制切换，
// 绝不让已失效的 IP 靠历史分数赖在 Hosts 里。
func decideSwitch(switchTo bool, cur string, results []probe.ProbeResult) bool {
	if switchTo {
		return true
	}
	if cur == "" {
		return true
	}
	return !roundOK(results, cur)
}

// stateForDomain 取出属于指定 domain 的候选状态（按 IP 为键的子 map）。
// 全局状态键带域名前缀，避免多域名共享同一批 fastly IP 时互相覆盖/串扰。
func stateForDomain(state map[string]*decision.Candidate, domain string) map[string]*decision.Candidate {
	sub := make(map[string]*decision.Candidate)
	prefix := domain + "|"
	for k, c := range state {
		if strings.HasPrefix(k, prefix) {
			sub[strings.TrimPrefix(k, prefix)] = c
		}
	}
	return sub
}

// mergeState 把子 map 的变更合并回全局状态。
func mergeState(state map[string]*decision.Candidate, sub map[string]*decision.Candidate, domain string) {
	for ip, c := range sub {
		c.Domain = domain
		state[domain+"|"+ip] = c
	}
}

// currentIPInDomain 返回指定域名当前在用的 IP（无则空串）。
func currentIPInDomain(state map[string]*decision.Candidate, domain string) string {
	for _, c := range state {
		if c.Domain == domain && c.InUse {
			return c.IP
		}
	}
	return ""
}

// markAppliedInDomain 把指定域名的在用 IP 标记为 ip。
func markAppliedInDomain(state map[string]*decision.Candidate, domain, ip string) {
	for _, c := range state {
		c.InUse = c.Domain == domain && c.IP == ip
	}
	key := domain + "|" + ip
	if c, ok := state[key]; ok {
		c.InUse = true
	} else {
		state[key] = &decision.Candidate{IP: ip, Domain: domain, InUse: true}
	}
}

// clearInUseForDomain 清除指定域名的在用标记（该域名本轮被剔除时调用）。
func clearInUseForDomain(state map[string]*decision.Candidate, domain string) {
	for _, c := range state {
		if c.Domain == domain {
			c.InUse = false
		}
	}
}

// domainResult 是单个域名并发处理后的汇总产物。
type domainResult struct {
	entries     map[string]string   // 该域名写入的 域名->IP（可能为空）
	lines       []string            // 明细行
	dropped     []string            // 被剔除的域名
	results     []probe.ProbeResult // 本轮探测明细（供探测报告落盘；DoH 失败时为空）
	checkRan    bool                // 对选定 IP 执行了真实业务校验
	checkFailed bool                // 业务校验未通过（被 RST/超时/证书不符 → 该 IP 禁止写入）
	inconclusive bool               // 校验因全局超时未跑完（不计入受限取证，避免误报）
}

// Options 是 RunApplyOpts 的可选行为开关。
type Options struct {
	// OnPrimary 在主域名（cfg.Domains[0]，即 github.com）探测出可用 IP 并写入
	// Hosts 后立刻回调（其余域名仍在后台探测），参数是本次合并写入的全部 域名->IP。
	// 用于「加速已生效」的秒级通知：主域名一通，用户马上就能打开网页。
	// 回调运行在主域名的处理协程里，不得阻塞太久。
	OnPrimary func(entries map[string]string)
}

// RunApply 执行一轮「解析 -> 探测 -> 决策 -> 写 Hosts」。
// 所有域名完全并发处理（互不阻塞），事件经 r 实时上报（回调串行化，
// 保证 CLI 表格不交错、GUI 事件有序）。
// 返回：真实写入 Hosts 的 entries（引擎自己统计，不依赖回读）、明细行、
// restricted（是否判定为「网络环境受限：所有业务校验均未通过」）、错误。
func RunApply(ctx context.Context, cfg *config.Config, r Reporter) (map[string]string, []string, bool, error) {
	return RunApplyOpts(ctx, cfg, r, Options{})
}

// RunApplyOpts 在 RunApply 的基础上支持主域名提前生效：
// github.com 探测出可用 IP 的那一刻就合并写入 Hosts 并回调 OnPrimary，
// raw/objects 等其余域名继续在后台探测，最终由收尾的全量写入统一。
//
// 并发模型说明：probe.ProbeIPs 的信号量（probe.Concurrency）是包级全局的，
// 所有域名的所有候选 IP 共享同一个全局协程池——谁先测完谁先出结果，
// 不存在「按域名逐个串行探测」的旧模式。
func RunApplyOpts(ctx context.Context, cfg *config.Config, r Reporter, opts Options) (map[string]string, []string, bool, error) {
	if r == nil {
		r = NopReporter{}
	}
	state, err := decision.LoadState()
	if err != nil {
		r.Warn("读取状态失败，使用空状态: " + err.Error())
		state = make(map[string]*decision.Candidate)
	}
	// 丢弃旧版无域名前缀的键，避免脏数据累积
	for k := range state {
		if !strings.Contains(k, "|") {
			delete(state, k)
		}
	}

	var mu sync.Mutex // 保护 state / entries / lines / dropped，并串行化 Reporter 回调
	var wg sync.WaitGroup
	entries := make(map[string]string, len(cfg.Domains))
	lines := make([]string, 0, len(cfg.Domains))
	dropped := make([]string, 0)
	report := make(map[string][]cache.ProbeRecord, len(cfg.Domains)) // 探测报告（预检用）
	checkRan, checkFailed := 0, 0                                    // 业务校验执行数 / 失败数

	primary := ""
	if len(cfg.Domains) > 0 {
		primary = cfg.Domains[0]
	}

	for _, domain := range cfg.Domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			res := processDomain(ctx, cfg, domain, r, state, &mu)
			// ★ 主域名提前生效：不等其余域名，立刻把「现有区块 + 主域名新 IP」
			// 合并写入 Hosts（合并而非整块替换，避免把其他域名的有效记录短暂清空），
			// 然后回调通知「加速已生效」。
			// 本协程在 wg.Wait() 之前执行完毕，与收尾的全量写入天然不并发。
			if domain == primary && opts.OnPrimary != nil && len(res.entries) > 0 {
				if merged, merr := mergeIntoCurrentBlock(res.entries); merr == nil {
					if aerr := executor.ApplyHosts(merged); aerr == nil {
						opts.OnPrimary(merged)
					} else {
						r.Warn("主域名提前写入 Hosts 失败: " + aerr.Error())
					}
				}
			}
			mu.Lock()
			defer mu.Unlock()
			for d, ip := range res.entries {
				entries[d] = ip
			}
			lines = append(lines, res.lines...)
			dropped = append(dropped, res.dropped...)
			if res.checkRan {
				checkRan++
				if res.checkFailed {
					checkFailed++
				}
			}
			// 探测报告：DoH 解析失败的域名没有本轮明细，不进报告（保留证据新鲜度）
			if len(res.results) > 0 {
				recs := make([]cache.ProbeRecord, 0, len(res.results))
				for _, pr := range res.results {
					recs = append(recs, cache.ProbeRecord{IP: pr.IP, OK: pr.OK, Err: pr.Err})
				}
				report[domain] = recs
			}
		}(domain)
	}
	wg.Wait()

	// ★ 受限网络判定：跑过业务校验、且所有校验都不通过、且没有任何域名写入成功
	//（个别域名 DoH 失败/全局超时未跑完校验时不误报——证据不足不下结论）。
	restricted := checkRan > 0 && checkFailed == checkRan && len(entries) == 0

	// 落盘上一轮探测报告（深度加速「开启预检」的证据来源，失败不致命）
	if err := cache.SaveProbeReport(report); err != nil {
		r.Warn("保存探测报告失败: " + err.Error())
	}

	for _, d := range dropped {
		lines = append(lines, fmt.Sprintf("%s -> (剔除，本轮无可用 IP)", d))
	}
	sort.Strings(lines)

	if len(entries) == 0 && len(dropped) == 0 {
		return nil, nil, restricted, fmt.Errorf("本轮没有任何域名处理成功")
	}
	if err := decision.SaveState(state); err != nil {
		r.Warn("保存状态失败: " + err.Error())
	}
	// restricted 时 entries 必为空 → ApplyHosts(空) 会清空区块（自动清理残留的无效记录）
	if err := executor.ApplyHosts(entries); err != nil {
		return entries, lines, restricted, fmt.Errorf("写入 Hosts 失败（请以管理员身份运行）: %w", err)
	}
	// git 加速：写 Hosts 成功后同步应用 insteadOf 改写（SSH/git 协议 -> HTTPS）。
	// 失败不致命（未装 git 等），只告警，不影响主流程。
	if len(entries) > 0 {
		if err := executor.ApplyGit(nil); err != nil {
			r.Warn(err.Error())
		}
	}
	return entries, lines, restricted, nil
}

// RestoreHosts 是「安全还原」的统一入口（GUI 与 CLI 共用）：
// 删除 Hosts 区块、还原被注释的冲突行、清理 git insteadOf 配置。
// git 清理失败不致命，只告警。
func RestoreHosts(r Reporter) error {
	if r == nil {
		r = NopReporter{}
	}
	if err := executor.RemoveHosts(); err != nil {
		return err
	}
	if err := executor.RemoveGit(nil); err != nil {
		r.Warn("git insteadOf 清理失败: " + err.Error())
	}
	return nil
}

// processDomain 处理单个域名：解析 -> 探测 -> 决策，返回该域名的写入结果。
// state 与 Reporter 回调的访问由 mu 串行化。
func processDomain(ctx context.Context, cfg *config.Config, domain string, r Reporter, state map[string]*decision.Candidate, mu *sync.Mutex) domainResult {
	mu.Lock()
	r.DomainStart(domain)
	sub := stateForDomain(state, domain)
	cur := currentIPInDomain(sub, domain)
	mu.Unlock()

	results, err := ResolveAndProbe(ctx, cfg, domain)
	if err != nil {
		// DoH 解析失败属于本地解析链路问题（不代表 IP 失效），
		// 此时保留旧 IP 并告警，避免本地网络抖动导致整块 Hosts 被清空。
		mu.Lock()
		defer mu.Unlock()
		r.Warn(fmt.Sprintf("DoH 解析失败，保留 %s 旧记录: %v", domain, err))
		out := domainResult{entries: map[string]string{}}
		if cur != "" {
			out.entries[domain] = cur
			out.lines = append(out.lines, fmt.Sprintf("%s -> %s", domain, cur))
		}
		return out
	}

	best, switchTo := decision.SelectBest(results, sub)

	mu.Lock()
	defer mu.Unlock()

	// 迟滞修正：当前在用 IP 本轮已失败时，强制切换，绝不保活失效 IP
	switchTo = decideSwitch(switchTo, cur, results)
	chosen, ok := PickChosen(best, switchTo, cur)

	bestIP := chosen
	if !ok {
		bestIP = ""
	}
	r.DomainProbed(domain, results, bestIP)

	out := domainResult{entries: map[string]string{}, results: results}
	if !ok {
		// 本轮该域名所有候选 IP 均失败或处于冷却期：
		// 必须把旧记录从 ghsmart 区块中剔除，绝不沿用失效 IP。
		clearInUseForDomain(state, domain)
		out.dropped = append(out.dropped, domain)
		r.DomainSkipped(domain)
		return out
	}

	// ★ 真实业务连通性校验（写入 Hosts 前的最后一关）：
	// 带 SNI + 严格证书校验直连 chosen 发 GET robots.txt。
	// TCP/TLS 探测通过 ≠ 网页能用（VPN 在 TLS 层代答握手后掐业务流量、
	// DoH 污染返回「不是这个域名」的 IP，都能骗过握手探测）。
	// 校验不过 → 该 IP 禁止写入 Hosts，按「无可用 IP」处理。
	if ctx.Err() != nil {
		// 全局 10 秒预算已耗尽：宁可不写，也绝不写一个没通过业务校验的 IP
		out.inconclusive = true
		out.lines = append(out.lines, fmt.Sprintf("%s -> %s（全局超时，业务校验未完成，本轮放弃）", domain, chosen))
		clearInUseForDomain(state, domain)
		out.dropped = append(out.dropped, domain)
		r.DomainSkipped(domain)
		return out
	}
	out.checkRan = true
	if cerr := probe.BusinessCheck(ctx, chosen, domain, businessCheckTimeout); cerr != nil {
		if ctx.Err() != nil {
			// 校验途中全局预算耗尽：不算受限证据，但同样放弃写入
			out.inconclusive = true
			out.lines = append(out.lines, fmt.Sprintf("%s -> %s（全局超时，业务校验未完成，本轮放弃）", domain, chosen))
			clearInUseForDomain(state, domain)
			out.dropped = append(out.dropped, domain)
			r.DomainSkipped(domain)
			return out
		}
		out.checkFailed = true
		clearInUseForDomain(state, domain)
		out.dropped = append(out.dropped, domain)
		out.lines = append(out.lines, fmt.Sprintf("%s -> %s 业务校验失败（%v），禁止写入 Hosts", domain, chosen, cerr))
		r.Warn(fmt.Sprintf("%s 的候选 IP %s 未通过真实业务校验: %v", domain, chosen, cerr))
		r.DomainSkipped(domain)
		return out
	}
	out.lines = append(out.lines, fmt.Sprintf("%s -> %s（已通过真实业务校验）", domain, chosen))

	markAppliedInDomain(sub, domain, chosen)
	mergeState(state, sub, domain)
	out.entries[domain] = chosen
	out.lines = append(out.lines, fmt.Sprintf("%s -> %s", domain, chosen))
	return out
}

// mergeIntoCurrentBlock 把新增条目合并进当前 Hosts 区块的已有记录。
// 主域名提前生效时用合并写入而不是整块替换，
// 避免其他域名的有效加速记录在「提前生效 → 全量写入」的间隙里短暂丢失。
func mergeIntoCurrentBlock(add map[string]string) (map[string]string, error) {
	cur, err := executor.ReadHostsBlock()
	if err != nil {
		return nil, err
	}
	merged := make(map[string]string, len(cur)+len(add))
	for d, ip := range cur {
		merged[d] = ip
	}
	for d, ip := range add {
		merged[d] = ip
	}
	return merged, nil
}

// ApplyOnce 是 RunApply 的便捷封装：自带 10 秒硬超时上下文。
func ApplyOnce(cfg *config.Config, r Reporter) (map[string]string, []string, bool, error) {
	return ApplyOnceOpts(cfg, r, Options{})
}

// ApplyOnceOpts 是 RunApplyOpts 的便捷封装：自带 10 秒硬超时上下文。
func ApplyOnceOpts(cfg *config.Config, r Reporter, opts Options) (map[string]string, []string, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), applyTimeout)
	defer cancel()
	return RunApplyOpts(ctx, cfg, r, opts)
}
