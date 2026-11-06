// App 是 Wails GUI 的后端绑定层：把 internal/engine 的能力暴露给前端，
// 并通过 Wails Events 把探测过程实时推送给界面渲染。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/energye/systray"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	syswin "golang.org/x/sys/windows"

	"ghsmart/internal/autostart"
	"ghsmart/internal/cache"
	"ghsmart/internal/config"
	"ghsmart/internal/doh"
	"ghsmart/internal/engine"
	"ghsmart/internal/executor"
	"ghsmart/internal/jobobj"
	"ghsmart/internal/license"
	"ghsmart/internal/probe"
	"ghsmart/internal/proxyguard"
	"ghsmart/internal/sysproxy"
	"ghsmart/internal/updater"
	"ghsmart/internal/webproxy"
)

// App 持有 Wails 上下文与运行状态。
type App struct {
	ctx      context.Context
	busy     atomic.Bool
	quitting atomic.Bool
	pro      atomic.Bool // Pro 已解锁
	// 自愈循环：healOn 是唯一对外状态源，healCancel 用于停止循环。
	// 用互斥锁保护 cancel 的读写，杜绝「关闭后状态仍显示开启」的竞态。
	healMu     sync.Mutex
	healCancel context.CancelFunc
	healOn     atomic.Bool
	// 深度网页加速（本地 TLS 分片代理 + 系统代理接管）。
	// deepOn 是唯一对外状态源；proxy/deepAddr/deepMode/deepCompat 由 deepMu 保护。
	deepMu       sync.Mutex
	proxy        *webproxy.Server
	deepAddr     string
	deepMode     string
	deepCompat   bool // 保留字段：老配置兼容用，新流程不再有兼容模式
	deepDegraded bool // 代理层已静默降级为纯隧道（状态栏显示「智能降级」）
	deepOn       atomic.Bool
	// deepGen 是「接管代际」：每次成功开启 +1。关闭时后台还原系统代理前先比对
	// 它——期间用户若又点开了（代际变了），这次旧还原必须放弃，否则会把刚接管好
	// 的系统代理又写回直连，用户看到的就是「开了跟没开一样」。
	deepGen atomic.Int64
	// restoreMu 把「写系统代理」这一小段临界区串行化（接管 vs 还原）。
	// 只锁注册表读写，绝不覆盖启动/停止代理、也不覆盖 UI 返回路径——
	// 所以关闭时用户感觉不到它，开启时最多等一下正在跑的还原。
	restoreMu sync.Mutex
	// bypassRemoved 记录本次接管从系统「代理例外列表」里剔除了哪些 GitHub 条目，
	// 供前端回显（用户可据此去 Windows 代理设置里核对）。
	bypassRemoved []string

	// 优选 IP 解析缓存（host -> IP，10 分钟过期），避免每个 CONNECT 都解析
	ipMu    sync.Mutex
	ipCache map[string]ipEntry

	// 作业对象 + 守卫进程：保证「主进程被强杀」时系统代理也会被还原。
	// job 由 main 创建并注入；guard 在第一次开启深度加速时懒派生（免费用户不占进程）。
	job       *jobobj.Job
	guardOnce sync.Once
	guard     *proxyguard.Guard

	// 诊断日志（GUI 无控制台，写 ~/.ghsmart/ghsmart.log）
	logMu   sync.Mutex
	logFile *os.File

	// silent 表示本次是「开机自启」带起来的（--silent）：
	// 窗口隐藏到托盘，其余状态恢复逻辑与手动打开完全一致。
	silent bool

	// 开机自启状态缓存：查询要 fork schtasks（几十毫秒），
	// 不能每次 emitState 都查；只在启动与切换后刷新。
	autoMu sync.Mutex
	autoSt autostart.Status

	// 检查更新：updateInfo 缓存最近一次结果（界面多次 emitState 不必重复请求），
	// updateBusy 防并发重复检查。失败时不写缓存，下次启动自然重试。
	updateMu   sync.Mutex
	updateInfo *updater.Info
	updateBusy atomic.Bool

	// hostsRepOnce 保证「压制了其他加速工具记录」在一次加速里只提示一遍：
	// 主域名提前写入与收尾全量写入都会回报，不去重会连弹两次。
	hostsRepOnce atomic.Bool
}

// appVersion 是程序版本号，用于检查更新与界面显示。
//
// 发版时必须与外面前端 index.html 的两处显示、wails.json 的 productVersion、
// README 一并同步——漏一处就会出现「检测到新版本 1.0.9，但界面写着 1.0.8」。
const appVersion = "1.0.11"

// NewApp 创建应用实例。
func NewApp() *App {
	return &App{}
}

// startup 由 Wails 在窗口创建后回调，保存运行时上下文。
// 已持久化的 Pro 授权在此做离线复验（到期/机器码变更会拒绝），通过则恢复解锁；
// 自动自愈开关处于开启状态时顺带拉起后台循环。
//
// silent=true 表示这次是「开机自启」带起来的（--silent）：窗口隐藏到托盘，
// 但状态恢复逻辑与手动打开完全一致——用户下次看主界面时，开关已经是打开的样子。
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	cfg := a.loadCfg()
	st := a.loadLicenseState()

	// v1.0.8 迁移：旧版**无条件**写过 git@github.com: 与 ssh:// 的改写。
	// 光改代码不改存量等于没修——老用户升级后，那三条 insteadOf 还留在
	// 他的全局配置里，SSH 推送照样是坏的。所以升级后第一次启动强制对齐一次。
	st = a.migrateGit108(st)

	// 第一件事：如果上次是异常退出（进程被强杀）导致系统代理还指着本机，
	// 立刻按「精准核对」还原——只有确实指向我们时才动，第三方代理绝不覆盖。
	if restored, err := sysproxy.Recover(cfg.WebProxy.Listen); err != nil {
		a.emitStatus("系统代理兜底还原失败: "+err.Error(), "warn")
	} else if restored {
		a.emitStatus("已自动还原上次遗留的系统代理", "ok")
	}
	// 第二道闸：僵尸代理清理。备份可能在强杀时根本没写成/被删，
	// 只要「系统代理指向我们的端口但端口无人监听」就强制关闭——
	// 绝不让用户一开机就全网断连（公司域名全打不开的那种）。
	a.cleanZombieProxy(cfg.WebProxy.Listen)
	if st.Key != "" {
		if ok, err := license.VerifyOffline(st.Key); err == nil && ok {
			a.pro.Store(true)
			if st.AutoHeal {
				a.startHeal(cfg)
			}
			if st.DeepAccel {
				// 重启后恢复上次状态：不再问模式、不问兼容，
				// 一律按「智能模式」启动（分片→失败自动降级）
				if err := a.startDeep(cfg); err != nil {
					a.emitStatus("深度加速恢复失败: "+err.Error(), "warn")
				}
			}
		}
	}
	// ★ 缓存秒应用：上次探测成功的最优 IP 直接恢复加速（免费版无条件），
	// 打开软件即用，无需再点按钮；随后后台静默校验更优 IP。
	a.applyCacheOnStartup(cfg)
	// 查一次自启状态（要 fork schtasks，只查这一次，之后走缓存）。
	a.refreshAutoStatus()
	a.emitState()
	// 检查更新：异步、失败静默、绝不阻塞启动。
	//
	// 所有用户都检查（含未授权）：ghsmart 是「同一份程序 + 授权解锁」，
	// 免费用户同样需要拿到 bug 修复——比如 v1.0.8 修的 SSH 改写，
	// 老版本一旦被点过「一键加速」就会把 SSH 推送弄坏，不给免费用户升级通道
	// 等于把最普遍的伤害留在最多的人身上。
	go a.checkUpdateAsync()
	if a.silent {
		a.logf("静默自启：已按上次状态恢复（深度加速=%v，自愈=%v，窗口隐藏到托盘）",
			a.deepOn.Load(), a.healOn.Load())
	}
}

func (a *App) deepListenAddr() string {
	a.deepMu.Lock()
	defer a.deepMu.Unlock()
	if a.proxy == nil {
		return ""
	}
	return a.proxy.Addr()
}

// ---------- 僵尸代理清理（启动自检） ----------

// cleanZombieProxy 是启动自检的核心修复（防强杀残留的「僵尸代理」）：
// 系统代理指向我们的监听地址，但本程序此刻并没有在监听该端口——
// 正常只有开深度加速才会写代理，所以这一定是上次强杀/崩溃残留的死代理。
// 直接强制关闭系统代理（ProxyEnable=0），绝不让用户一开机就全网断连。
//
// 与 Recover（按备份精准还原）互补：备份丢了/没写成时，这道闸保证兜底。
//
// 注入点：单测替换这两个变量即可，绝不碰真实注册表。
var (
	zombieIsOn    = sysproxy.IsOn
	zombieDisable = sysproxy.DisableIfOwned
)

func (a *App) cleanZombieProxy(listen string) {
	target := listen
	if target == "" {
		target = sysproxy.DefaultTarget
	}
	if !zombieIsOn(target) {
		return // 系统代理没指向我们，无事可做（第三方代理绝不误杀）
	}
	if a.deepListenAddr() != "" {
		return // 我们自己确实在监听（理论上启动早期不会发生），不误杀
	}
	ok, err := zombieDisable(target)
	if err != nil {
		a.emitStatus("僵尸代理清理失败: "+err.Error(), "err")
		return
	}
	if ok {
		a.logf("启动自检：检测到强杀残留的僵尸代理（%s 无人监听），已强制关闭系统代理", target)
		a.emitStatus("检测到上次异常退出残留的失效代理，已自动关闭（网络已恢复直连）", "warn")
	}
}

// loadCfg 加载配置：优先 exe 同目录 configs/default.yaml，读不到用内置默认。
// GHSMART_LISTEN 环境变量可覆盖监听地址（单测注入随机端口用，生产不设置）。
func (a *App) loadCfg() *config.Config {
	var cfg *config.Config
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "configs", "default.yaml")
		if c, err := config.Load(p); err == nil {
			cfg = c
		}
	}
	if cfg == nil {
		cfg, _ = config.Load("") // 文件缺失时 config.Load 自动回退默认值
	}
	if lp := os.Getenv("GHSMART_LISTEN"); lp != "" {
		cfg.WebProxy.Listen = lp
	}
	engine.Configure(cfg)
	return cfg
}

// guiReporter 实现 engine.Reporter：把事件实时推送到前端。
type guiReporter struct {
	a *App
}

func (g guiReporter) DomainStart(domain string) {
	runtime.EventsEmit(g.a.ctx, "engine:domain", map[string]any{
		"phase":  "start",
		"domain": domain,
	})
}

func (g guiReporter) DomainProbed(domain string, results []probe.ProbeResult, bestIP string) {
	rows := make([]map[string]any, 0, len(results))
	for _, r := range results {
		rows = append(rows, map[string]any{
			"ip":     r.IP,
			"tcp":    r.TCPMs,
			"tls":    r.TLSMs,
			"http":   r.HTTPMs,
			"score":  r.Score,
			"ok":     r.OK,
			"chosen": r.IP == bestIP,
		})
	}
	runtime.EventsEmit(g.a.ctx, "engine:domain", map[string]any{
		"phase":  "result",
		"domain": domain,
		"rows":   rows,
		"best":   bestIP,
	})
}

func (g guiReporter) DomainSkipped(domain string) {
	runtime.EventsEmit(g.a.ctx, "engine:domain", map[string]any{
		"phase":  "skipped",
		"domain": domain,
	})
}

func (g guiReporter) Warn(msg string) {
	runtime.EventsEmit(g.a.ctx, "engine:warn", msg)
}

// StartApply 一键智能加速：缓存秒应用 -> 后台全新探测校验。
// 缓存秒应用对免费版无条件开放（产品基础体验，绝不与 Pro 绑定）。
// 过程通过 engine:cache / engine:primary / engine:domain / engine:applied 事件推送前端。
func (a *App) StartApply() error {
	// 清空上一轮探测报告：深度加速预检已改为实时微测，旧报告只会误导人；
	// 本轮探测结束后引擎会写入新的报告（覆盖式）。放在最前面，
	// 保证用户一点击就作废旧结论（哪怕后面因为忙/未就绪提前返回）。
	if err := cache.ClearProbeReport(); err != nil {
		a.logf("清理历史探测报告失败（不影响加速）: %v", err)
	}
	if a.ctx == nil {
		return errors.New("应用尚未就绪")
	}
	if !a.busy.CompareAndSwap(false, true) {
		return errors.New("正在执行中，请稍候")
	}
	cfg := a.loadCfg()
	// 新一轮加速：允许再报一次 hosts 冲突（上一轮的提示已经翻篇了）
	a.hostsRepOnce.Store(false)
	// 起始日志：出问题时「这一轮到底有没有真的跑起来」必须一眼能从日志查到
	// （v1.0.9 事故排查就是靠日志里的「缓存秒应用」反推出点击确实生效了）。
	a.logf("一键加速: 开始（域名 %d 个）", len(cfg.Domains))

	// ★ 缓存秒应用（核心提速）：有新鲜缓存时 0.1 秒内写 Hosts + 刷 DNS，
	// 用户立刻可用；随后在后台静默发起一轮全新探测，发现更优 IP 再悄悄替换并提示。
	cached := a.loadFreshCache(cfg)
	if len(cached) > 0 {
		if rep, err := executor.ApplyHostsReport(cached); err == nil {
			a.invalidateAllHostIP()
			a.reportHostsConflict(rep)
			a.logf("缓存秒应用: 已写入 %d 条缓存记录，后台即将重新校验", len(cached))
			runtime.EventsEmit(a.ctx, "engine:cache", map[string]any{
				"ok": true, "written": len(cached),
			})
			a.emitStatus("加速已生效（缓存秒应用，后台校验更优 IP 中...）", "ok")
		} else {
			a.logf("缓存秒应用失败（将走完整探测流程）: %v", err)
			cached = nil
		}
	} else {
		a.emitStatus("正在探测，请稍候...", "busy")
	}
	go func() {
		started := time.Now()
		writtenCount := 0
		// settled 保证「本轮只发一次结束信号」：前端把按钮解锁的唯一依据就是它。
		// 任何一条返回路径（成功/失败/受限/证据不足/panic）都必须走到这里，
		// 否则按钮会永远停在「正在探测，请稍候...」上——用户只能重启软件。
		settled := false
		emitApplied := func(p map[string]any) {
			if settled {
				return
			}
			settled = true
			runtime.EventsEmit(a.ctx, "engine:applied", p)
		}
		defer func() {
			if r := recover(); r != nil {
				a.logf("一键加速协程异常: %v", r)
				emitApplied(map[string]any{
					"ok": false, "written": 0,
					"error": "本轮探测异常结束（已自动恢复），请重试",
				})
				a.emitStatus("本轮探测异常结束（已自动恢复），请重试", "err")
			}
			// 兜底：既没成功也没失败就结束了（例如引擎返回了未预期状态），
			// 也必须给前端一个结束信号，绝不能让它无限等待。
			emitApplied(map[string]any{
				"ok": false, "written": 0,
				"error": "本轮探测未产生结果，请重试",
			})
			a.busy.Store(false)
			a.logf("一键加速: 结束，写入 %d 条，耗时 %s", writtenCount, time.Since(started).Round(time.Millisecond))
		}()

		written, lines, restricted, err := engine.ApplyOnceOpts(cfg, guiReporter{a}, engine.Options{
			// 档位由用户的「Git 加速（HTTPS 模式）」开关决定：
			// 默认档只处理已停用的 git://，绝不改用户 SSH 推送路径。
			GitLevel: a.gitLevel(),
			// 主域名（github.com）一探测成功就立刻写入并通知 UI，
			// 其余域名继续在后台探测（由引擎在收尾统一全量写入）。
			OnPrimary: func(entries map[string]string) {
				a.invalidateAllHostIP()
				a.emitStatus("加速已生效（主域名已生效，其余域名后台优化中...）", "ok")
				runtime.EventsEmit(a.ctx, "engine:primary", map[string]any{
					"ok": true, "written": len(entries),
				})
			},
			// 压住了别的加速工具的记录就必须说出来（引擎在主域名提前写入与
			// 收尾写入两处都会回报，reportHostsConflict 内部去重）
			OnHostsConflict: func(rep executor.HostsReport) { a.reportHostsConflict(rep) },
		})
		writtenCount = len(written)
		// hosts 区块可能刚刚被改写：代理手里的 IP 缓存必须作废，
		// 否则「刚优选出的新 IP」要等 10 分钟才生效（这是双加速叠加的必要配合）。
		a.invalidateAllHostIP()

		// ★ 证据不足（探测通过但业务校验没跑完）：**什么都不改**。
		// 这是 v1.0.10 实机事故的正面修正——之前的逻辑会在这里把 Hosts 区块
		// 写成空块、顺手清掉缓存，等于用一个「不知道」抹掉上次确定可用的加速。
		if errors.Is(err, engine.ErrInconclusive) {
			a.logf("本轮证据不足（业务校验未完成），已保留现有 Hosts 与缓存；明细: %s",
				strings.Join(lines, " | "))
			emitApplied(map[string]any{
				"ok": false, "written": 0, "inconclusive": true,
				"error": "网络较慢，本轮未完成真实验证（已保留上次的加速记录）",
			})
			a.emitStatus("网络较慢，本轮未完成验证（已保留上次的加速记录），可稍后重试", "warn")
			return
		}
		// ★ 受限网络（所有 IP 都没通过真实业务校验，典型：公司 VPN 全量 RST）：
		// 清理无效 Hosts 记录（引擎已把区块清空）+ 清缓存 + 弹红色警告
		if restricted {
			_ = cache.Clear() // 绝不让死 IP 留到下次秒应用
			a.logf("受限网络判定成立：所有候选 IP 均未通过真实业务校验，已清理 Hosts 区块与缓存")
			a.emitStatus("当前网络环境受限（如公司 VPN），无法通过修改 Hosts 加速。", "err")
			runtime.EventsEmit(a.ctx, "engine:netrestricted", map[string]any{
				"ok": true, "written": 0,
			})
			return
		}
		if err != nil {
			// ★ 绝不能静默失败：这一条是 v1.0.11 现场复盘补上的。
			// 上一版这里只往界面发事件、不写日志，结果「日志显示写入 4 条、hosts 里却只有 1 行」
			// 这种最要命的现场在日志里查不到任何原因（实际是收尾那次写盘被安全软件占了句柄）。
			a.logf("一键加速失败：探测到 %d 个域名可用 IP，但落盘未成功：%v", len(written), err)
			emitApplied(map[string]any{
				"ok": false, "lines": lines, "written": 0, "error": err.Error(),
			})
			a.emitStatus("加速失败: "+err.Error(), "err")
			return
		}
		// 探测成功：刷新本地缓存（免费版同样保存，秒应用是基础体验）
		if len(written) > 0 {
			if serr := cache.Save(written); serr != nil {
				a.logf("保存优选缓存失败: %v", serr)
			}
		} else {
			_ = cache.Clear() // 全部域名不可用 → 缓存一并清掉，绝不让死 IP 留到下次秒应用
		}
		// 写入结果以引擎统计的 written 为准；读回的 entries 仅作展示参考
		entries, rerr := executor.ReadHostsBlock()
		if len(written) > 0 {
			a.logf("Hosts 已写入 %d 条优选记录，IP 缓存已作废（代理下次连接会用新 IP）", len(written))
		}
		payload := map[string]any{
			"ok": true, "lines": lines, "written": len(written),
		}
		if rerr == nil {
			payload["entries"] = entries
		}
		// 缓存秒应用过 → 对比本轮结果，发现更优 IP 才提示（悄悄替换已完成）
		if len(cached) > 0 {
			if updated := diffUpdated(written, cached, cfg.Domains); len(updated) > 0 {
				payload["updated"] = updated
			}
		}
		emitApplied(payload)
		if len(written) > 0 {
			a.emitStatus("加速已生效", "ok")
		} else {
			a.emitStatus("本轮未写入任何加速记录（全部域名不可用）", "warn")
		}
	}()
	return nil
}

// loadFreshCache 读取仍在有效期内、且只含本配置管辖域名的缓存优选记录。
// 没有可用的缓存时返回 nil。
func (a *App) loadFreshCache(cfg *config.Config) map[string]string {
	return cache.FreshFor(cfg.Domains)
}

// diffUpdated 对比本轮探测结果与缓存基线，找出被替换成更优 IP 的域名
// （顺序按 cfg.Domains，保证前端展示稳定）。
func diffUpdated(written, baseline map[string]string, domains []string) []map[string]string {
	var updated []map[string]string
	for _, d := range domains {
		ip, ok := written[d]
		if !ok {
			continue
		}
		if old, had := baseline[d]; had && old != ip {
			updated = append(updated, map[string]string{"domain": d, "from": old, "to": ip})
		}
	}
	return updated
}

// silentReporter 丢弃所有探测事件：启动时的后台静默校验不打扰界面。
type silentReporter struct{}

func (silentReporter) DomainStart(string)                               {}
func (silentReporter) DomainProbed(string, []probe.ProbeResult, string) {}
func (silentReporter) DomainSkipped(string)                             {}
func (silentReporter) Warn(string)                                      {}

// revalidateSilently 后台静默重探测：不推探测明细（界面保持安静），
// 发现更优 IP 时悄悄替换（引擎收尾已全量写入）并提示一次；
// 结果与基线一致则只记日志，绝不刷屏。
func (a *App) revalidateSilently(cfg *config.Config, baseline map[string]string) {
	written, _, restricted, err := engine.ApplyOnceOpts(cfg, silentReporter{}, engine.Options{
		GitLevel: a.gitLevel(),
	})
	a.invalidateAllHostIP()
	// 后台校验发现受限网络：清缓存 + 通知前端弹红色警告（秒应用写入的死 IP 已被引擎清出 Hosts）
	if restricted {
		_ = cache.Clear()
		a.logf("后台校验判定受限网络：所有候选 IP 均未通过真实业务校验，已清理缓存")
		a.emitStatus("当前网络环境受限（如公司 VPN），无法通过修改 Hosts 加速。", "err")
		runtime.EventsEmit(a.ctx, "engine:netrestricted", map[string]any{"ok": true, "written": 0})
		return
	}
	if err != nil {
		a.logf("后台缓存校验失败（缓存记录保持不变）: %v", err)
		return
	}
	if len(written) > 0 {
		if serr := cache.Save(written); serr != nil {
			a.logf("保存优选缓存失败: %v", serr)
		}
	} else {
		_ = cache.Clear()
	}
	updated := diffUpdated(written, baseline, cfg.Domains)
	if len(updated) > 0 {
		a.emitStatus("已为您更新更优 IP", "ok")
		runtime.EventsEmit(a.ctx, "engine:cacheupdated", map[string]any{"updated": updated})
		a.logf("后台校验发现更优 IP，已悄悄替换 %d 条", len(updated))
	} else {
		a.logf("后台缓存校验完成，缓存 IP 已是最优（%d 条）", len(written))
	}
}

// applyCacheOnStartup 打开软件时的缓存秒应用：上次探测成功的最优 IP
// 直接写入 Hosts（免费版无条件开放），用户无需点按钮即恢复加速；
// 随后后台静默发起一轮全新探测校验更优 IP。
func (a *App) applyCacheOnStartup(cfg *config.Config) {
	cached := a.loadFreshCache(cfg)
	if len(cached) == 0 {
		return
	}
	// 区块已与缓存一致时不必重写（避免无谓地动 Hosts 文件）
	if cur, err := executor.ReadHostsBlock(); err == nil && hostsEntriesEqual(cur, cached) {
		a.logf("启动检查: Hosts 区块与缓存一致（%d 条），跳过重写", len(cached))
	} else if rep, err := executor.ApplyHostsReport(cached); err != nil {
		a.logf("启动缓存秒应用失败: %v", err)
		return
	} else {
		// 启动时也可能压住别人的记录（用户在这一版之前装过别的加速器）：
		// 一样要说，不能因为「是自动做的」就悄悄处理
		a.reportHostsConflict(rep)
	}
	a.invalidateAllHostIP()
	a.emitStatus("已用缓存恢复加速（"+fmt.Sprint(len(cached))+" 条），后台校验更优 IP 中...", "ok")
	a.logf("启动缓存秒应用: 已写入 %d 条缓存记录", len(cached))
	// 后台静默校验更优 IP；busy 闸被占（自愈正在跑等）就跳过本轮
	if a.busy.CompareAndSwap(false, true) {
		go func() {
			defer a.busy.Store(false)
			a.revalidateSilently(cfg, cached)
		}()
	}
}

// hostsEntriesEqual 判断两个 域名->IP 映射是否完全一致。
func hostsEntriesEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for d, ip := range a {
		if v, ok := b[d]; !ok || v != ip {
			return false
		}
	}
	return true
}

// RemoveHosts 即「🧹 一键还原网络」：按需、精准地清理所有 ghsmart 留下的痕迹。
// 顺序很重要——先摘代理再删 Hosts，中间任何一步失败都不会让用户「网断在半路」。
// 权限：**全用户开放**（Free 用户也必须有急救能力，否则被死代理锁死）。
func (a *App) RemoveHosts() error {
	if a.ctx == nil {
		return errors.New("应用尚未就绪")
	}
	// 1) 关闭深度加速：精准还原系统代理（只在我们接管时还原；Clash 等第三方代理不动）
	// 用户点的是「一键还原网络」，语义就是「现在就干净」，所以这里等它做完。
	a.stopDeepWait(5 * time.Second)
	// 2) 停掉自愈，否则刚还原完又被后台巡检写回去
	a.stopHeal()
	if st := a.loadLicenseState(); st.AutoHeal || st.DeepAccel {
		st.AutoHeal = false
		st.DeepAccel = false
		_ = a.saveLicenseState(st)
	}
	// 3) 清 Hosts 区块 + 还原被注释的冲突行 + 清理 git insteadOf
	if err := engine.RestoreHosts(guiReporter{a}); err != nil {
		a.emitState()
		return fmt.Errorf("Hosts 还原失败: %w", err)
	}
	// 4) 缓存一并清空：用户明确选择还原网络后，
	//    绝不能在下次打开软件时又把缓存 IP 自动写回 Hosts
	if err := cache.Clear(); err != nil {
		a.logf("清理优选缓存失败: %v", err)
	}
	// 5) Hosts 已清空 → 作废代理的 IP 缓存，避免它继续用旧优选 IP
	a.invalidateAllHostIP()
	a.emitStatus("已安全还原", "ok")
	runtime.EventsEmit(a.ctx, "engine:removed", true)
	a.emitState()
	return nil
}

// GetAppliedEntries 返回当前 Hosts 中 ghsmart 区块生效的 域名->IP。
func (a *App) GetAppliedEntries() (map[string]string, error) {
	return executor.ReadHostsBlock()
}

// IsElevated 返回当前进程是否以管理员权限运行（UAC 静默提权时界面可据此确认）。
func (a *App) IsElevated() bool {
	return syswin.GetCurrentProcessToken().IsElevated()
}

// allowCloseOnX 回答「现在点窗口 ✕ 该不该真的关闭」。
//
// 平时返回 false：✕ 只是隐藏到托盘（托盘工具的正常行为）。
// 一旦退出流程启动（托盘点了「退出」），必须返回 true——否则 runtime.Quit
// 会卡在 OnBeforeClose 这一关，窗口永远关不掉，用户只能杀进程。
func (a *App) allowCloseOnX() bool {
	return a.quitting.Load()
}

// quitWatchdogDelay 是「请求退出」到「强制结束进程」的等待时间。
// 正常退出远快于此；留够时间让 Wails 先走完 OnBeforeClose / OnShutdown，
// 也给「退出清场超时放弃等待」留出后台 goroutine 收尾的余量。
// 声明成变量是为了测试能缩短它（测试进程不能被 os.Exit 打死）。
var quitWatchdogDelay = 3 * time.Second

// exitCleanupTimeout 是退出清场（还原代理/停循环）的等待上限。
// 清场若卡住（休眠唤醒后代理句柄异常等）超过它，直接放弃等待优先退出，
// 防止 UI 卡死；后台 goroutine 会继续跑完还原，watchdog 强退前还会再兜底一次。
// 声明成变量同样是为了测试可缩短。
var exitCleanupTimeout = 2 * time.Second

// forceQuit 是退出兜底的执行体：先撤托盘（避免幽灵图标），再强制结束进程。
// 声明成变量同样是为了测试可替换。
var forceQuit = func() {
	systray.Quit()
	time.Sleep(200 * time.Millisecond)
	os.Exit(0)
}

// QuitApp 是唯一的「退出程序」入口（托盘菜单、界面关闭都走这里）。
//
// 顺序很关键（血泪）：必须先把 quitting 置位、还原系统代理，**最后**才撤托盘图标。
// 旧实现先 systray.Quit() 再 runtime.Quit()，一旦 Wails 没能立刻结束进程，
// 就进入「托盘消息循环已停、图标点不动、进程还活着」的死局——用户只能去
// 任务管理器杀进程。
//
// 另外加一道 watchdog 兜底：托盘程序必须保证「点了退出就一定退」，
// 正常退出时进程会先结束、watchdog 自然消失；只有 runtime.Quit 失效时它才生效。
func (a *App) QuitApp() {
	if !a.quitting.CompareAndSwap(false, true) {
		return // 已经在退出流程中，重复点击直接忽略
	}
	a.logf("用户请求退出：还原系统代理并关闭进程")
	// 清场带超时保护：正常毫秒级完成；一旦卡住（休眠唤醒后句柄异常等）
	// 最多等 exitCleanupTimeout 就放弃等待优先退出，绝不把 UI 卡死。
	// 清场 goroutine 自身会继续跑完（还原代理最要紧），watchdog 也会兜底。
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.Shutdown() // 幂等：还原代理、停自愈、停看门狗、关日志
	}()
	select {
	case <-done:
	case <-time.After(exitCleanupTimeout):
		a.logf("退出清场超过 %v 未完成，放弃等待优先退出", exitCleanupTimeout)
	}

	if a.ctx != nil {
		runtime.Quit(a.ctx)
	}

	go func() {
		// 正常情况进程会在数百毫秒内结束，走不到这里。
		// 走到这里说明 Wails 没能关掉窗口（隐藏态 / 消息循环卡住），
		// 必须强退：否则托盘已撤、进程常驻，用户再也关不掉了。
		time.Sleep(quitWatchdogDelay)
		// 强退前再精准还原一次系统代理（毫秒级、幂等）：万一同步清场被
		// 卡住没跑完，进程一走代理还指着死端口就等于让用户断网。
		if _, err := sysproxy.Restore(a.targetAddr()); err != nil {
			a.logf("退出兜底：还原系统代理失败: %v", err)
		}
		forceQuit()
	}()
}

// Shutdown 退出前的清场：还原系统代理（最关键，否则用户会断网）并停掉自愈循环。
// 由 Wails 的 OnShutdown 与托盘退出共同调用，可重复执行（幂等）。
func (a *App) Shutdown() {
	// 退出场景不能用纯异步：进程一走，未完成的还原就没了（只剩守卫进程兜底）。
	// 这里最多等 exitCleanupTimeout，超时也不阻塞退出。
	a.stopDeepWait(exitCleanupTimeout)
	a.stopHeal()
	a.closeLog()
}

// closeLog 关闭诊断日志句柄（退出前调用，避免 Windows 上文件被占用）。
func (a *App) closeLog() {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	if a.logFile != nil {
		_ = a.logFile.Close()
		a.logFile = nil
	}
}

// licenseState 是 ~/.ghsmart/license.json 的持久化结构。
type licenseState struct {
	Key         string `json:"key"`          // 已通过校验的授权码
	ValidatedAt string `json:"validated_at"` // 最近一次成功校验时间
	AutoHeal    bool   `json:"auto_heal"`    // 自愈开关状态
	DeepAccel   bool   `json:"deep_accel"`   // 深度网页加速开关状态
	DeepMode    string `json:"deep_mode"`    // 深度加速模式：auto / manual
	DeepCompat  bool   `json:"deep_compat"`  // 深度加速兼容模式（公司 VPN 场景，不做 TLS 分片）

	// v1.0.8 新增：三个「无感」相关开关的记忆，重启后按上次状态恢复。
	GitHTTPS    bool `json:"git_https"`     // Git 加速（HTTPS 模式）：是否改写 SSH 到 HTTPS
	CLIProxyEnv bool `json:"cli_proxy_env"` // 命令行加速：是否同时写用户级环境变量（gh/curl）
	AutoStart   bool `json:"auto_start"`    // 开机自启并最小化到托盘

	// Migrated108 标记「v1.0.8 的 git 改写迁移」已执行过。
	// 旧版无条件把 SSH 改写成 HTTPS，升级后必须主动清一次存量，
	// 否则改代码等于没改（用户的 git push 还是坏的）。只做一次，不反复 fork git。
	Migrated108 bool `json:"migrated_108"`

	// SkippedVersion 记录用户明确「先不升级」的版本号。
	// 有了它，跳过就是真的跳过——同一个版本不会每次开机都来烦一次。
	SkippedVersion string `json:"skipped_version"`
}

// licensePath 返回授权状态文件路径（默认 ~/.ghsmart/license.json）。
// 环境变量 GHSMART_LICENSE_FILE 可覆盖（单测隔离用，避免碰真实授权文件）。
func licensePath() (string, error) {
	if p := os.Getenv("GHSMART_LICENSE_FILE"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ghsmart", "license.json"), nil
}

// loadLicenseState 读取本地授权状态；文件缺失返回零值。
func (a *App) loadLicenseState() licenseState {
	st := licenseState{}
	p, err := licensePath()
	if err != nil {
		return st
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return st
	}
	_ = json.Unmarshal(data, &st)
	return st
}

// saveLicenseState 持久化授权状态。
func (a *App) saveLicenseState(st licenseState) error {
	p, err := licensePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o600)
}

// polar 相关实现已移除：授权完全离线（ECDSA P-256 验签，见 internal/license/ecdsa.go）。

// ActivatePro 离线校验激活码（签名 + 机器码 + 有效期）并解锁 Pro。
// 校验通过后持久化到 license.json，下次启动自动复验恢复。
func (a *App) ActivatePro(key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("请输入激活码")
	}
	ok, err := license.VerifyOffline(key)
	if err != nil {
		return err // 验签失败的具体原因（格式/机器码/过期/伪造）直接展示给用户
	}
	if !ok {
		return errors.New("激活码无效")
	}
	st := a.loadLicenseState()
	st.Key = key
	st.ValidatedAt = time.Now().Format("2006-01-02 15:04:05")
	if err := a.saveLicenseState(st); err != nil {
		return fmt.Errorf("保存授权状态失败: %w", err)
	}
	a.pro.Store(true)
	a.emitState()
	return nil
}

// GetMachineCode 返回本机机器码（16 位 hex），供用户复制后发给发码方。
func (a *App) GetMachineCode() (string, error) {
	return license.MachineCodeHex()
}

// ClearLicense 清除本地授权：还原系统代理、关闭自愈循环、删除 license.json、回到 Free。
// 前端状态由 emitState 统一刷新。
func (a *App) ClearLicense() error {
	a.stopDeepWait(exitCleanupTimeout) // 先退 Pro 功能，尤其是别把系统代理留在本机
	a.stopHeal()
	a.pro.Store(false)
	p, err := licensePath()
	if err == nil {
		if rerr := os.Remove(p); rerr != nil && !os.IsNotExist(rerr) {
			return fmt.Errorf("删除授权文件失败: %w", rerr)
		}
	}
	a.emitState()
	return nil
}

// GetProState 返回 Pro 解锁与自愈开关状态。
func (a *App) GetProState() map[string]any {
	return a.proState()
}

// proState 组装当前授权状态（唯一事实来源），供各绑定方法回传给前端。
func (a *App) proState() map[string]any {
	st := a.loadLicenseState()
	m := map[string]any{
		"pro":        a.pro.Load(),
		"autoHeal":   a.healOn.Load(),
		"deepAccel":  a.deepOn.Load(),
		"deepListen": "",
		"deepMode":   "",
		// v1.0.8：三个「无感/安全」开关的真实状态
		"gitHTTPS":    st.GitHTTPS,
		"cliProxyEnv": st.CLIProxyEnv,
		"silent":      a.silent,
	}
	// 自启状态走内存缓存：查询要 fork schtasks，不能每次 emitState 都做。
	auto := a.autoStatus()
	m["autoStart"] = auto.Enabled
	m["autoStartMode"] = string(auto.Mode)
	m["autoStartNeedsUAC"] = auto.NeedsUAC
	m["autoStartDetail"] = auto.Detail
	// 版本与更新状态：前端标题栏和「检查更新」按钮都靠它，不在前端写死版本号
	for k, v := range a.updatePayload() {
		m[k] = v
	}
	a.deepMu.Lock()
	if a.deepMode != "" {
		m["deepMode"] = a.deepMode
	}
	// deepDegraded 是「已开启 · 智能降级」的唯一依据：分片被拦后代理自己切了隧道。
	m["deepDegraded"] = a.deepDegraded
	if a.proxy != nil {
		m["deepListen"] = a.proxy.Addr()
		m["deepStats"] = a.proxy.Stats()
	}
	m["bypassRemoved"] = append([]string(nil), a.bypassRemoved...)
	a.deepMu.Unlock()
	return m
}

// migrateGit108 处理「从旧版升级上来」的 git 配置存量。
//
// 背景：v1.0.7 及更早**无条件**把 git@github.com: / ssh:// 改写成 HTTPS，
// 这会打断用 SSH key 推送的用户。v1.0.8 改成默认档不碰 SSH，但存量不会自己消失——
// 老用户升级后必须主动清一次，否则「修了 bug 但用户的 git push 还是坏的」。
//
// 只做一次（Migrated108 标记），之后每次启动只按用户选择恢复 HTTPS 模式，
// 绝不反复 fork git 子进程去写配置。
func (a *App) migrateGit108(st licenseState) licenseState {
	level := executor.GitRewriteGitOnly
	if st.GitHTTPS {
		level = executor.GitRewriteSSH
	}

	if st.Migrated108 {
		// 已迁移过：只在用户主动开着 HTTPS 模式时恢复，其余什么都不做
		if st.GitHTTPS {
			if err := executor.ApplyGit(level); err != nil {
				a.logf("恢复 Git HTTPS 模式失败（不影响主流程）: %v", err)
			}
		}
		return st
	}

	if err := executor.ApplyGit(level); err != nil {
		// 未装 git 等情况：不写标记，下次启动再试（不影响主流程）
		a.logf("v1.0.8 迁移：git 改写对齐失败（下次启动重试）: %v", err)
		return st
	}
	st.Migrated108 = true
	if serr := a.saveLicenseState(st); serr != nil {
		a.logf("记录 v1.0.8 迁移标记失败: %v", serr)
	}
	a.logf("v1.0.8 迁移：git 改写已对齐到 %s 档（旧版遗留的 SSH 改写已按需清除）", level)
	return st
}

// gitLevel 返回当前应使用的 git 改写档位（用户开关决定）。
func (a *App) gitLevel() string {
	if a.loadLicenseState().GitHTTPS {
		return executor.GitRewriteSSH
	}
	return executor.GitRewriteGitOnly
}

// autoStatus 读取自启状态缓存（启动时与每次切换后刷新）。
func (a *App) autoStatus() autostart.Status {
	a.autoMu.Lock()
	defer a.autoMu.Unlock()
	if a.autoSt.Mode == "" {
		return autostart.Status{Mode: autostart.ModeNone, Detail: "未开启"}
	}
	return a.autoSt
}

// refreshAutoStatus 重新查询并写入缓存。
func (a *App) refreshAutoStatus() autostart.Status {
	st := autostart.Query()
	a.autoMu.Lock()
	a.autoSt = st
	a.autoMu.Unlock()
	return st
}

// syncCLIProxy 把「命令行加速」对齐到当前实际状态：
//
//	深度加速开着 → 写 git 按 URL 代理（只影响 github.com），
//	               用户另外开了「环境变量」时才写 HTTP_PROXY/HTTPS_PROXY；
//	深度加速关着 → 全部精确撤销。
//
// 内部要 fork git 子进程（几十毫秒），因此调用方都用 goroutine，
// 绝不在 UI 线程同步等待。
func (a *App) syncCLIProxy() {
	a.deepMu.Lock()
	srv := a.proxy
	a.deepMu.Unlock()
	if srv == nil {
		if err := executor.RemoveCLIProxy(); err != nil {
			a.logf("撤销命令行代理失败: %v", err)
		}
		return
	}
	st := a.loadLicenseState()
	res, err := executor.ApplyCLIProxy(srv.Addr(), st.CLIProxyEnv)
	if err != nil {
		a.logf("命令行加速设置失败: %v", err)
		a.emitStatus("命令行加速设置失败: "+err.Error(), "warn")
		return
	}
	if res.Skipped != "" {
		// 用户已有自己的代理环境变量：如实告诉他我们没动，别让人以为设成功了
		a.emitStatus(res.Skipped, "warn")
	}
	a.logf("命令行加速: git 按 URL 代理=%v，环境变量=%v %s", res.GitApplied, res.EnvApplied, res.Detail)
}

// SetGitHTTPS 开关「Git 加速（HTTPS 模式）」。
//
// 开启后才会把 git@github.com: / ssh:// 改写成 HTTPS——这会改变 push 路径，
// 所以必须由用户主动勾选，界面也要把代价说清楚。关闭时立即精确撤销，
// SSH 推送能力当场恢复，不需要重启。
func (a *App) SetGitHTTPS(on bool) (map[string]any, error) {
	level := executor.GitRewriteGitOnly
	if on {
		level = executor.GitRewriteSSH
	}
	if err := executor.ApplyGit(level); err != nil {
		return a.proState(), err
	}
	st := a.loadLicenseState()
	st.GitHTTPS = on
	if err := a.saveLicenseState(st); err != nil {
		return a.proState(), fmt.Errorf("设置已生效，但保存状态失败（重启后会恢复默认）: %w", err)
	}
	a.logf("Git 加速档位切换为 %s（SSH 改写=%v）", level, on)
	a.emitState()
	return a.proState(), nil
}

// SetCLIProxyEnv 开关「命令行加速」里的环境变量部分（影响 gh / curl 等所有进程）。
//
// git 的按 URL 代理随深度加速自动生效，不需要这个开关；
// 这里控制的是更重的手段：写用户级 HTTP_PROXY / HTTPS_PROXY。
// 用户机器上已有自己的代理设置时，写入会被自动跳过并如实回报。
func (a *App) SetCLIProxyEnv(on bool) (map[string]any, error) {
	st := a.loadLicenseState()
	st.CLIProxyEnv = on
	if err := a.saveLicenseState(st); err != nil {
		return a.proState(), fmt.Errorf("保存状态失败: %w", err)
	}
	go a.syncCLIProxy()
	a.emitState()
	return a.proState(), nil
}

// ---------- Hosts 共存冲突告知 ----------

// reportHostsConflict 把「本次动过 Hosts 区块外的记录」如实告诉用户。
//
// 背景：ghsmart 写入前会注释掉与待写域名冲突的既有行（否则 Windows
// 「首条匹配优先」会把我们的记录压住，加速等于没做）。但那些行往往不是用户
// 手写的，而是**另一款加速工具**写的——被注释掉的那款就会莫名失效。
// 以前的实现默默处理，用户完全不知道，于是「装了两个加速器其中一个不灵」
// 这类问题永远查不出原因。
//
// 只提示一次（hostsRepOnce）：一轮加速里主域名提前写入与收尾写入都会回报，
// 去重后用户只看到一条，不会觉得软件在刷屏。
//
// 返回是否真的向用户报告了（供测试断言去重规则，调用方可忽略）。
func (a *App) reportHostsConflict(rep executor.HostsReport) bool {
	if rep.Commented == 0 && len(rep.ForeignTools) == 0 {
		return false
	}
	if !a.hostsRepOnce.CompareAndSwap(false, true) {
		return false
	}

	msg := ""
	if len(rep.ForeignTools) > 0 {
		msg = fmt.Sprintf("检测到 %s 也在管理相同的域名。为避免互相抢，已把它写的 %d 条记录临时注释；"+
			"关闭加速时会原样恢复。两款加速工具同时开容易互相干扰，建议只保留一款。",
			strings.Join(rep.ForeignTools, "、"), rep.Commented)
	} else {
		msg = fmt.Sprintf("Hosts 里有 %d 条与本次加速域名冲突的记录（可能来自其他加速工具），"+
			"已临时注释以免抢生效；关闭加速时会原样恢复。", rep.Commented)
	}
	a.logf("Hosts 共存提示: %s（被注释样本: %v）", msg, rep.CommentedLines)
	payload := map[string]any{
		"commented": rep.Commented,
		"lines":     rep.CommentedLines,
		"tools":     rep.ForeignTools,
		"message":   msg,
	}
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "engine:hosts-conflict", payload)
	}
	a.emitStatus("已加速，但压制了其他加速工具的记录（详见提示）", "warn")
	return true
}

// ---------- 检查更新 ----------

// updatePayload 组装版本与更新状态（唯一事实来源，供 proState 与事件共用）。
//
// 未检查过时也要返回 version：「界面显示 1.0.9」不依赖网络，
// 更不该由前端写死——否则发版时四处同步漏一处，界面就开始撒谎。
func (a *App) updatePayload() map[string]any {
	a.updateMu.Lock()
	defer a.updateMu.Unlock()
	m := map[string]any{
		"version":         appVersion,
		"updateAvailable": false,
	}
	if a.updateInfo == nil {
		return m
	}
	i := a.updateInfo
	m["updateAvailable"] = i.HasUpdate
	m["latest"] = i.Latest
	m["tag"] = i.Tag
	m["url"] = i.URL
	m["notes"] = i.Notes
	m["publishedAt"] = i.PublishedAt
	return m
}

// checkUpdateAsync 在后台检查一次更新：失败静默、不阻塞启动。
//
// 启动路径上多等一秒，用户就觉得软件卡——所以这里先睡 3 秒避开
// 「缓存秒应用 + 后台探测」的网络与 CPU 高峰，再发请求。
// 查询失败（公司防火墙拦 api.github.com、GitHub 限流）只写日志，
// 绝不让状态栏变红：查不到更新不是错误，软件照常能用。
func (a *App) checkUpdateAsync() {
	if !updater.Enabled() {
		a.logf("检查更新: 已通过 GHSMART_NO_UPDATE_CHECK 关闭")
		return
	}
	if !a.updateBusy.CompareAndSwap(false, true) {
		return
	}
	defer a.updateBusy.Store(false)

	time.Sleep(3 * time.Second)

	info, err := updater.Check(context.Background(), appVersion)
	if err != nil {
		a.logf("检查更新失败（不影响使用）: %v", err)
		return
	}
	// 用户明确跳过过这个版本 → 尊重选择：连「有待更新」这个状态都不留。
	// 若只 return 不改 info，下一次 emitState 又会把徽标顶回来，跳过就成了摆设。
	skipped := false
	if info.HasUpdate {
		if st := a.loadLicenseState(); st.SkippedVersion == info.Latest {
			skipped = true
			info.HasUpdate = false
		}
	}
	a.updateMu.Lock()
	a.updateInfo = info
	a.updateMu.Unlock()
	a.logf("检查更新: 本地 %s，远端 %s，有新版本=%v（已跳过该版本=%v）",
		info.Current, info.Latest, info.HasUpdate, skipped)

	if !info.HasUpdate {
		return
	}
	a.emitStatus(fmt.Sprintf("发现新版本 %s（右上角查看）", info.Tag), "ok")
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "app:update", a.updatePayload())
	}
}

// CheckUpdate 是前端「检查更新」按钮的入口：手动触发时用户需要知道结果，
// 所以失败要把原因返回出去（与后台静默检查不同）。
func (a *App) CheckUpdate() (map[string]any, error) {
	if !updater.Enabled() {
		return a.updatePayload(), errors.New("更新检查已被环境变量 GHSMART_NO_UPDATE_CHECK 关闭")
	}
	info, err := updater.Check(context.Background(), appVersion)
	if err != nil {
		return a.updatePayload(), fmt.Errorf("检查更新失败（可能是网络或被限流）: %w", err)
	}
	a.updateMu.Lock()
	a.updateInfo = info
	a.updateMu.Unlock()
	a.logf("手动检查更新: 本地 %s，远端 %s，有新版本=%v", info.Current, info.Latest, info.HasUpdate)
	return a.updatePayload(), nil
}

// OpenReleasePage 用系统浏览器打开新版本下载页。
//
// 不接受前端传参：只打开后端自己从 GitHub API 拿到的地址（或仓库固定地址），
// 避免这个绑定方法退化成一个「任意 URL 打开器」。
func (a *App) OpenReleasePage() error {
	url := "https://github.com/djy0314/ghsmart_OpenSource/releases/latest"
	a.updateMu.Lock()
	if a.updateInfo != nil && a.updateInfo.URL != "" {
		url = a.updateInfo.URL
	}
	a.updateMu.Unlock()
	if a.ctx == nil {
		return errors.New("应用尚未就绪")
	}
	runtime.BrowserOpenURL(a.ctx, url)
	a.logf("已打开下载页: %s", url)
	return nil
}

// SkipUpdate 记住「这个版本先不升级」，此后不再为它提示。
func (a *App) SkipUpdate() map[string]any {
	a.updateMu.Lock()
	latest := ""
	if a.updateInfo != nil {
		latest = a.updateInfo.Latest
	}
	a.updateMu.Unlock()
	if latest != "" {
		st := a.loadLicenseState()
		st.SkippedVersion = latest
		if err := a.saveLicenseState(st); err != nil {
			a.logf("保存跳过版本失败: %v", err)
		} else {
			a.logf("用户选择跳过版本 %s", latest)
		}
		// 同步把「有待更新」清掉：否则界面每次刷新都会把徽标重新显示出来
		a.updateMu.Lock()
		if a.updateInfo != nil {
			a.updateInfo.HasUpdate = false
		}
		a.updateMu.Unlock()
	}
	return a.updatePayload()
}

// SetAutoStart 开关「开机自动启动并最小化到托盘」。
//
// 实际机制由 internal/autostart 决定：优先计划任务（免 UAC 静默启动），
// 失败降级注册表 Run 键（开机会弹一次 UAC）。返回值里的
// autoStartMode / autoStartNeedsUAC 就是真实生效的机制，
// 界面必须按它渲染，不能一律说"已开启"。
func (a *App) SetAutoStart(on bool) (map[string]any, error) {
	exe, err := os.Executable()
	if err != nil {
		return a.proState(), fmt.Errorf("无法定位程序路径: %w", err)
	}
	var st autostart.Status
	if on {
		st, err = autostart.Enable(exe)
	} else {
		err = autostart.Disable()
		if err == nil {
			st = autostart.Status{Mode: autostart.ModeNone, Detail: "已关闭"}
		}
	}
	a.autoMu.Lock()
	a.autoSt = st
	a.autoMu.Unlock()
	if err == nil {
		ls := a.loadLicenseState()
		ls.AutoStart = on
		if serr := a.saveLicenseState(ls); serr != nil {
			a.logf("保存自启状态失败: %v", serr)
		}
		a.logf("开机自启: %v（机制=%s，需要 UAC=%v）%s", on, st.Mode, st.NeedsUAC, st.Detail)
	}
	a.emitState()
	if err != nil {
		return a.proState(), err
	}
	return a.proState(), nil
}

// SetAutoHeal 开关后台自动自愈（仅 Pro 可用），返回操作后的真实状态。
// 前端必须用返回值渲染，杜绝「本地猜测状态」与后端不一致。
func (a *App) SetAutoHeal(on bool) (map[string]any, error) {
	started := time.Now()
	defer func() {
		a.logf("后台自愈: 切换为 %v 完成，耗时 %s", on, time.Since(started).Round(time.Millisecond))
	}()
	if !a.pro.Load() {
		return a.proState(), errors.New("自动自愈是 Pro 功能，请先解锁")
	}
	if on {
		a.startHeal(a.loadCfg())
	} else {
		a.stopHeal()
	}
	st := a.loadLicenseState()
	st.AutoHeal = a.healOn.Load()
	if err := a.saveLicenseState(st); err != nil {
		return a.proState(), err
	}
	a.emitState()
	return a.proState(), nil
}

// startHeal 启动后台自愈循环：按配置 interval 周期执行一轮 apply，
// 与手动加速共用 busy 闸（忙时本轮跳过），窗口隐藏到托盘时照常工作。
// 幂等：重复调用会先停掉旧循环，绝不留双循环。
func (a *App) startHeal(cfg *config.Config) {
	interval, err := cfg.IntervalDuration()
	if err != nil || interval < 30*time.Second {
		interval = 10 * time.Minute
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.healMu.Lock()
	old := a.healCancel
	a.healCancel = cancel
	a.healMu.Unlock()
	if old != nil {
		old() // 先停旧循环
	}
	a.healOn.Store(true)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return // 已关闭
			case <-ticker.C:
				if !a.busy.CompareAndSwap(false, true) {
					continue // 上一轮还没跑完，跳过本周期
				}
				a.emitStatus("后台自愈: 正在巡检...", "busy")
				// 自愈循环是长驻协程：里面 panic 会把整个进程带走（用户看到的是
				// 「软件自己没了」）。这里必须 recover，并把 busy 闸放回去，
				// 否则下一个周期永远进不来。
				func() {
					defer func() {
						if r := recover(); r != nil {
							a.logf("后台自愈协程异常: %v", r)
							a.emitStatus("后台自愈: 本轮巡检异常（已自动恢复）", "warn")
						}
						a.busy.Store(false)
					}()
					_, _, _, err := engine.ApplyOnceOpts(cfg, guiReporter{a}, engine.Options{
						GitLevel: a.gitLevel(),
					})
					if err != nil {
						if errors.Is(err, engine.ErrInconclusive) {
							a.logf("后台自愈: 本轮证据不足，保持现有记录不动")
							a.emitStatus("后台自愈: 网络较慢，本轮未完成验证（已保留现有记录）", "warn")
							return
						}
						a.emitStatus("后台自愈: "+err.Error(), "err")
						return
					}
					a.emitStatus("后台自愈: 巡检完成", "ok")
				}()
			}
		}
	}()
	a.emitState()
}

// stopHeal 停止自愈循环并立即翻转状态；未运行时为安全空操作。
func (a *App) stopHeal() {
	a.healMu.Lock()
	cancel := a.healCancel
	a.healCancel = nil
	a.healMu.Unlock()
	if cancel != nil {
		cancel()
	}
	a.healOn.Store(false)
}

// 深度加速的两种模式（前端单选，后端只认字符串）。
const (
	DeepModeAuto   = "auto"   // 接管系统代理（默认）
	DeepModeManual = "manual" // 只开本地端口，绝不碰注册表
)

// normalizeDeepMode 把前端传值收敛成合法模式，非法值回落到 auto。
func normalizeDeepMode(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), DeepModeManual) {
		return DeepModeManual
	}
	return DeepModeAuto
}

// SetDeepAccel 开关「深度网页加速」（仅 Pro 可用）。
//
// 2026-11-04 号主重构：不再有模式选择、不再有预检拦截。
// 点开关就是开，连不上是网络的问题，不是软件拦人的理由。
//
//	on=true  → 启动本地代理（默认 TLS 分片），auto 模式接管系统代理
//	on=false → 精准还原系统代理后关闭端口
//
// 「连不上」由代理层自己解决：连续握手被重置会自动降级成纯隧道，
// 界面只显示「已开启 · 智能降级」，不弹任何红色错误。
func (a *App) SetDeepAccel(on bool) (map[string]any, error) {
	started := time.Now()
	// 耗时日志：这个方法是「点开关没反应」投诉的第一嫌疑对象
	//（要写注册表、要广播 WM_SETTINGCHANGE），有没有拖住 UI 靠日志说话。
	defer func() {
		a.logf("深度加速: 切换为 %v 完成，耗时 %s", on, time.Since(started).Round(time.Millisecond))
	}()
	if !a.pro.Load() {
		return a.proState(), errors.New("深度网页加速是 Pro 功能，请先解锁")
	}
	if on {
		if err := a.startDeep(a.loadCfg()); err != nil {
			return a.proState(), err
		}
	} else {
		a.stopDeep()
	}
	st := a.loadLicenseState()
	st.DeepAccel = a.deepOn.Load()
	if err := a.saveLicenseState(st); err != nil {
		return a.proState(), fmt.Errorf("深度加速已按预期切换，但保存状态失败: %w", err)
	}
	return a.proState(), nil
}

// vpnNicKeywords 是虚拟/VPN 网卡的识别关键字（深信服 aTrust/EasyConnect、
// 各类 TAP/TUN、思科 AnyConnect 等）。命中其一即不作为「物理网卡」候选。
var vpnNicKeywords = []string{
	"vpn", "sangfor", "atrust", "easyconnect", "sslvpn", "tap", "tun",
	"ppp", "wireguard", "openvpn", "anyconnect", "globalprotect",
	"virtual", "vethernet", "hyper-v", "wsl", "vmware", "virtualbox",
	"loopback", "bluetooth", "debug",
}

// physicalNICIPs 自动探测「物理网卡」的 IPv4 源地址（最多 2 个），
// 供代理拨号绑定用：绑定后流量强制从物理网卡发出，绕开 aTrust 等
// VPN 虚拟网卡对默认路由的劫持（见 webproxy.dialIPBound 注释）。
// 探测规则：Up + 非 Loopback + 名称不命中 VPN/虚拟关键字 + 配有非链路本地 IPv4。
// 一个都探不到时返回 nil（拨号竞速退回普通路径，功能不受影响）。
func physicalNICIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := strings.ToLower(ifc.Name)
		hit := false
		for _, kw := range vpnNicKeywords {
			if strings.Contains(name, kw) {
				hit = true
				break
			}
		}
		if hit {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, ad := range addrs {
			ipn, ok := ad.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipn.IP.To4()
			if ip4 == nil || ip4.IsLinkLocalUnicast() || ip4.IsLoopback() {
				continue
			}
			out = append(out, ip4.String())
			break // 每张网卡只取第一个 IPv4
		}
		if len(out) >= 2 {
			break
		}
	}
	return out
}

// startDeep 拉起本地代理并接管系统代理。
//
// 2026-11-04 号主重构：没有模式参数、没有兼容开关——一律「智能模式」：
//   - 启动即用 TLS 分片（对抗 SNI 阻断）
//   - 连续握手被重置 → 代理层自己降级为纯 CONNECT 隧道并回调 onDeepDegrade
//
// 用户只需要知道「开了」还是「没开」，剩下的全部交给底层。
// 任何一步失败都会回滚，绝不留「端口开着但系统代理没接管」的中间态。
func (a *App) startDeep(cfg *config.Config) error {
	a.deepMu.Lock()
	if a.proxy == nil {
		localAddrs := physicalNICIPs()
		if len(localAddrs) > 0 {
			a.logf("VPN 兼容：探测到物理网卡源地址 %v，拨号竞速将附带绑定源地址的入口", localAddrs)
		} else {
			a.logf("VPN 兼容：未探测到可用的物理网卡 IPv4，拨号走普通路径")
		}
		srv := webproxy.New(webproxy.Options{
			Listen: cfg.WebProxy.Listen,
			Split: webproxy.Splitter{
				Window: cfg.WebProxy.SplitWindow,
				Delay:  time.Duration(cfg.WebProxy.SplitDelayMS) * time.Millisecond,
			},
			Hosts:   cfg.WebProxy.SplitHosts,
			Resolve: a.resolveHosts, // 502 的根因修复：连优选 IP，不走被污染的本地 DNS
			// 全部候选都拨不通 → 作废缓存，别拿同一批死 IP 反复撞
			ResolveInvalidate: a.invalidateHostIP,
			DialTimeout:       time.Duration(cfg.WebProxy.DialTimeoutMS) * time.Millisecond,
			LocalAddrs:        localAddrs,
			// 静默降级：分片被中间设备拦到一定次数就自己切隧道，
			// 只回调一次用于更新状态栏，不弹窗、不关加速
			OnDegrade:    a.onDeepDegrade,
			DegradeAfter: 3,
			Logf:         a.logf,
		})
		if _, err := srv.Start(); err != nil {
			a.deepMu.Unlock()
			return fmt.Errorf("启动本地加速代理失败: %w", err)
		}
		a.proxy = srv
		a.deepAddr = srv.Addr()
	}
	addr := a.proxy.Addr()
	a.deepMu.Unlock()

	// 守卫进程：从现在起，哪怕主进程被任务管理器强杀，系统代理也会被还原。
	// 懒派生——免费用户不开深度加速就完全不占额外进程。
	a.ensureGuard(cfg)

	{
		// 与后台还原互斥：避免「刚接管好又被上一轮的迟到还原写回直连」
		a.restoreMu.Lock()
		res, err := sysproxy.Apply(addr)
		if err == nil {
			// 接管成功 → 代际 +1；此后任何更早的还原都会在锁内发现代际不符而作废
			a.deepGen.Add(1)
		}
		a.restoreMu.Unlock()
		if err == nil {
			a.deepMu.Lock()
			a.bypassRemoved = append([]string(nil), res.RemovedBypass...)
			a.deepMu.Unlock()
			// bypass 清理是本次 ERR_CONNECTION_CLOSED 的根因修复，必须留痕
			if len(res.RemovedBypass) > 0 {
				a.logf("已从系统代理例外列表（bypass）中移除 %d 条 GitHub 系条目: %s",
					len(res.RemovedBypass), strings.Join(res.RemovedBypass, ", "))
				a.emitStatus("已清理代理例外列表中的 "+strings.Join(res.RemovedBypass, "、"), "warn")
			} else {
				a.logf("系统代理例外列表无 GitHub 条目（bypass=%q）", res.Bypass)
			}
		}
		if err != nil {
			// 接管失败就全量回滚，别留个没人用的本地端口
			a.deepMu.Lock()
			if a.proxy != nil {
				_ = a.proxy.Stop()
				a.proxy = nil
				a.deepAddr = ""
			}
			a.deepMu.Unlock()
			a.deepOn.Store(false)
			return err
		}
	}
	a.deepMu.Lock()
	a.deepMode = DeepModeAuto
	a.deepCompat = false
	a.deepDegraded = false // 每次重新开启都从「分片模式」开始试
	a.deepMu.Unlock()
	a.deepOn.Store(true)
	a.emitState()
	// 命令行接管放到后台：要 fork git 子进程，绝不能挡住「开启」按钮的返回。
	go a.syncCLIProxy()
	return nil
}

// restoreProxyFn 是系统代理还原的注入点（单测替换成可控的慢速/失败桩）。
var restoreProxyFn = sysproxy.Restore

// stopDeep 关闭深度加速，**返回一个在系统代理还原完成后关闭的 channel**。
//
// 为什么拆两段（这是「关闭卡好几秒」的根因修复）：
//  1. sysproxy.Restore 要读注册表 → 写注册表 → InternetSetOptionW 广播，
//     被 VPN / 安全软件拦的时候能停好几秒；
//  2. 本地代理 Stop 也可能要等正在拨号的请求退出来。
//
// 这两件都不该让用户在按钮上等。所以同步段只做三件微秒级的事——
// 摘掉状态、释放监听端口、标记已关闭；还原动作丢进 goroutine，
// 完成后发 deep:closed 事件，前端据此把 Toast 从「正在清理」改成「已还原」。
//
// 调用方：SetDeepAccel / RemoveHosts 走异步（要丝滑）；
// Shutdown 走 stopDeepWait（退出前必须尽量等完，否则用户断网）。
func (a *App) stopDeep() <-chan struct{} {
	a.deepMu.Lock()
	srv := a.proxy
	a.proxy = nil
	a.deepAddr = ""
	a.deepDegraded = false
	a.bypassRemoved = nil
	a.deepOn.Store(false)
	a.deepMu.Unlock()

	// 释放监听端口 + 暴力切断在途隧道；Stop 已改为不等 wg，微秒级返回。
	// 必须先放端口再还原注册表：否则用户紧接着再点开启会撞端口占用。
	if srv != nil {
		_ = srv.Stop()
	}

	// 记下当前代际：还原前若代际变了，说明用户已经重新开启，这次还原作废。
	gen := a.deepGen.Load()
	target := a.targetAddr()
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.restoreSystemProxy(gen, target)
	}()
	// 命令行代理清理独立跑：它要 fork git 子进程（几十毫秒起），
	// 绝不能拖慢「关闭已完成」的信号——否则用户点关闭会等出白屏，
	// 退出流程的 watchdog 也会被它连累。清理本身幂等，晚一点无副作用。
	go func() {
		if err := executor.RemoveCLIProxy(); err != nil {
			a.logf("撤销命令行代理失败: %v", err)
		}
	}()
	return done
}

// stopDeepWait 是 stopDeep 的同步版：最多等 timeout，超时就不再等
// （还原动作仍在后台跑，另有守卫进程兜底）。
func (a *App) stopDeepWait(timeout time.Duration) {
	done := a.stopDeep()
	select {
	case <-done:
	case <-time.After(timeout):
		a.logf("等待系统代理还原超过 %v，不再阻塞退出（守卫进程会兜底）", timeout)
	}
}

// restoreSystemProxy 在后台还原系统代理，完成后广播 deep:closed。
//
// 事件字段：ok=true 表示已还原（含「本来就没接管」和「已作废」两种正常情况），
// err 非空表示还原失败（UI 必须明说，否则用户可能上不了网还不知道原因）。
func (a *App) restoreSystemProxy(gen int64, target string) {
	start := time.Now()
	defer func() {
		if r := recover(); r != nil {
			a.logf("还原系统代理时发生异常: %v", r)
			a.emitDeepClosed(false, fmt.Sprint(r), time.Since(start), false)
		}
	}()

	// 与接管互斥：拿到锁之后再校验代际，彻底堵死「检查通过 → 用户点开 →
	// 还原把新接管写回直连」的竞态窗口。
	a.restoreMu.Lock()
	if a.deepGen.Load() != gen || a.deepOn.Load() {
		a.restoreMu.Unlock()
		a.logf("跳过过期的系统代理还原（期间已重新开启深度加速）")
		a.emitDeepClosed(true, "", time.Since(start), true)
		return
	}
	ok, err := restoreProxyFn(target)
	a.restoreMu.Unlock()
	ms := time.Since(start).Milliseconds()
	if err != nil {
		a.logf("还原系统代理失败（耗时 %dms）: %v", ms, err)
		a.emitDeepClosed(false, err.Error(), time.Since(start), false)
		return
	}
	a.logf("系统代理已还原（changed=%v，耗时 %dms）", ok, ms)
	a.emitDeepClosed(true, "", time.Since(start), false)
}

// emitDeepClosedEvent 是事件出口的注入点（单测替换它抓 payload）。
var emitDeepClosedEvent = func(a *App, payload map[string]any) {
	if a.ctx == nil {
		return
	}
	runtime.EventsEmit(a.ctx, "deep:closed", payload)
}

// emitDeepClosed 广播「深度加速已彻底关闭、系统代理已还原」。
func (a *App) emitDeepClosed(ok bool, errMsg string, d time.Duration, skipped bool) {
	payload := map[string]any{
		"ok":      ok,
		"ms":      d.Milliseconds(),
		"skipped": skipped,
	}
	if errMsg != "" {
		payload["err"] = errMsg
	}
	emitDeepClosedEvent(a, payload)
}

// guardSpawn 是守卫进程的派生入口（测试替换，避免在单测里拉起真实子进程）。
var guardSpawn = proxyguard.Spawn

// ensureGuard 懒派生守卫进程（每个进程生命周期内只派生一次）。
//
// 职责边界：守卫不参与正常业务，只做一件事——盯着主进程句柄，
// 主进程一死（含被任务管理器强杀）就按备份把系统代理还原掉。
// 免费用户不开深度加速时不会派生，不额外占内存。
func (a *App) ensureGuard(cfg *config.Config) {
	a.guardOnce.Do(func() {
		target := cfg.WebProxy.Listen
		if target == "" {
			target = sysproxy.DefaultTarget
		}
		g, err := guardSpawn(a.job, target)
		if err != nil {
			a.logf("守卫进程启动异常（强杀还原能力可能受限）: %v", err)
		}
		if g != nil {
			a.guard = g
			a.logf("守卫进程已就绪 pid=%d：主进程被强杀也会还原系统代理", g.Pid())
		} else {
			a.logf("守卫进程未能启动：强杀后仅靠下次启动自检恢复")
		}
	})
}

// onDeepDegrade 是代理层「静默降级」的回调。
//
// 含义：中间设备把分片的 TLS 握手当异常流量掐得太狠，代理自己切成纯隧道继续工作。
// 这里**只**做两件事：记日志 + 把状态栏换成「已开启 · 智能降级」。
// 不弹窗、不关加速、不要求用户做任何选择——这才是「底层自愈」该有的样子。
func (a *App) onDeepDegrade(reason string) {
	a.deepMu.Lock()
	a.deepDegraded = true
	a.deepMu.Unlock()
	a.logf("深度加速已智能降级为纯隧道（原因: %s）", reason)
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "deep:degraded", map[string]any{"reason": reason})
	}
	a.emitStatus("已开启 · 智能降级", "ok")
	a.emitState()
}

// primaryDomain 返回配置域名列表的主域名（github.com）；列表为空返回空串。
func (a *App) primaryDomain() string {
	cfg := a.loadCfg()
	if len(cfg.Domains) > 0 {
		return cfg.Domains[0]
	}
	return ""
}

// targetAddr 返回我们应当接管的代理地址（配置里的监听地址）。
func (a *App) targetAddr() string {
	addr := a.loadCfg().WebProxy.Listen
	if addr == "" {
		return sysproxy.DefaultTarget
	}
	return addr
}

// logf 统一日志出口（GUI 下没有控制台，写到 ~/.ghsmart/ghsmart.log，
// 排查 502 / 分片失败时直接看这个文件）。
func (a *App) logf(format string, args ...any) {
	line := time.Now().Format("2006-01-02 15:04:05 ") + fmt.Sprintf(format, args...)
	a.logMu.Lock()
	defer a.logMu.Unlock()
	if a.logFile == nil {
		if p, err := logPath(); err == nil {
			_ = os.MkdirAll(filepath.Dir(p), 0o755)
			if f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
				a.logFile = f
			}
		}
	}
	if a.logFile != nil {
		_, _ = a.logFile.WriteString(line + "\n")
	}
}

// logPath 返回日志文件路径（GHSMART_LOG_FILE 可覆盖，测试用）。
func logPath() (string, error) {
	if p := os.Getenv("GHSMART_LOG_FILE"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ghsmart", "ghsmart.log"), nil
}

// resolveHosts 给代理提供候选「优选 IP」：Hosts 优选池优先，其次 DoH，最后应急 IP 池。
//
// 注意这里返回的只是**候选**：代理会对它们并发建连竞速，只有真正连上的才会被采用。
// 所以即便「一键智能加速」写进 hosts 的那条 IP 已经失效，它也只是输掉比赛，
// 不会像以前那样把浏览器的 CONNECT 卡到超时（ERR_CONNECTION_TIMED_OUT）。
// 结果缓存 10 分钟，避免每个 CONNECT 都解析一次；全部候选失败时由 invalidateHostIP 作废。
func (a *App) resolveHosts(host string) []string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil
	}
	// 本身就是 IP 直接返回
	if net.ParseIP(host) != nil {
		return []string{host}
	}
	// 非管辖域名（普通网站）：不用 DoH。它们不在 hosts 区块里，系统解析不会被我们污染，
	// 代理会按域名直连；若这里强行 DoH，反而会给每个网站加一次解析延迟。
	if !a.isManagedHost(host) {
		return nil
	}
	a.ipMu.Lock()
	if e, ok := a.ipCache[host]; ok && time.Since(e.at) < 10*time.Minute {
		a.ipMu.Unlock()
		return e.ips
	}
	a.ipMu.Unlock()

	var ips []string
	// 1) Hosts 区块里的优选 IP（「探测 + 决策」的产物，最权威）
	if entries, err := executor.ReadHostsBlock(); err == nil {
		if v, ok := entries[host]; ok && net.ParseIP(v) != nil {
			ips = append(ips, v)
		}
	}
	// 2) 兜底：DoH 解析（IPv4 优先，绕开被污染的系统 DNS）
	cfg := a.loadCfg()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	list, err := doh.ResolveWith(ctx, host, cfg.DoHEndpoints)
	cancel()
	if err == nil {
		for _, v := range list {
			if v.To4() == nil {
				continue // 国内到 GitHub 的 IPv6 常被黑洞，不作为候选
			}
			ips = appendIP(ips, v.String())
		}
	}
	// 3) 最后一道保险：应急 IP 池（DoH 被污染 / 唯一 A 记录失效时用）
	for _, g := range cfg.WebProxy.FallbackIPs {
		suffix := strings.ToLower(strings.TrimPrefix(g.Suffix, "."))
		if suffix == "" || (host != suffix && !strings.HasSuffix(host, "."+suffix)) {
			continue
		}
		for _, ip := range g.IPs {
			ips = appendIP(ips, ip)
		}
	}
	a.ipMu.Lock()
	if a.ipCache == nil {
		a.ipCache = make(map[string]ipEntry)
	}
	a.ipCache[host] = ipEntry{ips: ips, at: time.Now()}
	a.ipMu.Unlock()
	if len(ips) == 0 {
		a.logf("解析 %s 失败（Hosts 与 DoH 均无结果），将回退系统 DNS", host)
	}
	return ips
}

// isManagedHost 判断域名是否在配置的 split_hosts 里（= ghsmart 会改写其 hosts 记录）。
func (a *App) isManagedHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	for _, suffix := range a.loadCfg().WebProxy.SplitHosts {
		suffix = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(suffix), "."))
		if suffix == "" {
			continue
		}
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

// invalidateHostIP 作废某域名的 IP 缓存：
// 代理那边所有候选都拨不通时调用，下一次 CONNECT 会重新问 DoH，
// 而不是拿着同一批死 IP 反复撞 10 分钟。
func (a *App) invalidateHostIP(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return
	}
	a.ipMu.Lock()
	delete(a.ipCache, host)
	a.ipMu.Unlock()
	a.logf("已作废 %s 的 IP 缓存，下次连接将重新解析", host)
}

// invalidateAllHostIP 清空全部 IP 缓存（hosts 区块被改写后调用）。
func (a *App) invalidateAllHostIP() {
	a.ipMu.Lock()
	a.ipCache = nil
	a.ipMu.Unlock()
}

// appendIP 追加去重。
func appendIP(list []string, ip string) []string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return list
	}
	for _, v := range list {
		if v == ip {
			return list
		}
	}
	return append(list, ip)
}

type ipEntry struct {
	ips []string
	at  time.Time
}

// emitStatus 推送状态文本与样式类（busy/ok/warn/err），
// 前端一次渲染到位，避免状态点在多个事件间来回闪跳。
func (a *App) emitStatus(text, cls string) {
	if a.ctx == nil {
		return // 无 GUI 上下文（单测/CLI 场景）时静默
	}
	runtime.EventsEmit(a.ctx, "engine:status", map[string]any{
		"text": text, "cls": cls,
	})
}

// emitState 推送 Pro/自愈当前状态（解锁状态变化、启动恢复时调用）。
func (a *App) emitState() {
	if a.ctx == nil {
		return
	}
	runtime.EventsEmit(a.ctx, "engine:state", a.proState())
}
