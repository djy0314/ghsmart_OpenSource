// App 是 Wails GUI 的后端绑定层：把 internal/engine 的能力暴露给前端，
// 并通过 Wails Events 把探测过程实时推送给界面渲染。
package main

import (
	"context"
	"crypto/tls"
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

	"ghsmart/internal/cache"
	"ghsmart/internal/config"
	"ghsmart/internal/doh"
	"ghsmart/internal/engine"
	"ghsmart/internal/executor"
	"ghsmart/internal/license"
	"ghsmart/internal/probe"
	"ghsmart/internal/sysproxy"
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
	deepMu     sync.Mutex
	proxy      *webproxy.Server
	deepAddr   string
	deepMode   string
	deepCompat bool // 兼容模式：不做 TLS 分片（公司 VPN 场景）
	deepOn     atomic.Bool
	// bypassRemoved 记录本次接管从系统「代理例外列表」里剔除了哪些 GitHub 条目，
	// 供前端回显（用户可据此去 Windows 代理设置里核对）。
	bypassRemoved []string

	// 优选 IP 解析缓存（host -> IP，10 分钟过期），避免每个 CONNECT 都解析
	ipMu    sync.Mutex
	ipCache map[string]ipEntry

	// 诊断日志（GUI 无控制台，写 ~/.ghsmart/ghsmart.log）
	logMu   sync.Mutex
	logFile *os.File
}

// NewApp 创建应用实例。
func NewApp() *App {
	return &App{}
}

// startup 由 Wails 在窗口创建后回调，保存运行时上下文。
// 已持久化的 Pro 授权在此做离线复验（到期/机器码变更会拒绝），通过则恢复解锁；
// 自动自愈开关处于开启状态时顺带拉起后台循环。
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	cfg := a.loadCfg()
	// 第一件事：如果上次是异常退出（进程被强杀）导致系统代理还指着本机，
	// 立刻按「精准核对」还原——只有确实指向我们时才动，第三方代理绝不覆盖。
	if restored, err := sysproxy.Recover(cfg.WebProxy.Listen); err != nil {
		a.emitStatus("系统代理兜底还原失败: "+err.Error(), "warn")
	} else if restored {
		a.emitStatus("已自动还原上次遗留的系统代理", "ok")
	}
	if st := a.loadLicenseState(); st.Key != "" {
		if ok, err := license.VerifyOffline(st.Key); err == nil && ok {
			a.pro.Store(true)
			if st.AutoHeal {
				a.startHeal(cfg)
			}
			if st.DeepAccel {
				if err := a.startDeep(cfg, st.DeepMode, a.effectiveCompat(st, cfg)); err != nil {
					a.emitStatus("深度加速恢复失败: "+err.Error(), "warn")
				}
			}
		}
	}
	// 兼容模式默认值：license.json 里用户勾选过的优先，否则取配置文件开关
	a.deepMu.Lock()
	a.deepCompat = a.effectiveCompat(a.loadLicenseState(), cfg)
	a.deepMu.Unlock()
	// ★ 缓存秒应用：上次探测成功的最优 IP 直接恢复加速（免费版无条件），
	// 打开软件即用，无需再点按钮；随后后台静默校验更优 IP。
	a.applyCacheOnStartup(cfg)
	a.emitState()
}

// loadCfg 加载配置：优先 exe 同目录 configs/default.yaml，读不到用内置默认。
func (a *App) loadCfg() *config.Config {
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "configs", "default.yaml")
		if cfg, err := config.Load(p); err == nil {
			engine.Configure(cfg)
			return cfg
		}
	}
	cfg, _ := config.Load("") // 文件缺失时 config.Load 自动回退默认值
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

	// ★ 缓存秒应用（核心提速）：有新鲜缓存时 0.1 秒内写 Hosts + 刷 DNS，
	// 用户立刻可用；随后在后台静默发起一轮全新探测，发现更优 IP 再悄悄替换并提示。
	cached := a.loadFreshCache(cfg)
	if len(cached) > 0 {
		if err := executor.ApplyHosts(cached); err == nil {
			a.invalidateAllHostIP()
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
		defer a.busy.Store(false)
		written, lines, restricted, err := engine.ApplyOnceOpts(cfg, guiReporter{a}, engine.Options{
			// 主域名（github.com）一探测成功就立刻写入并通知 UI，
			// 其余域名继续在后台探测（由引擎在收尾统一全量写入）。
			OnPrimary: func(entries map[string]string) {
				a.invalidateAllHostIP()
				a.emitStatus("加速已生效（主域名已生效，其余域名后台优化中...）", "ok")
				runtime.EventsEmit(a.ctx, "engine:primary", map[string]any{
					"ok": true, "written": len(entries),
				})
			},
		})
		// hosts 区块可能刚刚被改写：代理手里的 IP 缓存必须作废，
		// 否则「刚优选出的新 IP」要等 10 分钟才生效（这是双加速叠加的必要配合）。
		a.invalidateAllHostIP()
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
			runtime.EventsEmit(a.ctx, "engine:applied", map[string]any{
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
		runtime.EventsEmit(a.ctx, "engine:applied", payload)
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
	written, _, restricted, err := engine.ApplyOnce(cfg, silentReporter{})
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
	} else if err := executor.ApplyHosts(cached); err != nil {
		a.logf("启动缓存秒应用失败: %v", err)
		return
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
	a.stopDeep()
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
// 正常退出远快于此；留够时间让 Wails 先走完 OnBeforeClose / OnShutdown。
// 声明成变量是为了测试能缩短它（测试进程不能被 os.Exit 打死）。
var quitWatchdogDelay = 2 * time.Second

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
	a.Shutdown() // 幂等：还原代理、停自愈、关日志

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
	a.stopDeep()
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
	a.stopDeep() // 先退 Pro 功能，尤其是别把系统代理留在本机
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
	m := map[string]any{
		"pro":        a.pro.Load(),
		"autoHeal":   a.healOn.Load(),
		"deepAccel":  a.deepOn.Load(),
		"deepListen": "",
		"deepMode":   "",
	}
	a.deepMu.Lock()
	if a.deepMode != "" {
		m["deepMode"] = a.deepMode
	}
	m["deepCompat"] = a.deepCompat
	// 弹窗默认勾选来源：配置文件 web_proxy.compat_mode（号主要求：默认不勾，
	// 只有配置文件明确设了默认开启才勾；不再沿用「上次的选择」）
	m["deepCompatDefault"] = a.loadCfg().WebProxy.CompatMode
	if a.proxy != nil {
		m["deepListen"] = a.proxy.Addr()
		m["deepStats"] = a.proxy.Stats()
	}
	m["bypassRemoved"] = append([]string(nil), a.bypassRemoved...)
	a.deepMu.Unlock()
	return m
}

// SetAutoHeal 开关后台自动自愈（仅 Pro 可用），返回操作后的真实状态。
// 前端必须用返回值渲染，杜绝「本地猜测状态」与后端不一致。
func (a *App) SetAutoHeal(on bool) (map[string]any, error) {
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
				_, _, _, err := engine.ApplyOnce(cfg, guiReporter{a})
				a.busy.Store(false)
				if err != nil {
					a.emitStatus("后台自愈: "+err.Error(), "err")
					continue
				}
				a.emitStatus("后台自愈: 巡检完成", "ok")
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
//	on=true, mode=auto   → 启动本地 TLS 分片代理 + 接管系统代理（写注册表 + WinINET 广播）
//	on=true, mode=manual → 只启动本地代理端口，绝对不碰注册表
//	on=false             → 精准还原系统代理后关闭端口
//	compat=true          → 兼容模式：不做 TLS 分片，纯 CONNECT 隧道（公司 VPN 场景）
//	force=true           → 跳过实时微测预检（用户点「仍然强制开启」的逃生通道）
//
// 返回操作后的真实状态，前端必须用返回值渲染。
func (a *App) SetDeepAccel(on bool, mode string, compat bool, force bool) (map[string]any, error) {
	if !a.pro.Load() {
		return a.proState(), errors.New("深度网页加速是 Pro 功能，请先解锁")
	}
	mode = normalizeDeepMode(mode)
	if on {
		// 预检闸（后端为准，前端拦截只是体验优化）：现场做 2 秒实时微测，
		// 只要此刻能连上 github.com 就放行——绝不拿旧报告拦人。
		// force=true 是用户点了「仍然强制开启」的逃生通道：跳过微测，
		// 但照样记录在案（日志可查、后果自负）。
		if !force {
			if ok, reason, checked, _ := a.deepPrecheckLive(a.primaryDomain()); !ok {
				a.logf("深度加速被预检拦截（实时微测 %d 个候选全部不可达）", checked)
				return a.proState(), errors.New(reason)
			}
		} else {
			a.logf("深度加速被用户强制开启（跳过实时微测预检）")
		}
		if err := a.startDeep(a.loadCfg(), mode, compat); err != nil {
			return a.proState(), err
		}
	} else {
		a.stopDeep()
	}
	st := a.loadLicenseState()
	st.DeepAccel = a.deepOn.Load()
	if st.DeepAccel {
		st.DeepMode = mode
		st.DeepCompat = compat
	}
	if err := a.saveLicenseState(st); err != nil {
		return a.proState(), fmt.Errorf("深度加速已按预期切换，但保存状态失败: %w", err)
	}
	return a.proState(), nil
}

// effectiveCompat 计算兼容模式的生效值：用户在 UI 里明确勾选过的（license.json）
// 优先；从未记录过时用配置文件 web_proxy.compat_mode 作为默认。
func (a *App) effectiveCompat(st licenseState, cfg *config.Config) bool {
	if st.DeepCompat {
		return true
	}
	return cfg.WebProxy.CompatMode
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

// startDeep 拉起本地代理；auto 模式再接管系统代理。
// compat=true 为兼容模式：不做 TLS 分片（公司 VPN 场景），其余规则不变。
// 任何一步失败都会回滚，绝不留「端口开着但系统代理没接管」或反过来的中间态。
func (a *App) startDeep(cfg *config.Config, mode string, compat bool) error {
	mode = normalizeDeepMode(mode)

	a.deepMu.Lock()
	if a.proxy == nil {
		localAddrs := physicalNICIPs()
		if len(localAddrs) > 0 {
			a.logf("VPN 兼容：探测到物理网卡源地址 %v，拨号竞速将附带绑定源地址的入口", localAddrs)
		} else {
			a.logf("VPN 兼容：未探测到可用的物理网卡 IPv4，拨号走普通路径")
		}
		if compat {
			a.logf("深度加速以兼容模式启动：不做 TLS 分片，纯 CONNECT 隧道")
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
			DialTimeout: time.Duration(cfg.WebProxy.DialTimeoutMS) * time.Millisecond,
			DisableSplit:      compat,
			LocalAddrs:        localAddrs,
			// 自动避让：公司 VPN 等环境拦截加速流量时，连续全败即自动关闭，
			// 防止用户网页全卡死（回调在独立协程里执行，可安全 Stop）
			OnAutoFallback: a.autoFallbackDeep,
			Logf:              a.logf,
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

	if mode == DeepModeAuto {
		res, err := sysproxy.Apply(addr)
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
	a.deepMode = mode
	a.deepCompat = compat
	a.deepMu.Unlock()
	a.deepOn.Store(true)
	a.emitState()
	return nil
}

// stopDeep 关闭深度加速：**先精准还原系统代理**（网络优先恢复），再断开本地端口。
// 手动模式下系统代理本来就没改，Restore 会识别出「不是我们的」并原样跳过。
func (a *App) stopDeep() {
	a.deepMu.Lock()
	defer a.deepMu.Unlock()
	if _, err := sysproxy.Restore(a.targetAddr()); err != nil {
		// 还原失败必须让用户知道（否则可能上不了网），但仍要把代理端口关掉
		a.emitStatus("还原系统代理失败: "+err.Error(), "err")
	}
	if a.proxy != nil {
		_ = a.proxy.Stop()
		a.proxy = nil
		a.deepAddr = ""
	}
	a.deepOn.Store(false)
}

// autoFallbackDeep 是代理触发的「自动避让」：连续多轮全部候选失败时
// 自动关闭深度加速，把开关变灰，并通知前端弹友好提示。
// 只在深度加速确实开着时生效；Hosts 模式（一键智能加速）不受任何影响。
func (a *App) autoFallbackDeep(reason string) {
	if a.ctx == nil || !a.deepOn.Load() {
		return
	}
	a.logf("Auto-Fallback: 自动关闭深度加速，原因: %s", reason)
	a.stopDeep()
	// 开关状态持久化为关闭，重启后不会自动恢复一个已被判定不可用的功能
	st := a.loadLicenseState()
	st.DeepAccel = false
	_ = a.saveLicenseState(st)
	// 要求 3：Hosts 模式可用性——只要区块里还有有效记录就不算失效，如实上报
	hostsLeft := 0
	if entries, err := executor.ReadHostsBlock(); err == nil {
		hostsLeft = len(entries)
	}
	a.emitState()
	runtime.EventsEmit(a.ctx, "deep:autofallback", map[string]any{
		"reason":       reason,
		"state":        a.proState(),
		"hostsEntries": hostsLeft,
	})
}

// classifyNetErr 把底层探测错误翻译成用户能看懂的失败原因（透明化）。
func classifyNetErr(errStr string) string {
	s := strings.ToLower(errStr)
	switch {
	case strings.Contains(s, "no such host") || strings.Contains(s, "lookup"):
		return "DNS 解析失败"
	case strings.Contains(s, "tcp 失败") && strings.Contains(s, "i/o timeout"):
		return "TCP 连接超时（IP 不可达或被防火墙/VPN 拦截）"
	case strings.Contains(s, "tls 失败") && (strings.Contains(s, "reset") || strings.Contains(s, "forcibly closed")):
		return "TLS 握手被重置（典型的 VPN/防火墙代答拦截）"
	case strings.Contains(s, "tls 失败") && strings.Contains(s, "i/o timeout"):
		return "TLS 握手超时（连接被静默丢弃）"
	case strings.Contains(s, "certificate"):
		return "证书校验失败（连上的不是真 GitHub，DNS 被污染）"
	default:
		return errStr
	}
}

// deepCheckResult 是实时微测的完整结果：是否可用 + 逐条诊断明细。
type deepCheckResult struct {
	OK      bool
	Checked int      // 实际尝试的候选 IP 数
	Detail  []string // 给用户看的失败原因明细（成功时可能为空）
}

// deepLiveCheckTimeout 是「深度加速」实时预检微测的总预算。
// 号主定稿：2 秒即可——够一次真实 TCP+TLS 握手，又不至于让用户干等。
const deepLiveCheckTimeout = 2 * time.Second

// deepRestrictedMsg 是实时微测全部失败时的提示文案（号主定稿，勿改字）。
const deepRestrictedMsg = "当前网络环境依然受限，请确保已彻底关闭公司 VPN 后重试。若仍不行，请仅使用「一键智能加速」。"

// deepProbeFn 是实时连通性微测的实现（测试可替换），默认走 probe.ProbeIPs
// ——真实的 TCP 连接 + SNI 严格校验证书 TLS 握手 + HTTP 应答。
var deepProbeFn = probe.ProbeIPs

// directTLSCheck 是最小保底微测：系统 DNS 直连 domain:443，做一次
// 严格校验证书的 TLS 握手。用于「一个候选 IP 都拿不到」时仍能判定网络是否恢复。
var directTLSCheck = func(domain string, timeout time.Duration) (bool, error) {
	nc, err := (&net.Dialer{Timeout: timeout}).Dial("tcp", net.JoinHostPort(domain, "443"))
	if err != nil {
		return false, err
	}
	defer nc.Close()
	conn := tls.Client(nc, &tls.Config{ServerName: domain, MinVersion: tls.VersionTLS12})
	_ = nc.SetDeadline(time.Now().Add(timeout))
	if err := conn.Handshake(); err != nil {
		return false, err
	}
	_ = conn.Close()
	return true, nil
}

// dohResolveCap 是预检里 DoH 现解析的时间上限：只为补充候选 IP，
// 拿不到就直连兜底，绝不能把整个 2 秒预算耗在 DNS 上（国内 DoH 常被墙）。
const dohResolveCap = 700 * time.Millisecond

// deepCandidatesFn 是候选收集的可注入入口（测试用来造「候选为空」场景，
// 验证拿不到任何 IP 时会退回直连 TLS 兜底，而不是误判成网络受限）。
var deepCandidatesFn = func(a *App, ctx context.Context, cfg *config.Config, domain string, dohTimeout time.Duration, detail *[]string) []string {
	return a.deepCandidates(ctx, cfg, domain, dohTimeout, detail)
}

// deepCandidates 收集实时微测的候选 IP（最多 4 个，按「最可能通」排序）：
// Hosts 现有记录 → 优选缓存 → DoH 解析（受 dohTimeout 限制）。
// detail 记录候选收集过程，微测失败时原样展示给用户。
func (a *App) deepCandidates(ctx context.Context, cfg *config.Config, domain string, dohTimeout time.Duration, detail *[]string) []string {
	seen := make(map[string]bool, 4)
	out := make([]string, 0, 4)
	add := func(ip string) {
		if ip == "" || len(out) >= 4 || seen[ip] || net.ParseIP(ip) == nil {
			return
		}
		seen[ip] = true
		out = append(out, ip)
	}
	// 1. Hosts 里正在生效的记录（用户点过一键加速才会写）
	if entries, err := executor.ReadHostsBlock(); err == nil {
		if ip := entries[domain]; ip != "" {
			*detail = append(*detail, "候选来源·Hosts 现有记录: "+ip)
			add(ip)
		}
	}
	// 2. 优选缓存（上次探测成功的结果）
	if m, _, err := cache.Load(); err == nil {
		if ip := m[domain]; ip != "" {
			*detail = append(*detail, "候选来源·优选缓存: "+ip)
			add(ip)
		}
	}
	// 3. DoH 现解析（拿不到新 IP 也不影响前两步）
	if len(out) < 4 && len(cfg.DoHEndpoints) > 0 {
		dctx, cancel := context.WithTimeout(ctx, dohTimeout)
		defer cancel()
		ips, err := doh.ResolveWith(dctx, domain, cfg.DoHEndpoints)
		if err != nil {
			*detail = append(*detail, "候选来源·DoH 解析失败: "+classifyNetErr(err.Error()))
		} else if got := doh.DedupIPStrings(ips); len(got) == 0 {
			*detail = append(*detail, "候选来源·DoH 解析成功但无应答记录")
		} else {
			for _, ip := range got {
				add(ip)
			}
		}
	}
	return out
}

// deepLiveCheck 立刻做一次针对主域名的真实 TCP/TLS 连通性微测。
// 任一候选探测通过即放行；候选全空时退回系统 DNS 直连 TLS 握手。
// 总耗时受 deepLiveCheckTimeout 约束（DoH 现解析最多占 dohResolveCap，
// 剩余时间全部留给真正的连通性探测）。Detail 带逐条失败原因（透明化）。
func (a *App) deepLiveCheck(cfg *config.Config, domain string) deepCheckResult {
	if domain == "" {
		return deepCheckResult{OK: true} // 没配域名就没有可拦的依据
	}
	deadline := time.Now().Add(deepLiveCheckTimeout)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	detail := make([]string, 0, 8)
	ips := deepCandidatesFn(a, ctx, cfg, domain, dohResolveCap, &detail)
	remain := time.Until(deadline)
	if remain < 300*time.Millisecond {
		remain = 300 * time.Millisecond // 保底握手时间；总耗时最多约 2.3 秒
	}
	if len(ips) == 0 {
		ok, err := directTLSCheck(domain, remain)
		if ok {
			return deepCheckResult{OK: true}
		}
		detail = append(detail, "系统 DNS 直连 "+domain+":443 失败: "+classifyNetErr(err.Error()))
		return deepCheckResult{Checked: 0, Detail: detail}
	}
	pctx, pcancel := context.WithTimeout(context.Background(), remain)
	defer pcancel()
	for _, r := range deepProbeFn(pctx, ips, domain, remain) {
		if r.OK {
			return deepCheckResult{OK: true, Checked: len(ips)}
		}
		if r.Err != "" {
			detail = append(detail, "候选 "+r.IP+": "+classifyNetErr(r.Err))
		}
	}
	return deepCheckResult{Checked: len(ips), Detail: detail}
}

// deepPrecheckLive 是深度加速的预检闸，只认「此刻的真实连通性」。
//
// 历史教训：旧实现读 lastprobe.json（上一轮探测报告）判定，用户在 VPN 下
// 失败过一次后，即使关掉 VPN、网络已恢复，6 小时内仍会被旧报告拦截。
// 现在改为实时微测：通就放行（并清掉旧失败报告），确实不通才拦截——
// 拦截时附上逐条失败原因（detail），UI 提供「仍然强制开启」逃生通道。
func (a *App) deepPrecheckLive(domain string) (ok bool, reason string, checked int, detail []string) {
	cfg := a.loadCfg()
	res := a.deepLiveCheck(cfg, domain)
	if res.OK {
		// 网络已恢复：旧的失败报告立刻作废，避免下次再拿它当依据
		if err := cache.ClearProbeReport(); err != nil {
			a.logf("清理历史探测报告失败（不影响放行）: %v", err)
		}
		return true, "", res.Checked, nil
	}
	return false, deepRestrictedMsg, res.Checked, res.Detail
}

// CheckDeepPrecondition 供前端在打开「深度加速」弹窗前调用：
// 每次都现场发起 2 秒实时微测，拦截时返回 reason + 逐条诊断明细（detail）。
func (a *App) CheckDeepPrecondition() map[string]any {
	ok, reason, checked, detail := a.deepPrecheckLive(a.primaryDomain())
	a.logf("深度加速预检（实时微测）: ok=%v 候选=%d", ok, checked)
	return map[string]any{
		"ok":      ok,
		"reason":  reason,
		"domain":  a.primaryDomain(),
		"checked": checked,
		"live":    true,
		"detail":  detail,
	}
}

// RefreshDeepPrecondition 是「网络体检·重新检测」：强制清空探测报告与
// 代理侧 IP 缓存（DoH 每次都是现查、无本地缓存），然后立刻重跑实时微测，
// 保证用户点刷新时绝不被任何陈旧状态卡死。
func (a *App) RefreshDeepPrecondition() map[string]any {
	a.invalidateAllHostIP()
	if err := cache.ClearProbeReport(); err != nil {
		a.logf("网络体检清理探测报告失败: %v", err)
	}
	a.logf("网络体检: 已清空探测报告与 IP 缓存，重新实时微测")
	return a.CheckDeepPrecondition()
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
