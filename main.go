// ghsmart GUI 入口：Wails v2 窗口 + 系统托盘。
// 双击运行即弹 UAC 提权（见 build/windows/wails.exe.manifest），
// 关闭窗口隐藏到托盘，托盘菜单可显示主界面 / 一键加速 / 恢复 Hosts / 退出。
package main

import (
	"context"
	"embed"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/energye/systray"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"ghsmart/internal/jobobj"
	"ghsmart/internal/proxyguard"
	"ghsmart/internal/selfcheck"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/windows/icon.ico
var trayIcon []byte

func main() {
	// 启动自校验（仅发布构建带 -tags selfcheck 时编入）：
	// 校验自身 exe 是否被改过。必须在任何业务逻辑和窗口之前——校验失败时
	// 只弹一次系统提示框然后退出，绝不允许出现主界面。
	// 开发构建不带该 tag，Verify 是空实现，零开销。
	if err := selfcheck.Verify(); err != nil {
		selfcheck.Fail(err.Error())
	}

	// 守卫进程分支：必须在任何 GUI/托盘初始化之前处理，
	// 否则守卫会再开一个窗口、再派生一个守卫，无限递归。
	if len(os.Args) > 1 && os.Args[1] == proxyguard.GuardArg {
		os.Exit(proxyguard.Run(os.Args[2:]))
	}

	app := NewApp()
	// --silent：由「开机自启」（计划任务或 Run 键）带起时使用。
	// 效果 = 窗口不弹出、直接进托盘，但状态恢复逻辑与手动打开完全一致。
	app.silent = hasArg(os.Args[1:], "--silent")

	// 作业对象：主进程一死，作业内所有辅助进程被操作系统立刻终止，
	// 不会留下占着端口的孤儿。守卫进程刻意不加入作业（它要活到最后收尾）。
	// 这里不显式 Close：进程退出时系统统一回收句柄，避免与守卫的竞态。
	if job, err := jobobj.New(); err == nil {
		app.job = job
	} else {
		app.logf("作业对象创建失败（不影响代理与还原）: %v", err)
	}

	// 托盘在独立 goroutine 运行
	go systray.Run(app.onTrayReady, func() {})

	err := wails.Run(&options.App{
		Title:     "ghsmart - GitHub 智能加速",
		Width:     760,
		Height:    720,
		MinWidth:  620,
		MinHeight: 600,
		// 静默自启时不显示主窗口，直接常驻托盘。
		// 用户点托盘「显示主界面」随时能看见它——不是偷偷在后台跑。
		StartHidden: app.silent,
		// 关键：WebView2 底色必须与页面 --bg 一致（#0f172a）。
		// 缺省是白色，界面批量重绘（表格插入/弹窗显隐）时会短暂露出白底，
		// 表现为用户看到的「界面一闪一下」。
		BackgroundColour: &options.RGBA{R: 0x0f, G: 0x17, B: 0x2a, A: 255},
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		OnStartup: func(ctx context.Context) {
			app.startup(ctx)
			scheduleSelfQuit(app)
		},
		// DOM 就绪时前端的事件监听器已全部绑定完毕，此时重发一次授权状态，
		// 保证「启动即显示 Pro/Free」，杜绝 OnStartup 阶段 emitState
		// 早于 EventsOn 绑定而被吞掉的时序竞态。
		OnDomReady: func(ctx context.Context) {
			app.emitState()
		},
		// 点 X 不退出：隐藏到托盘；托盘「退出」才真正关闭。
		// 但退出流程已启动（quitting=true）时必须放行，否则 runtime.Quit
		// 打不开关窗这一关，就变成「点了退出却退不掉」。
		OnBeforeClose: func(ctx context.Context) bool {
			if app.allowCloseOnX() {
				return false // 允许真正关闭
			}
			wruntime.WindowHide(ctx)
			return true // 阻止默认关闭行为
		},
		// 进程退出前的最后一道保险：还原系统代理。
		// 没这一步，用户关掉软件就可能上不了网（代理指向已经死掉的本地端口）。
		OnShutdown: func(ctx context.Context) {
			app.Shutdown()
		},
		Bind: []interface{}{app},
		Windows: &windows.Options{
			Theme:               windows.Dark,
			WindowIsTranslucent: false,
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
	// 任何退出路径（托盘退出 / 界面关闭 / 系统注销）走到这里都必须撤掉托盘图标，
	// 否则 Windows 通知区域会残留一个点不动的幽灵图标。
	systray.Quit()
}

// scheduleSelfQuit 是自动化验收钩子：环境变量 GHSMART_QUIT_SELFTEST=<毫秒> 时，
// 启动后自动走一遍「托盘退出」流程（QuitApp），用来实证「点了退出进程真的会退」。
//
// 托盘菜单没法脚本点击，但退出链路（Shutdown → runtime.Quit → watchdog 强退）
// 是同一份代码，所以这个钩子测的就是真实退出路径。普通用户不设该变量，行为不变。
func scheduleSelfQuit(a *App) {
	v := os.Getenv("GHSMART_QUIT_SELFTEST")
	if v == "" {
		return
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return
	}
	go func() {
		time.Sleep(time.Duration(n) * time.Millisecond)
		a.QuitApp()
	}()
}

// hasArg 判断命令行参数里是否有某个开关（形如 --silent）。
func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// onTrayReady 构建托盘图标与右键菜单。
func (a *App) onTrayReady() {
	systray.SetIcon(trayIcon)
	systray.SetTooltip("ghsmart - GitHub 智能加速")

	mShow := systray.AddMenuItem("显示主界面", "显示 ghsmart 主窗口")
	mApply := systray.AddMenuItem("一键加速", "探测并写入最优 Hosts")
	mRestore := systray.AddMenuItem("恢复 Hosts", "移除 ghsmart 区块并还原")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("退出", "彻底关闭 ghsmart")

	mShow.Click(func() {
		wruntime.WindowShow(a.ctx)
		wruntime.WindowUnminimise(a.ctx)
	})
	mApply.Click(func() {
		_ = a.StartApply()
	})
	mRestore.Click(func() {
		_ = a.RemoveHosts()
	})
	mQuit.Click(func() {
		// 只交给 QuitApp：它内部会还原代理、撤托盘、关进程并带 watchdog 兜底。
		// 绝不在这里先 systray.Quit()——那会让「退出没退掉」变成死局。
		a.QuitApp()
	})
}
