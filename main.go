// ghsmart GUI 入口：Wails v2 窗口 + 系统托盘。
// 双击运行即弹 UAC 提权（见 build/windows/wails.exe.manifest），
// 关闭窗口隐藏到托盘，托盘菜单可显示主界面 / 一键加速 / 恢复 Hosts / 退出。
package main

import (
	"context"
	"embed"
	"fmt"
	"os"

	"github.com/energye/systray"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/windows/icon.ico
var trayIcon []byte

func main() {
	app := NewApp()

	// 托盘在独立 goroutine 运行
	go systray.Run(app.onTrayReady, func() {})

	err := wails.Run(&options.App{
		Title:     "ghsmart - GitHub 智能加速",
		Width:     760,
		Height:    720,
		MinWidth:  620,
		MinHeight: 600,
		// 关键：WebView2 底色必须与页面 --bg 一致（#0f172a）。
		// 缺省是白色，界面批量重绘（表格插入/弹窗显隐）时会短暂露出白底，
		// 表现为用户看到的「界面一闪一下」。
		BackgroundColour: &options.RGBA{R: 0x0f, G: 0x17, B: 0x2a, A: 255},
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		OnStartup: app.startup,
		// DOM 就绪时前端的事件监听器已全部绑定完毕，此时重发一次授权状态，
		// 保证「启动即显示 Pro/Free」，杜绝 OnStartup 阶段 emitState
		// 早于 EventsOn 绑定而被吞掉的时序竞态。
		OnDomReady: func(ctx context.Context) {
			app.emitState()
		},
		// 点 X 不退出：隐藏到托盘；托盘「退出」才真正关闭
		OnBeforeClose: func(ctx context.Context) bool {
			if app.quitting.Load() {
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
		systray.Quit()
		a.QuitApp()
	})
}
