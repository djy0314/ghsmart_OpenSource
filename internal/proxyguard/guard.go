// Package proxyguard 提供「主进程死了也要把系统代理还原」的守卫进程。
//
// 为什么需要它：Windows 的作业对象只能杀进程，不能替死掉的进程改注册表。
// 想让「任务管理器强杀 ghsmart.exe」之后系统代理仍然被还原，就必须有一个
// 独立进程活着做这件事——这跟看门狗定时器不是一类东西：
//
//   - 看门狗：进程内 ticker 轮询，进程死了它也死，纯属自欺欺人；
//   - 守卫进程：独立进程，阻塞在内核句柄上等父进程退出（零 CPU 轮询），
//     父进程一死立刻还原注册表后自行退出。
//
// 守卫进程刻意「不」放进作业对象，并且持有作业句柄的继承副本，
// 这样主进程被强杀时作业不会提前关闭，守卫不会被连带杀死。
package proxyguard

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"ghsmart/internal/jobobj"
	"ghsmart/internal/sysproxy"
)

// GuardArg 是守卫进程的启动标记：ghsmart.exe --guard <pid> <target> <jobHandle>。
const GuardArg = "--guard"

// Guard 是主进程侧的守卫句柄。
type Guard struct {
	cmd *exec.Cmd
}

// Spawn 派生守卫进程并把它加入作业。
//
// target 传给守卫，用于父进程死后按同一个代理地址精准还原。
// job 可为 nil（测试或无法创建作业时），此时只是没有「防孤儿」的作业保护。
func Spawn(job *jobobj.Job, target string) (*Guard, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("取自身路径失败: %w", err)
	}
	if job != nil {
		// 句柄必须可继承，否则守卫拿不到作业句柄 → 主进程一死作业就关 → 守卫被杀
		if err := job.MakeInheritable(); err != nil {
			return nil, err
		}
	}
	handleVal := uint64(0)
	if job != nil {
		handleVal = uint64(job.Handle())
	}
	cmd := exec.Command(exe,
		GuardArg,
		strconv.Itoa(os.Getpid()),
		target,
		strconv.FormatUint(handleVal, 10),
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
		// 子进程继承作业句柄（Go 会把这些句柄带进 CreateProcess 的继承列表）
		AdditionalInheritedHandles: func() []syscall.Handle {
			if job == nil {
				return nil
			}
			return []syscall.Handle{syscall.Handle(job.Handle())}
		}(),
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动守卫进程失败: %w", err)
	}
	// 作业赋值失败不算致命：退化成「没有防孤儿保护」，但还原能力仍在
	if job != nil {
		if err := job.Assign(cmd.Process.Pid); err != nil {
			return &Guard{cmd: cmd}, fmt.Errorf("守卫进程未加入作业（还原能力不受影响）: %w", err)
		}
	}
	return &Guard{cmd: cmd}, nil
}

// Pid 返回守卫进程号（诊断用）。
func (g *Guard) Pid() int {
	if g == nil || g.cmd == nil || g.cmd.Process == nil {
		return 0
	}
	return g.cmd.Process.Pid
}

// Release 解除对守卫进程的引用。**不杀它**：它要活到主进程退出之后。
func (g *Guard) Release() {
	if g == nil || g.cmd == nil || g.cmd.Process == nil {
		return
	}
	// Windows 上不 Wait 会留下僵尸句柄，但守卫的生命周期比主进程长，
	// 这里只释放 Go 侧句柄，不影响子进程继续运行。
	_ = g.cmd.Process.Release()
}

// ---------- 守卫进程侧 ----------

// Run 是守卫进程的入口，返回进程退出码。
// args 形如 [pid, target, jobHandle]。
func Run(args []string) int {
	if len(args) < 3 {
		return 2
	}
	pid, err := strconv.Atoi(args[0])
	if err != nil || pid <= 0 {
		return 2
	}
	target := args[1]
	if target == "" {
		target = sysproxy.DefaultTarget
	}
	// 继承来的作业句柄只持有、不关闭：这是作业不被提前关闭的保险。
	// 进程退出时系统会统一回收句柄，不需要显式 Close。
	var keepAlive windows.Handle
	if h, err := strconv.ParseUint(args[2], 10, 64); err == nil && h != 0 {
		keepAlive = windows.Handle(h)
	}
	_ = keepAlive

	waitParentExit(uint32(pid))
	markParentGone(pid)
	// 测试/自证钩子：GHSMART_GUARD_DRYRUN=1 时只记录日志，不碰真实注册表
	if os.Getenv("GHSMART_GUARD_DRYRUN") != "1" {
		restoreWithRetry(target, 3)
	}
	return 0
}

// markParentGone 是自证钩子：把「父进程已退出」写进日志文件，
// 用于自动化验证「强杀主进程后守卫确实醒过来了」。
func markParentGone(pid int) {
	p := os.Getenv("GHSMART_GUARD_LOG")
	if p == "" {
		return
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "parent-gone pid=%d at=%s\n", pid, time.Now().Format(time.RFC3339Nano))
}

// waitParentExit 阻塞在内核句柄上等目标进程退出（零 CPU 占用，不用定时器）。
func waitParentExit(pid uint32) {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		// 打不开说明进程已经没了（或权限不足）——直接进入还原分支更安全
		time.Sleep(200 * time.Millisecond)
		return
	}
	defer windows.CloseHandle(h)
	_, _ = windows.WaitForSingleObject(h, windows.INFINITE)
}

// restoreWithRetry 还原系统代理；失败重试（注册表偶尔被安全软件短暂锁住）。
func restoreWithRetry(target string, attempts int) {
	for i := 0; i < attempts; i++ {
		if _, err := sysproxy.Restore(target); err == nil {
			return
		}
		time.Sleep(time.Duration(150*(i+1)) * time.Millisecond)
	}
}
