// Package jobobj 封装 Windows 作业对象（Job Object）。
//
// 用途只有一个：保证 ghsmart 派生的辅助进程不会变成孤儿。
// 作业设置 JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE —— 作业最后一个句柄关闭时，
// 作业内的进程会被操作系统立刻终止。主进程把自己的辅助进程 assign 进来，
// 于是「主进程被任务管理器强杀」时，这些进程绝不会残留占端口。
//
// 注意：KILL_ON_JOB_CLOSE 不能用来「还原注册表代理」——作业关闭只能杀进程，
// 不能执行任何用户态代码。还原代理由 proxyguard 的守卫进程负责（它刻意
// 不放进作业里，并且持有作业句柄让作业不被提前关闭）。
package jobobj

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	jobObjectExtendedLimitInformation = 9
	jobObjectLimitKillOnJobClose      = 0x2000
)

// basicLimitInformation 对应 JOBOBJECT_BASIC_LIMIT_INFORMATION。
type basicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

// ioCounters 对应 IO_COUNTERS。
type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

// extendedLimitInformation 对应 JOBOBJECT_EXTENDED_LIMIT_INFORMATION。
type extendedLimitInformation struct {
	BasicLimitInformation basicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

// Job 是一个作业对象句柄。
type Job struct {
	handle windows.Handle
}

// New 创建一个「最后句柄关闭即杀光作业内进程」的作业对象。
func New() (*Job, error) {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("创建作业对象失败: %w", err)
	}
	var info extendedLimitInformation
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
	if _, err := windows.SetInformationJobObject(
		h,
		jobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("设置作业对象限制失败: %w", err)
	}
	return &Job{handle: h}, nil
}

// Handle 返回原始句柄（交给子进程继承用）。
func (j *Job) Handle() windows.Handle {
	if j == nil {
		return 0
	}
	return j.handle
}

// MakeInheritable 让作业句柄可被子进程继承。
//
// 关键：守卫进程必须继承并持有这个句柄，否则主进程一死句柄全关，
// KILL_ON_JOB_CLOSE 会立刻触发——那守卫进程就跟着一起死了，没人收尾。
func (j *Job) MakeInheritable() error {
	if j == nil {
		return nil
	}
	if err := windows.SetHandleInformation(
		j.handle, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT,
	); err != nil {
		return fmt.Errorf("设置作业句柄可继承失败: %w", err)
	}
	return nil
}

// Assign 把进程加入作业。
func (j *Job) Assign(pid int) error {
	if j == nil {
		return nil
	}
	ph, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("打开进程 %d 失败: %w", pid, err)
	}
	defer windows.CloseHandle(ph)
	if err := windows.AssignProcessToJobObject(j.handle, ph); err != nil {
		return fmt.Errorf("将进程 %d 加入作业失败: %w", pid, err)
	}
	return nil
}

// Close 关闭作业句柄。作业内若还有进程且已无可继承句柄，它们会立刻被终止。
func (j *Job) Close() error {
	if j == nil || j.handle == 0 {
		return nil
	}
	err := windows.CloseHandle(j.handle)
	j.handle = 0
	return err
}
