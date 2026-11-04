package jobobj

import (
	"os/exec"
	"testing"
	"time"
)

// TestKillOnJobClose 验证 JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE 真的生效：
// 作业句柄最后一份关闭时，作业内的子进程必须被操作系统立刻终止，
// 不需要任何人去 Kill —— 这正是「主进程被强杀也不留孤儿进程」的底层保证。
func TestKillOnJobClose(t *testing.T) {
	job, err := New()
	if err != nil {
		t.Fatalf("创建作业失败: %v", err)
	}

	cmd := exec.Command("cmd", "/c", "ping", "-n", "60", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动子进程失败: %v", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	if err := job.Assign(cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		t.Skipf("当前环境无法把进程加入作业（可能已在非嵌套作业中）: %v", err)
	}

	// 子进程应该还活着
	select {
	case <-exited:
		t.Fatal("加入作业后子进程不应自己退出")
	case <-time.After(150 * time.Millisecond):
	}

	// 关掉作业最后一份句柄 → 子进程应被系统杀死
	if err := job.Close(); err != nil {
		t.Fatalf("关闭作业失败: %v", err)
	}

	select {
	case <-exited:
		// 正常：被系统终止，Wait 返回 ExitError
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("关闭作业后子进程仍存活，KILL_ON_JOB_CLOSE 未生效")
	}
}
