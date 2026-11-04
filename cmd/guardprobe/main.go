// guardprobe 是 Job Object + 守卫进程的攻击模拟靶子：
// 它创建作业、派生守卫，然后自己进入空转，等着被外部强杀。
// 自动化脚本杀掉它之后，检查守卫日志是否出现 parent-gone。
package main

import (
	"fmt"
	"os"
	"time"

	"ghsmart/internal/jobobj"
	"ghsmart/internal/proxyguard"
)

func main() {
	// 守卫进程分支：必须最先判断，否则会递归派生守卫
	if len(os.Args) > 1 && os.Args[1] == proxyguard.GuardArg {
		os.Exit(proxyguard.Run(os.Args[2:]))
	}

	job, err := jobobj.New()
	if err != nil {
		fmt.Println("JOB_ERR", err)
		os.Exit(1)
	}
	g, err := proxyguard.Spawn(job, "127.0.0.1:18080")
	if err != nil {
		// 加入作业失败不算致命，但要把原因打出来
		fmt.Println("SPAWN_WARN", err)
	}
	if g == nil {
		fmt.Println("SPAWN_FAIL")
		os.Exit(1)
	}
	fmt.Printf("PROBE_PID=%d GUARD_PID=%d\n", os.Getpid(), g.Pid())
	os.Stdout.Sync()
	// 保持存活，等外部强杀（真实模拟任务管理器结束进程）
	for {
		time.Sleep(time.Hour)
	}
}
