// selfcheckprobe 是自校验的端到端验证靶子（不参与正式构建）。
//
// 它调用与正式程序完全相同的 selfcheck.Verify()，但用控制台输出代替 MessageBox，
// 这样攻击模拟（改 1 字节 / 截断 / 无戳）可以在无 GUI、无 UAC 的环境里自动化判定。
//
// 用法：
//   go build -tags selfcheck -o probe.exe ./cmd/selfcheckprobe
//   probe.exe                      # 未回填 -> VERIFY FAIL，退出码 3
//   py tools/patch_selfstamp.py probe.exe
//   probe.exe                      # 回填后 -> VERIFY OK，退出码 0
package main

import (
	"fmt"
	"os"

	"ghsmart/internal/selfcheck"
)

func main() {
	if err := selfcheck.Verify(); err != nil {
		fmt.Println("VERIFY FAIL:", err)
		os.Exit(3)
	}
	fmt.Println("VERIFY OK")
}
