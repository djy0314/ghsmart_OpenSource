//go:build selfcheck

// Package selfcheck 提供启动自校验：**校验域置零哈希**。
//
// 依据《Windows 工具安全加固规范 v1》第三节：禁止「全文件哈希常量」（改常量→哈希变→
// 死循环）。正确做法是把预期哈希本身排除在计算之外，回填哈希不改变计算结果。
//
// 戳布局（追加在 exe 文件末尾，共 64 字节）：
//
//	[0:32]  魔数 stampMagic
//	[32:64] 预期哈希 expected
//
// 校验：读全文件 → 把 expected 的 32 字节置零 → SHA256 → 与 expected 比对。
//
// 为什么放在文件末尾而不是在文件里搜魔数：garble -literals 会把字符串常量加密，
// 构建产物里已经搜不到魔数明文，回填脚本无法按魔数定位。末尾定长偏移对混淆免疫。
package selfcheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	stampLen   = 64
	magicOff   = 0
	hashOff    = 32
	hashLen    = 32
)

// stampMagic 32 字节魔数。garble 会把它加密，但运行时值正确，比对不受影响。
var stampMagic = [32]byte{
	'G', 'H', 'S', 'M', 'A', 'R', 'T', '-', 'S', 'E', 'L', 'F', 'H', 'A', 'S', 'H',
	'-', 'S', 'T', 'A', 'M', 'P', '-', 'v', '1', '-', '0', '0', '0', '0', '0', '0',
}

// ErrNotStamped 表示文件末尾没有校验戳（未回填的构建产物）。
var ErrNotStamped = fmt.Errorf("文件校验信息缺失")

// ErrTampered 表示哈希不匹配（文件被修改过）。
type ErrTampered struct {
	Want string
	Got  string
}

func (e *ErrTampered) Error() string {
	return fmt.Sprintf("文件校验失败（预期 %s… 实际 %s…）", e.Want[:16], e.Got[:16])
}

// Verify 校验当前可执行文件。
func Verify() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("无法定位自身文件: %w", err)
	}
	return verifyFile(exe)
}

// verifyFile 是校验核心，便于测试直接对任意文件调用。
func verifyFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取自身文件失败: %w", err)
	}
	return verifyBytes(data)
}

// verifyBytes 对内存映像做校验。
func verifyBytes(data []byte) error {
	if len(data) < stampLen {
		return ErrNotStamped
	}
	tail := data[len(data)-stampLen:]

	if !bytes.Equal(tail[magicOff:magicOff+32], stampMagic[:]) {
		return ErrNotStamped
	}

	want := make([]byte, hashLen)
	copy(want, tail[hashOff:hashOff+hashLen])

	// 校验域置零：把 expected 的 32 字节当成全零参与哈希，再与 expected 比对。
	// 这样「回填哈希」这个动作本身不改变计算结果，从根上避免全文件哈希常量的死循环。
	// 写法上分两段 Write 而不是复制整个文件，13MB 的 exe 省掉一次大拷贝。
	h := sha256.New()
	h.Write(data[:len(data)-hashLen])
	h.Write(make([]byte, hashLen))
	got := h.Sum(nil)

	if !bytes.Equal(want, got) {
		return &ErrTampered{
			Want: hex.EncodeToString(want),
			Got:  hex.EncodeToString(got),
		}
	}
	return nil
}

// Fail 用系统模态框告知用户并立即退出。
// 必须在 wails.Run 之前调用——校验失败时不允许出现主窗口。
func Fail(msg string) {
	text := "程序文件已损坏或被修改，为保护您的账号与环境安全，已停止运行。\n\n" +
		"请从官方渠道重新下载完整安装包。\n\n" +
		"（技术信息：" + msg + "）"
	msgBox("ghsmart 文件校验失败", text)
	os.Exit(3)
}

// msgBox 直接调 user32!MessageBoxW，不依赖任何 GUI 框架。
func msgBox(title, text string) {
	user32 := syscall.NewLazyDLL("user32.dll")
	proc := user32.NewProc("MessageBoxW")

	const (
		mbOK              = 0x00000000
		mbIconError       = 0x00000010
		mbSetForeground   = 0x00010000
		mbTopmost         = 0x00040000
	)
	titlePtr, _ := syscall.UTF16PtrFromString(title)
	textPtr, _ := syscall.UTF16PtrFromString(text)
	proc.Call(0,
		uintptr(unsafe.Pointer(textPtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		uintptr(mbOK|mbIconError|mbSetForeground|mbTopmost))
}

// Layout 把戳布局暴露给测试与回填工具自证（避免两边算法漂移）。
func Layout() (magic int, hashBytes int) { return len(stampMagic), hashLen }
