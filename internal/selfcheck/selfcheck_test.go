//go:build selfcheck

package selfcheck

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// stamp 构造一个「已正确回填」的映像，算法必须与 tools/patch_selfstamp.py 完全一致。
func stamp(body []byte) []byte {
	buf := make([]byte, 0, len(body)+stampLen)
	buf = append(buf, body...)
	buf = append(buf, stampMagic[:]...)
	buf = append(buf, make([]byte, hashLen)...)

	h := sha256.New()
	h.Write(buf[:len(buf)-hashLen])
	h.Write(make([]byte, hashLen))
	copy(buf[len(buf)-hashLen:], h.Sum(nil))
	return buf
}

func TestVerifyBytesOK(t *testing.T) {
	data := stamp(bytes.Repeat([]byte{0xAA}, 1024))
	if err := verifyBytes(data); err != nil {
		t.Fatalf("回填后应通过: %v", err)
	}
}

func TestVerifyBytesEmptyBodyStillOK(t *testing.T) {
	// 只有戳、没有正文的极端情况也必须自洽（证明哈希域置零逻辑不依赖正文）
	if err := verifyBytes(stamp(nil)); err != nil {
		t.Fatalf("空正文应通过: %v", err)
	}
}

func TestVerifyBytesNoStamp(t *testing.T) {
	cases := map[string][]byte{
		"过短":   bytes.Repeat([]byte{1}, 10),
		"刚好64": bytes.Repeat([]byte{1}, 64),
	}
	for name, data := range cases {
		if err := verifyBytes(data); err != ErrNotStamped {
			t.Fatalf("%s 应返回 ErrNotStamped，得到 %v", name, err)
		}
	}
}

func TestVerifyBytesBadMagic(t *testing.T) {
	data := stamp(bytes.Repeat([]byte{0x0F}, 256))
	data[len(data)-stampLen] = 'X'
	if err := verifyBytes(data); err != ErrNotStamped {
		t.Fatalf("魔数被改应判定为无戳，得到 %v", err)
	}
}

// 核心判据：改 1 个字节必须被拦住（验收矩阵第 1 条）
func TestVerifyBytesOneByteFlip(t *testing.T) {
	base := stamp(bytes.Repeat([]byte{0x11}, 512))
	for _, pos := range []int{0, 100, 511} {
		data := append([]byte{}, base...)
		data[pos] ^= 0x01
		var te *ErrTampered
		if err := verifyBytes(data); !errors.As(err, &te) {
			t.Fatalf("位置 %d 改 1 字节未被拦截，得到 %v", pos, err)
		}
	}
}

func TestVerifyBytesHashFieldTampered(t *testing.T) {
	data := stamp(bytes.Repeat([]byte{0x33}, 512))
	data[len(data)-1] ^= 0xFF
	var te *ErrTampered
	if err := verifyBytes(data); !errors.As(err, &te) {
		t.Fatalf("哈希域被改应拦截，得到 %v", err)
	}
}

func TestVerifyBytesTruncated(t *testing.T) {
	data := stamp(bytes.Repeat([]byte{0x22}, 512))
	if err := verifyBytes(data[:len(data)-1]); err == nil {
		t.Fatal("截断 1 字节应失败")
	}
}

func TestVerifyBytesAppended(t *testing.T) {
	data := stamp(bytes.Repeat([]byte{0x22}, 512))
	if err := verifyBytes(append(data, 0x00)); err == nil {
		t.Fatal("尾部追加字节应失败")
	}
}

func TestVerifyFileRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fake.exe")
	if err := os.WriteFile(p, stamp(bytes.Repeat([]byte{0x44}, 4096)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyFile(p); err != nil {
		t.Fatalf("落盘文件应通过: %v", err)
	}
}

// 幂等性：同一份数据反复 stamp 结果必须稳定（否则回填脚本二次运行会算坏）
func TestStampIsIdempotent(t *testing.T) {
	body := bytes.Repeat([]byte{0x55}, 300)
	once := stamp(body)
	again := stamp(body)
	if !bytes.Equal(once, again) {
		t.Fatal("同一正文两次 stamp 结果不一致")
	}
	// 对已回填的映像重新走一遍「置零后重算」，结果必须等于原值
	h := sha256.New()
	h.Write(once[:len(once)-hashLen])
	h.Write(make([]byte, hashLen))
	if !bytes.Equal(h.Sum(nil), once[len(once)-hashLen:]) {
		t.Fatal("置零重算与原回填不一致")
	}
}
