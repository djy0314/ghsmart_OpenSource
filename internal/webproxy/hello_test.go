package webproxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// captureConn 只收不发，用来抓一份真实的 ClientHello 字节。
type captureConn struct{ bytes.Buffer }

func (c *captureConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *captureConn) Close() error             { return nil }
func (c *captureConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5555}
}
func (c *captureConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

// realClientHello 用 crypto/tls 真实生成一份包含指定 SNI 的 ClientHello 记录。
func realClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	cc := &captureConn{}
	conn := tls.Client(cc, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	_ = conn.Handshake() // 对端无响应必然失败，但 ClientHello 已写出
	raw := cc.Bytes()
	total, ok := recordLen(raw)
	if !ok {
		t.Fatalf("抓到的不是 TLS 握手记录，前 16 字节: % x", raw[:min(16, len(raw))])
	}
	return raw[:total]
}

func TestSNISpanFindsHost(t *testing.T) {
	hello := realClientHello(t, "github.com")
	if !IsClientHello(hello) {
		t.Fatal("IsClientHello 判定失败")
	}
	start, end, ok := SNISpan(hello)
	if !ok {
		t.Fatal("SNISpan 未找到 SNI")
	}
	if got := string(hello[start:end]); got != "github.com" {
		t.Fatalf("SNI = %q, 期望 github.com", got)
	}
	if got := SNIHost(hello); got != "github.com" {
		t.Fatalf("SNIHost = %q", got)
	}
}

func TestSNISpanRejectsGarbage(t *testing.T) {
	if _, _, ok := SNISpan([]byte("GET / HTTP/1.1\r\n\r\n")); ok {
		t.Fatal("明文 HTTP 不应被解析出 SNI")
	}
	if IsClientHello([]byte{0x16, 0x03, 0x01, 0x00, 0x10, 0x01}) {
		t.Fatal("长度不足的记录不应判定为完整 ClientHello")
	}
}

// 核心断言：智能分片后，任何单个分片都不包含完整域名。
func TestSmartSplitHidesWholeDomain(t *testing.T) {
	hello := realClientHello(t, "github.com")
	sp := Splitter{Window: 0}
	sizes, err := sp.WriteWithSizes(io.Discard, hello)
	if err != nil {
		t.Fatalf("分片写入失败: %v", err)
	}
	if len(sizes) < 3 {
		t.Fatalf("智能分片应至少 3 段（首字节 + SNI 中点 + 尾巴），实际 %d 段: %v", len(sizes), sizes)
	}
	if sizes[0] != 1 {
		t.Fatalf("首段应为 1 字节，实际 %d", sizes[0])
	}
	total := 0
	for _, n := range sizes {
		total += n
	}
	if total != len(hello) {
		t.Fatalf("分片总长 %d != ClientHello 长度 %d", total, len(hello))
	}

	// 逐段检查：拼不回完整域名
	from := 0
	for i, n := range sizes {
		frag := hello[from : from+n]
		if bytes.Contains(frag, []byte("github.com")) {
			t.Fatalf("第 %d 段（%d 字节）仍包含完整域名，分片无效", i, n)
		}
		from += n
	}
}

func TestWindowSplit(t *testing.T) {
	hello := realClientHello(t, "raw.githubusercontent.com")
	sp := Splitter{Window: 64}
	sizes, err := sp.WriteWithSizes(io.Discard, hello)
	if err != nil {
		t.Fatalf("分片写入失败: %v", err)
	}
	for i, n := range sizes[:len(sizes)-1] {
		if n != 64 {
			t.Fatalf("第 %d 段 = %d 字节，期望 64", i, n)
		}
	}
	if last := sizes[len(sizes)-1]; last <= 0 || last > 64 {
		t.Fatalf("末段长度异常: %d", last)
	}
	total := 0
	for _, n := range sizes {
		total += n
	}
	if total != len(hello) {
		t.Fatalf("分片总长 %d != %d", total, len(hello))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
