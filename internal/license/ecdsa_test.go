// ecdsa_test.go 生成临时测试密钥做全流程攻击模拟，不依赖硬编码公钥。
package license

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

// newTestKey 生成测试用 P-256 密钥对。
func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	return k
}

// signTestCode 用指定密钥按协议格式签出一个激活码（测试辅助）。
func signTestCode(t *testing.T, priv *ecdsa.PrivateKey, machine [8]byte, issued, expires uint32) string {
	t.Helper()
	code, err := SignLicenseWithDates(priv, machine, issued, expires)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	return code
}

// TestOfflineRoundTrip：真实密钥签发 → 本机校验通过。
func TestOfflineRoundTrip(t *testing.T) {
	priv := newTestKey(t)
	var m [8]byte
	copy(m[:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	code := signTestCode(t, priv, m, 0, 0)

	if len(code) != 112 {
		t.Fatalf("激活码应为 112 字符，实际 %d: %s", len(code), code)
	}
	if _, err := verifyWithKey(code, &priv.PublicKey, m, time.Now()); err != nil {
		t.Fatalf("合法激活码应通过: %v", err)
	}
}

// TestOfflineWrongMachine：机器码不匹配必须拒绝。
func TestOfflineWrongMachine(t *testing.T) {
	priv := newTestKey(t)
	var m [8]byte
	code := signTestCode(t, priv, m, 0, 0)

	var other [8]byte
	other[0] = 0xFF
	if _, err := verifyWithKey(code, &priv.PublicKey, other, time.Now()); err == nil {
		t.Fatal("机器码不匹配应拒绝")
	}
}

// TestOfflineExpired：过期激活码必须拒绝；永久码（expiry=0）必须放行。
func TestOfflineExpired(t *testing.T) {
	priv := newTestKey(t)
	var m [8]byte
	now := uint32(time.Now().UTC().Unix() / 86400)

	expired := signTestCode(t, priv, m, now-100, now-1)
	if _, err := verifyWithKey(expired, &priv.PublicKey, m, time.Now()); err == nil {
		t.Fatal("过期激活码应拒绝")
	}

	forever := signTestCode(t, priv, m, now, 0)
	if _, err := verifyWithKey(forever, &priv.PublicKey, m, time.Now()); err != nil {
		t.Fatalf("永久激活码应放行: %v", err)
	}
}

// TestOfflineTampered：载荷翻转 1 字节必须被验签拦下。
func TestOfflineTampered(t *testing.T) {
	priv := newTestKey(t)
	var m [8]byte
	code := signTestCode(t, priv, m, 0, 0)

	raw, _ := base64.StdEncoding.DecodeString(code)
	raw[10] ^= 0x01 // 篡改载荷中间字节
	tampered := base64.StdEncoding.EncodeToString(raw)
	if _, err := verifyWithKey(tampered, &priv.PublicKey, m, time.Now()); err == nil {
		t.Fatal("篡改后的激活码必须被验签拒绝")
	}
}

// TestOfflineForgedSignature：换掉签名必须拒绝。
func TestOfflineForgedSignature(t *testing.T) {
	priv := newTestKey(t)
	var m [8]byte
	code := signTestCode(t, priv, m, 0, 0)

	raw, _ := base64.StdEncoding.DecodeString(code)
	for i := 20; i < 84; i++ {
		raw[i] ^= 0xFF // 签名区全部翻转
	}
	forged := base64.StdEncoding.EncodeToString(raw)
	if _, err := verifyWithKey(forged, &priv.PublicKey, m, time.Now()); err == nil {
		t.Fatal("伪造签名必须被拒绝")
	}
}

// TestOfflineBadFormat：非法 Base64 与错误长度必须拒绝。
func TestOfflineBadFormat(t *testing.T) {
	priv := newTestKey(t)
	var m [8]byte

	if _, err := verifyWithKey("不是base64!!", &priv.PublicKey, m, time.Now()); err == nil {
		t.Fatal("非法 Base64 应拒绝")
	}
	short := base64.StdEncoding.EncodeToString(make([]byte, 40))
	if _, err := verifyWithKey(short, &priv.PublicKey, m, time.Now()); err == nil {
		t.Fatal("长度不足应拒绝")
	}
}

// TestMachineCodeStable：本机机器码两次读取必须一致且为 16 位 hex。
func TestMachineCodeStable(t *testing.T) {
	a, err := MachineCodeHex()
	if err != nil {
		t.Fatalf("读取机器码失败: %v", err)
	}
	b, err := MachineCodeHex()
	if err != nil {
		t.Fatalf("读取机器码失败: %v", err)
	}
	if a != b || len(a) != 16 {
		t.Fatalf("机器码不稳定或长度不对: %q vs %q", a, b)
	}
}
