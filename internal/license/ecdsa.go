// ghsmart 离线授权：ECDSA P-256 验签，完全本地校验，无任何网络依赖。
//
// 激活码协议（与 LAN快传 PRO 同款设计，跨产品密钥对相互独立）：
//
//	激活码 = Base64Std( 20B 载荷 ‖ 64B P1363 签名 )，共 84B → 112 字符
//	载荷   = Magic 'LP'(2B) + 版本(1B) + 标志位(1B) + 机器码(8B)
//	       + 签发日 u32(4B) + 到期日 u32(4B)   （日期为自 1970-01-01 UTC 的天数）
//	签名   = P1363 (r‖s 各 32B)，对 20B 载荷签名
//
// 客户端只硬编码公钥；私钥仅存在于发码机的 keygen_private.pem。
package license

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

// 硬编码公钥（P-256，X||Y 各 32 字节）。与 keygen_private.pem 配对，换钥必须重新生成。
var (
	pubKeyX, _ = hex.DecodeString("2a4dcdbad461b1df6b5797b951e86e18ace6bb4375b24ebb32fded0fe9aa1b31")
	pubKeyY, _ = hex.DecodeString("83f8388b1f4026a6d6b260acb9aa667e06660a04febb99fd94b06c95d89d9662")
)

// 激活码协议常量。
const (
	licenseMagicByte1 = 'L'
	licenseMagicByte2 = 'P'
	licenseVersion    = 1
	licenseFlagPro    = 0x01
	licensePayloadLen = 20
	licenseSigLen     = 64
)

// pubKey 返回硬编码的验证公钥。
func pubKey() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(pubKeyX),
		Y:     new(big.Int).SetBytes(pubKeyY),
	}
}

// LicensePayload 是激活码载荷的解析结果。
type LicensePayload struct {
	Version byte
	Flags   byte
	Machine [8]byte
	Issued  uint32 // 自 1970-01-01 UTC 的天数
	Expires uint32 // 自 1970-01-01 UTC 的天数；0 表示永久
}

// MachineCodeHex 返回本机机器码的 16 位大写 hex（用户复制后发给发码方）。
func MachineCodeHex() (string, error) {
	m, err := machineCodeBytes()
	if err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(m[:])), nil
}

// daysSinceEpoch 把 time 截断到 UTC 天数。
func daysSinceEpoch(t time.Time) uint32 {
	return uint32(t.UTC().Unix() / 86400)
}

// DaysSinceEpoch 是 daysSinceEpoch 的导出形式（keygen 签发自检对账用）。
func DaysSinceEpoch(t time.Time) uint32 { return daysSinceEpoch(t) }

// SignLicense 用私钥为指定机器码签发激活码（keygen 使用）。
// days 为有效天数；days <= 0 表示永久（到期日写 0）。
func SignLicense(priv *ecdsa.PrivateKey, machine [8]byte, days int) (string, error) {
	now := daysSinceEpoch(time.Now())
	var expiry uint32
	if days > 0 {
		expiry = now + uint32(days)
	}
	return SignLicenseWithDates(priv, machine, now, expiry)
}

// SignLicenseWithDates 用显式日期签发（单测与 keygen 共用）。
// expires=0 表示永久。
func SignLicenseWithDates(priv *ecdsa.PrivateKey, machine [8]byte, issued, expires uint32) (string, error) {
	payload := make([]byte, licensePayloadLen)
	payload[0] = licenseMagicByte1
	payload[1] = licenseMagicByte2
	payload[2] = licenseVersion
	payload[3] = licenseFlagPro
	copy(payload[4:12], machine[:])
	binary.BigEndian.PutUint32(payload[12:16], issued)
	binary.BigEndian.PutUint32(payload[16:20], expires)

	h := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		return "", fmt.Errorf("签名失败: %w", err)
	}
	sig := make([]byte, licenseSigLen)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	return base64.StdEncoding.EncodeToString(append(payload, sig...)), nil
}

// VerifyOffline 校验激活码：格式、魔数、版本、标志位、机器码、有效期、签名全查。
// 返回 (true, nil) 表示本机可解锁 Pro。
func VerifyOffline(code string) (bool, error) {
	m, err := machineCodeBytes()
	if err != nil {
		return false, fmt.Errorf("读取机器码失败: %w", err)
	}
	payload, err := verifyWithKey(code, pubKey(), m, time.Now())
	if err != nil {
		return false, err
	}
	_ = payload
	return true, nil
}

// verifyWithKey 是核心校验逻辑，密钥/机器码/当前时间可注入（供单测使用）。
func verifyWithKey(code string, pub *ecdsa.PublicKey, machine [8]byte, now time.Time) (*LicensePayload, error) {
	raw, err := base64.StdEncoding.DecodeString(code)
	if err != nil {
		return nil, errors.New("激活码不是合法的 Base64")
	}
	if len(raw) != licensePayloadLen+licenseSigLen {
		return nil, fmt.Errorf("激活码长度不对（应为 %d 字节，实际 %d）", licensePayloadLen+licenseSigLen, len(raw))
	}
	payload, sig := raw[:licensePayloadLen], raw[licensePayloadLen:]

	if payload[0] != licenseMagicByte1 || payload[1] != licenseMagicByte2 {
		return nil, errors.New("激活码格式不对（缺少 LP 魔数）")
	}
	if payload[2] != licenseVersion {
		return nil, fmt.Errorf("不支持的激活码版本 %d", payload[2])
	}
	if payload[3]&licenseFlagPro == 0 {
		return nil, errors.New("激活码不含 Pro 权限")
	}

	var p LicensePayload
	p.Version = payload[2]
	p.Flags = payload[3]
	copy(p.Machine[:], payload[4:12])
	p.Issued = binary.BigEndian.Uint32(payload[12:16])
	p.Expires = binary.BigEndian.Uint32(payload[16:20])

	if p.Machine != machine {
		return nil, errors.New("激活码与本机机器码不匹配")
	}
	today := daysSinceEpoch(now)
	if p.Expires != 0 && today > p.Expires {
		return nil, errors.New("激活码已过期")
	}
	if p.Expires != 0 && p.Issued > p.Expires {
		return nil, errors.New("激活码日期非法（签发晚于到期）")
	}

	// P1363: r = sig[:32], s = sig[32:]
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	h := sha256.Sum256(payload)
	if !ecdsa.Verify(pub, h[:], r, s) {
		return nil, errors.New("激活码签名校验失败（疑似伪造或损坏）")
	}
	return &p, nil
}

// ParseMachineCode 把用户粘贴的机器码解析为 8 字节。
// 容忍大小写、空格、连字符；必须恰好 16 位 hex。
func ParseMachineCode(s string) ([8]byte, error) {
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '-', '\t', '\n', '\r':
			return -1 // 剔除常见分隔符
		}
		return r
	}, s)
	if len(clean) != 16 {
		return [8]byte{}, errors.New("机器码应为 16 位 hex（在客户端 Pro 弹窗中复制）")
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return [8]byte{}, errors.New("机器码不是合法的 hex")
	}
	var m [8]byte
	copy(m[:], b)
	return m, nil
}

// VerifyForMachine 用指定机器码校验激活码并返回载荷（keygen 自检用，
// 不做本机机器码比对——发码机上激活码本来就是给别的机器的）。
func VerifyForMachine(code string, machine [8]byte) (*LicensePayload, error) {
	return verifyWithKey(code, pubKey(), machine, time.Now())
}

// LoadPrivateKey 从 PEM 文件加载发码私钥（keygen 使用）。
func LoadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("私钥文件不是合法的 PEM")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}
