//go:build !windows

// 非 Windows 平台的机器码：无注册表可用，退化为主机名 + 当前用户名的哈希。
// ghsmart 当前只发布 Windows 版，此实现仅保证可编译。

package license

import (
	"crypto/sha256"
	"os"
	"os/user"
)

// machineRawID 返回参与机器码计算的原始唯一标识。
func machineRawID() (string, error) {
	host, err := os.Hostname()
	if err != nil {
		return "", err
	}
	id := host
	if u, err := user.Current(); err == nil {
		id += "|" + u.Username
	}
	return id, nil
}

// machineCodeBytes 返回 8 字节机器码。
func machineCodeBytes() ([8]byte, error) {
	var out [8]byte
	raw, err := machineRawID()
	if err != nil {
		return out, err
	}
	sum := sha256.Sum256([]byte(raw))
	copy(out[:], sum[:8])
	return out, nil
}
