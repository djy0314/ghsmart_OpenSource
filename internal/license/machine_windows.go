//go:build windows

// 机器码获取（Windows）：读注册表 MachineGuid（系统安装时生成的唯一 GUID），
// SHA256 后取前 8 字节。算法发布即冻结，保证同一台机器升级版本后机器码不变。

package license

import (
	"crypto/sha256"
	"golang.org/x/sys/windows/registry"
)

// machineRawID 返回参与机器码计算的原始唯一标识。
func machineRawID() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()
	guid, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return "", err
	}
	return guid, nil
}

// machineCodeBytes 返回 8 字节机器码（SHA256(MachineGuid) 前 8 字节）。
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
