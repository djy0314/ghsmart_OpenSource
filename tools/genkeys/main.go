// genkeys 一次性生成 ghsmart 的 ECDSA P-256 授权密钥对：
//   - 私钥写入 keygen_private.pem（SEC1 格式）——发给码的机器保存，绝不打包进 exe；
//   - 公钥打印 X||Y 原始字节 hex——复制进 internal/license/ecdsa.go 的硬编码常量。
//
// 用法: go run ./tools/genkeys [输出pem路径]
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	out := "keygen_private.pem"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "生成密钥失败:", err)
		os.Exit(1)
	}

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "序列化私钥失败:", err)
		os.Exit(1)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(out, pemData, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "写私钥文件失败:", err)
		os.Exit(1)
	}

	pub := key.PublicKey
	x := pub.X.FillBytes(make([]byte, 32))
	y := pub.Y.FillBytes(make([]byte, 32))
	fmt.Println("私钥已写入:", out, "（妥善保管，勿随 exe 分发）")
	fmt.Println("公钥 X hex:", hex.EncodeToString(x))
	fmt.Println("公钥 Y hex:", hex.EncodeToString(y))
}
