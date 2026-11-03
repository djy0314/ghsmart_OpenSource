// Package license 定义授权校验接口。
// Phase 1 提供恒通过的 NoopVerifier 占位；Phase 4 再替换为真实校验实现。
package license

// Verifier 是授权码校验接口。
type Verifier interface {
	// Verify 校验授权 key，返回是否有效及错误信息。
	Verify(key string) (bool, error)
}

// NoopVerifier 是空校验实现：任何 key 都返回 true。
type NoopVerifier struct{}

// Verify 恒返回 (true, nil)，Phase 4 之前作为默认实现。
func (NoopVerifier) Verify(_ string) (bool, error) {
	return true, nil
}

// Ensure 返回可用的 Verifier；传入 nil 时返回 NoopVerifier。
func Ensure(v Verifier) Verifier {
	if v == nil {
		return NoopVerifier{}
	}
	return v
}
