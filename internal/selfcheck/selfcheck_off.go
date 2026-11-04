//go:build !selfcheck

// Package selfcheck 在未启用 selfcheck 构建标签时是空实现。
//
// 日常开发（wails build 不带 -tags selfcheck）不校验，任何改动都能直接跑；
// 只有发布构建（tools/build_release.ps1）才注入该标签，把校验编进去。
// 用构建标签而不是 ldflags 字符串开关：标签决定代码是否存在，改数据绕不过去。
package selfcheck

// Verify 开发构建恒通过。
func Verify() error { return nil }

// Fail 开发构建不调用。
func Fail(string) {}
