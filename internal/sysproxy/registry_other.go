//go:build !windows

package sysproxy

import "errors"

// 非 Windows 平台：系统代理接管不支持（本项目仅发布 Windows 版），
// 保留编译占位，保证 go vet ./... 在任意平台可跑。

func defaultStore() Store { return unsupportedStore{} }

type unsupportedStore struct{}

func (unsupportedStore) Read() (Values, error) {
	return Values{}, errors.New("仅支持 Windows")
}

func (unsupportedStore) Write(Values) error {
	return errors.New("仅支持 Windows")
}
