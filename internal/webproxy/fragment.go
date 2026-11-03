package webproxy

import (
	"io"
	"sort"
	"time"
)

// Splitter 决定一条 ClientHello 被切成哪几段、段间停顿多久。
type Splitter struct {
	// Window > 0：固定按 Window 字节切片（对应 SpoofDPI 的 --window-size）。
	// Window <= 0：智能分片——首字节单独一段，再在 SNI 主机名正中间切一刀，
	// 保证任何单个 TCP 段里都读不到完整域名（连中间设备做单段匹配也失效）。
	Window int
	// Delay 是段之间的停顿，给 DPI 制造「这属于不同连接」的错觉；
	// 0 表示不停顿（内核仍会按 write 边界分成多个段，但停顿更稳）。
	Delay time.Duration
}

// Plan 返回切点偏移列表（严格递增，且 0 < cut < len(b)）。
// 切点为空表示不需要分片（数据太短或解析不出 SNI 且 Window<=0 时的兜底除外）。
func (s Splitter) Plan(b []byte) []int {
	if len(b) < 2 {
		return nil
	}
	if s.Window > 0 {
		var cuts []int
		for i := s.Window; i < len(b); i += s.Window {
			cuts = append(cuts, i)
		}
		return cuts
	}
	cuts := []int{1} // 首字节单独一段：DPI 只检查首段时看到的是残缺记录
	if st, en, ok := SNISpan(b); ok && en > st {
		mid := st + (en-st)/2
		if mid > 1 && mid < len(b) {
			cuts = append(cuts, mid)
		}
	}
	sort.Ints(cuts)
	// 去重并剔除非法切点
	out := cuts[:0]
	prev := 0
	for _, c := range cuts {
		if c > prev && c < len(b) {
			out = append(out, c)
			prev = c
		}
	}
	return out
}

// Write 按 Plan 把 b 分片写入 w，返回写入的总字节数。
// 每一片都是一次独立的 Write 调用，配合段间停顿即可在链路上形成独立 TCP 段。
func (s Splitter) Write(w io.Writer, b []byte) error {
	cuts := s.Plan(b)
	from := 0
	for _, cut := range cuts {
		if err := s.writeChunk(w, b[from:cut]); err != nil {
			return err
		}
		from = cut
	}
	if from < len(b) {
		return s.writeChunk(w, b[from:])
	}
	return nil
}

// WriteWithSizes 与 Write 相同，但把每片长度回传（单测/诊断用）。
func (s Splitter) WriteWithSizes(w io.Writer, b []byte) ([]int, error) {
	cuts := s.Plan(b)
	var sizes []int
	from := 0
	for _, cut := range cuts {
		if err := s.writeChunk(w, b[from:cut]); err != nil {
			return sizes, err
		}
		sizes = append(sizes, cut-from)
		from = cut
	}
	if from < len(b) {
		if err := s.writeChunk(w, b[from:]); err != nil {
			return sizes, err
		}
		sizes = append(sizes, len(b)-from)
	}
	return sizes, nil
}

func (s Splitter) writeChunk(w io.Writer, p []byte) error {
	if len(p) == 0 {
		return nil
	}
	if _, err := w.Write(p); err != nil {
		return err
	}
	if s.Delay > 0 {
		time.Sleep(s.Delay)
	}
	return nil
}
