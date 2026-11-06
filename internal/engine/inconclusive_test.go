package engine

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// 这两个用例钉的是 v1.0.10 实机事故的根因：
// 探测把全局预算吃光 → 业务校验一次没跑 → 所有域名被当成「不可用」→
// Hosts 区块被写成空块、缓存被清掉，界面还谎报「全部域名不可用」。
// 对方日志里 github.com 明明探到 5 个 OK 的候选 IP。

func TestMustPreserveState(t *testing.T) {
	cases := []struct {
		name         string
		written      int
		inconclusive int
		want         bool
	}{
		{"有写入就不谈保持", 3, 2, false},
		{"全靠猜（0 写入 + 有没验证完的）→ 保持现状", 0, 1, true},
		{"全部域名都没验证完 → 保持现状", 0, 5, true},
		{"一条没写但每个都验证过且失败 → 可以清（这是真证据）", 0, 0, false},
	}
	for _, c := range cases {
		if got := mustPreserveState(c.written, c.inconclusive); got != c.want {
			t.Errorf("%s: mustPreserveState(%d,%d)=%v，期望 %v",
				c.name, c.written, c.inconclusive, got, c.want)
		}
	}
}

// ErrInconclusive 必须是可被 errors.Is 命中的哨兵值，且文案要能直接给用户看
// （上层会原样贴到状态栏，绝不能出现「error: xxx」这种内部口气）。
func TestErrInconclusiveContract(t *testing.T) {
	wrapped := errors.Join(errors.New("外层包装"), ErrInconclusive) // 模拟被包装后仍可识别
	if !errors.Is(wrapped, ErrInconclusive) {
		t.Fatal("ErrInconclusive 必须能被 errors.Is 识别，否则上层无法区分「证据不足」和「真失败」")
	}
	msg := ErrInconclusive.Error()
	for _, kw := range []string{"保留", "加速记录"} {
		if !strings.Contains(msg, kw) {
			t.Fatalf("错误文案缺少关键字 %q（用户会直接看到这句）: %s", kw, msg)
		}
	}
}

// 预算不许被改小：10 秒预算下，5 个域名 × 3 候选 × 5 秒单次探测
// 正好是两波超时（≈10s），业务校验必然拿不到时间片。
func TestApplyTimeoutNotShrunk(t *testing.T) {
	if applyTimeout < 25*time.Second {
		t.Fatalf("applyTimeout=%v 太小：探测阶段本身就可能吃掉 10s 以上，"+
			"业务校验会一次都跑不到（v1.0.10 事故根因），不要改回去", applyTimeout)
	}
	if businessCheckTimeout <= 0 || businessCheckTimeout > applyTimeout {
		t.Fatalf("businessCheckTimeout=%v 与整体预算 %v 不匹配", businessCheckTimeout, applyTimeout)
	}
}
