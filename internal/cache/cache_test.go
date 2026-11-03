package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// withTempCache 把缓存文件隔离到临时目录，测试绝不碰真实 ~/.ghsmart。
func withTempCache(t *testing.T) {
	t.Helper()
	t.Setenv("GHSMART_CACHE_FILE", filepath.Join(t.TempDir(), "cache.json"))
}

// TestSaveLoadRoundTrip：保存后原样读回，条目与时间戳都不丢。
func TestSaveLoadRoundTrip(t *testing.T) {
	withTempCache(t)
	in := map[string]string{"github.com": "140.82.112.3", "raw.githubusercontent.com": "185.199.108.133"}
	if err := Save(in); err != nil {
		t.Fatalf("Save 失败: %v", err)
	}
	out, savedAt, err := Load()
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if len(out) != 2 || out["github.com"] != "140.82.112.3" {
		t.Fatalf("读回内容不符: %v", out)
	}
	if savedAt.IsZero() || time.Since(savedAt) > time.Minute {
		t.Fatalf("savedAt 异常: %v", savedAt)
	}
}

// TestFreshForFiltering：FreshFor 必须过滤掉非管辖域名与非法 IP。
func TestFreshForFiltering(t *testing.T) {
	withTempCache(t)
	if err := Save(map[string]string{
		"github.com":    "140.82.112.3",
		"evil.example":  "1.2.3.4",   // 非管辖域名 → 必须剔除
		"broken.domain": "not-an-ip", // 非法 IP → 必须剔除
	}); err != nil {
		t.Fatalf("Save 失败: %v", err)
	}
	got := FreshFor([]string{"github.com", "raw.githubusercontent.com"})
	if len(got) != 1 || got["github.com"] != "140.82.112.3" {
		t.Fatalf("FreshFor 过滤结果不符: %v", got)
	}
}

// TestFreshForExpired：超过 MaxAge 的缓存绝不参与秒应用。
func TestFreshForExpired(t *testing.T) {
	withTempCache(t)
	if err := Save(map[string]string{"github.com": "140.82.112.3"}); err != nil {
		t.Fatalf("Save 失败: %v", err)
	}
	// 手工把时间戳拨回 MaxAge 之前
	p, _ := Path()
	data, _ := os.ReadFile(p)
	future := time.Now().Add(-MaxAge - time.Hour)
	stale := `{"saved_at":"` + future.Format(time.RFC3339Nano) + `","entries":{"github.com":"140.82.112.3"}}`
	if err := os.WriteFile(p, []byte(stale), 0o644); err != nil {
		t.Fatalf("改写缓存失败: %v", err)
	}
	_ = data
	if got := FreshFor([]string{"github.com"}); got != nil {
		t.Fatalf("过期缓存必须被拒绝，got %v", got)
	}
}

// TestFreshForMissing：文件缺失时返回 nil 且不报错。
func TestFreshForMissing(t *testing.T) {
	withTempCache(t)
	if got := FreshFor([]string{"github.com"}); got != nil {
		t.Fatalf("无缓存应返回 nil，got %v", got)
	}
}

// TestClear：清空后再读必须为空；重复清空（文件不存在）也必须静默成功。
func TestClear(t *testing.T) {
	withTempCache(t)
	if err := Save(map[string]string{"github.com": "140.82.112.3"}); err != nil {
		t.Fatalf("Save 失败: %v", err)
	}
	if err := Clear(); err != nil {
		t.Fatalf("Clear 失败: %v", err)
	}
	if entries, _, _ := Load(); len(entries) != 0 {
		t.Fatalf("Clear 后仍有残留: %v", entries)
	}
	if err := Clear(); err != nil {
		t.Fatalf("重复 Clear 应静默成功: %v", err)
	}
}

// TestSaveEmptyClears：空结果保存等价于清缓存，绝不让死 IP 留到下次秒应用。
func TestSaveEmptyClears(t *testing.T) {
	withTempCache(t)
	if err := Save(map[string]string{"github.com": "140.82.112.3"}); err != nil {
		t.Fatalf("Save 失败: %v", err)
	}
	if err := Save(map[string]string{}); err != nil {
		t.Fatalf("Save(空) 失败: %v", err)
	}
	if entries, _, _ := Load(); len(entries) != 0 {
		t.Fatalf("Save(空) 后仍有残留: %v", entries)
	}
}

// withTempProbe 把探测报告隔离到临时目录，测试绝不碰真实 ~/.ghsmart。
func withTempProbe(t *testing.T) {
	t.Helper()
	t.Setenv("GHSMART_PROBE_FILE", filepath.Join(t.TempDir(), "lastprobe.json"))
}

// TestProbeReportRoundTrip：探测报告保存后原样读回。
func TestProbeReportRoundTrip(t *testing.T) {
	withTempProbe(t)
	in := map[string][]ProbeRecord{
		"github.com": {
			{IP: "20.205.243.166", OK: false, Err: "TCP 失败: timeout"},
			{IP: "140.82.112.3", OK: true},
		},
	}
	if err := SaveProbeReport(in); err != nil {
		t.Fatalf("SaveProbeReport 失败: %v", err)
	}
	out, savedAt, err := LoadProbeReport()
	if err != nil {
		t.Fatalf("LoadProbeReport 失败: %v", err)
	}
	if savedAt.IsZero() {
		t.Fatal("savedAt 不应为零值")
	}
	recs := out["github.com"]
	if len(recs) != 2 {
		t.Fatalf("应有 2 条记录，实际 %d: %+v", len(recs), recs)
	}
	if recs[0].IP != "20.205.243.166" || recs[0].OK || recs[0].Err == "" {
		t.Fatalf("记录 0 内容不符: %+v", recs[0])
	}
	if recs[1].IP != "140.82.112.3" || !recs[1].OK {
		t.Fatalf("记录 1 内容不符: %+v", recs[1])
	}
}

// TestProbeReportMissing：文件缺失返回空 map 且无错误。
func TestProbeReportMissing(t *testing.T) {
	withTempProbe(t)
	out, savedAt, err := LoadProbeReport()
	if err != nil || len(out) != 0 || !savedAt.IsZero() {
		t.Fatalf("缺失时应返回空报告: out=%v err=%v", out, err)
	}
}
