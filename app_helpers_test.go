package main

// 通用测试辅助 + 「一键智能加速清空旧报告」回归。
// 预检机制已随 2026-11-04 重构移除，这里只保留与预检无关的共享工具。

import (
	"os"
	"testing"

	"ghsmart/internal/cache"
	"ghsmart/internal/config"
)

// withTempProbeReport 把探测报告与优选缓存隔离到临时目录，
// 并按需写入一份「上一轮全失败」的历史报告。
func withTempProbeReport(t *testing.T, report map[string][]cache.ProbeRecord) {
	t.Helper()
	t.Setenv("GHSMART_PROBE_FILE", t.TempDir()+"/lastprobe.json")
	t.Setenv("GHSMART_CACHE_FILE", t.TempDir()+"/cache.json")
	if report != nil {
		if err := cache.SaveProbeReport(report); err != nil {
			t.Fatalf("写入探测报告失败: %v", err)
		}
	}
}

// a0Config 返回默认配置（不依赖外部文件）。
// 监听地址改为随机端口：单测绝不能跟正在真机运行的正式版抢 18080。
func a0Config(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("加载默认配置失败: %v", err)
	}
	cfg.WebProxy.Listen = "127.0.0.1:0"
	return cfg
}

// staleFailureReport 模拟 VPN 期间探测全失败的历史报告。
func staleFailureReport() map[string][]cache.ProbeRecord {
	return map[string][]cache.ProbeRecord{
		"github.com": {
			{IP: "20.205.243.166", OK: false, Err: "TCP 失败: dial tcp 20.205.243.166:443: i/o timeout"},
			{IP: "140.82.112.3", OK: false, Err: "TCP 失败: i/o timeout"},
		},
	}
}

// TestStartApplyClearsProbeReport：点「一键智能加速」必须立刻清空旧探测报告，
// 绝不让陈旧的失败记录影响任何后续判断。
func TestStartApplyClearsProbeReport(t *testing.T) {
	withTempProbeReport(t, staleFailureReport())
	p, err := cache.ProbePath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("前置条件：旧报告应存在: %v", err)
	}
	a := NewApp() // ctx 为 nil：StartApply 会提前返回「未就绪」，但清空动作必须已经发生
	if err := a.StartApply(); err == nil {
		t.Fatal("ctx 为空时 StartApply 应报未就绪")
	}
	if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
		t.Fatalf("点击一键加速后旧报告必须被清空（statErr=%v）", statErr)
	}
}
