// Package cache 提供「最优 IP 本地缓存」（~/.ghsmart/cache.json）：
// 每次探测成功后把 域名 -> 最优 IP 落盘；下次打开软件或点击「一键智能加速」时
// 优先读取缓存并在 0.1 秒内写入 Hosts + 刷新 DNS，让用户立刻可用；
// 随后由后台静默重探测校验，发现更优 IP 再悄悄替换。
//
// 该机制对免费版无条件开放（产品基础体验），绝不与 Pro 授权绑定。
package cache

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MaxAge 是缓存可被「秒应用」的最长有效期。
// 超过即视为过期：绝不自动写入 Hosts（IP 可能已大面积漂移），
// 只走正常探测流程；探测成功后缓存自然被刷新。
const MaxAge = 72 * time.Hour

// Path 返回缓存文件路径（默认 ~/.ghsmart/cache.json）。
// 环境变量 GHSMART_CACHE_FILE 可覆盖（单测隔离用）。
func Path() (string, error) {
	if p := os.Getenv("GHSMART_CACHE_FILE"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ghsmart", "cache.json"), nil
}

// fileData 是 cache.json 的磁盘结构。
type fileData struct {
	SavedAt time.Time         `json:"saved_at"`          // 本批缓存写入时间（统一过期判断）
	Entries map[string]string `json:"entries"`           // 域名 -> 最优 IP
}

// Load 读取缓存；文件缺失时返回空 map、零时间与 nil 错误。
func Load() (map[string]string, time.Time, error) {
	entries := map[string]string{}
	p, err := Path()
	if err != nil {
		return entries, time.Time{}, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return entries, time.Time{}, nil
		}
		return entries, time.Time{}, err
	}
	var fd fileData
	if err := json.Unmarshal(data, &fd); err != nil {
		return entries, time.Time{}, err
	}
	if fd.Entries != nil {
		entries = fd.Entries
	}
	return entries, fd.SavedAt, nil
}

// Save 原子化写入缓存（临时文件 + 重命名，杜绝写一半被读到）。
func Save(entries map[string]string) error {
	if len(entries) == 0 {
		return Clear() // 空结果直接清缓存，别留死 IP 供下次秒应用
	}
	p, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(fileData{SavedAt: time.Now(), Entries: entries}, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Clear 删除缓存文件；文件不存在时静默成功。
func Clear() error {
	p, err := Path()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// FreshFor 读取仍在有效期内的缓存，并做三重过滤：
//  1. 只保留 domains 列表管辖的域名（配置之外的旧域名绝不自动写 Hosts）；
//  2. IP 必须合法（防手工改坏的 cache.json 把脏数据写进系统）；
//  3. 整体未超过 MaxAge（过期即弃，只走正常探测）。
//
// 返回 nil 表示没有可秒应用的缓存。
func FreshFor(domains []string) map[string]string {
	entries, savedAt, err := Load()
	if err != nil || len(entries) == 0 {
		return nil
	}
	if savedAt.IsZero() || time.Since(savedAt) > MaxAge {
		return nil
	}
	allowed := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		allowed[strings.ToLower(d)] = struct{}{}
	}
	out := make(map[string]string, len(entries))
	for d, ip := range entries {
		if _, ok := allowed[strings.ToLower(d)]; !ok {
			continue
		}
		if net.ParseIP(ip) == nil {
			continue
		}
		out[d] = ip
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ---------------------------------------------------------------------------
// 上一轮探测报告（~/.ghsmart/lastprobe.json）
//
// 用途：深度加速的「开启预检」——用户点开关时先看上一轮探测结果，
// 如果主域名的所有候选 IP 都不可达（超时/被拦），直接阻止开启深度加速，
// 引导用户使用 Hosts 模式（一键智能加速），避免开启后网页全卡死。

// ProbeRecord 是单个候选 IP 的探测结论。
type ProbeRecord struct {
	IP  string `json:"ip"`
	OK  bool   `json:"ok"`
	Err string `json:"err,omitempty"`
}

// probeFile 是 lastprobe.json 的磁盘结构。
type probeFile struct {
	SavedAt time.Time                `json:"saved_at"`
	Domains map[string][]ProbeRecord `json:"domains"`
}

// ProbePath 返回探测报告路径（默认 ~/.ghsmart/lastprobe.json）。
// 环境变量 GHSMART_PROBE_FILE 可覆盖（单测隔离用）。
func ProbePath() (string, error) {
	if p := os.Getenv("GHSMART_PROBE_FILE"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ghsmart", "lastprobe.json"), nil
}

// SaveProbeReport 原子化写入上一轮探测报告（整体覆盖：报告只保留最新一轮）。
func SaveProbeReport(domains map[string][]ProbeRecord) error {
	if len(domains) == 0 {
		return nil // 没有任何结果时不落盘，保留旧报告
	}
	p, err := ProbePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(probeFile{SavedAt: time.Now(), Domains: domains}, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// ClearProbeReport 删除历史探测报告（文件不存在视为成功）。
// 用途：深度加速预检已改为实时微测，旧报告一律作废；
// 一键智能加速开始时也强制清空，避免旧结论干扰后续判断。
func ClearProbeReport() error {
	p, err := ProbePath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// LoadProbeReport 读取探测报告；文件缺失返回空 map、零时间与 nil 错误。
func LoadProbeReport() (map[string][]ProbeRecord, time.Time, error) {
	domains := map[string][]ProbeRecord{}
	p, err := ProbePath()
	if err != nil {
		return domains, time.Time{}, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return domains, time.Time{}, nil
		}
		return domains, time.Time{}, err
	}
	var pf probeFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return domains, time.Time{}, err
	}
	if pf.Domains != nil {
		domains = pf.Domains
	}
	return domains, pf.SavedAt, nil
}
