// Package decision 实现候选 IP 的评分决策、失败熔断（冷却期）与迟滞防抖，
// 并负责把决策状态持久化到 ~/.ghsmart/state.json 供 daemon 跨重启使用。
package decision

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"ghsmart/internal/probe"
)

const (
	// FailThreshold 是连续失败多少次后进入冷却期。
	FailThreshold = 2
	// CooldownDuration 是熔断冷却期时长。
	CooldownDuration = 10 * time.Minute
	// hysteresisRatio 是迟滞阈值：新 IP 分数需比当前在用 IP 低 15% 以上才切换。
	hysteresisRatio = 0.85
)

// Candidate 是单个 IP 的持久化决策状态。
type Candidate struct {
	IP        string    `json:"ip"`
	Domain    string    `json:"domain"`
	Score     float64   `json:"score"`
	FailCount int       `json:"fail_count"`
	Cooldown  time.Time `json:"cooldown,omitempty"`
	InUse     bool      `json:"in_use,omitempty"`
}

// StatePath 返回状态文件路径 ~/.ghsmart/state.json。
func StatePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ghsmart", "state.json"), nil
}

// LoadState 从磁盘读取状态；文件不存在时返回空 map 和 nil 错误。
func LoadState() (map[string]*Candidate, error) {
	state := make(map[string]*Candidate)
	path, err := StatePath()
	if err != nil {
		return state, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return state, nil
		}
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, fmt.Errorf("解析状态文件 %s 失败: %w", path, err)
	}
	return state, nil
}

// SaveState 把状态原子化写入 ~/.ghsmart/state.json。
func SaveState(state map[string]*Candidate) error {
	path, err := StatePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// MarkApplied 把 ip 标记为当前在用（用于迟滞判断），其余取消标记。
func MarkApplied(state map[string]*Candidate, ip string) {
	for _, c := range state {
		c.InUse = c.IP == ip
	}
	if _, ok := state[ip]; !ok {
		state[ip] = &Candidate{IP: ip, InUse: true}
	} else {
		state[ip].InUse = true
	}
}

// CurrentIP 返回当前标记为在用的 IP（没有则返回空串）。
func CurrentIP(state map[string]*Candidate) string {
	for _, c := range state {
		if c.InUse {
			return c.IP
		}
	}
	return ""
}

// SelectBest 从探测结果中选出最优 IP。
// 返回选中的探测结果，以及是否建议切换（考虑迟滞与冷却期）。
// 同时会更新 state 中的失败计数与冷却时间（由调用方负责持久化）。
func SelectBest(results []probe.ProbeResult, state map[string]*Candidate) (probe.ProbeResult, bool) {
	now := time.Now()
	var best probe.ProbeResult
	found := false

	for _, r := range results {
		c, ok := state[r.IP]
		if !ok {
			c = &Candidate{IP: r.IP}
			state[r.IP] = c
		}
		if r.OK {
			c.Score = r.Score
			c.FailCount = 0
		} else {
			c.FailCount++
			if c.FailCount >= FailThreshold {
				c.Cooldown = now.Add(CooldownDuration)
			}
			continue // OK=false 的结果不参与选择
		}
		if !c.Cooldown.IsZero() && now.Before(c.Cooldown) {
			continue // 冷却期内不参与选择
		}
		if !found || r.Score < best.Score {
			best = r
			found = true
		}
	}

	if !found {
		return probe.ProbeResult{Err: "所有候选 IP 均失败或处于冷却期"}, false
	}

	cur := CurrentIP(state)
	if cur == "" || cur == best.IP {
		return best, cur != best.IP
	}
	// 迟滞：当前在用 IP 分数只比新最优差不到 15% 时，不切换。
	if c, ok := state[cur]; ok && c.Score > 0 && best.Score > c.Score*hysteresisRatio {
		return best, false
	}
	return best, true
}
