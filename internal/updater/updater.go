// Package updater 检查 GitHub Releases 上是否有新版本。
//
// # 为什么需要它
//
// v1.0.8 及更早**完全没有更新通道**：客户装了什么版本就永远是什么版本，
// 号主每次发版只能去论坛发帖喊人，客户也不会知道自己手上的版本有没有修过 bug。
//
// # 设计约束
//
//   - 失败必须静默：网络不通、公司防火墙拦 api.github.com、GitHub 限流（60 次/小时/IP）
//     都是常态，检查更新失败**绝不能让界面报错**，更不能阻塞启动。
//   - 超时短：8 秒。启动路径上任何超过 10 秒的等待都会让用户觉得「这软件卡」。
//   - 可完全关闭：GHSMART_NO_UPDATE_CHECK=1，给企业环境/离线机器留后路。
//   - 不自动下载、不静默升级：只提示「有新版本」并给出 Release 页链接。
//     自动更新在这种需要管理员权限、会改 Hosts 的工具上风险太高，不做。
package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// DefaultAPI 是 GitHub 的 latest release 接口。
const DefaultAPI = "https://api.github.com/repos/djy0314/ghsmart_OpenSource/releases/latest"

// DefaultTimeout 是单次检查的超时（启动路径上不能等太久）。
const DefaultTimeout = 8 * time.Second

// Info 是一次检查的结果。
type Info struct {
	HasUpdate   bool   `json:"hasUpdate"`   // 远端版本是否比本地新
	Current     string `json:"current"`     // 本地版本（归一化）
	Latest      string `json:"latest"`      // 远端版本（归一化，去 v 前缀）
	Tag         string `json:"tag"`         // 远端原始 tag，如 v1.0.9
	URL         string `json:"url"`         // Release 页面
	Notes       string `json:"notes"`       // Release 正文（截断）
	PublishedAt string `json:"publishedAt"` // 发布时间
}

// Enabled 报告本次进程是否允许做更新检查。
// GHSMART_NO_UPDATE_CHECK 设为非空且非 "0" 时关闭。
func Enabled() bool {
	v := strings.TrimSpace(os.Getenv("GHSMART_NO_UPDATE_CHECK"))
	return v == "" || v == "0"
}

// apiURL 返回本次检查使用的接口地址（GHSMART_UPDATE_API 可覆盖，供测试与自建镜像使用）。
func apiURL() string {
	if v := strings.TrimSpace(os.Getenv("GHSMART_UPDATE_API")); v != "" {
		return v
	}
	return DefaultAPI
}

// releaseJSON 是 GitHub release 接口里我们关心的字段。
// 只声明需要的字段：接口返回体有几十个键，全量解析没必要。
type releaseJSON struct {
	TagName     string `json:"tag_name"`
	HTMLURL     string `json:"html_url"`
	Body        string `json:"body"`
	PublishedAt string `json:"published_at"`
	Draft       bool   `json:"draft"`
	Prerelease  bool   `json:"prerelease"`
}

// Check 查询 latest release 并与 current 比较。
//
// current 传 "1.0.8" 或 "v1.0.8" 都可以（内部归一化）。
// 返回的 Info.HasUpdate 才是「该不该提示用户」的唯一依据——
// 远端版本更旧或相同都算 false，绝不因为「取到了数据」就提示。
func Check(ctx context.Context, current string) (*Info, error) {
	if !Enabled() {
		return nil, fmt.Errorf("更新检查已通过环境变量关闭")
	}
	cur := Normalize(current)
	if cur == "" {
		return nil, fmt.Errorf("本地版本号为空，无法比较")
	}

	timeout := DefaultTimeout
	if dl, ok := ctx.Deadline(); ok {
		// 调用方若给了更短的整体预算，就按它来（不让本函数成为超时放大器）
		if time.Until(dl) < timeout {
			timeout = time.Until(dl)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL(), nil)
	if err != nil {
		return nil, err
	}
	// GitHub API 强制要求 User-Agent，缺省会被 403 直接拒掉
	req.Header.Set("User-Agent", "ghsmart-updater")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// 404（仓库改名/删了）与 403（限流）都走这里，一律静默
		return nil, fmt.Errorf("查询更新失败: HTTP %d", resp.StatusCode)
	}

	// 限制读取体积：正常返回体几 KB，防的是被劫持后灌一个巨大响应把内存吃满
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, err
	}
	var rel releaseJSON
	if err := json.Unmarshal(body, &rel); err != nil {
		return nil, fmt.Errorf("解析更新信息失败: %w", err)
	}
	if rel.TagName == "" {
		return nil, fmt.Errorf("更新信息缺少 tag_name")
	}
	// 预发布版不提示：客户要的是稳定版，草稿/预发布只属于开发者自己
	if rel.Draft || rel.Prerelease {
		return &Info{
			HasUpdate: false,
			Current:   cur,
			Latest:    Normalize(rel.TagName),
			Tag:       rel.TagName,
			URL:       rel.HTMLURL,
		}, nil
	}

	latest := Normalize(rel.TagName)
	info := &Info{
		Current:     cur,
		Latest:      latest,
		Tag:         rel.TagName,
		URL:         rel.HTMLURL,
		Notes:       truncate(rel.Body, 2000),
		PublishedAt: rel.PublishedAt,
	}
	info.HasUpdate = Compare(latest, cur) > 0
	return info, nil
}

// Normalize 把版本号归一化：去掉前导 v/V 与首尾空白。
func Normalize(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	return v
}

// Compare 比较两个版本号，返回 -1 / 0 / 1。
//
// 规则：
//
//	"1.0.9" > "1.0.8"，"1.1" > "1.0.9"，"1.0.8.1" > "1.0.8"
//	主版本号相同时，带预发布后缀的更低："1.0.9-beta" < "1.0.9"
//	解析不出来的段落按 0 处理（宁可漏提示，也绝不因脏数据误报）
func Compare(a, b string) int {
	an, apre := splitVersion(a)
	bn, bpre := splitVersion(b)
	n := len(an)
	if len(bn) > n {
		n = len(bn)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(an) {
			x = an[i]
		}
		if i < len(bn) {
			y = bn[i]
		}
		if x != y {
			if x > y {
				return 1
			}
			return -1
		}
	}
	// 主版本相同：无预发布后缀的更新
	switch {
	case apre == "" && bpre != "":
		return 1
	case apre != "" && bpre == "":
		return -1
	case apre == bpre:
		return 0
	case apre > bpre:
		return 1
	default:
		return -1
	}
}

// splitVersion 把 "1.0.9-beta.1" 拆成 ([1,0,9], "beta.1")。
func splitVersion(v string) ([]int, string) {
	v = Normalize(v)
	if v == "" {
		return nil, ""
	}
	pre := ""
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		pre = v[i+1:]
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	nums := make([]int, 0, len(parts))
	for _, p := range parts {
		// 允许 "1.0.8rc1" 这种脏数据：取开头的数字部分
		digits := p
		for i, r := range p {
			if r < '0' || r > '9' {
				digits = p[:i]
				break
			}
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			n = 0
		}
		nums = append(nums, n)
	}
	return nums, pre
}

// truncate 按字符（rune）截断，避免把中文切出半个字。
func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}
