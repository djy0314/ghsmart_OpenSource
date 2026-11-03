// ghsmart 是一个纯本地运行的 GitHub 访问智能优选 CLI。
// 通过 DoH 解析、多 IP 探测、评分决策、原子化更新系统 Hosts 实现加速，
// 不运营任何代理或中转服务，零后端、零运营成本。
// 编排逻辑在 internal/engine，GUI 版（Wails）同样复用该内核。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"ghsmart/internal/config"
	"ghsmart/internal/engine"
	"ghsmart/internal/license"
	"ghsmart/internal/probe"
)

var (
	cfgPath    string
	licenseKey string
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	root := &cobra.Command{
		Use:   "ghsmart",
		Short: "GitHub 访问智能优选（纯本地 DoH + 探测 + Hosts）",
	}
	root.PersistentFlags().StringVarP(&cfgPath, "config", "c", "configs/default.yaml", "配置文件路径")
	root.PersistentFlags().StringVarP(&licenseKey, "license", "l", "", "授权码（离线验签，可选）")

	root.AddCommand(probeCmd(), applyCmd(), daemonCmd(), removeCmd(), activateCmd())
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// checkLicense 校验授权码。CLI 传 -l 时走离线验签；不传则放行
// （CLI 是开发者自用工具，GUI 的 Pro 门禁不受影响）。
func checkLicense() error {
	if licenseKey == "" {
		return nil
	}
	ok, err := license.VerifyOffline(licenseKey)
	if err != nil {
		return fmt.Errorf("授权校验失败: %w", err)
	}
	if !ok {
		return fmt.Errorf("授权码无效")
	}
	return nil
}

// loadOrExit 加载配置，失败时输出错误并退出。
func loadOrExit() *config.Config {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		slog.Error("加载配置失败", "err", err)
		os.Exit(1)
	}
	engine.Configure(cfg)
	return cfg
}

// cliReporter 实现 engine.Reporter：把探测过程打印成终端表格。
type cliReporter struct{}

func (cliReporter) DomainStart(domain string) {
	slog.Info("开始探测", "domain", domain)
}

func (cliReporter) DomainProbed(domain string, results []probe.ProbeResult, bestIP string) {
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintf(w, "\nDomain: %s\n", domain)
	fmt.Fprintln(w, "IP\tTCP(ms)\tTLS(ms)\tHTTP(ms)\tScore\tOK")
	var best *probe.ProbeResult
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%.1f\t%v\n",
			r.IP, r.TCPMs, r.TLSMs, r.HTTPMs, r.Score, r.OK)
		if r.OK && (best == nil || r.Score < best.Score) {
			tmp := r
			best = &tmp
		}
	}
	w.Flush()
	if best != nil {
		fmt.Printf("Best: %s\n", best.IP)
	} else {
		fmt.Printf("Best: (无可用 IP)\n")
	}
}

func (cliReporter) DomainSkipped(domain string) {
	fmt.Printf("已跳过（无可用IP）: %s\n", domain)
}

func (cliReporter) Warn(msg string) {
	slog.Warn(msg)
}

// probeCmd 实现 ghsmart probe：只探测评分，不写 Hosts。
func probeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "probe",
		Short: "解析并探测所有域名候选 IP，打印评分表（不写 Hosts）",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkLicense(); err != nil {
				return err
			}
			cfg := loadOrExit()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			rep := cliReporter{}
			for _, domain := range cfg.Domains {
				results, err := engine.ResolveAndProbe(ctx, cfg, domain)
				if err != nil {
					slog.Error("探测失败", "domain", domain, "err", err)
					continue
				}
				var best *probe.ProbeResult
				for i := range results {
					if results[i].OK && (best == nil || results[i].Score < best.Score) {
						best = &results[i]
					}
				}
				bestIP := ""
				if best != nil {
					bestIP = best.IP
				}
				rep.DomainProbed(domain, results, bestIP)
			}
			return nil
		},
	}
}

// applyCmd 实现 ghsmart apply：探测、选优并写入 Hosts。
func applyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "apply",
		Short: "探测并选出最优 IP，写入系统 Hosts 的 ghsmart 区块",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkLicense(); err != nil {
				return err
			}
			cfg := loadOrExit()

			written, lines, restricted, err := engine.ApplyOnce(cfg, cliReporter{})
			if err != nil {
				return err
			}
			if restricted {
				return fmt.Errorf("当前网络环境受限（如公司 VPN），无法通过修改 Hosts 加速。已清理无效记录。")
			}
			fmt.Printf("\n本轮结果（实际写入 %d 条）:\n", len(written))
			for _, l := range lines {
				fmt.Println("  " + l)
			}
			fmt.Println("DNS 缓存已刷新。")
			return nil
		},
	}
}

// daemonCmd 实现 ghsmart daemon：先 apply 一次，再按间隔循环，Ctrl+C 优雅退出。
func daemonCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "daemon",
		Short: "按配置间隔循环执行 probe + decision + apply，Ctrl+C 退出",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkLicense(); err != nil {
				return err
			}
			cfg := loadOrExit()
			interval, err := cfg.IntervalDuration()
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
			defer stop()

			// 先执行一次
			written, lines, restricted, err := engine.ApplyOnce(cfg, cliReporter{})
			now := time.Now().Format("2006-01-02 15:04:05")
			if err != nil {
				slog.Error("apply 失败", "time", now, "err", err)
			} else if restricted {
				fmt.Printf("[%s] 当前网络环境受限（如公司 VPN），无法通过修改 Hosts 加速\n", now)
			} else if len(written) > 0 {
				fmt.Printf("[%s] 当前选中: %s\n", now, strings.Join(lines, ", "))
			} else {
				fmt.Printf("[%s] 本轮无可用 IP，已清除失效记录\n", now)
			}

			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					fmt.Println("\n收到退出信号，ghsmart daemon 已优雅退出（Hosts 区块保留，可用 ghsmart remove 清理）。")
					return nil
				case <-ticker.C:
					written, lines, restricted, err := engine.ApplyOnce(cfg, cliReporter{})
					now := time.Now().Format("2006-01-02 15:04:05")
					if err != nil {
						slog.Error("apply 失败", "time", now, "err", err)
						continue
					}
					if restricted {
						fmt.Printf("[%s] 当前网络环境受限（如公司 VPN），无法通过修改 Hosts 加速\n", now)
					} else if len(written) > 0 {
						fmt.Printf("[%s] 当前选中: %s\n", now, strings.Join(lines, ", "))
					} else {
						fmt.Printf("[%s] 本轮无可用 IP，已清除失效记录\n", now)
					}
				}
			}
		},
	}
}

// licenseStorePath 返回激活状态文件路径（与 GUI 共用同一份 ~/.ghsmart/license.json）。
func licenseStorePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ghsmart", "license.json"), nil
}

// activateCmd 实现 ghsmart activate：离线验签激活码并持久化解锁状态。
func activateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "activate <激活码>",
		Short: "校验离线激活码并解锁 Pro（与 GUI 共用授权状态）",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			code := strings.TrimSpace(args[0])
			ok, err := license.VerifyOffline(code)
			if err != nil {
				return fmt.Errorf("激活失败: %w", err)
			}
			if !ok {
				return fmt.Errorf("激活码无效")
			}

			p, err := licenseStorePath()
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return err
			}
			// 与 GUI 共用 license.json：读取旧内容并合并，保留 auto_heal 等已有字段
			st := map[string]any{}
			if old, err := os.ReadFile(p); err == nil {
				_ = json.Unmarshal(old, &st)
			}
			st["key"] = code
			st["validated_at"] = time.Now().Format("2006-01-02 15:04:05")
			data, _ := json.MarshalIndent(st, "", "  ")
			if err := os.WriteFile(p, data, 0o600); err != nil {
				return fmt.Errorf("保存激活状态失败: %w", err)
			}
			fmt.Println("✓ 激活成功，Pro 已解锁（本机）。状态已写入", p)
			return nil
		},
	}
}

// removeCmd 实现 ghsmart remove：删除 Hosts 中的 ghsmart 区块。
func removeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove",
		Short: "删除系统 Hosts 中的 ghsmart 区块并刷新 DNS",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkLicense(); err != nil {
				return err
			}
			if err := engine.RestoreHosts(cliReporter{}); err != nil {
				return fmt.Errorf("清理 Hosts 失败（请以管理员身份运行）: %w", err)
			}
			fmt.Println("ghsmart 区块已从 Hosts 中移除，冲突行已还原，git insteadOf 已清理，DNS 缓存已刷新。")
			return nil
		},
	}
}
