//go:build live

// 实网验收（-tags live，默认不跑）：
// 用「手动模式」启动真实的后端代理（不碰注册表），然后像用户一样用 curl 打过去。
//
//	go test -tags live . -run TestLiveDeep -v
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ghsmart/internal/cache"
)

func TestLiveDeepAccelCurl(t *testing.T) {
	t.Setenv("GHSMART_LICENSE_FILE", filepath.Join(t.TempDir(), "license.json"))
	t.Setenv("GHSMART_SYSPROXY_FILE", filepath.Join(t.TempDir(), "sysproxy.bak.json"))
	logFile := filepath.Join(t.TempDir(), "ghsmart.log")
	t.Setenv("GHSMART_LOG_FILE", logFile)
	defer func() {
		if data, err := os.ReadFile(logFile); err == nil {
			t.Logf("代理日志:\n%s", data)
		}
	}()

	a := NewApp()
	a.pro.Store(true)
	cfg := a.loadCfg()
	cfg.WebProxy.Listen = "127.0.0.1:0" // 随机端口，别和真机 18080 抢
	cfg.WebProxy.SplitDelayMS = 10
	if err := a.startDeep(cfg, DeepModeManual, false); err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}
	defer a.Shutdown()

	addr := a.GetProState()["deepListen"].(string)
	if addr == "" {
		t.Fatal("没拿到监听地址")
	}
	t.Logf("本地代理监听: %s（手动模式，未改注册表）", addr)

	// 解析链路先单独验收：必须拿到「优选 IP」而不是空
	if ips := a.resolveHosts("github.com"); len(ips) == 0 {
		t.Fatal("resolveHosts(github.com) 没有拿到任何优选 IP")
	} else {
		t.Logf("resolveHosts(github.com) = %v", ips)
	}

	cases := []struct {
		name string
		args []string
	}{
		// -m 20：单个用例最多等 20s，避免某个 IP 假活时把整个用例拖成几分钟
		{"HEAD 主页", []string{"-I", "-sS", "-m", "20", "-o", os.DevNull, "-w", "%{http_code}", "https://github.com/"}},
		{"GET raw 文件", []string{"-sS", "-m", "20", "-o", os.DevNull, "-w", "%{http_code}", "https://raw.githubusercontent.com/git/git/master/README.md"}},
		{"GET 静态资源域", []string{"-sS", "-m", "20", "-o", os.DevNull, "-w", "%{http_code}", "https://codeload.github.com/"}},
	}
	for _, c := range cases {
		args := append([]string{"-x", "http://" + addr}, c.args...)
		out, err := exec.Command("curl", args...).CombinedOutput()
		code := strings.TrimSpace(string(out))
		if err != nil {
			t.Fatalf("%s: curl 执行失败: %v (%s)", c.name, err, code)
		}
		t.Logf("%s -> HTTP %s", c.name, code)
		if code != "200" && code != "301" && code != "302" {
			t.Fatalf("%s: 期望 200/3xx，实际 %s（502 说明拨号或分片链路挂了）", c.name, code)
		}
	}

	st := a.proxy.Stats()
	t.Logf("代理统计: total=%d split=%d pass=%d lastHost=%s", st.Total, st.Split, st.Pass, st.LastHost)
	if st.Split == 0 {
		t.Fatal("curl 走通了但一次分片都没发生，说明 CONNECT 没走分片路径")
	}
}

// 号主实机那个组合场景的复刻：先点「一键智能加速」把优选 IP 写进 hosts，
// 再开「深度网页加速」。若那条 IP 已经失效，旧代码的代理会一直卡到超时
// （ERR_CONNECTION_TIMED_OUT）。这里把「hosts 里那条死 IP」直接注入解析缓存，
// 验证双加速叠加时代理仍能秒开（并发竞速会绕过它）。
func TestLiveDeepWithStaleHostsIP(t *testing.T) {
	t.Setenv("GHSMART_LICENSE_FILE", filepath.Join(t.TempDir(), "license.json"))
	t.Setenv("GHSMART_SYSPROXY_FILE", filepath.Join(t.TempDir(), "sysproxy.bak.json"))
	logFile := filepath.Join(t.TempDir(), "ghsmart.log")
	t.Setenv("GHSMART_LOG_FILE", logFile)

	a := NewApp()
	a.pro.Store(true)
	cfg := a.loadCfg()
	cfg.WebProxy.Listen = "127.0.0.1:0"
	cfg.WebProxy.SplitDelayMS = 10
	if err := a.startDeep(cfg, DeepModeManual, false); err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}
	defer a.Shutdown()
	addr := a.GetProState()["deepListen"].(string)

	// 先让它正常解析一次，拿到真实可用 IP
	real := a.resolveHosts("github.com")
	if len(real) == 0 {
		t.Fatal("解析不到 github.com")
	}
	// 再模拟「hosts 里那条优选 IP 已经失效」：死 IP 排到最前面
	a.ipMu.Lock()
	a.ipCache["github.com"] = ipEntry{
		ips: append([]string{"10.255.255.1"}, real...),
		at:  time.Now(),
	}
	a.ipMu.Unlock()
	t.Logf("注入的候选（首位为死 IP）: %v", append([]string{"10.255.255.1"}, real...))

	start := time.Now()
	out, err := exec.Command("curl",
		"-x", "http://"+addr, "-I", "-sS", "-m", "20",
		"-o", os.DevNull, "-w", "%{http_code}", "https://github.com/").CombinedOutput()
	elapsed := time.Since(start)
	code := strings.TrimSpace(string(out))
	if err != nil {
		t.Fatalf("curl 失败: %v (%s)", err, code)
	}
	t.Logf("hosts 里躺着死 IP 时：HTTP %s，耗时 %v", code, elapsed.Round(time.Millisecond))
	if code != "200" {
		t.Fatalf("期望 200，实际 %s", code)
	}
	if elapsed > 8*time.Second {
		t.Fatalf("被死 IP 拖慢到 %v（应靠并发竞速绕过）", elapsed)
	}

	if data, err := os.ReadFile(logFile); err == nil {
		t.Logf("代理日志:\n%s", data)
	}
}

// TestLivePrecheckRealNetwork 是号主报障的实网回归：
// 先造一份「VPN 期间 github.com 全失败」的旧报告，再走真实网络的实时微测——
// 只要此刻能连上 github.com，预检必须放行，且旧报告必须被清空。
//
//	go test -tags live . -run TestLivePrecheckRealNetwork -v
func TestLivePrecheckRealNetwork(t *testing.T) {
	probeFile := filepath.Join(t.TempDir(), "lastprobe.json")
	t.Setenv("GHSMART_PROBE_FILE", probeFile)
	t.Setenv("GHSMART_CACHE_FILE", filepath.Join(t.TempDir(), "cache.json"))

	if err := cache.SaveProbeReport(map[string][]cache.ProbeRecord{
		"github.com": {{IP: "20.205.243.166", OK: false, Err: "TCP 失败: i/o timeout"}},
	}); err != nil {
		t.Fatalf("写入旧失败报告失败: %v", err)
	}

	// 先自证本机此刻确实能连上：连不上就跳过，绝不把「真断网」误判成代码失败
	cfg := NewApp().loadCfg()
	if res := NewApp().deepLiveCheck(cfg, "github.com"); !res.OK {
		t.Skipf("当前网络确实连不上 github.com（候选 %d 个），跳过实时预检验收", res.Checked)
	}
	t.Log("自证通过：本机此刻可连 github.com")

	a := NewApp()
	start := time.Now()
	pc := a.CheckDeepPrecondition()
	t.Logf("预检耗时 %v，结果 %+v", time.Since(start), pc)

	if pc["ok"] != true {
		t.Fatalf("网络可通却被预检拦截（号主报障复现）: %+v", pc)
	}
	if pc["live"] != true {
		t.Fatalf("预检必须走实时微测: %+v", pc)
	}
	if _, err := os.Stat(probeFile); !os.IsNotExist(err) {
		t.Fatalf("放行后旧报告必须被清空（statErr=%v）", err)
	}
}
