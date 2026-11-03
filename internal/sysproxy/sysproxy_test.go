package sysproxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// memStore 用内存模拟注册表，绝不触碰真实系统代理。
type memStore struct{ v Values }

func (m *memStore) Read() (Values, error) { return m.v, nil }
func (m *memStore) Write(v Values) error  { m.v = v; return nil }

func tmpPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "sysproxy.bak.json")
}

const target = "127.0.0.1:18080"

// 核心安全断言：开启时先备份原值，关闭时按原值还原。
func TestApplyBackupAndRestore(t *testing.T) {
	st := &memStore{v: Values{Enable: 1, Server: "127.0.0.1:7890", Override: "*.cn", HasOverride: true}}
	p := tmpPath(t)

	if _, err := applyWith(st, p, target); err != nil {
		t.Fatalf("apply 失败: %v", err)
	}
	if st.v.Server != target || st.v.Enable != 1 {
		t.Fatalf("系统代理未指向本地代理: %+v", st.v)
	}
	if st.v.Override != "*.cn" || !st.v.HasOverride {
		t.Fatalf("不应动 ProxyOverride: %+v", st.v)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("备份文件应存在: %v", err)
	}

	restored, err := restoreWith(st, p, target)
	if err != nil {
		t.Fatalf("restore 失败: %v", err)
	}
	if !restored {
		t.Fatal("应执行还原")
	}
	if st.v.Server != "127.0.0.1:7890" || st.v.Enable != 1 {
		t.Fatalf("未还原到用户原值: %+v", st.v)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("还原后备份文件应被删除")
	}
}

// 二次开启（例如先关后开、或重复点）不能把我们的地址当原值备份下来。
func TestApplyTwiceKeepsOriginalBackup(t *testing.T) {
	st := &memStore{v: Values{Enable: 0, Server: ""}}
	p := tmpPath(t)

	if _, err := applyWith(st, p, target); err != nil {
		t.Fatal(err)
	}
	if _, err := applyWith(st, p, target); err != nil {
		t.Fatal(err)
	}
	if _, err := restoreWith(st, p, target); err != nil {
		t.Fatal(err)
	}
	if st.v.Enable != 0 || st.v.Server != "" {
		t.Fatalf("应还原为「无代理」，实际 %+v", st.v)
	}
}

// 崩溃兜底：下次启动时当前值仍是我们写的 → 自动还原。
func TestRecoverRestoresWhenStillOurs(t *testing.T) {
	st := &memStore{v: Values{Enable: 0, Server: "old:8080"}}
	p := tmpPath(t)

	if _, err := applyWith(st, p, target); err != nil {
		t.Fatal(err)
	}
	// 模拟进程被强杀：不做 Restore，直接走启动兜底
	restored, err := recoverWith(st, p, target)
	if err != nil {
		t.Fatalf("recover 失败: %v", err)
	}
	if !restored {
		t.Fatal("应执行兜底还原")
	}
	if st.v.Server != "old:8080" {
		t.Fatalf("兜底还原值错误: %+v", st.v)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("兜底还原后应删除备份")
	}
}

// 用户自己改过系统代理：只清理备份，绝不覆盖用户当前的设置。
func TestRecoverLeavesUserProxyAlone(t *testing.T) {
	st := &memStore{v: Values{Enable: 0, Server: "old:8080"}}
	p := tmpPath(t)

	if _, err := applyWith(st, p, target); err != nil {
		t.Fatal(err)
	}
	st.v = Values{Enable: 1, Server: "127.0.0.1:7897"} // 用户自己换成了另一个代理

	restored, err := recoverWith(st, p, target)
	if err != nil {
		t.Fatal(err)
	}
	if restored {
		t.Fatal("不应覆盖用户手动设置的代理")
	}
	if st.v.Server != "127.0.0.1:7897" {
		t.Fatalf("用户代理被改坏: %+v", st.v)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("陈旧备份应被清理")
	}
}

// 没有备份时 Restore 必须是安全空操作（不能把 ProxyEnable 写成别的值）。
func TestRestoreWithoutBackupIsNoop(t *testing.T) {
	st := &memStore{v: Values{Enable: 0, Server: ""}}
	if restored, err := restoreWith(st, tmpPath(t), target); err != nil {
		t.Fatalf("无备份时 restore 不应报错: %v", err)
	} else if restored {
		t.Fatal("无备份且未指向上游时不应动注册表")
	}
	if st.v.Server != "" || st.v.Enable != 0 {
		t.Fatalf("无备份时不应改注册表: %+v", st.v)
	}
}

// 关键防误伤：系统代理是第三方（如 Clash 7890）时，「一键还原网络」绝不能改它。
func TestRestoreSkipsThirdPartyProxy(t *testing.T) {
	st := &memStore{v: Values{Enable: 1, Server: "127.0.0.1:7890"}}
	restored, err := restoreWith(st, tmpPath(t), target)
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if restored {
		t.Fatal("第三方代理不该被判定为我们的")
	}
	if st.v.Enable != 1 || st.v.Server != "127.0.0.1:7890" {
		t.Fatalf("第三方代理被误改: %+v", st.v)
	}
}

// 备份文件丢了、但系统代理还指着我们的端口 → 启动兜底必须关掉它，避免死代理断网。
func TestRestoreStaleWithoutBackup(t *testing.T) {
	st := &memStore{v: Values{Enable: 1, Server: target}}
	restored, err := restoreWith(st, tmpPath(t), target)
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if !restored {
		t.Fatal("指向我们的脏状态应被清理")
	}
	if st.v.Enable != 0 {
		t.Fatalf("应关闭代理，实际 %+v", st.v)
	}
}

// http:// 前缀、大小写、多协议串都要能识别成「我们的」。
func TestOwnedByVariants(t *testing.T) {
	cases := []struct {
		v    Values
		want bool
	}{
		{Values{Enable: 1, Server: "127.0.0.1:18080"}, true},
		{Values{Enable: 1, Server: "http://127.0.0.1:18080"}, true},
		{Values{Enable: 1, Server: "http=127.0.0.1:18080;https=127.0.0.1:18080"}, true},
		{Values{Enable: 0, Server: "127.0.0.1:18080"}, false},
		{Values{Enable: 1, Server: "127.0.0.1:7890"}, false},
	}
	for i, c := range cases {
		if got := ownedBy(c.v, target); got != c.want {
			t.Fatalf("case %d: ownedBy(%+v) = %v, 期望 %v", i, c.v, got, c.want)
		}
	}
}

// ===== Bypass（ProxyOverride）清理：本次 ERR_CONNECTION_CLOSED 的根因 =====

// 真实用户机器上的历史残留：接管时必须全部剔除，只留 <local> 与用户自有项。
func TestApplyStripsGitHubFromBypass(t *testing.T) {
	raw := "*.ghproxy.net;*.ghp.ci;*.kkgithub.com;*.github.com;raw.githubusercontent.com;" +
		"<local>;*.cn;192.168.*;*.mycorp.local"
	st := &memStore{v: Values{Enable: 1, Server: "127.0.0.1:7890", Override: raw, HasOverride: true}}
	p := tmpPath(t)

	res, err := applyWith(st, p, target)
	if err != nil {
		t.Fatalf("apply 失败: %v", err)
	}
	if left := BypassHasGitHub(st.v.Override); len(left) > 0 {
		t.Fatalf("接管后 bypass 仍残留 GitHub 域名: %v（完整值 %q）", left, st.v.Override)
	}
	for _, keep := range []string{"<local>", "*.cn", "192.168.*", "*.mycorp.local"} {
		if !strings.Contains(st.v.Override, keep) {
			t.Fatalf("用户自有条目 %q 被误删: %q", keep, st.v.Override)
		}
	}
	if len(res.RemovedBypass) != 5 {
		t.Fatalf("应剔除 5 条 GitHub 系条目，实际 %v", res.RemovedBypass)
	}

	// 还原：必须把原始 bypass 原样写回（原样 = 连那些镜像残留一起回来，这是用户的设置）
	if _, err := restoreWith(st, p, target); err != nil {
		t.Fatal(err)
	}
	if st.v.Override != raw {
		t.Fatalf("还原后 bypass 未原样恢复:\n 得到 %q\n 期望 %q", st.v.Override, raw)
	}
}

// 各种写法（通配、协议头、端口、子域）都要能识别出来。
func TestSanitizeOverrideVariants(t *testing.T) {
	raw := "*github.com;github.com:443;https://github.com;*.api.github.com;" +
		"objects.githubusercontent.com;*.githubassets.com;ghcr.io;<local>;10.0.0.0/8"
	got, removed := SanitizeOverride(raw)
	if left := BypassHasGitHub(got); len(left) > 0 {
		t.Fatalf("仍有残留: %v", left)
	}
	if !strings.Contains(got, "<local>") || !strings.Contains(got, "10.0.0.0/8") {
		t.Fatalf("误删了非 GitHub 条目: %q", got)
	}
	if len(removed) != 7 {
		t.Fatalf("应剔除 7 条，实际 %d: %v", len(removed), removed)
	}
}

// 全是 GitHub 条目时，清理后要补回 <local>，不能留空（否则本地回环也走代理）。
func TestSanitizeOverrideEmptyFallsBackToLocal(t *testing.T) {
	got, _ := SanitizeOverride("*.github.com;ghproxy.net")
	if got != "<local>" {
		t.Fatalf("应回落到 <local>，实际 %q", got)
	}
}

// 已经在位（地址 + bypass 都干净）时不能重复写注册表。
func TestApplySkipsRewriteWhenAlreadyClean(t *testing.T) {
	st := &memStore{v: Values{Enable: 1, Server: target, Override: "<local>", HasOverride: true}}
	p := tmpPath(t)
	res, err := applyWith(st, p, target)
	if err != nil {
		t.Fatal(err)
	}
	if res.Bypass != "<local>" {
		t.Fatalf("Bypass 应为 <local>，实际 %q", res.Bypass)
	}
	if st.v.Override != "<local>" {
		t.Fatalf("不应改动已干净的列表: %q", st.v.Override)
	}
}

// 已指向我们但 bypass 是脏的（老版本接管的遗留）→ 必须补写一次清理。
func TestApplyFixesDirtyBypassWhenAlreadyOurs(t *testing.T) {
	st := &memStore{v: Values{Enable: 1, Server: target, Override: "*.github.com", HasOverride: true}}
	if _, err := applyWith(st, tmpPath(t), target); err != nil {
		t.Fatal(err)
	}
	if left := BypassHasGitHub(st.v.Override); len(left) > 0 {
		t.Fatalf("老版本遗留的脏 bypass 未被清理: %v", left)
	}
}
