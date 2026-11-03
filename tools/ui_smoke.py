# -*- coding: utf-8 -*-
"""ghsmart 界面烟测（不需要 WebView2 / 不需要管理员）：

把 frontend/dist/index.html 复制一份，在页面脚本前注入 Wails 绑定 mock，
再用无头浏览器真实渲染 + 真实点击，把结果画在页面上并截图。

覆盖：
  1. 底部两个 Pro 开关都渲染、互不重叠、不溢出
  2. Free 状态点「深度网页加速」→ 弹解锁框，不报 JS 错
  3. Pro 状态点「深度网页加速」→ 弹「请选择加速模式」→ 选手动 → 确定
     → 调用 SetDeepAccel(true,"manual")，文字变「已开启 · 手动」
  4. 再点一次 → 直接关闭（不再弹窗），SetDeepAccel(false,...)
  5. 自愈开关与深度加速互不串台
  6. 全程无 window.onerror / unhandledrejection

用法： py tools/ui_smoke.py
产物： D:/project/ghsmart/.uitest/ui_<free|pro>.png
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "frontend", "dist", "index.html")
OUT_DIR = os.path.join(ROOT, ".uitest")

BROWSERS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
]

MOCK = r"""
<script>
window.__calls = [];
window.__errors = [];
window.__state = { pro: __PRO__, autoHeal: false, deepAccel: false, deepListen: "", deepMode: "", deepCompat: false, deepCompatDefault: false };
window.__blocked = __BLOCKED__;
window.__wait = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };
function __log(msg) {
  window.__errors.push(msg);
  var d = document.getElementById("__testlog");
  if (d) d.textContent = window.__errors.join(" || ");
}
window.addEventListener("error", function (e) { __log("JS ERROR: " + e.message); });
window.addEventListener("unhandledrejection", function (e) { __log("REJECT: " + e.reason); });
window.runtime = { EventsOn: function () {} };
window.go = { main: { App: {
  IsElevated: function () { return Promise.resolve(true); },
  GetAppliedEntries: function () { return Promise.resolve({ "github.com": "20.205.243.166" }); },
  CheckDeepPrecondition: function () { window.__calls.push(["CheckDeepPrecondition"]);
    if (window.__blocked) {
      return { ok: false, live: true, checked: 1,
        reason: "当前网络环境依然受限，请确保已彻底关闭公司 VPN 后重试。若仍不行，请仅使用「一键智能加速」。",
        detail: ["候选来源·优选缓存: 20.205.243.166", "候选 20.205.243.166: TCP 连接超时（IP 不可达或被防火墙/VPN 拦截）"] };
    }
    return { ok: true, reason: "", checked: 0, live: true, detail: null }; },
  GetProState: function () { return Promise.resolve(window.__state); },
  SetAutoHeal: function (on) { window.__calls.push(["SetAutoHeal", on]);
    window.__state.autoHeal = on; return Promise.resolve(window.__state); },
  SetDeepAccel: function (on, mode, compat, force) { window.__calls.push(["SetDeepAccel", on, mode, !!compat, !!force]);
    window.__state.deepCompat = on ? !!compat : window.__state.deepCompat;
    window.__state.deepAccel = on;
    window.__state.deepMode = on ? mode : "";
    window.__state.deepListen = on ? "127.0.0.1:18080" : "";
    return Promise.resolve(window.__state); },
  RefreshDeepPrecondition: function () { window.__calls.push(["RefreshDeepPrecondition"]);
    return window.__blocked ? { ok: false, reason: "当前网络环境依然受限，请确保已彻底关闭公司 VPN 后重试。若仍不行，请仅使用「一键智能加速」。",
      detail: ["候选 20.205.243.166: TCP 连接超时（IP 不可达或被防火墙/VPN 拦截）"] } : { ok: true, live: true }; },
  GetMachineCode: function () { return Promise.resolve("EE76C20B7DB8B9C9"); },
  ActivatePro: function () { return Promise.resolve(); },
  ClearLicense: function () { return Promise.resolve(); },
  RemoveHosts: function () { window.__calls.push(["RemoveHosts"]);
    window.__state.deepAccel = false; window.__state.autoHeal = false;
    return Promise.resolve(); },
  StartApply: function () { return Promise.resolve(); }
} } };
</script>
"""

DRIVER = r"""
<div id="__testlog" style="position:fixed;left:0;right:0;bottom:0;z-index:9999;
     font:11px Consolas,monospace;color:#fbbf24;background:rgba(0,0,0,.85);
     padding:4px 6px;white-space:pre-wrap;max-height:150px;overflow:auto"></div>
<script>
function __rect(id) {
  var el = document.getElementById(id);
  if (!el) return "MISSING";
  var r = el.getBoundingClientRect();
  return Math.round(r.left) + "," + Math.round(r.top) + " " +
         Math.round(r.width) + "x" + Math.round(r.height);
}
function __overlap(a, b) {
  var ra = document.getElementById(a).getBoundingClientRect();
  var rb = document.getElementById(b).getBoundingClientRect();
  return !(ra.right <= rb.left || rb.right <= ra.left ||
           ra.bottom <= rb.top || rb.bottom <= ra.top);
}
async function __run() {
  var out = [];
  // ===== 专项场景：预检失败弹窗（原因透明化 + 强制开启逃生通道）=====
  if (window.__blocked) {
    document.getElementById("deep-toggle").click();
    await __wait(600);
    out.push("blockedMask=" + document.getElementById("blocked-mask").className);
    out.push("blockedReason=" + document.getElementById("blocked-reason").textContent.slice(0, 30));
    out.push("blockedDetail=" + document.getElementById("blocked-detail").textContent.slice(0, 60));
    // 重新检测（网络体检）：mock 仍返回失败，弹窗内容应被刷新且不报错
    document.getElementById("blocked-refresh").click();
    await __wait(600);
    out.push("afterRefresh mask=" + document.getElementById("blocked-mask").className +
             " callsHasRefresh=" + JSON.stringify(window.__calls.some(function (c) { return c[0] === "RefreshDeepPrecondition"; })));
    // 强制开启 → 进模式窗且出现黄色警示条 → 确定 → 后端收到 force=true
    document.getElementById("blocked-force").click();
    await __wait(200);
    out.push("modeMaskAfterForce=" + document.getElementById("mode-mask").className +
             " forceNote=" + document.getElementById("mode-force-note").className);
    document.getElementById("mode-ok").click();
    await __wait(300);
    var setCalls = window.__calls.filter(function (c) { return c[0] === "SetDeepAccel"; });
    out.push("forceOn accel=" + window.__state.deepAccel +
             " setCalls=" + JSON.stringify(setCalls) +
             " statusTxt=" + JSON.stringify(document.getElementById("status-text").textContent));
    out.push("errors=" + (window.__errors.length ? window.__errors.join("|") : "NONE"));
    document.getElementById("__testlog").textContent = out.join("\n");
    return;
  }
  // ===== 常规主流程场景 =====
  out.push("pro-toggle=" + __rect("pro-toggle"));
  out.push("deep-toggle=" + __rect("deep-toggle"));
  out.push("restore-btn=" + __rect("restore-btn"));
  out.push("overlap=" + __overlap("pro-toggle", "deep-toggle"));

  // 点深度加速
  document.getElementById("deep-toggle").click();
  await __wait(250);

  if (window.__state.pro) {
    out.push("modeMask=" + document.getElementById("mode-mask").className);
    out.push("modeSel=" + document.getElementById("mode-auto").className + "/" +
             document.getElementById("mode-manual").className);
    // 兼容模式默认不勾选（配置未设默认开启）；点文字区应能切换勾选
    var cc = document.getElementById("compat-check");
    out.push("compatDefault=" + cc.checked);
    var row = document.getElementById("compat-row");
    row.querySelector(".d").click();   // 点说明文字（label 包裹后应联动）
    out.push("compatAfterTextClick=" + cc.checked);
    row.querySelector(".t").click();   // 点标题文字切回
    out.push("compatAfterTitleClick=" + cc.checked);
    // 选手动模式 → 确定
    document.getElementById("mode-manual").click();
    await __wait(120);
    out.push("afterPickSel=" + document.getElementById("mode-auto").className + "/" +
             document.getElementById("mode-manual").className);
    document.getElementById("mode-ok").click();
    await __wait(300);
    out.push("afterOn accel=" + window.__state.deepAccel +
             " mode=" + window.__state.deepMode +
             " cls=" + document.getElementById("deep-toggle").className +
             " txt=" + JSON.stringify(document.getElementById("deep-state").textContent));
    // 再点一次：应直接关闭，不弹模式窗
    document.getElementById("deep-toggle").click();
    await __wait(300);
    out.push("afterOff accel=" + window.__state.deepAccel +
             " mask=" + document.getElementById("mode-mask").className +
             " txt=" + JSON.stringify(document.getElementById("deep-state").textContent));
    // 自愈开关不应串台
    document.getElementById("pro-toggle").click();
    await __wait(250);
    out.push("heal=" + window.__state.autoHeal +
             " healCls=" + document.getElementById("pro-toggle").className +
             " deepCls=" + document.getElementById("deep-toggle").className);
  } else {
    out.push("proMask=" + document.getElementById("pro-mask").className);
  }

  // 一键还原网络：确认框 + 确认
  document.getElementById("restore-btn").click();
  await __wait(150);
  var maskCls = document.getElementById("modal-mask").className;
  document.getElementById("modal-yes").click();
  await __wait(250);
  out.push("restoreMaskBefore=" + maskCls + " calls=" + JSON.stringify(window.__calls));
  out.push("errors=" + (window.__errors.length ? window.__errors.join("|") : "NONE"));
  document.getElementById("__testlog").textContent = out.join("\n");
}
setTimeout(__run, 350);
</script>
"""


def build_page(pro, blocked=False):
    with open(SRC, "r", encoding="utf-8") as f:
        html = f.read()
    mock = MOCK.replace("__PRO__", "true" if pro else "false")
    mock = mock.replace("__BLOCKED__", "true" if blocked else "false")
    marker = "  <script>\n    // ===== 基础引用 ====="
    if marker not in html:
        raise SystemExit("找不到主脚本插入点，index.html 结构变了？")
    html = html.replace(marker, mock + marker, 1)
    html = html.replace("</body>", DRIVER + "</body>", 1)
    name = "ui_pro" if pro else "ui_free"
    if blocked:
        name = "ui_blocked"
    path = os.path.join(OUT_DIR, name + ".html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


def find_browser():
    for p in BROWSERS:
        if os.path.exists(p):
            return p
    raise SystemExit("没找到 Chrome/Edge，无法做界面烟测")


def shoot(browser, page, png):
    profile = tempfile.mkdtemp(prefix="ghsmart-ui-")
    cmd = [
        browser,
        "--headless=new",
        "--disable-gpu",
        "--hide-scrollbars",
        "--no-first-run",
        "--user-data-dir=" + profile,
        "--window-size=760,720",
        "--virtual-time-budget=6000",
        "--screenshot=" + png,
        "file:///" + page.replace("\\", "/"),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    shutil.rmtree(profile, ignore_errors=True)
    if not os.path.exists(png):
        print(r.stdout[-2000:])
        print(r.stderr[-2000:])
        raise SystemExit("截图失败")


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    browser = find_browser()
    for pro in (False, True):
        page = build_page(pro)
        png = os.path.join(OUT_DIR, "ui_pro.png" if pro else "ui_free.png")
        shoot(browser, page, png)
        print("OK ->", png)
    # 专项：预检失败弹窗（原因透明化 + 重新检测 + 强制开启）
    page = build_page(True, blocked=True)
    png = os.path.join(OUT_DIR, "ui_blocked.png")
    shoot(browser, page, png)
    print("OK ->", png)
    return 0


if __name__ == "__main__":
    sys.exit(main())
