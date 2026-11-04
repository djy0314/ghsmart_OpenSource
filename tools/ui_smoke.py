# -*- coding: utf-8 -*-
"""ghsmart 界面烟测（不需要 WebView2 / 不需要管理员）：

把 frontend/dist/index.html 复制一份，在页面脚本前注入 Wails 绑定 mock，
再用无头浏览器真实渲染 + 真实点击，把断言画在页面上并截图。

v1.0.4 起验证的是「极简交互」：
  1. 点「深度网页加速」= 直接开，禁止出现任何模式选择弹窗 / 预检拦截弹窗
  2. 界面里根本不存在 mode-mask / blocked-mask / 兼容勾选 / 网络急救按钮
  3. 状态栏文案：已开启 → 降级后「已开启 · 智能降级」
  4. 降级事件只让顶部灰条出现，不弹红色错误
  5. Free 用户点深度加速仍走 Pro 解锁框（唯一允许的弹窗）
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
window.__handlers = {};
window.__state = { pro: __PRO__, autoHeal: false, deepAccel: false, deepListen: "",
                   deepDegraded: false, deepMode: "" };
window.__wait = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };
function __log(msg) {
  window.__errors.push(msg);
  var d = document.getElementById("__testlog");
  if (d) d.textContent = window.__errors.join(" || ");
}
window.addEventListener("error", function (e) { __log("JS ERROR: " + e.message); });
window.addEventListener("unhandledrejection", function (e) { __log("REJECT: " + e.reason); });
window.runtime = {
  EventsOn: function (name, cb) {
    (window.__handlers[name] = window.__handlers[name] || []).push(cb);
  }
};
window.__fire = function (name, payload) {
  (window.__handlers[name] || []).forEach(function (f) { f(payload || {}); });
};
window.go = { main: { App: {
  IsElevated: function () { return Promise.resolve(true); },
  GetAppliedEntries: function () { return Promise.resolve({ "github.com": "20.205.243.166" }); },
  GetProState: function () { return Promise.resolve(window.__state); },
  SetAutoHeal: function (on) { window.__calls.push(["SetAutoHeal", on]);
    window.__state.autoHeal = on; return Promise.resolve(window.__state); },
  SetDeepAccel: function (on) { window.__calls.push(["SetDeepAccel", on]);
    if (!on) {
      // 模拟「后端还原注册表被 VPN / 安全软件卡住」：800ms 后才返回，
      // 期间 __state 仍是开启 —— 前端若不乐观更新，界面就会一直显示已开启。
      return new Promise(function (res) {
        setTimeout(function () {
          window.__state.deepAccel = false;
          window.__state.deepDegraded = false;
          window.__state.deepListen = "";
          window.__slowResolved = true;
          res(window.__state);
        }, 800);
      });
    }
    window.__state.deepAccel = on;
    window.__state.deepDegraded = false;
    window.__state.deepListen = on ? "127.0.0.1:18080" : "";
    return Promise.resolve(window.__state); },
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
     padding:4px 6px;white-space:pre-wrap;max-height:170px;overflow:auto"></div>
<script>
function __rect(id) {
  var el = document.getElementById(id);
  if (!el) return "MISSING";
  var r = el.getBoundingClientRect();
  return Math.round(r.left) + "," + Math.round(r.top) + " " +
         Math.round(r.width) + "x" + Math.round(r.height);
}
function __absent(id) { return document.getElementById(id) === null; }
async function __run() {
  var out = [];
  // 极简性硬断言：这些元素必须彻底不存在
  out.push("gone.modeMask=" + __absent("mode-mask") +
           " gone.blocked=" + __absent("blocked-mask") +
           " gone.compat=" + __absent("compat-check") +
           " gone.firstaid=" + __absent("firstaid-btn") +
           " gone.forceBar=" + __absent("force-bar"));
  out.push("hintBar=" + !__absent("hint-bar") + " rect=" + __rect("hint-bar"));
  out.push("restore-btn=" + __rect("restore-btn") + " deep-toggle=" + __rect("deep-toggle"));

  // 点深度加速
  document.getElementById("deep-toggle").click();
  await __wait(400);

  if (window.__state.pro) {
    var calls = window.__calls.filter(function (c) { return c[0] === "SetDeepAccel"; });
    out.push("pro: calls=" + JSON.stringify(calls) +
             " accel=" + window.__state.deepAccel +
             " 文本=" + JSON.stringify(document.getElementById("deep-state").textContent) +
             " 状态=" + JSON.stringify(document.getElementById("status-text").textContent));
    out.push("pro: 遮罩残留=" + !__absent("mode-mask") + "/" + !__absent("blocked-mask"));

    // 模拟代理层静默降级
    window.__fire("deep:degraded", { reason: "test" });
    await __wait(200);
    out.push("降级后: 文本=" + JSON.stringify(document.getElementById("deep-state").textContent) +
             " 灰条=" + document.getElementById("hint-bar").className +
             " 文案=" + JSON.stringify(document.getElementById("hint-bar").textContent));

    // 再点一次 → 关闭：乐观更新必须在 120ms 内让界面变灰（后端此刻还没返回）
    window.__slowResolved = false;
    document.getElementById("deep-toggle").click();
    await __wait(120);
    var dt = document.getElementById("deep-toggle");
    out.push("关闭@120ms: 后端已返回=" + !!window.__slowResolved +
             " 界面文本=" + JSON.stringify(document.getElementById("deep-state").textContent) +
             " 开关on=" + dt.classList.contains("on") +
             " 状态=" + JSON.stringify(document.getElementById("status-text").textContent) +
             " toast=" + JSON.stringify(document.getElementById("toast").textContent));

    // 等后端真正返回，再触发「还原完成」事件
    await __wait(1000);
    window.__fire("deep:closed", { ok: true, ms: 842, skipped: false });
    await __wait(250);
    out.push("关闭完成: accel=" + window.__state.deepAccel +
             " 文本=" + JSON.stringify(document.getElementById("deep-state").textContent) +
             " 状态=" + JSON.stringify(document.getElementById("status-text").textContent) +
             " toast=" + JSON.stringify(document.getElementById("toast").textContent) +
             " 灰条=" + document.getElementById("hint-bar").className);

    // 自愈开关不串台
    document.getElementById("pro-toggle").click();
    await __wait(300);
    out.push("自愈=" + window.__state.autoHeal +
             " 深度类=" + document.getElementById("deep-toggle").className);
  } else {
    out.push("free: 应弹 Pro 解锁框 mask=" + document.getElementById("pro-mask").className);
  }

  // 一键还原网络
  document.getElementById("restore-btn").click();
  await __wait(200);
  var maskCls = document.getElementById("modal-mask").className;
  document.getElementById("modal-yes").click();
  await __wait(300);
  out.push("restore: 确认前=" + maskCls + " calls=" + JSON.stringify(window.__calls));
  out.push("errors=" + (window.__errors.length ? window.__errors.join("|") : "NONE"));
  document.getElementById("__testlog").textContent = out.join("\n");
}
setTimeout(__run, 350);
</script>
"""


def build_page(pro):
    with open(SRC, "r", encoding="utf-8") as f:
        html = f.read()
    mock = MOCK.replace("__PRO__", "true" if pro else "false")
    marker = "  <script>\n    // ===== 基础引用 ====="
    if marker not in html:
        raise SystemExit("找不到主脚本插入点，index.html 结构变了？")
    html = html.replace(marker, mock + marker, 1)
    html = html.replace("</body>", DRIVER + "</body>", 1)
    name = "ui_pro" if pro else "ui_free"
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
        "--virtual-time-budget=8000",
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
