// 绑定注入回归测试（v1.0.11 实机事故的守门员）。
//
// 事故：页面脚本顶层写死 `const app = window.go.main.App`。
// Wails 的绑定注入只要比页面脚本晚一步，app 就被永久固化为 undefined，
// 所有按钮报 "Cannot read properties of undefined (reading 'XXX')"，
// 而后端其实活着（日志正常、事件正常），用户看到的是「软件全废」。
//
// 本探针真实加载 frontend/dist/index.html，用 4 种最恶劣的注入时序验证：
//   late       绑定晚到 500ms（竞态）
//   obfuscated 绑定对象名不叫 App（混淆改名）
//   never      绑定根本不来
//   nort       连 window.runtime 都没有
// 并把修复前的旧文件当对照组跑一遍，实证旧代码确实会复现号主截图里的报错。
//
// 用法: node tools/probe_fe_binding.js [可选: 另一个 html 的绝对路径]
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const PORT = 9413;
const EDGE = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const PAGE = process.argv[2]
  ? 'file:///' + process.argv[2].replace(/\\/g, '/')
  : 'file:///D:/project/ghsmart/frontend/dist/index.html';
const IS_OLD = !!process.argv[2];

const fails = [];
function check(name, cond, detail) {
  console.log((cond ? '  [PASS] ' : '  [FAIL] ') + name + (cond ? '' : '  <-- ' + JSON.stringify(detail)));
  if (!cond) fails.push(name);
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

const STUB = `
(() => {
  const sc = new URLSearchParams(location.search).get('s') || 'late';
  window.__errors = [];
  window.addEventListener('error', (e) => window.__errors.push('error: ' + e.message));
  window.addEventListener('unhandledrejection', (e) =>
    window.__errors.push('rejection: ' + (e.reason && (e.reason.message || e.reason))));
  window.__calls = {};
  window.__state = {
    pro: true, version: '1.0.11', autoHeal: true, deepAccel: true,
    deepListen: '127.0.0.1:18080', deepMode: '', deepDegraded: false,
    gitHTTPS: false, cliProxyEnv: false, autoStart: false, autoStartMode: 'none',
    autoStartNeedsUAC: false, updateAvailable: false
  };
  window.__makeApp = function () {
    const App = {};
    const methods = ['ActivatePro','CheckUpdate','ClearLicense','GetAppliedEntries','GetMachineCode',
      'GetProState','IsElevated','OpenReleasePage','QuitApp','RemoveHosts','SetAutoHeal',
      'SetAutoStart','SetCLIProxyEnv','SetDeepAccel','SetGitHTTPS','Shutdown','SkipUpdate','StartApply'];
    methods.forEach((m) => {
      App[m] = (...a) => {
        window.__calls[m] = (window.__calls[m] || 0) + 1;
        if (m === 'GetProState') return Promise.resolve(Object.assign({}, window.__state));
        if (m === 'IsElevated') return Promise.resolve(false);
        if (m === 'GetAppliedEntries') return Promise.resolve({'github.com':'20.27.177.113'});
        if (m === 'SetAutoHeal') { window.__state.autoHeal = !!a[0]; }
        if (m === 'SetDeepAccel') { window.__state.deepAccel = !!a[0]; }
        return Promise.resolve(Object.assign({}, window.__state));
      };
    });
    return App;
  };
  if (sc !== 'nort') {
    window.runtime = {
      EventsOn: () => () => {}, EventsOnMultiple: () => () => {},
      EventsEmit: () => {}, EventsOff: () => {}, LogPrint: () => {},
      WindowSetTitle: () => {}, Quit: () => {}, BrowserOpenURL: () => {},
    };
  }
  if (sc === 'obfuscated') {
    // 混淆把 App 改名：绑定对象不叫 App，但方法都在
    window.go = { main: { Zq9Xk2: window.__makeApp() } };
  } else if (sc === 'never') {
    window.go = { main: {} };
  } else if (sc === 'late') {
    // 文档创建时绑定还没到；由探针在 500ms 后补注入，模拟 Wails 竞态
  }
})();
`;

(async () => {
  const profile = path.join(os.tmpdir(), 'edge-bind-' + Date.now());
  const child = spawn(EDGE, ['--headless=new', '--disable-gpu', '--no-first-run',
    '--remote-debugging-port=' + PORT, '--user-data-dir=' + profile,
    '--window-size=900,1150', '--allow-file-access-from-files', 'about:blank'], { stdio: 'ignore' });
  const cleanup = () => { try { child.kill(); } catch {} try { fs.rmSync(profile, { recursive: true, force: true }); } catch {} };

  let page = null;
  for (let i = 0; i < 60 && !page; i++) {
    try { const list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json(); page = list.find(t => t.type === 'page'); } catch {}
    if (!page) await sleep(300);
  }
  if (!page) { console.log('NO TARGET'); cleanup(); process.exit(2); }

  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise(res => ws.addEventListener('open', res));
  let id = 0; const pending = new Map(); const exceptions = [];
  ws.addEventListener('message', ev => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
    if (m.method === 'Runtime.exceptionThrown') {
      const d = m.params.exceptionDetails;
      const desc = (d.exception && (d.exception.description || d.exception.value)) || d.text;
      // 后端未就绪时 backend() 主动抛错属于预期行为（已有 toast），不算顶层异常
      if (!/后端尚未就绪/.test(String(desc))) exceptions.push(desc);
    }
  });
  const send = (method, params) => {
    const myId = ++id;
    ws.send(JSON.stringify({ id: myId, method, params: params || {} }));
    return new Promise(res => pending.set(myId, res));
  };
  const js = async (expr) => {
    const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
    if (r.result && r.result.exceptionDetails) {
      return '__EXC__ ' + ((r.result.exceptionDetails.exception || {}).description || r.result.exceptionDetails.text);
    }
    return r.result && r.result.result ? r.result.result.value : undefined;
  };
  const snap = () => js(`JSON.stringify({
      status: (document.getElementById('status-text')||{}).textContent,
      toast: (document.getElementById('toast')||{}).textContent,
      calls: window.__calls || {},
      errs: window.__errors || []
    })`);
  const load = async (sc, lateInject) => {
    exceptions.length = 0;
    await send('Page.navigate', { url: PAGE + '?s=' + sc + '&_=' + Date.now() });
    await sleep(550);
    if (lateInject) await js('window.go = { main: { App: window.__makeApp() } }; 1');
    await sleep(1000);
    return JSON.parse(await snap());
  };

  await send('Runtime.enable'); await send('Page.enable');
  await send('Emulation.setDeviceMetricsOverride', { width: 900, height: 1150, deviceScaleFactor: 1, mobile: false });
  await send('Page.addScriptToEvaluateOnNewDocument', { source: STUB });

  console.log('目标页面: ' + PAGE + (IS_OLD ? '  (修复前对照组)' : ''));

  console.log('== 1) 绑定晚到 500ms（竞态复现）==');
  let s;
  if (IS_OLD) {
    // 对照组：window.go.main 存在但 App 没注入，正是号主实机那一刻的状态。
    // 旧代码把 undefined 固化进顶层常量，点「开机自启」就会复现截图里的红字。
    s = await load('never', false);
    await js('document.getElementById("autostart-toggle").click(); 1');
    await sleep(400);
    s = JSON.parse(await snap());
    check('[对照] 旧代码复现号主报错 reading SetAutoStart',
      /Cannot read properties of undefined \(reading 'SetAutoStart'\)/.test((s.toast || '') + (s.status || '')), s);
    check('[对照] 旧代码状态栏被错误占据', /Cannot read properties/.test(s.status || ''), s);
  } else {
    s = await load('late', true);
    check('状态栏显示后端已连接', /后端已连接|加速已生效/.test(s.status || ''), s);
    await js('document.getElementById("go-btn").click(); 1');
    await sleep(600);
    s = JSON.parse(await snap());
    check('一键加速真的调到了 StartApply', (s.calls.StartApply || 0) >= 1, s);
    check('无顶层 JS 异常', exceptions.length === 0 && (s.errs || []).length === 0, { exceptions, errs: s.errs });
  }

  console.log('== 2) 绑定对象名被混淆（不叫 App）==');
  s = await load('obfuscated', false);
  if (!IS_OLD) {
    check('按能力找到绑定对象', /后端已连接|加速已生效/.test(s.status || ''), s);
    await js('document.getElementById("go-btn").click(); 1');
    await sleep(600);
    s = JSON.parse(await snap());
    check('改名后仍能调用 StartApply', (s.calls.StartApply || 0) >= 1, s);
  }

  console.log('== 3) 绑定根本不来 ==');
  s = await load('never', false);
  if (!IS_OLD) {
    await js('document.getElementById("toast").textContent=""; document.getElementById("go-btn").click(); 1');
    await sleep(400);
    s = JSON.parse(await snap());
    check('点按钮有 Toast（不是静默）', /后端尚未就绪/.test(s.toast || ''), s);
    check('按钮没有 disabled 锁死', await js('document.getElementById("go-btn").disabled') === false, s);
    await sleep(12500);
    s = JSON.parse(await snap());
    check('超时后状态栏写明未就绪', /后端未就绪/.test(s.status || ''), s);
  }

  console.log('== 4) 连 window.runtime 都没有 ==');
  s = await load('nort', false);
  if (!IS_OLD) {
    check('页面脚本没崩', exceptions.length === 0, exceptions);
    await js('document.getElementById("toast").textContent=""; document.getElementById("go-btn").click(); 1');
    await sleep(400);
    s = JSON.parse(await snap());
    check('点按钮仍有 Toast', (s.toast || '').length > 0, s);
  }

  console.log('');
  console.log(fails.length === 0 ? '结果: 全部通过' : '结果: 失败 ' + fails.length + ' 项: ' + JSON.stringify(fails));
  try { ws.close(); } catch {}
  cleanup();
  process.exit(fails.length === 0 ? 0 : 2);
})();
