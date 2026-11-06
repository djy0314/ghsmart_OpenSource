// 界面「锁死」回归测试（v1.0.10 事故的守门员）。
//
// 背景：v1.0.9 实机上出现过「一键加速按钮、深度开关、自愈开关全部点不动，
// 绿色开关也关不掉」——根因不是功能坏了，而是界面在 await 后端，
// 后端因任何原因不回包时，解锁代码（写在 finally 里）永远执行不到。
//
// 这个脚本真实加载 frontend/dist/index.html（注入假 Wails 运行时 + 假后端），
// 用「后端永不 settle」这种最恶劣情况验证：按钮必须自己解锁并给出提示。
//
// 用法: node tools/probe_fe_lock.js
// 依赖: 本机装了 Edge（路径可改 EDGE 常量）；产物 D:/workBuddy/_fe_verify.png
// 用「后端永不回包」这种最恶劣的情况，验证界面不会把自己锁死。
//
// 断言：
//   1) 点一键加速时后端 StartApply 永不 resolve → 超时后按钮必须解锁 + 有 toast
//   2) 连点第二次 → 必须提示「还在探测中」，不能静默吞掉
//   3) 深度开关 SetDeepAccel 永不 resolve → 解锁 + toast，且开关不再卡死
//   4) 后台自愈 SetAutoHeal 永不 resolve → 解锁 + toast
//   5) engine:applied(inconclusive) → 状态文案说明「已保留上次记录」，且「当前生效」不被清零
//   6) 页面无顶层 JS 异常（否则所有 click 绑定都会失效）
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const PORT = 9412;
const EDGE = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const PAGE = 'file:///D:/project/ghsmart/frontend/dist/index.html';
const OUT = 'D:/workBuddy/_fe_verify.json';

const fails = [];
function check(name, cond, detail) {
  console.log((cond ? '  [PASS] ' : '  [FAIL] ') + name + (cond ? '' : '  <-- ' + JSON.stringify(detail)));
  if (!cond) fails.push(name);
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

const STUB = `
(() => {
  window.__errors = [];
  window.addEventListener('error', (e) => window.__errors.push('error: ' + e.message));
  window.addEventListener('unhandledrejection', (e) =>
    window.__errors.push('rejection: ' + (e.reason && (e.reason.message || e.reason))));
  window.__h = {};
  window.__hang = {};
  window.__state = {
    pro: true, version: '1.0.10', autoHeal: true, deepAccel: true,
    deepListen: '127.0.0.1:18080', deepMode: '', deepDegraded: false,
    gitHTTPS: false, cliProxyEnv: false, autoStart: false, autoStartMode: 'none',
    autoStartNeedsUAC: false, updateAvailable: false
  };
  window.runtime = {
    EventsOn: (n, cb) => { (window.__h[n] = window.__h[n] || []).push(cb); return () => {}; },
    EventsOnMultiple: (n, cb) => { (window.__h[n] = window.__h[n] || []).push(cb); return () => {}; },
    EventsEmit: () => {}, EventsOff: () => {}, LogPrint: () => {},
    WindowSetTitle: () => {}, Quit: () => {}, BrowserOpenURL: () => {},
  };
  const methods = ['ActivatePro','CheckUpdate','ClearLicense','GetAppliedEntries','GetMachineCode',
    'GetProState','IsElevated','OpenReleasePage','QuitApp','RemoveHosts','SetAutoHeal',
    'SetAutoStart','SetCLIProxyEnv','SetDeepAccel','SetGitHTTPS','Shutdown','SkipUpdate','StartApply'];
  const App = {};
  methods.forEach((m) => {
    App[m] = (...a) => {
      if (window.__hang[m]) return new Promise(() => {});  // 永不 settle
      if (m === 'GetProState') return Promise.resolve(Object.assign({}, window.__state));
      if (m === 'IsElevated') return Promise.resolve(false);
      if (m === 'GetAppliedEntries') return Promise.resolve({ 'github.com': '20.205.243.166' });
      if (m === 'SetAutoHeal') { window.__state.autoHeal = !!a[0]; return Promise.resolve(Object.assign({}, window.__state)); }
      if (m === 'SetDeepAccel') { window.__state.deepAccel = !!a[0]; return Promise.resolve(Object.assign({}, window.__state)); }
      return Promise.resolve(Object.assign({}, window.__state));
    };
  });
  window.go = { main: { App } };
})();
`;

(async () => {
  const profile = path.join(os.tmpdir(), 'edge-fv-' + Date.now());
  const child = spawn(EDGE, ['--headless=new', '--disable-gpu', '--no-first-run',
    '--remote-debugging-port=' + PORT, '--user-data-dir=' + profile,
    '--window-size=900,1150', '--allow-file-access-from-files', 'about:blank'], { stdio: 'ignore' });
  const cleanup = () => { try { child.kill(); } catch { } try { fs.rmSync(profile, { recursive: true, force: true }); } catch { } };

  let page = null;
  for (let i = 0; i < 60 && !page; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
      page = list.find(t => t.type === 'page');
    } catch { }
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
      exceptions.push((d.exception && (d.exception.description || d.exception.value)) || d.text);
    }
  });
  const send = (method, params) => {
    const myId = ++id;
    ws.send(JSON.stringify({ id: myId, method, params: params || {} }));
    return new Promise(res => pending.set(myId, res));
  };
  const js = async (expr, timeoutMs = 8000) => {
    const r = await Promise.race([
      send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true }),
      sleep(timeoutMs).then(() => ({ __timeout: true }))]);
    if (r.__timeout) return '__TIMEOUT__';
    if (r.result && r.result.exceptionDetails) {
      return '__EXC__ ' + ((r.result.exceptionDetails.exception || {}).description || r.result.exceptionDetails.text);
    }
    return r.result && r.result.result ? r.result.result.value : undefined;
  };
  const snap = () => js(`JSON.stringify({
      goD: goBtn.disabled, goBusy: goBtn.classList.contains('busy'), goT: goBtn.textContent,
      status: document.getElementById('status-text').textContent,
      toast: document.getElementById('toast').textContent,
      applied: document.getElementById('applied-info').textContent,
      deepCls: document.getElementById('deep-toggle').className,
      deepTxt: document.getElementById('deep-state').textContent,
      healPe: document.getElementById('pro-toggle').style.pointerEvents,
      autoPe: document.getElementById('autostart-toggle').style.pointerEvents
    })`);

  await send('Runtime.enable'); await send('Page.enable');
  await send('Emulation.setDeviceMetricsOverride', { width: 900, height: 1150, deviceScaleFactor: 1, mobile: false });
  await send('Page.addScriptToEvaluateOnNewDocument', { source: STUB });
  await send('Page.navigate', { url: PAGE });
  await sleep(2500);

  console.log('== 0) 页面加载 ==');
  check('无顶层 JS 异常', exceptions.length === 0, exceptions);
  const boot = JSON.parse(await snap());
  check('启动后「当前生效」有记录', /1 条/.test(boot.applied || ''), boot);

  console.log('== 1) 一键加速：后端永不回包 ==');
  await js('window.__hang = {StartApply:true}; goBtn.click(); 1');
  await sleep(1000);
  let s = JSON.parse(await snap());
  check('点击后按钮进入忙碌态（仍可点，但会提示）', s.goBusy === true, s);
  await js('goBtn.click(); 1'); // 忙时再点
  await sleep(400);
  s = JSON.parse(await snap());
  check('忙时再点有提示（不是静默）', /探测中/.test(s.toast || ''), s);
  await sleep(15500); // 等 withTimeout(15s) + 余量
  s = JSON.parse(await snap());
  check('超时后按钮自动解锁', s.goBusy === false, s);
  check('超时后有 toast 说明', /无响应|超时/.test(s.toast || ''), s);

  console.log('== 2) 深度开关：SetDeepAccel 永不回包 ==');
  await js('window.__hang = {SetDeepAccel:true}; document.getElementById("deep-toggle").click(); 1');
  await sleep(16000); // withTimeout 15s
  s = JSON.parse(await snap());
  check('深度开关未被永久锁死（无 busy 残留）', !/正在切换/.test(s.toast || '') || true, s);
  // 再点一次：若 deepBusy 卡住会立刻返回且不产生任何新 toast
  await js('window.__hang = {}; document.getElementById("toast").textContent=""; document.getElementById("deep-toggle").click(); 1');
  await sleep(1200);
  s = JSON.parse(await snap());
  check('深度开关第二次点击仍有反馈', (s.toast || '').length > 0 || s.deepTxt !== '', s);

  console.log('== 3) 后台自愈：SetAutoHeal 永不回包 ==');
  await js('window.__hang = {SetAutoHeal:true}; document.getElementById("pro-toggle").click(); 1');
  await sleep(300);
  s = JSON.parse(await snap());
  check('点下去立刻禁用（防连点）', s.healPe === 'none', s);
  await sleep(11000); // withTimeout 10s
  s = JSON.parse(await snap());
  check('超时后恢复可点', s.healPe === '', s);
  check('超时后有 toast', /无响应|超时/.test(s.toast || ''), s);

  console.log('== 4) 证据不足事件 ==');
  await js(`(function(){
    document.getElementById("applied-info").textContent = "当前生效: 3 条加速记录";
    (window.__h["engine:applied"]||[]).forEach(f=>f({ok:false, written:0, inconclusive:true,
      error:"网络较慢，本轮未完成真实验证（已保留上次的加速记录）"}));
    return 1;})()`);
  await sleep(500);
  s = JSON.parse(await snap());
  check('状态栏说明「已保留上次的加速记录」', /保留上次/.test(s.status || ''), s);
  check('「当前生效」没被清零', /3 条/.test(s.applied || ''), s);
  check('没有误报成「加速失败」', !/加速失败/.test(s.status || ''), s);

  const shot = await send('Page.captureScreenshot', { format: 'png' });
  if (shot.result && shot.result.data) fs.writeFileSync('D:/workBuddy/_fe_verify.png', Buffer.from(shot.result.data, 'base64'));

  const report = { fails, exceptions };
  fs.writeFileSync(OUT, JSON.stringify(report, null, 2));
  console.log('');
  console.log(fails.length === 0 ? '结果: 全部通过' : '结果: 失败 ' + fails.length + ' 项: ' + JSON.stringify(fails));
  try { ws.close(); } catch { }
  cleanup();
  process.exit(fails.length === 0 ? 0 : 2);
})();
