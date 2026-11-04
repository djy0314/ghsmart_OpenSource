# ghsmart

纯本地运行的 GitHub 访问智能优选。不运营任何代理或中转服务——所有加速均通过
**DoH 解析 → 多 IP 探测 → 评分决策 → 原子化更新系统 Hosts** 完成，零后端、零运营成本。

提供两种形态，共用同一内核（`internal/engine`）：

- **GUI 版**（Wails v2）：双击即用，UAC 自动提权，一键加速 + 托盘常驻
- **CLI 版**：`cmd/ghsmart`，适合脚本与服务器场景

## ⚠️ 安全提示

本软件完全免费且纯本地运行，绝无任何后门。官方发布渠道是我的个人小站 ([https://tools.zf314.cn/](https://tools.zf314.cn/)，含网盘下载地址) 和本 GitHub 仓库的 Releases 页面。如果您从其他第三方网站下载，请自行甄别风险。

## 🚀 普通用户下载

不需要懂代码！请点击右侧的 **[Releases](https://github.com/djy0314/ghsmart_OpenSource/releases)** 页面，下载最新的 `ghsmart_v1.0.2.zip`，解压后双击 `ghsmart.exe` 即用（单文件，无安装、无依赖）。官方发布包提供 SHA-256 校验值。

## GUI 版（推荐小白使用）

```bash
wails build        # 产物: build/bin/ghsmart.exe（单文件，前端已内嵌）
```

功能：

- 双击启动自动弹出 UAC 提权（`build/windows/wails.exe.manifest` 配置 `requireAdministrator`）
- 「🚀 一键智能加速」：探测过程经 Wails Events 实时推送到界面，逐域名滚动显示评分表
- 「🧹 恢复系统 Hosts」：强制二次确认后移除 ghsmart 区块，绝不触碰用户其他内容
- 点 X 关闭窗口缩到系统托盘；托盘右键菜单：显示主界面 / 一键加速 / 恢复 Hosts / 退出
- 「⚡ 后台自动自愈 (Pro)」为锁定占位（`internal/license` 接口预留，当前全走 Free）

## 架构

| 模块 | 职责 |
|------|------|
| `internal/doh` | 通过公共 DoH 端点（Cloudflare / Google / 阿里）解析域名，不内置任何写死的 IP |
| `internal/probe` | 对候选 IP 并发探测：TCP 连接、TLS 握手（校验证书链与 SAN）、HTTP HEAD 首字节 |
| `internal/decision` | 评分决策、连续失败 2 次进入 10 分钟冷却、15% 迟滞防抖；状态持久化到 `~/.ghsmart/state.json` |
| `internal/engine` | 编排内核：解析→探测→决策→写 Hosts 全流程，CLI 与 GUI 共用，经 `Reporter` 接口上报事件 |
| `internal/executor` | Hosts 区块原子化管理（`# ghsmart begin/end`）、DNS 缓存刷新、Git 配置占位（Phase 2） |
| `internal/config` | YAML 配置加载与默认值 |
| `internal/license` | 授权校验接口占位（Phase 4 替换） |

评分公式：`Score = 0.4×TCP(ms) + 0.4×TLS(ms) + 0.2×HTTP(ms)`，数值越低越好。

## 构建与运行

依赖 Go 1.21+：

```bash
go build ./...
go build -o ghsmart.exe ./cmd/ghsmart   # 或 go run ./cmd/ghsmart ...
go test ./...
```

## 子命令用法

### `ghsmart probe`

解析配置中每个域名的候选 IP，并发探测后打印评分表，**不写 Hosts**：

```
Domain: github.com
IP              TCP(ms)  TLS(ms)  HTTP(ms)  Score   OK
20.205.243.166  109      130      119       119.4   true
Best: 20.205.243.166
```

### `ghsmart apply`

探测 → 选优 → 写入系统 Hosts 的 `# ghsmart begin/end` 区块 → 刷新 DNS 缓存。
**需要管理员 / root 权限**，权限不足会提示「请以管理员身份运行」。

- 只管理 ghsmart 区块，绝不修改用户其他内容
- 写入前自动备份原文件到 `~/.ghsmart/hosts.bak`
- 临时文件 + 原子重命名写入；Windows 下重命名失败回退为直接覆盖并提示
- 重复执行不会产生重复区块

### `ghsmart daemon`

先执行一次 apply，然后按配置的 `interval` 循环执行 probe + decision + apply，
每轮打印时间戳与当前选中 IP。`Ctrl+C` 优雅退出（Hosts 区块保留）。

### `ghsmart remove`

删除 Hosts 中的 ghsmart 区块并刷新 DNS（附加命令，便于一键还原）。

## 权限说明

| 操作 | 权限要求 |
|------|----------|
| probe | 普通用户即可 |
| apply / daemon / remove | Windows 需管理员；macOS/Linux 需 root（macOS 刷新 DNS 额外需要 `sudo` 权限） |

## 配置说明

默认读取 `configs/default.yaml`，可用 `-c` 指定其他路径：

```yaml
doh_endpoints:        # DoH 端点列表，按序容错（随机起点轮询）
  - https://cloudflare-dns.com/dns-query
  - https://dns.google/dns-query
  - https://dns.alidns.com/dns-query
domains:              # 需要优选的域名
  - github.com
  - assets-cdn.github.com
  - github.global.ssl.fastly.net
  - raw.githubusercontent.com
  - objects.githubusercontent.com
probe_timeout: 5s     # 单 IP 探测超时
interval: 10m         # daemon 轮询间隔
max_concurrent: 10    # 探测最大并发
```

## 数据文件（均在 `~/.ghsmart/`）

- `state.json` — 决策状态（失败计数、冷却期、在用 IP），daemon 跨重启沿用
- `hosts.bak` — 每次 apply/remove 前的 Hosts 备份
- `cache.json` — 最优 IP 缓存（秒应用机制：打开软件/点加速时先写 Hosts 立即可用，再后台重探测校验更优 IP；72 小时后过期；「一键还原网络」会清空）

## 常见问题（FAQ）

### 开着深信服 aTrust / 公司 VPN 时，深度网页加速报 ERR_CONNECTION_CLOSED？

根因：VPN 的虚拟网卡改写了系统默认路由，ghsmart 本地代理发往优选 IP 的流量被引到公司防火墙并重置。

应对（按优先级）：
1. 深度加速已内置**物理网卡绑定竞速**：自动探测物理网卡的 IPv4，拨号时附带「绑定源地址」的入口强制从物理网卡出去，绕开虚拟网卡路由。多数情况下无感修复。
2. 在「深度网页加速」开启弹窗里勾选**兼容模式（公司 VPN 环境）**：不做 TLS 分片，只做基础 HTTP CONNECT 隧道（公司防火墙会把分片的握手判为异常流量）。也可在 `configs/default.yaml` 里设 `web_proxy.compat_mode: true`。
3. **最优先保底方案**：如果以上仍不行，请勿在公司 VPN 环境下同时开启深度网页加速，仅使用「一键智能加速」（Hosts 模式）即可——它不经过本地代理，与 VPN 无冲突。

### 点了「一键智能加速」后网页还是打不开？

加速已生效，但浏览器和系统各有自己的 DNS 缓存：请按 **Ctrl+F5** 强制刷新页面，或重启浏览器。

## 已知限制

- 部分地区无法直连 Cloudflare/Google DoH，程序会自动尝试下一个端点（阿里 DoH 通常可用）
- 被污染的解析结果（指向无效 IP）会被探测环节天然淘汰，无需额外处理

## 关于作者 & 更多作品

如果你觉得这个工具对你有帮助，欢迎访问我的个人小站 [https://tools.zf314.cn/](https://tools.zf314.cn/) 逛逛，里面有我写的其他免费小工具，例如：

- **NetEye**：绿色单文件的 Windows 网络连接查看器，替代资源监视器里不好用的网络页
- **LAN快传**：局域网文件互传神器，无需数据线、无需登录、极速传输大文件
