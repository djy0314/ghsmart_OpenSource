package webproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Options 是代理服务器的构造参数。
type Options struct {
	// Listen 是监听地址，如 127.0.0.1:18080；端口为 0 时由系统分配（单测用）。
	Listen string
	// Split 是分片策略。
	Split Splitter
	// Hosts 是需要分片的域名后缀（小写，无前导点）；为空表示除本地地址外全部分片。
	Hosts []string
	// Dial 可替换底层拨号（单测注入用）；为 nil 时用带超时的直连拨号。
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Resolve 返回该域名的候选「优选 IP」（按优先级，只放 IP 字面量）。
	// 这是修 502 的关键：默认 DNS 在国内会被污染，且 github.com 有 AAAA 记录，
	// 直连常落到不可达 IPv6 → 拨号超时 → CONNECT 502。
	//
	// 返回 nil 有两种含义：① 普通域名（不需要特殊解析，按域名直连）；
	// ② 管辖域名一个 IP 都没拿到（此时若 Resolve 非 nil，会直接 502，绝不退回系统解析）。
	Resolve func(host string) []string
	// ResolveInvalidate 在「全部候选都拨不通」时回调，让上层作废该域名的缓存，
	// 下次重新走 DoH，而不是拿同一批死 IP 反复撞。
	ResolveInvalidate func(host string)
	// DisableSplit 是「兼容模式」开关：开启后对任何域名都不做 TLS 分片，
	// 只做基础的 HTTP CONNECT 隧道（流量形态与普通代理完全一致）。
	// 场景：深信服 aTrust 等公司 VPN 的底层防火墙会把「分片的 TLS 握手」判为
	// 异常流量并重置连接（浏览器表现 ERR_CONNECTION_CLOSED）。
	// 注意它只关分片，**不改变拨号规则**：管辖域名依旧只按优选 IP 拨号。
	DisableSplit bool
	// LocalAddrs 是可选的本机源 IP 列表（物理网卡的 IPv4，由上层自动探测）。
	// 拨号竞速时会为候选 IP 额外增加「绑定该源地址」的入口：
	// Windows 的强主机发送模型保证绑定后包只从该网卡发出，
	// 从而绕开 aTrust 等虚拟网卡对默认路由的劫持。
	// 绑定失败（IP 不是本机的等）由竞速机制自然淘汰，无任何副作用。
	LocalAddrs []string
	// OnAutoFallback 是「自动避让」回调：管辖域名的 CONNECT 连续
	// autoFallbackThreshold 轮「全部候选 IP 失败 / 握手被拦」时触发一次，
	// 参数是最后一条失败原因。上层应借此自动关闭深度加速（公司 VPN 场景下
	// 继续开着只会让用户网页全卡死）。回调在独立协程里执行，可安全调用 Stop。
	OnAutoFallback func(reason string)
	// Logf 是可选日志钩子（GUI 下写 ~/.ghsmart/ghsmart.log）。
	Logf func(format string, args ...any)

	// 以下是超时参数，0 表示用包内默认值（单测会调小以免跑几十秒）。
	HandshakeWait     time.Duration // 等 ServerHello 的时限
	HandshakeBudget   time.Duration // 单个 CONNECT 全部分片尝试的总预算
	PlainFallbackWait time.Duration // 不分片兜底那一次的等待时限
	DialTimeout       time.Duration // 单个候选 IP 的建连时限（默认 3s）
}

// Stats 是给 UI 展示的运行计数。
type Stats struct {
	Active   int    `json:"active"`   // 当前活跃隧道数
	Total    int64  `json:"total"`    // 累计连接数
	Split    int64  `json:"split"`    // 累计执行 TLS 分片的握手数
	Pass     int64  `json:"pass"`     // 累计未分片（非目标域名/非 ClientHello）
	Retry    int64  `json:"retry"`    // 累计「握手无响应→换 IP/换节奏」重试次数
	Plain    int64  `json:"plain"`    // 累计「分片全失败→不分片直发」救回次数
	Addr     string `json:"addr"`     // 监听地址
	LastHost string `json:"lastHost"` // 最近一次分片的域名（诊断用）
}

// Server 是本地 HTTP 代理（支持 CONNECT 隧道与普通 HTTP 转发）。
type Server struct {
	opts Options

	mu    sync.Mutex
	ln    net.Listener
	conns map[net.Conn]struct{}
	done  bool
	wg    sync.WaitGroup

	active  atomic.Int64
	total   atomic.Int64
	nSplit  atomic.Int64
	nPass   atomic.Int64
	nRetry  atomic.Int64
	nPlain  atomic.Int64
	lastHos atomic.Value // string

	// good 记录「每个域名最近一次握手成功的 IP」，下次同域名优先用它。
	// 这能把「首选 IP 已经死了」的坑位成本降到 0，也让 Chrome 的多连接并发更顺。
	goodMu sync.Mutex
	good   map[string]string

	// 自动避让（Auto-Fallback）状态：
	// failStreak 是连续「该域名全部候选都失败」的轮数，成功即清零；
	// fallbackFired 保证回调只触发一次（触发后代理会被上层关掉）。
	failStreak    atomic.Int32
	fallbackFired atomic.Bool
}

// 握手阶段的节奏参数：第一次用配置值，失败后逐步拉长间隔（DPI 越难重组）。
var retryDelays = []time.Duration{0, 30 * time.Millisecond, 60 * time.Millisecond}

// maxHandshakeAttempts 是单个 CONNECT 的最大尝试次数（含换 IP 与换节奏）。
const maxHandshakeAttempts = 4

// maxDialCandidates 是拨号阶段最多尝试的候选 IP 数。
const maxDialCandidates = 5

// dialTimeout 是单个候选 IP 的建连时限（3s 硬要求，见 dialIP 注释）。
const dialTimeout = 3 * time.Second

// dialStagger 是并发竞速时各候选的起跑间隔。
const dialStagger = 80 * time.Millisecond

// serverHelloWait 是「发完 ClientHello 后等上游第一个字节」的时限。
// 超过即认为这条连接被 RST/丢弃，换一次再试。
const serverHelloWait = 3 * time.Second

// handshakeBudget 是单个 CONNECT 全部分片重试的总时长预算。
// 浏览器（尤其 Chrome）自己的代理超时更短，无限重试只会让页面「卡住」而不是报错。
const handshakeBudget = 7 * time.Second

// plainFallbackWait 是「分片全失败 → 退回不分片直发」那一次的等待时限。
const plainFallbackWait = 3 * time.Second

// autoFallbackThreshold 是触发「自动避让」的连续全败轮数：
// 管辖域名连续 3 条 CONNECT 全部候选失败/握手被拦，基本可断定是
// 网络环境（公司 VPN 等）在拦截加速流量，再开着只会让用户网页全卡死。
const autoFallbackThreshold = 3

// noteUpstreamFail 记一次「管辖域名全部候选失败」，达到阈值时触发自动避让回调（仅一次）。
func (s *Server) noteUpstreamFail(reason string) {
	n := s.failStreak.Add(1)
	if n < autoFallbackThreshold {
		return
	}
	if s.opts.OnAutoFallback == nil || !s.fallbackFired.CompareAndSwap(false, true) {
		return
	}
	s.logf("自动避让触发：连续 %d 轮全部候选失败，通知上层关闭深度加速（最后原因: %v）", n, reason)
	go s.opts.OnAutoFallback(reason)
}

// noteUpstreamOK 连接成功（建连且开始服务），清零连败计数。
func (s *Server) noteUpstreamOK() {
	s.failStreak.Store(0)
}

// VPN 兼容竞速的参数：只为前几个候选 IP 增加绑定源地址的入口，
// 且最多绑 2 个物理网卡，避免 socket 数量爆炸。
const (
	maxBoundCandidates = 3
	maxBoundAddrs      = 2
	// boundStagger 是绑定入口相对普通入口的延后起跑时间：
	// 健康机器上普通路径大概率秒连，绑定入口只是陪跑；
	// VPN 劫持场景下普通入口会被快速 RST，绑定入口随即接管。
	boundStagger = 120 * time.Millisecond
)

// 超时参数的取值入口：Options 里给了就用给的，否则用默认常量。
func (s *Server) handshakeWaitD() time.Duration {
	if s.opts.HandshakeWait > 0 {
		return s.opts.HandshakeWait
	}
	return serverHelloWait
}

func (s *Server) handshakeBudgetD() time.Duration {
	if s.opts.HandshakeBudget > 0 {
		return s.opts.HandshakeBudget
	}
	return handshakeBudget
}

func (s *Server) plainFallbackWaitD() time.Duration {
	if s.opts.PlainFallbackWait > 0 {
		return s.opts.PlainFallbackWait
	}
	return plainFallbackWait
}

// dialTimeoutD 是单个候选 IP 的建连时限。
// 3s 是硬要求：浏览器自己等不了太久，一个假活 IP 卡 8s 就是 ERR_CONNECTION_TIMED_OUT。
func (s *Server) dialTimeoutD() time.Duration {
	if s.opts.DialTimeout > 0 {
		return s.opts.DialTimeout
	}
	return dialTimeout
}

// dialIP 按「IP 字面量」建连——这是本文件的铁律。
//
// 为什么不能用域名：net.Dial("tcp", "github.com:443") 会走 Go 内置解析器，
// 而 Windows 上它读的是系统 DNS **和 hosts 文件**。ghsmart 自己的「一键智能加速」
// 刚好会往 hosts 里写一条优选 IP，一旦那条 IP 失效，代理拨号就会卡在这条死 IP 上
// 直到超时（实机表现：ERR_CONNECTION_TIMED_OUT），而且越「优化」越慢。
// 所以这里显式拒绝非 IP 地址：真出了这种事，日志里能立刻看到，而不是静默退回系统解析。
func (s *Server) dialIP(ctx context.Context, ip, port string) (net.Conn, error) {
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("内部错误：拒绝按域名拨号（%q），必须用 IP 字面量", ip)
	}
	ctx, cancel := context.WithTimeout(ctx, s.dialTimeoutD())
	defer cancel()
	addr := net.JoinHostPort(ip, port)
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := s.opts.Dial(ctx, "tcp", addr)
		ch <- res{c, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		return r.c, nil
	case <-ctx.Done():
		// 拨号方可能稍后才返回连接，别把它泄漏掉
		go func() {
			select {
			case r := <-ch:
				if r.c != nil {
					_ = r.c.Close()
				}
			case <-time.After(10 * time.Second):
			}
		}()
		return nil, fmt.Errorf("连接 %s 超时（%v）", addr, s.dialTimeoutD())
	}
}

// dialName 只用于「ghsmart 不管辖的域名」（普通网站）。
// 这些域名不在 hosts 区块里，系统解析不会被我们污染，所以允许按域名拨号。
func (s *Server) dialName(ctx context.Context, host, port string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, s.dialTimeoutD())
	defer cancel()
	return s.opts.Dial(ctx, "tcp", net.JoinHostPort(host, port))
}

// dialIPBound 与 dialIP 相同，但把本地源地址绑定到 localIP（物理网卡的 IPv4）。
//
// 为什么能绕开 VPN：Windows（Vista 起）默认强主机发送模型——socket 绑定了
// 物理网卡的源 IP 后，包只会从该网卡发出，不再跟随「VPN 虚拟网卡改写的
// 默认路由」。深信服 aTrust 等客户端正是靠虚拟网卡劫持默认路由把流量引去
// 公司防火墙的；绑定后流量直接走物理网卡出去，虚拟网卡形同虚设。
// localIP 不是本机地址时拨号立即失败，由竞速机制自然淘汰，无任何副作用。
func (s *Server) dialIPBound(ctx context.Context, ip, port, localIP string) (net.Conn, error) {
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("内部错误：拒绝按域名拨号（%q），必须用 IP 字面量", ip)
	}
	laddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(localIP, "0"))
	if err != nil {
		return nil, fmt.Errorf("非法本地源地址 %q: %w", localIP, err)
	}
	ctx, cancel := context.WithTimeout(ctx, s.dialTimeoutD())
	defer cancel()
	d := &net.Dialer{Timeout: s.dialTimeoutD(), LocalAddr: laddr}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
}

// dialRace 并发竞速拨一批候选 IP：谁先连上就用谁，其余立刻放弃。
//
// 这是「3 秒内没响应就换备选 IP」的实现方式，同时天然完成「并发探测校验」：
// 候选 IP 只有真正连上才算数，hosts 里那条失效静态 IP 不会赢，也就卡不住浏览器。
// 依次串行试（旧做法）的代价是每个死 IP 都要白等一次超时，5 个候选就是 15s+。
//
// VPN 兼容：若 LocalAddrs 非空，会为前 maxBoundCandidates 个候选 IP 额外挂上
// 「绑定物理网卡源 IP」的竞速入口——普通入口被 VPN 虚拟网卡劫持/RST 时，
// 绑定入口仍能从物理网卡直连成功（见 dialIPBound 注释）。
func (s *Server) dialRace(ctx context.Context, ips []string, port string) (net.Conn, string, []string) {
	type res struct {
		c   net.Conn
		ip  string
		err error
	}
	type entrant struct {
		ip   string
		wait time.Duration
		run  func(context.Context) (net.Conn, error)
	}

	var entrants []entrant
	for i, ip := range ips {
		e := entrant{ip: ip, wait: time.Duration(i) * dialStagger}
		e.run = func(ctx context.Context) (net.Conn, error) {
			return s.dialIP(ctx, ip, port)
		}
		entrants = append(entrants, e)
	}
	if len(s.opts.LocalAddrs) > 0 {
		addrs := s.opts.LocalAddrs
		if len(addrs) > maxBoundAddrs {
			addrs = addrs[:maxBoundAddrs]
		}
		for i, ip := range ips {
			if i >= maxBoundCandidates {
				break
			}
			for _, la := range addrs {
				e := entrant{ip: ip + "@bind(" + la + ")", wait: dialStagger + boundStagger}
				e.run = func(ctx context.Context) (net.Conn, error) {
					return s.dialIPBound(ctx, ip, port, la)
				}
				entrants = append(entrants, e)
			}
		}
		if len(entrants) > len(ips) {
			s.logf("VPN 兼容竞速：已为前 %d 个候选 IP 增加绑定源地址的拨号入口（本地源=%v）",
				min(len(ips), maxBoundCandidates), addrs)
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ch := make(chan res, len(entrants))
	for _, e := range entrants {
		go func(e entrant) {
			// 错开起跑：首选 IP 大概率秒连，没必要同时去打扰其他路径
			if e.wait > 0 {
				select {
				case <-time.After(e.wait):
				case <-ctx.Done():
					return
				}
			}
			c, err := e.run(ctx)
			select {
			case ch <- res{c: c, ip: e.ip, err: err}:
			case <-ctx.Done():
				if c != nil {
					_ = c.Close()
				}
			}
		}(e)
	}

	var fails []string
	for range entrants {
		select {
		case r := <-ch:
			if r.err == nil {
				return r.c, r.ip, fails
			}
			fails = append(fails, r.ip+"("+shortErr(r.err)+")")
		case <-ctx.Done():
			return nil, "", fails
		}
	}
	return nil, "", fails
}

// shortErr 把拨号错误压成一行（日志和 502 响应体都要短）。
func shortErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if len(msg) > 60 {
		msg = msg[:57] + "..."
	}
	return msg
}

// New 创建代理服务器（尚未监听）。
func New(opts Options) *Server {
	if opts.Dial == nil {
		d := &net.Dialer{Timeout: 3500 * time.Millisecond, KeepAlive: 30 * time.Second}
		// 注意：必须是直连，不能读系统代理环境变量，
		// 否则「系统代理指向本机」时会形成自我递归。
		opts.Dial = d.DialContext
	}
	return &Server{
		opts:  opts,
		conns: make(map[net.Conn]struct{}),
		good:  make(map[string]string),
	}
}

// Start 开始监听；返回实际监听地址（Listen 端口为 0 时可用于单测）。
func (s *Server) Start() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		return s.ln.Addr().String(), nil
	}
	addr := s.opts.Listen
	if addr == "" {
		addr = "127.0.0.1:18080"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("监听 %s 失败: %w", addr, err)
	}
	s.ln = ln
	s.wg.Add(1)
	go s.acceptLoop(ln)
	return ln.Addr().String(), nil
}

// Addr 返回当前监听地址（未启动为空）。
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// DropConns 断开全部在途连接，但保持监听不动。
// 用于系统休眠唤醒后：所有 TCP 连接的对端早已失效，与其等它们逐个超时
// 卡住浏览器，不如全部立刻断开让浏览器重连（新连接走新路由）。
func (s *Server) DropConns() {
	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close() // serve 的 track(defer) 会把它们从表里摘掉
	}
}

// Stop 关闭监听并断开所有在途隧道（关闭深度加速时要立刻放行直连）。
func (s *Server) Stop() error {
	s.mu.Lock()
	if s.done {
		s.mu.Unlock()
		return nil
	}
	s.done = true
	ln := s.ln
	s.ln = nil
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	var err error
	if ln != nil {
		err = ln.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
	s.wg.Wait()
	return err
}

// Stats 返回运行计数快照。
func (s *Server) Stats() Stats {
	host, _ := s.lastHos.Load().(string)
	return Stats{
		Active:   int(s.active.Load()),
		Total:    s.total.Load(),
		Split:    s.nSplit.Load(),
		Pass:     s.nPass.Load(),
		Retry:    s.nRetry.Load(),
		Plain:    s.nPlain.Load(),
		Addr:     s.Addr(),
		LastHost: host,
	}
}

func (s *Server) acceptLoop(ln net.Listener) {
	defer s.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.logf("accept 失败: %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		s.track(c, true)
		s.total.Add(1)
		s.active.Add(1)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				if r := recover(); r != nil {
					s.logf("处理连接时 panic: %v", r)
				}
				s.track(c, false)
				s.active.Add(-1)
				_ = c.Close()
			}()
			s.serve(c)
		}()
	}
}

func (s *Server) track(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[c] = struct{}{}
		return
	}
	delete(s.conns, c)
}

func (s *Server) serve(c net.Conn) {
	// 客户端必须在 20s 内把请求头发完，防半开连接堆积
	_ = c.SetReadDeadline(time.Now().Add(20 * time.Second))
	br := bufio.NewReaderSize(c, 32<<10)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	if strings.EqualFold(req.Method, http.MethodConnect) {
		s.handleConnect(c, br, req)
		return
	}
	s.handlePlain(c, req)
}

// handleConnect 处理 HTTPS 隧道。
//
// 顺序必须是：先拨号（失败才好回 502）→ 回 200 → 再读客户端的 ClientHello。
// 反过来（先读 hello 再回 200）会死等：浏览器/curl 拿到 200 才会发 TLS 握手。
//
// 关于 502：HTTP 的 502 只能在「回过 200 之前」发。一旦回过
// 「200 Connection Established」，这条 TCP 就已经是裸 TLS 流了，此时往里写
// "HTTP/1.1 502" 会被浏览器当成 TLS 记录解析（报 ERR_SSL_PROTOCOL_ERROR）。
// 所以失败分两类处理：
//   - 200 之前（拨号/候选 IP 全挂）→ 标准 502 + 失败原因（浏览器显示正常错误页）
//   - 200 之后（分片握手全失败）  → TLS fatal alert + 半关闭收尾（不是 RST 硬断）
func (s *Server) handleConnect(c net.Conn, br *bufio.Reader, req *http.Request) {
	host, port, target := splitTarget(req)
	if host == "" {
		s.writeErr(c, http.StatusBadRequest, "缺少目标地址")
		return
	}
	split := s.shouldSplit(host)
	managed := s.isManaged(host)

	up, _, err := s.dialUpstream(context.Background(), host, port, managed)
	if err != nil {
		reason := fmt.Sprintf("无法连接到 %s：%v", target, err)
		// 502 的日志要把「试过哪些 IP、各自为什么失败」写清楚，否则线上没法定位
		s.logf("CONNECT %s 返回 502（未回 200 阶段）: %v", target, err)
		// 自动避让：只统计管辖域名（GitHub 系）的全败；普通网站失败不代表加速链路被拦
		if managed {
			s.noteUpstreamFail(err.Error())
		}
		s.writeErr(c, http.StatusBadGateway, reason)
		return
	}
	var upRef net.Conn = up
	defer func() {
		if upRef != nil {
			_ = upRef.Close()
		}
	}()

	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if !split {
		s.nPass.Add(1)
		s.noteUpstreamOK()
		s.tunnel(c, br, upRef)
		return
	}

	hello, ok := s.readClientHello(c, br)
	if !ok || !IsClientHello(hello) {
		// 不是 TLS 握手（明文 HTTP 误走 CONNECT 等）：原样直通，一个字节都不改
		s.logf("CONNECT %s 首包非 ClientHello，按直通处理", target)
		s.nPass.Add(1)
		s.noteUpstreamOK()
		s.tunnel(c, br, upRef)
		return
	}

	// 注意所有权：把首条连接交给 handshakeFragment 全权处置
	//（它失败时自己关、成功时用 prefixedConn 包住或换新连接），
	// 这里只保留返回的连接，绝不再二次 Close 底层 conn。
	sni, sizes, newUp, herr := s.handshakeFragment(upRef, host, port, hello)
	upRef = newUp
	if herr != nil {
		// 已经回过 200，无法再发 HTTP 502；用协议正确的 TLS alert + 干净收尾，
		// 让浏览器得到「握手失败」而不是连接被重置（RST 会显示 ERR_CONNECTION_CLOSED）。
		s.logf("CONNECT %s TLS 握手彻底失败（分片 %d 次尝试 + 直发回退均失败）: %v",
			target, maxHandshakeAttempts, herr)
		// 握手阶段彻底失败同样计入自动避让：VPN 场景下正是「连上了但被 RST」的形态
		s.noteUpstreamFail(herr.Error())
		s.abortTLS(c, br, herr)
		return
	}
	s.nSplit.Add(1)
	s.lastHos.Store(sni)
	s.noteUpstreamOK()
	s.logf("TLS 分片 %s SNI=%s hello=%dB 分%d段 %v", host, sni, len(hello), len(sizes), sizes)
	s.tunnel(c, br, upRef)
}

// handshakeFragment 把 ClientHello 分片发出，并等上游第一个字节（ServerHello）。
// 等不到（被 RST / 丢弃 / IP 假活）就换 IP、拉长分片间隔重试；整轮失败后再退回
// 「不分片直发」兜底一次（有些链路是分片本身被中间设备搞坏，而不是 SNI 被拦）。
//
// 重试时的拨号同样**只按 IP 字面量**：上游候选全部来自优选池 + DoH，
// 绝不允许任何一步退回系统解析（那会读到 hosts 里的失效 IP，越重试越卡）。
func (s *Server) handshakeFragment(first net.Conn, host, port string, hello []byte) (string, []int, net.Conn, error) {
	sni := SNIHost(hello)
	ips := s.candidateIPs(host)
	firstIP := remoteIP(first)

	// 第一条连接是 dialUpstream 竞速赢家，已经连好了；重试时换成别的 IP。
	cand := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip != firstIP {
			cand = append(cand, ip)
		}
	}
	if len(cand) == 0 {
		cand = ips // 只有一个候选：允许用同一 IP 换节奏重试
	}
	// order 里空串表示「复用已经连好的 first 连接」。
	order := cand
	if first != nil {
		order = append([]string{""}, cand...)
	}
	if len(order) == 0 {
		return sni, nil, nil, errors.New("没有可用 IP")
	}

	deadline := time.Now().Add(s.handshakeBudgetD())
	var lastErr error
	attempt := 0
	var up net.Conn

	for _, ip := range order {
		if attempt >= maxHandshakeAttempts || time.Now().After(deadline) {
			break
		}
		attempt++
		// 重试策略：优先「换 IP」（同一 IP 换节奏意义不大），
		// 每换一次把分片间隔拉长一档。
		delay := retryDelays[min(attempt-1, len(retryDelays)-1)]

		if ip == "" {
			up = first // 复用 dialUpstream 已经建好的连接
		} else {
			var derr error
			up, derr = s.dialIP(context.Background(), ip, port)
			if derr != nil {
				lastErr = fmt.Errorf("连接 %s:%s 失败: %w", ip, port, derr)
				s.logf("第%d次尝试拨号失败（IP=%s）: %v", attempt, ip, derr)
				continue
			}
			s.logf("第%d次尝试切换上游 IP=%s（真实远端 %s）", attempt, ip, remoteIP(up))
		}
		via := remoteIP(up)

		sp := Splitter{Window: s.opts.Split.Window, Delay: delay}
		sizes, werr := sp.WriteWithSizes(up, hello)
		if werr != nil {
			_ = up.Close()
			up = nil
			lastErr = fmt.Errorf("向 %s 写 ClientHello 失败: %w", via, werr)
			s.logf("第%d次尝试写失败（%s）: %v", attempt, via, werr)
			continue
		}

		// 等 ServerHello。等不到 = 这条链被 RST 或丢弃，换一条再试。
		buf := make([]byte, 4096)
		n, rerr := readFirstBytes(up, buf, s.handshakeWaitD())
		if n > 0 {
			if attempt > 1 {
				s.nRetry.Add(int64(attempt - 1))
			}
			s.rememberGood(host, via)
			s.logf("上游握手成功 %s via %s（第%d次尝试，分片间隔%v，%d段，首包%dB）",
				host, via, attempt, delay, len(sizes), n)
			return sni, sizes, &prefixedConn{Conn: up, prefix: buf[:n]}, nil
		}
		_ = up.Close()
		up = nil
		if rerr != nil {
			lastErr = fmt.Errorf("等 %s 的 ServerHello 失败: %w", via, rerr)
		} else {
			lastErr = fmt.Errorf("%s 无响应即关闭", via)
		}
		s.forgetGood(host, via)
		s.logf("第%d次尝试失败（%s，分片间隔%v）: %v", attempt, via, delay, lastErr)
	}

	// 兜底：分片本身可能是失败原因（例如中间盒重组异常）→ 不分片直发一次。
	if c2, perr := s.handshakePlain(host, port, hello); perr == nil {
		s.nPlain.Add(1)
		s.logf("分片全部失败，改走「不分片直发」成功: %s", host)
		return sni, []int{len(hello)}, c2, nil
	} else {
		s.logf("不分片直发也失败: %s: %v", host, perr)
		if lastErr == nil {
			lastErr = perr
		} else {
			lastErr = fmt.Errorf("%v；不分片直发也失败: %w", lastErr, perr)
		}
	}

	if lastErr == nil {
		lastErr = errors.New("没有可用 IP")
	}
	return sni, nil, nil, lastErr
}

// handshakePlain 把同一条 ClientHello 不分片直接发出，作为分片失败后的兜底。
// 同样只按 IP 拨号（候选含「上次成功 IP」优先）。
func (s *Server) handshakePlain(host, port string, hello []byte) (net.Conn, error) {
	ips := s.candidateIPs(host)
	if len(ips) == 0 {
		return nil, errors.New("没有可用 IP，无法做不分片兜底")
	}
	var lastErr error
	for _, ip := range ips {
		conn, err := s.dialIP(context.Background(), ip, port)
		if err != nil {
			lastErr = err
			continue
		}
		if _, werr := conn.Write(hello); werr != nil {
			_ = conn.Close()
			lastErr = werr
			continue
		}
		buf := make([]byte, 4096)
		n, rerr := readFirstBytes(conn, buf, s.plainFallbackWaitD())
		if n > 0 {
			s.rememberGood(host, remoteIP(conn))
			s.logf("不分片直发成功 %s via %s", host, remoteIP(conn))
			return &prefixedConn{Conn: conn, prefix: buf[:n]}, nil
		}
		_ = conn.Close()
		if rerr != nil {
			lastErr = rerr
		} else {
			lastErr = errors.New("无响应即关闭")
		}
	}
	if lastErr == nil {
		lastErr = errors.New("没有可用 IP")
	}
	return nil, lastErr
}

// abortTLS 在「已经回过 200」之后宣告失败。
// 不能发 HTTP 502（客户端此时按 TLS 记录解析），改为发 TLS fatal alert
// （handshake_failure）再半关闭 + 读空残留，避免留下 RST 让浏览器报 ERR_CONNECTION_CLOSED。
func (s *Server) abortTLS(c net.Conn, br *bufio.Reader, reason error) {
	_ = c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	// TLS1.2 记录头 + Alert: fatal(2) handshake_failure(40)
	_, _ = c.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28})
	closeWrite(c)
	drainQuietly(c, br, 800*time.Millisecond)
	if reason != nil {
		s.logf("已向客户端发送 TLS handshake_failure 并正常关闭: %v", reason)
	}
}

// readFirstBytes 等第一个字节到达（最多 wait），返回读到的字节数与错误。
// 0 字节 = 上游没给 ServerHello（被拦/被丢），调用方应当换路重试。
func readFirstBytes(c net.Conn, buf []byte, wait time.Duration) (int, error) {
	_ = c.SetReadDeadline(time.Now().Add(wait))
	n, err := c.Read(buf)
	_ = c.SetReadDeadline(time.Time{})
	if n > 0 {
		return n, nil
	}
	return 0, err
}

// remoteIP 取出连接真实的远端 IP（用于日志与「优选 IP」记忆）。
func remoteIP(c net.Conn) string {
	if c == nil {
		return ""
	}
	addr := c.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// drainQuietly 在关闭前把对端还可能发来的字节读空，避免 close 时产生 RST。
func drainQuietly(c net.Conn, br *bufio.Reader, wait time.Duration) {
	_ = c.SetReadDeadline(time.Now().Add(wait))
	if br != nil {
		_, _ = io.CopyN(io.Discard, br, 64<<10)
	} else {
		_, _ = io.CopyN(io.Discard, c, 64<<10)
	}
	_ = c.SetReadDeadline(time.Time{})
}

// rememberGood / recallGood / forgetGood 维护「域名 → 上次成功 IP」的小缓存。
func (s *Server) rememberGood(host, ip string) {
	if ip == "" || net.ParseIP(ip) == nil {
		return
	}
	s.goodMu.Lock()
	defer s.goodMu.Unlock()
	if s.good == nil {
		s.good = make(map[string]string)
	}
	s.good[strings.ToLower(host)] = ip
}

func (s *Server) recallGood(host string) string {
	s.goodMu.Lock()
	defer s.goodMu.Unlock()
	return s.good[strings.ToLower(host)]
}

func (s *Server) forgetGood(host, ip string) {
	s.goodMu.Lock()
	defer s.goodMu.Unlock()
	if cur, ok := s.good[strings.ToLower(host)]; ok && (ip == "" || cur == ip) {
		delete(s.good, strings.ToLower(host))
	}
}

// splitTarget 从 CONNECT 请求里取 host / port / host:port。
func splitTarget(req *http.Request) (host, port, target string) {
	target = req.Host
	if target == "" {
		target = req.URL.Host
	}
	if target == "" {
		return "", "", ""
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(strings.Trim(target, "[]"), "443")
	}
	host, port, _ = net.SplitHostPort(target)
	return host, port, target
}

// readClientHello 读出客户端第一条 TLS 记录（最多 5s 等待）。
// 先用 Peek 看记录头：不是 TLS 握手就一个字节都不消费，直通路径还能原样转发。
// 读到的字节已经在手里，后面无论重试几次都用同一份，客户端完全无感。
func (s *Server) readClientHello(c net.Conn, br *bufio.Reader) ([]byte, bool) {
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, false
	}
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()

	hdr, err := br.Peek(5)
	if err != nil {
		return nil, false
	}
	total, ok := recordLen(hdr)
	if !ok || total > maxHelloLen {
		return nil, false // 未消费任何字节
	}
	buf := make([]byte, total)
	if _, err := io.ReadFull(br, buf); err != nil {
		return nil, false
	}
	return buf, true
}

// dialUpstream 建立到上游的连接。
//
// 规则（这是本轮重构的核心）：
//   - ghsmart 管辖的域名（需要分片的）**只按 IP 字面量拨号**，候选来自
//     Hosts 优选池 + DoH + 应急 IP 池，并全部经过并发建连校验；
//     绝不走系统解析，避免读到自己写进 hosts 的失效 IP。
//   - 其余普通域名（不在 hosts 区块里，不会被污染）才允许按域名拨号，
//     否则接管系统代理后所有网站都会挂。
func (s *Server) dialUpstream(ctx context.Context, host, port string, managed bool) (net.Conn, string, error) {
	ips := s.candidateIPs(host)
	if len(ips) > 0 {
		conn, via, fails := s.dialRace(ctx, ips, port)
		if conn != nil {
			s.logf("CONNECT %s:%s 已建连 IP=%s（真实远端 %s）",
				host, port, via, remoteIP(conn))
			return conn, net.JoinHostPort(via, port), nil
		}
		if s.opts.ResolveInvalidate != nil {
			s.opts.ResolveInvalidate(host)
		}
		if managed || s.opts.Resolve != nil {
			return nil, "", fmt.Errorf("候选 IP 全部建连失败: %s", strings.Join(fails, ", "))
		}
	}
	// 走到这里有两种情况：① 普通域名（不管辖）② 完全没有解析器（单测/CLI 裸跑）。
	// 后者不能挡，否则测试与 CLI 场景全废；生产里 Resolve 永远非空。
	if managed && len(ips) == 0 && s.opts.Resolve != nil {
		return nil, "", errors.New("没有可用 IP：Hosts 优选池与 DoH、应急 IP 池均无结果")
	}
	conn, err := s.dialName(ctx, host, port)
	if err != nil {
		return nil, "", fmt.Errorf("按域名建连失败: %w", err)
	}
	s.logf("CONNECT %s:%s 已建连（非管辖域名，走系统解析，IP=%s）", host, port, remoteIP(conn))
	return conn, net.JoinHostPort(host, port), nil
}

// candidateIPs 返回候选 IP 列表（只含 IP 字面量，按优先级去重）。
// 末尾不再追加「空串 = 退回系统解析」——那正是失效 hosts 卡死代理的入口。
func (s *Server) candidateIPs(host string) []string {
	var raw []string
	if s.opts.Resolve != nil {
		raw = append(raw, s.opts.Resolve(host)...)
	}
	// 上次握手成功的 IP 提到最前面：Chrome 一个页面会开十几条 CONNECT，
	// 让它们都优先命中已知可用的 IP，避免每条都去踩一次死 IP。
	if g := s.recallGood(host); g != "" {
		raw = append([]string{g}, raw...)
	}
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, ip := range raw {
		ip = strings.TrimSpace(strings.Trim(ip, "[]"))
		if net.ParseIP(ip) == nil {
			continue // 非 IP 一律不认（宁可不连，也不退回系统解析）
		}
		key := strings.ToLower(ip)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ip)
		if len(out) >= maxDialCandidates {
			break
		}
	}
	return out
}

// tunnel 双向搬运，支持半关闭，避免把长连接吊死。
func (s *Server) tunnel(c net.Conn, br *bufio.Reader, up net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(up, br) // br 里可能还有已缓冲的字节
		closeWrite(up)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(c, up)
		closeWrite(c)
		done <- struct{}{}
	}()
	<-done
	// 另一方向允许继续收尾（HTTP keep-alive 常见），但最多再等 10s：
	// 等太久会让「浏览器已放弃、上游还挂着」的隧道长期占着 goroutine。
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
}

// handlePlain 处理普通 HTTP（非 CONNECT）：改写为 origin-form 后转发。
func (s *Server) handlePlain(c net.Conn, req *http.Request) {
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	if host == "" {
		s.writeErr(c, http.StatusBadRequest, "缺少目标地址")
		return
	}
	port := "80"
	if h, p, err := net.SplitHostPort(host); err == nil {
		host, port = h, p
	}
	up, _, err := s.dialUpstream(context.Background(), host, port, s.isManaged(host))
	if err != nil {
		s.logf("普通 HTTP %s 返回 502: %v", host, err)
		s.writeErr(c, http.StatusBadGateway, "无法连接到 "+host+"："+err.Error())
		return
	}
	defer up.Close()

	req.RequestURI = "" // 让 Request.Write 使用 origin-form（GET /path HTTP/1.1）
	if err := req.Write(up); err != nil {
		return
	}
	_, _ = io.Copy(c, up)
}

func (s *Server) writeErr(c net.Conn, code int, msg string) {
	body := msg
	_, _ = fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\n"+
		"Content-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
}

// isManaged 判断该域名是否由 ghsmart 管辖（命中配置里的 split_hosts）。
// 只有这些域名的 hosts 记录会被我们改写，所以也只有它们必须「只按 IP 拨号」；
// 其余普通域名不在 hosts 区块里，允许按域名解析（否则接管系统代理后全网都打不开）。
//
// 注意：管辖判定**不受兼容模式影响**——兼容模式只关 TLS 分片，
// 绝不能让管辖域名退回系统解析（那会读到失效 hosts IP，卡死浏览器）。
func (s *Server) isManaged(host string) bool {
	if len(s.opts.Hosts) == 0 {
		return false
	}
	return matchesHosts(host, s.opts.Hosts)
}

// matchesHosts 是 split_hosts 后缀匹配的公共实现。
func matchesHosts(host string, hosts []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	for _, suffix := range hosts {
		suffix = strings.ToLower(strings.TrimSpace(suffix))
		suffix = strings.TrimPrefix(suffix, ".")
		if suffix == "" {
			continue
		}
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

// shouldSplit 判断该域名是否需要 TLS 分片。
// 兼容模式（DisableSplit，公司 VPN 场景）下一律返回 false：纯 CONNECT 隧道。
func (s *Server) shouldSplit(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	if s.opts.DisableSplit {
		return false
	}
	if len(s.opts.Hosts) == 0 {
		return !isLocalAddr(host)
	}
	return matchesHosts(host, s.opts.Hosts)
}

func isLocalAddr(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

func (s *Server) logf(format string, args ...any) {
	if s.opts.Logf != nil {
		s.opts.Logf(format, args...)
	}
}

func closeWrite(c net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

// prefixedConn 把「握手阶段已经读出来但还没转发」的字节排在真连接前面。
type prefixedConn struct {
	net.Conn
	prefix []byte
}

func (p *prefixedConn) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// Target 解析 CONNECT 目标为 host:port（导出便于单测）。
func Target(host string, defPort int) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(defPort))
}
