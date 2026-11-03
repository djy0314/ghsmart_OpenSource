// Package webproxy 实现 ghsmart Pro 的「深度网页加速」：
// 一个纯本地、无证书、无 MITM 的 HTTP/HTTPS 代理。
//
// 为什么不是 uTLS：uTLS 解决的是「自己构造 ClientHello」（浏览器指纹伪装），
// 只有在代理终止 TLS、也就是做 MITM 时才用得上，那会让用户必须安装根证书。
// 本代理走 HTTP CONNECT 隧道，TLS 端到端发生在浏览器与 GitHub 之间，
// 代理只是字节搬运工——但搬运工可以决定「这些字节以几个 TCP 段发出去」。
//
// 于是用的是 SpoofDPI / Green Tunnel / GoodbyeDPI 验证过的同一套机制：
// CONNECT 隧道建立后，客户端发来的 ClientHello 明文可读，代理把它拆成
// 若干份依次写出（首字节单独一段 + 在 SNI 主机名中点再切一刀），
// DPI 在单个 TCP 段里拼不出完整域名，SNI 阻断失效，而服务端会自行重组。
// 全程不解密、不装证书、不引入第三方依赖。
package webproxy

const (
	tlsRecordHandshake   = 0x16 // TLS record: handshake
	handshakeClientHello = 0x01 // handshake type: ClientHello
	extServerName        = 0x0000
	// maxHelloLen 是单个 TLS 记录允许的最大长度（RFC 8446 上限 2^14，留余量）。
	maxHelloLen = 1 << 15
)

// recordLen 解析 b 开头的 TLS 记录头（5 字节），返回「含头在内的整条记录长度」。
// b 不足 5 字节、不是 handshake 记录或长度非法时返回 ok=false。
func recordLen(b []byte) (int, bool) {
	if len(b) < 5 || b[0] != tlsRecordHandshake {
		return 0, false
	}
	n := int(b[3])<<8 | int(b[4])
	if n <= 0 || n > maxHelloLen {
		return 0, false
	}
	return 5 + n, true
}

// IsClientHello 判断 b 是否为「完整且内容是 ClientHello」的 TLS 记录。
// 只认单记录：跨记录的 ClientHello 极罕见，遇到就退回原样转发。
func IsClientHello(b []byte) bool {
	total, ok := recordLen(b)
	if !ok || len(b) < total || len(b) < 6 {
		return false
	}
	return b[5] == handshakeClientHello
}

// cursor 是带边界检查的只读游标，避免手写偏移时数组越界。
type cursor struct {
	b   []byte
	pos int
}

func (c *cursor) u8() (byte, bool) {
	if c.pos+1 > len(c.b) {
		return 0, false
	}
	v := c.b[c.pos]
	c.pos++
	return v, true
}

func (c *cursor) u16() (int, bool) {
	if c.pos+2 > len(c.b) {
		return 0, false
	}
	v := int(c.b[c.pos])<<8 | int(c.b[c.pos+1])
	c.pos += 2
	return v, true
}

func (c *cursor) u24() (int, bool) {
	if c.pos+3 > len(c.b) {
		return 0, false
	}
	v := int(c.b[c.pos])<<16 | int(c.b[c.pos+1])<<8 | int(c.b[c.pos+2])
	c.pos += 3
	return v, true
}

func (c *cursor) skip(n int) bool {
	if n < 0 || c.pos+n > len(c.b) {
		return false
	}
	c.pos += n
	return true
}

func (c *cursor) slice(n int) ([]byte, bool) {
	if n < 0 || c.pos+n > len(c.b) {
		return nil, false
	}
	v := c.b[c.pos : c.pos+n]
	c.pos += n
	return v, true
}

// SNISpan 在完整的 ClientHello 记录里定位 server_name（主机名）字节区间。
// 返回的 start/end 是相对整条记录（含 5 字节头）的绝对偏移，左闭右开。
// 解析失败（无 SNI、结构异常、ECH 加密了 SNI）时 ok=false。
func SNISpan(b []byte) (start, end int, ok bool) {
	if !IsClientHello(b) {
		return 0, 0, false
	}
	c := &cursor{b: b, pos: 5}
	if _, ok := c.u8(); !ok { // handshake type
		return 0, 0, false
	}
	hsLen, ok := c.u24()
	if !ok || hsLen <= 0 || 5+4+hsLen > len(b) {
		return 0, 0, false
	}
	if !c.skip(2) { // client version
		return 0, 0, false
	}
	if !c.skip(32) { // random
		return 0, 0, false
	}
	sidLen, ok := c.u8()
	if !ok || !c.skip(int(sidLen)) {
		return 0, 0, false
	}
	csLen, ok := c.u16()
	if !ok || !c.skip(csLen) {
		return 0, 0, false
	}
	compLen, ok := c.u8()
	if !ok || !c.skip(int(compLen)) {
		return 0, 0, false
	}
	// 没有扩展段（老式 ClientHello）：无 SNI
	if c.pos >= len(b) {
		return 0, 0, false
	}
	extTotal, ok := c.u16()
	if !ok {
		return 0, 0, false
	}
	extEnd := c.pos + extTotal
	if extEnd > len(b) {
		return 0, 0, false
	}
	for c.pos+4 <= extEnd {
		etype, ok := c.u16()
		if !ok {
			return 0, 0, false
		}
		elen, ok := c.u16()
		if !ok || c.pos+elen > extEnd {
			return 0, 0, false
		}
		if etype != extServerName {
			c.pos += elen
			continue
		}
		// server_name 扩展：list_len(2) + [name_type(1)=0 + name_len(2) + name]
		body, _ := c.slice(elen)
		lc := &cursor{b: body}
		listLen, ok := lc.u16()
		if !ok || listLen > len(body)-2 {
			return 0, 0, false
		}
		ntype, ok := lc.u8()
		if !ok || ntype != 0 { // 0 = host_name
			return 0, 0, false
		}
		nameLen, ok := lc.u16()
		if !ok {
			return 0, 0, false
		}
		name, ok := lc.slice(nameLen)
		if !ok {
			return 0, 0, false
		}
		// body 起点 = c.pos - elen；再算上 2 字节 list_len + 1 字节 name_type + 2 字节 name_len
		base := c.pos - elen + 5
		return base, base + len(name), true
	}
	return 0, 0, false
}

// SNIHost 返回 ClientHello 里的主机名（调试/日志用）。
func SNIHost(b []byte) string {
	s, e, ok := SNISpan(b)
	if !ok {
		return ""
	}
	return string(b[s:e])
}
