package engine

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ConnDump 一条镜像连接的完整记录（双向字节流，截断后）。
type ConnDump struct {
	Addr        string // 连接目标 host:port
	StartedAt   time.Time
	DurationMs  int64
	ClientData  string // 客户端→服务端累计字节（截断+UTF-8 清洗）
	ServerData  string // 服务端→客户端累计字节
	ClientLen   int    // 原始字节数（截断前）
	ServerLen   int
	ClientTrunc bool
	ServerTrunc bool
}

// MirrorProxy 进程内 socks5 镜像代理：串联在引擎出口，逐连接记录
// 双向原始字节流（含 fuzz 字典、多请求攻击链的全部中间请求）。
// 上游支持三种形态：
//   - ""          直连目标
//   - socks5://   经上游 socks5 转发（全协议）
//   - http(s)://  经上游 HTTP CONNECT 隧道转发
//
// 协议说明：socks5 对 nuclei 的 http.Transport 与 fastdialer 均生效，
// 因此 http 与 network 两个批次的流量都经过本镜像。
type MirrorProxy struct {
	ln       net.Listener
	upstream string // 上游代理 URL（"" = 直连）
	maxBytes int    // 每方向镜像截断上限
	onConn   func(ConnDump)

	mu    sync.Mutex
	conns map[net.Conn]struct{}
	wg    sync.WaitGroup
}

// StartMirror 启动镜像代理（监听 127.0.0.1 随机端口）。
func StartMirror(upstream string, maxBytes int, onConn func(ConnDump)) (*MirrorProxy, error) {
	if onConn == nil {
		return nil, fmt.Errorf("mirror: onConn callback required")
	}
	if maxBytes <= 0 {
		maxBytes = 65536
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("mirror listen: %w", err)
	}
	m := &MirrorProxy{ln: ln, upstream: upstream, maxBytes: maxBytes, onConn: onConn, conns: make(map[net.Conn]struct{})}
	m.wg.Add(1)
	go m.acceptLoop()
	return m, nil
}

// Addr 返回可直接交给 nuclei WithProxy 的代理地址（socks5://127.0.0.1:port）。
func (m *MirrorProxy) Addr() string {
	return "socks5://" + m.ln.Addr().String()
}

// Close 停止接受新连接并强制收尾全部活动连接；返回时所有 onConn
// 回调已执行完毕（残余连接的 dump 已交付）。
func (m *MirrorProxy) Close() {
	_ = m.ln.Close()
	m.mu.Lock()
	for c := range m.conns {
		_ = c.Close()
	}
	m.mu.Unlock()
	m.wg.Wait()
}

func (m *MirrorProxy) acceptLoop() {
	defer m.wg.Done()
	for {
		conn, err := m.ln.Accept()
		if err != nil {
			return
		}
		m.mu.Lock()
		m.conns[conn] = struct{}{}
		m.mu.Unlock()
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.serve(conn)
			m.mu.Lock()
			delete(m.conns, conn)
			m.mu.Unlock()
		}()
	}
}

// serve 处理一条客户端连接：socks5 握手 → 上游拨号 → 双向镜像转发。
func (m *MirrorProxy) serve(client net.Conn) {
	defer client.Close()
	started := time.Now()

	remote, target, err := m.handshakeAndDial(client)
	if err != nil {
		return // 握手/拨号失败：无流量可记录
	}
	defer remote.Close()

	cm := newMirrorBuf(m.maxBytes) // client→server 累计镜像
	sm := newMirrorBuf(m.maxBytes) // server→client 累计镜像

	finished := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(remote, io.TeeReader(client, cm))
		finished <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, io.TeeReader(remote, sm))
		finished <- struct{}{}
	}()
	<-finished
	// 任一方向结束即关闭双端，强制另一方向返回（半关闭语义）
	_ = client.Close()
	_ = remote.Close()
	<-finished

	cd, cs := cm.snapshot()
	sd, ss := sm.snapshot()
	m.onConn(ConnDump{
		Addr:        target,
		StartedAt:   started,
		DurationMs:  time.Since(started).Milliseconds(),
		ClientData:  sanitize(cd),
		ServerData:  sanitize(sd),
		ClientLen:   cs.total,
		ServerLen:   ss.total,
		ClientTrunc: cs.trunc,
		ServerTrunc: ss.trunc,
	})
}

// handshakeAndDial 完成 socks5 服务端握手并建立上游连接（直连或经上游代理隧道），
// 返回上游连接与目标地址。
func (m *MirrorProxy) handshakeAndDial(client net.Conn) (net.Conn, string, error) {
	// 1. greeting: [VER NMETHODS METHODS...]
	head := make([]byte, 2)
	if _, err := io.ReadFull(client, head); err != nil {
		return nil, "", err
	}
	if head[0] != 0x05 {
		return nil, "", fmt.Errorf("mirror: not socks5 (ver=%d)", head[0])
	}
	if _, err := io.ReadFull(client, make([]byte, int(head[1]))); err != nil {
		return nil, "", err
	}
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil { // NO AUTH
		return nil, "", err
	}

	// 2. request: [VER CMD RSV ATYP ADDR PORT]
	rh := make([]byte, 4)
	if _, err := io.ReadFull(client, rh); err != nil {
		return nil, "", err
	}
	if rh[1] != 0x01 { // 仅支持 CONNECT
		_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return nil, "", fmt.Errorf("mirror: unsupported cmd %d", rh[1])
	}
	var host string
	var rest []byte
	switch rh[3] {
	case 0x01: // IPv4
		b := make([]byte, 6)
		if _, err := io.ReadFull(client, b); err != nil {
			return nil, "", err
		}
		host = net.IP(b[:4]).String()
		rest = b[4:]
	case 0x03: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(client, l); err != nil {
			return nil, "", err
		}
		b := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(client, b); err != nil {
			return nil, "", err
		}
		host = string(b[:int(l[0])])
		rest = b[int(l[0]):]
	case 0x04: // IPv6
		b := make([]byte, 18)
		if _, err := io.ReadFull(client, b); err != nil {
			return nil, "", err
		}
		host = net.IP(b[:16]).String()
		rest = b[16:]
	default:
		return nil, "", fmt.Errorf("mirror: bad atyp %d", rh[3])
	}
	port := binary.BigEndian.Uint16(rest[:2])
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	// 3. 上游拨号
	var remote net.Conn
	var err error
	switch {
	case m.upstream == "":
		remote, err = net.DialTimeout("tcp", target, 10*time.Second)
	case strings.HasPrefix(m.upstream, "socks5"):
		remote, err = dialViaSocks5(m.upstream, target)
	default: // http(s) CONNECT
		remote, err = dialViaHTTPConnect(m.upstream, target)
	}
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // REP=host unreachable
		return nil, "", err
	}

	// 4. 成功回复（bnd 地址置零即可）
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		_ = remote.Close()
		return nil, "", err
	}
	return remote, target, nil
}

// dialViaSocks5 经上游 socks5 建立到 target 的隧道。
func dialViaSocks5(proxyURL, target string) (net.Conn, error) {
	addr := strings.TrimPrefix(strings.TrimPrefix(proxyURL, "socks5://"), "socks5h://")
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	d := 10 * time.Second
	_ = c.SetDeadline(time.Now().Add(d))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = c.Close()
		return nil, err
	}
	r := make([]byte, 2)
	if _, err := io.ReadFull(c, r); err != nil || r[1] == 0xFF {
		_ = c.Close()
		return nil, fmt.Errorf("mirror: upstream socks5 auth failed")
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		_ = c.Close()
		return nil, err
	}
	h := make([]byte, 4)
	if _, err := io.ReadFull(c, h); err != nil {
		_ = c.Close()
		return nil, err
	}
	if h[1] != 0x00 {
		_ = c.Close()
		return nil, fmt.Errorf("mirror: upstream socks5 connect rep=%d", h[1])
	}
	var skip int
	switch h[3] {
	case 0x01:
		skip = 4
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			_ = c.Close()
			return nil, err
		}
		skip = int(l[0])
	case 0x04:
		skip = 16
	}
	if _, err := io.ReadFull(c, make([]byte, skip+2)); err != nil {
		_ = c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

// dialViaHTTPConnect 经上游 HTTP 代理 CONNECT 隧道到 target。
func dialViaHTTPConnect(proxyURL, target string) (net.Conn, error) {
	addr := strings.TrimPrefix(strings.TrimPrefix(proxyURL, "https://"), "http://")
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		_ = c.Close()
		return nil, err
	}
	br := make([]byte, 1)
	var line []byte
	for {
		if _, err := c.Read(br); err != nil {
			_ = c.Close()
			return nil, err
		}
		line = append(line, br[0])
		if len(line) >= 4 && string(line[len(line)-4:]) == "\r\n\r\n" {
			break
		}
		if len(line) > 1<<16 {
			_ = c.Close()
			return nil, fmt.Errorf("mirror: upstream CONNECT header too large")
		}
	}
	status := string(line)
	if !strings.Contains(status, " 200 ") && !strings.HasSuffix(strings.TrimSpace(status), "200 Connection established") {
		_ = c.Close()
		return nil, fmt.Errorf("mirror: upstream CONNECT refused: %s", strings.TrimSpace(strings.SplitN(status, "\r\n", 2)[0]))
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

// mirrorBuf 线程安全的方向字节收集器（累计计数 + 截断缓冲）。
type mirrorBuf struct {
	mu    sync.Mutex
	buf   []byte
	max   int
	total int
}

func newMirrorBuf(max int) *mirrorBuf {
	return &mirrorBuf{max: max}
}

func (b *mirrorBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.total += len(p)
	if room := b.max - len(b.buf); room > 0 {
		n := len(p)
		if n > room {
			n = room
		}
		b.buf = append(b.buf, p[:n]...)
	}
	return len(p), nil
}

func (b *mirrorBuf) snapshot() ([]byte, struct {
	total int
	trunc bool
}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf, struct {
		total int
		trunc bool
	}{total: b.total, trunc: b.total > len(b.buf)}
}

// sanitize 字节流转可存储文本（UTF-8 清洗，同 task_traffic 规范）。
func sanitize(b []byte) string {
	return strings.ToValidUTF8(string(b), "\uFFFD")
}
