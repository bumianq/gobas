package engine

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// TestMirrorDirect 画像代理直连模式：socks5 握手 → 隧道内回显数据镜像完整。
func TestMirrorDirect(t *testing.T) {
	// 本地回显服务端
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}()
		}
	}()

	var dumps []ConnDump
	dumped := make(chan struct{})
	m, err := StartMirror("", 1024, func(d ConnDump) {
		dumps = append(dumps, d)
		close(dumped)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	// 客户端：手工 socks5 握手（IPv4 地址形态）
	c, err := net.Dial("tcp", strings.TrimPrefix(m.Addr(), "socks5://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	r := make([]byte, 2)
	if _, err := io.ReadFull(c, r); err != nil {
		t.Fatal(err)
	}
	if r[0] != 0x05 || r[1] != 0x00 {
		t.Fatalf("bad greeting reply: %x", r)
	}
	// CONNECT 127.0.0.1:<port>
	addr := ln.Addr().(*net.TCPAddr)
	req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, byte(addr.Port >> 8), byte(addr.Port)}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0x00 {
		t.Fatalf("connect rep=%d", rep[1])
	}

	msg := "hello-mirror"
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Fatalf("echo mismatch: %q", buf)
	}
	_ = c.Close()

	select {
	case <-dumped:
	case <-time.After(3 * time.Second):
		t.Fatal("no dump callback")
	}
	d := dumps[0]
	if !strings.HasSuffix(d.Addr, addr.String()[strings.LastIndex(addr.String(), ":"):]) {
		t.Fatalf("dump addr %q not to echo server %s", d.Addr, addr)
	}
	if !strings.Contains(d.ClientData, msg) || !strings.Contains(d.ServerData, msg) {
		t.Fatalf("mirror data incomplete: c=%q s=%q", d.ClientData, d.ServerData)
	}
	if d.ClientLen != len(msg) || d.ServerLen != len(msg) {
		t.Fatalf("mirror len mismatch: %d/%d", d.ClientLen, d.ServerLen)
	}
}
