package target

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestProbeTCP(t *testing.T) {
	// 起一个本地 TCP 监听
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
			_ = c.Close()
		}
	}()

	p := &Prober{Timeout: 2 * time.Second}
	b := p.Probe(context.Background(), ln.Addr().String())
	if !b.Alive || b.ErrText != "" {
		t.Errorf("open port: alive=%v err=%q", b.Alive, b.ErrText)
	}

	// 关闭端口：找空闲端口（监听后立即关闭）
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	closedAddr := ln2.Addr().String()
	ln2.Close()
	b = p.Probe(context.Background(), closedAddr)
	if b.Alive || b.ErrText == "" {
		t.Errorf("closed port: alive=%v err=%q", b.Alive, b.ErrText)
	}
}
