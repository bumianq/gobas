package target

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Baseline 目标基线探活结果（作为 TIMEOUT/BLOCKED 判定的对照）。
type Baseline struct {
	Alive      bool
	StatusCode int
	RTTMS      int64
	ErrText    string
	ProbedAt   time.Time
}

// Prober baseline 探测器。
type Prober struct {
	Timeout time.Duration
	Proxy   string // 探活代理（仅 HTTP 目标），空则直连
}

// Probe 探测目标基线：
//   - TCP 目标（host:port 无 scheme）：TCP 拨号，端口开放即存活（RTT=拨号耗时）；
//   - HTTP 目标：无害 GET，任何 HTTP 应答（含 404/503）都算 Alive，仅传输层错误视为不可达。
func (p *Prober) Probe(ctx context.Context, rawURL string) Baseline {
	if p.Timeout <= 0 {
		p.Timeout = 8 * time.Second
	}
	if IsTCP(rawURL) {
		return p.probeTCP(ctx, rawURL)
	}
	return p.probeHTTP(ctx, rawURL)
}

// probeTCP 对纯 TCP 目标拨号探活（端口开放即攻击面存在）。
// 注意：HTTP 代理不适用于裸 TCP 拨号，此处直连。
func (p *Prober) probeTCP(ctx context.Context, addr string) Baseline {
	var timeout = p.Timeout
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d < timeout {
			timeout = d
		}
	}
	start := time.Now()
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	rtt := time.Since(start).Milliseconds()
	if err != nil {
		return Baseline{RTTMS: rtt, ErrText: err.Error(), ProbedAt: time.Now()}
	}
	_ = conn.Close()
	return Baseline{Alive: true, RTTMS: rtt, ProbedAt: time.Now()}
}

// probeHTTP 对 HTTP 目标发起无害 GET 请求测量基线：RTT、状态码、传输错误。
func (p *Prober) probeHTTP(ctx context.Context, rawURL string) Baseline {
	client := &http.Client{
		Timeout: p.Timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}
	if p.Proxy != "" {
		proxyURL, err := url.Parse(p.Proxy)
		if err == nil {
			client.Transport = &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
				Proxy:             http.ProxyURL(proxyURL),
				DisableKeepAlives: true,
			}
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Baseline{ErrText: err.Error(), ProbedAt: time.Now()}
	}
	req.Header.Set("User-Agent", "gobas-baseline/1.0")

	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start).Milliseconds()
	if err != nil {
		return Baseline{RTTMS: rtt, ErrText: err.Error(), ProbedAt: time.Now()}
	}
	defer resp.Body.Close()
	return Baseline{
		Alive:      true,
		StatusCode: resp.StatusCode,
		RTTMS:      rtt,
		ProbedAt:   time.Now(),
	}
}
