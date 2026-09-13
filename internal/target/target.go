// Package target 目标管理与 baseline 探活。
package target

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// IsTCP 判断是否为纯 TCP 目标（host:port 无 scheme）。
// 这类目标交给 nuclei network 协议按 host:port 直接拨号，
// 探活走 TCP 拨号而非 HTTP GET。
func IsTCP(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, "://") {
		return false
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil || host == "" || port == "" {
		return false
	}
	if _, err := strconv.Atoi(port); err != nil {
		return false
	}
	return true
}

// NormalizeURL 规范化目标：host:port 形式（无 scheme）视为 TCP 目标原样保留；
// 其余无 scheme 输入补默认 http:// 并去尾部斜杠。
func NormalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty url")
	}
	if IsTCP(raw) {
		return raw, nil
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse url: %w", err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("missing host in %q", raw)
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// HostKey 提取归一化键，用于把引擎事件匹配回目标。
// TCP 目标（host:port 无 scheme）直接返回小写原样——引擎事件返回的 Host
// 即原始输入（network 协议见 request.go 的 input.MetaInput.Input）；
// HTTP 目标显式补默认端口（80/443），保证两侧键一致。
func HostKey(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if IsTCP(rawURL) {
		return strings.ToLower(rawURL)
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return strings.ToLower(strings.TrimRight(rawURL, "/"))
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	if u.Port() == "" {
		if scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	return scheme + "://" + host
}

// BareHostKey 返回 HTTP 目标的无 scheme 键（host:port）。
// nuclei network 协议的失败路径事件 Host 为提取后的 host:port（无 scheme，
// 见 request.go executeOnTarget 的 responseToDSLMap(address)），
// HostKey 回配时需兼容该变体；TCP 目标返回空串（本身无 scheme）。
func BareHostKey(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if IsTCP(rawURL) {
		return ""
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	host := strings.ToLower(u.Host)
	if u.Port() == "" {
		if strings.ToLower(u.Scheme) == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	return host
}
