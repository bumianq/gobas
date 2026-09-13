// Package verdict BAS 判定层：把攻击事件 + 基线对照归类为六种判定。
// 纯函数包，零外部状态，方便表驱动测试。
package verdict

import (
	"regexp"
	"strconv"
	"strings"

	"gobas/internal/target"
)

// Kind 判定类型。
type Kind string

const (
	// HIT 模板匹配，漏洞存在
	HIT Kind = "HIT"
	// BLOCKED 被防御设备拦截（状态码/WAF 指纹/连接重置）
	BLOCKED Kind = "BLOCKED"
	// TIMEOUT 攻击请求超时但 baseline 正常（疑似 IPS 丢包）
	TIMEOUT Kind = "TIMEOUT"
	// UNREACHABLE baseline 即失败，目标不可达
	UNREACHABLE Kind = "UNREACHABLE"
	// MISS 正常执行未命中
	MISS Kind = "MISS"
	// ERROR 其他执行错误
	ERROR Kind = "ERROR"
)

// Evidence 判定输入证据。
type Evidence struct {
	Matched     bool             // 模板匹配（MatcherStatus）
	Status      int              // 攻击响应状态码
	BodySnippet string           // 响应体片段（WAF 指纹匹配用）
	FailureText string           // 连接级错误原文
	NoResponse  bool             // payload 已发出但零响应且无错误（network 静默丢弃）
	Baseline    target.Baseline  // 同目标基线
}

// Classifier 判定分类器。
type Classifier struct {
	BlockedStatuses      map[int]bool
	WAFPatterns          []*regexp.Regexp
	TimeoutPatterns      []*regexp.Regexp
	RSTPatterns          []*regexp.Regexp
	UnreachablePatterns  []*regexp.Regexp
}

// NewClassifier 构建分类器；blockedStatuses 为空时用默认集合。
func NewClassifier(blockedStatuses []int) *Classifier {
	if len(blockedStatuses) == 0 {
		blockedStatuses = []int{403, 405, 418, 429, 501}
	}
	c := &Classifier{BlockedStatuses: map[int]bool{}}
	for _, s := range blockedStatuses {
		c.BlockedStatuses[s] = true
	}
	c.WAFPatterns = compileAll(
		`(?i)cloudflare`, `(?i)cf-ray`, `(?i)safedog`, `(?i)安全狗`,
		`(?i)阿里云`, `(?i)aliyungf`, `(?i)mod_?security`,
		`(?i)aws.?waf`, `(?i)bigip`, `(?i)fortigate`, `(?i)fortinet`,
		`(?i)sucuri`, `(?i)imperva`, `(?i)incapsula`, `(?i)akamai`,
		`(?i)请求被拦截`, `(?i)访问被拒绝`, `(?i)blocked by waf`, `(?i)we Blocked Your Request`,
	)
	c.TimeoutPatterns = compileAll(
		`(?i)timeout`, `(?i)deadline exceeded`, `(?i)context deadline`,
	)
	c.RSTPatterns = compileAll(
		`(?i)connection reset`, `(?i)econnreset`, `(?i)broken pipe`,
	)
	// 网络层不可达特征：端口关闭/被防火墙过滤/路由不可达。
	// 这类失败说明攻击面在网络层即不存在（如 network 模板探测的端口未开放），
	// 归类 UNREACHABLE 而非 ERROR（非系统故障，是目标环境的确定性结果）。
	// "no ips provided in dialWrap"：多地址 network 模板（{{Hostname}}:固定端口）
	// 对带端口目标渲染出非法地址（如 127.0.0.1:8080:6379），拨号层无有效 IP，
	// 同属攻击面不存在的确定性结果。
	// "EOF"：拨号成功但对端立即关闭连接（目标端口非模板协议，如对 HTTP 端口发
	// FTP/T3 握手），无有效服务响应面。
	c.UnreachablePatterns = compileAll(
		`(?i)port closed`, `(?i)port filtered`, `(?i)connection refused`,
		`(?i)no route to host`, `(?i)network is unreachable`,
		`(?i)no ips provided`, `(?i)\bEOF\b`,
	)
	return c
}

func compileAll(pats ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(pats))
	for _, p := range pats {
		if re, err := regexp.Compile(p); err == nil {
			out = append(out, re)
		}
	}
	return out
}

func matchAny(res []*regexp.Regexp, s string) bool {
	if s == "" {
		return false
	}
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// Classify 归类判定。优先级：
// Matched > baseline 不可达 > 网络层不可达（端口关闭等） > 超时模式 > 拦截特征 > 有响应未匹配 > ERROR > MISS。
func (c *Classifier) Classify(e Evidence) Kind {
	// 1. 模板匹配 → HIT
	if e.Matched {
		return HIT
	}
	// 2. baseline 不可达 → UNREACHABLE
	if !e.Baseline.Alive {
		return UNREACHABLE
	}
	// 3. 网络层不可达（端口关闭/被过滤/连接拒绝）→ UNREACHABLE（攻击面不存在）
	if matchAny(c.UnreachablePatterns, e.FailureText) {
		return UNREACHABLE
	}
	// 4. 连接级错误命中超时模式 → TIMEOUT（baseline 已正常）
	if matchAny(c.TimeoutPatterns, e.FailureText) {
		return TIMEOUT
	}
	// 4.5 payload 已送达但零响应（无错误文本）→ TIMEOUT：nuclei network 模板
	// 对无响应不报错（静默等满超时），这类任务此前误判为无痕 MISS。
	// 语义：攻击已发出但被静默丢弃——防护设备 drop 模式或目标协议不匹配
	// 无回显；区别于 RST 主动拒绝（→BLOCKED）与端口关闭（→UNREACHABLE）。
	// 精确区分"设备拦截"与"服务器不回显"需结合镜像连接耗时特征：
	// 零 RST + 耗时≈引擎超时上限 + 同端口正常请求有响应 = 倾向服务器不回显；
	// 出现 RST/拦截页 = 设备拦截（后者已被上方分支捕获）。
	if e.NoResponse {
		return TIMEOUT
	}
	// 5. 拦截特征：状态码 / WAF 指纹 / 连接被 RST
	if c.BlockedStatuses[e.Status] ||
		matchAny(c.WAFPatterns, e.BodySnippet) ||
		matchAny(c.RSTPatterns, e.FailureText) {
		return BLOCKED
	}
	// 6. 有响应未命中 → MISS
	if e.Status > 0 {
		return MISS
	}
	// 7. 其余执行错误 → ERROR
	if e.FailureText != "" {
		return ERROR
	}
	// 8. 兜底：已执行未匹配（补账场景）
	return MISS
}

// ParseResponseStatus 从原始响应 dump 中解析最终状态码。
// 响应可能含重定向链，取最后一条 "HTTP/x.y <code> ..." 状态行。
func ParseResponseStatus(response string) int {
	if response == "" {
		return 0
	}
	code := 0
	for _, line := range strings.Split(response, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "HTTP/") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			if n, err := strconv.Atoi(parts[1]); err == nil {
				code = n
			}
		}
	}
	return code
}

// BodySnippet 从原始响应 dump 中提取正文片段（跳过头部），max 512 字节。
func BodySnippet(response string) string {
	if response == "" {
		return ""
	}
	idx := strings.Index(response, "\r\n\r\n")
	body := response
	if idx >= 0 {
		body = response[idx+4:]
	} else if i := strings.Index(response, "\n\n"); i >= 0 {
		body = response[i+2:]
	}
	body = strings.TrimSpace(body)
	if len(body) > 512 {
		body = body[:512]
	}
	return body
}
