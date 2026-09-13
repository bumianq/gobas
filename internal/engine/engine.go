// Package engine 封装 nuclei v3 SDK 执行引擎。
// 关键设计：全部事件（匹配 + 未匹配 + 失败）经由自定义 output.Writer 捕获——
//   - Write(*ResultEvent)          → 匹配事件（HIT 数据源）
//   - WriteFailure(*InternalWrappedEvent) → 未匹配/失败事件（MISS/BLOCKED/TIMEOUT 数据源，
//     InternalEvent 含 response/status_code/error 原文）
//
// 对外仅暴露引擎无关的事件结构，隔离 SDK 版本变动。
package engine

import (
	"context"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
)

// Options 引擎执行选项。
type Options struct {
	TemplatePaths []string // 模板文件绝对路径
	Targets       []string // 目标 URL 列表
	ProtocolTypes string   // 协议过滤（CSV，主协议精确匹配），默认 "http,websocket,code,tcp"
	TimeoutSec    int      // 单请求超时
	Retries       int      // 失败重试
	RateLimitPerS int      // 全局限速（请求/秒），0 不限
	// Proxy 扫描流量出口代理（空 = 直连）。指向 Burp/mitmproxy 可逐请求观察
	// 攻击 payload 与响应。http(s) 代理仅作用于 HTTP 协议流量（raw TCP 不走），
	// socks5 代理对全部协议生效（fastdialer 自带拨号超时兜底，不会挂死）。
	Proxy         string
	Interactsh    bool     // OOB 回连（BAS 场景默认关闭）
	// OnLoaded 引擎过滤后实际加载的模板 ID（含 workflow）。
	// nuclei 加载器会按能力门控过滤（dast/headless/file 需对应标志开启，
	// 且 ProtocolTypes 按模板主协议精确匹配），未加载的模板不会被执行，
	// 调用方应将其计入跳过统计而非误判 MISS。
	OnLoaded  func(templateIDs []string)
	OnResult  func(ResultEvent)
	OnFailure func(FailureEvent)
}

// ResultEvent 匹配事件（引擎无关）。
type ResultEvent struct {
	TemplateID  string
	Host        string // 原始目标（可能是完整 URL 或 host:port）
	Type        string
	MatchedAt   string
	MatcherName string
	Request     string
	Response    string
	Status      int
	Matched     bool
	ErrText     string
	Timestamp   time.Time
}

// FailureEvent 连接级失败 / 未匹配事件（引擎无关）。
type FailureEvent struct {
	TemplateID string
	Host       string
	Type       string // 协议类型（http/network/websocket/code，可能为空）
	Status     int
	Request    string // 原始请求 dump（code 协议无请求，恒空）
	Response   string // 原始响应 dump（network 协议走 data→raw fallback）
	ErrText    string
	Timestamp  time.Time
}

// Run 执行一次引擎扫描，阻塞直至完成或 ctx 取消。
func Run(ctx context.Context, opts Options) error {
	if opts.ProtocolTypes == "" {
		opts.ProtocolTypes = "http,websocket,code,tcp"
	}
	var engineOpts []nuclei.NucleiSDKOptions

	engineOpts = append(engineOpts,
		// 本地模板文件 + 不限制内网目标
		nuclei.WithSandboxOptions(true, false),
		// 全矩阵判定基石：未匹配的 (POC,目标) 对也产生事件
		nuclei.EnableMatcherStatus(),
		// 启用 code 协议模板（本地解释器执行模板内脚本攻击目标，BAS 攻击模拟的核心能力；
		// 连带启用 self-contained 加载，但自包含模板由 service 层分类排除，不进引擎）
		nuclei.EnableCodeTemplates(),
		// 启用 self-contained 模板加载能力（自包含模板由 service 层分类排除，不进引擎）
		nuclei.EnableSelfContainedTemplates(),
		// 启用 global matchers 模板加载能力
		nuclei.EnableGlobalMatchersTemplates(),
		// BAS 场景关闭 OOB 回连（CacheSize 等默认值必须显式给出，
		// 零值会触发 interactsh 内部 gcache panic）
		nuclei.WithInteractshOptions(nuclei.InteractshOpts{
			NoInteractsh:   !opts.Interactsh,
			CacheSize:      5000,
			Eviction:       time.Minute,
			CooldownPeriod: 5 * time.Second,
			PollDuration:   5 * time.Second,
		}),
		// DisableMaxHostErr：被 WAF 连续拦截的目标不得被静默跳过
		nuclei.WithNetworkConfig(nuclei.NetworkConfig{
			Timeout:           opts.TimeoutSec,
			Retries:           opts.Retries,
			DisableMaxHostErr: true,
		}),
		// 关闭联网版本检查，保持离线可运行
		nuclei.DisableUpdateCheck(),
		// 静默 SDK 自身日志输出
		nuclei.WithVerbosity(nuclei.VerbosityOptions{Silent: true}),
	)

	engineOpts = append(engineOpts,
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: opts.TemplatePaths}),
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{ProtocolTypes: opts.ProtocolTypes}),
	)

	if opts.Proxy != "" {
		// 扫描流量走代理：调试时指向 Burp/mitmproxy 可逐请求观察攻击 payload 与响应
		engineOpts = append(engineOpts, nuclei.WithProxy([]string{opts.Proxy}, false))
	}
	if opts.RateLimitPerS > 0 {
		engineOpts = append(engineOpts, nuclei.WithGlobalRateLimitCtx(ctx, opts.RateLimitPerS, time.Second))
	}

	// 自定义 writer：拦截 Write（匹配）与 WriteFailure（未匹配/失败）
	engineOpts = append(engineOpts, nuclei.UseOutputWriter(newEventWriter(opts.OnResult, opts.OnFailure)))

	ne, err := nuclei.NewNucleiEngineCtx(ctx, engineOpts...)
	if err != nil {
		return err
	}
	defer ne.Close()

	ne.LoadTargets(opts.Targets, false)

	// 预加载模板并回报实际加载的 ID 集合（幂等：ExecuteCallbackWithCtx 会跳过已加载）。
	// 未被加载的模板（dast/headless/file 能力门控、主协议不匹配、解析失败）
	// 不会产生任何事件，调用方须将其计入跳过统计而非误判 MISS。
	if err := ne.LoadAllTemplates(); err != nil {
		return err
	}
	if opts.OnLoaded != nil {
		loaded := ne.GetTemplates()
		workflows := ne.GetWorkflows()
		ids := make([]string, 0, len(loaded)+len(workflows))
		for _, t := range loaded {
			if t != nil {
				ids = append(ids, t.ID)
			}
		}
		for _, t := range workflows {
			if t != nil {
				ids = append(ids, t.ID)
			}
		}
		opts.OnLoaded(ids)
	}

	// 不传回调：全部事件已由自定义 writer 捕获（SDK 内部将 writer 与 mock writer 合成 MultiWriter）
	return ne.ExecuteCallbackWithCtx(ctx)
}
