package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"gobas/internal/engine"
	"gobas/internal/store"
	"gobas/internal/target"
	"gobas/internal/verdict"
)

// ScanRequest 扫描请求。
type ScanRequest struct {
	Name        string
	TargetIDs   []int64         // 空 = 全部 alive 目标
	POCFilter   store.POCFilter // POC 选择器
	IncludeDead bool            // 保留探活失败的目标（判定为 UNREACHABLE）
	// Proxy 扫描流量出口代理：空 = 直连；非空 = 攻击流量经该代理发出
	// （如指向 Burp/WAF 模拟代理观察请求与拦截行为）。仅影响引擎攻击流量，
	// 不影响探活与 POC 源同步。
	Proxy        string
	// 执行参数（零值回落到全局配置）
	TimeoutSec    int
	Retries       int
	RateLimitPerS int
}

// normalizeProxy 校验并规范化代理地址：无 scheme 时自动补 http:// 前缀，
// 仅支持 http/https/socks5。空串原样返回（= 直连）。
func normalizeProxy(proxy string) (string, error) {
	proxy = strings.TrimSpace(proxy)
	if proxy == "" {
		return "", nil
	}
	if !strings.Contains(proxy, "://") {
		proxy = "http://" + proxy
	}
	u, err := url.Parse(proxy)
	if err != nil {
		return "", fmt.Errorf("无效代理地址 %q: %w", proxy, err)
	}
	switch u.Scheme {
	case "http", "https", "socks5":
	default:
		return "", fmt.Errorf("无效代理协议 %q（支持 http/https/socks5）", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("无效代理地址 %q（缺少 host:port）", proxy)
	}
	return proxy, nil
}

// ScanOptionsResolved 解析后的执行参数。
func (s *Service) resolveScanOpts(req ScanRequest) (timeout, retries, rateLimit int) {
	timeout = req.TimeoutSec
	if timeout <= 0 {
		timeout = s.cfg.Scan.TimeoutSec
	}
	retries = req.Retries
	if retries <= 0 {
		retries = s.cfg.Scan.Retries
	}
	rateLimit = req.RateLimitPerS
	if rateLimit <= 0 {
		rateLimit = s.cfg.Scan.RateLimitPerS
	}
	return
}

// DryRunMatrix 解析扫描矩阵（POC × 目标）但不执行。
func (s *Service) DryRunMatrix(ctx context.Context, req ScanRequest) ([]store.POC, []store.Target, error) {
	pocs, targets, err := s.resolveScan(ctx, req)
	if err != nil {
		return nil, nil, err
	}
	return pocs, targets, nil
}

func (s *Service) resolveScan(ctx context.Context, req ScanRequest) ([]store.POC, []store.Target, error) {
	filter := req.POCFilter
	pocs, err := s.store.ListPOCs(filter)
	if err != nil {
		return nil, nil, fmt.Errorf("query pocs: %w", err)
	}
	if len(pocs) == 0 {
		return nil, nil, fmt.Errorf("no POCs matched the filter (index first via `gobas pocs index`)")
	}
	var targets []store.Target
	if len(req.TargetIDs) > 0 {
		targets, err = s.store.GetTargetsByIDs(req.TargetIDs)
	} else {
		var all []store.Target
		all, err = s.store.ListTargets()
		for _, t := range all {
			if t.Alive || req.IncludeDead {
				targets = append(targets, t)
			}
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("query targets: %w", err)
	}
	if len(targets) == 0 {
		return nil, nil, fmt.Errorf("no targets selected (add via `gobas target add <url>`)")
	}
	return pocs, targets, nil
}

// StartScan 启动后台扫描，立即返回 scan id。
func (s *Service) StartScan(ctx context.Context, req ScanRequest) (int64, error) {
	proxy, err := normalizeProxy(req.Proxy)
	if err != nil {
		return 0, err
	}
	req.Proxy = proxy

	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	if s.runningScan != nil {
		select {
		case <-s.runningScan.done:
			// 上一个扫描已结束，允许继续
		default:
			return 0, fmt.Errorf("scan #%d is still running; cancel it first", s.runningScan.id)
		}
	}

	filterJSON, _ := json.Marshal(req.POCFilter)
	scanID, err := s.store.CreateScan(req.Name, string(filterJSON), req.Proxy)
	if err != nil {
		return 0, err
	}

	runCtx, cancel := context.WithCancel(context.Background())
	rs := &runningScan{id: scanID, cancel: cancel, done: make(chan struct{})}
	s.runningScan = rs

	go func() {
		defer close(rs.done)
		s.executeScan(runCtx, scanID, req)
	}()
	return scanID, nil
}

// CancelScan 取消运行中的扫描。
func (s *Service) CancelScan(ctx context.Context, id int64) error {
	s.scanMu.Lock()
	rs := s.runningScan
	s.scanMu.Unlock()
	if rs == nil || rs.id != id {
		return fmt.Errorf("scan #%d is not running", id)
	}
	rs.cancel()
	return nil
}

// DeleteScan 删除扫描历史（含结果、流量级联删除）。
// 运行中的扫描不允许删除（避免引擎回调写入已删行），请先取消并等待结束。
func (s *Service) DeleteScan(ctx context.Context, id int64) error {
	s.scanMu.Lock()
	rs := s.runningScan
	s.scanMu.Unlock()
	if rs != nil && rs.id == id {
		select {
		case <-rs.done:
			// 已结束，允许删除
		default:
			return fmt.Errorf("扫描 #%d 正在运行，请先取消再删除", id)
		}
	}
	ok, err := s.store.DeleteScan(id)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("扫描 #%d 不存在", id)
	}
	return nil
}

// GetScan 查询扫描。
func (s *Service) GetScan(ctx context.Context, id int64) (*store.Scan, error) {
	return s.store.GetScan(id)
}

// ListScans 扫描列表（倒序分页）。
func (s *Service) ListScans(ctx context.Context, limit, offset int) ([]store.Scan, error) {
	return s.store.ListScans(limit, offset)
}

// CountScans 扫描总数。
func (s *Service) CountScans(ctx context.Context) (int, error) {
	return s.store.CountScans()
}

// ScanResults 扫描结果（verdict 过滤，空则全部）。
func (s *Service) ScanResults(ctx context.Context, id int64, verdictFilter string) ([]store.ResultDetail, error) {
	return s.store.ListResults(id, verdictFilter)
}

// ScanTraffic 扫描任务流量（pocID/targetID <=0 不过滤），按 seq 保序；
// search 非空 = 请求/响应包内容特征搜索（field: ""=both/request/response），
// 方便人工发现设备拦截特征（WAF 指纹/拦截页特征）进行二次判定。
// 返回 (流量行, 总数)。limit<=0 默认 1000（store 内 clamp 上限 10000）。
func (s *Service) ScanTraffic(ctx context.Context, scanID, pocID, targetID int64, search, field string, limit, offset int) ([]store.TrafficDetail, int, error) {
	rows, err := s.store.ListTraffic(scanID, pocID, targetID, search, field, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.store.CountTraffic(scanID, pocID, targetID, search, field)
	if err != nil {
		return nil, 0, err
	}
	return rows, total, nil
}

// ScanTrafficDump 镜像连接流水（socks5 镜像代理逐连接捕获的双向原始
// 字节流，含 fuzz 字典/多请求攻击链的全部中间请求）。
func (s *Service) ScanTrafficDump(scanID int64, limit, offset int) ([]store.TrafficDump, int, error) {
	rows, err := s.store.ListTrafficDump(scanID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.store.CountTrafficDump(scanID)
	if err != nil {
		return nil, 0, err
	}
	return rows, total, nil
}

// VerdictUpdateRequest 人工修正判定请求。
type VerdictUpdateRequest struct {
	ResultIDs   []int64 `json:"result_ids"`   // 指定结果行（空 = 不限）
	FromVerdict string  `json:"from_verdict"` // 原判定过滤（空 = 不限；两者都空 = 全部结果）
	ToVerdict   string  `json:"to_verdict"`   // 目标判定（空 = 恢复机器自动判定）
}

// validVerdicts 合法判定集合（与 verdict.Kind 一致）。
var validVerdicts = map[string]bool{
	"HIT": true, "BLOCKED": true, "TIMEOUT": true,
	"UNREACHABLE": true, "MISS": true, "ERROR": true,
}

// UpdateScanVerdicts 人工修正扫描结果判定（单个/批量/按类别/恢复）。
// 机器自动判定不总可靠（如 WAF 指纹误判 MISS），人工结合流量特征二次
// 判定后改写结果类别；同步刷新扫描级判定计数，报告导出读 verdict 列
// 天然反映人工修正。运行中的扫描禁止修改（结果仍在写入）。
// 返回受影响行数。
func (s *Service) UpdateScanVerdicts(ctx context.Context, scanID int64, req VerdictUpdateRequest) (int64, error) {
	if req.ToVerdict != "" && !validVerdicts[req.ToVerdict] {
		return 0, fmt.Errorf("无效判定 %q（合法值：HIT/BLOCKED/TIMEOUT/UNREACHABLE/MISS/ERROR，空=恢复自动判定）", req.ToVerdict)
	}
	if req.FromVerdict != "" && !validVerdicts[req.FromVerdict] {
		return 0, fmt.Errorf("无效原判定 %q", req.FromVerdict)
	}
	if len(req.ResultIDs) == 0 && req.FromVerdict == "" && req.ToVerdict == "" {
		return 0, fmt.Errorf("请指定 result_ids 或 from_verdict（不能无条件恢复全部）")
	}
	sc, err := s.store.GetScan(scanID)
	if err != nil {
		return 0, err
	}
	if sc == nil {
		return 0, fmt.Errorf("扫描 #%d 不存在", scanID)
	}
	if sc.Status == "running" {
		return 0, fmt.Errorf("扫描 #%d 正在运行，结果仍在写入，请结束后再修改判定", scanID)
	}
	n, err := s.store.UpdateResultVerdicts(scanID, req.ResultIDs, req.FromVerdict, req.ToVerdict)
	if err != nil {
		return 0, err
	}
	if err := s.store.RefreshScanVerdictCounts(scanID); err != nil {
		return 0, fmt.Errorf("刷新判定计数: %w", err)
	}
	return n, nil
}

// executeScan 扫描主流程：探活 → 引擎执行 → 聚合 → 判定 → 落库。
func (s *Service) executeScan(ctx context.Context, scanID int64, req ScanRequest) {
	status := "completed"
	var finalErr string
	// panic 兜底收尾流量（后文赋值；主路径已 drain 则为空操作）
	var flushPanicTraffic func()
	var flushPanicDump func()
	defer func() {
		if r := recover(); r != nil {
			status = "failed"
			finalErr = fmt.Sprintf("panic: %v", r)
			slog.Error("scan panic", "scan", scanID, "panic", r)
			if flushPanicTraffic != nil {
				flushPanicTraffic()
			}
			if flushPanicDump != nil {
				flushPanicDump()
			}
		}
		s.finishScan(scanID, status, finalErr)
	}()

	// 1. 解析 POC 与目标
	pocs, targets, err := s.resolveScan(ctx, req)
	if err != nil {
		status = "failed"
		finalErr = err.Error()
		return
	}

	// 2. baseline 探活（更新库；剔除不可达，除非 IncludeDead）
	prober := s.prober()
	baselines := make(map[int64]target.Baseline, len(targets))
	live := make([]store.Target, 0, len(targets))
	for _, t := range targets {
		if ctx.Err() != nil {
			status = "canceled"
			return
		}
		b := prober.Probe(ctx, t.URL)
		_ = s.store.UpdateTargetBaseline(t.ID, b.Alive, b.StatusCode, b.RTTMS, b.ErrText)
		baselines[t.ID] = b
		if b.Alive || req.IncludeDead {
			live = append(live, t)
		} else {
			slog.Warn("target unreachable, excluded", "url", t.URL, "err", b.ErrText)
		}
	}
	// 3. 模板可执行性分类（在计数前完成，total 只含可执行对）：
	//    索引期已做引擎级真实验证（加载成功的才入库），此处为旧数据兜底：
	//    - headless（需浏览器）/ 非 http/websocket/code/tcp 协议 / self-contained（自包含，
	//      不对扫描目标发请求）→ 跳过，计入扫描级统计（不生成 ERROR 任务）
	executable, skipCount := s.classifyPOCs(ctx, pocs)

	// 目标分类：矩阵按协议完全互斥——
	// HTTP 目标（带 scheme）仅执行 http/websocket 协议 POC，
	// TCP 目标（host:port 无 scheme）仅执行 network 协议 POC。
	// （network POC 的 host 表达式绑定固定服务端口（{{Host}}:6379 等），
	// 对 HTTP 目标只产生端口不匹配噪音；HTTP POC 对 Redis/SSH 等裸 TCP
	// 端口无法发 HTTP 请求。同目标的两种表达合计恰好覆盖全部 POC 各一次）
	httpLive := make([]store.Target, 0, len(live))
	tcpLive := make([]store.Target, 0, len(live))
	for _, t := range live {
		if target.IsTCP(t.URL) {
			tcpLive = append(tcpLive, t)
		} else {
			httpLive = append(httpLive, t)
		}
	}

	networkPOCs := 0
	for _, p := range executable {
		if strings.Contains(p.Protocols, `"network"`) {
			networkPOCs++
		}
	}
	httpPOCs := len(executable) - networkPOCs
	total := len(httpLive)*httpPOCs + len(tcpLive)*networkPOCs
	if skipped := len(tcpLive) * httpPOCs; skipped > 0 {
		skipCount[skipReasonTCPMismatch] += skipped
	}
	if skipped := len(httpLive) * networkPOCs; skipped > 0 {
		skipCount[skipReasonHTTPMismatch] += skipped
	}
	_ = s.store.UpdateScanCounts(scanID, len(live), len(executable), total)
	_ = s.store.AddScanTargets(scanID, targetIDs(live))
	egress := "直连"
	if req.Proxy != "" {
		egress = "经代理 " + req.Proxy
	}
	slog.Info("scan matrix resolved", "scan", scanID,
		"targets", len(live), "pocs", len(executable), "total", total, "egress", egress)
	if len(live) == 0 {
		finalErr = "all targets unreachable"
		return
	}
	if total == 0 {
		finalErr = "no executable pairs (HTTP targets need http-protocol POCs; TCP targets need network-protocol POCs)"
		return
	}

	// 4. 构建路由映射（仅可执行模板进引擎；协议与目标类型互斥分批）
	tplToPOC := make(map[string]int64, len(executable))
	paths := make([]string, 0, len(executable))     // HTTP 目标批次：非 network 协议模板
	tcpPaths := make([]string, 0)                   // TCP 目标批次：仅 network 协议模板
	for _, p := range executable {
		path := p.FilePath
		if !filepath.IsAbs(path) {
			path = filepath.Join(s.cfg.Workspace, path)
		}
		if strings.Contains(p.Protocols, `"network"`) {
			tcpPaths = append(tcpPaths, path)
		} else {
			paths = append(paths, path)
		}
		tplToPOC[p.TemplateID] = p.ID
	}
	// code 协议模板重签：nuclei 对未验证签名的 code 模板无条件拒绝加载，
	// 本地签名器对未通过官方验证的 code 模板重签（幂等，已签则跳过）。
	if ls := engine.Instance(); ls != nil {
		for _, p := range executable {
			if !strings.Contains(p.Protocols, `"code"`) {
				continue
			}
			path := p.FilePath
			if !filepath.IsAbs(path) {
				path = filepath.Join(s.cfg.Workspace, path)
			}
			if err := ls.SignFile(path); err != nil {
				slog.Warn("re-sign code template", "path", path, "err", err)
			}
		}
	}
	hostToTarget := make(map[string]int64, len(live))
	httpTargetURLs := make([]string, 0, len(httpLive))
	tcpTargetURLs := make([]string, 0, len(tcpLive))
	for _, t := range live {
		hostToTarget[target.HostKey(t.URL)] = t.ID
		// HTTP 目标补无 scheme 键变体：network 协议失败路径事件的 Host 为
		// 提取后的 host:port（无 scheme），保证引擎事件可靠回配目标
		if bk := target.BareHostKey(t.URL); bk != "" {
			hostToTarget[bk] = t.ID
		}
		if target.IsTCP(t.URL) {
			tcpTargetURLs = append(tcpTargetURLs, t.URL)
		} else {
			httpTargetURLs = append(httpTargetURLs, t.URL)
		}
	}

	// 4. 引擎执行 + (poc,target) 对聚合
	type pairAgg struct {
		pocID, targetID int64
		matched         bool
		matcherName     string
		matchedAt       string
		status          int
		bodySnippet     string
		failureText     string
		noResponse      bool // payload 已发出但零响应且无错误（→TIMEOUT）
	}
	var mu sync.Mutex
	pairs := map[string]*pairAgg{}
	seen := 0   // 引擎回调次数（匹配+失败）
	judged := 0 // 判定完成数（含补账 MISS）
	progressEvery := 25
	if total/10 > progressEvery {
		progressEvery = total / 10
	}

	getPair := func(pocID, targetID int64) *pairAgg {
		k := fmt.Sprintf("%d|%d", pocID, targetID)
		if agg, ok := pairs[k]; ok {
			return agg
		}
		agg := &pairAgg{pocID: pocID, targetID: targetID}
		pairs[k] = agg
		return agg
	}

	// ---- 任务流量记录：事件级请求/响应包缓冲，批量落库 ----
	// 锁内追加（seq 保事件顺序），锁外插入（DB 写不阻塞引擎事件管线；
	// 并发 flush 由 store 单连接在 DB 层天然串行化）。
	trafficOn := s.cfg.Scan.TrafficSave
	trafficMax := s.cfg.Scan.TrafficMaxBytes
	if trafficMax <= 0 {
		trafficMax = 65536
	}
	var trafficBuf []store.Traffic // mu 保护
	trafficSeq := 0                // mu 保护
	const trafficFlushRows = 256

	// recordTrafficLocked 截断并追加一条流量（须持 mu）；缓冲满时 swap 出快照返回。
	recordTrafficLocked := func(pocID, targetID int64, proto string, matched bool, status int, req, resp string) []store.Traffic {
		if !trafficOn {
			return nil
		}
		req, reqTr := truncateTraffic(req, trafficMax)
		resp, respTr := truncateTraffic(resp, trafficMax)
		trafficSeq++
		trafficBuf = append(trafficBuf, store.Traffic{
			ScanID: scanID, TargetID: targetID, POCID: pocID, Seq: trafficSeq,
			Protocol: proto, Matched: matched, Status: status,
			Request: req, Response: resp, ReqTruncated: reqTr, RespTruncated: respTr,
		})
		if len(trafficBuf) >= trafficFlushRows {
			out := trafficBuf
			trafficBuf = nil
			return out
		}
		return nil
	}

	// drainTraffic 取出并清空残余缓冲（自带锁，幂等）。
	drainTraffic := func() []store.Traffic {
		mu.Lock()
		defer mu.Unlock()
		out := trafficBuf
		trafficBuf = nil
		return out
	}

	// insertTraffic 锁外批量落库（失败仅告警丢弃：流量是审计数据，不影响判定）。
	insertTraffic := func(rows []store.Traffic) {
		if len(rows) == 0 {
			return
		}
		if err := s.store.InsertTraffic(rows); err != nil {
			slog.Warn("insert traffic dropped", "scan", scanID, "rows", len(rows), "err", err)
		}
	}
	// panic 兜底闭包（executeScan 顶部 defer 调用）
	flushPanicTraffic = func() { insertTraffic(drainTraffic()) }

	timeoutSec, retries, rateLimit := s.resolveScanOpts(req)
	loaded := map[string]bool{} // 引擎实际加载的模板 ID（能力门控/主协议过滤后）

	// ---- 逐连接流量镜像：进程内 socks5 代理串联引擎出口 ----
	// nuclei 事件模型只回调最终请求（fuzz 字典/多请求攻击链的中间请求
	// 在 SDK 层拿不到），镜像代理在传输层逐连接记录双向字节流补全。
	// 上游 = 用户配置的扫描代理（空 = 直连）；引擎 Proxy 改指本地镜像。
	var mirror *engine.MirrorProxy
	var dumpBuf []store.TrafficDump // mu 保护
	dumpSeq := 0                    // mu 保护
	const dumpFlushRows = 128
	insertDump := func(rows []store.TrafficDump) {
		if len(rows) == 0 {
			return
		}
		if err := s.store.InsertTrafficDump(rows); err != nil {
			slog.Warn("insert traffic dump dropped", "scan", scanID, "rows", len(rows), "err", err)
		}
	}
	if trafficOn {
		mirror, err = engine.StartMirror(req.Proxy, trafficMax, func(d engine.ConnDump) {
			var flush []store.TrafficDump
			func() {
				mu.Lock()
				defer mu.Unlock()
				dumpSeq++
				dumpBuf = append(dumpBuf, store.TrafficDump{
					ScanID: scanID, Seq: dumpSeq, Addr: d.Addr,
					StartedAt: d.StartedAt.Format("2006-01-02 15:04:05"),
					DurationMs: d.DurationMs,
					ClientData: d.ClientData, ServerData: d.ServerData,
					ClientLen: d.ClientLen, ServerLen: d.ServerLen,
					ClientTrunc: d.ClientTrunc, ServerTrunc: d.ServerTrunc,
				})
				if len(dumpBuf) >= dumpFlushRows {
					flush = dumpBuf
					dumpBuf = nil
				}
			}()
			insertDump(flush)
		})
		if err != nil {
			// 镜像启动失败：降级直连/直接走用户代理，事件级流量照常记录
			slog.Warn("traffic mirror unavailable, fallback to direct proxy", "scan", scanID, "err", err)
			mirror = nil
		}
	}
	engineProxy := req.Proxy
	if mirror != nil {
		engineProxy = mirror.Addr()
	}
	// drainDump 取出残余镜像缓冲（自带锁，幂等）。
	drainDump := func() []store.TrafficDump {
		mu.Lock()
		defer mu.Unlock()
		out := dumpBuf
		dumpBuf = nil
		return out
	}
	// panic 兜底一并冲刷镜像缓冲。
	flushPanicDump = func() { insertDump(drainDump()) }

	// 引擎分批执行：HTTP 目标×全部模板、TCP 目标×仅 network 模板。
	// 两批共用事件回调与 (poc,target) 聚合；任一批失败即终止后续批次。
	type execBatch struct {
		name    string
		targets []string
		paths   []string
	}
	batches := make([]execBatch, 0, 2)
	if len(httpTargetURLs) > 0 && len(paths) > 0 {
		batches = append(batches, execBatch{name: "http", targets: httpTargetURLs, paths: paths})
	}
	if len(tcpTargetURLs) > 0 && len(tcpPaths) > 0 {
		batches = append(batches, execBatch{name: "tcp", targets: tcpTargetURLs, paths: tcpPaths})
	}
	for _, b := range batches {
		if ctx.Err() != nil {
			status = "canceled"
			break
		}
		err = engine.Run(ctx, engine.Options{
			TemplatePaths: b.paths,
			Targets:       b.targets,
			ProtocolTypes: "http,websocket,code,tcp",
			TimeoutSec:    timeoutSec,
			Retries:       retries,
			RateLimitPerS: rateLimit,
			// 扫描流量出口：镜像代理地址（上游串联用户代理/直连）；
			// 镜像不可用时回退用户代理（空 = 直连）
			Proxy:     engineProxy,
			Interactsh: false,
			OnLoaded: func(ids []string) {
				for _, id := range ids {
					loaded[id] = true
				}
				slog.Info("engine loaded templates", "scan", scanID, "batch", b.name, "loaded", len(ids), "of", len(b.paths))
			},
			OnResult: func(ev engine.ResultEvent) {
				var flush []store.Traffic
				func() {
					mu.Lock()
					defer mu.Unlock()
					pocID, ok := tplToPOC[ev.TemplateID]
					if !ok {
						slog.Debug("OnResult template not in map", "tpl", ev.TemplateID, "host", ev.Host)
						return
					}
					tid, ok := hostToTarget[target.HostKey(ev.Host)]
					if !ok {
						slog.Debug("OnResult host not in map", "tpl", ev.TemplateID, "host", ev.Host, "hostkey", target.HostKey(ev.Host))
						return
					}
					agg := getPair(pocID, tid)
					agg.matched = true
					agg.matcherName = ev.MatcherName
					agg.matchedAt = ev.MatchedAt
					if ev.Status > 0 {
						agg.status = ev.Status
					}
					if agg.bodySnippet == "" {
						agg.bodySnippet = verdict.BodySnippet(ev.Response)
					}
					flush = recordTrafficLocked(pocID, tid, ev.Type, true, ev.Status, ev.Request, ev.Response)
					seen++
					if seen%progressEvery == 0 {
						_ = s.store.UpdateScanDone(scanID, seen)
						s.bus.publish(scanID, Event{Type: "progress", Done: seen, Total: total})
					}
				}()
				insertTraffic(flush)
			},
			OnFailure: func(ev engine.FailureEvent) {
				var flush []store.Traffic
				func() {
					mu.Lock()
					defer mu.Unlock()
					pocID, ok := tplToPOC[ev.TemplateID]
					if !ok {
						slog.Debug("OnFailure template not in map", "tpl", ev.TemplateID, "host", ev.Host)
						return
					}
					tid, ok := hostToTarget[target.HostKey(ev.Host)]
					if !ok {
						slog.Debug("OnFailure host not in map", "tpl", ev.TemplateID, "host", ev.Host, "hostkey", target.HostKey(ev.Host))
						return
					}
					agg := getPair(pocID, tid)
					if ev.Status > 0 {
						agg.status = ev.Status
					}
					if agg.bodySnippet == "" {
						agg.bodySnippet = verdict.BodySnippet(ev.Response)
					}
					if ev.ErrText != "" {
						agg.failureText = appendText(agg.failureText, ev.ErrText)
					}
					// network 协议发出后零响应且无错误：nuclei 静默等满超时
				// 不报错（区别于 HTTP 超时会带 timeout 错误文本），
				// 事件级表现为 request 有 payload、response 空、err 空——
				// 记为攻击送达但被静默丢弃（→TIMEOUT），不再无痕 MISS。
				// 注意事件 type 为 "tcp"（nuclei 内部对 network 协议的执行名）。
				if ev.Type == "tcp" && ev.Request != "" && ev.Response == "" && ev.ErrText == "" {
					agg.noResponse = true
				}
					flush = recordTrafficLocked(pocID, tid, ev.Type, false, ev.Status, ev.Request, ev.Response)
					seen++
					if seen%progressEvery == 0 {
						s.bus.publish(scanID, Event{Type: "progress", Done: seen, Total: total})
					}
				}()
				insertTraffic(flush)
			},
		})
		// 引擎对整批模板报"无可用模板"（如 dast/fuzz 模板全被能力门控过滤）：
		// 非系统故障，不判 failed——判定阶段按"引擎未加载"计入跳过统计
		if err != nil && strings.Contains(err.Error(), "No templates available") {
			slog.Info("engine loaded no templates (all filtered by capability gating)", "scan", scanID, "batch", b.name)
			err = nil
			continue
		}
		if err != nil {
			break // 失败/取消：终止后续批次，统一在下方处理状态
		}
	} // for batches
	if err != nil {
		if ctx.Err() != nil {
			status = "canceled"
		} else {
			status = "failed"
			finalErr = err.Error()
			slog.Error("engine run failed", "scan", scanID, "err", err)
		}
	}
	// 流量收尾：engine.Run 全部出口（completed/canceled/failed/无模板）统一
	// 落库残余缓冲，保证 FinishScan 前流量完整（幂等，panic 路径由 defer 兜底）。
	// 镜像代理先 Close（等残余连接收尾、dump 回调全部入缓冲）再统一冲刷。
	if mirror != nil {
		mirror.Close()
	}
	insertTraffic(drainTraffic())
	insertDump(drainDump())

	// 5. 全矩阵判定（无事件对补账 MISS）
	classifier := verdict.NewClassifier(s.cfg.Verdict.BlockedStatuses)
	var results []store.Result
	counters := store.VerdictCounters{}

	mu.Lock()
	for _, p := range executable {
		// 引擎加载阶段被能力门控过滤（dast/fuzz 等特殊能力模板）或主协议不匹配：
		// 模板实际未执行，计入跳过统计（不生成任务，不误报 MISS/ERROR）
		if !loaded[p.TemplateID] {
			skipCount[skipReasonUnloaded]++
			continue
		}
		isNetwork := strings.Contains(p.Protocols, `"network"`)
		for _, t := range live {
			// 矩阵按协议互斥：TCP 目标仅执行 network 协议 POC，HTTP 目标仅执行
			// 非 network 协议 POC。未进引擎矩阵的组合不生成结果记录
			// （同一目标的两种表达合计恰好每个 POC 执行一次）
			if target.IsTCP(t.URL) != isNetwork {
				continue
			}
			judged++
			agg := pairs[fmt.Sprintf("%d|%d", p.ID, t.ID)]
			ev := verdict.Evidence{Baseline: baselines[t.ID]}
			if agg != nil {
				ev.Matched = agg.matched
				ev.Status = agg.status
				ev.BodySnippet = agg.bodySnippet
				ev.FailureText = agg.failureText
				ev.NoResponse = agg.noResponse
			}
			kind := classifier.Classify(ev)
			var matchedAt, matcherName, errText string
			var respStatus int
			if agg != nil {
				matcherName = agg.matcherName
				matchedAt = agg.matchedAt
				respStatus = agg.status
				errText = agg.failureText
			}
			evidence, _ := json.Marshal(map[string]any{
				"status":  respStatus,
				"snippet": ev.BodySnippet,
				"failure": errText,
			})
			results = append(results, store.Result{
				ScanID:         scanID,
				TargetID:       t.ID,
				POCID:          p.ID,
				Verdict:        string(kind),
				MatchedAt:      matchedAt,
				MatcherName:    matcherName,
				ResponseStatus: respStatus,
				ErrorText:      truncate(errText, 500),
				Evidence:       string(evidence),
			})
			switch kind {
			case verdict.HIT:
				counters.Hit++
			case verdict.BLOCKED:
				counters.Blocked++
			case verdict.TIMEOUT:
				counters.Timeout++
			case verdict.UNREACHABLE:
				counters.Unreachable++
			case verdict.MISS:
				counters.Miss++
			default:
				counters.Error++
			}
			// 逐结果发布事件
			s.bus.publish(scanID, Event{Type: "result", Result: &ResultPayload{
				TargetID:       t.ID,
				TargetURL:      t.URL,
				POCID:          p.ID,
				TemplateID:     p.TemplateID,
				Severity:       p.Severity,
				Verdict:        string(kind),
				ResponseStatus: respStatus,
				ErrorText:      truncate(errText, 200),
			}})
			if judged%progressEvery == 0 {
				_ = s.store.UpdateScanDone(scanID, judged)
				s.bus.publish(scanID, Event{Type: "progress", Done: judged, Total: total})
			}
		}
	}
	mu.Unlock()

	// 6. 批量落库（跳过统计附加到扫描说明，详情页横幅展示）
	if err := s.store.InsertResults(results); err != nil {
		slog.Error("insert results", "scan", scanID, "err", err)
	}
	if note := formatSkipNote(skipCount); note != "" {
		if finalErr == "" {
			finalErr = note
		} else {
			finalErr = finalErr + "；" + note
		}
		slog.Info("scan skipped non-executable templates", "scan", scanID, "note", note)
	}
	_ = s.store.FinishScan(scanID, status, counters, finalErr)
	_ = s.store.UpdateScanDone(scanID, len(results))
	slog.Info("scan finished",
		"scan", scanID, "status", status,
		"hit", counters.Hit, "blocked", counters.Blocked, "timeout", counters.Timeout,
		"miss", counters.Miss, "error", counters.Error)
	s.bus.publish(scanID, Event{Type: "done", Done: len(results), Total: total, ErrText: finalErr})
}

// finishScan 兜底结束扫描（executeScan 正常路径已自行 FinishScan，
// 此处仅覆盖失败/panic/canceled 等提前退出场景）。
func (s *Service) finishScan(scanID int64, status, finalErr string) {
	sc, err := s.store.GetScan(scanID)
	if err != nil || sc == nil {
		return
	}
	if sc.Status == "running" {
		_ = s.store.FinishScan(scanID, status, store.VerdictCounters{}, finalErr)
	}
	if finalErr != "" {
		s.bus.publish(scanID, Event{Type: "error", ErrText: finalErr})
	}
}

func targetIDs(ts []store.Target) []int64 {
	ids := make([]int64, 0, len(ts))
	for _, t := range ts {
		ids = append(ids, t.ID)
	}
	return ids
}

func appendText(old, new string) string {
	if old == "" {
		return new
	}
	if strings.Contains(old, new) {
		return old
	}
	return old + "; " + new
}

// truncateTraffic 流量字段截断（头部截断天然保留 HTTP 状态行与 headers，
// WAF 指纹所在）并清洗为合法 UTF-8（tcp raw/gzip body 等二进制数据防 JSON
// 序列化异常；字节截断可能切断多字节字符，截断后再清洗补 U+FFFD）。
func truncateTraffic(s string, n int) (string, bool) {
	if len(s) > n {
		return strings.ToValidUTF8(s[:n], "\uFFFD") + "...", true
	}
	return strings.ToValidUTF8(s, "\uFFFD"), false
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// 扫描级跳过原因（计数聚合 key，最终拼入扫描说明展示于详情页横幅）。
const (
	skipReasonHeadless    = "headless 需浏览器环境"
	skipReasonProtocol    = "协议暂不支持（引擎支持 http/websocket/code/tcp）"
	skipReasonSelfCont    = "self-contained 自包含模板（不针对扫描目标）"
	skipReasonUnloaded    = "引擎加载时被跳过（旧数据兜底：索引期已引擎级验证，重新索引可消除）"
	skipReasonInteractsh  = "依赖 OOB 回连（interactsh 已禁用，恒定失败）"
	skipReasonCreds       = "需运行时输入（凭证/vars 变量，无输入时无有效请求）"
	skipReasonTCPMismatch = "TCP 目标仅执行 network 协议 POC"
	skipReasonHTTPMismatch = "HTTP 目标仅执行 http/websocket 协议 POC（network POC 仅打 TCP 目标）"
	skipReasonPureCode    = "纯 code 脚本模板（本地子进程发请求，无流量数据且依赖本机工具）"
)

// classifyPOCs 按引擎可执行性分类选中模板。
// 索引期已完成静态预过滤 + 引擎真实加载验证（加载成功的才入库），
// 入库的都是可执行的。此处为旧数据兜底（重新索引后理论上不再命中）。
func (s *Service) classifyPOCs(ctx context.Context, list []store.POC) (executable []store.POC, skip map[string]int) {
	executable = make([]store.POC, 0, len(list))
	skip = map[string]int{}
	for _, p := range list {
		// 兜底：索引过滤后不应出现这些情况，但旧数据可能未过滤
		if strings.Contains(p.Protocols, `"headless"`) {
			skip[skipReasonHeadless]++
			continue
		}
		// OOB 回连依赖：引擎禁用 interactsh，此类模板恒定 ERROR（前置拦截）
		if p.HasInteractsh {
			skip[skipReasonInteractsh]++
			continue
		}
		// 凭证依赖：无凭证输入时不产生有效请求（前置拦截）
		if isCredsTemplate(p) {
			skip[skipReasonCreds]++
			continue
		}
		if !strings.Contains(p.Protocols, `"http"`) &&
			!strings.Contains(p.Protocols, `"websocket"`) &&
			!strings.Contains(p.Protocols, `"code"`) &&
			!strings.Contains(p.Protocols, `"network"`) {
			skip[skipReasonProtocol]++
			continue
		}
		// 纯 code 模板兜底：本地子进程发请求，无流量数据且依赖本机外部工具
		if isPureCodeProtocols(p.Protocols) {
			skip[skipReasonPureCode]++
			continue
		}
		if p.SelfContained == 1 {
			skip[skipReasonSelfCont]++
			continue
		}
		executable = append(executable, p)
	}
	return executable, skip
}

// isCredsTemplate 判断是否为凭证依赖模板（login-check/creds-stuffing 标签）。
// 索引时通过 YAML 变量声明模式检测（NeedsCredentials），此处按标签兜底旧数据。
func isCredsTemplate(p store.POC) bool {
	return strings.Contains(p.Tags, ",login-check,") || strings.Contains(p.Tags, ",creds-stuffing,")
}

// isPureCodeProtocols 判断 Protocols JSON 串是否为纯 code（含 code 且不含 http/network/websocket）。
func isPureCodeProtocols(protocols string) bool {
	return strings.Contains(protocols, `"code"`) &&
		!strings.Contains(protocols, `"http"`) &&
		!strings.Contains(protocols, `"network"`) &&
		!strings.Contains(protocols, `"websocket"`)
}

// POCClassifyResult 单个 POC 的可执行性分类结果。
type POCClassifyResult struct {
	POCID      int64  `json:"poc_id"`
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Executable bool   `json:"executable"`
	Reason     string `json:"reason,omitempty"` // 不可执行原因（空=可执行）
}

// ClassifyPOCsByIDs 按 ID 查询 POC 并分类可执行性，返回逐项结果。
// 用于添加模板集时即时提醒用户哪些模板不可执行及原因。
func (s *Service) ClassifyPOCsByIDs(ctx context.Context, ids []int64) ([]POCClassifyResult, error) {
	pocs, err := s.store.ListPOCs(store.POCFilter{IDs: ids, Limit: len(ids)})
	if err != nil {
		return nil, fmt.Errorf("query pocs: %w", err)
	}
	executable, skip := s.classifyPOCs(ctx, pocs)

	// 构建可执行集合
	execSet := make(map[int64]bool, len(executable))
	for _, p := range executable {
		execSet[p.ID] = true
	}
	// 逐项标记
	out := make([]POCClassifyResult, 0, len(pocs))
	for _, p := range pocs {
		r := POCClassifyResult{POCID: p.ID, TemplateID: p.TemplateID, Name: p.Name}
		if execSet[p.ID] {
			r.Executable = true
		} else {
			r.Reason = classifyReason(p)
		}
		out = append(out, r)
	}
	_ = skip // skip 已在 classifyPOCs 内部用于聚合统计，这里逐项展示
	return out, nil
}

// classifyReason 根据 POC 属性判定不可执行原因（与 classifyPOCs 逻辑一致）。
// 对于通过了协议过滤且非自包含的模板，返回 skipReasonUnloaded 作为兜底——
// 这类模板在引擎加载阶段可能因签名验证、能力门控等动态检查被跳过，
// 具体原因需扫描时才能确定。
func classifyReason(p store.POC) string {
	if strings.Contains(p.Protocols, `"headless"`) {
		return skipReasonHeadless
	}
	if p.HasInteractsh {
		return skipReasonInteractsh
	}
	if isCredsTemplate(p) {
		return skipReasonCreds
	}
	if !strings.Contains(p.Protocols, `"http"`) &&
		!strings.Contains(p.Protocols, `"websocket"`) &&
		!strings.Contains(p.Protocols, `"code"`) &&
		!strings.Contains(p.Protocols, `"network"`) {
		return skipReasonProtocol
	}
	if isPureCodeProtocols(p.Protocols) {
		return skipReasonPureCode
	}
	if p.SelfContained == 1 {
		return skipReasonSelfCont
	}
	return skipReasonUnloaded
}

// formatSkipNote 汇总跳过统计为扫描级说明（如"已跳过 88 个不可执行模板：…"）。
func formatSkipNote(skip map[string]int) string {
	if len(skip) == 0 {
		return ""
	}
	total := 0
	keys := make([]string, 0, len(skip))
	for k, v := range skip {
		total += v
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s × %d", k, skip[k]))
	}
	return fmt.Sprintf("已跳过 %d 个不可执行模板：%s", total, strings.Join(parts, "、"))
}
