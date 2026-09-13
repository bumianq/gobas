package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"gobas/internal/report"
	"gobas/internal/service"
	"gobas/internal/store"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ImportCSV string  `json:"import_csv"`
		Workers   int     `json:"workers"`
		// Proxy 代理覆盖：null/缺省 = 用配置代理；"" = 本次直连；URL = 用该代理
		Proxy *string `json:"proxy"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	// 后台启动：全量同步可长达数十分钟，立即返回，
	// 实时进度经 GET /sync/events（SSE）推送。
	if err := s.svc.StartSyncAsync(req.ImportCSV, req.Workers, req.Proxy); err != nil {
		if errors.Is(err, service.ErrSyncBusy) {
			writeErr(w, http.StatusConflict, err)
			return
		}
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true})
}

// handleSyncEvents SSE 实时推送同步进度（轮询内部状态快照）。
//
// 协议：
//
//	event: progress   // data: {done,total,running}
//	event: result     // data: {result} 单仓库完成
//	event: done       // data: {done,total,err_text} 同步结束
func (s *Server) handleSyncEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, errors.New("streaming unsupported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ticker := time.NewTicker(700 * time.Millisecond)
	defer ticker.Stop()

	sent := 0 // 已推送的结果数（用于增量）
	everSeen := false
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			st := s.svc.SyncStatusNow()
			if st.Total == 0 && !everSeen {
				continue // 尚未有任何同步启动（前端先 POST 再连 SSE，正常不至此）
			}
			everSeen = true
			// 进度变化才推
			if err := writeSSE(w, "progress", map[string]any{
				"done": st.Done, "total": st.Total, "running": st.Running,
			}); err != nil {
				return
			}
			// 增量推送新完成的结果
			for i := sent; i < len(st.Results); i++ {
				if err := writeSSE(w, "result", map[string]any{"result": st.Results[i]}); err != nil {
					return
				}
			}
			sent = len(st.Results)
			flusher.Flush()
			if st.Finished {
				_ = writeSSE(w, "done", map[string]any{
					"done": st.Done, "total": st.Total, "err_text": st.ErrText,
				})
				flusher.Flush()
				return
			}
		}
	}
}

// handleSyncStatus 同步状态快照（非流式轮询备用）。
func (s *Server) handleSyncStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.SyncStatusNow())
}

// handleSettings 返回运行时设置（GUI 展示用）。
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"proxy": s.svc.ProxyConfig(),
	})
}

func pocFilterFromQuery(r *http.Request) store.POCFilter {
	q := r.URL.Query()
	atoi := func(k string) int {
		n, _ := strconv.Atoi(q.Get(k))
		return n
	}
	return store.POCFilter{
		SetID:        int64(atoi("set_id")),
		Severity:     q.Get("severity"),
		Tag:          q.Get("tag"),
		Protocol:     q.Get("protocol"),
		Official:     q.Get("official"),
		Custom:       q.Get("custom"),
		Executable:   q.Get("executable"),
		CVE:          q.Get("cve"),
		CNVD:         q.Get("cnvd"),
		Keyword:      q.Get("search"),
		NoInteractsh: q.Get("no_interactsh") == "true",
		Limit:        atoi("limit"),
		Offset:       atoi("offset"),
	}
}

func (s *Server) handleListPOCs(w http.ResponseWriter, r *http.Request) {
	filter := pocFilterFromQuery(r)
	pocs, err := s.svc.QueryPOCs(r.Context(), filter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	total, err := s.svc.CountPOCs(r.Context(), filter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pocs": pocs, "total": total})
}

// handleIndexPOCs 后台重建 POC 索引（立即返回，进度经 /pocs/index/events）。
func (s *Server) handleIndexPOCs(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.StartIndexAsync(nil); err != nil {
		if errors.Is(err, service.ErrSyncBusy) {
			writeErr(w, http.StatusConflict, err)
			return
		}
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true})
}

// handleIndexStatus 索引状态快照（非流式轮询备用）。
func (s *Server) handleIndexStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.IndexStatusNow())
}

// handleIndexEvents SSE 实时推送索引进度。
//
// 协议：
//
//	event: progress   // data: {done,total,current_repo}
//	event: done       // data: {done,total,stats,err_text}
func (s *Server) handleIndexEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, errors.New("streaming unsupported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ticker := time.NewTicker(600 * time.Millisecond)
	defer ticker.Stop()

	lastDone := -1
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			st := s.svc.IndexStatusNow()
			if !st.Running && !st.Finished {
				continue // 尚未有索引任务
			}
			// 进度变化或刚开始才推，避免无效流量
			if st.Done != lastDone || st.Total == 0 {
				lastDone = st.Done
				if err := writeSSE(w, "progress", map[string]any{
					"done": st.Done, "total": st.Total, "current_repo": st.CurrentRepo,
				}); err != nil {
					return
				}
				flusher.Flush()
			}
			if st.Finished {
				_ = writeSSE(w, "done", map[string]any{
					"done": st.Done, "total": st.Total, "stats": st.Stats, "err_text": st.ErrText,
				})
				flusher.Flush()
				return
			}
		}
	}
}

func (s *Server) handlePOCStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.svc.POCStats(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleGetPOC(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	pocs, err := s.svc.QueryPOCs(r.Context(), store.POCFilter{IDs: []int64{id}})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if len(pocs) == 0 {
		writeErr(w, http.StatusNotFound, errNotFound)
		return
	}
	writeJSON(w, http.StatusOK, pocs[0])
}

// customPOCReq 人工 POC 添加/修改请求体。
type customPOCReq struct {
	Content string `json:"content"` // nuclei 模板 YAML 原文
}

// handleAddCustomPOC 人工添加 POC。
func (s *Server) handleAddCustomPOC(w http.ResponseWriter, r *http.Request) {
	var req customPOCReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	p, err := s.svc.AddCustomPOC(r.Context(), req.Content)
	if err != nil {
		writeCustomPOCErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

// handleUpdateCustomPOC 修改人工 POC。
func (s *Server) handleUpdateCustomPOC(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	var req customPOCReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	p, err := s.svc.UpdateCustomPOC(r.Context(), id, req.Content)
	if err != nil {
		writeCustomPOCErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// handleDeleteCustomPOC 删除人工 POC。
func (s *Server) handleDeleteCustomPOC(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.svc.DeleteCustomPOC(id); err != nil {
		writeCustomPOCErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// handleGetPOCContent 获取人工 POC 模板 YAML 原文（编辑回显用）。
func (s *Server) handleGetPOCContent(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	content, err := s.svc.GetPOCContent(id)
	if err != nil {
		writeCustomPOCErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"content": content})
}

// writeCustomPOCErr 人工 POC 操作错误 → HTTP 状态码映射。
func writeCustomPOCErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrPOCNotFound):
		writeErr(w, http.StatusNotFound, err)
	case errors.Is(err, service.ErrNotCustomPOC):
		writeErr(w, http.StatusForbidden, err)
	case errors.Is(err, service.ErrTemplateIDTaken):
		writeErr(w, http.StatusConflict, err)
	default:
		writeErr(w, http.StatusBadRequest, err)
	}
}

func (s *Server) handleAddTargets(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URLs []string `json:"urls"`
		Name string   `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	var targets []store.Target
	for _, u := range req.URLs {
		t, err := s.svc.AddTarget(r.Context(), u, req.Name)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		targets = append(targets, *t)
	}
	writeJSON(w, http.StatusOK, map[string]any{"targets": targets})
}

func (s *Server) handleListTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := s.svc.ListTargets(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"targets": targets})
}

func (s *Server) handleProbeTargets(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	targets, err := s.svc.ProbeTargets(r.Context(), req.IDs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"targets": targets})
}

func (s *Server) handleDeleteTarget(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.svc.RemoveTarget(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string   `json:"name"`
		TargetIDs   []int64  `json:"target_ids"`
		POCIDs      []int64  `json:"poc_ids"`
		PocSetID    int64    `json:"poc_set_id"`
		Executable  string   `json:"executable"`
		Severity    string   `json:"severity"`
		Tag         string   `json:"tag"`
		CVE         string   `json:"cve"`
		CNVD        string   `json:"cnvd"`
		Search      string   `json:"search"`
		Protocol    string   `json:"protocol"`
		Official    string   `json:"official"`
		Custom      string   `json:"custom"` // "true"=仅人工添加 / "false"=仅自动拉取 / ""=全部（与 official 组合使用）
		NoInteractsh bool    `json:"no_interactsh"`
		Max         int      `json:"max"`
		IncludeDead bool     `json:"include_dead"`
		// Proxy 扫描流量出口代理：空/缺省 = 直连；URL = 攻击流量经该代理发出
		Proxy *string `json:"proxy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	proxy := ""
	if req.Proxy != nil {
		proxy = *req.Proxy
	}
	scanID, err := s.svc.StartScan(r.Context(), service.ScanRequest{
		Name:      req.Name,
		TargetIDs: req.TargetIDs,
		POCFilter: store.POCFilter{
			IDs:          req.POCIDs,
			SetID:        req.PocSetID,
			Executable:   req.Executable,
			Severity:     req.Severity,
			Tag:          req.Tag,
			CVE:          req.CVE,
			CNVD:         req.CNVD,
			Keyword:      req.Search,
			Protocol:     req.Protocol,
			Official:     req.Official,
			Custom:       req.Custom,
			NoInteractsh: req.NoInteractsh,
			Limit:        req.Max,
		},
		IncludeDead: req.IncludeDead,
		Proxy:       proxy,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"scan_id": scanID})
}

// ---- POC 模板集 ----

func (s *Server) handleListPOCSets(w http.ResponseWriter, r *http.Request) {
	sets, err := s.svc.ListPOCSets()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if sets == nil {
		sets = []store.POCSet{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sets": sets})
}

func (s *Server) handleCreatePOCSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string  `json:"name"`
		Description string  `json:"description"`
		POCIDs      []int64 `json:"poc_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeErr(w, http.StatusBadRequest, errors.New("name required"))
		return
	}
	ps, err := s.svc.CreatePOCSet(strings.TrimSpace(req.Name), req.Description, req.POCIDs)
	if err != nil {
		if errors.Is(err, store.ErrSetNameExists) {
			writeErr(w, http.StatusConflict, err)
			return
		}
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	// 分类可执行性：让前端即时提醒用户哪些模板不可执行
	classification, _ := s.svc.ClassifyPOCsByIDs(r.Context(), req.POCIDs)
	writeJSON(w, http.StatusCreated, map[string]any{"id": ps.ID, "name": ps.Name, "poc_count": ps.POCCount, "classification": classification})
}

func setIDFromURL(r *http.Request) (int64, error) {
	return strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
}

func (s *Server) handleGetPOCSet(w http.ResponseWriter, r *http.Request) {
	id, err := setIDFromURL(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	ps, err := s.svc.GetPOCSet(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	pocs, err := s.svc.ListPOCsInSet(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"set": ps, "pocs": pocs})
}

func (s *Server) handleUpdatePOCSet(w http.ResponseWriter, r *http.Request) {
	id, err := setIDFromURL(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.svc.UpdatePOCSet(id, req.Name, req.Description); err != nil {
		if errors.Is(err, store.ErrSetNameExists) {
			writeErr(w, http.StatusConflict, err)
			return
		}
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleDeletePOCSet(w http.ResponseWriter, r *http.Request) {
	id, err := setIDFromURL(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.svc.DeletePOCSet(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleAddPOCsToSet 批量加入 POC 到模板集（幂等）。
func (s *Server) handleAddPOCsToSet(w http.ResponseWriter, r *http.Request) {
	id, err := setIDFromURL(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	var req struct {
		POCIDs []int64 `json:"poc_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	added, err := s.svc.AddPOCsToSet(id, req.POCIDs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	// 分类可执行性：让前端即时提醒用户哪些模板不可执行
	classification, _ := s.svc.ClassifyPOCsByIDs(r.Context(), req.POCIDs)
	writeJSON(w, http.StatusOK, map[string]any{"added": added, "classification": classification})
}

// handleRemovePOCsFromSet 批量移除（poc_ids 空数组/缺省 = 清空整个集）。
func (s *Server) handleRemovePOCsFromSet(w http.ResponseWriter, r *http.Request) {
	id, err := setIDFromURL(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	var req struct {
		POCIDs []int64 `json:"poc_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	removed, err := s.svc.RemovePOCsFromSet(id, req.POCIDs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"removed": removed})
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if offset < 0 {
		offset = 0
	}
	scans, err := s.svc.ListScans(r.Context(), limit, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	total, err := s.svc.CountScans(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scans": scans, "total": total})
}

func scanIDFromURL(r *http.Request) (int64, error) {
	return strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	id, err := scanIDFromURL(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	sc, err := s.svc.GetScan(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if sc == nil {
		writeErr(w, http.StatusNotFound, errNotFound)
		return
	}
	writeJSON(w, http.StatusOK, sc)
}

func (s *Server) handleScanResults(w http.ResponseWriter, r *http.Request) {
	id, err := scanIDFromURL(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	results, err := s.svc.ScanResults(r.Context(), id, r.URL.Query().Get("verdict"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// handleScanTraffic 扫描任务流量（请求/响应包记录）。
// query：poc_id/target_id（<=0 不过滤）、search（包内容特征搜索关键词）、
// field（搜索字段：request/response，缺省=两者）、limit（默认 1000，上限 10000）、offset。
func (s *Server) handleScanTraffic(w http.ResponseWriter, r *http.Request) {
	id, err := scanIDFromURL(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	q := r.URL.Query()
	atoi64 := func(k string) int64 {
		n, _ := strconv.ParseInt(q.Get(k), 10, 64)
		return n
	}
	atoi := func(k string) int {
		n, _ := strconv.Atoi(q.Get(k))
		return n
	}
	rows, total, err := s.svc.ScanTraffic(r.Context(), id, atoi64("poc_id"), atoi64("target_id"),
		q.Get("search"), q.Get("field"), atoi("limit"), atoi("offset"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if rows == nil {
		rows = []store.TrafficDetail{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"traffic": rows, "total": total})
}

// handleScanTrafficDump 扫描镜像连接流水（socks5 镜像代理逐连接捕获的
// 双向原始字节流，含 fuzz 字典/多请求攻击链的全部中间请求）。
// query：limit（默认 200，上限 10000）、offset。
func (s *Server) handleScanTrafficDump(w http.ResponseWriter, r *http.Request) {
	id, err := scanIDFromURL(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 200
	}
	if limit > 10000 {
		limit = 10000
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	rows, total, err := s.svc.ScanTrafficDump(id, limit, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if rows == nil {
		rows = []store.TrafficDump{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"dump": rows, "total": total})
}

// handleUpdateScanVerdicts 人工修正扫描结果判定（单个/批量/按类别/恢复）。
// body：{"result_ids":[...], "from_verdict":"", "to_verdict":""}。
// to_verdict 为空 = 恢复机器自动判定（须指定 result_ids 或 from_verdict）。
func (s *Server) handleUpdateScanVerdicts(w http.ResponseWriter, r *http.Request) {
	id, err := scanIDFromURL(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	var req service.VerdictUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	n, err := s.svc.UpdateScanVerdicts(r.Context(), id, req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"updated": n})
}

func (s *Server) handleCancelScan(w http.ResponseWriter, r *http.Request) {
	id, err := scanIDFromURL(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.svc.CancelScan(r.Context(), id); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "canceling"})
}

// handleDeleteScan 删除扫描历史（结果/流量级联删除；运行中拒绝）。
func (s *Server) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	id, err := scanIDFromURL(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.svc.DeleteScan(r.Context(), id); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	id, err := scanIDFromURL(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "md"
	}
	m, err := s.svc.BuildReport(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="gobas-report-`+
		strconv.FormatInt(id, 10)+`.`+format+`"`)
	if err := report.Export(m, format, w); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
}
