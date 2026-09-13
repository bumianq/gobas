package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

var errNotFound = errors.New("not found")

// sseHeartbeat 每 15s 发送注释行，防止代理/浏览器断开空闲连接。
const sseHeartbeat = 15 * time.Second

// handleScanEvents SSE 实时推送扫描事件流。
//
// 协议：
//
//	event: <type>          // progress|result|done|error
//	data: <json payload>
//
// 客户端断开、扫描结束（done/error）后连接关闭。
func (s *Server) handleScanEvents(w http.ResponseWriter, r *http.Request) {
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

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, errors.New("streaming unsupported"))
		return
	}

	// 已结束的扫描：重放汇总后立即结束（便于前端刷新页面补齐终态）。
	if sc.Status != "running" {
		writeSSE(w, "done", map[string]any{
			"scan_id": sc.ID,
			"status":  sc.Status,
			"done":    sc.DoneTasks,
			"total":   sc.TotalTasks,
		})
		flusher.Flush()
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	events, unsub := s.svc.SubscribeScan(id)
	defer unsub()

	// 先推一条当前进度快照，避免前端在首个事件前空白。
	writeSSE(w, "progress", map[string]any{
		"scan_id": sc.ID,
		"done":    sc.DoneTasks,
		"total":   sc.TotalTasks,
	})
	flusher.Flush()

	heartbeat := time.NewTicker(sseHeartbeat)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			// 竞态兜底：done 事件在订阅前已发布则通道静默，
			// 心跳时轮询状态，已结束则补发 done 并关闭。
			if sc, err := s.svc.GetScan(r.Context(), id); err == nil && sc != nil && sc.Status != "running" {
				writeSSE(w, "done", map[string]any{
					"scan_id": sc.ID,
					"status":  sc.Status,
					"done":    sc.DoneTasks,
					"total":   sc.TotalTasks,
				})
				flusher.Flush()
				return
			}
			// SSE 注释行保活
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case ev, ok := <-events:
			if !ok {
				return
			}
			if err := writeSSE(w, ev.Type, ev); err != nil {
				return
			}
			flusher.Flush()
			if ev.Type == "done" || ev.Type == "error" {
				return
			}
		}
	}
}

// writeSSE 写一条 SSE 事件（event + data JSON）。
func writeSSE(w http.ResponseWriter, event string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data); err != nil {
		return err
	}
	return nil
}
