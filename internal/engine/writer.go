package engine

import (
	"sync/atomic"
	"time"

	"github.com/logrusorgru/aurora/v4"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"

	"gobas/internal/verdict"
)

// eventWriter 实现 nuclei output.Writer 接口，是唯一的事件拦截点。
type eventWriter struct {
	onResult  func(ResultEvent)
	onFailure func(FailureEvent)
	count     atomic.Int32
}

var _ output.Writer = (*eventWriter)(nil)

func newEventWriter(onResult func(ResultEvent), onFailure func(FailureEvent)) *eventWriter {
	return &eventWriter{onResult: onResult, onFailure: onFailure}
}

// Close 实现 output.Writer。
func (w *eventWriter) Close() {}

// Colorizer 实现 output.Writer。
func (w *eventWriter) Colorizer() *aurora.Aurora { return nil }

// Write 拦截匹配事件（模板命中）。
func (w *eventWriter) Write(re *output.ResultEvent) error {
	w.count.Add(1)
	if w.onResult == nil || re == nil {
		return nil
	}
	ev := ResultEvent{
		TemplateID:  re.TemplateID,
		Host:        hostOf(re),
		Type:        re.Type,
		MatchedAt:   re.Matched,
		MatcherName: re.MatcherName,
		Request:     re.Request,
		Response:    re.Response,
		Status:      verdict.ParseResponseStatus(re.Response),
		Matched:     true, // Write 路径只承接匹配事件（WriteResult 仅在匹配时调用）
		ErrText:     re.Error,
		Timestamp:   re.Timestamp,
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	w.onResult(ev)
	return nil
}

// WriteFailure 拦截未匹配 / 失败事件。
// MatcherStatus 开启时，未命中模板的 (POC,目标) 对会经由此路径，
// InternalEvent 携带 response/status_code/error/host/template-id 原文。
func (w *eventWriter) WriteFailure(ev *output.InternalWrappedEvent) error {
	w.count.Add(1)
	if w.onFailure == nil || ev == nil {
		return nil
	}
	ie := ev.InternalEvent
	fe := FailureEvent{
		TemplateID: toString(ie["template-id"]),
		Host:       toString(ie["host"]),
		Type:       toString(ie["type"]),
		Status:     toInt(ie["status_code"]),
		Request:    toString(ie["request"]),
		Response:   responseOf(ie),
		ErrText:    toString(ie["error"]),
		Timestamp:  time.Now(),
	}
	// 合成事件路径（tmplexec fakeEvent）：结果在 Results 里
	if fe.TemplateID == "" && len(ev.Results) > 0 {
		re := ev.Results[len(ev.Results)-1]
		fe.TemplateID = re.TemplateID
		fe.Host = hostOf(re)
		if fe.ErrText == "" {
			fe.ErrText = re.Error
		}
	}
	w.onFailure(fe)
	return nil
}

// Request 实现 output.Writer（trace 日志，忽略）。
func (w *eventWriter) Request(templateID, url, requestType string, err error) {}

// RequestStatsLog 实现 output.Writer（统计日志，忽略）。
func (w *eventWriter) RequestStatsLog(statusCode, response string) {}

// WriteStoreDebugData 实现 output.Writer（调试落盘，忽略）。
func (w *eventWriter) WriteStoreDebugData(host, templateID, eventType string, data string) {}

// ResultCount 实现 output.Writer。
func (w *eventWriter) ResultCount() int { return int(w.count.Load()) }

// hostOf 从 ResultEvent 提取主机标识（优先完整 URL，其次 scheme://host:port）。
func hostOf(re *output.ResultEvent) string {
	if re == nil {
		return ""
	}
	if re.URL != "" {
		return re.URL
	}
	if re.Host != "" {
		if re.Scheme != "" {
			if re.Port != "" {
				return re.Scheme + "://" + re.Host + ":" + re.Port
			}
			return re.Scheme + "://" + re.Host
		}
		return re.Host
	}
	return re.Matched
}

// toString InternalEvent 值安全转字符串。
func toString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// toInt InternalEvent 值安全转整数。
func toInt(v interface{}) int {
	switch n := v.(type) {
	case int:
		return n
	case int32:
		return int(n)
	case int64:
		return int(n)
	case uint64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

// responseOf 提取事件响应原文（协议 fallback 链）。
// http/websocket 存 "response" 键；network/tcp 无该键，响应在
// "data"（最后读取字节）与 "raw"（完整交互数据）中。
func responseOf(ie map[string]interface{}) string {
	if s := toString(ie["response"]); s != "" {
		return s
	}
	if s := toString(ie["data"]); s != "" {
		return s
	}
	return toString(ie["raw"])
}
