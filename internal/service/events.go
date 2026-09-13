package service

import (
	"sync"
	"time"
)

// Event 扫描进度事件（CLI 直消费打印，server 转 SSE）。
type Event struct {
	Type      string    `json:"type"` // progress|result|done|error
	ScanID    int64     `json:"scan_id"`
	Done      int       `json:"done,omitempty"`
	Total     int       `json:"total,omitempty"`
	Result    *ResultPayload `json:"result,omitempty"`
	ErrText   string    `json:"err_text,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// ResultPayload 判定结果载荷（含可读名称）。
type ResultPayload struct {
	TargetID       int64  `json:"target_id"`
	TargetURL      string `json:"target_url"`
	POCID          int64  `json:"poc_id"`
	TemplateID     string `json:"template_id"`
	Severity       string `json:"severity,omitempty"`
	Verdict        string `json:"verdict"`
	ResponseStatus int    `json:"response_status,omitempty"`
	ErrorText      string `json:"error_text,omitempty"`
}

// eventBus 每 scan 一组订阅者的内存 pub/sub。
type eventBus struct {
	mu   sync.Mutex
	subs map[int64]map[chan Event]struct{}
}

func newEventBus() *eventBus {
	return &eventBus{subs: map[int64]map[chan Event]struct{}{}}
}

// subscribe 订阅指定扫描的事件；返回取消函数。
func (b *eventBus) subscribe(scanID int64) (<-chan Event, func()) {
	ch := make(chan Event, 256)
	b.mu.Lock()
	if b.subs[scanID] == nil {
		b.subs[scanID] = map[chan Event]struct{}{}
	}
	b.subs[scanID][ch] = struct{}{}
	b.mu.Unlock()
	unsub := func() {
		b.mu.Lock()
		if m, ok := b.subs[scanID]; ok {
			delete(m, ch)
			if len(m) == 0 {
				delete(b.subs, scanID)
			}
		}
		b.mu.Unlock()
		// publish 为非阻塞（select+default），移除订阅后无发送方阻塞，
		// 无需排空 channel（排空循环在 channel 未 close 时会永久阻塞）。
	}
	return ch, unsub
}

// publish 非阻塞发布（订阅者缓冲满则丢弃，SSE/CLI 均容忍）。
func (b *eventBus) publish(scanID int64, ev Event) {
	ev.ScanID = scanID
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs[scanID] {
		select {
		case ch <- ev:
		default:
		}
	}
}

// SubscribeScan 订阅扫描事件流。
func (s *Service) SubscribeScan(scanID int64) (<-chan Event, func()) {
	return s.bus.subscribe(scanID)
}
