package engine

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// TestWriteFailureResponseFallback 验证失败事件响应提取的协议 fallback 链：
// response → data（network 协议）→ raw（完整交互数据）。
func TestWriteFailureResponseFallback(t *testing.T) {
	cases := []struct {
		name string
		ie   map[string]interface{}
		want string
	}{
		{
			name: "http协议取response键",
			ie: map[string]interface{}{
				"template-id": "tpl-http",
				"host":        "http://127.0.0.1",
				"type":        "http",
				"status_code": 200,
				"request":     "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
				"response":    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
			},
			want: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
		},
		{
			name: "network协议无response时取data",
			ie: map[string]interface{}{
				"template-id": "tpl-network",
				"host":        "127.0.0.1:8080",
				"type":        "network",
				"request":     "PING",
				"data":        "PONG",
				"raw":         "PINGPONG",
			},
			want: "PONG",
		},
		{
			name: "network协议无data时取raw",
			ie: map[string]interface{}{
				"template-id": "tpl-network-raw",
				"host":        "127.0.0.1:8080",
				"type":        "network",
				"request":     "PING",
				"raw":         "PINGPONG",
			},
			want: "PINGPONG",
		},
		{
			name: "response优先于data与raw",
			ie: map[string]interface{}{
				"template-id": "tpl-priority",
				"host":        "http://127.0.0.1",
				"response":    "R",
				"data":        "D",
				"raw":         "W",
			},
			want: "R",
		},
		{
			name: "全部为空返回空串",
			ie: map[string]interface{}{
				"template-id": "tpl-empty",
				"host":        "http://127.0.0.1",
			},
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got FailureEvent
			w := newEventWriter(nil, func(ev FailureEvent) { got = ev })
			if err := w.WriteFailure(&output.InternalWrappedEvent{InternalEvent: c.ie}); err != nil {
				t.Fatalf("WriteFailure: %v", err)
			}
			if got.Response != c.want {
				t.Fatalf("Response = %q, want %q", got.Response, c.want)
			}
		})
	}
}

// TestWriteFailureRequestExtraction 验证失败事件的请求与协议类型提取。
func TestWriteFailureRequestExtraction(t *testing.T) {
	var got FailureEvent
	w := newEventWriter(nil, func(ev FailureEvent) { got = ev })
	err := w.WriteFailure(&output.InternalWrappedEvent{InternalEvent: map[string]interface{}{
		"template-id": "tpl-http",
		"host":        "http://127.0.0.1",
		"type":        "http",
		"status_code": 403,
		"request":     "GET /admin HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
		"response":    "HTTP/1.1 403 Forbidden\r\n\r\n",
		"error":       "some error",
	}})
	if err != nil {
		t.Fatalf("WriteFailure: %v", err)
	}
	if got.Request != "GET /admin HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n" {
		t.Fatalf("Request = %q", got.Request)
	}
	if got.Type != "http" {
		t.Fatalf("Type = %q, want http", got.Type)
	}
	if got.Status != 403 {
		t.Fatalf("Status = %d, want 403", got.Status)
	}
	if got.ErrText != "some error" {
		t.Fatalf("ErrText = %q", got.ErrText)
	}
}
