package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// 测试固件模板：必命中（status 200）
const tplAlwaysHit = `id: gobas-test-always-hit
info:
  name: Gobas Test Always Hit
  author: gobas
  severity: info
  tags: gobas,test
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: status
        status:
          - 200
`

// 测试固件模板：必不匹配
const tplNeverMatch = `id: gobas-test-never-match
info:
  name: Gobas Test Never Match
  author: gobas
  severity: info
  tags: gobas,test
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "gobas-never-match-impossible-string-7f3a9c"
`

// 测试固件模板：请求必返回 403 的路径（验证 BLOCKED 判定数据来源）
const tplBlocked = `id: gobas-test-blocked
info:
  name: Gobas Test Blocked Path
  author: gobas
  severity: high
  tags: gobas,test
http:
  - method: GET
    path:
      - "{{BaseURL}}/gobas-blocked"
    matchers:
      - type: status
        status:
          - 200
`

func writeTemplates(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	for i, tpl := range []string{tplAlwaysHit, tplNeverMatch, tplBlocked} {
		if err := os.WriteFile(filepath.Join(dir, "tpl"+string(rune('0'+i))+".yaml"), []byte(tpl), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return []string{
		filepath.Join(dir, "tpl0.yaml"),
		filepath.Join(dir, "tpl1.yaml"),
		filepath.Join(dir, "tpl2.yaml"),
	}
}

// TestRunFullMatrix 验证引擎事件流全矩阵：
// 匹配事件走 OnResult；未匹配事件（含响应原文与状态码）走 OnFailure。
func TestRunFullMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("skip engine test in short mode")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gobas-blocked" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Blocked by WAF (gobas-test)"))
			return
		}
		_, _ = w.Write([]byte("hello gobas"))
	}))
	defer srv.Close()

	var mu sync.Mutex
	var results []ResultEvent
	var failures []FailureEvent

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	err := Run(ctx, Options{
		TemplatePaths: writeTemplates(t),
		Targets:       []string{srv.URL},
		ProtocolTypes: "http",
		TimeoutSec:    10,
		Retries:       1,
		RateLimitPerS: 50,
		Interactsh:    false,
		OnResult: func(ev ResultEvent) {
			mu.Lock()
			results = append(results, ev)
			mu.Unlock()
		},
		OnFailure: func(ev FailureEvent) {
			mu.Lock()
			failures = append(failures, ev)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	// 期望：1 个匹配（always-hit），2 个未匹配（never-match 200、blocked 403）
	if len(results) != 1 || results[0].TemplateID != "gobas-test-always-hit" || !results[0].Matched {
		t.Errorf("results = %+v, want 1 always-hit matched event", results)
	}
	if len(failures) != 2 {
		t.Fatalf("failures = %+v, want 2 unmatched events", failures)
	}
	var foundMiss, foundBlocked bool
	for _, f := range failures {
		switch f.TemplateID {
		case "gobas-test-never-match":
			foundMiss = true
			if f.Status != 200 {
				t.Errorf("never-match status = %d, want 200（未匹配事件应携带状态码）", f.Status)
			}
		case "gobas-test-blocked":
			foundBlocked = true
			if f.Status != 403 {
				t.Errorf("blocked status = %d, want 403（BLOCKED 判定的数据前提）", f.Status)
			}
			if f.Response == "" {
				t.Error("blocked event response should not be empty")
			}
		}
		// 流量记录前提：未匹配事件也应携带完整请求原文
		if f.Request == "" {
			t.Errorf("failure event request should not be empty: %+v", f)
		}
		if f.Type != "http" {
			t.Errorf("failure event type = %q, want http", f.Type)
		}
	}
	if !foundMiss || !foundBlocked {
		t.Errorf("failures missing expected templates: miss=%v blocked=%v", foundMiss, foundBlocked)
	}
	// 匹配事件同样应携带请求/响应原文（流量记录数据源）
	if len(results) > 0 && (results[0].Request == "" || results[0].Response == "") {
		t.Errorf("matched event should carry request/response: req=%q resp=%q",
			results[0].Request, results[0].Response)
	}
}
