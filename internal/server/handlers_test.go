package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"gobas/internal/config"
	"gobas/internal/service"
	"gobas/internal/store"
)

// newTestServer 构建真实 service（临时 workspace）+ 种子数据
// （1 完成扫描 + 2 结果 + 2 流量），返回测试服务器与 store 直连句柄。
func newTestServer(t *testing.T) (*httptest.Server, *store.Store, int64) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Workspace = dir
	cfg.Network.Proxy = ""
	cfg.Server.AuthEnabled = false // 认证在 auth_test.go 中单独覆盖测试
	svc, err := service.New(cfg)
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}
	t.Cleanup(func() { svc.Close() })
	// 第二个 store 句柄用于播种数据（WAL 支持多连接）
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		t.Fatalf("seed store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	scanID, err := st.CreateScan("t", "{}", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.InsertResults([]store.Result{
		{ScanID: scanID, TargetID: 1, POCID: 1, Verdict: "MISS"},
		{ScanID: scanID, TargetID: 1, POCID: 2, Verdict: "BLOCKED"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertTraffic([]store.Traffic{
		{ScanID: scanID, TargetID: 1, POCID: 1, Seq: 1, Protocol: "http", Status: 403,
			Request: "GET /x HTTP/1.1", Response: "HTTP/1.1 403 Forbidden\r\nServer: Safedog"},
		{ScanID: scanID, TargetID: 1, POCID: 2, Seq: 2, Protocol: "http", Status: 200,
			Request: "GET /y HTTP/1.1", Response: "HTTP/1.1 200 OK"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishScan(scanID, "completed", store.VerdictCounters{Miss: 1, Blocked: 1}, ""); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(New(svc).Handler())
	t.Cleanup(ts.Close)
	return ts, st, scanID
}

// TestVerdictUpdateEndpoint 判定修改端点：单条/批量/非法值/恢复。
func TestVerdictUpdateEndpoint(t *testing.T) {
	ts, st, scanID := newTestServer(t)
	path := ts.URL + "/api/v1/scans/" + itoa(scanID) + "/results/verdict"

	// 单条修改：MISS → HIT
	var res struct {
		Updated int64 `json:"updated"`
	}
	postJSON(t, path, map[string]any{"from_verdict": "MISS", "to_verdict": "HIT"}, &res)
	if res.Updated != 1 {
		t.Fatalf("updated = %d, want 1", res.Updated)
	}
	sc, _ := st.GetScan(scanID)
	if sc.HitCount != 1 || sc.MissCount != 0 {
		t.Fatalf("扫描计数未同步：HIT=%d MISS=%d", sc.HitCount, sc.MissCount)
	}

	// 非法判定 → 400
	resp, err := http.Post(path, "application/json", strings.NewReader(`{"from_verdict":"MISS","to_verdict":"MAYBE"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid verdict status = %d, want 400", resp.StatusCode)
	}

	// 恢复 → 计数回滚
	postJSON(t, path, map[string]any{"from_verdict": "HIT", "to_verdict": ""}, &res)
	if res.Updated != 1 {
		t.Fatalf("restore updated = %d, want 1", res.Updated)
	}
	sc, _ = st.GetScan(scanID)
	if sc.HitCount != 0 || sc.MissCount != 1 {
		t.Fatalf("恢复后计数未回滚：HIT=%d MISS=%d", sc.HitCount, sc.MissCount)
	}

	// 按 ID 列表批量修改（单条场景）
	details, _ := st.ListResults(scanID, "BLOCKED")
	if len(details) != 1 {
		t.Fatalf("BLOCKED 行数 = %d, want 1", len(details))
	}
	postJSON(t, path, map[string]any{"result_ids": []int64{details[0].ID}, "to_verdict": "TIMEOUT"}, &res)
	if res.Updated != 1 {
		t.Fatalf("by-ids updated = %d, want 1", res.Updated)
	}
	sc, _ = st.GetScan(scanID)
	if sc.TimeoutCount != 1 || sc.BlockedCount != 0 {
		t.Fatalf("按 ID 修改后计数未同步：TIMEOUT=%d BLOCKED=%d", sc.TimeoutCount, sc.BlockedCount)
	}
}

// TestTrafficSearchEndpoint 流量特征搜索端点。
func TestTrafficSearchEndpoint(t *testing.T) {
	ts, _, scanID := newTestServer(t)
	base := ts.URL + "/api/v1/scans/" + itoa(scanID) + "/traffic"

	// 响应特征命中（WAF 指纹）
	var res struct {
		Traffic []store.TrafficDetail `json:"traffic"`
		Total   int                   `json:"total"`
	}
	getJSON(t, base+"?search=Safedog", &res)
	if res.Total != 1 || len(res.Traffic) != 1 || res.Traffic[0].POCID != 1 {
		t.Fatalf("search Safedog: total=%d rows=%d, want 1 行（POC 1）", res.Total, len(res.Traffic))
	}

	// 请求特征 + 字段限定
	getJSON(t, base+"?search=%2Fx&field=request", &res)
	if res.Total != 1 || res.Traffic[0].Request != "GET /x HTTP/1.1" {
		t.Fatalf("field=request search /x: total=%d", res.Total)
	}
	// 仅响应字段搜请求关键词 → 0
	getJSON(t, base+"?search=%2Fx&field=response", &res)
	if res.Total != 0 {
		t.Fatalf("field=response search /x 应为 0, got %d", res.Total)
	}

	// 无搜索参数 → 全量
	getJSON(t, base, &res)
	if res.Total != 2 {
		t.Fatalf("无搜索 total = %d, want 2", res.Total)
	}
}

func postJSON(t *testing.T, url string, body any, out any) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url, "application/json", strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: status %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}

func getJSON(t *testing.T, url string, out any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
