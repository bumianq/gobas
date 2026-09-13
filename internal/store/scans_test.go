package store

import (
	"path/filepath"
	"testing"
)

// openTestStore 打开临时数据库并插入基础数据（1 扫描 + 3 结果 + 3 流量）。
func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	scanID, err := st.CreateScan("t", "{}", "")
	if err != nil {
		t.Fatal(err)
	}
	err = st.InsertResults([]Result{
		{ScanID: scanID, TargetID: 1, POCID: 1, Verdict: "MISS"},
		{ScanID: scanID, TargetID: 1, POCID: 2, Verdict: "MISS"},
		{ScanID: scanID, TargetID: 1, POCID: 3, Verdict: "BLOCKED"},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = st.InsertTraffic([]Traffic{
		{ScanID: scanID, TargetID: 1, POCID: 1, Seq: 1, Protocol: "http", Status: 403,
			Request: "GET /admin HTTP/1.1", Response: "HTTP/1.1 403 Forbidden\r\nServer: Safedog\r\n\r\nblocked"},
		{ScanID: scanID, TargetID: 1, POCID: 2, Seq: 2, Protocol: "http", Status: 200,
			Request: "GET /ok HTTP/1.1", Response: "HTTP/1.1 200 OK\r\n\r\nnormal"},
		{ScanID: scanID, TargetID: 1, POCID: 3, Seq: 3, Protocol: "network",
			Request: "raw\x00probe", Response: "banner: SSH-2.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func testScanID(t *testing.T, st *Store) int64 {
	t.Helper()
	scans, err := st.ListScans(1, 0)
	if err != nil || len(scans) != 1 {
		t.Fatalf("list scans: %v (%d)", err, len(scans))
	}
	return scans[0].ID
}

func resultVerdicts(t *testing.T, st *Store, scanID int64) map[int64]Result {
	t.Helper()
	details, err := st.ListResults(scanID, "")
	if err != nil {
		t.Fatal(err)
	}
	out := map[int64]Result{}
	for _, d := range details {
		out[d.ID] = d.Result
	}
	return out
}

// TestUpdateResultVerdictsByID 单条与多条 ID 修改。
func TestUpdateResultVerdictsByID(t *testing.T) {
	st := openTestStore(t)
	scanID := testScanID(t, st)
	vs := resultVerdicts(t, st, scanID)

	// 单条：第一个 MISS → HIT
	var missID int64
	for id, r := range vs {
		if r.Verdict == "MISS" {
			missID = id
			break
		}
	}
	n, err := st.UpdateResultVerdicts(scanID, []int64{missID}, "", "HIT")
	if err != nil || n != 1 {
		t.Fatalf("update by id: n=%d err=%v", n, err)
	}
	got := resultVerdicts(t, st, scanID)[missID]
	if got.Verdict != "HIT" {
		t.Fatalf("verdict = %q, want HIT", got.Verdict)
	}
	if got.AutoVerdict != "MISS" {
		t.Fatalf("auto_verdict = %q, want MISS（首次修改回填机器判定）", got.AutoVerdict)
	}
	if got.ManualAt == "" {
		t.Fatal("manual_at 应记录人工修改时间")
	}

	// 二次修改：auto_verdict 保持首次回填值不变
	if _, err := st.UpdateResultVerdicts(scanID, []int64{missID}, "", "BLOCKED"); err != nil {
		t.Fatal(err)
	}
	got = resultVerdicts(t, st, scanID)[missID]
	if got.Verdict != "BLOCKED" || got.AutoVerdict != "MISS" {
		t.Fatalf("二次修改后 verdict=%q auto=%q, want BLOCKED/MISS", got.Verdict, got.AutoVerdict)
	}

	// 多条 ID 批量
	var missIDs []int64
	for id, r := range resultVerdicts(t, st, scanID) {
		if r.Verdict == "MISS" {
			missIDs = append(missIDs, id)
		}
	}
	if len(missIDs) != 1 {
		t.Fatalf("剩余 MISS 应为 1 条，got %d", len(missIDs))
	}
	n, err = st.UpdateResultVerdicts(scanID, missIDs, "", "TIMEOUT")
	if err != nil || n != 1 {
		t.Fatalf("batch by ids: n=%d err=%v", n, err)
	}
}

// TestUpdateResultVerdictsByCategory 按类别批量修改。
func TestUpdateResultVerdictsByCategory(t *testing.T) {
	st := openTestStore(t)
	scanID := testScanID(t, st)

	// 全部 MISS（2 条）→ BLOCKED
	n, err := st.UpdateResultVerdicts(scanID, nil, "MISS", "BLOCKED")
	if err != nil || n != 2 {
		t.Fatalf("update by category: n=%d err=%v", n, err)
	}
	details, err := st.ListResults(scanID, "BLOCKED")
	if err != nil {
		t.Fatal(err)
	}
	if len(details) != 3 { // 原 1 + 新改 2
		t.Fatalf("BLOCKED 计数 = %d, want 3", len(details))
	}
	manual := 0
	for _, d := range details {
		if d.AutoVerdict != "" || d.ManualAt != "" {
			manual++
			if d.AutoVerdict != "MISS" {
				t.Fatalf("人工修改行 auto_verdict = %q, want MISS", d.AutoVerdict)
			}
		}
	}
	if manual != 2 {
		t.Fatalf("人工修改行 = %d, want 2（原 BLOCKED 行不应被标记）", manual)
	}
	// 未修改类别不受影响
	misses, _ := st.ListResults(scanID, "MISS")
	if len(misses) != 0 {
		t.Fatalf("MISS 应清零，got %d", len(misses))
	}
}

// TestRestoreResultVerdicts 恢复机器自动判定。
func TestRestoreResultVerdicts(t *testing.T) {
	st := openTestStore(t)
	scanID := testScanID(t, st)

	// MISS(2) → BLOCKED，BLOCKED(1) → HIT
	if _, err := st.UpdateResultVerdicts(scanID, nil, "MISS", "BLOCKED"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateResultVerdicts(scanID, nil, "BLOCKED", "HIT"); err != nil {
		t.Fatal(err)
	}
	hits, _ := st.ListResults(scanID, "HIT")
	if len(hits) != 3 {
		t.Fatalf("HIT = %d, want 3", len(hits))
	}

	// 全部恢复：verdict 回到 auto_verdict（MISS×2 + BLOCKED×1）
	n, err := st.UpdateResultVerdicts(scanID, nil, "", "")
	if err != nil || n != 3 {
		t.Fatalf("restore: n=%d err=%v", n, err)
	}
	vs := resultVerdicts(t, st, scanID)
	var miss, blocked int
	for _, r := range vs {
		if r.ManualAt != "" || r.AutoVerdict != "" {
			t.Fatalf("恢复后应清空 manual_at/auto_verdict: %+v", r)
		}
		switch r.Verdict {
		case "MISS":
			miss++
		case "BLOCKED":
			blocked++
		}
	}
	if miss != 2 || blocked != 1 {
		t.Fatalf("恢复后 MISS=%d BLOCKED=%d, want 2/1", miss, blocked)
	}
}

// TestRefreshScanVerdictCounts 人工修改后扫描级计数同步。
func TestRefreshScanVerdictCounts(t *testing.T) {
	st := openTestStore(t)
	scanID := testScanID(t, st)
	if err := st.FinishScan(scanID, "completed", VerdictCounters{Miss: 2, Blocked: 1}, ""); err != nil {
		t.Fatal(err)
	}

	// MISS ×2 → HIT，刷新计数
	if _, err := st.UpdateResultVerdicts(scanID, nil, "MISS", "HIT"); err != nil {
		t.Fatal(err)
	}
	if err := st.RefreshScanVerdictCounts(scanID); err != nil {
		t.Fatal(err)
	}
	sc, err := st.GetScan(scanID)
	if err != nil || sc == nil {
		t.Fatal(err)
	}
	if sc.HitCount != 2 || sc.BlockedCount != 1 || sc.MissCount != 0 {
		t.Fatalf("counts after refresh: HIT=%d BLOCKED=%d MISS=%d, want 2/1/0",
			sc.HitCount, sc.BlockedCount, sc.MissCount)
	}
	if sc.DoneTasks != 3 {
		t.Fatalf("done_tasks = %d, want 3", sc.DoneTasks)
	}
}

// TestListTrafficSearch 流量包内容特征搜索。
func TestListTrafficSearch(t *testing.T) {
	st := openTestStore(t)
	scanID := testScanID(t, st)

	// 请求包命中
	rows, err := st.ListTraffic(scanID, 0, 0, "admin", "", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].POCID != 1 {
		t.Fatalf("search request 'admin': got %d rows", len(rows))
	}

	// 响应包命中（WAF 指纹）
	rows, err = st.ListTraffic(scanID, 0, 0, "Safedog", "", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].POCID != 1 {
		t.Fatalf("search response 'Safedog': got %d rows", len(rows))
	}

	// 仅响应包字段：请求中的关键词不应命中
	rows, err = st.ListTraffic(scanID, 0, 0, "admin", TrafficFieldResponse, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("field=response search 'admin' should miss, got %d", len(rows))
	}

	// 仅请求包字段
	rows, err = st.ListTraffic(scanID, 0, 0, "Safedog", TrafficFieldRequest, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("field=request search 'Safedog' should miss, got %d", len(rows))
	}

	// LIKE 通配符应被转义为字面量（无行含 "GET /a%in"）
	rows, err = st.ListTraffic(scanID, 0, 0, "%in%", "", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("wildcard chars should be literal, got %d rows", len(rows))
	}

	// 计数与过滤组合（poc_id + search）
	n, err := st.CountTraffic(scanID, 1, 0, "Forbidden", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("count with poc filter = %d, want 1", n)
	}

	// 状态行特征搜索（人工发现拦截特征的典型用法）
	rows, err = st.ListTraffic(scanID, 0, 0, "403", "", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Status != 403 {
		t.Fatalf("search '403' status-line: got %d rows", len(rows))
	}
}
