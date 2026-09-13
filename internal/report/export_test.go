package report

import (
	"bytes"
	"encoding/csv"
	"path/filepath"
	"strings"
	"testing"

	"gobas/internal/store"
)

func testModel() *Model {
	return &Model{
		Scan:  store.Scan{ID: 1, Name: "t", Status: "completed", POCCount: 2, TargetCount: 1, TotalTasks: 2},
		Total: 2,
		Counts: map[string]int{"HIT": 1, "MISS": 1},
		Targets: []TargetRow{{
			TargetID: 1, URL: "http://a", Counts: map[string]int{"HIT": 1, "MISS": 1},
			Results: []ResultRow{
				{
					ResultDetail: store.ResultDetail{Result: store.Result{Verdict: "HIT", ResponseStatus: 200}, TemplateID: "poc-a", POCName: "A", Severity: "critical"},
					Traffic: []store.Traffic{
						{Seq: 1, Protocol: "http", Status: 200, Request: "GET /a HTTP/1.1", Response: "HTTP/1.1 200 OK", Matched: true},
						{Seq: 2, Protocol: "http", Request: "GET /b HTTP/1.1", Response: "HTTP/1.1 404 Not Found"},
					},
				},
				{ResultDetail: store.ResultDetail{Result: store.Result{Verdict: "MISS"}, TemplateID: "poc-b", POCName: "B"}},
			},
		}},
	}
}

func TestExportTraffic(t *testing.T) {
	m := testModel()

	// JSON：traffic 数组挂到结果上，多事件保序
	var jb bytes.Buffer
	if err := Export(m, "json", &jb); err != nil {
		t.Fatal(err)
	}
	js := jb.String()
	for _, want := range []string{`"TemplateID": "poc-a"`, `"traffic"`, `"Seq": 1`, `"Seq": 2`, `"GET /a HTTP/1.1"`} {
		if !strings.Contains(js, want) {
			t.Errorf("json export missing %q", want)
		}
	}

	// CSV：request/response 列，多事件以分隔行拼接；manual/auto_verdict 人工修正列
	var cb bytes.Buffer
	if err := Export(m, "csv", &cb); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&cb).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("csv rows = %d, want 3 (header + 2 results)", len(rows))
	}
	if got := rows[0]; len(got) != 11 || got[9] != "request" || got[10] != "response" {
		t.Errorf("csv header = %v", got)
	}
	if !strings.Contains(rows[1][9], "\n----------\n") {
		t.Errorf("csv multi-event request not joined: %q", rows[1][9])
	}
	if !strings.HasPrefix(rows[1][9], "GET /a HTTP/1.1") {
		t.Errorf("csv request = %q", rows[1][9])
	}
	if rows[2][9] != "" || rows[2][10] != "" {
		t.Errorf("csv no-traffic result should have empty packets: %q %q", rows[2][9], rows[2][10])
	}
	// 未人工修正的行 manual 列为空
	if rows[1][5] != "" || rows[2][5] != "" {
		t.Errorf("csv manual column should be empty for auto-judged rows: %q %q", rows[1][5], rows[2][5])
	}

	// MD：流量明细段含请求/响应包（4 空格缩进代码块），无流量结果不生成段
	var mb bytes.Buffer
	if err := Export(m, "md", &mb); err != nil {
		t.Fatal(err)
	}
	md := mb.String()
	for _, want := range []string{
		"#### 流量明细：poc-a（HIT）",
		"**事件 seq=1**（协议 http，状态码 200，命中匹配）",
		"    GET /a HTTP/1.1",
		"    HTTP/1.1 200 OK",
		"**事件 seq=2**（协议 http，状态码 0）",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("md export missing %q", want)
		}
	}
	if strings.Contains(md, "流量明细：poc-b") {
		t.Error("md export should not render traffic section for result without traffic")
	}
}

// TestManualVerdictExportSync 人工修正判定后报告导出同步：
// verdict 列为人工判定，计数聚合更新，MD/CSV 携带人工修正标记。
func TestManualVerdictExportSync(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	scanID, _ := st.CreateScan("t", "{}", "")
	if err := st.InsertResults([]store.Result{
		{ScanID: scanID, TargetID: 1, POCID: 1, Verdict: "MISS"},
		{ScanID: scanID, TargetID: 1, POCID: 2, Verdict: "MISS"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishScan(scanID, "completed", store.VerdictCounters{Miss: 2}, ""); err != nil {
		t.Fatal(err)
	}

	// 人工修正：全部 MISS → BLOCKED（模拟发现 WAF 拦截特征后的二次判定）
	if _, err := st.UpdateResultVerdicts(scanID, nil, "MISS", "BLOCKED"); err != nil {
		t.Fatal(err)
	}
	if err := st.RefreshScanVerdictCounts(scanID); err != nil {
		t.Fatal(err)
	}

	m, err := Build(st, scanID)
	if err != nil {
		t.Fatal(err)
	}
	if m.Counts["BLOCKED"] != 2 || m.Counts["MISS"] != 0 {
		t.Fatalf("报告计数未同步人工修正：BLOCKED=%d MISS=%d, want 2/0", m.Counts["BLOCKED"], m.Counts["MISS"])
	}
	for _, tgt := range m.Targets {
		for _, r := range tgt.Results {
			if r.Verdict != "BLOCKED" {
				t.Fatalf("报告 verdict = %q, want BLOCKED（人工修正后）", r.Verdict)
			}
			if r.AutoVerdict != "MISS" || r.ManualAt == "" {
				t.Fatalf("报告应携带人工修正元数据：auto=%q manual_at=%q", r.AutoVerdict, r.ManualAt)
			}
		}
	}

	// MD：判定列含人工修正标记
	var mb bytes.Buffer
	if err := Export(m, "md", &mb); err != nil {
		t.Fatal(err)
	}
	md := mb.String()
	if !strings.Contains(md, "**BLOCKED** ✎人工（自动：MISS）") {
		t.Errorf("md 应含人工修正标记，got:\n%s", md)
	}

	// CSV：manual=yes + auto_verdict 列
	var cb bytes.Buffer
	if err := Export(m, "csv", &cb); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&cb).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for i, row := range rows[1:] {
		if row[4] != "BLOCKED" || row[5] != "yes" || row[6] != "MISS" {
			t.Errorf("csv 行 %d: verdict=%q manual=%q auto=%q, want BLOCKED/yes/MISS", i, row[4], row[5], row[6])
		}
	}

	// JSON：人工修正元数据字段
	var jb bytes.Buffer
	if err := Export(m, "json", &jb); err != nil {
		t.Fatal(err)
	}
	js := jb.String()
	if !strings.Contains(js, `"AutoVerdict": "MISS"`) || !strings.Contains(js, `"ManualAt": "`) {
		t.Errorf("json 应含 AutoVerdict/ManualAt 字段")
	}
}
