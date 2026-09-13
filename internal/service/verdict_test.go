package service

import (
	"path/filepath"
	"strings"
	"testing"

	"gobas/internal/store"
)

// newVerdictTestService 构造仅含 store 的 Service（UpdateScanVerdicts
// 只依赖 store，无需 engine/config 初始化）。
func newVerdictTestService(t *testing.T) (*Service, int64) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
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
	if err := st.FinishScan(scanID, "completed", store.VerdictCounters{Miss: 1, Blocked: 1}, ""); err != nil {
		t.Fatal(err)
	}
	return &Service{store: st}, scanID
}

// TestUpdateScanVerdicts 校验与计数同步（service 入口，CLI/API 共用）。
func TestUpdateScanVerdicts(t *testing.T) {
	svc, scanID := newVerdictTestService(t)
	ctx := t.Context()

	// 非法目标判定拒绝
	if _, err := svc.UpdateScanVerdicts(ctx, scanID, VerdictUpdateRequest{FromVerdict: "MISS", ToVerdict: "MAYBE"}); err == nil {
		t.Fatal("非法 to_verdict 应被拒绝")
	}
	// 非法原判定拒绝
	if _, err := svc.UpdateScanVerdicts(ctx, scanID, VerdictUpdateRequest{FromVerdict: "NOPE", ToVerdict: "HIT"}); err == nil {
		t.Fatal("非法 from_verdict 应被拒绝")
	}
	// 无条件恢复拒绝
	if _, err := svc.UpdateScanVerdicts(ctx, scanID, VerdictUpdateRequest{}); err == nil {
		t.Fatal("无条件恢复全部应被拒绝")
	}
	// 不存在的扫描
	if _, err := svc.UpdateScanVerdicts(ctx, 9999, VerdictUpdateRequest{FromVerdict: "MISS", ToVerdict: "HIT"}); err == nil {
		t.Fatal("不存在的扫描应报错")
	}

	// 正常批量修改：MISS → BLOCKED，计数同步
	n, err := svc.UpdateScanVerdicts(ctx, scanID, VerdictUpdateRequest{FromVerdict: "MISS", ToVerdict: "BLOCKED"})
	if err != nil || n != 1 {
		t.Fatalf("update: n=%d err=%v", n, err)
	}
	sc, err := svc.GetScan(ctx, scanID)
	if err != nil || sc == nil {
		t.Fatal(err)
	}
	if sc.BlockedCount != 2 || sc.MissCount != 0 {
		t.Fatalf("计数未同步：BLOCKED=%d MISS=%d, want 2/0", sc.BlockedCount, sc.MissCount)
	}

	// 恢复机器判定（仅人工修改过的 1 行；原生 BLOCKED 行不受影响）
	n, err = svc.UpdateScanVerdicts(ctx, scanID, VerdictUpdateRequest{FromVerdict: "BLOCKED", ToVerdict: ""})
	if err != nil || n != 1 {
		t.Fatalf("restore: n=%d err=%v", n, err)
	}
	sc, _ = svc.GetScan(ctx, scanID)
	if sc.BlockedCount != 1 || sc.MissCount != 1 {
		t.Fatalf("恢复后计数未同步：BLOCKED=%d MISS=%d, want 1/1", sc.BlockedCount, sc.MissCount)
	}
}

// TestUpdateScanVerdictsRunningScan 运行中的扫描禁止修改判定。
func TestUpdateScanVerdictsRunningScan(t *testing.T) {
	svc, _ := newVerdictTestService(t)
	// 直接构造 running 扫描
	scanID2, err := svc.store.CreateScan("running-scan", "{}", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.store.InsertResults([]store.Result{{ScanID: scanID2, TargetID: 1, POCID: 1, Verdict: "MISS"}}); err != nil {
		t.Fatal(err)
	}
	_, err = svc.UpdateScanVerdicts(t.Context(), scanID2, VerdictUpdateRequest{FromVerdict: "MISS", ToVerdict: "HIT"})
	if err == nil || !strings.Contains(err.Error(), "正在运行") {
		t.Fatalf("运行中扫描应拒绝修改判定, got err=%v", err)
	}
}
