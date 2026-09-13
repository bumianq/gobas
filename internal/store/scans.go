package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Scan 一次扫描任务。
type Scan struct {
	ID              int64
	Name            string
	Status          string // running|completed|failed|canceled
	POCFilter       string // JSON 快照（可复现）
	Proxy           string // 扫描流量出口代理（空 = 直连）
	TargetCount     int
	POCCount        int
	TotalTasks      int
	DoneTasks       int
	HitCount        int
	BlockedCount    int
	TimeoutCount    int
	UnreachableCount int
	MissCount       int
	ErrorCount      int
	ErrorText       string // 失败原因（引擎错误/panic 等）
	StartedAt       string
	FinishedAt      string
}

// VerdictCounters 各判定计数。
type VerdictCounters struct {
	Hit, Blocked, Timeout, Unreachable, Miss, Error int
}

const scanColumns = `id, name, status, poc_filter, proxy, target_count, poc_count, total_tasks, done_tasks,
hit_count, blocked_count, timeout_count, unreachable_count, miss_count, error_count, error_text, started_at, finished_at`

func scanScan(row interface{ Scan(...any) error }) (*Scan, error) {
	var sc Scan
	if err := row.Scan(&sc.ID, &sc.Name, &sc.Status, &sc.POCFilter, &sc.Proxy, &sc.TargetCount, &sc.POCCount,
		&sc.TotalTasks, &sc.DoneTasks, &sc.HitCount, &sc.BlockedCount, &sc.TimeoutCount,
		&sc.UnreachableCount, &sc.MissCount, &sc.ErrorCount, &sc.ErrorText, &sc.StartedAt, &sc.FinishedAt); err != nil {
		return nil, err
	}
	return &sc, nil
}

// CreateScan 创建 running 状态的扫描记录（proxy 为扫描流量出口代理，空 = 直连）。
func (s *Store) CreateScan(name, pocFilterJSON, proxy string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO scans (name, status, poc_filter, proxy, started_at) VALUES (?, 'running', ?, ?, ?)`,
		name, pocFilterJSON, proxy, time.Now().Format("2006-01-02 15:04:05"))
	if err != nil {
		return 0, fmt.Errorf("create scan: %w", err)
	}
	return res.LastInsertId()
}

// AddScanTargets 关联扫描与目标。
func (s *Store) AddScanTargets(scanID int64, targetIDs []int64) error {
	if len(targetIDs) == 0 {
		return nil
	}
	var sb strings.Builder
	sb.WriteString(`INSERT OR IGNORE INTO scan_targets (scan_id, target_id) VALUES `)
	args := make([]any, 0, len(targetIDs)*2)
	for i, tid := range targetIDs {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("(?,?)")
		args = append(args, scanID, tid)
	}
	_, err := s.db.Exec(sb.String(), args...)
	return err
}

// UpdateScanCounts 更新扫描的任务规模（探活剔除不可达目标后）。
func (s *Store) UpdateScanCounts(id int64, targetCount, pocCount, totalTasks int) error {
	_, err := s.db.Exec(`UPDATE scans SET target_count=?, poc_count=?, total_tasks=? WHERE id=?`,
		targetCount, pocCount, totalTasks, id)
	return err
}

// UpdateScanDone 更新已完成任务数。
func (s *Store) UpdateScanDone(id int64, done int) error {
	_, err := s.db.Exec(`UPDATE scans SET done_tasks=? WHERE id=?`, done, id)
	return err
}

// FinishScan 结束扫描并写入各判定计数与失败原因。
func (s *Store) FinishScan(id int64, status string, c VerdictCounters, errText string) error {
	_, err := s.db.Exec(`UPDATE scans SET status=?, hit_count=?, blocked_count=?, timeout_count=?,
unreachable_count=?, miss_count=?, error_count=?, done_tasks=hit_count+blocked_count+timeout_count+unreachable_count+miss_count+error_count,
error_text=?, finished_at=datetime('now','localtime') WHERE id=?`,
		status, c.Hit, c.Blocked, c.Timeout, c.Unreachable, c.Miss, c.Error, errText, id)
	return err
}

// GetScan 按 id 查询。
func (s *Store) GetScan(id int64) (*Scan, error) {
	row := s.db.QueryRow(`SELECT `+scanColumns+` FROM scans WHERE id = ?`, id)
	sc, err := scanScan(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return sc, err
}

// ListScans 扫描列表（倒序分页）。
func (s *Store) ListScans(limit, offset int) ([]Scan, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := s.db.Query(`SELECT `+scanColumns+` FROM scans ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Scan
	for rows.Next() {
		sc, err := scanScan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *sc)
	}
	return out, rows.Err()
}

// CountScans 扫描总数。
func (s *Store) CountScans() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM scans`).Scan(&n)
	return n, err
}

// DeleteScan 删除扫描（results / scan_targets / task_traffic 依赖
// ON DELETE CASCADE 级联删除；不存在时返回 false）。
func (s *Store) DeleteScan(id int64) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM scans WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// FailOrphanedScans 启动时将遗留 running 状态的扫描标记为 failed（进程上次异常退出）。
func (s *Store) FailOrphanedScans() error {
	_, err := s.db.Exec(`UPDATE scans SET status='failed', finished_at=datetime('now','localtime') WHERE status='running'`)
	return err
}

// Result 单个 (POC, 目标) 对的判定结果。
type Result struct {
	ID             int64
	ScanID         int64
	TargetID       int64
	POCID          int64
	Verdict        string // 当前生效判定（人工修改后直接更新此列）
	AutoVerdict    string // 机器自动判定（人工首次修改时回填，用于恢复；空=未修改过）
	ManualAt       string // 人工修改时间（空=未修改过）
	MatchedAt      string
	MatcherName    string
	ResponseStatus int
	ResponseTimeMS int64
	ErrorText      string
	Evidence       string // JSON
	CreatedAt      string
}

// ResultDetail 联表后的结果详情（报告用）。
type ResultDetail struct {
	Result
	TargetURL  string
	TargetName string
	TemplateID string
	POCName    string
	Severity   string
}

// InsertResults 批量插入结果（单事务）。
func (s *Store) InsertResults(results []Result) error {
	if len(results) == 0 {
		return nil
	}
	const batch = 500
	for start := 0; start < len(results); start += batch {
		end := start + batch
		if end > len(results) {
			end = len(results)
		}
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		stmt, err := tx.Prepare(`INSERT OR IGNORE INTO results
(scan_id, target_id, poc_id, verdict, matched_at, matcher_name, response_status, response_time_ms, error_text, evidence, created_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			tx.Rollback()
			return err
		}
		now := time.Now().Format("2006-01-02 15:04:05")
		for _, r := range results[start:end] {
			if _, err := stmt.Exec(r.ScanID, r.TargetID, r.POCID, r.Verdict, r.MatchedAt,
				r.MatcherName, r.ResponseStatus, r.ResponseTimeMS, r.ErrorText, r.Evidence, now); err != nil {
				stmt.Close()
				tx.Rollback()
				return fmt.Errorf("insert result: %w", err)
			}
		}
		stmt.Close()
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// ListResults 查询扫描结果（联 targets/pocs），verdict 为空则全部。
func (s *Store) ListResults(scanID int64, verdict string) ([]ResultDetail, error) {
	q := `SELECT r.id, r.scan_id, r.target_id, r.poc_id, r.verdict, r.auto_verdict, r.manual_at,
	r.matched_at, r.matcher_name, r.response_status, r.response_time_ms, r.error_text, r.evidence, r.created_at,
	COALESCE(t.url,''), COALESCE(t.name,''), COALESCE(p.template_id,''), COALESCE(p.name,''), COALESCE(p.severity,'')
FROM results r
LEFT JOIN targets t ON t.id = r.target_id
LEFT JOIN pocs p ON p.id = r.poc_id
WHERE r.scan_id = ?`
	args := []any{scanID}
	if verdict != "" {
		q += ` AND r.verdict = ?`
		args = append(args, verdict)
	}
	q += ` ORDER BY r.verdict, r.target_id, r.poc_id`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ResultDetail
	for rows.Next() {
		var d ResultDetail
		if err := rows.Scan(&d.ID, &d.ScanID, &d.TargetID, &d.POCID, &d.Verdict, &d.AutoVerdict, &d.ManualAt,
			&d.MatchedAt, &d.MatcherName, &d.ResponseStatus, &d.ResponseTimeMS, &d.ErrorText, &d.Evidence,
			&d.CreatedAt, &d.TargetURL, &d.TargetName, &d.TemplateID, &d.POCName, &d.Severity); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// UpdateResultVerdicts 人工修正判定：将 scanID 下符合条件的结果 verdict 改为 toVerdict。
// ids 非空 = 仅这些结果行；fromVerdict 非空 = 仅当前判定匹配的行（两者可组合；
// 都为空 = 该扫描全部结果）。返回受影响行数。
// toVerdict 传空串 = 恢复机器自动判定（仅影响人工修改过的行）。
func (s *Store) UpdateResultVerdicts(scanID int64, ids []int64, fromVerdict, toVerdict string) (int64, error) {
	var q string
	var args []any
	if toVerdict == "" {
		// 恢复：仅人工修改过的行（auto_verdict 非空）；重置回机器判定状态
		q = `UPDATE results SET verdict = auto_verdict, auto_verdict = '', manual_at = ''
WHERE scan_id = ? AND auto_verdict != ''`
		args = []any{scanID}
	} else {
		// 修改：首次修改回填 auto_verdict（保留机器判定），verdict 更新为人工判定
		q = `UPDATE results SET
	auto_verdict = CASE WHEN auto_verdict = '' THEN verdict ELSE auto_verdict END,
	verdict = ?, manual_at = datetime('now','localtime')
WHERE scan_id = ?`
		args = []any{toVerdict, scanID}
	}
	if fromVerdict != "" {
		// from 匹配当前生效判定（含已人工修改过的行）
		q += ` AND verdict = ?`
		args = append(args, fromVerdict)
	}
	if len(ids) > 0 {
		ph := make([]string, 0, len(ids))
		for _, id := range ids {
			ph = append(ph, "?")
			args = append(args, id)
		}
		q += ` AND id IN (` + strings.Join(ph, ",") + `)`
	}
	res, err := s.db.Exec(q, args...)
	if err != nil {
		return 0, fmt.Errorf("update result verdicts: %w", err)
	}
	return res.RowsAffected()
}

// RefreshScanVerdictCounts 从 results 重新聚合判定计数回写 scans 表。
// 人工修正判定后调用，保证扫描级统计（判定矩阵/报告汇总/CLI）与明细一致。
func (s *Store) RefreshScanVerdictCounts(scanID int64) error {
	_, err := s.db.Exec(`WITH agg AS (
	SELECT
		COALESCE(SUM(CASE WHEN verdict = 'HIT' THEN 1 ELSE 0 END), 0)         AS hit_count,
		COALESCE(SUM(CASE WHEN verdict = 'BLOCKED' THEN 1 ELSE 0 END), 0)     AS blocked_count,
		COALESCE(SUM(CASE WHEN verdict = 'TIMEOUT' THEN 1 ELSE 0 END), 0)     AS timeout_count,
		COALESCE(SUM(CASE WHEN verdict = 'UNREACHABLE' THEN 1 ELSE 0 END), 0) AS unreachable_count,
		COALESCE(SUM(CASE WHEN verdict = 'MISS' THEN 1 ELSE 0 END), 0)        AS miss_count,
		COALESCE(SUM(CASE WHEN verdict = 'ERROR' THEN 1 ELSE 0 END), 0)       AS error_count,
		COUNT(*)                                                              AS done_tasks
	FROM results WHERE scan_id = ?
)
UPDATE scans SET
	hit_count         = (SELECT hit_count FROM agg),
	blocked_count     = (SELECT blocked_count FROM agg),
	timeout_count     = (SELECT timeout_count FROM agg),
	unreachable_count = (SELECT unreachable_count FROM agg),
	miss_count        = (SELECT miss_count FROM agg),
	error_count       = (SELECT error_count FROM agg),
	done_tasks        = (SELECT done_tasks FROM agg)
WHERE id = ?`, scanID, scanID)
	return err
}
