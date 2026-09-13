package store

import (
	"fmt"
	"strings"
	"time"
)

// Traffic 单条任务流量（一个 (POC,目标) 任务可能产生多条，seq 保序）。
type Traffic struct {
	ID             int64
	ScanID         int64
	TargetID       int64
	POCID          int64
	Seq            int    // 扫描内事件顺序
	Protocol       string // http|network|websocket|code|''（未知）
	Matched        bool   // true=Write 匹配路径 false=WriteFailure 路径
	Status         int    // HTTP 状态码（非 HTTP 为 0）
	Request        string // 截断后的原始请求 dump
	Response       string // 截断后的原始响应 dump
	ReqTruncated   bool
	RespTruncated  bool
	CreatedAt      string
}

// TrafficDetail 联表后的流量详情（API/CLI 展示用）。
type TrafficDetail struct {
	Traffic
	TargetURL  string
	TargetName string
	TemplateID string
	POCName    string
}

// InsertTraffic 批量插入流量（单事务，分批）。普通 INSERT：同一任务多事件
// 各占一行，不做幂等去重。
func (s *Store) InsertTraffic(rows []Traffic) error {
	if len(rows) == 0 {
		return nil
	}
	const batch = 500
	for start := 0; start < len(rows); start += batch {
		end := start + batch
		if end > len(rows) {
			end = len(rows)
		}
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		stmt, err := tx.Prepare(`INSERT INTO task_traffic
(scan_id, target_id, poc_id, seq, protocol, matched, status, request, response, req_truncated, resp_truncated, created_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			tx.Rollback()
			return err
		}
		now := time.Now().Format("2006-01-02 15:04:05")
		for _, r := range rows[start:end] {
			matched, reqTr, respTr := 0, 0, 0
			if r.Matched {
				matched = 1
			}
			if r.ReqTruncated {
				reqTr = 1
			}
			if r.RespTruncated {
				respTr = 1
			}
			if _, err := stmt.Exec(r.ScanID, r.TargetID, r.POCID, r.Seq, r.Protocol,
				matched, r.Status, r.Request, r.Response, reqTr, respTr, now); err != nil {
				stmt.Close()
				tx.Rollback()
				return fmt.Errorf("insert traffic: %w", err)
			}
		}
		stmt.Close()
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// TrafficField 搜索字段范围。
const (
	TrafficFieldBoth     = ""        // 请求+响应（默认）
	TrafficFieldRequest  = "request" // 仅请求包
	TrafficFieldResponse = "response" // 仅响应包
)

// likeEscape 转义 LIKE 通配符（% _ \），配合 ESCAPE '\' 精确子串匹配。
func likeEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// trafficWhere 构造流量查询公共 WHERE 与参数（pocID/targetID <= 0 表示不过滤；
// search 非空 = 请求/响应包内容特征搜索，field 限定搜索字段，空 = 两者）。
func trafficWhere(scanID, pocID, targetID int64, search, field string) (string, []any) {
	q := ` WHERE scan_id = ?`
	args := []any{scanID}
	if pocID > 0 {
		q += ` AND poc_id = ?`
		args = append(args, pocID)
	}
	if targetID > 0 {
		q += ` AND target_id = ?`
		args = append(args, targetID)
	}
	if search != "" {
		kw := "%" + likeEscape(search) + "%"
		switch field {
		case TrafficFieldRequest:
			q += ` AND request LIKE ? ESCAPE '\'`
			args = append(args, kw)
		case TrafficFieldResponse:
			q += ` AND response LIKE ? ESCAPE '\'`
			args = append(args, kw)
		default: // 请求 + 响应任一命中
			q += ` AND (request LIKE ? ESCAPE '\' OR response LIKE ? ESCAPE '\')`
			args = append(args, kw, kw)
		}
	}
	return q, args
}

// ListTraffic 查询扫描流量（联 targets/pocs），按 seq 保序。
// limit<=0 默认 1000，上限 10000；offset 翻页。
// search 非空 = 请求/响应包内容特征搜索（field 见 TrafficField* 常量）。
func (s *Store) ListTraffic(scanID, pocID, targetID int64, search, field string, limit, offset int) ([]TrafficDetail, error) {
	if limit <= 0 {
		limit = 1000
	}
	if limit > 10000 {
		limit = 10000
	}
	if offset < 0 {
		offset = 0
	}
	where, args := trafficWhere(scanID, pocID, targetID, search, field)
	q := `SELECT t.id, t.scan_id, t.target_id, t.poc_id, t.seq, t.protocol, t.matched, t.status,
	t.request, t.response, t.req_truncated, t.resp_truncated, t.created_at,
	COALESCE(tg.url,''), COALESCE(tg.name,''), COALESCE(p.template_id,''), COALESCE(p.name,'')
FROM task_traffic t
LEFT JOIN targets tg ON tg.id = t.target_id
LEFT JOIN pocs p ON p.id = t.poc_id` + where + ` ORDER BY t.seq LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrafficDetail
	for rows.Next() {
		var d TrafficDetail
		var matched, reqTr, respTr int
		if err := rows.Scan(&d.ID, &d.ScanID, &d.TargetID, &d.POCID, &d.Seq, &d.Protocol, &matched, &d.Status,
			&d.Request, &d.Response, &reqTr, &respTr, &d.CreatedAt,
			&d.TargetURL, &d.TargetName, &d.TemplateID, &d.POCName); err != nil {
			return nil, err
		}
		d.Matched, d.ReqTruncated, d.RespTruncated = matched == 1, reqTr == 1, respTr == 1
		out = append(out, d)
	}
	return out, rows.Err()
}

// ListScanTrafficAll 查询扫描全部流量行（不联表、不限条数，
// 按 target_id, poc_id, seq 保序），报告导出用。
func (s *Store) ListScanTrafficAll(scanID int64) ([]Traffic, error) {
	rows, err := s.db.Query(`SELECT id, scan_id, target_id, poc_id, seq, protocol, matched, status,
request, response, req_truncated, resp_truncated, created_at
FROM task_traffic WHERE scan_id = ? ORDER BY target_id, poc_id, seq`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Traffic
	for rows.Next() {
		var t Traffic
		var matched, reqTr, respTr int
		if err := rows.Scan(&t.ID, &t.ScanID, &t.TargetID, &t.POCID, &t.Seq, &t.Protocol, &matched, &t.Status,
			&t.Request, &t.Response, &reqTr, &respTr, &t.CreatedAt); err != nil {
			return nil, err
		}
		t.Matched, t.ReqTruncated, t.RespTruncated = matched == 1, reqTr == 1, respTr == 1
		out = append(out, t)
	}
	return out, rows.Err()
}

// CountTraffic 按过滤条件统计流量行数（API 分页 total）。
// search/field 语义同 ListTraffic。
func (s *Store) CountTraffic(scanID, pocID, targetID int64, search, field string) (int, error) {
	where, args := trafficWhere(scanID, pocID, targetID, search, field)
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM task_traffic`+where, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}
