package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// POC 已索引的 nuclei 模板元数据行。
type POC struct {
	ID            int64
	TemplateID    string
	Name          string
	Authors       string
	Severity      string
	Tags          string // ",tag1,tag2," 包裹，支持 LIKE '%,tag,%' 精确匹配
	CVEIDs        string // 逗号分隔
	CNVDIDs       string
	CWEIDs        string
	CVSSScore     float64
	Protocols     string // JSON 数组，如 ["http","network"]
	HasInteractsh bool
	SelfContained int  // -1=未检测 0=否 1=是（自包含模板不对扫描目标发请求）
	Verified      bool   // 模板签名是否通过官方验证器验证
	CodeEngines   string // code 协议使用的语言引擎（CSV，如 "php,python3"）
	FilePath      string
	ContentHash   string
	FileSize      int64
	SourceRepo    string
	IsOfficial    bool
	IsCustom      bool // 人工添加（独立于自动拉取源，重建索引不删除）
	IndexedAt     string
}

// POCFilter POC 查询过滤器。
type POCFilter struct {
	IDs          []int64
	SetID        int64  // 按模板集过滤（与 IDs 等其他条件 AND 组合）
	Severity     string
	Tag          string
	Protocol     string
	Official     string // "true"=仅官方源 / "false"=仅社区源 / ""=全部
	Custom       string // "true"=仅人工添加 / "false"=仅自动拉取 / ""=全部
	Executable   string // "true"=仅可执行 / "false"=仅不可执行 / ""=全部
	CVE          string
	CNVD         string
	Keyword      string // 模糊匹配 template_id/name/tags/cve/cnvd
	NoInteractsh bool
	Limit        int
	Offset       int
}

const pocColumns = `id, template_id, name, authors, severity, tags, cve_ids, cnvd_ids, cwe_ids,
cvss_score, protocols, has_interactsh, self_contained, verified, code_engines, file_path, content_hash, file_size,
source_repo, is_official, is_custom, indexed_at`

func scanPOC(row interface{ Scan(...any) error }) (*POC, error) {
	var p POC
	var hasInteractsh, isOfficial, verified, isCustom int
	if err := row.Scan(&p.ID, &p.TemplateID, &p.Name, &p.Authors, &p.Severity, &p.Tags,
		&p.CVEIDs, &p.CNVDIDs, &p.CWEIDs, &p.CVSSScore, &p.Protocols,
		&hasInteractsh, &p.SelfContained, &verified, &p.CodeEngines, &p.FilePath, &p.ContentHash, &p.FileSize,
		&p.SourceRepo, &isOfficial, &isCustom, &p.IndexedAt); err != nil {
		return nil, err
	}
	p.HasInteractsh = hasInteractsh != 0
	p.IsOfficial = isOfficial != 0
	p.Verified = verified != 0
	p.IsCustom = isCustom != 0
	return &p, nil
}

// InsertPOC 插入 POC。
// 去重规则（官方库先入库为基准）：
//  1. template_id 已存在 → 跳过（同一漏洞的社区微改版，保留先入库的官方版）；
//  2. content_hash 唯一冲突 → 忽略（完全相同内容的兜底）。
func (s *Store) InsertPOC(p *POC) (id int64, inserted bool, err error) {
	// file_path 统一落相对 baseDir 的相对路径（跨机器复制项目仍可用）
	p.FilePath = s.RelPath(p.FilePath)
	// 同 template_id 已有记录：先到先得（索引顺序保证官方源最前）
	var existID int64
	err = s.db.QueryRow(`SELECT id FROM pocs WHERE template_id = ? LIMIT 1`, p.TemplateID).Scan(&existID)
	if err == nil {
		return existID, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, false, fmt.Errorf("query poc by template_id: %w", err)
	}

	res, err := s.db.Exec(`INSERT OR IGNORE INTO pocs
(template_id, name, authors, severity, tags, cve_ids, cnvd_ids, cwe_ids, cvss_score,
protocols, has_interactsh, self_contained, verified, code_engines, file_path, content_hash, file_size, source_repo, is_official, is_custom, indexed_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		p.TemplateID, p.Name, p.Authors, p.Severity, p.Tags, p.CVEIDs, p.CNVDIDs, p.CWEIDs,
		p.CVSSScore, p.Protocols, boolToInt(p.HasInteractsh), p.SelfContained, boolToInt(p.Verified), p.CodeEngines, p.FilePath,
		p.ContentHash, p.FileSize, p.SourceRepo, boolToInt(p.IsOfficial), boolToInt(p.IsCustom), time.Now().Format("2006-01-02 15:04:05"))
	if err != nil {
		return 0, false, fmt.Errorf("insert poc: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 { // content_hash 冲突（不同 ID 但内容相同的边缘情况），取已有记录 id
		if err := s.db.QueryRow(`SELECT id FROM pocs WHERE content_hash = ?`, p.ContentHash).Scan(&existID); err != nil {
			return 0, false, fmt.Errorf("query duplicate poc: %w", err)
		}
		return existID, false, nil
	}
	id, _ = res.LastInsertId()
	return id, true, nil
}

// DeleteAllPOCs 清空自动拉取的 POC 索引（重建索引用）。
// 人工添加的 POC（is_custom=1）独立于自动拉取源，重建时保留；
// results 不级联，历史扫描结果保留。
func (s *Store) DeleteAllPOCs() error {
	_, err := s.db.Exec(`DELETE FROM pocs WHERE is_custom = 0`)
	return err
}

// UpdateCustomPOC 更新人工 POC 元数据（修改模板后重新解析回写）。
func (s *Store) UpdateCustomPOC(p *POC) error {
	p.FilePath = s.RelPath(p.FilePath)
	res, err := s.db.Exec(`UPDATE pocs SET
template_id=?, name=?, authors=?, severity=?, tags=?, cve_ids=?, cnvd_ids=?, cwe_ids=?, cvss_score=?,
protocols=?, has_interactsh=?, self_contained=?, verified=?, code_engines=?, file_path=?, content_hash=?, file_size=?,
source_repo=?, is_official=?, is_custom=1, indexed_at=?
WHERE id=? AND is_custom=1`,
		p.TemplateID, p.Name, p.Authors, p.Severity, p.Tags, p.CVEIDs, p.CNVDIDs, p.CWEIDs,
		p.CVSSScore, p.Protocols, boolToInt(p.HasInteractsh), p.SelfContained, boolToInt(p.Verified), p.CodeEngines, p.FilePath,
		p.ContentHash, p.FileSize, p.SourceRepo, boolToInt(p.IsOfficial), time.Now().Format("2006-01-02 15:04:05"), p.ID)
	if err != nil {
		return fmt.Errorf("update custom poc: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteCustomPOC 删除人工 POC 行（仅 is_custom=1 可删，自动拉取行拒绝）。
// poc_set_items 级联清理；results 不级联，历史扫描结果保留。
func (s *Store) DeleteCustomPOC(id int64) error {
	res, err := s.db.Exec(`DELETE FROM pocs WHERE id=? AND is_custom=1`, id)
	if err != nil {
		return fmt.Errorf("delete custom poc: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// SelfContainedUpdate 自包含检测结果回写项。
type SelfContainedUpdate struct {
	ID  int64
	Val int // 0=否 1=是
}

// UpdatePOCSelfContained 批量回写自包含检测结果（扫描懒检测缓存，避免重复读文件）。
func (s *Store) UpdatePOCSelfContained(updates []SelfContainedUpdate) error {
	if len(updates) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for _, u := range updates {
		if _, err := tx.Exec(`UPDATE pocs SET self_contained=? WHERE id=?`, u.Val, u.ID); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func buildPOCWhere(f POCFilter) (string, []any) {
	where := []string{"1=1"}
	var args []any
	if len(f.IDs) > 0 {
		ph := make([]string, len(f.IDs))
		for i, id := range f.IDs {
			ph[i] = "?"
			args = append(args, id)
		}
		where = append(where, "id IN ("+strings.Join(ph, ",")+")")
	}
	if f.SetID > 0 {
		where = append(where, "id IN (SELECT poc_id FROM poc_set_items WHERE set_id = ?)")
		args = append(args, f.SetID)
	}
	// 可执行性筛选：
	// 索引时已过滤不可执行模板（headless/非支持协议/自包含/缺解释器/纯code），
	// 入库的都是可执行的。此处兜底旧数据：纯 code 模板（含 code 且不含
	// http/network/websocket）不可执行——本地子进程发请求，无流量数据；
	// 混合模板保留（http/network 段不受 code 签名门控，未签名也可执行）。
	const execCond = `(protocols NOT LIKE '%"code"%' OR protocols LIKE '%"http"%' OR protocols LIKE '%"network"%' OR protocols LIKE '%"websocket"%')`
	switch f.Executable {
	case "true":
		where = append(where, execCond)
	case "false":
		where = append(where, "NOT ("+execCond+")")
	}
	if f.Severity != "" {
		where = append(where, "severity = ?")
		args = append(args, strings.ToLower(f.Severity))
	}
	if f.Tag != "" {
		where = append(where, "tags LIKE ?")
		args = append(args, "%,"+strings.ToLower(f.Tag)+",%")
	}
	if f.Protocol != "" {
		where = append(where, "protocols LIKE ?")
		args = append(args, `%"`+strings.ToLower(f.Protocol)+`"%`)
	}
	switch f.Official {
	case "true":
		where = append(where, "is_official = 1")
	case "false":
		where = append(where, "is_official = 0")
	}
	switch f.Custom {
	case "true":
		where = append(where, "is_custom = 1")
	case "false":
		where = append(where, "is_custom = 0")
	}
	if f.CVE != "" {
		where = append(where, "cve_ids LIKE ?")
		args = append(args, "%"+strings.ToUpper(f.CVE)+"%")
	}
	if f.CNVD != "" {
		where = append(where, "cnvd_ids LIKE ?")
		args = append(args, "%"+strings.ToUpper(f.CNVD)+"%")
	}
	if f.Keyword != "" {
		kw := "%" + f.Keyword + "%"
		where = append(where, "(template_id LIKE ? OR name LIKE ? OR tags LIKE ? OR cve_ids LIKE ? OR cnvd_ids LIKE ?)")
		args = append(args, kw, kw, kw, kw, kw)
	}
	if f.NoInteractsh {
		where = append(where, "has_interactsh = 0")
	}
	return strings.Join(where, " AND "), args
}

// ListPOCs 按过滤器查询 POC 列表。
func (s *Store) ListPOCs(f POCFilter) ([]POC, error) {
	where, args := buildPOCWhere(f)
	q := `SELECT ` + pocColumns + ` FROM pocs WHERE ` + where + ` ORDER BY id`
	if f.Limit > 0 {
		q += ` LIMIT ? OFFSET ?`
		args = append(args, f.Limit, f.Offset)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("list pocs: %w", err)
	}
	defer rows.Close()
	var out []POC
	for rows.Next() {
		p, err := scanPOC(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// CountPOCs 按过滤器统计数量。
func (s *Store) CountPOCs(f POCFilter) (int, error) {
	where, args := buildPOCWhere(f)
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM pocs WHERE `+where, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// GetPOC 按 id 查询单个 POC。
func (s *Store) GetPOC(id int64) (*POC, error) {
	row := s.db.QueryRow(`SELECT `+pocColumns+` FROM pocs WHERE id = ?`, id)
	p, err := scanPOC(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return p, err
}

// POCIDByTemplateID 按 template_id 查询 POC id（人工添加查重用）。
func (s *Store) POCIDByTemplateID(templateID string) (int64, bool, error) {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM pocs WHERE template_id = ? LIMIT 1`, templateID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

// POCStats POC 库统计信息。
type POCStats struct {
	Total          int
	BySeverity     map[string]int
	ByProtocol     map[string]int
	BySourceTop10  []KV
	WithInteractsh int
	Official       int
	Custom         int
}

// KV 通用键值对。
type KV struct {
	Key   string
	Value int
}

// POCStats 返回索引统计。
func (s *Store) POCStats() (*POCStats, error) {
	st := &POCStats{BySeverity: map[string]int{}, ByProtocol: map[string]int{}}
	// COALESCE：空表时 SUM 返回 NULL，直接 Scan 到 int 会报错
	if err := s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(has_interactsh),0), COALESCE(SUM(is_official),0), COALESCE(SUM(is_custom),0) FROM pocs`).
		Scan(&st.Total, &st.WithInteractsh, &st.Official, &st.Custom); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT COALESCE(NULLIF(severity,''),'unknown') sev, COUNT(*) FROM pocs GROUP BY sev ORDER BY 2 DESC`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k string
		var v int
		if err := rows.Scan(&k, &v); err != nil {
			rows.Close()
			return nil, err
		}
		st.BySeverity[k] = v
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// protocols 为 JSON 数组，在应用层聚合
	prows, err := s.db.Query(`SELECT protocols FROM pocs`)
	if err != nil {
		return nil, err
	}
	defer prows.Close()
	for prows.Next() {
		var protoJSON string
		if err := prows.Scan(&protoJSON); err != nil {
			return nil, err
		}
		for _, p := range splitJSONArray(protoJSON) {
			st.ByProtocol[p]++
		}
	}
	if err := prows.Err(); err != nil {
		return nil, err
	}
	srows, err := s.db.Query(`SELECT source_repo, COUNT(*) c FROM pocs GROUP BY source_repo ORDER BY c DESC LIMIT 10`)
	if err != nil {
		return nil, err
	}
	defer srows.Close()
	for srows.Next() {
		var kv KV
		if err := srows.Scan(&kv.Key, &kv.Value); err != nil {
			return nil, err
		}
		st.BySourceTop10 = append(st.BySourceTop10, kv)
	}
	return st, srows.Err()
}

func splitJSONArray(s string) []string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"`)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
