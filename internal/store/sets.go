package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// POCSet POC 模板集（自由组装的 POC 分组）。
type POCSet struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	POCCount    int    `json:"poc_count"` // 列表查询时填充
	CreatedAt   string `json:"created_at"`
}

// ErrSetNameExists 模板集名称已存在。
var ErrSetNameExists = errors.New("同名模板集已存在")

// CreatePOCSet 创建模板集。
func (s *Store) CreatePOCSet(name, description string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO poc_sets (name, description, created_at) VALUES (?, ?, ?)`,
		name, description, time.Now().Format("2006-01-02 15:04:05"))
	if err != nil {
		if isUniqueViolation(err) {
			return 0, ErrSetNameExists
		}
		return 0, fmt.Errorf("create poc set: %w", err)
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// isUniqueViolation 判断 SQLite 唯一约束冲突（modernc 驱动错误信息匹配）。
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed")
}

// ListPOCSets 全部模板集（含 POC 数量，按创建时间倒序）。
func (s *Store) ListPOCSets() ([]POCSet, error) {
	rows, err := s.db.Query(`
SELECT ps.id, ps.name, ps.description, COUNT(psi.poc_id), ps.created_at
FROM poc_sets ps LEFT JOIN poc_set_items psi ON psi.set_id = ps.id
GROUP BY ps.id ORDER BY ps.id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list poc sets: %w", err)
	}
	defer rows.Close()
	var out []POCSet
	for rows.Next() {
		var ps POCSet
		if err := rows.Scan(&ps.ID, &ps.Name, &ps.Description, &ps.POCCount, &ps.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, ps)
	}
	return out, rows.Err()
}

// GetPOCSet 按 ID 查模板集。
func (s *Store) GetPOCSet(id int64) (*POCSet, error) {
	var ps POCSet
	err := s.db.QueryRow(`
SELECT ps.id, ps.name, ps.description, COUNT(psi.poc_id), ps.created_at
FROM poc_sets ps LEFT JOIN poc_set_items psi ON psi.set_id = ps.id
WHERE ps.id = ? GROUP BY ps.id`, id).
		Scan(&ps.ID, &ps.Name, &ps.Description, &ps.POCCount, &ps.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &ps, nil
}

// UpdatePOCSet 更新名称/描述（空字段不覆盖）。
func (s *Store) UpdatePOCSet(id int64, name, description string) error {
	if name != "" {
		if _, err := s.db.Exec(`UPDATE poc_sets SET name = ? WHERE id = ?`, name, id); err != nil {
			if isUniqueViolation(err) {
				return ErrSetNameExists
			}
			return fmt.Errorf("update poc set name: %w", err)
		}
	}
	if description != "" {
		if _, err := s.db.Exec(`UPDATE poc_sets SET description = ? WHERE id = ?`, description, id); err != nil {
			return fmt.Errorf("update poc set description: %w", err)
		}
	}
	return nil
}

// DeletePOCSet 删除模板集（items 级联删除）。
func (s *Store) DeletePOCSet(id int64) error {
	_, err := s.db.Exec(`DELETE FROM poc_sets WHERE id = ?`, id)
	return err
}

// AddPOCsToSet 批量添加 POC 到模板集（INSERT OR IGNORE 幂等，返回实际新增数）。
func (s *Store) AddPOCsToSet(setID int64, pocIDs []int64) (int, error) {
	if len(pocIDs) == 0 {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO poc_set_items (set_id, poc_id, added_at) VALUES (?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	added := 0
	now := time.Now().Format("2006-01-02 15:04:05")
	for _, pid := range pocIDs {
		res, err := stmt.Exec(setID, pid, now)
		if err != nil {
			return 0, fmt.Errorf("add poc to set: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			added++
		}
	}
	return added, tx.Commit()
}

// RemovePOCsFromSet 批量移除模板集中的 POC（空列表 = 清空）。
func (s *Store) RemovePOCsFromSet(setID int64, pocIDs []int64) (int, error) {
	var (
		res sql.Result
		err error
	)
	if len(pocIDs) == 0 {
		res, err = s.db.Exec(`DELETE FROM poc_set_items WHERE set_id = ?`, setID)
	} else {
		// IN 占位符
		ph := ""
		args := []any{setID}
		for i, pid := range pocIDs {
			if i > 0 {
				ph += ","
			}
			ph += "?"
			args = append(args, pid)
		}
		res, err = s.db.Exec(`DELETE FROM poc_set_items WHERE set_id = ? AND poc_id IN (`+ph+`)`, args...)
	}
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ListPOCsInSet 模板集内的 POC 列表（join pocs 元数据）。
func (s *Store) ListPOCsInSet(setID int64) ([]POC, error) {
	rows, err := s.db.Query(`SELECT ` + pocColumns + `
FROM pocs p JOIN poc_set_items psi ON psi.poc_id = p.id
WHERE psi.set_id = ? ORDER BY p.id`, setID)
	if err != nil {
		return nil, fmt.Errorf("list pocs in set: %w", err)
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
