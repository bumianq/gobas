package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Target 被测目标。
type Target struct {
	ID             int64
	Name           string
	URL            string
	Alive          bool
	BaselineStatus int
	BaselineRTTMS  int64
	BaselineError  string
	LastProbeAt    string
	CreatedAt      string
}

const targetColumns = `id, name, url, alive, baseline_status, baseline_rtt_ms, baseline_error, last_probe_at, created_at`

func scanTarget(row interface{ Scan(...any) error }) (*Target, error) {
	var t Target
	var alive int
	if err := row.Scan(&t.ID, &t.Name, &t.URL, &alive, &t.BaselineStatus, &t.BaselineRTTMS,
		&t.BaselineError, &t.LastProbeAt, &t.CreatedAt); err != nil {
		return nil, err
	}
	t.Alive = alive != 0
	return &t, nil
}

// UpsertTarget 新增或更新目标（按 URL 唯一），返回最终记录。
func (s *Store) UpsertTarget(url, name string) (*Target, error) {
	_, err := s.db.Exec(`INSERT INTO targets (name, url, created_at) VALUES (?, ?, ?)
ON CONFLICT(url) DO UPDATE SET name = excluded.name`, name, url, time.Now().Format("2006-01-02 15:04:05"))
	if err != nil {
		return nil, fmt.Errorf("upsert target: %w", err)
	}
	row := s.db.QueryRow(`SELECT `+targetColumns+` FROM targets WHERE url = ?`, url)
	t, err := scanTarget(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("target disappeared after upsert")
	}
	return t, err
}

// GetTarget 按 id 查询。
func (s *Store) GetTarget(id int64) (*Target, error) {
	row := s.db.QueryRow(`SELECT `+targetColumns+` FROM targets WHERE id = ?`, id)
	t, err := scanTarget(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}

// ListTargets 全部目标。
func (s *Store) ListTargets() ([]Target, error) {
	rows, err := s.db.Query(`SELECT ` + targetColumns + ` FROM targets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// GetTargetsByIDs 按 id 集合查询。
func (s *Store) GetTargetsByIDs(ids []int64) ([]Target, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	ph := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		ph[i] = "?"
		args[i] = id
	}
	rows, err := s.db.Query(`SELECT `+targetColumns+` FROM targets WHERE id IN (`+
		strings.Join(ph, ",")+`) ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// RemoveTarget 删除目标。
func (s *Store) RemoveTarget(id int64) error {
	_, err := s.db.Exec(`DELETE FROM targets WHERE id = ?`, id)
	return err
}

// UpdateTargetBaseline 更新目标基线探活结果。
func (s *Store) UpdateTargetBaseline(id int64, alive bool, status int, rttMS int64, errMsg string) error {
	_, err := s.db.Exec(`UPDATE targets SET alive=?, baseline_status=?, baseline_rtt_ms=?, baseline_error=?, last_probe_at=? WHERE id=?`,
		boolToInt(alive), status, rttMS, errMsg, time.Now().Format("2006-01-02 15:04:05"), id)
	return err
}
