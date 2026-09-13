package store

import (
	"database/sql"
	"fmt"
)

// TrafficDump 一条镜像连接的原始流量记录（socks5 镜像代理逐连接捕获）。
type TrafficDump struct {
	ID          int64
	ScanID      int64
	Seq         int // 扫描内连接顺序
	Addr        string
	StartedAt   string
	DurationMs  int64
	ClientData  string // 客户端→服务端（截断+UTF-8 清洗）
	ServerData  string // 服务端→客户端
	ClientLen   int    // 原始字节数（截断前）
	ServerLen   int
	ClientTrunc bool
	ServerTrunc bool
}

// InsertTrafficDump 批量插入镜像连接流水（单事务，分批）。
func (s *Store) InsertTrafficDump(rows []TrafficDump) error {
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
		stmt, err := tx.Prepare(`INSERT INTO scan_traffic_dump
(scan_id, seq, addr, started_at, duration_ms, client_data, server_data, client_len, server_len, client_trunc, server_trunc)
VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			tx.Rollback()
			return err
		}
		for _, r := range rows[start:end] {
			ct, st := 0, 0
			if r.ClientTrunc {
				ct = 1
			}
			if r.ServerTrunc {
				st = 1
			}
			if _, err := stmt.Exec(r.ScanID, r.Seq, r.Addr, r.StartedAt, r.DurationMs,
				r.ClientData, r.ServerData, r.ClientLen, r.ServerLen, ct, st); err != nil {
				stmt.Close()
				tx.Rollback()
				return fmt.Errorf("insert traffic dump: %w", err)
			}
		}
		stmt.Close()
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// ListTrafficDump 分页查询镜像连接流水（seq 升序）。
func (s *Store) ListTrafficDump(scanID int64, limit, offset int) ([]TrafficDump, error) {
	rows, err := s.db.Query(`SELECT id, scan_id, seq, addr, started_at, duration_ms,
client_data, server_data, client_len, server_len, client_trunc, server_trunc
FROM scan_traffic_dump WHERE scan_id = ? ORDER BY seq LIMIT ? OFFSET ?`,
		scanID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrafficDump
	for rows.Next() {
		var r TrafficDump
		var ct, st int
		if err := rows.Scan(&r.ID, &r.ScanID, &r.Seq, &r.Addr, &r.StartedAt, &r.DurationMs,
			&r.ClientData, &r.ServerData, &r.ClientLen, &r.ServerLen, &ct, &st); err != nil {
			return nil, err
		}
		r.ClientTrunc = ct == 1
		r.ServerTrunc = st == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountTrafficDump 镜像连接总数。
func (s *Store) CountTrafficDump(scanID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM scan_traffic_dump WHERE scan_id = ?`, scanID).Scan(&n)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return n, err
}
