// Package store 提供 SQLite 持久化（modernc.org/sqlite 纯 Go 驱动，无 CGo）。
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

// Store SQLite 存储。
type Store struct {
	db *sql.DB
	// baseDir 数据库所在目录（工作区）。持久化的 file_path 一律存相对
	// baseDir 的路径，跨机器复制项目后仍可用；AbsPath 负责还原。
	baseDir string
}

// Open 打开（必要时创建）数据库并执行迁移。
func Open(path string) (*Store, error) {
	// WAL 提升并发读写；busy_timeout 缓解锁竞争；外键约束用于级联删除
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// modernc sqlite 驱动对并发写敏感，限制单连接避免 database is locked
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	baseDir, _ := filepath.Abs(filepath.Dir(path))
	s := &Store{db: db, baseDir: baseDir}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// AbsPath 将持久化的相对路径还原为绝对路径（已是绝对的保持不变）。
func (s *Store) AbsPath(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(s.baseDir, p)
}

// RelPath 将绝对路径转换为相对 baseDir 的相对路径。
// 仅当目标位于 baseDir 内时转换（避免 ../ 越界路径在扫描时解析错位）；
// 已在 baseDir 树外的绝对路径保持原样，读侧 AbsPath 不二次拼装。
func (s *Store) RelPath(abs string) string {
	abs = filepath.Clean(abs)
	if abs == "" || !filepath.IsAbs(abs) {
		return abs
	}
	rel, err := filepath.Rel(s.baseDir, abs)
	if err != nil {
		return abs
	}
	if rel == "." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
		return abs
	}
	return rel
}

// Close 关闭数据库。
func (s *Store) Close() error { return s.db.Close() }
