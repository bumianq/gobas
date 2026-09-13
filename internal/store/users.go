package store

import (
	"database/sql"
	"errors"
	"time"
)

// ErrUserNotFound 用户不存在。
var ErrUserNotFound = errors.New("用户不存在")

// User 认证用户。
type User struct {
	ID                 int64  `json:"id"`
	Username           string `json:"username"`
	PasswordHash       string `json:"-"`
	MustChangePassword bool   `json:"must_change_password"`
	CreatedAt          string `json:"created_at"`
}

// SessionRecord 会话记录（token 仅存哈希）。
type SessionRecord struct {
	ID        int64
	UserID    int64
	TokenHash string
	ExpiresAt string
}

// CountUsers 用户总数（首启判断用）。
func (s *Store) CountUsers() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// CreateUser 创建用户。
func (s *Store) CreateUser(username, passwordHash string, mustChange bool) (*User, error) {
	now := time.Now().Format("2006-01-02 15:04:05")
	mc := 0
	if mustChange {
		mc = 1
	}
	res, err := s.db.Exec(
		`INSERT INTO users (username, password_hash, must_change_password, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		username, passwordHash, mc, now, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &User{ID: id, Username: username, PasswordHash: passwordHash, MustChangePassword: mustChange, CreatedAt: now}, nil
}

// GetUserByUsername 按用户名查用户。
func (s *Store) GetUserByUsername(username string) (*User, error) {
	u := &User{}
	var mc int
	err := s.db.QueryRow(
		`SELECT id, username, password_hash, must_change_password, created_at FROM users WHERE username = ?`,
		username).Scan(&u.ID, &u.Username, &u.PasswordHash, &mc, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	u.MustChangePassword = mc == 1
	return u, nil
}

// GetUserByID 按 id 查用户。
func (s *Store) GetUserByID(id int64) (*User, error) {
	u := &User{}
	var mc int
	err := s.db.QueryRow(
		`SELECT id, username, password_hash, must_change_password, created_at FROM users WHERE id = ?`,
		id).Scan(&u.ID, &u.Username, &u.PasswordHash, &mc, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	u.MustChangePassword = mc == 1
	return u, nil
}

// UpdateUserPassword 更新密码哈希并设置强制改密标记。
func (s *Store) UpdateUserPassword(userID int64, newHash string, mustChange bool) error {
	mc := 0
	if mustChange {
		mc = 1
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	_, err := s.db.Exec(
		`UPDATE users SET password_hash = ?, must_change_password = ?, updated_at = ? WHERE id = ?`,
		newHash, mc, now, userID)
	return err
}

// CreateSession 创建会话（token 存入前必须先哈希）。
func (s *Store) CreateSession(userID int64, tokenHash string, expiresAt time.Time) (*SessionRecord, error) {
	now := time.Now().Format("2006-01-02 15:04:05")
	exp := expiresAt.Format("2006-01-02 15:04:05")
	res, err := s.db.Exec(
		`INSERT INTO sessions (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)`,
		userID, tokenHash, exp, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &SessionRecord{ID: id, UserID: userID, TokenHash: tokenHash, ExpiresAt: exp}, nil
}

// GetSessionByTokenHash 按 token 哈希查会话（含用户信息，JOIN）。
func (s *Store) GetSessionByTokenHash(tokenHash string) (*SessionRecord, *User, error) {
	rec := &SessionRecord{}
	u := &User{}
	var mc int
	err := s.db.QueryRow(`
		SELECT s.id, s.user_id, s.token_hash, s.expires_at,
		       u.id, u.username, u.password_hash, u.must_change_password, u.created_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ?`, tokenHash).
		Scan(&rec.ID, &rec.UserID, &rec.TokenHash, &rec.ExpiresAt,
			&u.ID, &u.Username, &u.PasswordHash, &mc, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	u.MustChangePassword = mc == 1
	return rec, u, nil
}

// DeleteSessionByTokenHash 删除会话（登出）。
func (s *Store) DeleteSessionByTokenHash(tokenHash string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

// DeleteExpiredSessions 清理过期会话（登录时顺带执行）。
func (s *Store) DeleteExpiredSessions() error {
	now := time.Now().Format("2006-01-02 15:04:05")
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, now)
	return err
}

// DeleteUserSessionsExcept 删除某用户全部会话（可保留当前会话；keepSessionID<=0 表示全删）。
// 用于改密/重置密码后踢掉旧会话。
func (s *Store) DeleteUserSessionsExcept(userID int64, keepSessionID int64) error {
	if keepSessionID <= 0 {
		_, err := s.db.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID)
		return err
	}
	_, err := s.db.Exec(`DELETE FROM sessions WHERE user_id = ? AND id != ?`, userID, keepSessionID)
	return err
}
