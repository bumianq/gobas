// 认证业务：首启建号、登录/登出、改密、CLI 重置密码、会话鉴权。
// 密码只存 bcrypt 哈希；会话 token 随机生成，DB 仅存 SHA-256 哈希；
// 首次登录强制改密由 must_change_password 标记驱动（服务端 403 拦截）。
package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ErrInvalidCredentials 用户名或密码错误（统一文案防用户名枚举）。
var ErrInvalidCredentials = errors.New("用户名或密码错误")

// ErrAuthDisabled 认证已被关闭。
var ErrAuthDisabled = errors.New("认证已关闭")

// ErrWeakPassword 新密码不合规。
var ErrWeakPassword = errors.New("密码长度至少 8 位")

// ErrSamePassword 新旧密码不能相同。
var ErrSamePassword = errors.New("新密码不能与旧密码相同")

// ErrAuthRequired 未登录或会话已过期。
var ErrAuthRequired = errors.New("未登录或会话已过期")

// ErrMustChangePassword 首次登录须先修改密码。
var ErrMustChangePassword = errors.New("首次登录须先修改密码后才能使用该功能")

// AuthUser 已认证用户（挂到请求上下文）。
type AuthUser struct {
	ID                 int64
	Username           string
	MustChangePassword bool
}

// AuthStatus 认证状态快照（/auth/status 返回）。
type AuthStatus struct {
	Enabled            bool   `json:"enabled"`
	Authenticated      bool   `json:"authenticated"`
	Username           string `json:"username,omitempty"`
	MustChangePassword bool   `json:"must_change_password"`
}

// randomPassword 生成 n 位随机密码（剔除易混淆字符 0O1lI 与空格）。
func randomPassword(n int) string {
	const charset = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	buf := make([]byte, n)
	tmp := make([]byte, n)
	if _, err := rand.Read(tmp); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err)) // 系统熵池故障，无法继续
	}
	for i := 0; i < n; i++ {
		buf[i] = charset[int(tmp[i])%len(charset)]
	}
	return string(buf)
}

// hashToken token 原文 → 存库用 SHA-256 十六进制。
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// EnsureFirstRunAdmin 首启建号：users 表为空时创建 admin + 随机初始密码。
// 返回 created=是否本次新创建、plain=初始密码（仅 created 时有意义）。
// 密码只打印/返回给调用方（serve 横幅），不落库。
func (s *Service) EnsureFirstRunAdmin() (created bool, plain string, err error) {
	n, err := s.store.CountUsers()
	if err != nil {
		return false, "", fmt.Errorf("count users: %w", err)
	}
	if n > 0 {
		return false, "", nil
	}
	plain = randomPassword(16)
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return false, "", fmt.Errorf("hash password: %w", err)
	}
	u, err := s.store.CreateUser("admin", string(hash), true)
	if err != nil {
		return false, "", fmt.Errorf("create admin: %w", err)
	}
	s.initialAdminPwd = plain // serve 横幅读取
	slog.Info("首次运行已生成管理员账号", "username", u.Username)
	return true, plain, nil
}

// InitialAdminPassword 返回本进程首次运行生成的初始密码（非首启为空）。
func (s *Service) InitialAdminPassword() string { return s.initialAdminPwd }

// AuthEnabled 认证开关。
func (s *Service) AuthEnabled() bool { return s.cfg.Server.AuthEnabled }

// sessionTTL 会话有效期。
func (s *Service) sessionTTL() time.Duration {
	h := s.cfg.Server.SessionTTLHours
	if h <= 0 {
		h = 24
	}
	return time.Duration(h) * time.Hour
}

// SessionTTL 公开会话有效期（Cookie MaxAge 等）。
func (s *Service) SessionTTL() time.Duration { return s.sessionTTL() }

// AuthStatusNow 认证状态（/auth/status）。
func (s *Service) AuthStatusNow(token string) AuthStatus {
	st := AuthStatus{Enabled: s.cfg.Server.AuthEnabled}
	if !st.Enabled {
		return st
	}
	if u := s.AuthenticateSession(token); u != nil {
		st.Authenticated = true
		st.Username = u.Username
		st.MustChangePassword = u.MustChangePassword
	}
	return st
}

// Login 校验用户名密码，成功则创建会话并返回 token（调用方写 Cookie）。
func (s *Service) Login(username, password string) (token string, u *AuthUser, err error) {
	if !s.cfg.Server.AuthEnabled {
		return "", nil, ErrAuthDisabled
	}
	user, err := s.store.GetUserByUsername(username)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		// 统一失败口径 + 固定延迟防爆破
		time.Sleep(200 * time.Millisecond)
		return "", nil, ErrInvalidCredentials
	}
	_ = s.store.DeleteExpiredSessions() // 顺带清理过期会话
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", nil, fmt.Errorf("rand token: %w", err)
	}
	token = hex.EncodeToString(tokenBytes)
	if _, err := s.store.CreateSession(user.ID, hashToken(token), time.Now().Add(s.sessionTTL())); err != nil {
		return "", nil, fmt.Errorf("create session: %w", err)
	}
	return token, &AuthUser{ID: user.ID, Username: user.Username, MustChangePassword: user.MustChangePassword}, nil
}

// AuthenticateSession 校验会话 token → 用户；无效/过期返回 nil（过期顺带删除）。
func (s *Service) AuthenticateSession(token string) *AuthUser {
	if token == "" {
		return nil
	}
	rec, user, err := s.store.GetSessionByTokenHash(hashToken(token))
	if err != nil || rec == nil {
		return nil
	}
	exp, err := time.ParseInLocation("2006-01-02 15:04:05", rec.ExpiresAt, time.Local)
	if err != nil || time.Now().After(exp) {
		_ = s.store.DeleteSessionByTokenHash(rec.TokenHash)
		return nil
	}
	return &AuthUser{ID: user.ID, Username: user.Username, MustChangePassword: user.MustChangePassword}
}

// Logout 登出：删除本会话。
func (s *Service) Logout(token string) error {
	if token == "" {
		return nil
	}
	return s.store.DeleteSessionByTokenHash(hashToken(token))
}

// ChangePassword 修改密码：校验旧密码 → 更新哈希 → 取消强制改密 → 踢掉其他会话。
// sessionID 为当前会话记录 id，用于保留本会话。
func (s *Service) ChangePassword(token, oldPwd, newPwd string) error {
	if len(newPwd) < 8 {
		return ErrWeakPassword
	}
	if newPwd == oldPwd {
		return ErrSamePassword
	}
	rec, user, err := s.store.GetSessionByTokenHash(hashToken(token))
	if err != nil || rec == nil {
		return ErrAuthRequired
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPwd)) != nil {
		return ErrInvalidCredentials
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPwd), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	if err := s.store.UpdateUserPassword(user.ID, string(hash), false); err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	if err := s.store.DeleteUserSessionsExcept(user.ID, rec.ID); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}
	return nil
}

// ResetPassword CLI 重置密码：空密码自动生成随机；强制下次登录改密并踢掉全部旧会话。
func (s *Service) ResetPassword(username, newPwd string) (string, error) {
	user, err := s.store.GetUserByUsername(username)
	if err != nil {
		return "", err
	}
	if newPwd == "" {
		newPwd = randomPassword(16)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPwd), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	if err := s.store.UpdateUserPassword(user.ID, string(hash), true); err != nil {
		return "", fmt.Errorf("update password: %w", err)
	}
	if err := s.store.DeleteUserSessionsExcept(user.ID, 0); err != nil {
		return "", fmt.Errorf("revoke sessions: %w", err)
	}
	return newPwd, nil
}
