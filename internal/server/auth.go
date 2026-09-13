// 认证中间件与 /auth/* 端点。
// 会话采用 HttpOnly Cookie（EventSource SSE 天然携带，无需查询参数）。
// 放行规则：healthz/login/status 匿名；其余 API 须已登录；
// must_change_password=1 时仅放行 change-password/logout。
package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"gobas/internal/service"
)

// sessionCookieName 会话 Cookie 名。
const sessionCookieName = "gobas_session"

// authUserCtxKey 已认证用户写入请求上下文的键。
type authUserCtxKey struct{}

// authUserFromContext 取出中间件注入的已认证用户（无 = nil）。
func authUserFromContext(r *http.Request) *service.AuthUser {
	u, _ := r.Context().Value(authUserCtxKey{}).(*service.AuthUser)
	return u
}

// authToken 读取会话 Cookie。
func authToken(r *http.Request) string {
	if c, err := r.Cookie(sessionCookieName); err == nil {
		return c.Value
	}
	return ""
}

// setSessionCookie 下发会话 Cookie（MaxAge 与会话 TTL 一致，浏览器重启不丢）。
func setSessionCookie(w http.ResponseWriter, token string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

// clearSessionCookie 清除会话 Cookie（登出）。
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// authMiddleware 保护 /api/v1 下的业务路由。
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 认证关闭：全部放行（GUI 由 /auth/status 感知并跳过登录页）
		if !s.svc.AuthEnabled() {
			next.ServeHTTP(w, r)
			return
		}
		p := r.URL.Path
		// 匿名端点
		if p == "/api/v1/healthz" || p == "/api/v1/auth/login" || p == "/api/v1/auth/status" {
			next.ServeHTTP(w, r)
			return
		}
		// 其余端点须登录
		token := authToken(r)
		u := s.svc.AuthenticateSession(token)
		if u == nil {
			writeErr(w, http.StatusUnauthorized, service.ErrAuthRequired)
			return
		}
		// 首次登录强制改密：除改密/登出外一律 403
		if u.MustChangePassword && p != "/api/v1/auth/logout" && p != "/api/v1/auth/change-password" {
			writeErr(w, http.StatusForbidden, service.ErrMustChangePassword)
			return
		}
		ctx := context.WithValue(r.Context(), authUserCtxKey{}, u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// handleLogin POST /auth/login {username,password} → 下发会话 Cookie。
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if r.Body == nil {
		writeErr(w, http.StatusBadRequest, errors.New("empty body"))
		return
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	token, u, err := s.svc.Login(req.Username, req.Password)
	if err != nil {
		if errors.Is(err, service.ErrAuthDisabled) {
			writeErr(w, http.StatusForbidden, err)
			return
		}
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	setSessionCookie(w, token, s.svc.SessionTTL())
	writeJSON(w, http.StatusOK, map[string]any{
		"username":             u.Username,
		"must_change_password": u.MustChangePassword,
		"auth_enabled":         true,
	})
}

// handleLogout POST /auth/logout → 删除会话 + 清 Cookie。
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := authToken(r)
	if token != "" {
		_ = s.svc.Logout(token)
	}
	clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// handleChangePassword POST /auth/change-password {old_password,new_password}。
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	token := authToken(r)
	if err := s.svc.ChangePassword(token, req.OldPassword, req.NewPassword); err != nil {
		switch {
		case errors.Is(err, service.ErrAuthRequired):
			writeErr(w, http.StatusUnauthorized, err)
		case errors.Is(err, service.ErrWeakPassword), errors.Is(err, service.ErrSamePassword):
			writeErr(w, http.StatusBadRequest, err)
		default:
			writeErr(w, http.StatusUnauthorized, err) // 旧密码错误
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "changed"})
}

// handleAuthStatus GET /auth/status → 认证状态（前端启动引导）。
func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.AuthStatusNow(authToken(r)))
}
