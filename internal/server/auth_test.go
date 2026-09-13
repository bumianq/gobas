package server

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"gobas/internal/config"
	"gobas/internal/service"
)

// newAuthServer 认证启用的测试服务；返回服务句柄 + 首启初始密码。
func newAuthServer(t *testing.T) (*httptest.Server, *service.Service, string) {
	t.Helper()
	cfg := config.Default()
	cfg.Workspace = t.TempDir()
	cfg.Network.Proxy = ""
	cfg.Server.AuthEnabled = true
	svc, err := service.New(cfg)
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}
	t.Cleanup(func() { svc.Close() })
	// service.New 已在首启时自动创建 admin（随机初始密码）
	pwd := svc.InitialAdminPassword()
	if pwd == "" {
		t.Fatal("initial admin password empty")
	}
	ts := httptest.NewServer(New(svc).Handler())
	t.Cleanup(ts.Close)
	return ts, svc, pwd
}

// authDo 带 Cookie jar 的请求（客户端共享 jar 自动携带会话 Cookie）。
func authDo(t *testing.T, client *http.Client, method, url, body string) (int, map[string]any) {
	t.Helper()
	b := body
	if b == "" {
		b = "{}"
	}
	req, err := http.NewRequest(method, url, strings.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func authClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar}
}

// 未登录拦截与匿名端点。
func TestAuthGate(t *testing.T) {
	ts, _, _ := newAuthServer(t)
	c := authClient()

	if st, _ := authDo(t, c, http.MethodGet, ts.URL+"/api/v1/auth/status", ""); st != http.StatusOK {
		t.Fatalf("auth/status = %d, want 200", st)
	}
	if st, _ := authDo(t, c, http.MethodGet, ts.URL+"/api/v1/healthz", ""); st != http.StatusOK {
		t.Fatalf("healthz = %d, want 200", st)
	}
	// 业务接口未登录 → 401
	if st, _ := authDo(t, c, http.MethodGet, ts.URL+"/api/v1/pocs", ""); st != http.StatusUnauthorized {
		t.Fatalf("pocs = %d, want 401", st)
	}
	// 错误密码 → 401
	if st, _ := authDo(t, c, http.MethodPost, ts.URL+"/api/v1/auth/login", `{"username":"admin","password":"wrong"}`); st != http.StatusUnauthorized {
		t.Fatalf("login wrong = %d, want 401", st)
	}
}

// 首次登录强制改密 → 改密解锁 → 旧密码失效新密码可登录。
func TestAuthForcedChangePassword(t *testing.T) {
	ts, _, pwd := newAuthServer(t)
	c := authClient()
	base := ts.URL + "/api/v1"

	st, body := authDo(t, c, http.MethodPost, base+"/auth/login", `{"username":"admin","password":"`+pwd+`"}`)
	if st != http.StatusOK {
		t.Fatalf("login = %d, want 200", st)
	}
	if body["must_change_password"] != true {
		t.Fatalf("must_change_password = %v, want true", body["must_change_password"])
	}
	// 强制改密期间业务接口 403
	if st, _ := authDo(t, c, http.MethodGet, base+"/pocs", ""); st != http.StatusForbidden {
		t.Fatalf("pocs while forced = %d, want 403", st)
	}
	// 旧密码错误 → 401
	if st, _ := authDo(t, c, http.MethodPost, base+"/auth/change-password", `{"old_password":"bad","new_password":"NewPass123"}`); st != http.StatusUnauthorized {
		t.Fatalf("change bad old = %d, want 401", st)
	}
	// 正确改密 → 放行业务
	if st, _ := authDo(t, c, http.MethodPost, base+"/auth/change-password", `{"old_password":"`+pwd+`","new_password":"NewPass123"}`); st != http.StatusOK {
		t.Fatalf("change = %d, want 200", st)
	}
	if st, _ := authDo(t, c, http.MethodGet, base+"/pocs", ""); st != http.StatusOK {
		t.Fatalf("pocs after change = %d, want 200", st)
	}
	// 旧密码失效 / 新密码可登录且不再强制
	if st, _ := authDo(t, c, http.MethodPost, base+"/auth/login", `{"username":"admin","password":"`+pwd+`"}`); st != http.StatusUnauthorized {
		t.Fatalf("old pwd login = %d, want 401", st)
	}
	c2 := authClient()
	if st, body := authDo(t, c2, http.MethodPost, base+"/auth/login", `{"username":"admin","password":"NewPass123"}`); st != http.StatusOK || body["must_change_password"] != false {
		t.Fatalf("new pwd login = %d/%v, want 200/false", st, body)
	}
}

// 登出后会话失效。
func TestAuthLogout(t *testing.T) {
	ts, _, pwd := newAuthServer(t)
	c := authClient()
	base := ts.URL + "/api/v1"

	authDo(t, c, http.MethodPost, base+"/auth/login", `{"username":"admin","password":"`+pwd+`"}`)
	authDo(t, c, http.MethodPost, base+"/auth/change-password", `{"old_password":"`+pwd+`","new_password":"NewPass123"}`)
	if st, _ := authDo(t, c, http.MethodGet, base+"/pocs", ""); st != http.StatusOK {
		t.Fatalf("pocs = %d, want 200", st)
	}
	if st, _ := authDo(t, c, http.MethodPost, base+"/auth/logout", ""); st != http.StatusOK {
		t.Fatalf("logout = %d, want 200", st)
	}
	if st, _ := authDo(t, c, http.MethodGet, base+"/pocs", ""); st != http.StatusUnauthorized {
		t.Fatalf("pocs after logout = %d, want 401", st)
	}
}

// CLI 重置随机密码：新密码可登录且强制改密，旧密码失效。
func TestAuthResetPassword(t *testing.T) {
	ts, svc, pwd := newAuthServer(t)
	base := ts.URL + "/api/v1"

	newPwd, err := svc.ResetPassword("admin", "")
	if err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	if newPwd == "" || newPwd == pwd {
		t.Fatalf("new pwd invalid: %q", newPwd)
	}
	// 旧密码失效
	c := authClient()
	if st, _ := authDo(t, c, http.MethodPost, base+"/auth/login", `{"username":"admin","password":"`+pwd+`"}`); st != http.StatusUnauthorized {
		t.Fatalf("old pwd = %d, want 401", st)
	}
	// 新密码可登录且强制改密
	c2 := authClient()
	if st, body := authDo(t, c2, http.MethodPost, base+"/auth/login", `{"username":"admin","password":"`+newPwd+`"}`); st != http.StatusOK || body["must_change_password"] != true {
		t.Fatalf("new pwd = %d/%v, want 200/true", st, body)
	}
}

// 认证关闭时全部放行。
func TestAuthDisabled(t *testing.T) {
	cfg := config.Default()
	cfg.Workspace = t.TempDir()
	cfg.Network.Proxy = ""
	cfg.Server.AuthEnabled = false
	svc, err := service.New(cfg)
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}
	t.Cleanup(func() { svc.Close() })
	ts := httptest.NewServer(New(svc).Handler())
	t.Cleanup(ts.Close)

	c := authClient()
	if st, _ := authDo(t, c, http.MethodGet, ts.URL+"/api/v1/pocs", ""); st != http.StatusOK {
		t.Fatalf("pocs with auth disabled = %d, want 200", st)
	}
	if st, body := authDo(t, c, http.MethodGet, ts.URL+"/api/v1/auth/status", ""); st != http.StatusOK || body["enabled"] != false {
		t.Fatalf("auth/status = %d/%v, want 200/enabled:false", st, body)
	}
}
