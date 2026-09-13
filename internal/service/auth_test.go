package service

import (
	"testing"

	"gobas/internal/config"
)

// newAuthSvc 认证开启的测试服务（首启自动建 admin，返回初始密码）。
func newAuthSvc(t *testing.T) (*Service, string) {
	t.Helper()
	cfg := config.Default()
	cfg.Workspace = t.TempDir()
	cfg.Network.Proxy = ""
	svc, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { svc.Close() })
	return svc, svc.InitialAdminPassword()
}

// TestEnsureFirstRunAdmin 首启建号：幂等 + 随机密码 + 强制改密。
func TestEnsureFirstRunAdmin(t *testing.T) {
	svc, pwd := newAuthSvc(t)
	if pwd == "" {
		t.Fatal("initial password empty")
	}
	// 二次调用不再创建
	created, pwd2, err := svc.EnsureFirstRunAdmin()
	if err != nil {
		t.Fatal(err)
	}
	if created || pwd2 != "" {
		t.Fatalf("second EnsureFirstRunAdmin created=%v pwd=%q, want false/empty", created, pwd2)
	}
	u, err := svc.store.GetUserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	if !u.MustChangePassword {
		t.Fatal("admin should require forced password change")
	}
}

// TestChangePasswordRevokeOtherSessions 改密后踢掉其他会话、保留当前会话。
func TestChangePasswordRevokeOtherSessions(t *testing.T) {
	svc, pwd := newAuthSvc(t)
	tok1, _, err := svc.Login("admin", pwd)
	if err != nil {
		t.Fatal(err)
	}
	tok2, _, err := svc.Login("admin", pwd)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ChangePassword(tok2, pwd, "NewPass123"); err != nil {
		t.Fatal(err)
	}
	if svc.AuthenticateSession(tok1) != nil {
		t.Fatal("tok1 should be revoked after password change")
	}
	if svc.AuthenticateSession(tok2) == nil {
		t.Fatal("tok2 should survive password change")
	}
	// 短密码拒绝
	if err := svc.ChangePassword(tok2, "NewPass123", "short"); err != ErrWeakPassword {
		t.Fatalf("weak password err = %v, want %v", err, ErrWeakPassword)
	}
	// 新旧相同拒绝
	if err := svc.ChangePassword(tok2, "NewPass123", "NewPass123"); err != ErrSamePassword {
		t.Fatalf("same password err = %v, want %v", err, ErrSamePassword)
	}
}

// TestResetPasswordRevokesAll 重置密码后旧会话全部失效 + 强制改密。
func TestResetPasswordRevokesAll(t *testing.T) {
	svc, pwd := newAuthSvc(t)
	tok, _, err := svc.Login("admin", pwd)
	if err != nil {
		t.Fatal(err)
	}
	newPwd, err := svc.ResetPassword("admin", "")
	if err != nil {
		t.Fatal(err)
	}
	if newPwd == pwd {
		t.Fatal("reset password should differ from old")
	}
	if svc.AuthenticateSession(tok) != nil {
		t.Fatal("session should be revoked after reset")
	}
	if _, _, err := svc.Login("admin", pwd); err != ErrInvalidCredentials {
		t.Fatalf("old pwd login err = %v, want %v", err, ErrInvalidCredentials)
	}
	u, err := svc.store.GetUserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	if !u.MustChangePassword {
		t.Fatal("reset should force password change on next login")
	}
}
