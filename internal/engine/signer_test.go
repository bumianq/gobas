package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/templates/signer"
)

// TestLocalSignerSignAndVerify 验证本地签名器签名后能被 nuclei 验证器验证通过。
func TestLocalSignerSignAndVerify(t *testing.T) {
	tmp := t.TempDir()
	if err := Init(tmp); err != nil {
		t.Fatalf("Init: %v", err)
	}
	ls := Instance()
	if ls == nil {
		t.Fatal("Instance() returned nil")
	}
	t.Logf("fragment=%s identifier=%s", ls.fragment, ls.signer.Identifier())
	t.Logf("verifiers after init: %d", len(signer.DefaultTemplateVerifiers))

	// 用一个社区签名的 code 模板测试（路径自项目根推导，跨机器/目录可用）
	srcPath := findProjectFile(t, "clone-templates/projectdiscovery/nuclei-templates/code/cves/2020/CVE-2020-13935.yaml")
	data, err := os.ReadFile(srcPath)
	if err != nil {
		t.Skipf("template not found: %v", err)
	}

	// 签名前验证应失败
	if ls.Verify(data) {
		t.Error("template should not verify before signing")
	}

	// 签名
	signed, err := ls.SignTemplate(data)
	if err != nil {
		t.Fatalf("SignTemplate: %v", err)
	}

	// 签名后验证应通过（本地验证器）
	if !ls.Verify(signed) {
		t.Error("template should verify after signing")
	}

	// 写入临时文件，用 SignFile 验证幂等性
	dstPath := filepath.Join(tmp, "test.yaml")
	if err := os.WriteFile(dstPath, signed, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ls.SignFile(dstPath); err != nil {
		t.Fatalf("SignFile (idempotent): %v", err)
	}
	// 二次签名不应改变文件
	reSigned, _ := os.ReadFile(dstPath)
	if string(reSigned) != string(signed) {
		t.Error("SignFile modified already-signed template")
	}
}

// findProjectFile 从当前目录向上逐级查找项目根（含 go.mod），
// 拼接相对路径返回绝对路径；找不到则原样返回（读取时测试会 skip）。
func findProjectFile(t *testing.T, rel string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		return rel
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, rel)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return rel
		}
		dir = parent
	}
}
