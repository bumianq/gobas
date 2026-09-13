package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 验证用固件模板：正常可加载
const tplValid = `id: gobas-validate-ok
info:
  name: Validate OK
  author: gobas
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: status
        status:
          - 200
`

// 验证用固件模板：编译失败（非法正则）
const tplBrokenRegex = `id: gobas-validate-broken
info:
  name: Validate Broken Regex
  author: gobas
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: regex
        regex:
          - "[invalid(regex"
`

// 验证用固件模板：未签名 code 协议（引擎签名门控应拒绝加载）
const tplUnsignedCode = `id: gobas-validate-unsigned-code
info:
  name: Validate Unsigned Code
  author: gobas
  severity: info
code:
  - engine:
      - sh
    source: |
      echo hello
    matchers:
      - type: word
        words:
          - "hello"
`

// TestValidateTemplates 验证引擎级前置分类：
// 可编译模板加载成功、编译失败/未签名 code 模板被拒、重签后可加载。
func TestValidateTemplates(t *testing.T) {
	if testing.Short() {
		t.Skip("skip engine test in short mode")
	}
	dir := t.TempDir()
	okPath := filepath.Join(dir, "ok.yaml")
	brokenPath := filepath.Join(dir, "broken.yaml")
	codePath := filepath.Join(dir, "code.yaml")
	for p, c := range map[string]string{
		okPath:     tplValid,
		brokenPath: tplBrokenRegex,
		codePath:   tplUnsignedCode,
	} {
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// 未签名 code 模板：签名门控应拒绝
	loaded, err := ValidateTemplates(ctx, []string{okPath, brokenPath, codePath}, nil)
	if err != nil {
		t.Fatalf("ValidateTemplates: %v", err)
	}
	if !loaded["gobas-validate-ok"] {
		t.Error("valid template should load")
	}
	if loaded["gobas-validate-broken"] {
		t.Error("broken template should be rejected by engine")
	}
	if loaded["gobas-validate-unsigned-code"] {
		t.Error("unsigned code template should be rejected by signature gating")
	}

	// 本地重签后：code 模板应可加载（与扫描时行为一致）
	if err := Init(t.TempDir()); err != nil {
		t.Fatalf("Init signer: %v", err)
	}
	ls := Instance()
	if ls == nil {
		t.Fatal("Instance() returned nil after Init")
	}
	if err := ls.SignFile(codePath); err != nil {
		t.Fatalf("SignFile: %v", err)
	}
	loaded, err = ValidateTemplates(ctx, []string{codePath}, nil)
	if err != nil {
		t.Fatalf("ValidateTemplates after signing: %v", err)
	}
	if !loaded["gobas-validate-unsigned-code"] {
		t.Error("signed code template should load after local re-signing")
	}
}
