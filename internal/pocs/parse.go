// Package pocs 解析 nuclei 模板 YAML front-matter 元数据并构建索引。
// 轻量解析（gopkg.in/yaml.v3），不启动 nuclei 引擎。
package pocs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/templates/signer"
	"gopkg.in/yaml.v3"
)

// cnvdRe 匹配 CNVD/CNNVD 编号（社区模板惯例：写在 id/tags/文件名中）。
var cnvdRe = regexp.MustCompile(`(?i)\bcn?nvd[-_]?\d{4}[-_]?\d+\b`)

// credsVarRe 匹配凭证依赖声明（credentials-stuffing 模板惯例）：
// 顶层 variables 段声明 username/password 变量并引用运行时输入 {{username}}/{{password}}。
// 这类模板无凭证输入时不产生有效请求（空请求/无意义判定），不可自动执行。
var credsVarRe = regexp.MustCompile(`(?m)^\s*(username|password|user|pass):\s*['"]?\{\{(username|password|user|pass)\}\}`)

// credsRefRe 匹配请求中直接引用的运行时凭证输入（raw 请求体/URL 中 {{username}} 等）。
// 无 payloads/variables 提供源时，nuclei 无法解析该变量——不发出任何请求，
// 事件为空（无流量、无状态码、无错误，判定兜底 MISS）。
var credsRefRe = regexp.MustCompile(`\{\{(username|password|user|pass)\}\}`)

// credsProviderRe 匹配凭证提供源声明（variables/payloads 块中的 username/password 等
// 键定义，静态值或攻击模式列表）。有提供源的 {{username}} 引用可正常解析执行
// （如 default-login 模板的 pitchfork payloads）。
var credsProviderRe = regexp.MustCompile(`(?m)^\s*(username|password|user|pass):`)

// runtimeVarRefRe 匹配 variables 块中值为裸变量引用（{{word}}）的运行时输入依赖
// （如 database: "{{database}}"，需 -vars 传入；无输入时请求无法生成，事件为空）。
var runtimeVarRefRe = regexp.MustCompile(`^\{\{[a-zA-Z_][a-zA-Z0-9_]*\}\}$`)

// varBuiltins nuclei 内置模板变量（variables 块中引用它们是合法的，非运行时输入）。
var varBuiltins = map[string]bool{
	"baseurl": true, "rooturl": true, "hostname": true, "host": true,
	"port": true, "scheme": true, "randstr": true, "interactsh_url": true,
	"interactsh_protocol": true, "interactsh_id": true,
}

// nucleiEnvProvided nuclei 运行时注入 code 子进程 ENV 的目标派生变量
// （pkg/protocols/utils/variables.go KnownVariables）。code 源码只能读这些
// 与模板 variables 定义的变量；引用其他 ENV 属运行时输入（-vars 传入）。
var nucleiEnvProvided = map[string]bool{
	"baseurl": true, "rooturl": true, "hostname": true, "host": true,
	"port": true, "path": true, "query": true, "file": true,
	"scheme": true, "input": true, "fqdn": true, "rdn": true,
	"dn": true, "tld": true, "sd": true,
}

// envRefRegexps code 源码中读取环境变量的常见写法：
// ruby ENV['x']、python os.getenv('x')/os.environ['x']、
// node process.env.x、powershell $env:x。
var envRefRegexps = []*regexp.Regexp{
	regexp.MustCompile(`ENV\s*\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\]`),
	regexp.MustCompile(`os\.getenv\s*\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\)`),
	regexp.MustCompile(`os\.environ\s*\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\]`),
	regexp.MustCompile(`process\.env\.([A-Za-z_][A-Za-z0-9_]*)`),
	regexp.MustCompile(`\$env:([A-Za-z_][A-Za-z0-9_]*)`),
}

// knownProtocols nuclei 支持的协议类型（模板顶层键）。
var knownProtocols = map[string]bool{
	"http": true, "dns": true, "file": true, "network": true, "headless": true,
	"ssl": true, "websocket": true, "whois": true, "code": true, "ollama": true,
}

// POCMeta 模板元数据。
type POCMeta struct {
	TemplateID      string
	Name            string
	Authors         []string
	Severity        string
	Tags            []string
	Description      string
	CVEIDs          []string
	CNVDIDs         []string
	CWEIDs          []string
	CVSSScore       float64
	Protocols       []string
	HasInteractsh   bool // 依赖 OOB 回连（{{interactsh_url}}），引擎禁用 interactsh 时恒失败
	NeedsCredentials bool // 需运行时输入（凭证 {{username}}/{{password}} 或 -vars 变量），无输入时不产生有效请求（空事件）
	SelfContained    bool   // 模板级/请求级 self-contained（不对扫描目标发请求）
	Verified        bool   // 模板签名是否通过官方验证器验证
	CodeEngines     string // code 协议使用的语言引擎（CSV，如 "php,python3"），非 code 模板为空
	IsDAST          bool   // 是否含 fuzzing 字段（DAST 模板，需 -dast 标志开启）
	FilePath        string
	ContentHash     string
	FileSize        int64
}

// availableEngines 检测本地可用的 code 解释器（启动时缓存）。
var availableEngines map[string]bool

func init() {
	availableEngines = detectEngines()
}

// detectEngines 检测本地已安装的 code 解释器。
func detectEngines() map[string]bool {
	engines := map[string]bool{
		"sh": true, "bash": true, // macOS/Linux 默认有 shell
		"cmd": true, "cmd.exe": true,
	}
	for _, name := range []string{"python3", "py", "python", "node", "javascript", "js", "php", "powershell", "powershell.exe", "ruby", "perl"} {
		if _, err := exec.LookPath(name); err == nil {
			engines[name] = true
		}
	}
	return engines
}

// hasEngine 检查引擎是否本地可用。
func hasEngine(name string) bool {
	return availableEngines[name]
}

// isPureCode 判断协议集合是否为纯 code（含 code 且不含 http/network/websocket）。
func isPureCode(protocols []string) bool {
	hasCode := false
	for _, p := range protocols {
		switch p {
		case "code":
			hasCode = true
		case "http", "network", "websocket":
			return false
		}
	}
	return hasCode
}

// canExecute 根据模板属性做静态预过滤（快速排除明显不可执行模板）。
// 最终入库以引擎真实加载验证为准（index 阶段三），此处排除：
// headless 协议、非支持协议、自包含、纯 code 协议、code 引擎未安装、
// DAST（fuzzing）模板、依赖 OOB 回连（引擎禁用 interactsh，恒定失败）、需凭证输入。
// 纯 code 模板（不含 http/network/websocket 顶层协议）由本地子进程发请求：
// 引擎层无请求/响应事件（流量恒空、判定兜底 MISS），且脚本依赖本机外部工具
// （curl/websocat 等），环境不可控，统一排除；混合模板保留（http/network 段可正常执行）。
func canExecute(meta *POCMeta) bool {
	if meta.SelfContained || meta.IsDAST || meta.HasInteractsh || meta.NeedsCredentials {
		return false
	}
	hasSupported := false
	for _, p := range meta.Protocols {
		switch p {
		case "headless":
			return false
		case "http", "websocket", "code", "network":
			hasSupported = true
		}
	}
	if !hasSupported {
		return false
	}
	// 纯 code 模板排除（混合模板放行）
	if isPureCode(meta.Protocols) {
		return false
	}
	// code 协议模板需检查语言引擎是否本地可用
	for _, p := range meta.Protocols {
		if p == "code" && meta.CodeEngines != "" {
			engines := strings.Split(meta.CodeEngines, ",")
			for _, e := range engines {
				e = strings.TrimSpace(e)
				if e != "" && !hasEngine(e) {
					return false
				}
			}
		}
	}
	return true
}

// CanExecute 导出静态预过滤（人工添加 POC 复用与索引一致的准入规则）。
func CanExecute(meta *POCMeta) bool { return canExecute(meta) }

// FlexStrings 兼容 YAML 标量（逗号分隔）与序列两种写法的字符串列表。
type FlexStrings []string

// UnmarshalYAML 实现 yaml.Unmarshaler。
func (f *FlexStrings) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		if value.Tag == "!!null" {
			*f = nil
			return nil
		}
		*f = splitAndTrim(value.Value)
	case yaml.SequenceNode:
		var out []string
		if err := value.Decode(&out); err != nil {
			return err
		}
		*f = out
	default:
		return fmt.Errorf("unexpected yaml node kind %v for string list", value.Kind)
	}
	return nil
}

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// isTruthyYAML 判断 YAML 布尔节点真值（true/yes）。
func isTruthyYAML(n *yaml.Node) bool {
	return n != nil && (n.Value == "true" || n.Value == "yes")
}

// rawTemplate 模板 front-matter 原始结构。
type rawTemplate struct {
	ID   string `yaml:"id"`
	Info struct {
		Name           string      `yaml:"name"`
		Author         FlexStrings `yaml:"author"`
		Severity       FlexStrings `yaml:"severity"`
		Description    string      `yaml:"description"`
		Tags           FlexStrings `yaml:"tags"`
		Classification struct {
			CVEIDs    FlexStrings `yaml:"cve-id"`
			CWEIDs    FlexStrings `yaml:"cwe-id"`
			CVSSScore float64     `yaml:"cvss-score"`
		} `yaml:"classification"`
	} `yaml:"info"`
}

// ParseTemplateFile 解析模板文件元数据。
func ParseTemplateFile(path string) (*POCMeta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseTemplate(path, data)
}

// ParseTemplate 从字节内容解析模板元数据。
func ParseTemplate(path string, data []byte) (*POCMeta, error) {
	var raw rawTemplate
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if raw.ID == "" {
		return nil, fmt.Errorf("missing template id")
	}

	meta := &POCMeta{
		TemplateID:  raw.ID,
		Name:        raw.Info.Name,
		Authors:     raw.Info.Author,
		Severity:    normalizeSeverity(raw.Info.Severity),
		Tags:        raw.Info.Tags,
		Description: raw.Info.Description,
		CVEIDs:      normalizeIDs(raw.Info.Classification.CVEIDs, "CVE"),
		CWEIDs:      normalizeIDs(raw.Info.Classification.CWEIDs, "CWE"),
		CVSSScore:   raw.Info.Classification.CVSSScore,
	}

	// 顶层协议键 + self-contained 标记（模板级顶层键 / 协议请求块内的请求级键）
	var root yaml.Node
	varKeys := map[string]bool{} // 顶层 variables 定义的变量名（小写）
	var codeSources []string     // code 协议段源码（ENV 输入依赖检测）
	if err := yaml.Unmarshal(data, &root); err == nil && root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		if m := root.Content[0]; m.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(m.Content); i += 2 {
				k := strings.ToLower(m.Content[i].Value)
				v := m.Content[i+1]
				// nuclei 顶层键别名归一化：requests 是 http 的旧式别名，
				// 引擎照常加载，静态协议识别必须保持一致否则误杀。
				if k == "requests" {
					k = "http"
				}
				if knownProtocols[k] {
					meta.Protocols = append(meta.Protocols, k)
				}
				if k == "self-contained" && isTruthyYAML(v) {
					meta.SelfContained = true
				}
				// 顶层 variables 块：值为裸 {{word}} 引用（且非内置变量、非同块其他键）
				// 表示运行时输入依赖（-vars 传入），无输入时请求无法生成、事件为空
				if k == "variables" && v.Kind == yaml.MappingNode {
					collectVarKeys(v, varKeys)
					if needsRuntimeInput(v) {
						meta.NeedsCredentials = true
					}
				}
				// 请求级 self-contained：http/network/headless 等请求块内声明
				// code 协议请求块内提取 engine 字段（语言引擎，如 php/python3）
				if knownProtocols[k] && v.Kind == yaml.SequenceNode {
					for _, req := range v.Content {
						if req.Kind != yaml.MappingNode {
							continue
						}
						for j := 0; j+1 < len(req.Content); j += 2 {
							rk := strings.ToLower(req.Content[j].Value)
							if rk == "self-contained" && isTruthyYAML(req.Content[j+1]) {
								meta.SelfContained = true
							}
							// fuzzing 字段标记为 DAST 模板（需 -dast 标志，引擎默认未开启）
							if rk == "fuzzing" {
								meta.IsDAST = true
							}
							// code 协议的 engine 字段：可能是标量或序列
							if k == "code" && rk == "engine" {
								engines := extractEngines(req.Content[j+1])
								for _, e := range engines {
									if meta.CodeEngines == "" {
										meta.CodeEngines = e
									} else if !strings.Contains(","+meta.CodeEngines+",", ","+e+",") {
										meta.CodeEngines += "," + e
									}
								}
							}
							// code 协议的 source 字段：收集用于 ENV 输入依赖检测
							if k == "code" && rk == "source" && req.Content[j+1].Kind == yaml.ScalarNode {
								codeSources = append(codeSources, req.Content[j+1].Value)
							}
						}
					}
				}
			}
		}
	}
	sort.Strings(meta.Protocols)

	// code 源码 ENV 输入依赖检测：子进程 ENV 仅含 nuclei 注入的目标派生变量
	// （BaseURL/RootURL/Hostname 等）与模板 variables 定义值；引用其他 ENV
	// （如 SAMLResponse/username 等需 -vars 传入的输入）的模板，无输入时
	// 脚本崩溃、模板链中止——不发出任何请求（无事件、无流量）→ 不可自动执行。
	if len(codeSources) > 0 && needsRuntimeEnvInput(codeSources, varKeys) {
		meta.NeedsCredentials = true
	}

	// interactsh 回连标记
	meta.HasInteractsh = strings.Contains(string(data), "{{interactsh")

	// 凭证/运行时输入依赖标记：
	// 1. variables 段声明 username/password 引用运行时输入（creds-stuffing 惯例）；
	// 2. 请求中直接引用 {{username}}/{{password}} 等，且无 payloads/variables 提供源
	//    （default-login 模板经 pitchfork payloads 提供静态凭证，可正常执行）；
	// 3. variables 块值为裸 {{word}} 自引用（需 -vars 运行时输入）。
	// 三种情况无输入时均不产生有效请求（空事件，无流量），不可自动执行。
	meta.NeedsCredentials = meta.NeedsCredentials ||
		credsVarRe.Match(data) ||
		(credsRefRe.Match(data) && !credsProviderRe.Match(data))

	// CNVD/CNNVD 编号：从 id/tags/文件名提取
	blob := raw.ID + "," + strings.Join(raw.Info.Tags, ",") + "," + filepath.Base(path)
	if found := cnvdRe.FindAllString(blob, -1); len(found) > 0 {
		seen := map[string]bool{}
		for _, v := range found {
			v = strings.ToUpper(v)
			if !seen[v] {
				seen[v] = true
				meta.CNVDIDs = append(meta.CNVDIDs, v)
			}
		}
	}

	sum := sha256.Sum256(data)
	meta.ContentHash = hex.EncodeToString(sum[:])
	meta.FileSize = int64(len(data))
	meta.FilePath = path

	// 签名验证：用 nuclei 官方验证器链检测模板签名是否通过。
	// code 协议模板如果未通过官方签名验证，nuclei 引擎会无条件拒绝加载
	// （本地签名器会在扫描时重签，但 POC 库展示时标记为"需重签"）。
	meta.Verified = verifySignature(data)

	return meta, nil
}

// collectVarKeys 收集 variables 映射块的键名（小写）到 out。
func collectVarKeys(varsNode *yaml.Node, out map[string]bool) {
	for i := 0; i+1 < len(varsNode.Content); i += 2 {
		out[strings.ToLower(varsNode.Content[i].Value)] = true
	}
}

// needsRuntimeEnvInput 检测 code 源码是否引用了 nuclei 未提供的 ENV 变量。
// 子进程 ENV 仅含目标派生变量（nucleiEnvProvided）、模板 variables 定义值
// 与内置变量；引用其他 ENV（SAMLResponse/metadata_url 等需 -vars 传入的
// 输入）时，无输入则脚本崩溃、模板链中止（无事件、无流量）。
func needsRuntimeEnvInput(sources []string, defined map[string]bool) bool {
	for _, src := range sources {
		for _, re := range envRefRegexps {
			for _, m := range re.FindAllStringSubmatch(src, -1) {
				for _, name := range m[1:] {
					if name == "" {
						continue
					}
					word := strings.ToLower(name)
					if !nucleiEnvProvided[word] && !varBuiltins[word] && !defined[word] {
						return true
					}
				}
			}
		}
	}
	return false
}

// needsRuntimeInput 判断 variables 映射块是否存在运行时输入依赖：
// 存在值为裸 {{word}} 的条目，且 word 既非内置变量（BaseURL/Hostname 等）
// 也非同块内其他静态键（变量互相引用是合法的）。
// 例：database: "{{database}}"（prest-sqli-auth-bypass，需 -vars 传入）。
func needsRuntimeInput(varsNode *yaml.Node) bool {
	keys := make(map[string]bool, len(varsNode.Content)/2)
	for i := 0; i+1 < len(varsNode.Content); i += 2 {
		keys[strings.ToLower(varsNode.Content[i].Value)] = true
	}
	for i := 1; i < len(varsNode.Content); i += 2 {
		key := strings.ToLower(varsNode.Content[i-1].Value)
		v := varsNode.Content[i]
		if v.Kind != yaml.ScalarNode {
			continue
		}
		val := strings.TrimSpace(v.Value)
		if !runtimeVarRefRe.MatchString(val) {
			continue // 非裸 {{word}} 引用（静态值或插值表达式）
		}
		word := strings.ToLower(strings.Trim(val, "{} "))
		// 自引用（word == key）= 运行时输入；引用同块其他键/内置变量 = 合法
		if !varBuiltins[word] && (word == key || !keys[word]) {
			return true
		}
	}
	return false
}

// nopSignable 实现 signer.SignableTemplate 接口（无文件导入的模板）。
type nopSignable struct{}

func (nopSignable) GetFileImports() []string { return nil }
func (nopSignable) HasCodeProtocol() bool     { return false }

// verifySignature 用 nuclei 官方验证器链验证模板签名。
func verifySignature(data []byte) bool {
	for _, v := range signer.DefaultTemplateVerifiers {
		if ok, _ := v.Verify(data, nopSignable{}); ok {
			return true
		}
	}
	return false
}

// extractEngines 从 YAML 节点提取 code 引擎名称（标量或序列）。
func extractEngines(n *yaml.Node) []string {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.ScalarNode:
		s := strings.TrimSpace(n.Value)
		if s != "" {
			return []string{s}
		}
	case yaml.SequenceNode:
		var out []string
		for _, item := range n.Content {
			s := strings.TrimSpace(item.Value)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// normalizeSeverity 多值时取最高严重度。
func normalizeSeverity(sev FlexStrings) string {
	rank := map[string]int{"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5, "unknown": 1}
	best := ""
	for _, s := range sev {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if _, ok := rank[s]; !ok {
			continue
		}
		if best == "" || rank[s] > rank[best] {
			best = s
		}
	}
	if best == "" {
		return "unknown"
	}
	return best
}

// normalizeIDs 规范化 CVE/CWE 编号（大写、去重、可选补前缀）。
func normalizeIDs(ids FlexStrings, prefix string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		id = strings.ToUpper(strings.TrimSpace(id))
		if id == "" {
			continue
		}
		if prefix != "" && !strings.HasPrefix(id, prefix+"-") && regexpDigitOnly(id) {
			id = prefix + "-" + id
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func regexpDigitOnly(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

// SeverityRank 对外暴露严重度排序辅助（报告排序用）。
func SeverityRank(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

// FormatFloat 辅助格式化浮点（避免 strconv 依赖散落各处）。
func FormatFloat(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }
