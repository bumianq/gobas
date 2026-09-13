package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/template"

	"gobas/internal/store"
)

// SupportedFormats 支持的导出格式。
var SupportedFormats = []string{"json", "csv", "md"}

// Export 按格式导出报告。
func Export(m *Model, format string, w io.Writer) error {
	switch strings.ToLower(format) {
	case "json":
		return exportJSON(m, w)
	case "csv":
		return exportCSV(m, w)
	case "md", "markdown":
		return exportMarkdown(m, w)
	default:
		return fmt.Errorf("unsupported format %q (expect json|csv|md)", format)
	}
}

func exportJSON(m *Model, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(m)
}

func exportCSV(m *Model, w io.Writer) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	if err := cw.Write([]string{"target", "poc", "template_id", "severity", "verdict",
		"manual", "auto_verdict", "response_status", "error", "request", "response"}); err != nil {
		return err
	}
	for _, t := range m.Targets {
		for _, r := range t.Results {
			if err := cw.Write([]string{
				t.URL, r.POCName, r.TemplateID, r.Severity, r.Verdict,
				manualMark(r.ManualAt), r.AutoVerdict,
				fmt.Sprintf("%d", r.ResponseStatus), r.ErrorText,
				trafficCell(r.Traffic, func(tr store.Traffic) string { return tr.Request }),
				trafficCell(r.Traffic, func(tr store.Traffic) string { return tr.Response }),
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// manualMark 人工修正标记（CSV 列 / MD 表格用）。
func manualMark(manualAt string) string {
	if manualAt != "" {
		return "yes"
	}
	return ""
}

// trafficCell 将任务的多条流量事件按 seq 保序拼接为单元格文本，
// 事件间以分隔行隔开（多请求模板/攻击链还原）。
func trafficCell(events []store.Traffic, pick func(store.Traffic) string) string {
	var sb strings.Builder
	for _, e := range events {
		s := pick(e)
		if s == "" {
			continue
		}
		if sb.Len() > 0 {
			sb.WriteString("\n----------\n")
		}
		sb.WriteString(s)
	}
	return sb.String()
}

const mdTemplate = `# gobas 扫描报告 #{{.Scan.ID}}

- **名称**: {{.Scan.Name}}
- **状态**: {{.Scan.Status}}
- **开始**: {{.Scan.StartedAt}} / **结束**: {{.Scan.FinishedAt}}
- **规模**: {{.Scan.POCCount}} POC × {{.Scan.TargetCount}} 目标 = {{.Scan.TotalTasks}} 任务
- **报告生成**: {{.GeneratedAt.Format "2006-01-02 15:04:05"}}

## 判定汇总

| 判定 | 含义 | 数量 |
|---|---|---|
{{- range $v := .VerdictList }}
| {{$v.Name}} | {{$v.Desc}} | {{$v.Count}} |
{{- end }}

{{- if .Targets}}

## 目标矩阵

{{- range $t := .Targets}}

### {{$t.URL}}{{if $t.Name}}（{{$t.Name}}）{{end}}

| POC | 严重度 | 判定 | 状态码 | 错误 |
|---|---|---|---|---|
{{- range $r := $t.Results}}
| {{$r.TemplateID}} | {{$r.Severity}} | **{{$r.Verdict}}**{{if $r.ManualAt}} ✎人工{{if $r.AutoVerdict}}（自动：{{$r.AutoVerdict}}）{{end}}{{end}} | {{$r.ResponseStatus}} | {{truncate $r.ErrorText 80}} |
{{- end}}
{{- range $r := $t.Results}}
{{- if $r.Traffic}}

#### 流量明细：{{$r.TemplateID}}（{{$r.Verdict}}）
{{- range $tr := $r.Traffic}}

**事件 seq={{$tr.Seq}}**（协议 {{$tr.Protocol}}，状态码 {{$tr.Status}}{{if $tr.Matched}}，命中匹配{{end}}）
{{- if $tr.Request}}

请求包{{if $tr.ReqTruncated}}（已截断）{{end}}：

{{indent $tr.Request}}
{{- end}}
{{- if $tr.Response}}

响应包{{if $tr.RespTruncated}}（已截断）{{end}}：

{{indent $tr.Response}}
{{- end}}
{{- end}}
{{- end}}
{{- end}}
{{- end}}
{{- end}}
`

type mdVerdict struct {
	Name, Desc string
	Count      int
}

// Truncate 辅助模板函数。
func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func exportMarkdown(m *Model, w io.Writer) error {
	desc := map[string]string{
		"HIT":         "漏洞命中",
		"BLOCKED":     "被防御设备拦截",
		"TIMEOUT":     "攻击超时（疑似丢包）",
		"UNREACHABLE": "目标不可达",
		"MISS":        "未命中",
		"ERROR":       "执行错误",
	}
	data := struct {
		*Model
		VerdictList []mdVerdict
	}{Model: m}
	for _, v := range VerdictOrder {
		data.VerdictList = append(data.VerdictList, mdVerdict{Name: v, Desc: desc[v], Count: m.Counts[v]})
	}
	tpl := template.Must(template.New("report").
		Funcs(template.FuncMap{"truncate": truncateStr, "indent": indentCode}).
		Parse(mdTemplate))
	return tpl.Execute(w, data)
}

// indentCode 将报文每行缩进 4 空格形成 Markdown 缩进式代码块；
// 缩进式而非围栏代码块，避免报文内容中的反引号破坏渲染。
func indentCode(s string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = "    " + l
	}
	return strings.Join(lines, "\n")
}
