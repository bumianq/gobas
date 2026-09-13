package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
)

// validateBatchSize 引擎验证分批大小（控制单引擎内存占用）。
const validateBatchSize = 2000

// ValidateTemplates 用与扫描（engine.Run）完全一致的加载管线真实编译验证模板，
// 返回引擎实际加载成功的模板 ID 集合。
//
// 这是索引期"分类前置"的核心：静态 YAML 检查无法覆盖 nuclei 加载期的全部拒绝条件——
//   - 模板编译错误（正则/DSL/结构/payload 文件引用缺失等）
//   - 未签名 code / javascript 协议模板（引擎无条件拒绝）
//   - 能力门控（headless/DAST/file 等未启用的能力）
// 只有真实加载通过的模板才能保证扫描时不出现"入库时可执行、引用时报错"。
//
// 调用方须先对 code 协议模板完成本地重签（与扫描时一致），
// 否则未签名的 code 模板会被签名门控拒绝（误杀）。
// onProgress 在每批验证完成后回调（done/total 为文件数）。
func ValidateTemplates(ctx context.Context, paths []string, onProgress func(done, total int)) (map[string]bool, error) {
	loaded := make(map[string]bool, len(paths))
	total := len(paths)
	for start := 0; start < total; start += validateBatchSize {
		if err := ctx.Err(); err != nil {
			return loaded, err
		}
		end := start + validateBatchSize
		if end > total {
			end = total
		}
		batch := paths[start:end]
		ids, err := validateBatch(ctx, batch)
		if err != nil {
			return loaded, fmt.Errorf("validate batch [%d:%d]: %w", start, end, err)
		}
		for id := range ids {
			loaded[id] = true
		}
		if onProgress != nil {
			onProgress(end, total)
		}
	}
	return loaded, nil
}

// validateBatch 创建一次性引擎加载一批模板，返回实际加载成功的模板 ID。
// 引擎选项与 engine.Run 保持一致（sandbox/code/self-contained/interactsh 禁用/
// 协议过滤），确保验证结果即扫描时的加载行为。
func validateBatch(ctx context.Context, paths []string) (map[string]bool, error) {
	opts := []nuclei.NucleiSDKOptions{
		nuclei.WithSandboxOptions(true, false),
		nuclei.EnableCodeTemplates(),
		nuclei.EnableSelfContainedTemplates(),
		nuclei.EnableGlobalMatchersTemplates(),
		// BAS 场景关闭 OOB 回连（零值会触发 interactsh 内部 gcache panic）
		nuclei.WithInteractshOptions(nuclei.InteractshOpts{
			NoInteractsh:   true,
			CacheSize:      5000,
			Eviction:       time.Minute,
			CooldownPeriod: 5 * time.Second,
			PollDuration:    5 * time.Second,
		}),
		nuclei.DisableUpdateCheck(),
		nuclei.WithVerbosity(nuclei.VerbosityOptions{Silent: true}),
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: paths}),
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{ProtocolTypes: "http,websocket,code,tcp"}),
	}
	// 无目标加载：只验证模板编译与门控，不发任何请求
	ne, err := nuclei.NewNucleiEngineCtx(ctx, opts...)
	if err != nil {
		return nil, err
	}
	defer ne.Close()

	if err := ne.LoadAllTemplates(); err != nil {
		// "No templates available"：整批全被门控过滤（编译失败/签名拒绝），
		// 属正常情况，本批 0 个可加载；其余错误向上传递
		if strings.Contains(err.Error(), "No templates available") {
			return nil, nil
		}
		return nil, err
	}
	ids := make(map[string]bool)
	for _, t := range ne.GetTemplates() {
		if t != nil {
			ids[t.ID] = true
		}
	}
	for _, t := range ne.GetWorkflows() {
		if t != nil {
			ids[t.ID] = true
		}
	}
	return ids, nil
}
