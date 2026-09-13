// Package service 人工自定义 POC：独立于自动拉取源，添加/修改/删除。
// 模板文件存于 workspace/custom-pocs/（git 同步与重建索引不触碰），
// 入库走与索引完全一致的准入管线（静态预检 + code 重签 + 引擎真实加载验证）。
package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gobas/internal/engine"
	"gobas/internal/pocs"
	"gobas/internal/store"
)

// 人工 POC 操作错误（handlers 映射 HTTP 状态码用）。
var (
	ErrPOCNotFound     = errors.New("POC 不存在")
	ErrNotCustomPOC    = errors.New("仅人工添加的 POC 支持此操作")
	ErrTemplateIDTaken = errors.New("模板 ID 已存在（自动拉取或人工添加的 POC 中有同 ID 模板）")
)

// templateIDRe 合法模板 ID：字母数字开头，仅含字母数字/下划线/点/横线（防路径穿越）。
var templateIDRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

// AddCustomPOC 人工添加 POC：校验 → 落盘 → 引擎验证 → 入库（is_custom=1）。
func (s *Service) AddCustomPOC(ctx context.Context, content string) (*store.POC, error) {
	meta, path, err := s.validateCustom(ctx, content, 0)
	if err != nil {
		return nil, err
	}
	p := customPOCFromMeta(meta, path)
	id, inserted, err := s.store.InsertPOC(p)
	if err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("insert custom poc: %w", err)
	}
	if !inserted { // 并发窗口内被同 ID 模板抢占（罕见），放弃本次添加
		_ = os.Remove(path)
		return nil, ErrTemplateIDTaken
	}
	out, err := s.store.GetPOC(id)
	if err != nil || out == nil {
		return nil, ErrPOCNotFound
	}
	return out, nil
}

// UpdateCustomPOC 修改人工 POC：重新校验验证后覆盖文件并回写元数据。
// 允许修改模板 ID（改 ID 时旧文件同步清理）。
func (s *Service) UpdateCustomPOC(ctx context.Context, id int64, content string) (*store.POC, error) {
	old, err := s.store.GetPOC(id)
	if err != nil {
		return nil, err
	}
	if old == nil {
		return nil, ErrPOCNotFound
	}
	if !old.IsCustom {
		return nil, ErrNotCustomPOC
	}
	// 备份旧文件内容（validateCustom 覆盖写后 DB 回写失败的还原用）
	var oldData []byte
	if data, err := os.ReadFile(s.store.AbsPath(old.FilePath)); err == nil {
		oldData = data
	}
	meta, path, err := s.validateCustom(ctx, content, id)
	if err != nil {
		return nil, err
	}
	p := customPOCFromMeta(meta, path)
	p.ID = id
	if err := s.store.UpdateCustomPOC(p); err != nil {
		// 文件回滚：同 ID 覆盖场景还原旧内容，改 ID 场景删除新文件（旧文件未动）
		if s.store.AbsPath(old.FilePath) == path && oldData != nil {
			_ = os.WriteFile(path, oldData, 0o644)
		} else if s.store.AbsPath(old.FilePath) != path {
			_ = os.Remove(path)
		}
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrPOCNotFound
		}
		return nil, fmt.Errorf("update custom poc: %w", err)
	}
	// 模板 ID 变更时清理旧文件（同 ID 覆盖写无需处理）
	if s.store.AbsPath(old.FilePath) != path {
		_ = os.Remove(s.store.AbsPath(old.FilePath))
	}
	out, err := s.store.GetPOC(id)
	if err != nil || out == nil {
		return nil, ErrPOCNotFound
	}
	return out, nil
}

// DeleteCustomPOC 删除人工 POC（DB 行 + 模板文件；自动拉取行拒绝）。
// poc_set_items 级联清理；历史扫描结果不级联，保留。
func (s *Service) DeleteCustomPOC(id int64) error {
	p, err := s.store.GetPOC(id)
	if err != nil {
		return err
	}
	if p == nil {
		return ErrPOCNotFound
	}
	if !p.IsCustom {
		return ErrNotCustomPOC
	}
	if err := s.store.DeleteCustomPOC(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPOCNotFound
		}
		return err
	}
	_ = os.Remove(s.store.AbsPath(p.FilePath)) // 文件缺失不视为失败（DB 已删）
	return nil
}

// GetPOCContent 读取人工 POC 模板 YAML 原文（编辑回显用）。
// 同时供自动拉取 POC 的详情展示（file_path 为相对 baseDir 路径，读前还原）。
func (s *Service) GetPOCContent(id int64) (string, error) {
	p, err := s.store.GetPOC(id)
	if err != nil {
		return "", err
	}
	if p == nil {
		return "", ErrPOCNotFound
	}
	data, err := os.ReadFile(s.store.AbsPath(p.FilePath))
	if err != nil {
		return "", fmt.Errorf("read template file: %w", err)
	}
	return string(data), nil
}

// validateCustom 人工模板统一校验管线（与索引三阶段一致）：
// 解析 → ID 格式/查重 → 静态预检 → 落盘 custom-pocs/ → code 重签 → 引擎真实加载验证。
// excludeID>0 时查重排除该行（修改自身场景）。
// 返回最终元数据（重签后重新解析）与落盘路径。
// 失败回滚：目标文件原有内容还原（修改覆盖场景），新文件则删除。
func (s *Service) validateCustom(ctx context.Context, content string, excludeID int64) (*pocs.POCMeta, string, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil, "", errors.New("模板内容为空")
	}
	meta, err := pocs.ParseTemplate("custom", []byte(content))
	if err != nil {
		return nil, "", fmt.Errorf("模板解析失败: %w", err)
	}
	if !templateIDRe.MatchString(meta.TemplateID) {
		return nil, "", fmt.Errorf("模板 ID %q 不合法（需字母数字开头，仅含字母数字/下划线/点/横线）", meta.TemplateID)
	}
	// 库内同 ID 查重（自动拉取 + 人工添加）
	existID, found, err := s.store.POCIDByTemplateID(meta.TemplateID)
	if err != nil {
		return nil, "", fmt.Errorf("query poc by template_id: %w", err)
	}
	if found && existID != excludeID {
		return nil, "", ErrTemplateIDTaken
	}
	// 静态预检（与索引同规则：headless/自包含/OOB/凭证依赖/纯code/缺解释器）
	if !pocs.CanExecute(meta) {
		return nil, "", errors.New(rejectReason(meta))
	}
	// 落盘（code 模板重签与引擎验证均需真实文件）
	if err := os.MkdirAll(s.cfg.CustomPOCDir(), 0o755); err != nil {
		return nil, "", fmt.Errorf("create custom poc dir: %w", err)
	}
	path := filepath.Join(s.cfg.CustomPOCDir(), meta.TemplateID+".yaml")
	// 备份目标文件已有内容（修改同 ID 模板覆盖写场景，失败时还原，避免误删可用模板）
	var backup []byte
	if data, err := os.ReadFile(path); err == nil {
		backup = data
	}
	rollback := func() {
		if backup != nil {
			_ = os.WriteFile(path, backup, 0o644)
		} else {
			_ = os.Remove(path)
		}
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return nil, "", fmt.Errorf("write template file: %w", err)
	}
	// code 协议模板本地重签后重新落盘、重新解析（刷新 content_hash/Verified）。
	// 用 SignTemplate（去除旧签名后重签）而非 SignFile：编辑已签名模板时
	// 旧签名对新内容失效，且 SignFile 检测到本地签名标记会跳过重签，
	// 导致签名与内容不匹配、引擎验证必然失败。
	if hasCodeProtocol(meta.Protocols) {
		if ls := engine.Instance(); ls != nil {
			if signed, err := ls.SignTemplate([]byte(content)); err == nil {
				if err := os.WriteFile(path, signed, 0o644); err == nil {
					if m, err := pocs.ParseTemplateFile(path); err == nil {
						meta = m
					}
				}
			}
		}
	}
	// 引擎真实加载验证（与扫描加载管线一致，失败不入库）
	loaded, err := engine.ValidateTemplates(ctx, []string{path}, nil)
	if err != nil {
		rollback()
		return nil, "", fmt.Errorf("引擎验证失败: %w", err)
	}
	if !loaded[meta.TemplateID] {
		rollback()
		return nil, "", errors.New("引擎无法加载该模板（编译错误/签名门控/能力门控），请检查模板语法")
	}
	return meta, path, nil
}

// customPOCFromMeta 元数据转 store 行（is_custom=1，来源标记 custom）。
func customPOCFromMeta(meta *pocs.POCMeta, path string) *store.POC {
	protoJSON, _ := json.Marshal(meta.Protocols)
	selfContained := 0
	if meta.SelfContained {
		selfContained = 1
	}
	return &store.POC{
		TemplateID:    meta.TemplateID,
		Name:          meta.Name,
		Authors:       strings.Join(meta.Authors, ","),
		Severity:      meta.Severity,
		Tags:          "," + strings.ToLower(strings.Join(meta.Tags, ",")) + ",",
		CVEIDs:        strings.Join(meta.CVEIDs, ","),
		CNVDIDs:       strings.Join(meta.CNVDIDs, ","),
		CWEIDs:        strings.Join(meta.CWEIDs, ","),
		CVSSScore:     meta.CVSSScore,
		Protocols:     string(protoJSON),
		HasInteractsh: meta.HasInteractsh,
		SelfContained: selfContained,
		Verified:      meta.Verified,
		CodeEngines:   meta.CodeEngines,
		FilePath:      path,
		ContentHash:   meta.ContentHash,
		FileSize:      meta.FileSize,
		SourceRepo:    "custom",
		IsCustom:      true,
	}
}

// hasCodeProtocol 判断协议集合是否含 code。
func hasCodeProtocol(protocols []string) bool {
	for _, p := range protocols {
		if p == "code" {
			return true
		}
	}
	return false
}

// rejectReason 静态预检失败原因（与 canExecute 检查项一一对应，提示用户修改方向）。
func rejectReason(meta *pocs.POCMeta) string {
	switch {
	case meta.SelfContained:
		return "模板不可执行：自包含模板（self-contained，不对扫描目标发请求）"
	case meta.IsDAST:
		return "模板不可执行：DAST（fuzzing）模板，需专用引擎支持"
	case meta.HasInteractsh:
		return "模板不可执行：依赖 OOB 回连（{{interactsh_url}}），引擎已禁用 interactsh，恒定失败"
	case meta.NeedsCredentials:
		return "模板不可执行：需运行时凭证输入（{{username}}/{{password}} 等），无输入时不产生有效请求"
	}
	hasSupported := false
	for _, p := range meta.Protocols {
		switch p {
		case "http", "websocket", "code", "network":
			hasSupported = true
		case "headless":
			return "模板不可执行：headless 协议需浏览器环境"
		}
	}
	if !hasSupported {
		return "模板不可执行：顶层协议需包含 http/websocket/code/network 之一（纯 dns/file/whois 等不支持）"
	}
	for _, p := range meta.Protocols {
		if p == "code" {
			hasNet := false
			for _, q := range meta.Protocols {
				if q == "http" || q == "network" || q == "websocket" {
					hasNet = true
					break
				}
			}
			if !hasNet {
				return "模板不可执行：纯 code 脚本模板（本地子进程发请求，无流量数据），需混合 http/network/websocket 协议"
			}
			if meta.CodeEngines != "" {
				for _, e := range strings.Split(meta.CodeEngines, ",") {
					if e = strings.TrimSpace(e); e != "" {
						return fmt.Sprintf("模板不可执行：本机缺少 code 引擎 %q（模板声明: %s）", e, meta.CodeEngines)
					}
				}
			}
		}
	}
	return "模板不可执行"
}
