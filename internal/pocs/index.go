package pocs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gobas/internal/engine"
	"gobas/internal/source"
	"gobas/internal/store"
)

// IndexStats 索引统计。
type IndexStats struct {
	Repos          int `json:"repos"`
	Files          int `json:"files"`
	Indexed        int `json:"indexed"`
	Duplicates     int `json:"duplicates"`
	Invalid        int `json:"invalid"`           // 解析失败/静态不可执行（headless、纯code、OOB回连等）
	EngineRejected int `json:"engine_rejected"`   // 静态通过但引擎真实加载失败（编译错误/签名门控/能力门控）
}

// IndexProgress 索引进度（逐文件/逐批回调）。
type IndexProgress struct {
	Done  int    // 已完成数（解析阶段=文件数，验证阶段=已验证文件数）
	Total int    // 总数（解析阶段=文件总数，验证阶段=候选文件总数）
	Repo  string // 当前文件所属仓库（owner/repo 或 local），验证阶段为"引擎加载验证"
}

// Index 重建 POC 索引：清空后重新解析入库。
// 官方源先入库建立 content_hash 基准，社区源相同内容自动被 UNIQUE 约束去重，
// 等价于"官方基准增量"策略（比同名同大小判断更严谨）。
// cloneDir 为源仓库克隆根目录；extraDirs 为额外的本地模板目录（如 testdata）。
// onProgress 在每个文件解析/每批验证完成后回调（可传 nil）。
//
// 三阶段执行（分类彻底前置，入库即引擎可执行）：
//  1. 目录遍历收集全部模板文件（快）；
//  2. 逐文件解析 + 静态预过滤（headless/自包含/OOB回连/凭证/纯code/缺解释器，
//     快速排除明显不可执行模板；code 模板先本地重签，与扫描时一致）；
//  3. 引擎真实加载验证（与扫描加载管线完全一致）：编译错误、签名门控、能力门控
//     等导致的加载失败模板不入库，保证入库模板扫描时 100% 可加载、可获取流量。
func Index(ctx context.Context, st *store.Store, cloneDir string, extraDirs []string, onProgress func(IndexProgress)) (*IndexStats, error) {
	if err := st.DeleteAllPOCs(); err != nil {
		return nil, fmt.Errorf("clear pocs: %w", err)
	}
	stats := &IndexStats{}

	type fileItem struct {
		path     string
		repoKey  string
		official bool
	}
	var files []fileItem

	// 阶段一：收集（目录遍历，秒级）
	type repoInfo struct {
		key      string
		dir      string
		official bool
	}
	var repos []repoInfo
	if entries, err := os.ReadDir(cloneDir); err == nil {
		for _, owner := range entries {
			if !owner.IsDir() {
				continue
			}
			repoDirs, err := os.ReadDir(filepath.Join(cloneDir, owner.Name()))
			if err != nil {
				continue
			}
			for _, rd := range repoDirs {
				if !rd.IsDir() {
					continue
				}
				key := strings.ToLower(owner.Name() + "/" + rd.Name())
				repos = append(repos, repoInfo{
					key:      key,
					dir:      filepath.Join(cloneDir, owner.Name(), rd.Name()),
					official: key == source.OfficialRepo,
				})
			}
		}
	}
	// 官方源优先（保证去重基准先入库）
	sort.SliceStable(repos, func(i, j int) bool { return repos[i].official && !repos[j].official })
	for _, r := range repos {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		fs, err := Discover(r.dir)
		if err != nil {
			continue
		}
		stats.Repos++
		for _, f := range fs {
			files = append(files, fileItem{path: f, repoKey: r.key, official: r.official})
		}
	}
	for _, d := range extraDirs {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		fs, err := Discover(d)
		if err != nil {
			continue
		}
		if len(fs) > 0 {
			stats.Repos++
			for _, f := range fs {
				files = append(files, fileItem{path: f, repoKey: "local"})
			}
		}
	}
	stats.Files = len(files)

	// 阶段二：逐文件解析 + 静态预过滤（快，逐文件回调进度）
	type candidate struct {
		meta     *POCMeta
		repoKey  string
		official bool
	}
	candidates := make([]candidate, 0, len(files))
	seenIDs := make(map[string]bool, len(files)) // 同 ID 先到先得（与 InsertPOC 规则一致）
	for i, f := range files {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		meta, err := ParseTemplateFile(f.path)
		if err != nil {
			stats.Invalid++
			continue
		}
		if !canExecute(meta) {
			stats.Invalid++
			continue
		}
		if seenIDs[meta.TemplateID] {
			stats.Duplicates++
			continue
		}
		seenIDs[meta.TemplateID] = true
		// code 协议模板本地重签（与扫描时一致，幂等）：未签名 code 模板会被
		// 引擎签名门控拒绝。重签后重新解析刷新 content_hash/Verified。
		if hasCodeProtocol(meta.Protocols) {
			if ls := engine.Instance(); ls != nil {
				if err := ls.SignFile(f.path); err == nil {
					if m, err := ParseTemplateFile(f.path); err == nil {
						meta = m
					}
				}
			}
		}
		candidates = append(candidates, candidate{meta: meta, repoKey: f.repoKey, official: f.official})
		if onProgress != nil {
			onProgress(IndexProgress{Done: i + 1, Total: len(files), Repo: f.repoKey})
		}
	}

	// 阶段三：引擎真实加载验证（与扫描加载管线完全一致）。
	// 静态检查无法覆盖的拒绝条件（编译错误、签名门控、能力门控等）在此暴露，
	// 未加载成功的模板不入库——入库模板扫描时 100% 可执行。
	paths := make([]string, 0, len(candidates))
	for _, c := range candidates {
		paths = append(paths, c.meta.FilePath)
	}
	loaded, err := engine.ValidateTemplates(ctx, paths, func(done, total int) {
		if onProgress != nil {
			onProgress(IndexProgress{Done: done, Total: total, Repo: "引擎加载验证"})
		}
	})
	if err != nil {
		return stats, fmt.Errorf("engine validate templates: %w", err)
	}
	for _, c := range candidates {
		if !loaded[c.meta.TemplateID] {
			stats.EngineRejected++
			continue
		}
		insertPOC(st, c.meta, c.repoKey, c.official, stats)
	}
	return stats, nil
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

// insertPOC 解析元数据入库并累计统计。
func insertPOC(st *store.Store, meta *POCMeta, repoKey string, official bool, stats *IndexStats) {
	protoJSON, _ := json.Marshal(meta.Protocols)
	selfContained := 0
	if meta.SelfContained {
		selfContained = 1
	}
	p := &store.POC{
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
		FilePath:      meta.FilePath,
		ContentHash:   meta.ContentHash,
		FileSize:      meta.FileSize,
		SourceRepo:    repoKey,
		IsOfficial:    official,
	}
	if _, inserted, err := st.InsertPOC(p); err != nil {
		stats.Invalid++
	} else if inserted {
		stats.Indexed++
	} else {
		stats.Duplicates++
	}
}
