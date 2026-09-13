// Package service 装配层：编排 source/pocs/store/target/engine/verdict/report，
// 是 CLI 与 REST API（及未来 Web UI）的唯一入口。
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gobas/internal/config"
	"gobas/internal/engine"
	"gobas/internal/pocs"
	"gobas/internal/report"
	"gobas/internal/source"
	"gobas/internal/store"
	"gobas/internal/target"
)

// ErrSyncBusy 已有同步/索引任务在运行（API 返回 409）。
var ErrSyncBusy = errors.New("同步或索引任务已在进行中，请等待完成后再试")

// Service 应用服务。
type Service struct {
	cfg   *config.Config
	store *store.Store
	bus   *eventBus

	// initialAdminPwd 首次运行生成的 admin 初始密码槽位（serve 首启横幅用，
	// 非首启为空；密码仅在进程内短暂保留，不落库）。
	initialAdminPwd string

	scanMu      sync.Mutex // 串行化扫描（v1 同时只允许一个 scan 运行）
	runningScan *runningScan

	syncMu sync.Mutex // 串行化源同步与索引（均操作 clone 目录 / pocs 表）
	syncSt syncState  // 同步进度状态（SSE 轮询用）
	idxSt  indexState // 索引进度状态（SSE 轮询用）
}

type runningScan struct {
	id     int64
	cancel context.CancelFunc
	done   chan struct{}
}

// New 构建服务：打开数据库、恢复遗留扫描状态、初始化本地签名器。
func New(cfg *config.Config) (*Service, error) {
	if err := cfg.EnsureDirs(); err != nil {
		return nil, fmt.Errorf("create workspace: %w", err)
	}
	// 初始化本地签名器：生成/加载密钥对，注册到 nuclei 验证器链，
	// 使未官方签名的 code 模板经本地重签后可加载执行。
	if err := engine.Init(cfg.Workspace); err != nil {
		return nil, fmt.Errorf("init local signer: %w", err)
	}
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	if err := st.FailOrphanedScans(); err != nil {
		st.Close()
		return nil, fmt.Errorf("recover orphaned scans: %w", err)
	}
	svc := &Service{cfg: cfg, store: st, bus: newEventBus()}
	// 首启建号：users 表为空时创建 admin + 随机初始密码（仅控制台可见）
	if _, _, err := svc.EnsureFirstRunAdmin(); err != nil {
		return nil, fmt.Errorf("init auth: %w", err)
	}
	return svc, nil
}

// Close 释放资源。
func (s *Service) Close() error { return s.store.Close() }

// SyncStatus 同步状态快照（SSE 轮询用）。
type SyncStatus struct {
	Running   bool                `json:"running"`
	Finished  bool                `json:"finished"` // 本次同步已结束（含失败）
	Done      int                 `json:"done"`
	Total     int                 `json:"total"`
	Results   []source.SyncResult `json:"results"` // 已完成结果（完成序）
	ErrText   string              `json:"err_text,omitempty"`
	StartedAt time.Time           `json:"started_at"`
}

// syncState 同步进度（Sync 写、SyncStatus 读，mu 保护）。
type syncState struct {
	mu        sync.Mutex
	running   bool
	finished  bool
	done      int
	total     int
	results   []source.SyncResult
	errText   string
	startedAt time.Time
}

func (st *syncState) reset(total int) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.running, st.finished = true, false
	st.done, st.total = 0, total
	st.results = nil
	st.errText = ""
	st.startedAt = time.Now()
}

func (st *syncState) record(r source.SyncResult) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.done++
	st.results = append(st.results, r)
}

func (st *syncState) finish(errText string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.running, st.finished = false, true
	st.errText = errText
}

// snapshot 深拷贝结果切片，避免调用方与写入方竞争。
func (st *syncState) snapshot() SyncStatus {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := SyncStatus{
		Running: st.running, Finished: st.finished,
		Done: st.done, Total: st.total,
		ErrText: st.errText, StartedAt: st.startedAt,
	}
	if len(st.results) > 0 {
		out.Results = append([]source.SyncResult(nil), st.results...)
	}
	return out
}

// Sync 同步 POC 源仓库（CLI 用：阻塞至完成）。
// proxyOverride 为代理覆盖：nil 用配置值；非 nil 用该值（空字符串 = 本次直连）。
// 进度同时写入内部状态（供 SSE 轮询）。
func (s *Service) Sync(ctx context.Context, importCSV string, workers int, proxyOverride *string) ([]source.SyncResult, error) {
	// 全局单飞：同一 clone 目录并发 clone/fetch 会触发 git 锁冲突
	if !s.syncMu.TryLock() {
		return nil, ErrSyncBusy
	}
	defer s.syncMu.Unlock()
	return s.syncLocked(ctx, importCSV, workers, proxyOverride)
}

// StartSyncAsync 后台启动同步（REST 用：立即返回，进度经 SyncStatusNow 轮询）。
func (s *Service) StartSyncAsync(importCSV string, workers int, proxyOverride *string) error {
	if !s.syncMu.TryLock() {
		return ErrSyncBusy
	}
	go func() {
		defer s.syncMu.Unlock()
		if _, err := s.syncLocked(context.Background(), importCSV, workers, proxyOverride); err != nil {
			slog.Error("sync failed", "err", err)
		}
	}()
	return nil
}

// syncLocked 同步主体（调用方必须已持有 syncMu）。
func (s *Service) syncLocked(ctx context.Context, importCSV string, workers int, proxyOverride *string) ([]source.SyncResult, error) {
	srcs, err := source.LoadSources(s.cfg.SourcesPath())
	if err != nil && !os.IsNotExist(err) {
		s.syncSt.finish(err.Error())
		return nil, fmt.Errorf("load sources: %w", err)
	}
	if importCSV != "" {
		imported, err := source.ImportCSV(importCSV)
		if err != nil {
			s.syncSt.finish(err.Error())
			return nil, fmt.Errorf("import csv: %w", err)
		}
		srcs = source.MergeSources(srcs, imported)
		if err := source.SaveSources(s.cfg.SourcesPath(), srcs); err != nil {
			s.syncSt.finish(err.Error())
			return nil, fmt.Errorf("save sources: %w", err)
		}
		slog.Info("sources merged", "total", len(srcs))
	}
	if len(srcs) == 0 {
		err := fmt.Errorf("no sources configured: use --import-csv <repo.csv> or create %s", s.cfg.SourcesPath())
		s.syncSt.finish(err.Error())
		return nil, err
	}
	proxy := s.cfg.Network.Proxy
	if proxyOverride != nil {
		proxy = *proxyOverride
	}
	mgr := &source.Manager{
		CloneDir: s.cfg.CloneDir(),
		Workers:  workers,
		Proxy:    proxy,
	}
	s.syncSt.reset(len(srcs))
	slog.Info("sync started", "total", len(srcs), "workers", workers, "proxy", proxy)
	results := mgr.Sync(ctx, srcs, func(_, _ int, r source.SyncResult) {
		s.syncSt.record(r)
	})
	s.syncSt.finish("")
	slog.Info("sync finished", "total", len(results))
	return results, nil
}

// SyncStatusNow 返回当前同步状态快照。
func (s *Service) SyncStatusNow() SyncStatus { return s.syncSt.snapshot() }

// ProxyConfig 返回当前配置的代理地址（供 GUI 展示，空 = 直连）。
func (s *Service) ProxyConfig() string { return s.cfg.Network.Proxy }

// IndexStatus 索引状态快照（SSE 轮询用）。
type IndexStatus struct {
	Running     bool             `json:"running"`
	Finished    bool             `json:"finished"`
	Done        int              `json:"done"`
	Total       int              `json:"total"`
	CurrentRepo string           `json:"current_repo,omitempty"`
	Stats       *pocs.IndexStats `json:"stats,omitempty"` // 完成后填充
	ErrText     string           `json:"err_text,omitempty"`
	StartedAt   time.Time        `json:"started_at"`
}

// indexState 索引进度（写读各一，mu 保护）。
type indexState struct {
	mu          sync.Mutex
	running     bool
	finished    bool
	done        int
	total       int
	currentRepo string
	stats       *pocs.IndexStats
	errText     string
	startedAt   time.Time
}

func (st *indexState) reset() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.running, st.finished = true, false
	st.done, st.total = 0, 0
	st.currentRepo, st.stats, st.errText = "", nil, ""
	st.startedAt = time.Now()
}

func (st *indexState) record(p pocs.IndexProgress) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.done, st.total, st.currentRepo = p.Done, p.Total, p.Repo
}

func (st *indexState) finish(stats *pocs.IndexStats, errText string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.running, st.finished = false, true
	st.stats, st.errText = stats, errText
}

func (st *indexState) snapshot() IndexStatus {
	st.mu.Lock()
	defer st.mu.Unlock()
	return IndexStatus{
		Running: st.running, Finished: st.finished,
		Done: st.done, Total: st.total, CurrentRepo: st.currentRepo,
		Stats: st.stats, ErrText: st.errText, StartedAt: st.startedAt,
	}
}

// Index 重建 POC 索引（CLI 用：阻塞至完成）。
// extraDirs 为额外本地模板目录（相对路径会转为绝对）。
func (s *Service) Index(ctx context.Context, extraDirs []string) (*pocs.IndexStats, error) {
	// 与源同步共用互斥：索引会清空 pocs 表，与同步/并发索引冲突
	if !s.syncMu.TryLock() {
		return nil, ErrSyncBusy
	}
	defer s.syncMu.Unlock()
	return s.indexLocked(ctx, extraDirs)
}

// StartIndexAsync 后台启动索引重建（REST 用：立即返回，进度经 IndexStatusNow 轮询）。
func (s *Service) StartIndexAsync(extraDirs []string) error {
	if !s.syncMu.TryLock() {
		return ErrSyncBusy
	}
	go func() {
		defer s.syncMu.Unlock()
		if _, err := s.indexLocked(context.Background(), extraDirs); err != nil {
			slog.Error("index failed", "err", err)
		}
	}()
	return nil
}

// indexLocked 索引主体（调用方必须已持有 syncMu）。
func (s *Service) indexLocked(ctx context.Context, extraDirs []string) (*pocs.IndexStats, error) {
	abs := make([]string, 0, len(extraDirs))
	for _, d := range extraDirs {
		a, err := filepath.Abs(d)
		if err != nil {
			s.idxSt.finish(nil, err.Error())
			return nil, fmt.Errorf("abs path %s: %w", d, err)
		}
		abs = append(abs, a)
	}
	s.idxSt.reset()
	slog.Info("poc index started")
	stats, err := pocs.Index(ctx, s.store, s.cfg.CloneDir(), abs, func(p pocs.IndexProgress) {
		s.idxSt.record(p)
	})
	if err != nil {
		s.idxSt.finish(stats, err.Error())
		return stats, err
	}
	s.idxSt.finish(stats, "")
	slog.Info("poc index rebuilt",
		"repos", stats.Repos, "files", stats.Files,
		"indexed", stats.Indexed, "duplicates", stats.Duplicates, "invalid", stats.Invalid)
	return stats, nil
}

// IndexStatusNow 返回当前索引状态快照。
func (s *Service) IndexStatusNow() IndexStatus { return s.idxSt.snapshot() }

// QueryPOCs 查询 POC。
func (s *Service) QueryPOCs(ctx context.Context, f store.POCFilter) ([]store.POC, error) {
	return s.store.ListPOCs(f)
}

// CountPOCs 按过滤器统计 POC 数量（GUI 分页 / 扫描预览）。
func (s *Service) CountPOCs(ctx context.Context, f store.POCFilter) (int, error) {
	return s.store.CountPOCs(f)
}

// POCStats POC 库统计。
func (s *Service) POCStats(ctx context.Context) (*store.POCStats, error) {
	return s.store.POCStats()
}

// ---- POC 模板集 ----

// ListPOCSets 全部模板集。
func (s *Service) ListPOCSets() ([]store.POCSet, error) { return s.store.ListPOCSets() }

// CreatePOCSet 创建模板集并可选批量加入 POC。
func (s *Service) CreatePOCSet(name, description string, pocIDs []int64) (*store.POCSet, error) {
	id, err := s.store.CreatePOCSet(name, description)
	if err != nil {
		return nil, err
	}
	if len(pocIDs) > 0 {
		if _, err := s.store.AddPOCsToSet(id, pocIDs); err != nil {
			return nil, err
		}
	}
	return s.store.GetPOCSet(id)
}

// GetPOCSet 模板集详情。
func (s *Service) GetPOCSet(id int64) (*store.POCSet, error) { return s.store.GetPOCSet(id) }

// UpdatePOCSet 改名/描述。
func (s *Service) UpdatePOCSet(id int64, name, description string) error {
	return s.store.UpdatePOCSet(id, name, description)
}

// DeletePOCSet 删除模板集。
func (s *Service) DeletePOCSet(id int64) error { return s.store.DeletePOCSet(id) }

// AddPOCsToSet 批量加入（幂等）。
func (s *Service) AddPOCsToSet(setID int64, pocIDs []int64) (int, error) {
	return s.store.AddPOCsToSet(setID, pocIDs)
}

// RemovePOCsFromSet 批量移除（空列表=清空）。
func (s *Service) RemovePOCsFromSet(setID int64, pocIDs []int64) (int, error) {
	return s.store.RemovePOCsFromSet(setID, pocIDs)
}

// ListPOCsInSet 集内 POC 列表。
func (s *Service) ListPOCsInSet(setID int64) ([]store.POC, error) {
	return s.store.ListPOCsInSet(setID)
}

// AddTarget 新增目标并立即探活。
func (s *Service) AddTarget(ctx context.Context, rawURL, name string) (*store.Target, error) {
	url, err := target.NormalizeURL(rawURL)
	if err != nil {
		return nil, err
	}
	t, err := s.store.UpsertTarget(url, name)
	if err != nil {
		return nil, err
	}
	b := s.prober().Probe(ctx, url)
	if err := s.store.UpdateTargetBaseline(t.ID, b.Alive, b.StatusCode, b.RTTMS, b.ErrText); err != nil {
		return nil, err
	}
	return s.store.GetTarget(t.ID)
}

// ListTargets 目标列表。
func (s *Service) ListTargets(ctx context.Context) ([]store.Target, error) {
	return s.store.ListTargets()
}

// RemoveTarget 删除目标。
func (s *Service) RemoveTarget(ctx context.Context, id int64) error {
	return s.store.RemoveTarget(id)
}

// BuildReport 构建扫描报告模型（JSON/CSV/Markdown 导出用）。
func (s *Service) BuildReport(ctx context.Context, scanID int64) (*report.Model, error) {
	return report.Build(s.store, scanID)
}

// ProbeTargets 重新探活指定目标（ids 为空则全部）。
func (s *Service) ProbeTargets(ctx context.Context, ids []int64) ([]store.Target, error) {
	var targets []store.Target
	var err error
	if len(ids) == 0 {
		targets, err = s.store.ListTargets()
	} else {
		targets, err = s.store.GetTargetsByIDs(ids)
	}
	if err != nil {
		return nil, err
	}
	prober := s.prober()
	for _, t := range targets {
		b := prober.Probe(ctx, t.URL)
		if err := s.store.UpdateTargetBaseline(t.ID, b.Alive, b.StatusCode, b.RTTMS, b.ErrText); err != nil {
			return nil, err
		}
	}
	if len(ids) == 0 {
		return s.store.ListTargets()
	}
	return s.store.GetTargetsByIDs(ids)
}

func (s *Service) prober() *target.Prober {
	// 探活直连（代理仅供 POC 源 git 同步使用）
	return &target.Prober{Timeout: 8e9}
}
