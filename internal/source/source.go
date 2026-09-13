// Package source 管理 POC 源仓库清单与 git 同步。
// 使用系统 git 命令浅克隆（nuclei-templates 仓库过大，go-git 性能不可接受）。
package source

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// OfficialRepo 官方模板仓库（作为内容去重基准）。
const OfficialRepo = "projectdiscovery/nuclei-templates"

// Source 单个 POC 源仓库。
type Source struct {
	URL      string `yaml:"url" json:"url"`
	Official bool   `yaml:"official,omitempty" json:"official,omitempty"`
	Enabled  *bool  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
}

// EnabledOrDefault 未设置时默认启用。
func (s Source) EnabledOrDefault() bool { return s.Enabled == nil || *s.Enabled }

// SyncResult 单源同步结果。
type SyncResult struct {
	Source     Source `json:"source"`
	Status     string `json:"status"` // cloned|updated|failed|skipped
	Err        string `json:"err,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

// Manager 源同步管理器。
type Manager struct {
	CloneDir string        // 克隆根目录
	Workers  int           // 并发数
	Proxy    string        // git 出站代理，空则直连
	Timeout  time.Duration // 单仓库操作超时，<=0 时默认 15 分钟
}

// LoadSources 从 yaml 清单加载源列表。
func LoadSources(path string) ([]Source, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var wrap struct {
		Sources []Source `yaml:"sources"`
	}
	if err := yaml.Unmarshal(data, &wrap); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	seen := map[string]bool{}
	var out []Source
	for _, s := range wrap.Sources {
		s.URL = strings.TrimSpace(s.URL)
		if s.URL == "" || seen[s.URL] {
			continue
		}
		seen[s.URL] = true
		out = append(out, s)
	}
	return out, nil
}

// SaveSources 写回 yaml 清单。
func SaveSources(path string, srcs []Source) error {
	sort.Slice(srcs, func(i, j int) bool { return srcs[i].URL < srcs[j].URL })
	wrap := struct {
		Sources []Source `yaml:"sources"`
	}{Sources: srcs}
	data, err := yaml.Marshal(&wrap)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// ImportCSV 从旧版 CSV 清单（每行一个 URL）导入，官方库自动打 official 标记。
func ImportCSV(path string) ([]Source, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	seen := map[string]bool{}
	var out []Source
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, Source{URL: line, Official: RepoKey(line) == OfficialRepo})
	}
	return out, sc.Err()
}

// MergeSources 合并两份源列表（URL 去重，existing 优先保留 official 标记）。
func MergeSources(existing, imported []Source) []Source {
	idx := map[string]Source{}
	for _, s := range existing {
		idx[s.URL] = s
	}
	for _, s := range imported {
		if old, ok := idx[s.URL]; ok {
			if s.Official {
				old.Official = true
				idx[s.URL] = old
			}
			continue
		}
		idx[s.URL] = s
	}
	out := make([]Source, 0, len(idx))
	for _, s := range idx {
		out = append(out, s)
	}
	return out
}

// RepoKey 从 GitHub URL 提取小写 "owner/repo"；非标准 github.com 仓库 URL 返回空。
func RepoKey(rawURL string) string {
	u := strings.TrimSuffix(strings.TrimRight(strings.TrimSpace(rawURL), "/"), ".git")
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	u = strings.TrimPrefix(u, "www.")
	parts := strings.Split(u, "/")
	if len(parts) < 3 || parts[0] != "github.com" {
		return ""
	}
	owner, repo := parts[1], parts[2]
	if owner == "" || repo == "" {
		return ""
	}
	return strings.ToLower(owner + "/" + repo)
}

// Sync 并发同步全部源仓库，单源失败不中断整体。
// onProgress 在每个仓库完成时回调（worker goroutine 中调用，需自行保证并发安全），
// 传 nil 则不回调。
func (m *Manager) Sync(ctx context.Context, srcs []Source, onProgress func(done, total int, r SyncResult)) []SyncResult {
	if m.Workers <= 0 {
		m.Workers = 4
	}
	if m.Timeout <= 0 {
		m.Timeout = 15 * time.Minute
	}
	sem := make(chan struct{}, m.Workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make([]SyncResult, 0, len(srcs))
	done := 0

	record := func(r SyncResult) {
		mu.Lock()
		results = append(results, r)
		done++
		d, t := done, len(srcs)
		mu.Unlock()
		if onProgress != nil {
			onProgress(d, t, r)
		}
	}

	for _, s := range srcs {
		if !s.EnabledOrDefault() {
			record(SyncResult{Source: s, Status: "skipped", Err: "disabled"})
			continue
		}
		key := RepoKey(s.URL)
		if key == "" {
			record(SyncResult{Source: s, Status: "skipped", Err: "unsupported URL (expect github.com/owner/repo)"})
			continue
		}
		wg.Add(1)
		go func(s Source, key string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			start := time.Now()
			res := m.syncOne(ctx, s, key)
			res.DurationMS = time.Since(start).Milliseconds()
			record(res)
		}(s, key)
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Source.URL < results[j].Source.URL })
	return results
}

func (m *Manager) syncOne(ctx context.Context, s Source, key string) SyncResult {
	// 单仓库超时：防止失效仓库、网络黑洞或超大仓库长期占用 worker
	ctx, cancel := context.WithTimeout(ctx, m.Timeout)
	defer cancel()

	dir := filepath.Join(m.CloneDir, filepath.FromSlash(key))
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		// fetch + reset 比 pull 稳，避免本地分叉冲突
		if err := m.git(ctx, dir, "fetch", "--depth", "1", "origin"); err != nil {
			return SyncResult{Source: s, Status: "failed", Err: err.Error()}
		}
		if err := m.git(ctx, dir, "reset", "--hard", "FETCH_HEAD"); err != nil {
			return SyncResult{Source: s, Status: "failed", Err: err.Error()}
		}
		return SyncResult{Source: s, Status: "updated"}
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return SyncResult{Source: s, Status: "failed", Err: err.Error()}
	}
	if err := m.git(ctx, m.CloneDir, "clone", "--depth", "1", "--single-branch", s.URL, dir); err != nil {
		return SyncResult{Source: s, Status: "failed", Err: err.Error()}
	}
	return SyncResult{Source: s, Status: "cloned"}
}

func (m *Manager) git(ctx context.Context, dir string, args ...string) error {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv(m.Proxy)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 200 {
			msg = msg[:200] + "..."
		}
		return fmt.Errorf("git %s: %s: %v", strings.Join(args, " "), msg, err)
	}
	return nil
}

// gitEnv 构造 git 子进程环境：注入代理并禁用一切交互式凭据提示。
// 失效/私有仓库在 clone 时 GitHub 返回 401，git 默认会等待输入用户名，
// 服务端无人值守场景将永久卡死同步 worker。
func gitEnv(proxy string) []string {
	env := append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",     // 禁用终端用户名/密码提示
		"GIT_ASKPASS=/usr/bin/true", // 禁用 askpass GUI 弹窗（macOS/Linux 通用路径）
		"GCM_INTERACTIVE=never",     // 禁用 Git Credential Manager 交互
	)
	if proxy != "" {
		env = append(env,
			"HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy, "ALL_PROXY="+proxy,
			"http_proxy="+proxy, "https_proxy="+proxy, "all_proxy="+proxy,
		)
	}
	return env
}
