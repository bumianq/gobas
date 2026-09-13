// Package config 提供 gobas 运行配置的加载与默认值。
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// NetworkConfig 网络相关配置（代理）。
type NetworkConfig struct {
	// Proxy 出站代理，仅用于 POC 源 git 同步；扫描引擎与探活一律直连，空则同步也直连。
	Proxy string `yaml:"proxy"`
}

// ScanConfig 扫描执行参数。
type ScanConfig struct {
	TimeoutSec    int `yaml:"timeout_sec"`      // 单请求超时（秒）
	Retries       int `yaml:"retries"`          // 失败重试次数
	RateLimitPerS int `yaml:"rate_limit_per_s"` // 全局限速（请求/秒），0 不限
	MaxPOCs       int `yaml:"max_pocs"`         // 单次扫描 POC 数量上限（防内存爆炸）
	// TrafficSave 是否记录任务流量（请求/响应包）。
	// bool 默认值依赖「预置默认 + yaml 部分覆盖」语义（Load 用预填默认值的
	// cfg 反序列化，yaml.v3 只覆盖文件中出现的键），勿改成零值回落。
	TrafficSave bool `yaml:"traffic_save"`
	// TrafficMaxBytes 流量单字段（请求/响应各自）截断上限（字节），<=0 回落 65536。
	// 头部截断天然保留 HTTP 状态行与 headers（WAF 指纹所在）。
	TrafficMaxBytes int `yaml:"traffic_max_bytes"`
}

// VerdictConfig 判定层参数。
type VerdictConfig struct {
	// BlockedStatuses 视为"被拦截"的 HTTP 状态码集合。
	BlockedStatuses []int `yaml:"blocked_statuses"`
}

// ServerConfig REST/SSE 服务配置。
type ServerConfig struct {
	Addr string `yaml:"addr"`
	// AuthEnabled 是否启用登录认证。默认开启，首次运行创建 admin 随机密码；
	// 本地/内网纯 API 脚本化调用场景可设为 false 全部放行。
	AuthEnabled bool `yaml:"auth_enabled"`
	// SessionTTLHours 会话有效期（小时），过期需重新登录。
	SessionTTLHours int `yaml:"session_ttl_hours"`
}

// Config gobas 顶层配置。
type Config struct {
	Workspace string        `yaml:"workspace"` // 数据目录，空则程序所在目录
	Network   NetworkConfig `yaml:"network"`
	Scan      ScanConfig    `yaml:"scan"`
	Verdict   VerdictConfig `yaml:"verdict"`
	Server    ServerConfig  `yaml:"server"`
}

// defaultWorkspace 默认数据目录：程序可执行文件所在目录，
// 数据库与克隆仓库与二进制放在一起（绿色便携式）；
// 取不到可执行路径时退回当前工作目录。
func defaultWorkspace() string {
	if exe, err := os.Executable(); err == nil {
		if dir := filepath.Dir(exe); dir != "" && dir != "." {
			return dir
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		return cwd
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".gobas")
}

// Default 返回编译内置默认配置。
func Default() *Config {
	return &Config{
		Workspace: defaultWorkspace(),
		Network: NetworkConfig{
			Proxy: "http://127.0.0.1:7897",
		},
		Scan: ScanConfig{
			TimeoutSec:      10,
			Retries:         2,
			RateLimitPerS:   150,
			MaxPOCs:         500,
			TrafficSave:     true,
			TrafficMaxBytes: 65536,
		},
		Verdict: VerdictConfig{
			BlockedStatuses: []int{403, 405, 418, 429, 501},
		},
		Server: ServerConfig{
			Addr:            "127.0.0.1:8080",
			AuthEnabled:     true,
			SessionTTLHours: 24,
		},
	}
}

// Load 从 yaml 文件加载配置（缺省字段用默认值填充），path 为空则纯默认。
func Load(path string) (*Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
	}
	if cfg.Workspace == "" {
		cfg.Workspace = defaultWorkspace()
	}
	return cfg, nil
}

// CloneDir POC 源仓库克隆目录。
func (c *Config) CloneDir() string { return filepath.Join(c.Workspace, "clone-templates") }

// CustomPOCDir 人工添加 POC 模板文件目录（独立于 clone 目录，git 同步/重建索引不触碰）。
func (c *Config) CustomPOCDir() string { return filepath.Join(c.Workspace, "custom-pocs") }

// DBPath SQLite 数据库路径。
func (c *Config) DBPath() string { return filepath.Join(c.Workspace, "gobas.db") }

// SourcesPath POC 源清单路径。
func (c *Config) SourcesPath() string { return filepath.Join(c.Workspace, "sources.yaml") }

// EnsureDirs 创建工作目录（含人工 POC 目录）。
func (c *Config) EnsureDirs() error {
	if err := os.MkdirAll(c.Workspace, 0o755); err != nil {
		return err
	}
	return os.MkdirAll(c.CustomPOCDir(), 0o755)
}

// SetProxyFromFlags 按 CLI 标志覆盖代理配置。
// proxyFlag 非空则使用该代理；noProxy 为真则强制直连；两者都空则保持配置不变。
func (c *Config) SetProxyFromFlags(proxyFlag string, noProxy bool) {
	if noProxy {
		c.Network.Proxy = ""
		return
	}
	if proxyFlag != "" {
		c.Network.Proxy = proxyFlag
	}
}
