package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"gobas/internal/config"
	"gobas/internal/service"
)

var (
	cfgPath string
	proxy   string
	noProxy bool
)

// 全局服务实例（PersistentPreRunE 中初始化）。
var svc *service.Service

// 全局配置实例（PersistentPreRunE 中初始化）。
var appCfg *config.Config

var rootCmd = &cobra.Command{
	Use:   "gobas",
	Short: "GoBAS - 基于 Nuclei 的入侵与攻击模拟（BAS）工具",
	Long: `GoBAS：选取 POC → 选择目标 → 攻击模拟 → 依据返回包特征判定
（HIT 命中 / BLOCKED 被拦截 / TIMEOUT 超时 / UNREACHABLE 不可达 / MISS 未命中 / ERROR 错误）。

典型流程：
  gobas sync --import-csv repo.csv   # 同步 POC 源仓库
  gobas pocs index                    # 建立 POC 索引
  gobas target add http://target      # 添加 HTTP 目标（自动基线探活）
  gobas target add 1.2.3.4:6379       # 添加 TCP 目标（仅执行 network 协议 POC）
  gobas scan run --severity critical  # 执行攻击模拟
  gobas scan report 1                 # 导出拦截矩阵报告`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		cfg.SetProxyFromFlags(proxy, noProxy)
		appCfg = cfg
		svc, err = service.New(cfg)
		if err != nil {
			return err
		}
		return nil
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if svc != nil {
			_ = svc.Close()
		}
	},
}

// Execute 入口。
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgPath, "config", "", "配置文件路径（不指定则用内置默认值，数据目录默认为程序所在目录）")
	rootCmd.PersistentFlags().StringVar(&proxy, "proxy", "", "出站代理（覆盖配置；如 http://127.0.0.1:7897，便于 Burp 抓包调试）")
	rootCmd.PersistentFlags().BoolVar(&noProxy, "no-proxy", false, "强制直连（忽略配置中的代理）")
}
