package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"gobas/internal/server"
)

var serveAddr string

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "启动 REST API + SSE 服务（为 Web UI 预留）",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr := serveAddr
		if addr == "" {
			addr = appCfg.Server.Addr
		}
		srv := server.New(svc)
		fmt.Printf("GoBAS API 服务已启动：http://%s\n", addr)
		fmt.Println("端点：GET /api/v1/healthz | POST /api/v1/sync | GET /api/v1/pocs | POST /api/v1/targets")
		fmt.Println("      POST /api/v1/scans | GET /api/v1/scans/{id}/events (SSE) | GET /api/v1/scans/{id}/results")
		fmt.Println("      GET /api/v1/scans/{id}/traffic | GET /api/v1/scans/{id}/report")
		if pwd := svc.InitialAdminPassword(); pwd != "" {
			// 首次运行：admin + 随机初始密码（仅本次进程可见，不落盘）
			fmt.Println()
			fmt.Println("=========== 首次运行已生成管理员账号 ===========")
			fmt.Printf("  用户名：admin\n  初始密码：%s\n", pwd)
			fmt.Println("  登录 Web 后将强制要求修改密码，请务必牢记新密码！")
			fmt.Println("  忘记密码可执行：gobas auth reset-password")
			fmt.Println("==============================================")
		} else if svc.AuthEnabled() {
			fmt.Println("认证：已启用（忘记密码可执行 gobas auth reset-password 重置）")
		} else {
			fmt.Println("认证：已关闭（server.auth_enabled=false）")
		}
		// svc 生命周期由 root 的 PersistentPostRun 管理
		return srv.ListenAndServe(addr)
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "版本信息",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("gobas v0.1.0 (nuclei-engine)")
	},
}

func init() {
	serveCmd.Flags().StringVar(&serveAddr, "addr", "", "监听地址（空 = 配置文件 server.addr）")
	rootCmd.AddCommand(serveCmd, versionCmd)
}
