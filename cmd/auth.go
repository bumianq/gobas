package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	authUsername string
	authPassword string
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "认证管理（管理员密码重置）",
}

var resetPasswordCmd = &cobra.Command{
	Use:   "reset-password",
	Short: "重置管理员密码（生成随机密码，登录后须再次修改）",
	Long: `重置指定用户的密码：默认生成 16 位随机密码打印到控制台，
也可用 --password 指定。重置后所有已登录会话失效，且下次登录须强制修改密码。`,
	RunE: func(cmd *cobra.Command, args []string) error {
		pwd, err := svc.ResetPassword(authUsername, authPassword)
		if err != nil {
			return err
		}
		fmt.Printf("已重置用户 %s 的密码：%s\n", authUsername, pwd)
		fmt.Println("提示：所有旧会话已失效，该用户下次登录后将被强制要求修改密码。")
		return nil
	},
}

func init() {
	resetPasswordCmd.Flags().StringVar(&authUsername, "username", "admin", "要重置的用户名")
	resetPasswordCmd.Flags().StringVar(&authPassword, "password", "", "指定新密码（空 = 自动生成 16 位随机密码）")
	authCmd.AddCommand(resetPasswordCmd)
	rootCmd.AddCommand(authCmd)
}
