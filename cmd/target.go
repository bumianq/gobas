package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
)

var targetName string

var targetCmd = &cobra.Command{
	Use:   "target",
	Short: "目标管理（新增 / 探活 / 列表 / 删除）",
}

var targetAddCmd = &cobra.Command{
	Use:   "add <url>...",
	Short: "添加目标（自动基线探活）",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, raw := range args {
			t, err := svc.AddTarget(cmd.Context(), raw, targetName)
			if err != nil {
				fmt.Printf("✗ %s: %v\n", raw, err)
				continue
			}
			state := "存活"
			if !t.Alive {
				state = "不可达: " + t.BaselineError
			}
			fmt.Printf("+ #%d %s（%s，基线 %dms / HTTP %d）\n",
				t.ID, t.URL, state, t.BaselineRTTMS, t.BaselineStatus)
		}
		return nil
	},
}

var targetListCmd = &cobra.Command{
	Use:   "list",
	Short: "列出全部目标",
	RunE: func(cmd *cobra.Command, args []string) error {
		targets, err := svc.ListTargets(cmd.Context())
		if err != nil {
			return err
		}
		if len(targets) == 0 {
			fmt.Println("暂无目标（先 `gobas target add <url>`）")
			return nil
		}
		fmt.Printf("%-6s %-4s %-50s %-7s %s\n", "ID", "存活", "URL", "HTTP", "RTT")
		for _, t := range targets {
			alive := "✗"
			if t.Alive {
				alive = "✓"
			}
			fmt.Printf("%-6d %-4s %-50s %-7d %dms\n", t.ID, alive, t.URL, t.BaselineStatus, t.BaselineRTTMS)
		}
		return nil
	},
}

var targetProbeCmd = &cobra.Command{
	Use:   "probe [id...]",
	Short: "重新探活（指定 ID，缺省全部）",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		var ids []int64
		for _, a := range args {
			id, err := strconv.ParseInt(a, 10, 64)
			if err != nil {
				return fmt.Errorf("无效 ID: %s", a)
			}
			ids = append(ids, id)
		}
		targets, err := svc.ProbeTargets(cmd.Context(), ids)
		if err != nil {
			return err
		}
		for _, t := range targets {
			state := "存活"
			if !t.Alive {
				state = "不可达: " + t.BaselineError
			}
			fmt.Printf("#%-6d %-50s %s（HTTP %d / %dms）\n", t.ID, t.URL, state, t.BaselineStatus, t.BaselineRTTMS)
		}
		return nil
	},
}

var targetRemoveCmd = &cobra.Command{
	Use:   "remove <id>",
	Short: "删除目标",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("无效 ID: %w", err)
		}
		if err := svc.RemoveTarget(cmd.Context(), id); err != nil {
			return err
		}
		fmt.Printf("已删除目标 #%d\n", id)
		return nil
	},
}

func init() {
	targetAddCmd.Flags().StringVar(&targetName, "name", "", "目标备注名")
	targetCmd.AddCommand(targetAddCmd, targetListCmd, targetProbeCmd, targetRemoveCmd)
	rootCmd.AddCommand(targetCmd)
}
