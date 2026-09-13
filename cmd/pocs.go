package cmd

import (
	"fmt"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"gobas/internal/pocs"
	"gobas/internal/store"
)

var (
	pocSeverity string
	pocTag      string
	pocSearch   string
	pocLimit    int
)

var pocsCmd = &cobra.Command{
	Use:   "pocs",
	Short: "POC 模板库管理（索引 / 查询 / 统计）",
}

var pocsIndexCmd = &cobra.Command{
	Use:   "index",
	Short: "解析克隆目录中的全部模板并重建索引",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		type outcome struct {
			stats *pocs.IndexStats
			err   error
		}
		done := make(chan outcome, 1)
		go func() {
			st, err := svc.Index(cmd.Context(), args)
			done <- outcome{st, err}
		}()

		// 单行进度刷新（与 sync 一致，让用户区分"在跑"还是"卡死"）
		lastDone := -1
		var lastRepo string
		oc := func() outcome {
			for {
				select {
				case o := <-done:
					return o
				case <-time.After(400 * time.Millisecond):
					st := svc.IndexStatusNow()
					if st.Total > 0 && (st.Done != lastDone || st.CurrentRepo != lastRepo) {
						lastDone, lastRepo = st.Done, st.CurrentRepo
						pct := 0
						if st.Total > 0 {
							pct = st.Done * 100 / st.Total
						}
						fmt.Printf("\r[%d/%d] %d%% 当前: %s   ", st.Done, st.Total, pct, st.CurrentRepo)
					}
				}
			}
		}()
		fmt.Println() // 结束进度行

		if oc.err != nil {
			return oc.err
		}
		stats := oc.stats
		fmt.Printf("索引完成：仓库 %d · 文件 %d · 入库 %d · 去重 %d · 无效 %d · 引擎拒载 %d\n",
			stats.Repos, stats.Files, stats.Indexed, stats.Duplicates, stats.Invalid, stats.EngineRejected)
		return nil
	},
}

var pocsListCmd = &cobra.Command{
	Use:   "list",
	Short: "按条件查询 POC",
	RunE: func(cmd *cobra.Command, args []string) error {
		pocs, err := svc.QueryPOCs(cmd.Context(), store.POCFilter{
			Severity: pocSeverity,
			Tag:      pocTag,
			Keyword:  pocSearch,
			Limit:    pocLimit,
		})
		if err != nil {
			return err
		}
		if len(pocs) == 0 {
			fmt.Println("无匹配 POC（先执行 `gobas pocs index`）")
			return nil
		}
		fmt.Printf("%-6s %-40s %-9s %-24s %s\n", "ID", "TEMPLATE-ID", "SEVERITY", "TAGS", "NAME")
		for _, p := range pocs {
			tags := p.Tags
			if len(tags) > 24 {
				tags = tags[:21] + "..."
			}
			name := p.Name
			if len(name) > 40 {
				name = name[:37] + "..."
			}
			fmt.Printf("%-6d %-40s %-9s %-24s %s\n", p.ID, p.TemplateID, p.Severity, tags, name)
		}
		fmt.Printf("\n共 %d 条\n", len(pocs))
		return nil
	},
}

var pocsStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "POC 库统计",
	RunE: func(cmd *cobra.Command, args []string) error {
		stats, err := svc.POCStats(cmd.Context())
		if err != nil {
			return err
		}
		fmt.Printf("POC 总数：%d（官方源 %d，含 Interactsh 依赖 %d）\n\n",
			stats.Total, stats.Official, stats.WithInteractsh)
		fmt.Println("按严重度：")
		for _, s := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
			if n := stats.BySeverity[s]; n > 0 {
				fmt.Printf("  %-9s %d\n", s, n)
			}
		}
		fmt.Println("\n按协议：")
		for k, v := range stats.ByProtocol {
			fmt.Printf("  %-9s %d\n", k, v)
		}
		if len(stats.BySourceTop10) > 0 {
			fmt.Println("\nTOP10 来源仓库：")
			for _, kv := range stats.BySourceTop10 {
				fmt.Printf("  %-60s %d\n", kv.Key, kv.Value)
			}
		}
		return nil
	},
}

var pocsShowCmd = &cobra.Command{
	Use:   "show <id>",
	Short: "查看单个 POC 详情",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("无效 ID: %w", err)
		}
		pocs, err := svc.QueryPOCs(cmd.Context(), store.POCFilter{IDs: []int64{id}})
		if err != nil {
			return err
		}
		if len(pocs) == 0 {
			return fmt.Errorf("POC #%d 不存在", id)
		}
		p := pocs[0]
		fmt.Printf("ID:          %d\n", p.ID)
		fmt.Printf("TemplateID:  %s\n", p.TemplateID)
		fmt.Printf("名称:        %s\n", p.Name)
		fmt.Printf("作者:        %s\n", p.Authors)
		fmt.Printf("严重度:      %s\n", p.Severity)
		fmt.Printf("标签:        %s\n", p.Tags)
		fmt.Printf("CVE:         %s\n", p.CVEIDs)
		fmt.Printf("CNVD:        %s\n", p.CNVDIDs)
		fmt.Printf("协议:        %s\n", p.Protocols)
		fmt.Printf("Interactsh:  %v\n", p.HasInteractsh)
		fmt.Printf("来源仓库:    %s\n", p.SourceRepo)
		fmt.Printf("文件路径:    %s\n", p.FilePath)
		return nil
	},
}

func init() {
	pocsListCmd.Flags().StringVar(&pocSeverity, "severity", "", "严重度过滤（critical/high/medium/low/info）")
	pocsListCmd.Flags().StringVar(&pocTag, "tag", "", "标签过滤")
	pocsListCmd.Flags().StringVar(&pocSearch, "search", "", "关键词（模板ID/名称/CVE）")
	pocsListCmd.Flags().IntVar(&pocLimit, "limit", 50, "返回条数上限")

	pocsCmd.AddCommand(pocsIndexCmd, pocsListCmd, pocsStatsCmd, pocsShowCmd)
	rootCmd.AddCommand(pocsCmd)
}
