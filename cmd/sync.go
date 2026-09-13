package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"gobas/internal/source"
)

var (
	syncImportCSV string
	syncWorkers   int
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "同步 POC 源仓库（git clone / pull）",
	RunE: func(cmd *cobra.Command, args []string) error {
		start := time.Now()
		// CLI 的代理已由 root 全局标志（--proxy/--no-proxy）写入 appCfg，
		// service.Sync 默认读取配置，无需额外覆盖。
		type syncOutcome struct {
			results []source.SyncResult
			err     error
		}
		done := make(chan syncOutcome, 1)
		go func() {
			rs, err := svc.Sync(cmd.Context(), syncImportCSV, syncWorkers, nil)
			done <- syncOutcome{rs, err}
		}()

		// 单行进度刷新：[12/196] cloned 3 / failed 2 —— 让用户区分"在跑"还是"卡死"
		lastDone := -1
		var counts map[string]int
		outcome := func() syncOutcome {
			for {
				select {
				case o := <-done:
					return o
				case <-time.After(400 * time.Millisecond):
					st := svc.SyncStatusNow()
					if st.Total > 0 && st.Done != lastDone {
						lastDone = st.Done
						counts = map[string]int{}
						for _, r := range st.Results {
							if r.Status == "failed" {
								counts["failed"]++
							} else {
								counts["ok"]++
							}
						}
						fmt.Printf("\r[%d/%d] 进行中 · 成功 %d · 失败 %d   ",
							st.Done, st.Total, counts["ok"], counts["failed"])
					}
				}
			}
		}()
		fmt.Println() // 结束进度行

		if outcome.err != nil {
			return outcome.err
		}
		results := outcome.results
		var failed int
		for _, r := range results {
			icon := map[string]string{"cloned": "+", "updated": "↻", "skipped": "-"}[r.Status]
			if icon == "" {
				icon = "!"
				failed++
			}
			fmt.Printf("%s %-8s %-70s %6dms", icon, r.Status, r.Source.URL, r.DurationMS)
			if r.Err != "" {
				fmt.Printf("  %s", r.Err)
			}
			fmt.Println()
		}
		fmt.Printf("\n完成：%d 成功 / %d 失败，耗时 %s\n", len(results)-failed, failed, time.Since(start).Round(time.Millisecond))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(syncCmd)
	syncCmd.Flags().StringVar(&syncImportCSV, "import-csv", "", "导入旧项目 repo.csv 清单（首次迁移用，导入后合并保存到 sources.yaml）")
	syncCmd.Flags().IntVar(&syncWorkers, "workers", 4, "并发 git 克隆/拉取数")
}
