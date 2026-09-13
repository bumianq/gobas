package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"gobas/internal/report"
	"gobas/internal/service"
	"gobas/internal/store"
)

var (
	scanName        string
	scanTargets     []int64
	scanPOCIDs      []int64
	scanSeverity    string
	scanTag         string
	scanSearch      string
	scanMax         int
	scanIncludeDead bool
	scanDryRun      bool
	scanProxy       string
	scanVerdict     string
	scanFormat      string
	scanFollow      bool
	// scan traffic 子命令参数
	scanTrafficPOC    int64
	scanTrafficTarget int64
	scanTrafficLimit  int
	scanTrafficFull   bool
	scanTrafficSearch string
	scanTrafficField  string
	// scan verdict 子命令参数
	scanVerdictIDs   []int64
	scanVerdictFrom  string
	scanVerdictTo    string
	scanVerdictApply bool
	// scan dump 子命令参数
	scanDumpLimit int
	scanDumpFull  bool
	// scan delete 子命令参数
	scanDeleteForce bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "攻击模拟执行（run / list / status / results / traffic / dump / report / cancel）",
}

var scanRunCmd = &cobra.Command{
	Use:   "run",
	Short: "启动扫描并实时输出进度",
	RunE: func(cmd *cobra.Command, args []string) error {
		req := service.ScanRequest{
			Name:        scanName,
			TargetIDs:   scanTargets,
			POCFilter:   store.POCFilter{IDs: scanPOCIDs, Severity: scanSeverity, Tag: scanTag, Keyword: scanSearch, Limit: scanMax},
			IncludeDead: scanIncludeDead,
			Proxy:       scanProxy,
		}
		if scanDryRun {
			pocs, targets, err := svc.DryRunMatrix(cmd.Context(), req)
			if err != nil {
				return err
			}
			fmt.Printf("Dry-run：POC %d 个 × 目标 %d 个 = %d 任务\n", len(pocs), len(targets), len(pocs)*len(targets))
			return nil
		}

		scanID, err := svc.StartScan(cmd.Context(), req)
		if err != nil {
			return err
		}
		fmt.Printf("扫描 #%d 已启动\n", scanID)
		return streamEvents(cmd.Context(), scanID)
	},
}

// streamEvents 订阅事件流并实时渲染。
func streamEvents(ctx context.Context, scanID int64) error {
	events, unsub := svc.SubscribeScan(scanID)
	defer unsub()

	// 竞态兜底：扫描在订阅前已结束（done 事件已丢失）时直接回读终态。
	if sc, err := svc.GetScan(ctx, scanID); err == nil && sc != nil && sc.Status != "running" {
		fmt.Printf("扫描已结束：%s\n", sc.Status)
		printSummaryFromScan(sc)
		return nil
	}

	// 计数器用于最终汇总
	counts := map[string]int{}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-events:
			if !ok {
				printSummary(scanID, counts)
				return nil
			}
			switch ev.Type {
			case "progress":
				fmt.Printf("\r进度 %d/%d ...", ev.Done, ev.Total)
			case "result":
				if ev.Result != nil {
					r := ev.Result
					counts[r.Verdict]++
					icon := verdictIcon(r.Verdict)
					fmt.Printf("\n%s [%-10s] %-40s %s", icon, r.Verdict, r.TemplateID, r.TargetURL)
					if r.Severity != "" {
						fmt.Printf(" (%s)", r.Severity)
					}
				}
			case "done":
				fmt.Printf("\n扫描结束（%d/%d）", ev.Done, ev.Total)
				if ev.ErrText != "" {
					fmt.Printf("：%s", ev.ErrText)
				}
				fmt.Println()
				printSummary(scanID, counts)
				return nil
			case "error":
				fmt.Printf("\n错误：%s\n", ev.ErrText)
				printSummary(scanID, counts)
				return nil
			}
		}
	}
}

func verdictIcon(v string) string {
	switch v {
	case "HIT":
		return "🔴"
	case "BLOCKED":
		return "🛡"
	case "TIMEOUT":
		return "⏱"
	case "UNREACHABLE":
		return "✖"
	case "MISS":
		return "·"
	default:
		return "⚠"
	}
}

func printSummary(scanID int64, counts map[string]int) {
	if len(counts) == 0 {
		return
	}
	var parts []string
	for _, v := range report.VerdictOrder {
		if n := counts[v]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", v, n))
		}
	}
	fmt.Printf("汇总：scan #%d  %s\n", scanID, strings.Join(parts, " "))
	fmt.Printf("完整报告：gobas scan report %d --format md|json|csv\n", scanID)
}

// printSummaryFromScan 从数据库终态打印汇总（订阅竞态兜底路径）。
func printSummaryFromScan(sc *store.Scan) {
	fmt.Printf("汇总：scan #%d  HIT=%d BLOCKED=%d TIMEOUT=%d UNREACHABLE=%d MISS=%d ERROR=%d\n",
		sc.ID, sc.HitCount, sc.BlockedCount, sc.TimeoutCount, sc.UnreachableCount, sc.MissCount, sc.ErrorCount)
	fmt.Printf("完整报告：gobas scan report %d --format md|json|csv\n", sc.ID)
}

var scanListCmd = &cobra.Command{
	Use:   "list",
	Short: "扫描历史",
	RunE: func(cmd *cobra.Command, args []string) error {
		scans, err := svc.ListScans(cmd.Context(), 50, 0)
		if err != nil {
			return err
		}
		if len(scans) == 0 {
			fmt.Println("暂无扫描记录")
			return nil
		}
		fmt.Printf("%-6s %-9s %-18s %-12s %-12s %s\n", "ID", "状态", "命中", "任务", "开始时间", "名称")
		for _, sc := range scans {
			hit := fmt.Sprintf("%d/%d/%d/%d/%d/%d",
				sc.HitCount, sc.BlockedCount, sc.TimeoutCount, sc.UnreachableCount, sc.MissCount, sc.ErrorCount)
			fmt.Printf("%-6d %-9s %-18s %-12s %-12s %s\n",
				sc.ID, sc.Status, hit,
				fmt.Sprintf("%d/%d", sc.DoneTasks, sc.TotalTasks),
				sc.StartedAt, sc.Name)
		}
		return nil
	},
}

var scanStatusCmd = &cobra.Command{
	Use:   "status <id>",
	Short: "扫描详情",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("无效 ID: %w", err)
		}
		sc, err := svc.GetScan(cmd.Context(), id)
		if err != nil {
			return err
		}
		if sc == nil {
			return fmt.Errorf("扫描 #%d 不存在", id)
		}
		fmt.Printf("ID:        %d\n", sc.ID)
		fmt.Printf("名称:      %s\n", sc.Name)
		fmt.Printf("状态:      %s\n", sc.Status)
		fmt.Printf("目标/POC:  %d / %d（任务 %d，完成 %d）\n", sc.TargetCount, sc.POCCount, sc.TotalTasks, sc.DoneTasks)
		fmt.Printf("流量出口:  %s\n", proxyDisplay(sc.Proxy))
		fmt.Printf("判定:      HIT=%d BLOCKED=%d TIMEOUT=%d UNREACHABLE=%d MISS=%d ERROR=%d\n",
			sc.HitCount, sc.BlockedCount, sc.TimeoutCount, sc.UnreachableCount, sc.MissCount, sc.ErrorCount)
		fmt.Printf("开始:      %s\n", sc.StartedAt)
		if sc.FinishedAt != "" {
			fmt.Printf("结束:      %s\n", sc.FinishedAt)
		}
		return nil
	},
}

var scanResultsCmd = &cobra.Command{
	Use:   "results <id>",
	Short: "扫描结果（--verdict 过滤；ID 列可供 scan verdict --ids 使用）",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("无效 ID: %w", err)
		}
		results, err := svc.ScanResults(cmd.Context(), id, scanVerdict)
		if err != nil {
			return err
		}
		if len(results) == 0 {
			fmt.Println("无匹配结果")
			return nil
		}
		fmt.Printf("%-7s %-11s %-40s %-46s %s\n", "ID", "判定", "TEMPLATE-ID", "目标", "HTTP")
		for _, r := range results {
			manual := ""
			if r.ManualAt != "" {
				manual = " ✎"
			}
			fmt.Printf("%-7d %-11s %-40s %-46s %d%s\n", r.ID, r.Verdict, r.TemplateID, r.TargetURL, r.ResponseStatus, manual)
			if r.ErrorText != "" {
				fmt.Printf("    ↳ %s\n", r.ErrorText)
			}
		}
		fmt.Printf("\n共 %d 条（✎ = 人工修正过；修正：gobas scan verdict %d --ids <ID> --to <判定>）\n", len(results), id)
		return nil
	},
}

var scanReportCmd = &cobra.Command{
	Use:   "report <id>",
	Short: "导出报告（--format md|json|csv，默认 md 输出到 stdout）",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("无效 ID: %w", err)
		}
		m, err := svc.BuildReport(cmd.Context(), id)
		if err != nil {
			return err
		}
		return report.Export(m, scanFormat, os.Stdout)
	},
}

var scanCancelCmd = &cobra.Command{
	Use:   "cancel <id>",
	Short: "取消运行中的扫描",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("无效 ID: %w", err)
		}
		if err := svc.CancelScan(cmd.Context(), id); err != nil {
			return err
		}
		fmt.Printf("扫描 #%d 取消中\n", id)
		return nil
	},
}

var scanDeleteCmd = &cobra.Command{
	Use:   "delete <id...>",
	Short: "删除扫描历史（结果/流量级联删除，运行中的扫描需先取消）",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, a := range args {
			id, err := strconv.ParseInt(a, 10, 64)
			if err != nil {
				return fmt.Errorf("无效 ID: %w", err)
			}
			if !scanDeleteForce {
				sc, err := svc.GetScan(cmd.Context(), id)
				if err != nil {
					return err
				}
				if sc == nil {
					fmt.Printf("扫描 #%d 不存在，跳过\n", id)
					continue
				}
				fmt.Printf("确认删除扫描 #%d「%s」（%s，%d 任务，含结果与流量）？[y/N] ", id, sc.Name, sc.Status, sc.TotalTasks)
				var ans string
				fmt.Scanln(&ans)
				if ans != "y" && ans != "Y" && ans != "yes" {
					fmt.Printf("已跳过 #%d\n", id)
					continue
				}
			}
			if err := svc.DeleteScan(cmd.Context(), id); err != nil {
				fmt.Printf("删除 #%d 失败：%v\n", id, err)
				continue
			}
			fmt.Printf("扫描 #%d 已删除\n", id)
		}
		return nil
	},
}

var scanTrafficCmd = &cobra.Command{
	Use:   "traffic <id>",
	Short: "任务流量记录（请求/响应包，--full 查看完整包内容，--search 特征搜索）",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("无效 ID: %w", err)
		}
		rows, total, err := svc.ScanTraffic(cmd.Context(), id, scanTrafficPOC, scanTrafficTarget,
			scanTrafficSearch, scanTrafficField, scanTrafficLimit, 0)
		if err != nil {
			return err
		}
		if total == 0 {
			if scanTrafficSearch != "" {
				fmt.Printf("无匹配「%s」的流量记录\n", scanTrafficSearch)
			} else {
				fmt.Println("无流量记录（旧扫描无流量，或配置 traffic_save=false）")
			}
			return nil
		}
		if scanTrafficFull {
			for _, r := range rows {
				fmt.Printf("===== SEQ %d [%s] %s → %s (HTTP %d) =====\n",
					r.Seq, r.Protocol, r.TemplateID, r.TargetURL, r.Status)
				fmt.Println("--- REQUEST ---")
				if r.Request == "" {
					fmt.Println("(无)")
				} else {
					fmt.Println(r.Request)
				}
				fmt.Println("--- RESPONSE ---")
				if r.Response == "" {
					fmt.Println("(无)")
				} else {
					fmt.Println(r.Response)
				}
				fmt.Println()
			}
			fmt.Printf("共显示 %d/%d 条\n", len(rows), total)
			return nil
		}
		fmt.Printf("%-6s %-10s %-7s %-6s %-40s %-30s %s\n",
			"SEQ", "协议", "匹配", "HTTP", "TEMPLATE-ID", "目标", "请求/响应大小")
		for _, r := range rows {
			fmt.Printf("%-6d %-10s %-7s %-6d %-40s %-30s %s/%s\n",
				r.Seq, trafficProto(r.Protocol), trafficMatch(r.Matched), r.Status,
				r.TemplateID, r.TargetURL, trafficSize(r.Request, r.ReqTruncated), trafficSize(r.Response, r.RespTruncated))
		}
		fmt.Printf("\n共 %d 条（完整包内容：gobas scan traffic %d --full）\n", total, id)
		return nil
	},
}

var scanVerdictCmd = &cobra.Command{
	Use:   "verdict <id>",
	Short: "人工修正结果判定（--to 目标判定；--ids 指定结果行；--from 按原类别批量；--to 空=恢复自动判定）",
	Long: `人工修正结果判定：机器自动判定不总可靠（WAF 指纹误判等），
结合流量特征（gobas scan traffic <id> --search）二次判定后改写结果类别。

示例：
  gobas scan verdict 5 --ids 12,13 --to BLOCKED     # 指定结果行改为 BLOCKED
  gobas scan verdict 5 --from MISS --to BLOCKED     # 全部 MISS 批量改为 BLOCKED
  gobas scan verdict 5 --from MISS --to BLOCKED --apply  # 免确认执行
  gobas scan verdict 5 --ids 12 --to ""             # 恢复该行机器自动判定`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("无效 ID: %w", err)
		}
		if len(scanVerdictIDs) == 0 && scanVerdictFrom == "" {
			return fmt.Errorf("请指定 --ids（结果行）或 --from（原判定类别）")
		}
		// 预览受影响的结果行
		results, err := svc.ScanResults(cmd.Context(), id, scanVerdictFrom)
		if err != nil {
			return err
		}
		var affected []store.ResultDetail
		idSet := map[int64]bool{}
		for _, rid := range scanVerdictIDs {
			idSet[rid] = true
		}
		for _, r := range results {
			if len(idSet) == 0 || idSet[r.ID] {
				affected = append(affected, r)
			}
		}
		if len(affected) == 0 {
			fmt.Println("无匹配的结果行（--ids 指定的行不存在，或 --from 类别下无结果）")
			return nil
		}
		action := "改为 " + scanVerdictTo
		if scanVerdictTo == "" {
			action = "恢复机器自动判定"
		}
		fmt.Printf("将影响 %d 条结果（%s）：\n", len(affected), action)
		for _, r := range affected {
			fmt.Printf("  #%-6d %-11s %-40s %s\n", r.ID, r.Verdict, r.TemplateID, r.TargetURL)
		}
		if !scanVerdictApply {
			fmt.Printf("确认执行？[y/N] ")
			var ans string
			fmt.Scanln(&ans)
			if ans != "y" && ans != "Y" && ans != "yes" {
				fmt.Println("已取消")
				return nil
			}
		}
		n, err := svc.UpdateScanVerdicts(cmd.Context(), id, service.VerdictUpdateRequest{
			ResultIDs:   scanVerdictIDs,
			FromVerdict: scanVerdictFrom,
			ToVerdict:   scanVerdictTo,
		})
		if err != nil {
			return err
		}
		fmt.Printf("已修正 %d 条结果，判定计数已同步刷新\n", n)
		return nil
	},
}

var scanDumpCmd = &cobra.Command{
	Use:   "dump <id>",
	Short: "镜像连接流水（socks5 镜像代理逐连接记录，含 fuzz/多请求攻击链的全部中间请求，--full 查看完整字节流）",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("无效 ID: %w", err)
		}
		rows, total, err := svc.ScanTrafficDump(id, scanDumpLimit, 0)
		if err != nil {
			return err
		}
		if total == 0 {
			fmt.Println("无镜像连接记录（traffic_save=false，或旧版本扫描未启用镜像代理）")
			return nil
		}
		if scanDumpFull {
			for _, r := range rows {
				fmt.Printf("===== SEQ %d %s（%dms）=====\n", r.Seq, r.Addr, r.DurationMs)
				fmt.Println("--- 客户端 → 服务端 ---")
				if r.ClientData == "" {
					fmt.Println("(无)")
				} else {
					fmt.Println(r.ClientData)
				}
				fmt.Println("--- 服务端 → 客户端 ---")
				if r.ServerData == "" {
					fmt.Println("(无)")
				} else {
					fmt.Println(r.ServerData)
				}
				fmt.Println()
			}
			fmt.Printf("共显示 %d/%d 条\n", len(rows), total)
			return nil
		}
		fmt.Printf("%-6s %-24s %-8s %-16s %s\n", "SEQ", "目标", "耗时", "C→S", "S→C")
		for _, r := range rows {
			fmt.Printf("%-6d %-24s %-8d %-16s %s\n", r.Seq, r.Addr, r.DurationMs,
				trafficSize(r.ClientData, r.ClientTrunc), trafficSize(r.ServerData, r.ServerTrunc))
		}
		fmt.Printf("\n共 %d 条（完整字节流：gobas scan dump %d --full）\n", total, id)
		return nil
	},
}

// trafficProto 协议展示（空值兜底）。
func trafficProto(p string) string {
	if p == "" {
		return "?"
	}
	return p
}

// proxyDisplay 扫描流量出口展示（空 = 直连）。
func proxyDisplay(p string) string {
	if p == "" {
		return "直连（未走代理）"
	}
	return p
}

// trafficMatch 匹配标记。
func trafficMatch(m bool) string {
	if m {
		return "是"
	}
	return "否"
}

// trafficSize 大小展示（截断标记 *）。
func trafficSize(s string, truncated bool) string {
	size := fmt.Sprintf("%dB", len(s))
	if truncated {
		size += "*"
	}
	return size
}

func init() {
	scanRunCmd.Flags().StringVar(&scanName, "name", "", "扫描名称")
	scanRunCmd.Flags().Int64SliceVar(&scanTargets, "targets", nil, "目标 ID 列表（空 = 全部存活目标）")
	scanRunCmd.Flags().Int64SliceVar(&scanPOCIDs, "pocs", nil, "POC ID 列表（空 = 按过滤条件选取）")
	scanRunCmd.Flags().StringVar(&scanSeverity, "severity", "", "严重度过滤")
	scanRunCmd.Flags().StringVar(&scanTag, "tag", "", "标签过滤")
	scanRunCmd.Flags().StringVar(&scanSearch, "search", "", "关键词过滤")
	scanRunCmd.Flags().IntVar(&scanMax, "max", 0, "POC 数量上限（0 = 配置默认）")
	scanRunCmd.Flags().BoolVar(&scanIncludeDead, "include-dead", false, "包含探活失败目标（判定 UNREACHABLE）")
	scanRunCmd.Flags().StringVar(&scanProxy, "proxy", "", "扫描流量出口代理（如 http://127.0.0.1:8083，支持 http/https/socks5；空 = 直连）")
	scanRunCmd.Flags().BoolVar(&scanDryRun, "dry-run", false, "只解析矩阵不执行")

	scanResultsCmd.Flags().StringVar(&scanVerdict, "verdict", "", "判定过滤（HIT/BLOCKED/TIMEOUT/UNREACHABLE/MISS/ERROR）")
	scanReportCmd.Flags().StringVar(&scanFormat, "format", "md", "导出格式：md|json|csv")

	scanTrafficCmd.Flags().Int64Var(&scanTrafficPOC, "poc", 0, "按 POC ID 过滤（0 = 全部）")
	scanTrafficCmd.Flags().Int64Var(&scanTrafficTarget, "target", 0, "按目标 ID 过滤（0 = 全部）")
	scanTrafficCmd.Flags().IntVar(&scanTrafficLimit, "limit", 1000, "显示条数上限（上限 10000）")
	scanTrafficCmd.Flags().BoolVar(&scanTrafficFull, "full", false, "显示完整请求/响应包内容")
	scanTrafficCmd.Flags().StringVar(&scanTrafficSearch, "search", "", "请求/响应包内容特征搜索（如 WAF 拦截页指纹）")
	scanTrafficCmd.Flags().StringVar(&scanTrafficField, "field", "", "搜索字段：request|response（缺省 = 两者）")

	scanVerdictCmd.Flags().Int64SliceVar(&scanVerdictIDs, "ids", nil, "指定结果行 ID（gobas scan results 查看，可组合 --from）")
	scanVerdictCmd.Flags().StringVar(&scanVerdictFrom, "from", "", "按当前判定类别批量（如 --from MISS）")
	scanVerdictCmd.Flags().StringVar(&scanVerdictTo, "to", "", "目标判定（HIT/BLOCKED/TIMEOUT/UNREACHABLE/MISS/ERROR；空 = 恢复机器自动判定）")
	scanVerdictCmd.Flags().BoolVar(&scanVerdictApply, "apply", false, "跳过确认直接执行")

	scanDumpCmd.Flags().IntVar(&scanDumpLimit, "limit", 500, "显示条数上限")
	scanDumpCmd.Flags().BoolVar(&scanDumpFull, "full", false, "显示完整双向字节流")

	scanDeleteCmd.Flags().BoolVarP(&scanDeleteForce, "force", "f", false, "跳过确认直接删除")

	scanCmd.AddCommand(scanRunCmd, scanListCmd, scanStatusCmd, scanResultsCmd, scanReportCmd, scanCancelCmd, scanTrafficCmd, scanVerdictCmd, scanDumpCmd, scanDeleteCmd)
	rootCmd.AddCommand(scanCmd)
}
