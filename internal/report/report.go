// Package report 汇总扫描结果为拦截矩阵报告。
package report

import (
	"fmt"
	"sort"
	"time"

	"gobas/internal/store"
)

// ResultRow 单条结果及其任务流量（该 (POC,目标) 实际发送的请求包/响应包，
// 多事件模板按 seq 保序，无流量时为空）。
type ResultRow struct {
	store.ResultDetail
	Traffic []store.Traffic `json:"traffic,omitempty"`
}

// TargetRow 单目标的矩阵行。
type TargetRow struct {
	TargetID int64
	Name     string
	URL      string
	Alive    bool
	Counts   map[string]int // verdict → count
	Results  []ResultRow
}

// Model 报告模型。
type Model struct {
	Scan        store.Scan
	GeneratedAt time.Time
	Total       int
	Counts      map[string]int
	Targets     []TargetRow
}

// VerdictOrder 报告中判定展示顺序。
var VerdictOrder = []string{"HIT", "BLOCKED", "TIMEOUT", "UNREACHABLE", "MISS", "ERROR"}

// Build 从存储构建报告模型。
func Build(st *store.Store, scanID int64) (*Model, error) {
	sc, err := st.GetScan(scanID)
	if err != nil {
		return nil, err
	}
	if sc == nil {
		return nil, fmt.Errorf("scan #%d not found", scanID)
	}
	details, err := st.ListResults(scanID, "")
	if err != nil {
		return nil, err
	}
	// 任务流量按 (POC,目标) 分组挂到对应结果（无流量任务 Traffic 为空）
	traffic, err := st.ListScanTrafficAll(scanID)
	if err != nil {
		return nil, err
	}
	type taskKey struct{ poc, target int64 }
	byTask := make(map[taskKey][]store.Traffic, len(traffic))
	for _, tr := range traffic {
		k := taskKey{tr.POCID, tr.TargetID}
		byTask[k] = append(byTask[k], tr)
	}
	m := &Model{
		Scan:        *sc,
		GeneratedAt: time.Now(),
		Total:       len(details),
		Counts:      map[string]int{},
	}
	byTarget := map[int64]*TargetRow{}
	targetOrder := []int64{}
	for _, d := range details {
		row, ok := byTarget[d.TargetID]
		if !ok {
			row = &TargetRow{TargetID: d.TargetID, Name: d.TargetName, URL: d.TargetURL, Counts: map[string]int{}}
			byTarget[d.TargetID] = row
			targetOrder = append(targetOrder, d.TargetID)
		}
		row.Results = append(row.Results, ResultRow{
			ResultDetail: d,
			Traffic:      byTask[taskKey{d.POCID, d.TargetID}],
		})
		row.Counts[d.Verdict]++
		m.Counts[d.Verdict]++
	}
	// 每个目标内按判定优先级 + 严重度排序
	for _, row := range byTarget {
		sort.SliceStable(row.Results, func(i, j int) bool {
			vi, vj := verdictRank(row.Results[i].Verdict), verdictRank(row.Results[j].Verdict)
			if vi != vj {
				return vi < vj
			}
			return row.Results[i].TemplateID < row.Results[j].TemplateID
		})
	}
	for _, id := range targetOrder {
		m.Targets = append(m.Targets, *byTarget[id])
	}
	return m, nil
}

func verdictRank(v string) int {
	for i, s := range VerdictOrder {
		if s == v {
			return i
		}
	}
	return len(VerdictOrder)
}
