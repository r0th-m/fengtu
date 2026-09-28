// 事件聚合统计(切片五 get_stats 工具;与检索同属单一检索层纪律:
// 只产出只读 SELECT,聚合在 CH 侧做,不把全量拉进 Go)。
package query

import (
	"context"
	"fmt"
)

// StatGroup 聚合维度。
type StatGroup string

const (
	GroupByStatus StatGroup = "status" // 按状态码(fields.status;空值归「(无)」如实)
	GroupByDay    StatGroup = "day"    // 按日(ts;无时区源 ts 为 NULL 天然不参与,如实)
	GroupBySource StatGroup = "source" // 按源
)

// StatsParams 聚合参数。
type StatsParams struct {
	CaseID string
	Group  StatGroup
	Limit  int      // 0 → 默认 50;上限 500(桶过多截断,如实)
	// SourceIDs 可选:限定源集合(切片七,意图主机范围;空=不限)。
	SourceIDs []string
}

// StatRow 一个聚合桶。
type StatRow struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// BuildStatsSQL 聚合 SQL(只读 SELECT;COUNT 降序)。
func BuildStatsSQL(p StatsParams) (string, []any, error) {
	if p.CaseID == "" {
		return "", nil, fmt.Errorf("case_id 必填")
	}
	limit := p.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	var keyExpr string
	switch p.Group {
	case GroupByStatus:
		keyExpr = "if(JSONExtractString(fields, 'status') = '', '(无)', JSONExtractString(fields, 'status'))"
	case GroupByDay:
		keyExpr = "toString(toDate(ts))"
	case GroupBySource:
		keyExpr = "source_id"
	default:
		return "", nil, fmt.Errorf("group 须为 status|day|source: %q", p.Group)
	}
	sql := "SELECT " + keyExpr + " AS k, count() AS c FROM fengtu.events" +
		" WHERE case_id = ?"
	args := []any{p.CaseID}
	if len(p.SourceIDs) > 0 {
		sql += " AND source_id IN ("
		for i := range p.SourceIDs {
			if i > 0 {
				sql += ", "
			}
			sql += "?"
		}
		sql += ")"
		for _, sid := range p.SourceIDs {
			args = append(args, sid)
		}
	}
	if p.Group == GroupByDay {
		sql += " AND ts IS NOT NULL" // 无时区源如实不参与按日聚合(与检索时间窗同语义)
	}
	sql += " GROUP BY k ORDER BY c DESC LIMIT ?"
	args = append(args, limit)
	return sql, args, nil
}

// StatsQuerier 聚合执行器(store.CH 实现,单测 fake)。
type StatsQuerier interface {
	QueryStats(ctx context.Context, sql string, args ...any) ([]StatRow, error)
}
