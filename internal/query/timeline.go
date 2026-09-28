// 时间线聚合(切片 8b 案件页时间线 tab):全源按 ts 小时桶密度 +
// 无时区源单列(如实标「不参与时间线」)。与检索同属单一检索层纪律:
// 只产出只读 SELECT,聚合在 CH 侧做,桶数有上限(截断如实标)。
package query

import (
	"fmt"
)

// 时间线小时桶上限(≈171 天跨度的案件也装得下;超出截断如实标)。
const timelineBucketLimit = 4100

// BuildTimelineSQL 小时桶密度 SQL(key=桶起 Unix 秒,按桶升序)。
// 无时区源 ts 为 NULL 天然不参与(与检索时间窗同语义,如实)。
func BuildTimelineSQL(caseID string) (string, []any, error) {
	if caseID == "" {
		return "", nil, fmt.Errorf("case_id 必填")
	}
	sql := "SELECT toString(toUnixTimestamp(toStartOfHour(ts))) AS k, count() AS c" +
		" FROM fengtu.events WHERE case_id = ? AND ts IS NOT NULL" +
		" GROUP BY k ORDER BY k ASC LIMIT ?"
	return sql, []any{caseID, timelineBucketLimit}, nil
}

// BuildNoTZSQL 无时区源清单 SQL(key=source_id,count=事件数):
// 这些源不参与时间线/时间窗,单列如实标,不静默吞掉。
func BuildNoTZSQL(caseID string) (string, []any, error) {
	if caseID == "" {
		return "", nil, fmt.Errorf("case_id 必填")
	}
	sql := "SELECT source_id AS k, count() AS c FROM fengtu.events" +
		" WHERE case_id = ? AND ts IS NULL GROUP BY k ORDER BY c DESC LIMIT ?"
	return sql, []any{caseID, maxLimit}, nil
}
