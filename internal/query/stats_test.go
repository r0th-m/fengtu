package query

import (
	"strings"
	"testing"
)

func TestBuildStatsSQL(t *testing.T) {
	sql, args, err := BuildStatsSQL(StatsParams{CaseID: "c1", Group: GroupByStatus})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, "JSONExtractString") || len(args) != 2 {
		t.Fatalf("status 聚合 SQL 不符: %s %v", sql, args)
	}
	sql, _, err = BuildStatsSQL(StatsParams{CaseID: "c1", Group: GroupByDay})
	if err != nil || !strings.Contains(sql, "ts IS NOT NULL") {
		t.Fatalf("day 聚合应如实排除无时区源: %s", sql)
	}
	if _, _, err := BuildStatsSQL(StatsParams{CaseID: "c1", Group: "hour"}); err == nil {
		t.Fatal("非法 group 应拒")
	}
	if _, _, err := BuildStatsSQL(StatsParams{Group: GroupBySource}); err == nil {
		t.Fatal("缺 case_id 应拒")
	}
	// limit 上限截断
	_, args, _ = BuildStatsSQL(StatsParams{CaseID: "c1", Group: GroupBySource, Limit: 9999})
	if args[len(args)-1] != 500 {
		t.Fatalf("limit 应截断 500: %v", args)
	}
}
