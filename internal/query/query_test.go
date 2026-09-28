// 检索层焊死:SQL 构建 golden(语义逐点)/参数校验负样本/服务层只读通路。
package query

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func mustSQL(t *testing.T, p Params) (string, []any) {
	t.Helper()
	sql, args, err := BuildSearchSQL(p)
	if err != nil {
		t.Fatalf("BuildSearchSQL 失败: %v", err)
	}
	return sql, args
}

func TestBuildSearchSQLFull(t *testing.T) {
	from := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	sql, args := mustSQL(t, Params{
		CaseID: "c1", Q: "union select",
		Conds: []FieldCond{
			{Field: "src_ip", Op: OpEq, Values: []string{"10.0.0.1"}},
			{Field: "ua", Op: OpContains, Values: []string{"nmap", "sqlmap"}},
			{Field: "raw", Op: OpContains, Values: []string{"etc/passwd"}},
		},
		TSFrom: &from, TSTo: &to, SourceID: "s1", Limit: 50, Offset: 10,
	})
	want := "SELECT source_id, line_no, ts, kind, fields, raw FROM fengtu.events WHERE " +
		"case_id = ? AND source_id = ? AND positionCaseInsensitive(raw, ?) > 0" +
		" AND JSONExtractString(fields, ?) = ?" +
		" AND (positionCaseInsensitive(JSONExtractString(fields, ?), ?) > 0" +
		" OR positionCaseInsensitive(JSONExtractString(fields, ?), ?) > 0)" +
		" AND (positionCaseInsensitive(raw, ?) > 0)" +
		" AND ts >= ? AND ts <= ?" +
		" ORDER BY source_id, line_no LIMIT ? OFFSET ?"
	if sql != want {
		t.Fatalf("SQL 不符:\n got %s\nwant %s", sql, want)
	}
	wantArgs := []any{"c1", "s1", "union select", "src_ip", "10.0.0.1",
		"ua", "nmap", "ua", "sqlmap", "etc/passwd", from, to, 50, 10}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("参数不符: got %v want %v", args, wantArgs)
	}
}

func TestBuildSearchSQLMultiValueEq(t *testing.T) {
	sql, args := mustSQL(t, Params{
		CaseID: "c1",
		Conds:  []FieldCond{{Field: "status", Op: OpEq, Values: []string{"200", "204"}}},
	})
	want := "SELECT source_id, line_no, ts, kind, fields, raw FROM fengtu.events WHERE " +
		"case_id = ? AND JSONExtractString(fields, ?) IN (?, ?)" +
		" ORDER BY source_id, line_no LIMIT ? OFFSET ?"
	if sql != want {
		t.Fatalf("SQL 不符:\n got %s\nwant %s", sql, want)
	}
	if !reflect.DeepEqual(args, []any{"c1", "status", "200", "204", defaultLimit, 0}) {
		t.Fatalf("参数不符: %v", args)
	}
}

func TestBuildSearchSQLDefaults(t *testing.T) {
	sql, args := mustSQL(t, Params{CaseID: "c1"})
	if !strings.Contains(sql, "LIMIT ? OFFSET ?") {
		t.Fatalf("缺分页: %s", sql)
	}
	if !reflect.DeepEqual(args, []any{"c1", defaultLimit, 0}) {
		t.Fatalf("默认参数不符: %v", args)
	}
	// limit 超上限压到 1000
	_, args = mustSQL(t, Params{CaseID: "c1", Limit: 99999})
	if args[len(args)-2] != maxLimit {
		t.Fatalf("limit 上限未压: %v", args)
	}
}

func TestValidateNegative(t *testing.T) {
	cases := []Params{
		{}, // 缺 case_id
		{CaseID: "c1", Conds: []FieldCond{{Field: "x;DROP", Op: OpEq, Values: []string{"v"}}}},
		{CaseID: "c1", Conds: []FieldCond{{Field: "ua", Op: "regex", Values: []string{"v"}}}},
		{CaseID: "c1", Conds: []FieldCond{{Field: "ua", Op: OpEq}}},
		{CaseID: "c1", Conds: []FieldCond{{Field: "ua", Op: OpEq, Values: []string{""}}}},
		{CaseID: "c1", Offset: -1},
	}
	for i, p := range cases {
		if _, _, err := BuildSearchSQL(p); err == nil {
			t.Fatalf("负样本 #%d 应拒绝: %+v", i, p)
		}
	}
	from := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	if _, _, err := BuildSearchSQL(Params{CaseID: "c1", TSFrom: &from, TSTo: &to}); err == nil {
		t.Fatal("时间窗颠倒应拒绝")
	}
}

func TestBuildScanSQLKindEventOnly(t *testing.T) {
	sql, args, err := BuildScanSQL(Params{
		CaseID: "c1",
		Conds:  []FieldCond{{Field: "ua", Op: OpContains, Values: []string{"sqlmap"}}},
	})
	if err != nil {
		t.Fatalf("BuildScanSQL 失败: %v", err)
	}
	if !strings.Contains(sql, "kind = ?") {
		t.Fatalf("扫描须只扫 event 行: %s", sql)
	}
	if strings.Contains(sql, "LIMIT") {
		t.Fatalf("扫描流不该分页: %s", sql)
	}
	if !reflect.DeepEqual(args, []any{"c1", "event", "ua", "sqlmap"}) {
		t.Fatalf("扫描参数不符: %v", args)
	}
}

// fakeQuerier 记录 SQL/参数,返回罐头行(服务层通路 + 只读性检查)。
type fakeQuerier struct {
	gotSQL  string
	gotArgs []any
	rows    []Event
}

func (f *fakeQuerier) QueryEvents(_ context.Context, sql string, args ...any) ([]Event, error) {
	f.gotSQL, f.gotArgs = sql, args
	return f.rows, nil
}

func (f *fakeQuerier) StreamEvents(_ context.Context, sql string, args []any, fn func(Event) error) error {
	f.gotSQL, f.gotArgs = sql, args
	for _, e := range f.rows {
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

func TestServiceReadOnlyPassthrough(t *testing.T) {
	fq := &fakeQuerier{rows: []Event{{SourceID: "s1", LineNo: 42, Kind: "event"}}}
	s := NewService(fq)
	rows, err := s.Search(context.Background(), Params{CaseID: "c1", Q: "x"})
	if err != nil {
		t.Fatalf("Search 失败: %v", err)
	}
	if len(rows) != 1 || rows[0].LineNo != 42 {
		t.Fatalf("结果不符: %v", rows)
	}
	upper := strings.ToUpper(fq.gotSQL)
	if !strings.HasPrefix(upper, "SELECT") ||
		strings.Contains(upper, "INSERT") || strings.Contains(upper, "ALTER") ||
		strings.Contains(upper, "DROP") || strings.Contains(upper, "DELETE") ||
		strings.Contains(upper, "UPDATE") {
		t.Fatalf("检索层必须只读: %s", fq.gotSQL)
	}
	var streamed int
	if err := s.StreamMatch(context.Background(),
		Params{CaseID: "c1", Conds: []FieldCond{{Field: "ua", Op: OpContains, Values: []string{"x"}}}},
		func(Event) error { streamed++; return nil }); err != nil {
		t.Fatalf("StreamMatch 失败: %v", err)
	}
	if streamed != 1 {
		t.Fatalf("流式行数不符: %d", streamed)
	}
}
