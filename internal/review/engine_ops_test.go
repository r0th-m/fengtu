// 引擎×算子集成焊死:适用域路由(混源案件各族互不越界)/按域跳过账/
// evidence_grade 落库/未实现算子只注册/指定规则集扫描不夹带算子/
// RuleStats 接受率与待复审闸。
package review

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ye-mengwen/fengtu/internal/operator"
	"github.com/ye-mengwen/fengtu/internal/query"
)

// sourceAwareQuerier 按扫描 SQL 的 source_id 过滤(args 第三参;
// BuildScanSQL 形态:case_id, kind, source_id?)。
type sourceAwareQuerier struct{ rows []query.Event }

func (q *sourceAwareQuerier) QueryEvents(context.Context, string, ...any) ([]query.Event, error) {
	return q.rows, nil
}

func (q *sourceAwareQuerier) StreamEvents(_ context.Context, _ string, args []any,
	fn func(query.Event) error) error {
	sourceID := ""
	if len(args) >= 3 {
		sourceID, _ = args[2].(string)
	}
	for _, e := range q.rows {
		if sourceID != "" && e.SourceID != sourceID {
			continue
		}
		if e.Kind != "event" { // BuildScanSQL 恒 kind='event'
			continue
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

const opsTestYAML = `
id: web-bruteforce-chain
title: 爆破链
family: web
severity: high
applicable_to:
  log_types: [web_access]
params:
  fail_threshold: 2
  window_lines: 10
  window_seconds: 600
  fail_status: ["401"]
  success_status: ["200"]
implemented: true
`

const opsUnimplYAML = `
id: web-outlier
title: 离群
family: web
severity: low
applicable_to:
  log_types: [web_access]
implemented: false
`

func opsRegistry(t *testing.T) *operator.Registry {
	t.Helper()
	dir := t.TempDir()
	for name, text := range map[string]string{
		"a.yaml": opsTestYAML, "b.yaml": opsUnimplYAML,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	reg, err := operator.LoadDir(dir)
	if err != nil {
		t.Fatalf("算子注册表装载失败: %v", err)
	}
	return reg
}

// TestScanOperatorsDomainRouting 全量扫描:算子按适用域路由,各族互不越界。
func TestScanOperatorsDomainRouting(t *testing.T) {
	st := newFakeStore()
	st.sources = []ScanSource{
		{ID: "s-web", Kind: "text", LogType: "web_access"},
		{ID: "s-evtx", Kind: "evtx", LogType: "windows_event_log"},
		{ID: "s-nocat", Kind: "text"},
	}
	rows := []query.Event{
		{SourceID: "s-web", LineNo: 1, Kind: "event",
			Fields: `{"src_ip":"203.0.113.70","status":"401"}`},
		{SourceID: "s-web", LineNo: 2, Kind: "event",
			Fields: `{"src_ip":"203.0.113.70","status":"401"}`},
		{SourceID: "s-web", LineNo: 3, Kind: "event",
			Fields: `{"src_ip":"203.0.113.70","status":"200"}`},
		// evtx 源同类形态事件(web 算子不应越界来吃)
		{SourceID: "s-evtx", LineNo: 1, Kind: "event",
			Fields: `{"src_ip":"203.0.113.70","status":"401"}`},
		{SourceID: "s-evtx", LineNo: 2, Kind: "event",
			Fields: `{"src_ip":"203.0.113.70","status":"401"}`},
		{SourceID: "s-evtx", LineNo: 3, Kind: "event",
			Fields: `{"src_ip":"203.0.113.70","status":"200"}`},
	}
	rule, err := CompileRule("r.yaml", `
id: demo-rule
title: x
severity: low
target: any
match:
  raw: ["绝不存在于任何事件的词"]
`)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine([]*Rule{rule},
		query.NewService(&sourceAwareQuerier{rows: rows}), st)
	if err != nil {
		t.Fatal(err)
	}
	e.SetOperators(opsRegistry(t))

	sum, err := e.Scan(context.Background(), "case-1", "tester", nil)
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	if len(sum.Operators) != 2 {
		t.Fatalf("两个注册算子都应在账上: %+v", sum.Operators)
	}
	var bf, outlier OperatorSummary
	for _, os := range sum.Operators {
		switch os.OpID {
		case "web-bruteforce-chain":
			bf = os
		case "web-outlier":
			outlier = os
		}
	}
	// 适用域路由:web 算子只实例化 web 源,evtx/无品类源按域跳过
	if bf.MatchedSources != 1 || bf.SkippedDomain != 2 {
		t.Fatalf("适用域路由账错: %+v", bf)
	}
	// 命中只锚在 web 源(evtx 源同形态事件不被越界吃)
	if bf.HitsNew != 1 {
		t.Fatalf("爆破链应 1 命中: %+v", bf)
	}
	hits, _ := st.ListHits(context.Background(), "case-1", HitFilter{})
	for _, h := range hits {
		if h.RuleID == "web-bruteforce-chain" {
			if h.SourceID != "s-web" {
				t.Fatalf("web 算子越界命中 evtx 源: %+v", h)
			}
			if h.EvidenceGrade != "strong" {
				t.Fatalf("爆破链证据等级应为 strong: %s", h.EvidenceGrade)
			}
		}
	}
	// 未实现算子只注册不实例化,如实标
	if outlier.Implemented || outlier.Note == "" {
		t.Fatalf("未实现算子账应如实标: %+v", outlier)
	}

	// 幂等:重跑 hits_new=0
	sum2, err := e.Scan(context.Background(), "case-1", "tester", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, os := range sum2.Operators {
		if os.OpID == "web-bruteforce-chain" && (os.HitsNew != 0 || os.HitsDup != 1) {
			t.Fatalf("重跑去重幂等: %+v", os)
		}
	}
}

// TestFilteredScanSkipsOperators 指定规则集扫描不夹带算子(轮次语义:
// 勾什么扫什么)。
func TestFilteredScanSkipsOperators(t *testing.T) {
	st := newFakeStore()
	st.sources = []ScanSource{{ID: "s-web", Kind: "text", LogType: "web_access"}}
	rule, err := CompileRule("r.yaml", `
id: demo-rule
title: x
severity: low
target: any
match:
  raw: ["不存在的词"]
`)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine([]*Rule{rule},
		query.NewService(&sourceAwareQuerier{}), st)
	if err != nil {
		t.Fatal(err)
	}
	e.SetOperators(opsRegistry(t))
	sum, err := e.Scan(context.Background(), "case-1", "tester", []string{"demo-rule"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.Operators) != 0 {
		t.Fatalf("指定规则集扫描不应跑算子: %+v", sum.Operators)
	}
}

// TestRuleStats 接受率与待复审闸(近 90 天窗)。
func TestRuleStats(t *testing.T) {
	st := newFakeStore()
	rule, err := CompileRule("r.yaml", `
id: noisy-rule
title: x
severity: low
target: any
match:
  raw: ["不存在的词"]
`)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine([]*Rule{rule},
		query.NewService(&sourceAwareQuerier{}), st)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	// noisy-rule:12 条全 rejected(裁决 ≥10 且接受率 0 → 待复审)
	for i := 0; i < 12; i++ {
		if _, err := st.InsertHit(context.Background(), Hit{
			CaseID: "case-1", SourceID: "s1", LineNo: i + 1,
			RuleID: "noisy-rule", Status: "rejected",
		}, now); err != nil {
			t.Fatal(err)
		}
	}
	// ok-rule:3 接受 1 拒绝(接受率 0.75)
	for i := 0; i < 4; i++ {
		status := "accepted"
		if i == 3 {
			status = "rejected"
		}
		if _, err := st.InsertHit(context.Background(), Hit{
			CaseID: "case-1", SourceID: "s2", LineNo: i + 1,
			RuleID: "ok-rule", Status: status,
		}, now); err != nil {
			t.Fatal(err)
		}
	}
	// young-rule:3 条全 rejected(样本 <10,不判待复审——防误杀新规则)
	for i := 0; i < 3; i++ {
		if _, err := st.InsertHit(context.Background(), Hit{
			CaseID: "case-1", SourceID: "s3", LineNo: i + 1,
			RuleID: "young-rule", Status: "rejected",
		}, now); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := e.RuleStats(context.Background(), "case-1",
		now.Add(-90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]RuleStat{}
	for _, s := range stats {
		byID[s.RuleID] = s
	}
	noisy := byID["noisy-rule"]
	if !noisy.NeedsReview || noisy.AcceptanceRate == nil || *noisy.AcceptanceRate != 0 {
		t.Fatalf("noisy-rule 应待复审且接受率 0: %+v", noisy)
	}
	ok := byID["ok-rule"]
	if ok.NeedsReview || ok.AcceptanceRate == nil || *ok.AcceptanceRate != 0.75 {
		t.Fatalf("ok-rule 接受率应 0.75 不待复审: %+v", ok)
	}
	young := byID["young-rule"]
	if young.NeedsReview {
		t.Fatalf("样本不足不应判待复审(防误杀新规则): %+v", young)
	}
	// 窗口外不统计
	statsOld, err := e.RuleStats(context.Background(), "case-1",
		now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range statsOld {
		if s.Candidates != 0 {
			t.Fatalf("窗口外应零统计: %+v", s)
		}
	}
}
