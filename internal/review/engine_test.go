// 规则引擎焊死:YAML 装载正负样本/match 语义(AND·OR·大小写·声明序)/
// 扫描闭环(轮次递增·候选 pending·去重幂等·预算帽)/裁决通路。
package review

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ye-mengwen/fengtu/internal/query"
)

// ---- fake 存储与检索 ----

type fakeStore struct {
	mu       sync.Mutex // 并发裁决测试:fake 也须并发安全,否则竞态测试无效
	rounds   map[string]int // caseID → 已用最大轮次
	runs     []ScanRun
	hits     []Hit
	hitIndex map[string]bool // sourceID|lineNo|ruleID 去重键
	sources  []ScanSource    // 适用域路由源清单(测试注入)
}

func newFakeStore() *fakeStore {
	return &fakeStore{rounds: map[string]int{}, hitIndex: map[string]bool{}}
}

func (f *fakeStore) CreateScanRun(_ context.Context, caseID, actor, ruleIDsJSON string, now time.Time) (string, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rounds[caseID]++
	round := f.rounds[caseID]
	id := strings.Repeat("r", 8) + string(rune('0'+round))
	f.runs = append(f.runs, ScanRun{ID: id, CaseID: caseID, RoundNo: round,
		RuleIDsJSON: ruleIDsJSON, Actor: actor, CreatedAt: now})
	return id, round, nil
}

func (f *fakeStore) InsertHit(_ context.Context, h Hit, now time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := h.SourceID + "|" + strconv.Itoa(h.LineNo) + "|" + h.RuleID
	if f.hitIndex[key] {
		return false, nil
	}
	f.hitIndex[key] = true
	h.ID = key
	h.CreatedAt = now
	f.hits = append(f.hits, h)
	return true, nil
}

func (f *fakeStore) FinishScanRun(_ context.Context, runID, summaryJSON string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.runs {
		if f.runs[i].ID == runID {
			f.runs[i].SummaryJSON = summaryJSON
		}
	}
	return nil
}

func (f *fakeStore) ListHits(_ context.Context, caseID string, fl HitFilter) ([]Hit, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Hit
	for _, h := range f.hits {
		if h.CaseID != caseID {
			continue
		}
		if fl.Status != "" && h.Status != fl.Status {
			continue
		}
		if fl.Round != 0 && h.RoundNo != fl.Round {
			continue
		}
		out = append(out, h)
	}
	return out, nil
}

func (f *fakeStore) GetHit(_ context.Context, id string) (*Hit, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.hits {
		if f.hits[i].ID == id {
			cp := f.hits[i]
			return &cp, nil
		}
	}
	return nil, nil
}

// SetVerdict 人裁决(fake 真模拟 CAS:仅 pending 可落——与 PG
// `AND status='pending'` 同语义;已被裁决/无此行都返回 ok=false,
// 区分在引擎侧回查)。
func (f *fakeStore) SetVerdict(_ context.Context, id, actor, status, note string, now time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.hits {
		if f.hits[i].ID == id {
			if f.hits[i].Status != "pending" {
				return false, nil
			}
			f.hits[i].Status = status
			f.hits[i].ReviewedBy = actor
			f.hits[i].ReviewedAt = &now
			f.hits[i].ReviewNote = note
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeStore) ListScanRuns(_ context.Context, caseID string) ([]ScanRun, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]ScanRun, len(f.runs))
	copy(out, f.runs)
	return out, nil
}

func (f *fakeStore) ListSourcesForScan(context.Context, string) ([]ScanSource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sources, nil
}

func (f *fakeStore) RuleStatsRaw(_ context.Context, caseID string, since time.Time) ([]RuleStat, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	agg := map[string]*RuleStat{}
	var order []string
	for _, h := range f.hits {
		if h.CaseID != caseID || h.CreatedAt.Before(since) {
			continue
		}
		st := agg[h.RuleID]
		if st == nil {
			st = &RuleStat{RuleID: h.RuleID}
			agg[h.RuleID] = st
			order = append(order, h.RuleID)
		}
		st.Candidates++
		switch h.Status {
		case "accepted":
			st.Accepted++
		case "rejected":
			st.Rejected++
		default:
			st.Pending++
		}
	}
	var out []RuleStat
	for _, id := range order {
		out = append(out, *agg[id])
	}
	return out, nil
}

type fakeQuerier struct{ rows []query.Event }

func (f *fakeQuerier) QueryEvents(context.Context, string, ...any) ([]query.Event, error) {
	return f.rows, nil
}

func (f *fakeQuerier) StreamEvents(_ context.Context, _ string, _ []any, fn func(query.Event) error) error {
	for _, e := range f.rows {
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

// ---- 规则装载 ----

const scannerUAYAML = `
id: scanner-ua
title: 扫描器 User-Agent 特征
severity: medium
target: any
match:
  ua:
    - "sqlmap"
    - "nikto"
note: 公开工具指纹,UA 可伪造,命中只说明「自称」
max_hits: 3
`

func TestCompileRuleOK(t *testing.T) {
	r, err := CompileRule("t.yaml", scannerUAYAML)
	if err != nil {
		t.Fatalf("规则编译失败: %v", err)
	}
	if r.ID != "scanner-ua" || r.Severity != "medium" || r.MaxHits != 3 {
		t.Fatalf("规则字段不符: %+v", r)
	}
	if len(r.Match) != 1 || r.Match[0].Field != "ua" ||
		len(r.Match[0].Subs) != 2 || r.Match[0].Subs[0] != "sqlmap" {
		t.Fatalf("match 编译不符(声明序须保留): %+v", r.Match)
	}
}

func TestCompileRuleNegative(t *testing.T) {
	bad := []string{
		`id: x`, // 缺必填键
		`id: "BAD ID"
title: t
severity: medium
target: any
match: {ua: [x]}`,
		`id: ok-id
title: t
severity: critical
target: any
match: {ua: [x]}`, // severity 非法
		`id: ok-id
title: t
severity: medium
target: web
match: {ua: [x]}`, // target=web 未实现,拒载不猜
		`id: ok-id
title: t
severity: medium
target: any
match: {evil_field: [x]}`, // 未知匹配字段
		`id: ok-id
title: t
severity: medium
target: any
match: {}`, // 空 match
		`id: ok-id
title: t
severity: medium
target: any
match: {ua: [x]}
bogus_key: 1`, // 未知顶层键
	}
	for i, text := range bad {
		if _, err := CompileRule("bad.yaml", text); err == nil {
			t.Fatalf("负样本 #%d 应拒载", i)
		}
	}
}

// ---- match 语义 ----

func TestMatchRuleSemantics(t *testing.T) {
	r, err := CompileRule("t.yaml", `
id: multi
title: t
severity: low
target: any
match:
  method: ["GET"]
  ua: ["Nikto", "sqlmap"]
`)
	if err != nil {
		t.Fatalf("规则编译失败: %v", err)
	}
	// AND:两字段都命中才命中;大小写不敏感
	f, v, ok := matchRule(r, `{"method":"get","ua":"Nikto/2.1"}`, "")
	if !ok || f != "method" || v != "get" {
		t.Fatalf("AND+大小写语义不符: %q %q %v", f, v, ok)
	}
	// 声明序第一个命中字段记 matched_field
	if _, _, ok := matchRule(r, `{"method":"POST","ua":"sqlmap"}`, ""); ok {
		t.Fatal("method 不命中应整体不命中(AND)")
	}
	// raw 字段兜底整行
	r2, _ := CompileRule("t2.yaml", `
id: rawr
title: t
severity: low
target: any
match:
  raw: ["etc/passwd"]
`)
	if _, _, ok := matchRule(r2, `{}`, "GET /../../etc/passwd HTTP/1.1"); !ok {
		t.Fatal("raw 兜底应命中整行")
	}
}

// ---- 扫描闭环 ----

func TestScanRoundTrip(t *testing.T) {
	st := newFakeStore()
	fq := &fakeQuerier{rows: []query.Event{
		{SourceID: "s1", LineNo: 10, Kind: "event", Fields: `{"ua":"sqlmap/1.7"}`, Raw: "GET / sqlmap/1.7"},
		{SourceID: "s1", LineNo: 11, Kind: "event", Fields: `{"ua":"Mozilla/5.0"}`, Raw: "GET / Mozilla"},
		{SourceID: "s2", LineNo: 3, Kind: "event", Fields: `{"ua":"Nikto"}`, Raw: "GET / Nikto"},
	}}
	r, _ := CompileRule("t.yaml", scannerUAYAML)
	eng, err := NewEngine([]*Rule{r}, query.NewService(fq), st)
	if err != nil {
		t.Fatalf("引擎构造失败: %v", err)
	}
	ctx := context.Background()

	sum, err := eng.Scan(ctx, "case-1", "alice", nil)
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	if sum.RoundNo != 1 || len(sum.Rules) != 1 {
		t.Fatalf("轮次账不符: %+v", sum)
	}
	rs := sum.Rules[0]
	if rs.HitsNew != 2 || rs.HitsDup != 0 {
		t.Fatalf("首轮应新增 2 候选: %+v", rs)
	}
	hits, _ := eng.Hits(ctx, "case-1", HitFilter{Status: "pending"})
	if len(hits) != 2 {
		t.Fatalf("待审区应有 2 条 pending: %d", len(hits))
	}
	for _, h := range hits {
		if h.Status != "pending" || h.RoundNo != 1 {
			t.Fatalf("候选状态/轮次不符: %+v", h)
		}
		if !strings.Contains(h.DetailJSON, "命中≠结论") {
			t.Fatalf("候选 detail 缺判断权声明: %s", h.DetailJSON)
		}
	}

	// 重跑:轮次递增 + 去重幂等(hits_new=0)
	sum2, err := eng.Scan(ctx, "case-1", "alice", nil)
	if err != nil {
		t.Fatalf("重跑失败: %v", err)
	}
	if sum2.RoundNo != 2 {
		t.Fatalf("轮次应递增: %+v", sum2)
	}
	if sum2.Rules[0].HitsNew != 0 || sum2.Rules[0].HitsDup != 2 {
		t.Fatalf("重跑应全去重: %+v", sum2.Rules[0])
	}
}

func TestScanBudgetCap(t *testing.T) {
	st := newFakeStore()
	var rows []query.Event
	for i := 1; i <= 5; i++ {
		rows = append(rows, query.Event{
			SourceID: "s1", LineNo: i, Kind: "event",
			Fields: `{"ua":"sqlmap"}`, Raw: "x sqlmap",
		})
	}
	fq := &fakeQuerier{rows: rows}
	r, _ := CompileRule("t.yaml", scannerUAYAML) // max_hits: 3
	eng, _ := NewEngine([]*Rule{r}, query.NewService(fq), st)
	sum, err := eng.Scan(context.Background(), "case-1", "alice", nil)
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	rs := sum.Rules[0]
	if rs.HitsNew != 3 || rs.Truncated != 2 {
		t.Fatalf("预算帽应截断: %+v", rs)
	}
}

func TestVerdict(t *testing.T) {
	st := newFakeStore()
	fq := &fakeQuerier{rows: []query.Event{
		{SourceID: "s1", LineNo: 10, Kind: "event", Fields: `{"ua":"sqlmap"}`, Raw: "x"},
	}}
	r, _ := CompileRule("t.yaml", scannerUAYAML)
	eng, _ := NewEngine([]*Rule{r}, query.NewService(fq), st)
	ctx := context.Background()
	if _, err := eng.Scan(ctx, "case-1", "alice", nil); err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	hits, _ := eng.Hits(ctx, "case-1", HitFilter{})
	if len(hits) != 1 {
		t.Fatalf("应有 1 条候选: %d", len(hits))
	}
	// 非法状态
	if _, err := eng.Verdict(ctx, hits[0].ID, "bob", "pending", ""); err == nil {
		t.Fatal("裁决回 pending 应拒绝")
	}
	if _, err := eng.Verdict(ctx, "no-such", "bob", "accepted", ""); err == nil {
		t.Fatal("无此候选应报错")
	}
	h, err := eng.Verdict(ctx, hits[0].ID, "bob", "accepted", "实锤扫描器")
	if err != nil {
		t.Fatalf("裁决失败: %v", err)
	}
	if h.Status != "accepted" || h.ReviewedBy != "bob" || h.ReviewNote != "实锤扫描器" {
		t.Fatalf("裁决账不符: %+v", h)
	}
	// pending 过滤应查不到
	pending, _ := eng.Hits(ctx, "case-1", HitFilter{Status: "pending"})
	if len(pending) != 0 {
		t.Fatal("裁决后 pending 应清空")
	}
}
