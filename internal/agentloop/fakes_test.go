// agentloop 单测 fakes:PG 元数据面/CH 事件面/待审区存储/审计全部
// in-memory;mockProvider 脚本化(norma llm.Provider 线协议,不烧真钱)。
package agentloop

import (
	"context"
	"fmt"
	"iter"
	"sync"
	"time"

	"github.com/Autumn-27/norma/llm"

	"github.com/ye-mengwen/fengtu/internal/ingest/store"
	"github.com/ye-mengwen/fengtu/internal/query"
	"github.com/ye-mengwen/fengtu/internal/review"
)

// ---- fakeMeta(MetaStore) ----

type fakeMeta struct {
	mu       sync.Mutex
	cases    map[string]*store.Case
	sources  []store.Source
	sessions map[string]*store.AISession
	settings *store.AISettings
	seq      int

	ListSourcesCalls int
}

func newFakeMeta() *fakeMeta {
	return &fakeMeta{
		cases:    map[string]*store.Case{"case-1": {ID: "case-1", Name: "测试案"}},
		sessions: map[string]*store.AISession{},
	}
}

func (f *fakeMeta) GetCase(_ context.Context, id string) (*store.Case, error) {
	return f.cases[id], nil
}

func (f *fakeMeta) ListSources(_ context.Context, caseID string) ([]store.Source, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ListSourcesCalls++
	var out []store.Source
	for _, s := range f.sources {
		if s.CaseID == caseID {
			out = append(out, s)
		}
	}
	return out, nil
}

func (f *fakeMeta) GetSource(_ context.Context, id string) (*store.Source, error) {
	for _, s := range f.sources {
		if s.ID == id {
			cp := s
			return &cp, nil
		}
	}
	return nil, nil
}

func (f *fakeMeta) CreateAISession(_ context.Context, s *store.AISession) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	s.ID = fmt.Sprintf("sess-%d", f.seq)
	s.CreatedAt = time.Now().UTC()
	s.LastActiveAt = s.CreatedAt
	f.sessions[s.ID] = s
	return nil
}

func (f *fakeMeta) GetAISession(_ context.Context, id string) (*store.AISession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.sessions[id]
	if s == nil {
		return nil, nil
	}
	cp := *s
	return &cp, nil
}

func (f *fakeMeta) ListAISessions(_ context.Context, caseID string) ([]store.AISession, error) {
	var out []store.AISession
	for _, s := range f.sessions {
		if s.CaseID == caseID {
			out = append(out, *s)
		}
	}
	return out, nil
}

func (f *fakeMeta) TouchAISession(_ context.Context, id string, in, out int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.sessions[id]
	if s == nil {
		return fmt.Errorf("无此会话: %s", id)
	}
	if in > s.TokensIn {
		s.TokensIn = in
	}
	if out > s.TokensOut {
		s.TokensOut = out
	}
	return nil
}

func (f *fakeMeta) AbortAISession(_ context.Context, id string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.sessions[id]
	if s == nil {
		return false, nil
	}
	s.Status = "aborted"
	return true, nil
}

func (f *fakeMeta) GetAISettings(context.Context) (*store.AISettings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.settings == nil {
		return nil, nil
	}
	cp := *f.settings
	return &cp, nil
}

func (f *fakeMeta) SaveAISettings(_ context.Context, st *store.AISettings) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *st
	f.settings = &cp
	return nil
}

// ---- fakeEvents(query.Querier + query.StatsQuerier) ----

type fakeEvents struct {
	mu        sync.Mutex
	rows      []query.Event
	lastSQL   string
	lastArgs  []any
	statSQL   string
	statRows  []query.StatRow
	streamErr error
}

func (f *fakeEvents) QueryEvents(_ context.Context, sql string, args ...any) ([]query.Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastSQL, f.lastArgs = sql, args
	return f.rows, nil
}

func (f *fakeEvents) StreamEvents(_ context.Context, sql string, args []any,
	fn func(query.Event) error) error {
	if f.streamErr != nil {
		return f.streamErr
	}
	sourceID := ""
	for i, a := range args {
		if s, ok := a.(string); ok && i > 0 {
			// BuildScanSQL 参数序:case_id, kind, source_id?(见 query 包)
			if i == 2 {
				sourceID = s
			}
		}
	}
	for _, e := range f.rows {
		if sourceID != "" && e.SourceID != sourceID {
			continue
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeEvents) QueryStats(_ context.Context, sql string, _ ...any) ([]query.StatRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statSQL = sql
	return f.statRows, nil
}

// ---- fakeReviewStore(review.Store) ----

type fakeReviewStore struct {
	mu         sync.Mutex
	scanSrcs   []review.ScanSource
	hits       []review.Hit
	runs       []string // CreateScanRun 的 actor 记录
	rounds     int
	insertedID int
}

func (f *fakeReviewStore) CreateScanRun(_ context.Context, caseID, actor, _ string,
	_ time.Time) (string, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rounds++
	f.runs = append(f.runs, actor)
	return fmt.Sprintf("run-%d", f.rounds), f.rounds, nil
}

func (f *fakeReviewStore) InsertHit(_ context.Context, h review.Hit, _ time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ex := range f.hits {
		if ex.SourceID == h.SourceID && ex.LineNo == h.LineNo && ex.RuleID == h.RuleID {
			return false, nil
		}
	}
	f.insertedID++
	h.ID = fmt.Sprintf("hit-%d", f.insertedID)
	f.hits = append(f.hits, h)
	return true, nil
}

func (f *fakeReviewStore) FinishScanRun(context.Context, string, string) error { return nil }

func (f *fakeReviewStore) ListHits(_ context.Context, caseID string, fl review.HitFilter) ([]review.Hit, error) {
	var out []review.Hit
	for _, h := range f.hits {
		if h.CaseID == caseID && (fl.Status == "" || h.Status == fl.Status) {
			out = append(out, h)
		}
	}
	return out, nil
}

func (f *fakeReviewStore) GetHit(_ context.Context, id string) (*review.Hit, error) {
	for _, h := range f.hits {
		if h.ID == id {
			cp := h
			return &cp, nil
		}
	}
	return nil, nil
}

func (f *fakeReviewStore) SetVerdict(_ context.Context, id, actor, status, note string,
	_ time.Time) (bool, error) {
	for i, h := range f.hits {
		if h.ID == id {
			f.hits[i].Status = status
			f.hits[i].ReviewedBy = actor
			f.hits[i].ReviewNote = note
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeReviewStore) ListScanRuns(context.Context, string) ([]review.ScanRun, error) {
	return nil, nil
}

func (f *fakeReviewStore) ListSourcesForScan(context.Context, string) ([]review.ScanSource, error) {
	return f.scanSrcs, nil
}

func (f *fakeReviewStore) RuleStatsRaw(context.Context, string, time.Time) ([]review.RuleStat, error) {
	return nil, nil
}

// ---- fakeAudit ----

type auditRec struct {
	caseID, actor, action, scope string
	detail                       any
}

type fakeAudit struct {
	mu   sync.Mutex
	recs []auditRec
}

func (f *fakeAudit) AppendAudit(_ context.Context, caseID, actor, action, scope string,
	detail any) (int64, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recs = append(f.recs, auditRec{caseID, actor, action, scope, detail})
	return int64(len(f.recs)), "hash", nil
}

func (f *fakeAudit) byAction(action string) []auditRec {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []auditRec
	for _, r := range f.recs {
		if r.action == action {
			out = append(out, r)
		}
	}
	return out
}

// ---- mockProvider(norma llm.Provider 脚本化) ----

type scriptTurn struct {
	toolName  string // 空 = 纯文本终轮
	toolInput string
	text      string
	in, out   int
}

type mockProvider struct {
	mu         sync.Mutex
	turns      []scriptTurn
	calls      int
	toolSeen   []string // 各请求 advertised 的工具名(焊死「只注册只读六工具」)
	systemSeen []string // 各请求 system 段(焊死「意图上下文只能加码」)
	maxTokens  int      // 各请求 MaxTokens(厂商级预算层)
	// blockFn 非 nil 时接管 Stream(如 abort 测试:阻塞到 ctx 取消)
	blockFn func(ctx context.Context, yield func(llm.StreamEvent, error) bool)
}

func (m *mockProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		m.mu.Lock()
		i := m.calls
		m.calls++
		var names []string
		for _, t := range req.Tools {
			names = append(names, t.Name)
		}
		m.toolSeen = names
		m.systemSeen = append([]string{}, req.System...)
		m.maxTokens = req.MaxTokens
		m.mu.Unlock()
		if m.blockFn != nil {
			m.blockFn(ctx, yield)
			return
		}
		if i >= len(m.turns) {
			i = len(m.turns) - 1 // 重放末轮(应为 end_turn),防脚本耗尽死循环
		}
		turn := m.turns[i]
		if !yield(llm.StreamEvent{Type: llm.SEMessageStart}, nil) {
			return
		}
		if turn.toolName != "" {
			if !yield(llm.StreamEvent{Type: llm.SEToolUseStart, ToolID: "tu-1",
				ToolName: turn.toolName}, nil) {
				return
			}
			if !yield(llm.StreamEvent{Type: llm.SEToolInputJSON, Text: turn.toolInput}, nil) {
				return
			}
			yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "tool_use",
				Usage: llm.Usage{InputTokens: turn.in, OutputTokens: turn.out}}, nil)
		} else {
			if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: turn.text}, nil) {
				return
			}
			yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn",
				Usage: llm.Usage{InputTokens: turn.in, OutputTokens: turn.out}}, nil)
		}
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

func (m *mockProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{}, "", llm.Usage{}, fmt.Errorf("mock: Complete 未实现(测试只用 Stream)")
}
