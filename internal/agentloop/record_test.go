// 录制挂钩契约测试(切片十):档位语义(off 不录/metadata 默认只记元数据/
// full 录全文)、token/耗时/成败落账、录制失败不杀 loop。零 AI 调用:
// provider 全是脚本化 mock。
package agentloop

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"

	"github.com/ye-mengwen/fengtu/internal/ingest/store"
)

// stubRecorder 录制落库 stub(可注入失败,验「失败只 warn 不杀 loop」)。
type stubRecorder struct {
	mu   sync.Mutex
	recs []store.LLMRecord
	err  error
}

func (s *stubRecorder) InsertLLMRecord(_ context.Context, r *store.LLMRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.recs = append(s.recs, *r)
	return nil
}

func drainStream(t *testing.T, seq func(func(llm.StreamEvent, error) bool)) {
	t.Helper()
	for _, err := range seq {
		if err != nil {
			t.Fatalf("流事件错误: %v", err)
		}
	}
}

func newRecordProvider(inner llm.Provider, rec *stubRecorder, mode string,
	warns *[]string) *recordingProvider {

	return &recordingProvider{
		inner: inner,
		sess:  &store.AISession{ID: "sess-1", CaseID: "case-1"},
		kind:  "chat",
		model: "deepseek-chat",
		rec:   rec,
		mode:  func() string { return mode },
		now:   time.Now,
		onWarn: func(m string) {
			*warns = append(*warns, m)
		},
	}
}

func TestRecordMetadataMode(t *testing.T) {
	rec := &stubRecorder{}
	var warns []string
	p := newRecordProvider(&mockProvider{turns: []scriptTurn{
		{text: "结论草稿", in: 120, out: 34}}}, rec, "metadata", &warns)

	drainStream(t, p.Stream(context.Background(), llm.CompletionRequest{
		Messages: []llm.Message{llm.UserText("看看有无可疑进程")}}))

	if len(rec.recs) != 1 {
		t.Fatalf("应落 1 条录制账: %d", len(rec.recs))
	}
	r := rec.recs[0]
	if r.SessionID != "sess-1" || r.CaseID != "case-1" || r.Kind != "chat" {
		t.Fatalf("会话/案件锚不符: %+v", r)
	}
	if r.TokensIn != 120 || r.TokensOut != 34 || r.Status != "ok" {
		t.Fatalf("token/状态不符: %+v", r)
	}
	if r.Model != "deepseek-chat" {
		t.Fatalf("模型不符: %+v", r)
	}
	if r.Prompt != nil || r.Response != nil {
		t.Fatalf("metadata 档不该录全文: %+v", r)
	}
	if len(warns) != 0 {
		t.Fatalf("不该有 warn: %v", warns)
	}
}

func TestRecordFullMode(t *testing.T) {
	rec := &stubRecorder{}
	var warns []string
	p := newRecordProvider(&mockProvider{turns: []scriptTurn{
		{text: "发现可疑", in: 10, out: 5}}}, rec, "full", &warns)

	drainStream(t, p.Stream(context.Background(), llm.CompletionRequest{
		Messages: []llm.Message{llm.UserText("查一下")}}))

	if len(rec.recs) != 1 {
		t.Fatalf("应落 1 条: %d", len(rec.recs))
	}
	r := rec.recs[0]
	if r.Prompt == nil || r.Response == nil {
		t.Fatalf("full 档应录全文: %+v", r)
	}
	if *r.Response != "发现可疑" {
		t.Fatalf("response 全文不符: %q", *r.Response)
	}
	if *r.Prompt == "" {
		t.Fatalf("prompt 应含 messages JSON")
	}
}

func TestRecordOffMode(t *testing.T) {
	rec := &stubRecorder{}
	var warns []string
	p := newRecordProvider(&mockProvider{turns: []scriptTurn{
		{text: "x", in: 1, out: 1}}}, rec, "off", &warns)

	drainStream(t, p.Stream(context.Background(), llm.CompletionRequest{}))
	if len(rec.recs) != 0 {
		t.Fatalf("off 档不该落账: %d", len(rec.recs))
	}
}

func TestRecordErrorStatus(t *testing.T) {
	rec := &stubRecorder{}
	var warns []string
	inner := &mockProvider{blockFn: func(_ context.Context,
		yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{}, fmt.Errorf("厂商 500"))
	}}
	p := newRecordProvider(inner, rec, "metadata", &warns)

	// 错误事件照常透传给消费侧(不吞)
	var gotErr error
	for _, err := range p.Stream(context.Background(), llm.CompletionRequest{}) {
		if err != nil {
			gotErr = err
		}
	}
	if gotErr == nil {
		t.Fatal("错误应透传")
	}
	if len(rec.recs) != 1 || rec.recs[0].Status != "error" {
		t.Fatalf("错误调用应落 error 账: %+v", rec.recs)
	}
}

func TestRecordFailureDoesNotKillLoop(t *testing.T) {
	rec := &stubRecorder{err: fmt.Errorf("PG 挂了")}
	var warns []string
	p := newRecordProvider(&mockProvider{turns: []scriptTurn{
		{text: "正文", in: 3, out: 2}}}, rec, "metadata", &warns)

	drainStream(t, p.Stream(context.Background(), llm.CompletionRequest{}))
	if len(warns) != 1 {
		t.Fatalf("落账失败应 warn 一次: %v", warns)
	}
}

func TestRecordUnknownModeFallsBackMetadata(t *testing.T) {
	rec := &stubRecorder{}
	var warns []string
	p := newRecordProvider(&mockProvider{turns: []scriptTurn{
		{text: "x", in: 1, out: 1}}}, rec, "weird", &warns)

	drainStream(t, p.Stream(context.Background(), llm.CompletionRequest{}))
	if len(rec.recs) != 1 {
		t.Fatalf("未知档位应如实按默认 metadata 落账: %d", len(rec.recs))
	}
	if rec.recs[0].Prompt != nil {
		t.Fatalf("未知档位回落 metadata 不该录全文")
	}
}
