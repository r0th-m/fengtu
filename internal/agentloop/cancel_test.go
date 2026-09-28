// Cancel(steer 纠偏底座,交互改造切片三)焊死:中断在跑 loop 但不动会话账
// (会话保持 active 可续跑,transcript 延续)——与 Abort(标 aborted 终态)
// 的区别就是这条契约。
package agentloop

import (
	"context"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"
)

func TestCancelKeepsSessionActive(t *testing.T) {
	mp := &mockProvider{
		blockFn: func(ctx context.Context, yield func(llm.StreamEvent, error) bool) {
			for {
				select {
				case <-ctx.Done():
					yield(llm.StreamEvent{}, ctx.Err())
					return
				default:
					if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "…"}, nil) {
						return
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
		},
	}
	svc, meta, _, _, _ := testService(t, mp)
	ctx := context.Background()
	sess, err := svc.CreateSession(ctx, "case-1", "tester")
	if err != nil {
		t.Fatal(err)
	}
	ch, err := svc.Run(ctx, sess.ID, "长跑")
	if err != nil {
		t.Fatal(err)
	}
	first := <-ch
	if first.Kind != "text" && first.Kind != "thinking" {
		t.Fatalf("首个事件应为文本: %+v", first)
	}
	if err := svc.Cancel(ctx, sess.ID); err != nil {
		t.Fatalf("cancel 失败: %v", err)
	}
	done := make(chan []Event, 1)
	go func() { done <- drain(ch) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("cancel 后事件流未在 10s 内收尾")
	}
	// 与 Abort 的区别:会话账不动(保持 active),不记 ai.session.abort 审计
	got, _ := meta.GetAISession(ctx, sess.ID)
	if got.Status != "active" {
		t.Fatalf("Cancel 不应动会话账(应 active): %s", got.Status)
	}
	// 会话可续跑(steer 续跑语义;transcript 已在盘走 Resume)
	mp2 := &mockProvider{turns: []scriptTurn{{text: "纠偏后接着查", in: 1, out: 1}}}
	svc.deps.NewProvider = func(llm.Config) (llm.Provider, error) { return mp2, nil }
	evs := drain(mustRun(t, svc, sess.ID, "纠偏后接着查"))
	if kinds(evs)[len(evs)-1] != "result" {
		t.Fatalf("续跑应正常收尾: %v", kinds(evs))
	}
	// Cancel 幂等:没在跑即无操作
	if err := svc.Cancel(ctx, sess.ID); err != nil {
		t.Fatalf("Cancel 应幂等: %v", err)
	}
}

func mustRun(t *testing.T, svc *Service, id, prompt string) <-chan Event {
	t.Helper()
	ch, err := svc.Run(context.Background(), id, prompt)
	if err != nil {
		t.Fatalf("续跑失败: %v", err)
	}
	return ch
}
