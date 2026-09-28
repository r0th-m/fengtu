// loop 契约测试(mock provider,不烧真钱):
//   - 全链:建会话 → Run → 工具执行 → 文本终轮 → 审计锚点 → token 账 →
//     transcript 落盘 → 续聊 resume;
//   - 只读纪律:advertised 工具恰好是我们的六个只读工具(norma 默认
//     Write/Edit/Bash/后台任务工具一个都不在);
//   - 治理闸:外发关 403 语义/预算熔断/abort 中断。
package agentloop

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"

	"github.com/ye-mengwen/fengtu/internal/query"
	"github.com/ye-mengwen/fengtu/internal/review"
	"github.com/ye-mengwen/fengtu/internal/vault"
)

// testService 装配全 fake 的 Service(outbound 开,key 走 env 形态)。
func testService(t *testing.T, mp llm.Provider) (*Service, *fakeMeta, *fakeEvents,
	*fakeReviewStore, *fakeAudit) {
	t.Helper()
	return testServiceEnv(t, mp, map[string]string{
		"FENGTU_AI_API_KEY":  "sk-test",
		"FENGTU_AI_OUTBOUND": "true",
	})
}

// testServiceEnv 指定环境变量的装配(外发闸测试需要 env 不覆盖设置态)。
func testServiceEnv(t *testing.T, mp llm.Provider, env map[string]string) (*Service,
	*fakeMeta, *fakeEvents, *fakeReviewStore, *fakeAudit) {
	t.Helper()
	meta := newFakeMeta()
	events := &fakeEvents{}
	rs := &fakeReviewStore{}
	au := &fakeAudit{}
	rule, err := review.CompileRule("t.yaml", `
id: t-rule
title: t
severity: info
target: any
match:
  raw:
    - "x"
note: t
max_hits: 10
`)
	if err != nil {
		t.Fatalf("规则编译失败: %v", err)
	}
	qs := query.NewService(events)
	engine, err := review.NewEngine([]*review.Rule{rule}, qs, rs)
	if err != nil {
		t.Fatalf("引擎构造失败: %v", err)
	}
	v, err := vault.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(Deps{
		Meta: meta, Events: events, Query: qs, Review: engine,
		ReviewStore: rs, Vault: v, Audit: au,
		TranscriptDir: t.TempDir(),
		EnvLookup:     func(k string) string { return env[k] },
		NewProvider: func(llm.Config) (llm.Provider, error) { return mp, nil },
	})
	return svc, meta, events, rs, au
}

// drain 收完事件流。
func drain(ch <-chan Event) []Event {
	var out []Event
	for ev := range ch {
		out = append(out, ev)
	}
	return out
}

func kinds(evs []Event) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e.Kind)
	}
	return out
}

func TestLoopContract(t *testing.T) {
	mp := &mockProvider{turns: []scriptTurn{
		{toolName: "list_sources", toolInput: `{}`, in: 500, out: 50},
		{text: "疑似候选:无(已查源清单)", in: 800, out: 120},
	}}
	svc, meta, _, _, au := testService(t, mp)

	sess, err := svc.CreateSession(context.Background(), "case-1", "tester")
	if err != nil {
		t.Fatalf("建会话失败: %v", err)
	}
	if sess.BudgetTokens != 200000 {
		t.Fatalf("预算快照应为默认 20 万: %d", sess.BudgetTokens)
	}
	ch, err := svc.Run(context.Background(), sess.ID, "这个案件里有没有爆破迹象")
	if err != nil {
		t.Fatalf("Run 启动失败: %v", err)
	}
	evs := drain(ch)
	ks := kinds(evs)
	for _, want := range []string{"tool_use", "tool_result", "text", "result"} {
		found := false
		for _, k := range ks {
			if k == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("事件流缺 %s: %v", want, ks)
		}
	}
	// 工具真执行了(绑案件)
	if meta.ListSourcesCalls != 1 {
		t.Fatalf("list_sources 应执行 1 次: %d", meta.ListSourcesCalls)
	}
	// 只读纪律:advertised 工具恰好六个,无 norma 默认工具
	wantTools := map[string]bool{
		"search_events": true, "get_stats": true, "run_operator": true,
		"view_lines": true, "list_sources": true, "list_hits": true,
	}
	if len(mp.toolSeen) != 6 {
		t.Fatalf("advertised 工具应为 6 个: %v", mp.toolSeen)
	}
	for _, name := range mp.toolSeen {
		if !wantTools[name] {
			t.Fatalf("出现不该注册的工具: %s(%v)——norma 默认工具泄漏", name, mp.toolSeen)
		}
	}
	// 审计锚点:工具调用(名/耗时/行数)+ 消息汇总
	toolAudits := au.byAction("ai.tool_call")
	if len(toolAudits) != 1 || toolAudits[0].actor != "tester" ||
		toolAudits[0].caseID != "case-1" {
		t.Fatalf("工具审计锚点不符: %+v", toolAudits)
	}
	d, ok := toolAudits[0].detail.(map[string]any)
	if !ok || d["tool"] != "list_sources" {
		t.Fatalf("工具审计 detail 不符: %+v", toolAudits[0].detail)
	}
	if _, hasDur := d["duration_ms"]; !hasDur {
		t.Fatalf("工具审计缺耗时: %+v", d)
	}
	if msgs := au.byAction("ai.message"); len(msgs) != 1 {
		t.Fatalf("消息汇总审计应为 1 条: %d", len(msgs))
	}
	// token 账落 PG(norma usage 跨轮累计:500+800 / 50+120)
	got, _ := meta.GetAISession(context.Background(), sess.ID)
	if got.TokensIn != 1300 || got.TokensOut != 170 {
		t.Fatalf("token 账不符: in=%d out=%d", got.TokensIn, got.TokensOut)
	}
	// 终态文本如实
	var final *Event
	for i := range evs {
		if evs[i].Kind == "result" {
			final = &evs[i]
		}
	}
	if final == nil || !strings.Contains(final.Text, "疑似候选") {
		t.Fatalf("终态文本不符: %+v", final)
	}
}

// TestResume 续聊:同一会话第二条消息 resume transcript,消息史带着走。
func TestResume(t *testing.T) {
	mp := &mockProvider{turns: []scriptTurn{
		{text: "第一轮答复", in: 100, out: 10},
	}}
	svc, _, _, _, _ := testService(t, mp)
	sess, err := svc.CreateSession(context.Background(), "case-1", "tester")
	if err != nil {
		t.Fatal(err)
	}
	ch, err := svc.Run(context.Background(), sess.ID, "第一轮")
	if err != nil {
		t.Fatal(err)
	}
	drain(ch)
	// 第二条消息:resume 后模型应看到第一轮的用户消息
	ch, err = svc.Run(context.Background(), sess.ID, "第二轮")
	if err != nil {
		t.Fatal(err)
	}
	drain(ch)
	// resume 生效的硬证据:loop 正常跑完且 transcript 追加(两轮用户消息)
	// —— 消息史内容由 norma transcript 管理,此处焊「续聊不报错+可跑完」
	if mp.calls < 2 {
		t.Fatalf("应至少两次模型调用: %d", mp.calls)
	}
}

// TestHistory 历史回放:跑过一轮的会话,History 从 transcript 重建
// user/ai 问答对(交流区刷新重放的后端面);空会话回空片(非 nil/非错)。
func TestHistory(t *testing.T) {
	mp := &mockProvider{turns: []scriptTurn{
		{text: "第一轮答复", in: 100, out: 10},
	}}
	svc, _, _, _, _ := testService(t, mp)
	sess, err := svc.CreateSession(context.Background(), "case-1", "tester")
	if err != nil {
		t.Fatal(err)
	}
	// 空会话:零历史回 [](如实,不报错)
	msgs, err := svc.History(context.Background(), sess.ID)
	if err != nil {
		t.Fatalf("空会话历史回放失败: %v", err)
	}
	if msgs == nil || len(msgs) != 0 {
		t.Fatalf("空会话应回空片: %+v", msgs)
	}
	ch, err := svc.Run(context.Background(), sess.ID, "第一轮提问")
	if err != nil {
		t.Fatal(err)
	}
	drain(ch)
	msgs, err = svc.History(context.Background(), sess.ID)
	if err != nil {
		t.Fatalf("历史回放失败: %v", err)
	}
	var userSeen, aiSeen bool
	for _, m := range msgs {
		if m.Role == "user" && m.Text == "第一轮提问" {
			userSeen = true
		}
		if m.Role == "ai" && m.Text == "第一轮答复" {
			aiSeen = true
		}
		if m.Role != "user" && m.Role != "ai" {
			t.Fatalf("回放只许 user/ai 两档: %q", m.Role)
		}
	}
	if !userSeen || !aiSeen {
		t.Fatalf("回放缺问答: %+v", msgs)
	}
	// 无此会话如实拒
	if _, err := svc.History(context.Background(), "sess-none"); err == nil {
		t.Fatal("无此会话应报错")
	}
}

func TestOutboundGate(t *testing.T) {
	mp := &mockProvider{turns: []scriptTurn{{text: "x", in: 1, out: 1}}}
	// key 在 env;外发开关只走平台设置态(env 不覆盖)
	svc, _, _, _, _ := testServiceEnv(t, mp, map[string]string{
		"FENGTU_AI_API_KEY": "sk-test"})
	sess, _ := svc.CreateSession(context.Background(), "case-1", "tester")

	// 平台级外发关(默认 false)→ Run 启动前即拒(任何厂商调用前)
	_, err := svc.Run(context.Background(), sess.ID, "hi")
	if err == nil || !strings.Contains(err.Error(), "外发") {
		t.Fatalf("外发关应如实拒: %v", err)
	}
	if mp.calls != 0 {
		t.Fatalf("外发关时不许有任何厂商调用: %d", mp.calls)
	}
	// 设置态开后放行
	if err := svc.SaveSettings(context.Background(), "tester",
		SettingsInput{OutboundEnabled: boolPtr(true)}); err != nil {
		t.Fatal(err)
	}
	ch, err := svc.Run(context.Background(), sess.ID, "hi")
	if err != nil {
		t.Fatalf("外发开后应放行: %v", err)
	}
	drain(ch)
	if mp.calls == 0 {
		t.Fatal("外发开后应有厂商调用")
	}
}

func boolPtr(b bool) *bool { return &b }

// TestGatedProvider 库层闸:allowed()=false 时 Stream 直接产错误,不发请求。
func TestGatedProvider(t *testing.T) {
	mp := &mockProvider{turns: []scriptTurn{{text: "x", in: 1, out: 1}}}
	g := &gatedProvider{inner: mp, allowed: func() bool { return false }}
	for _, err := range g.Stream(context.Background(), llm.CompletionRequest{}) {
		if err == nil || !strings.Contains(err.Error(), "外发") {
			t.Fatalf("gatedProvider 应产外发闸错误: %v", err)
		}
	}
	if mp.calls != 0 {
		t.Fatalf("闸关时内层 provider 不应被调用: %d", mp.calls)
	}
}

func TestBudgetBreaker(t *testing.T) {
	mp := &mockProvider{turns: []scriptTurn{
		{toolName: "list_sources", toolInput: `{}`, in: 1500, out: 200},
		{text: "不会被送达", in: 2000, out: 400},
	}}
	svc, meta, _, _, _ := testService(t, mp)
	meta.settings = nil
	sess, err := svc.CreateSession(context.Background(), "case-1", "tester")
	if err != nil {
		t.Fatal(err)
	}
	// 会话预算快照改为 1000(实测口径:必触发)
	meta.mu.Lock()
	meta.sessions[sess.ID].BudgetTokens = 1000
	meta.mu.Unlock()

	ch, err := svc.Run(context.Background(), sess.ID, "查一下")
	if err != nil {
		t.Fatal(err)
	}
	evs := drain(ch)
	var be *Event
	for i := range evs {
		if evs[i].Kind == "budget_exceeded" {
			be = &evs[i]
		}
	}
	if be == nil {
		t.Fatalf("预算 1000 必触发熔断事件: %v", kinds(evs))
	}
	if !strings.Contains(be.ErrText, "熔断") {
		t.Fatalf("熔断事件应如实说明: %+v", be)
	}
}

func TestAbort(t *testing.T) {
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
	svc, meta, _, _, au := testService(t, mp)
	sess, err := svc.CreateSession(context.Background(), "case-1", "tester")
	if err != nil {
		t.Fatal(err)
	}
	ch, err := svc.Run(context.Background(), sess.ID, "长跑")
	if err != nil {
		t.Fatal(err)
	}
	// 等到首个文本事件(loop 确认在跑)再中断
	first := <-ch
	if first.Kind != "text" && first.Kind != "thinking" {
		t.Fatalf("首个事件应为文本: %+v", first)
	}
	if err := svc.Abort(context.Background(), sess.ID, "tester"); err != nil {
		t.Fatalf("abort 失败: %v", err)
	}
	// 流应在短时间内收尾(中断生效,不挂死)
	done := make(chan []Event, 1)
	go func() { done <- drain(ch) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("abort 后事件流未在 10s 内收尾")
	}
	got, _ := meta.GetAISession(context.Background(), sess.ID)
	if got.Status != "aborted" {
		t.Fatalf("会话账应为 aborted: %s", got.Status)
	}
	if n := len(au.byAction("ai.session.abort")); n != 1 {
		t.Fatalf("abort 审计应为 1 条: %d", n)
	}
	// aborted 会话不可续聊
	if _, err := svc.Run(context.Background(), sess.ID, "再聊"); err == nil {
		t.Fatal("aborted 会话应拒续聊")
	}
}

func TestRunNeedsActiveSessionAndPrompt(t *testing.T) {
	mp := &mockProvider{}
	svc, _, _, _, _ := testService(t, mp)
	if _, err := svc.Run(context.Background(), "sess-404", "hi"); err == nil {
		t.Fatal("无此会话应拒")
	}
	sess, _ := svc.CreateSession(context.Background(), "case-1", "tester")
	if _, err := svc.Run(context.Background(), sess.ID, ""); err == nil {
		t.Fatal("空消息应拒")
	}
}

func TestToolsAllReadOnly(t *testing.T) {
	svc, _, _, _, _ := testService(t, &mockProvider{})
	sess, _ := svc.CreateSession(context.Background(), "case-1", "tester")
	tools := svc.buildTools(sess, ResolvedConfig{})
	if len(tools) != 6 {
		t.Fatalf("应为 6 个只读工具: %d", len(tools))
	}
	for _, tl := range tools {
		if !tl.IsReadOnly(nil) {
			t.Fatalf("%s 未声明只读", tl.Name())
		}
		if !tl.IsConcurrencySafe(nil) {
			t.Fatalf("%s 未声明并发安全", tl.Name())
		}
		switch tl.Name() { // norma 默认工具焊死不许出现
		case "Bash", "Write", "Edit", "MultiEdit", "Read", "LS", "Glob", "Grep",
			"TaskOutput", "TaskStop", "TaskList", "Monitor":
			t.Fatalf("norma 默认工具泄漏: %s", tl.Name())
		}
	}
}
