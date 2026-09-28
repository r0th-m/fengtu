// 切片六契约测试:意图 worker 通路——CreateSessionBudget 预算快照 +
// RunWithSystem 意图上下文(铁律第一段/附加段加码)+ 厂商级 max_tokens。
package agentloop

import (
	"context"
	"strings"
	"testing"
)

func TestRunWithSystemIntentContext(t *testing.T) {
	mp := &mockProvider{turns: []scriptTurn{{text: "done", in: 1, out: 1}}}
	svc, meta, _, _, _ := testServiceEnv(t, mp, map[string]string{
		"FENGTU_AI_API_KEY":  "k",
		"FENGTU_AI_OUTBOUND": "true",
	})
	ctx := context.Background()
	// 指定预算建会话(意图 worker:单意图单会话)
	sess, err := svc.CreateSessionBudget(ctx, "case-1", "worker:rule", 50000, "")
	if err != nil {
		t.Fatal(err)
	}
	if sess.BudgetTokens != 50000 {
		t.Fatalf("会话预算快照=%d,应=50000", sess.BudgetTokens)
	}
	got, _ := meta.GetAISession(ctx, sess.ID)
	if got == nil || got.BudgetTokens != 50000 {
		t.Fatalf("会话账预算不符: %+v", got)
	}
	// 空附加段如实拒
	if _, err := svc.RunWithSystem(ctx, sess.ID, "干活", ""); err == nil {
		t.Fatal("空附加段应如实拒")
	}
	ch, err := svc.RunWithSystem(ctx, sess.ID, "干活", "# 意图链任务\n查 3306")
	if err != nil {
		t.Fatal(err)
	}
	drain(ch)
	// system 段:铁律永在第一位,意图上下文第二段(只能加码)
	if len(mp.systemSeen) != 2 || mp.systemSeen[0] != SystemPrompt {
		t.Fatalf("system 段装配不对: %v", mp.systemSeen)
	}
	if !strings.Contains(mp.systemSeen[1], "意图链任务") {
		t.Fatalf("意图上下文未进 system 段: %v", mp.systemSeen[1])
	}
	// 厂商级 max_tokens(默认档 4096)
	if mp.maxTokens != 4096 {
		t.Fatalf("MaxTokens=%d,应=4096", mp.maxTokens)
	}
}

func TestMaxTokensEnvOverride(t *testing.T) {
	mp := &mockProvider{turns: []scriptTurn{{text: "x", in: 1, out: 1}}}
	svc, _, _, _, _ := testServiceEnv(t, mp, map[string]string{
		"FENGTU_AI_API_KEY":    "k",
		"FENGTU_AI_OUTBOUND":   "true",
		"FENGTU_AI_MAX_TOKENS": "8192",
	})
	ctx := context.Background()
	sess, err := svc.CreateSession(ctx, "case-1", "tester")
	if err != nil {
		t.Fatal(err)
	}
	ch, err := svc.Run(ctx, sess.ID, "hi")
	if err != nil {
		t.Fatal(err)
	}
	drain(ch)
	if mp.maxTokens != 8192 {
		t.Fatalf("env 覆盖 MaxTokens=%d,应=8192", mp.maxTokens)
	}
}
