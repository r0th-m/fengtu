// AI 端点契约测试(fake AIFace):闸的状态映射(外发关 403/未配置 503)、
// 会话 CRUD/abort、SSE 流形态、AI 未装配 503。
package web

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ye-mengwen/fengtu/internal/agentloop"
	"github.com/ye-mengwen/fengtu/internal/ingest/store"
)

type fakeAI struct {
	runErr     error
	outboundOn bool
	events     []agentloop.Event
	sessions   map[string]*store.AISession
	history    map[string][]agentloop.HistoryMessage
	seq        int
	aborted    []string
	// 0.31.0 研判报告生成断言口:建会话预算 + 实际收到的 prompt(grounding)。
	lastBudget int64
	lastPrompt string
	// 切片十一:自测回执脚本化(零值=默认成功回执)
	probeProxyResult  agentloop.ProbeResult
	probeSearchResult agentloop.ProbeResult
	fetchModelsResult agentloop.FetchModelsResult
	lastFetchModels   *agentloop.FetchModelsInput // FetchModels 入参记录(断言用)
	lastSettings      *agentloop.SettingsInput // SaveSettings 入参记录(断言用)
}

func newFakeAI() *fakeAI {
	return &fakeAI{sessions: map[string]*store.AISession{},
		history: map[string][]agentloop.HistoryMessage{}, outboundOn: true}
}

func (f *fakeAI) CreateSession(_ context.Context, caseID, actor string) (*store.AISession, error) {
	return f.CreateSessionBudget(context.Background(), caseID, actor, 200000, "")
}

// CreateSessionBudget 指定预算建会话(fake;0.31.0 研判报告生成走这里,
// 预算落 lastBudget 供契约断言)。
func (f *fakeAI) CreateSessionBudget(_ context.Context, caseID, actor string,
	budgetTokens int64, hostScope string) (*store.AISession, error) {
	if caseID != "case-1" && !strings.HasPrefix(caseID, "00000000-") {
		return nil, fmt.Errorf("无此案件: %s", caseID)
	}
	f.seq++
	f.lastBudget = budgetTokens
	s := &store.AISession{ID: fmt.Sprintf("sess-%d", f.seq), CaseID: caseID,
		TranscriptID: "tx-" + fmt.Sprint(f.seq), Status: "active",
		CreatedBy: actor, BudgetTokens: budgetTokens, HostScope: hostScope,
		CreatedAt: time.Now().UTC()}
	f.sessions[s.ID] = s
	return s, nil
}

func (f *fakeAI) GetSession(_ context.Context, id string) (*store.AISession, error) {
	return f.sessions[id], nil
}

func (f *fakeAI) ListSessions(_ context.Context, caseID string) ([]store.AISession, error) {
	var out []store.AISession
	for _, s := range f.sessions {
		if s.CaseID == caseID {
			out = append(out, *s)
		}
	}
	return out, nil
}

func (f *fakeAI) History(_ context.Context, id string) ([]agentloop.HistoryMessage, error) {
	if f.sessions[id] == nil {
		return nil, fmt.Errorf("无此会话: %s", id)
	}
	if f.history[id] == nil {
		return []agentloop.HistoryMessage{}, nil
	}
	return f.history[id], nil
}

func (f *fakeAI) Abort(_ context.Context, id, _ string) error {
	if f.sessions[id] == nil {
		return fmt.Errorf("无此会话: %s", id)
	}
	f.sessions[id].Status = "aborted"
	f.aborted = append(f.aborted, id)
	return nil
}

func (f *fakeAI) Run(_ context.Context, sessionID, prompt string) (<-chan agentloop.Event, error) {
	if f.runErr != nil {
		return nil, f.runErr
	}
	if f.sessions[sessionID] == nil {
		return nil, fmt.Errorf("无此会话: %s", sessionID)
	}
	f.lastPrompt = prompt
	ch := make(chan agentloop.Event, len(f.events))
	for _, e := range f.events {
		ch <- e
	}
	close(ch)
	return ch, nil
}

func (f *fakeAI) PublicConfig(context.Context) (agentloop.ResolvedConfig, error) {
	return agentloop.ResolvedConfig{
		Provider: "deepseek", BaseURL: "https://api.deepseek.com/v1",
		Model: "deepseek-chat", KeySource: "env",
		OutboundEnabled: f.outboundOn, BudgetTokens: 200000,
	}, nil
}

func (f *fakeAI) SaveSettings(_ context.Context, _ string, in agentloop.SettingsInput) error {
	f.lastSettings = &in
	return nil
}

// ProbeProxy/ProbeSearch 切片十一联通性自测(fake:可脚本化回执)。
func (f *fakeAI) ProbeProxy(_ context.Context, proxy string) agentloop.ProbeResult {
	if f.probeProxyResult.OK || f.probeProxyResult.Detail != "" {
		r := f.probeProxyResult
		r.Target = proxy
		return r
	}
	return agentloop.ProbeResult{OK: true, Target: proxy, Detail: "fake 直连 HEAD → HTTP 200"}
}

func (f *fakeAI) ProbeSearch(_ context.Context, backend, _ string) agentloop.ProbeResult {
	if f.probeSearchResult.OK || f.probeSearchResult.Detail != "" {
		return f.probeSearchResult
	}
	return agentloop.ProbeResult{OK: true, Backend: backend, Detail: "fake 返回 3 条结果"}
}

// FetchModels 0.27.0 模型清单拉取(fake:可脚本化回执)。
func (f *fakeAI) FetchModels(_ context.Context, in agentloop.FetchModelsInput) agentloop.FetchModelsResult {
	f.lastFetchModels = &in
	if f.fetchModelsResult.OK || f.fetchModelsResult.Detail != "" {
		return f.fetchModelsResult
	}
	return agentloop.FetchModelsResult{OK: true, Protocol: in.Protocol,
		Models: []string{"deepseek-chat", "deepseek-reasoner"}, Detail: "fake 拉到 2 个模型"}
}

func TestAIEndpoints(t *testing.T) {
	e := newTestEnv(t)
	ai := newFakeAI()
	e.srv.deps.AI = ai
	e.login(t)

	// 设置读取(无 key 回显)
	code, out := e.do(t, "GET", "/api/ai/settings", nil)
	if code != 200 || !strings.Contains(fmt.Sprint(out), "deepseek") {
		t.Fatalf("设置读取失败: %d %v", code, out)
	}
	// 建会话(绑案件;fakeMeta 的案件来自上传流——用 fakeAI 认的 case-1)
	code, out = e.do(t, "POST", "/api/ai/sessions", map[string]string{"case_id": "case-1"})
	if code != http.StatusCreated {
		t.Fatalf("建会话失败: %d %v", code, out)
	}
	sessID := out["session"].(map[string]any)["id"].(string)
	// 会话不存在案件 → 400
	code, _ = e.do(t, "POST", "/api/ai/sessions", map[string]string{"case_id": "nope"})
	if code != http.StatusBadRequest {
		t.Fatalf("无此案件应 400: %d", code)
	}
	// 历史
	ai.history[sessID] = []agentloop.HistoryMessage{
		{Role: "user", Text: "有没有爆破迹象", TS: "2026-09-23T00:00:00Z"},
		{Role: "ai", Text: "疑似候选:无", TS: "2026-09-23T00:00:05Z"},
	}
	code, out = e.do(t, "GET", "/api/ai/sessions/"+sessID, nil)
	if code != 200 || out["session"] == nil {
		t.Fatalf("会话历史失败: %d %v", code, out)
	}
	msgs, ok := out["messages"].([]any)
	if !ok || len(msgs) != 2 || msgs[0].(map[string]any)["role"] != "user" ||
		msgs[1].(map[string]any)["text"] != "疑似候选:无" {
		t.Fatalf("历史回放投影不符: %v", out["messages"])
	}
	code, _ = e.do(t, "GET", "/api/ai/sessions/sess-404", nil)
	if code != http.StatusNotFound {
		t.Fatalf("无此会话应 404: %d", code)
	}
	// 案件会话清单
	code, out = e.do(t, "GET", "/api/cases/case-1/ai/sessions", nil)
	if code != 200 || len(out["sessions"].([]any)) != 1 {
		t.Fatalf("会话清单失败: %d %v", code, out)
	}

	// SSE 消息流
	ai.events = []agentloop.Event{
		{Kind: "text", Text: "疑似候选:"},
		{Kind: "tool_use", ToolName: "run_operator", ToolInput: `{"name":"web-bruteforce-chain"}`},
		{Kind: "tool_result", ToolOutput: `{"hits_new":2}`},
		{Kind: "result", Text: "已落待审区 2 条", Reason: "completed"},
	}
	req, _ := http.NewRequest("POST", e.ts.URL+"/api/ai/sessions/"+sessID+"/messages",
		strings.NewReader(`{"content":"有没有爆破迹象"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", sessionCookie+"="+e.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("SSE 应 200: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("应为 SSE: %s", ct)
	}
	var body strings.Builder
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		body.WriteString(sc.Text() + "\n")
	}
	sse := body.String()
	for _, want := range []string{"event: text", "event: tool_use", "event: tool_result",
		"event: result", "event: done", "疑似候选"} {
		if !strings.Contains(sse, want) {
			t.Fatalf("SSE 流缺 %q:\n%s", want, sse)
		}
	}

	// 外发闸关 → 403 如实
	ai.runErr = agentloop.ErrOutboundDisabled
	code, out = e.do(t, "POST", "/api/ai/sessions/"+sessID+"/messages",
		map[string]string{"content": "hi"})
	if code != http.StatusForbidden || !strings.Contains(fmt.Sprint(out), "外发") {
		t.Fatalf("外发关应 403 如实: %d %v", code, out)
	}
	// 未配置 key → 503 如实
	ai.runErr = agentloop.ErrNotConfigured
	code, _ = e.do(t, "POST", "/api/ai/sessions/"+sessID+"/messages",
		map[string]string{"content": "hi"})
	if code != http.StatusServiceUnavailable {
		t.Fatalf("未配置应 503: %d", code)
	}
	ai.runErr = nil

	// abort
	code, _ = e.do(t, "POST", "/api/ai/sessions/"+sessID+"/abort", nil)
	if code != 200 || len(ai.aborted) != 1 {
		t.Fatalf("abort 失败: %d %v", code, ai.aborted)
	}

	// 设置更新(审计留痕,不回显 key)
	code, _ = e.do(t, "PUT", "/api/ai/settings",
		map[string]any{"outbound_enabled": true, "api_key": "sk-secret"})
	if code != 200 {
		t.Fatalf("设置更新失败: %d", code)
	}
	var found bool
	for _, ent := range e.audit.entries {
		if ent.Action == "ai.settings" {
			found = true
			if strings.Contains(ent.DetailJSON, "sk-secret") {
				t.Fatal("审计 detail 不应含明文 key")
			}
		}
	}
	if !found {
		t.Fatal("设置更新应有审计锚点")
	}
}

// TestAISettingsNewFieldsAndProbes 切片十一:新设置字段(并发上限/全局代理/
// 联网搜索)经 PUT 落到 SettingsInput;两个自测端点永远 200 + {ok,detail},
// 失败是配置事实如实呈现;AI 未装配 503。
func TestAISettingsNewFieldsAndProbes(t *testing.T) {
	e := newTestEnv(t)
	ai := newFakeAI()
	e.srv.deps.AI = ai
	e.login(t)

	// PUT 新字段 → fake 收到的 SettingsInput 指针字段一一对应
	code, out := e.do(t, "PUT", "/api/ai/settings", map[string]any{
		"agent_concurrency": 2, "global_proxy": "http://127.0.0.1:7890",
		"web_search_enabled": true, "web_search_backend": "ddgs",
		"search_api_key": "sk-search",
	})
	if code != 200 {
		t.Fatalf("新字段保存失败: %d %v", code, out)
	}
	in := ai.lastSettings
	if in == nil || in.AgentConcurrency == nil || *in.AgentConcurrency != 2 ||
		in.GlobalProxy == nil || *in.GlobalProxy != "http://127.0.0.1:7890" ||
		in.WebSearchEnabled == nil || !*in.WebSearchEnabled ||
		in.WebSearchBackend == nil || *in.WebSearchBackend != "ddgs" ||
		in.SearchAPIKey == nil || *in.SearchAPIKey != "sk-search" {
		t.Fatalf("SettingsInput 新字段不符: %+v", in)
	}

	// 代理自测:表单值直测(不依赖已存);fake 默认成功
	code, out = e.do(t, "POST", "/api/ai/settings/test-proxy",
		map[string]string{"global_proxy": "http://127.0.0.1:7890"})
	if code != 200 || out["ok"] != true {
		t.Fatalf("代理自测失败: %d %v", code, out)
	}
	// 失败回执:如实 ok=false + 错误原文(仍 200)
	ai.probeProxyResult = agentloop.ProbeResult{OK: false, Detail: "连接拒绝"}
	code, out = e.do(t, "POST", "/api/ai/settings/test-proxy",
		map[string]string{"global_proxy": "http://127.0.0.1:1"})
	if code != 200 || out["ok"] != false || !strings.Contains(fmt.Sprint(out), "连接拒绝") {
		t.Fatalf("代理自测失败回执不符: %d %v", code, out)
	}

	// 搜索自测:成功带条数/后端
	ai.probeSearchResult = agentloop.ProbeResult{OK: true, Backend: "ddgs", Detail: "返回 3 条结果"}
	code, out = e.do(t, "POST", "/api/ai/settings/test-search",
		map[string]string{"web_search_backend": "ddgs"})
	if code != 200 || out["ok"] != true || out["backend"] != "ddgs" {
		t.Fatalf("搜索自测失败: %d %v", code, out)
	}
	// 失败如实
	ai.probeSearchResult = agentloop.ProbeResult{OK: false, Backend: "ddgs", Detail: "限流 429"}
	code, out = e.do(t, "POST", "/api/ai/settings/test-search", nil)
	if code != 200 || out["ok"] != false || !strings.Contains(fmt.Sprint(out), "限流 429") {
		t.Fatalf("搜索自测失败回执不符: %d %v", code, out)
	}
}

// TestAIPresetsAndFetchModels 0.27.0:厂商预设表端点(常量表,登录可读)+
// fetch-models 端点(永远 200 + {ok,models,detail},表单值直透 fake 断言)。
func TestAIPresetsAndFetchModels(t *testing.T) {
	e := newTestEnv(t)
	ai := newFakeAI()
	e.srv.deps.AI = ai
	e.login(t)

	// 预设表:8 档齐,deepseek 第一,custom 垫底,ollama 免 key
	code, out := e.do(t, "GET", "/api/ai/settings/presets", nil)
	if code != 200 {
		t.Fatalf("预设表读取失败: %d %v", code, out)
	}
	presets, ok := out["presets"].([]any)
	if !ok || len(presets) != 8 {
		t.Fatalf("预设表应为 8 档: %v", out["presets"])
	}
	first := presets[0].(map[string]any)
	last := presets[len(presets)-1].(map[string]any)
	if first["id"] != "deepseek" || last["id"] != "custom" {
		t.Fatalf("预设表排序不符: %s … %s", first["id"], last["id"])
	}
	var ollama map[string]any
	for _, p := range presets {
		m := p.(map[string]any)
		if m["id"] == "ollama" {
			ollama = m
		}
	}
	if ollama == nil || ollama["needs_key"] != false || ollama["protocol"] != "ollama" {
		t.Fatalf("ollama 预设不符: %v", ollama)
	}

	// fetch-models:表单值直透,默认 fake 成功回执
	code, out = e.do(t, "POST", "/api/ai/settings/fetch-models", map[string]string{
		"base_url": "https://api.deepseek.com/v1", "api_key": "sk-form",
		"protocol": "openai-compatible"})
	if code != 200 || out["ok"] != true {
		t.Fatalf("fetch-models 失败: %d %v", code, out)
	}
	if ai.lastFetchModels == nil || ai.lastFetchModels.BaseURL != "https://api.deepseek.com/v1" ||
		ai.lastFetchModels.APIKey != "sk-form" || ai.lastFetchModels.Protocol != "openai-compatible" {
		t.Fatalf("FetchModels 入参不符: %+v", ai.lastFetchModels)
	}
	models := out["models"].([]any)
	if len(models) != 2 || models[0] != "deepseek-chat" {
		t.Fatalf("模型清单不符: %v", out["models"])
	}
	// 失败回执:如实 ok=false + 原文(仍 200)
	ai.fetchModelsResult = agentloop.FetchModelsResult{OK: false, Detail: "HTTP 401: Invalid API key"}
	code, out = e.do(t, "POST", "/api/ai/settings/fetch-models",
		map[string]string{"base_url": "https://api.deepseek.com/v1"})
	if code != 200 || out["ok"] != false ||
		!strings.Contains(fmt.Sprint(out), "HTTP 401") {
		t.Fatalf("fetch-models 失败回执不符: %d %v", code, out)
	}
}

// TestAINotAssembled AI 未装配(Deps.AI nil)→ 全端点 503 如实,不崩。
func TestAINotAssembled(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	for method, path := range map[string]string{
		"GET":  "/api/ai/settings",
		"POST": "/api/ai/sessions",
		"GET2": "/api/ai/sessions/x",
	} {
		m := method
		if m == "GET2" {
			m = "GET"
		}
		code, _ := e.do(t, m, path, nil)
		if code != http.StatusServiceUnavailable {
			t.Fatalf("AI 未装配应 503: %s %s → %d", m, path, code)
		}
	}
	code, _ := e.do(t, "POST", "/api/ai/sessions/x/messages",
		map[string]string{"content": "hi"})
	if code != http.StatusServiceUnavailable {
		t.Fatalf("messages 未装配应 503: %d", code)
	}
}
