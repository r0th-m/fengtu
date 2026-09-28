// 切片十一单测:agent 并发上限/全局代理/联网搜索的设置解析、工具挂载闸、
// 代理注入 provider、联通性自测(全部 mock/httptest,不真连外网不烧真钱)。
package agentloop

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/tool"

	"github.com/ye-mengwen/fengtu/internal/ingest/store"
)

// ---- 设置解析/校验 ----

func TestSettingsNewFields(t *testing.T) {
	svc, meta, _, _, _ := testServiceEnv(t, &mockProvider{}, map[string]string{
		"FENGTU_AI_SECRET": "test-secret",
	})
	ctx := context.Background()

	// 非法值逐一拒(如实)
	zero := 0
	if err := svc.SaveSettings(ctx, "t", SettingsInput{AgentConcurrency: &zero}); err == nil {
		t.Fatal("agent_concurrency=0 应拒")
	}
	if err := svc.SaveSettings(ctx, "t", SettingsInput{GlobalProxy: strPtr("ftp://x")}); err == nil {
		t.Fatal("非法代理 scheme 应拒")
	}
	if err := svc.SaveSettings(ctx, "t", SettingsInput{GlobalProxy: strPtr("127.0.0.1:8080")}); err == nil {
		t.Fatal("缺 scheme 的代理应拒")
	}
	if err := svc.SaveSettings(ctx, "t", SettingsInput{WebSearchBackend: strPtr("bing")}); err == nil {
		t.Fatal("未知搜索后端应拒")
	}

	// 合法全量落库
	conc := 2
	if err := svc.SaveSettings(ctx, "t", SettingsInput{
		AgentConcurrency: &conc,
		GlobalProxy:      strPtr("socks5://127.0.0.1:1080"),
		WebSearchEnabled: boolPtr(true),
		WebSearchBackend: strPtr("tavily"),
		SearchAPIKey:     strPtr("tvly-secret"),
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(meta.settings.SearchAPIKeyEnc, "tvly-secret") {
		t.Fatal("搜索 key 应只存密文")
	}
	cfg, err := svc.resolveConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentConcurrency != 2 || cfg.GlobalProxy != "socks5://127.0.0.1:1080" ||
		!cfg.WebSearchEnabled || cfg.WebSearchBackend != "tavily" ||
		cfg.SearchAPIKey != "tvly-secret" || !cfg.SearchKeySet {
		t.Fatalf("新字段解析不符: %+v", cfg)
	}
	// PublicConfig:搜索 key 永不回显,只有有/无
	pub, err := svc.PublicConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pub.SearchAPIKey != "" || !pub.SearchKeySet {
		t.Fatalf("PublicConfig 泄露 key 或缺 search_key_set: %+v", pub)
	}
	// 部分更新不动已存搜索 key;显式清除
	if err := svc.SaveSettings(ctx, "t", SettingsInput{AgentConcurrency: &conc}); err != nil {
		t.Fatal(err)
	}
	if meta.settings.SearchAPIKeyEnc == "" {
		t.Fatal("部分更新不应动搜索 key")
	}
	if err := svc.SaveSettings(ctx, "t", SettingsInput{ClearSearchKey: true}); err != nil {
		t.Fatal(err)
	}
	if meta.settings.SearchAPIKeyEnc != "" {
		t.Fatal("ClearSearchKey 应清空密文")
	}
}

func TestSettingsNewDefaults(t *testing.T) {
	svc, _, _, _, _ := testServiceEnv(t, &mockProvider{}, map[string]string{})
	cfg, err := svc.resolveConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentConcurrency != DefaultAgentConcurrency {
		t.Fatalf("并发上限默认应=%d: %d", DefaultAgentConcurrency, cfg.AgentConcurrency)
	}
	if cfg.WebSearchBackend != "ddgs" || cfg.WebSearchEnabled || cfg.GlobalProxy != "" {
		t.Fatalf("搜索/代理默认档不符: %+v", cfg)
	}
}

// ---- web_search 工具挂载闸(开关关=不挂载,不靠模型自觉) ----

func gatedSvc(t *testing.T, st *store.AISettings) *Service {
	t.Helper()
	svc, meta, _, _, _ := testServiceEnv(t, &mockProvider{}, map[string]string{
		"FENGTU_AI_SECRET": "test-secret",
	})
	meta.settings = st
	return svc
}

func findToolByName(tools []tool.CoreTool, name string) bool {
	for _, tl := range tools {
		if tl.Name() == name {
			return true
		}
	}
	return false
}

func TestWebSearchToolGating(t *testing.T) {
	sess := &store.AISession{ID: "s1", CaseID: "case-1"}
	base := store.AISettings{ID: 1, OutboundEnabled: true,
		SessionBudgetTokens: 1000, MaxTokens: 100}

	// 开关关(默认):不挂
	svc := gatedSvc(t, &base)
	cfg, _ := svc.resolveConfig(context.Background())
	if findToolByName(svc.buildTools(sess, cfg), "web_search") {
		t.Fatal("开关关不应挂 web_search")
	}

	// 开 + ddgs(免 key):挂
	on := base
	on.WebSearchEnabled = true
	on.WebSearchBackend = "ddgs"
	svc = gatedSvc(t, &on)
	cfg, _ = svc.resolveConfig(context.Background())
	tools := svc.buildTools(sess, cfg)
	if !findToolByName(tools, "web_search") {
		t.Fatal("ddgs 后端应挂 web_search")
	}
	if len(tools) != 7 {
		t.Fatalf("挂上后应恰 7 个工具: %d", len(tools))
	}

	// 外发总开关关:搜索也是外发,不挂(外发同意闸)
	off := on
	off.OutboundEnabled = false
	svc = gatedSvc(t, &off)
	cfg, _ = svc.resolveConfig(context.Background())
	if findToolByName(svc.buildTools(sess, cfg), "web_search") {
		t.Fatal("外发关不应挂 web_search(搜索也是外发)")
	}

	// brave-free 缺 key:如实不挂
	nokey := on
	nokey.WebSearchBackend = "brave-free"
	svc = gatedSvc(t, &nokey)
	cfg, _ = svc.resolveConfig(context.Background())
	if findToolByName(svc.buildTools(sess, cfg), "web_search") {
		t.Fatal("带 key 后端缺 key 应如实不挂")
	}

	// brave-free 有 key(密文落库,解析时解密):挂
	withkey := on
	withkey.WebSearchBackend = "brave-free"
	enc, err := svc.encryptKey("brave-key")
	if err != nil {
		t.Fatal(err)
	}
	withkey.SearchAPIKeyEnc = enc
	svc = gatedSvc(t, &withkey)
	cfg, err = svc.resolveConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !findToolByName(svc.buildTools(sess, cfg), "web_search") {
		t.Fatal("带 key 后端有 key 应挂 web_search")
	}
}

// TestWebSearchToolRun 工具执行:fake probe 出结果;口径文案写死
// 「参考不是证据」;probe 失败如实错误结果;空 query 拒。
func TestWebSearchToolRun(t *testing.T) {
	svc, meta, _, _, _ := testServiceEnv(t, &mockProvider{}, map[string]string{})
	meta.settings = &store.AISettings{ID: 1, OutboundEnabled: true,
		WebSearchEnabled: true, WebSearchBackend: "ddgs",
		SessionBudgetTokens: 1000, MaxTokens: 100}
	var gotQuery string
	svc.deps.SearchProbe = func(_ context.Context, cfg tool.WebSearchConfig,
		query string, limit int) ([]tool.SearchResult, error) {
		gotQuery = query
		if cfg.Backend != "ddgs" {
			t.Errorf("后端应透传 ddgs: %s", cfg.Backend)
		}
		return []tool.SearchResult{{Title: "T", URL: "https://x", Description: "D", Position: 1}}, nil
	}
	cfg, _ := svc.resolveConfig(context.Background())
	tl, ok := svc.toolWebSearch(cfg)
	if !ok {
		t.Fatal("应挂载")
	}
	res := callTool(t, tl, `{"query":"ebury 报告"}`)
	text := res.Content[0].Text
	if gotQuery != "ebury 报告" || !strings.Contains(text, "https://x") {
		t.Fatalf("搜索执行不符: %q %s", gotQuery, text)
	}
	if !strings.Contains(text, "参考不是证据") || !strings.Contains(text, "source_id") {
		t.Fatalf("口径文案缺失(参考不是证据/锚点纪律): %s", text)
	}
	// 工具描述里同样写死口径(模型可见面)
	desc := tl.Description()
	if !strings.Contains(desc, "参考不是证据") {
		t.Fatalf("工具描述缺证据链口径: %s", desc)
	}
	// probe 失败:如实错误结果(工具重建,新 probe 才生效——装配时捕获)
	svc.deps.SearchProbe = func(context.Context, tool.WebSearchConfig, string, int) ([]tool.SearchResult, error) {
		return nil, fmt.Errorf("HTTP 502")
	}
	tl, ok = svc.toolWebSearch(cfg)
	if !ok {
		t.Fatal("应挂载")
	}
	res = callTool(t, tl, `{"query":"x"}`)
	if !strings.Contains(res.Content[0].Text, "HTTP 502") {
		t.Fatalf("probe 失败应如实呈现: %s", res.Content[0].Text)
	}
	// 空 query 拒
	res = callTool(t, tl, `{"query":" "}`)
	if !strings.Contains(res.Content[0].Text, "query 必填") {
		t.Fatalf("空 query 应拒: %s", res.Content[0].Text)
	}
}

// ---- 代理注入 provider(loop 全链,NewProvider 捕获 llm.Config) ----

func TestProxyInjectedIntoProvider(t *testing.T) {
	var gotProxy string
	mp := &mockProvider{turns: []scriptTurn{{text: "查完了", in: 10, out: 5}}}
	svc, meta, _, _, _ := testServiceEnv(t, mp, map[string]string{
		"FENGTU_AI_API_KEY": "sk-test", // key 走 env;代理走 PG 设置
	})
	svc.deps.NewProvider = func(c llm.Config) (llm.Provider, error) {
		gotProxy = c.Proxy
		return mp, nil
	}
	meta.settings = &store.AISettings{ID: 1, OutboundEnabled: true,
		GlobalProxy: "http://127.0.0.1:7890", SessionBudgetTokens: 1000, MaxTokens: 100}
	sess, err := svc.CreateSession(context.Background(), "case-1", "tester")
	if err != nil {
		t.Fatal(err)
	}
	ch, err := svc.Run(context.Background(), sess.ID, "hi")
	if err != nil {
		t.Fatal(err)
	}
	drain(ch)
	if gotProxy != "http://127.0.0.1:7890" {
		t.Fatalf("全局代理未注入 provider: %q", gotProxy)
	}
}

// ---- 联通性自测(httptest;不真连外网) ----

func TestProbeProxy(t *testing.T) {
	// 目标端点(base_url)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer target.Close()
	// 前置代理(记录是否经它转发)
	var viaProxy atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		viaProxy.Add(1)
		// 极简正向代理:只够自测(转发绝对 URI 的 HEAD)
		req, _ := http.NewRequest(r.Method, r.URL.String(), nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		w.WriteHeader(resp.StatusCode)
	}))
	defer proxy.Close()

	svc, meta, _, _, _ := testServiceEnv(t, &mockProvider{}, map[string]string{})
	meta.settings = &store.AISettings{ID: 1, BaseURL: target.URL,
		SessionBudgetTokens: 1000, MaxTokens: 100}

	// 直连
	r := svc.ProbeProxy(context.Background(), "")
	if !r.OK || !strings.Contains(r.Detail, "HTTP 200") || r.Target != target.URL {
		t.Fatalf("直连自测不符: %+v", r)
	}
	// 经代理
	r = svc.ProbeProxy(context.Background(), proxy.URL)
	if !r.OK || viaProxy.Load() == 0 {
		t.Fatalf("代理自测应经代理且成功: %+v via=%d", r, viaProxy.Load())
	}
	// 代理不通:如实失败
	r = svc.ProbeProxy(context.Background(), "http://127.0.0.1:1")
	if r.OK || r.Detail == "" {
		t.Fatalf("不通的代理应如实失败: %+v", r)
	}
	// 非法代理:如实失败
	r = svc.ProbeProxy(context.Background(), "ftp://x")
	if r.OK {
		t.Fatalf("非法代理应如实失败: %+v", r)
	}
}

func TestProbeSearch(t *testing.T) {
	svc, meta, _, _, _ := testServiceEnv(t, &mockProvider{}, map[string]string{
		"FENGTU_AI_SECRET": "test-secret",
	})
	enc, err := svc.encryptKey("stored-key")
	if err != nil {
		t.Fatal(err)
	}
	meta.settings = &store.AISettings{ID: 1, WebSearchBackend: "tavily",
		SearchAPIKeyEnc: enc, GlobalProxy: "http://p:1",
		SessionBudgetTokens: 1000, MaxTokens: 100}

	// key 回退已存(表单留空);代理用已存全局代理
	svc.deps.SearchProbe = func(_ context.Context, cfg tool.WebSearchConfig,
		_ string, _ int) ([]tool.SearchResult, error) {
		if cfg.TavilyAPIKey != "stored-key" {
			t.Errorf("应回退已存 key: %q", cfg.TavilyAPIKey)
		}
		if cfg.Proxy != "http://p:1" {
			t.Errorf("应用已存全局代理: %q", cfg.Proxy)
		}
		return []tool.SearchResult{{Title: "a"}, {Title: "b"}}, nil
	}
	r := svc.ProbeSearch(context.Background(), "", "")
	if !r.OK || r.Backend != "tavily" || !strings.Contains(r.Detail, "2 条") {
		t.Fatalf("搜索自测不符: %+v", r)
	}
	// 表单后端覆盖已存
	r = svc.ProbeSearch(context.Background(), "ddgs", "")
	if r.Backend != "ddgs" {
		t.Fatalf("表单后端应覆盖: %+v", r)
	}
	// 0 条结果:如实失败(可能被限流)
	svc.deps.SearchProbe = func(context.Context, tool.WebSearchConfig, string, int) ([]tool.SearchResult, error) {
		return nil, nil
	}
	r = svc.ProbeSearch(context.Background(), "", "")
	if r.OK {
		t.Fatalf("0 条结果应如实失败: %+v", r)
	}
	// probe 错误透传
	svc.deps.SearchProbe = func(context.Context, tool.WebSearchConfig, string, int) ([]tool.SearchResult, error) {
		return nil, fmt.Errorf("限流 429")
	}
	r = svc.ProbeSearch(context.Background(), "", "")
	if r.OK || !strings.Contains(r.Detail, "限流 429") {
		t.Fatalf("错误应透传: %+v", r)
	}
}
