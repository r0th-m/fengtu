// 厂商预设表 + 模型清单拉取单测(0.27.0)。
// 全部 httptest mock,零真外呼;fetch-models 各协议焊:正常列表/401/超时/
// 非 JSON/空清单/ollama 特判/key 回退已存。
package agentloop

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"
	"github.com/ye-mengwen/fengtu/internal/ingest/store"
)

// TestProviderPresets 预设表数据契约:id 唯一、协议合法、必备厂商齐、
// ollama 免 key、custom 垫底、deepseek 与内置默认档同端点。
func TestProviderPresets(t *testing.T) {
	presets := ProviderPresets()
	seen := map[string]bool{}
	want := []string{"deepseek", "openai", "dashscope", "zhipu", "moonshot",
		"anthropic", "ollama", "custom"}
	if len(presets) != len(want) {
		t.Fatalf("预设数不符: 要 %d 得 %d", len(want), len(presets))
	}
	for i, id := range want {
		p := presets[i]
		if p.ID != id {
			t.Fatalf("第 %d 位预设应为 %s,得 %s", i, id, p.ID)
		}
		if seen[p.ID] {
			t.Fatalf("预设 id 重复: %s", p.ID)
		}
		seen[p.ID] = true
		if !validProtocol(p.Protocol) {
			t.Fatalf("预设 %s 协议非法: %q", p.ID, p.Protocol)
		}
		if p.Name == "" || p.Note == "" {
			t.Fatalf("预设 %s 缺 name/note", p.ID)
		}
		if p.ID != "custom" && p.BaseURL == "" {
			t.Fatalf("预设 %s 缺默认 base_url", p.ID)
		}
	}
	if FindPreset("ollama").NeedsKey {
		t.Fatal("ollama 本地档应免 key")
	}
	if FindPreset("deepseek").BaseURL != defaultBaseURL {
		t.Fatal("deepseek 预设应与内置默认档同端点(向后兼容)")
	}
	if FindPreset("custom").BaseURL != "" {
		t.Fatal("custom 预设 base_url 应为空(用户自填)")
	}
	if FindPreset("nonexistent") != nil {
		t.Fatal("对不上的 id 应回 nil(前端显示自定义)")
	}
	// 副本语义:改返回值不动全局
	presets[0].BaseURL = " mutated "
	if ProviderPresets()[0].BaseURL != defaultBaseURL {
		t.Fatal("ProviderPresets 应回副本")
	}
}

func TestLLMFormatFor(t *testing.T) {
	if llmFormatFor(ProtocolAnthropic) != llm.FormatAnthropic {
		t.Fatal("anthropic 协议应映射 norma FormatAnthropic")
	}
	for _, p := range []string{ProtocolOpenAICompat, ProtocolOllama, ""} {
		if llmFormatFor(p) != llm.FormatOpenAI {
			t.Fatalf("协议 %q 应映射 FormatOpenAI(ollama 对话走其兼容端点)", p)
		}
	}
}

// fetchSvc 拉取测试用 service + meta(带 key 密文回退场景用)。
func fetchSvc(t *testing.T) (*Service, *fakeMeta) {
	t.Helper()
	svc, meta, _, _, _ := testServiceEnv(t, &mockProvider{}, map[string]string{
		"FENGTU_AI_SECRET": "test-secret",
	})
	return svc, meta
}

func TestFetchModelsOpenAICompat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("openai 兼容应打 /v1/models,实得 %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer sk-form" {
			t.Errorf("Bearer 头不符: %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]string{{"id": "m-a"}, {"id": "m-b"}, {"id": ""}},
		})
	}))
	defer srv.Close()
	svc, _ := fetchSvc(t)
	res := svc.FetchModels(context.Background(), FetchModelsInput{
		BaseURL: srv.URL + "/v1", APIKey: "sk-form", Protocol: "openai-compatible"})
	if !res.OK || len(res.Models) != 2 || res.Models[0] != "m-a" {
		t.Fatalf("正常列表不符: %+v", res)
	}
	if !strings.Contains(res.Detail, "2 个模型") {
		t.Fatalf("detail 不符: %s", res.Detail)
	}
}

func TestFetchModels401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":{"message":"Invalid API key"}}`)
	}))
	defer srv.Close()
	svc, _ := fetchSvc(t)
	res := svc.FetchModels(context.Background(), FetchModelsInput{
		BaseURL: srv.URL, APIKey: "sk-bad", Protocol: "openai-compatible"})
	if res.OK || !strings.Contains(res.Detail, "HTTP 401") ||
		!strings.Contains(res.Detail, "Invalid API key") {
		t.Fatalf("401 应如实回状态码+原文: %+v", res)
	}
}

func TestFetchModelsTimeout(t *testing.T) {
	old := fetchModelsTimeout
	fetchModelsTimeout = 50 * time.Millisecond
	defer func() { fetchModelsTimeout = old }()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
	}))
	defer srv.Close()
	svc, _ := fetchSvc(t)
	res := svc.FetchModels(context.Background(), FetchModelsInput{
		BaseURL: srv.URL, APIKey: "sk", Protocol: "openai-compatible"})
	if res.OK || res.Detail == "" {
		t.Fatalf("超时应如实失败: %+v", res)
	}
}

func TestFetchModelsNonJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "<html>not json</html>")
	}))
	defer srv.Close()
	svc, _ := fetchSvc(t)
	res := svc.FetchModels(context.Background(), FetchModelsInput{
		BaseURL: srv.URL, APIKey: "sk", Protocol: "openai-compatible"})
	if res.OK || !strings.Contains(res.Detail, "JSON") {
		t.Fatalf("非 JSON 应如实报结构不符: %+v", res)
	}
}

func TestFetchModelsEmptyList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
	}))
	defer srv.Close()
	svc, _ := fetchSvc(t)
	res := svc.FetchModels(context.Background(), FetchModelsInput{
		BaseURL: srv.URL, APIKey: "sk", Protocol: "openai-compatible"})
	if !res.OK || len(res.Models) != 0 || !strings.Contains(res.Detail, "空模型清单") {
		t.Fatalf("空清单应 ok 但如实标注: %+v", res)
	}
}

func TestFetchModelsAnthropic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("anthropic 应打 /v1/models,实得 %s", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != "sk-ant" ||
			r.Header.Get("anthropic-version") != "2023-06-01" {
			t.Errorf("anthropic 头不符: %v", r.Header)
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("anthropic 不应发 Bearer 头")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]string{{"id": "claude-sonnet-4-5"}},
		})
	}))
	defer srv.Close()
	svc, _ := fetchSvc(t)
	res := svc.FetchModels(context.Background(), FetchModelsInput{
		BaseURL: srv.URL, APIKey: "sk-ant", Protocol: "anthropic"})
	if !res.OK || len(res.Models) != 1 || res.Models[0] != "claude-sonnet-4-5" {
		t.Fatalf("anthropic 列表不符: %+v", res)
	}
}

func TestFetchModelsOllama(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			t.Errorf("ollama 应去 /v1 打 /api/tags,实得 %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("ollama 免 key,不应发鉴权头")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"models": []map[string]string{{"name": "qwen2:7b"}, {"name": "llama3:8b"}},
		})
	}))
	defer srv.Close()
	// 无 key 也拉(ollama 特判)
	svc, _ := fetchSvc(t)
	res := svc.FetchModels(context.Background(), FetchModelsInput{
		BaseURL: srv.URL + "/v1", Protocol: "ollama"})
	if !res.OK || len(res.Models) != 2 || res.Models[0] != "qwen2:7b" {
		t.Fatalf("ollama 列表不符: %+v", res)
	}
	// 拉不到:提示确认 ollama serve 在跑
	res = svc.FetchModels(context.Background(), FetchModelsInput{
		BaseURL: "http://127.0.0.1:1/v1", Protocol: "ollama"})
	if res.OK || !strings.Contains(res.Detail, "确认 ollama serve 在跑") {
		t.Fatalf("ollama 不可达应带提示: %+v", res)
	}
}

// TestFetchModelsKeyFallback 表单 key 留空 → 回退已存密文解密(同 test-search
// 口径);无任何 key 且非 ollama → 如实拒。
func TestFetchModelsKeyFallback(t *testing.T) {
	svc, meta := fetchSvc(t)
	enc, err := svc.encryptKey("sk-saved")
	if err != nil {
		t.Fatal(err)
	}
	meta.settings = &store.AISettings{ID: 1, APIKeyEnc: enc}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sk-saved" {
			t.Errorf("应回退已存 key,实得 %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]string{{"id": "m1"}}})
	}))
	defer srv.Close()
	res := svc.FetchModels(context.Background(), FetchModelsInput{
		BaseURL: srv.URL, Protocol: "openai-compatible"})
	if !res.OK {
		t.Fatalf("key 回退失败: %+v", res)
	}
	// 无 key 且非 ollama → 如实拒(不打请求)
	meta.settings = &store.AISettings{ID: 1}
	res = svc.FetchModels(context.Background(), FetchModelsInput{
		BaseURL: srv.URL, Protocol: "openai-compatible"})
	if res.OK || !strings.Contains(res.Detail, "无 API key") {
		t.Fatalf("无 key 应如实拒: %+v", res)
	}
}

func TestFetchModelsValidation(t *testing.T) {
	svc, _ := fetchSvc(t)
	res := svc.FetchModels(context.Background(), FetchModelsInput{
		BaseURL: "http://x", Protocol: "grpc"})
	if res.OK || !strings.Contains(res.Detail, "协议须为") {
		t.Fatalf("非法协议应拒: %+v", res)
	}
	res = svc.FetchModels(context.Background(), FetchModelsInput{
		Protocol: "openai-compatible"})
	if res.OK || !strings.Contains(res.Detail, "base_url 必填") {
		t.Fatalf("空 base_url 应拒: %+v", res)
	}
}
