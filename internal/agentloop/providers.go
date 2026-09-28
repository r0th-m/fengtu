// 厂商预设表 + 模型清单拉取(0.27.0-ai-providers;照树庭 backend/app/ai.py
// 预设表/测连形态移植)。
//
// 预设表是数据不是逻辑:厂商名/协议/默认 base_url/是否需要 key/备注,
// 人可换;协议枚举焊死(openai-compatible|anthropic|ollama)。
//
// 协议支持矩阵(如实,norma v0.4.1 llm 底座实测):
//   openai-compatible → norma FormatOpenAI(对话链路已接入,默认档)
//   anthropic         → norma FormatAnthropic(对话链路已接入)
//   ollama            → 对话走其 OpenAI 兼容端点({base}/v1,FormatOpenAI);
//                       拉模型走原生 /api/tags(挂 /v1 之外),免 key
// 模型清单拉取是真 HTTP 但免费(GET models 不烧 token);completion 不在本层。
package agentloop

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Autumn-27/norma/llm"
)

// 协议枚举(018 迁移 CHECK 同口径)。
const (
	ProtocolOpenAICompat = "openai-compatible"
	ProtocolAnthropic    = "anthropic"
	ProtocolOllama       = "ollama"
)

// fetchModelsTimeout 模型清单拉取硬上限(10s;var 而非 const 供单测收紧)。
var fetchModelsTimeout = 10 * time.Second

// ProviderPreset 厂商预设(数据驱动;前端下拉+自动填 base_url/协议)。
type ProviderPreset struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`  // openai-compatible|anthropic|ollama
	BaseURL  string `json:"base_url"`  // 默认端点(用户可改)
	NeedsKey bool   `json:"needs_key"` // ollama 本地免 key
	Note     string `json:"note"`      // 如实备注(协议支持度/坑)
}

// providerPresets 内置厂商预设表(顺序即前端下拉顺序;custom 永远垫底)。
// base_url 均为 OpenAI 兼容端点形态(带 /v1);ollama 拉模型时会去 /v1
// 打原生 /api/tags。
var providerPresets = []ProviderPreset{
	{ID: "deepseek", Name: "DeepSeek", Protocol: ProtocolOpenAICompat,
		BaseURL: "https://api.deepseek.com/v1", NeedsKey: true,
		Note: "OpenAI 兼容;丰图默认档"},
	{ID: "openai", Name: "OpenAI", Protocol: ProtocolOpenAICompat,
		BaseURL: "https://api.openai.com/v1", NeedsKey: true,
		Note: "OpenAI 兼容(Chat Completions);推理模型拒 max_tokens 的坑 norma 已有 opt-in 键"},
	{ID: "dashscope", Name: "通义千问(DashScope 兼容模式)", Protocol: ProtocolOpenAICompat,
		BaseURL: "https://dashscope.aliyuncs.com/compatible-mode/v1", NeedsKey: true,
		Note: "阿里百炼 OpenAI 兼容模式"},
	{ID: "zhipu", Name: "智谱 GLM", Protocol: ProtocolOpenAICompat,
		BaseURL: "https://open.bigmodel.cn/api/paas/v4", NeedsKey: true,
		Note: "智谱开放平台 OpenAI 兼容端点"},
	{ID: "moonshot", Name: "Moonshot(Kimi)", Protocol: ProtocolOpenAICompat,
		BaseURL: "https://api.moonshot.cn/v1", NeedsKey: true,
		Note: "Moonshot OpenAI 兼容端点"},
	{ID: "anthropic", Name: "Anthropic(Claude)", Protocol: ProtocolAnthropic,
		BaseURL: "https://api.anthropic.com", NeedsKey: true,
		Note: "Anthropic 原生线格式(norma FormatAnthropic,对话链路已接入);不是 OpenAI 兼容"},
	{ID: "ollama", Name: "Ollama(本地)", Protocol: ProtocolOllama,
		BaseURL: "http://localhost:11434/v1", NeedsKey: false,
		Note: "本地免 key;对话走 OpenAI 兼容端点(/v1),拉模型走原生 /api/tags"},
	{ID: "custom", Name: "自定义", Protocol: ProtocolOpenAICompat,
		BaseURL: "", NeedsKey: true,
		Note: "自填 base_url;协议手动选(默认 openai-compatible)"},
}

// ProviderPresets 厂商预设表副本(防调用方改全局)。
func ProviderPresets() []ProviderPreset {
	out := make([]ProviderPreset, len(providerPresets))
	copy(out, providerPresets)
	return out
}

// FindPreset 按 id 查预设(nil = 对不上,前端显示「自定义」)。
func FindPreset(id string) *ProviderPreset {
	for i := range providerPresets {
		if providerPresets[i].ID == id {
			return &providerPresets[i]
		}
	}
	return nil
}

// validProtocol 协议枚举校验(SaveSettings/迁移 CHECK 同口径)。
func validProtocol(p string) bool {
	switch p {
	case ProtocolOpenAICompat, ProtocolAnthropic, ProtocolOllama:
		return true
	}
	return false
}

// llmFormatFor 协议 → norma 线格式(对话链路;ollama 走其 OpenAI 兼容端点)。
func llmFormatFor(protocol string) llm.Format {
	if protocol == ProtocolAnthropic {
		return llm.FormatAnthropic
	}
	return llm.FormatOpenAI
}

// FetchModelsInput 模型清单拉取入参(表单值直测,先拉后存;
// api_key 空 = 回退已存密文解密,同 test-search 口径)。
type FetchModelsInput struct {
	BaseURL  string `json:"base_url"`
	APIKey   string `json:"api_key"` // 明文直测,永不落库
	Protocol string `json:"protocol"`
}

// FetchModelsResult 拉取回执(永远 200 呈现;ok=false 时 detail 是失败原文,
// 不猜不含凭据)。
type FetchModelsResult struct {
	OK       bool     `json:"ok"`
	Models   []string `json:"models"`
	Detail   string   `json:"detail"`
	Target   string   `json:"target,omitempty"`
	Protocol string   `json:"protocol"`
}

// FetchModels 拉厂商可用模型清单(真 HTTP 但免费;超时 10s;走已存全局代理)。
// 协议分派:openai-compatible → GET {base}/models(Bearer);anthropic →
// GET {base}/v1/models(x-api-key + anthropic-version);ollama →
// GET {base 去 /v1}/api/tags(免 key)。失败如实回原文;空清单 ok 但如实标注。
func (s *Service) FetchModels(ctx context.Context, in FetchModelsInput) FetchModelsResult {
	base := strings.TrimRight(strings.TrimSpace(in.BaseURL), "/")
	protocol := strings.TrimSpace(in.Protocol)
	if protocol == "" {
		protocol = ProtocolOpenAICompat
	}
	res := FetchModelsResult{Protocol: protocol, Models: []string{}}
	if !validProtocol(protocol) {
		res.Detail = fmt.Sprintf("协议须为 openai-compatible|anthropic|ollama(收到 %q)", in.Protocol)
		return res
	}
	if base == "" {
		res.Detail = "base_url 必填"
		return res
	}
	cfg, err := s.resolveConfig(ctx)
	if err != nil {
		res.Detail = "配置读取失败: " + err.Error()
		return res
	}
	key := strings.TrimSpace(in.APIKey)
	if key == "" {
		key = cfg.APIKey // 表单留空=用已存 key(key 永不回显,同 ARTEX)
	}
	if key == "" && protocol != ProtocolOllama {
		res.Detail = "无 API key(表单未填且未存);ollama 之外的厂商都要 key"
		return res
	}

	var url string
	req := func() (*http.Request, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		switch protocol {
		case ProtocolAnthropic:
			r.Header.Set("x-api-key", key)
			r.Header.Set("anthropic-version", "2023-06-01")
		case ProtocolOpenAICompat:
			if key != "" {
				r.Header.Set("Authorization", "Bearer "+key)
			}
		}
		return r, nil
	}
	switch protocol {
	case ProtocolOllama:
		root := base
		if strings.HasSuffix(root, "/v1") { // api/tags 挂在 /v1 之外(树庭同口径)
			root = root[:len(root)-3]
		}
		url = root + "/api/tags"
	case ProtocolAnthropic:
		url = base + "/v1/models"
	default:
		url = base + "/models"
	}
	res.Target = url

	newClient := s.deps.ProxyClient
	if newClient == nil {
		newClient = proxyHTTPClient
	}
	client, err := newClient(cfg.GlobalProxy) // 与 LLM 请求同走全局代理
	if err != nil {
		res.Detail = err.Error()
		return res
	}
	client.Timeout = fetchModelsTimeout

	r, err := req()
	if err != nil {
		res.Detail = "目标 URL 非法: " + err.Error()
		return res
	}
	resp, err := client.Do(r)
	if err != nil {
		res.Detail = err.Error()
		if protocol == ProtocolOllama {
			res.Detail += "(确认 ollama serve 在跑)"
		}
		return res
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		excerpt := strings.TrimSpace(string(body))
		if len(excerpt) > 300 {
			excerpt = excerpt[:300] + "…"
		}
		res.Detail = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, excerpt)
		if excerpt == "" {
			res.Detail = fmt.Sprintf("HTTP %d(响应体为空)", resp.StatusCode)
		}
		return res
	}

	// 两种线格式都是 {data:[{id}]};ollama 是 {models:[{name}]}
	var parsed struct {
		Data   []struct{ ID string `json:"id"` }   `json:"data"`
		Models []struct{ Name string `json:"name"` } `json:"models"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		res.Detail = "响应不是预期 JSON(模型清单结构不符): " + err.Error()
		return res
	}
	for _, m := range parsed.Data {
		if m.ID != "" {
			res.Models = append(res.Models, m.ID)
		}
	}
	for _, m := range parsed.Models {
		if m.Name != "" {
			res.Models = append(res.Models, m.Name)
		}
	}
	res.OK = true
	if len(res.Models) == 0 {
		res.Detail = "端点返回空模型清单(账号下可能无可用模型,如实)"
	} else {
		res.Detail = fmt.Sprintf("拉到 %d 个模型", len(res.Models))
	}
	return res
}
