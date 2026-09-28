// AI 沟通区端点(切片五,DESIGN §7):会话绑案件、SSE 流式回复、中断、
// 平台设置(厂商/key 密文/外发开关/预算)。治理闸在 agentloop 收口,
// 本层只做闸的结果映射:外发关 → 403 如实;未配置 → 503 如实。
package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/ye-mengwen/fengtu/internal/agentloop"
	"github.com/ye-mengwen/fengtu/internal/ingest/store"
)

// AIFace web 层需要的 AI 服务面(agentloop.Service 实现;单测 fake)。
type AIFace interface {
	CreateSession(ctx context.Context, caseID, actor string) (*store.AISession, error)
	// CreateSessionBudget 指定 token 预算建会话(0.31.0 研判报告生成用:
	// 单次固定预算,超了 agentloop 熔断如实截断标注)。
	CreateSessionBudget(ctx context.Context, caseID, actor string,
		budgetTokens int64, hostScope string) (*store.AISession, error)
	GetSession(ctx context.Context, id string) (*store.AISession, error)
	ListSessions(ctx context.Context, caseID string) ([]store.AISession, error)
	History(ctx context.Context, id string) ([]agentloop.HistoryMessage, error)
	Abort(ctx context.Context, id, actor string) error
	Run(ctx context.Context, sessionID, prompt string) (<-chan agentloop.Event, error)
	PublicConfig(ctx context.Context) (agentloop.ResolvedConfig, error)
	SaveSettings(ctx context.Context, actor string, in agentloop.SettingsInput) error
	// ProbeProxy/ProbeSearch 联通性自测(切片十一,设置页「测试」钮):
	// 真发一个 HEAD/查询,如实回 ok+细节;不烧 LLM。
	ProbeProxy(ctx context.Context, proxy string) agentloop.ProbeResult
	ProbeSearch(ctx context.Context, backend, key string) agentloop.ProbeResult
	// FetchModels 模型清单拉取(0.27.0;表单值直测,key 空=回退已存;
	// 真 HTTP 但免费,永远 200 + {ok,models,detail} 如实)。
	FetchModels(ctx context.Context, in agentloop.FetchModelsInput) agentloop.FetchModelsResult
}

// aiReady AI 服务未装配(Deps.AI nil)→ 503 如实,不崩。
func (s *Server) aiReady(w http.ResponseWriter) bool {
	if s.deps.AI == nil {
		writeErr(w, http.StatusServiceUnavailable,
			"AI 未启用(server 未装配 agentloop;见启动日志)")
		return false
	}
	return true
}

// aiErr AI 层错误 → HTTP 状态(外发闸 403;未配置 503;无此会话 404)。
func aiErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, agentloop.ErrOutboundDisabled):
		writeErr(w, http.StatusForbidden, err.Error())
	case errors.Is(err, agentloop.ErrNotConfigured):
		writeErr(w, http.StatusServiceUnavailable, err.Error())
	default:
		msg := err.Error()
		if len(msg) >= 4 && msg[:4] == "无此会话" {
			writeErr(w, http.StatusNotFound, msg)
		} else {
			writeErr(w, http.StatusBadRequest, msg)
		}
	}
}

func (s *Server) aiSettingsGet(w http.ResponseWriter, r *http.Request) {
	if !s.aiReady(w) {
		return
	}
	cfg, err := s.deps.AI.PublicConfig(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"settings": cfg,
		"note": "api_key 永不回显(只有 key_source: env|pg|none);" +
			"外发开关关=一切 AI 端点 403;环境变量 FENGTU_AI_* 优先于本设置",
	})
}

func (s *Server) aiSettingsPut(w http.ResponseWriter, r *http.Request) {
	if !s.aiReady(w) {
		return
	}
	var in agentloop.SettingsInput
	if !decodeJSON(w, r, &in) {
		return
	}
	u := userFrom(r.Context())
	actor := "system"
	if u != nil {
		actor = u.Username
	}
	if err := s.deps.AI.SaveSettings(r.Context(), actor, in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_, _, _ = s.deps.Audit.AppendAudit(r.Context(), "", actor,
		"ai.settings", "ai_settings", map[string]any{
			"outbound_enabled": in.OutboundEnabled, "budget": in.SessionBudgetTokens,
			"provider": in.Provider, "model": in.Model,
			"key_changed": in.APIKey != nil && *in.APIKey != "", "key_cleared": in.ClearKey,
			"agent_concurrency": in.AgentConcurrency, "global_proxy": in.GlobalProxy != nil,
			"web_search_enabled": in.WebSearchEnabled, "web_search_backend": in.WebSearchBackend,
			"search_key_changed": in.SearchAPIKey != nil && *in.SearchAPIKey != "",
			"search_key_cleared": in.ClearSearchKey,
			// 0.24.0 预算三闸(指针原样记账:未动=nil,不伪造值)
			"intent_fanout_limit": in.IntentFanoutLimit,
			"intent_chapter_limit": in.IntentChapterLimit,
			"intent_case_limit":    in.IntentCaseLimit,
		})
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

// aiTestProxy 全局代理联通性自测(切片十一;表单值直测,先测后存)。
// 永远 200 + {ok,detail,target}:失败是配置事实不是服务故障(照 ARTEX testWebSearch)。
func (s *Server) aiTestProxy(w http.ResponseWriter, r *http.Request) {
	if !s.aiReady(w) {
		return
	}
	var body struct {
		Proxy string `json:"global_proxy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err.Error() != "EOF" {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.deps.AI.ProbeProxy(r.Context(), body.Proxy))
}

// aiTestSearch 联网搜索自测(切片十一):后端/key 取表单值,空=回退已存;
// 真发一次查询(30s 硬上限),如实回条数/错误。不烧 LLM(搜索后端直连)。
func (s *Server) aiTestSearch(w http.ResponseWriter, r *http.Request) {
	if !s.aiReady(w) {
		return
	}
	var body struct {
		Backend string `json:"web_search_backend"`
		Key     string `json:"search_api_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err.Error() != "EOF" {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.deps.AI.ProbeSearch(r.Context(), body.Backend, body.Key))
}

// aiPresetsGet 厂商预设表(0.27.0;数据驱动,前端下拉+自动填 base_url/协议)。
// 非敏感(常量表),登录即可读。
func (s *Server) aiPresetsGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"presets": agentloop.ProviderPresets(),
		"note": "provider 对不上预设 id 的存量配置按「自定义」呈现;" +
			"协议 openai-compatible|anthropic 对话链路已接入,ollama 对话走其 OpenAI 兼容端点",
	})
}

// aiFetchModels 模型清单拉取(0.27.0):表单值直测(base_url+key+协议),
// key 空=回退已存密文;永远 200 + {ok,models,detail},失败是配置事实不是
// 服务故障(照 test-proxy 口径)。GET models 免费,不烧 token。
func (s *Server) aiFetchModels(w http.ResponseWriter, r *http.Request) {
	if !s.aiReady(w) {
		return
	}
	var in agentloop.FetchModelsInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil && err.Error() != "EOF" {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.deps.AI.FetchModels(r.Context(), in))
}

func (s *Server) aiCreateSession(w http.ResponseWriter, r *http.Request) {
	if !s.aiReady(w) {
		return
	}
	var body struct {
		CaseID string `json:"case_id"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.CaseID == "" {
		writeErr(w, http.StatusBadRequest, "case_id 必填")
		return
	}
	u := userFrom(r.Context())
	actor := "system"
	if u != nil {
		actor = u.Username
	}
	sess, err := s.deps.AI.CreateSession(r.Context(), body.CaseID, actor)
	if err != nil {
		aiErr(w, err)
		return
	}
	_, _, _ = s.deps.Audit.AppendAudit(r.Context(), body.CaseID, actor,
		"ai.session.create", sess.ID, map[string]any{"budget": sess.BudgetTokens})
	writeJSON(w, http.StatusCreated, map[string]any{"session": sess})
}

func (s *Server) aiListSessions(w http.ResponseWriter, r *http.Request) {
	if !s.aiReady(w) {
		return
	}
	sessions, err := s.deps.AI.ListSessions(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if sessions == nil {
		sessions = []store.AISession{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

func (s *Server) aiGetSession(w http.ResponseWriter, r *http.Request) {
	if !s.aiReady(w) {
		return
	}
	sess, err := s.deps.AI.GetSession(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if sess == nil {
		writeErr(w, http.StatusNotFound, "无此会话: "+r.PathValue("id"))
		return
	}
	msgs, err := s.deps.AI.History(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session":  sess,
		"messages": msgs, // 历史回放(user/ai 文本;交流区刷新重放用)
		"note":     "消息正文在 transcript(data/ai/<transcript_id>.jsonl,norma 追加态);messages 即其回放投影",
	})
}

func (s *Server) aiAbort(w http.ResponseWriter, r *http.Request) {
	if !s.aiReady(w) {
		return
	}
	u := userFrom(r.Context())
	actor := "system"
	if u != nil {
		actor = u.Username
	}
	if err := s.deps.AI.Abort(r.Context(), r.PathValue("id"), actor); err != nil {
		aiErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

// aiPostMessage SSE 流式回复:agentloop 事件直出(text/tool_use/tool_result/
// usage/result/budget_exceeded/error)。客户端断开不杀 loop(abort 端点才算
// 用户中断);loop 不随请求生命周期。
func (s *Server) aiPostMessage(w http.ResponseWriter, r *http.Request) {
	if !s.aiReady(w) {
		return
	}
	var body struct {
		Content string `json:"content"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	events, err := s.deps.AI.Run(r.Context(), r.PathValue("id"), body.Content)
	if err != nil {
		aiErr(w, err)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "响应不支持流式(SSE)")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	for ev := range events {
		b, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Kind, b)
		flusher.Flush()
	}
	_, _ = fmt.Fprint(w, "event: done\ndata: {}\n\n")
	flusher.Flush()
}
