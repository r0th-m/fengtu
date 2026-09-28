// Package agentloop AI 层薄壳(DESIGN §7):norma 当库引(锁版本 vendoring),
// 本包是唯一 import norma 的地方——它死了或转向时只换这层壳,web 层只见
// 本包自有类型。
//
// 一寸不让的治理面(全部在本包收口):
//   - 只读工具集:norma 默认的 Write/Edit/Bash 一律不注册(Options.Tools
//     显式传我们的只读工具,且 DisableBackgroundTasks 防它自动注入
//     任务管理工具);
//   - 预算熔断:PreToolUse hook + 消费侧硬停两道,超会话预算(默认 20 万
//     token,平台可配)即熔断如实;
//   - 外发同意:平台级 outbound_enabled 开关,关=任何厂商调用前 403 如实
//     (HTTP 层闸 + gatedProvider 库层闸双保险;CanUseTool 同步接闸——
//     但注意 norma 的权限管线对 read-only 工具在到达 ask 阶段前就自动
//     放行,真正的外发闸在 provider 层);
//   - 审计锚点:每次工具调用(名/参数/耗时/返回行数)经 PostToolUse hook
//     进审计哈希链;会话 transcript 由 norma 落 data/ai/ JSONL;
//   - 产出纪律:SystemPrompt 写死「一切发现=疑似候选,报锚点,不许断言」;
//     run_operator 的命中以 pending 落既有待审区,人裁决才算数。
package agentloop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"

	"github.com/ye-mengwen/fengtu/internal/ingest/store"
	"github.com/ye-mengwen/fengtu/internal/operator"
	"github.com/ye-mengwen/fengtu/internal/query"
	"github.com/ye-mengwen/fengtu/internal/review"
	"github.com/ye-mengwen/fengtu/internal/vault"
)

// ErrOutboundDisabled 外发闸关:任何厂商调用前如实拒(web 层映射 403)。
var ErrOutboundDisabled = errors.New("AI 外发已关闭(平台级开关);开启: PUT /api/ai/settings {outbound_enabled:true}")

// ErrNotConfigured AI 未配置(无 API key;环境变量或平台设置)。
var ErrNotConfigured = errors.New("AI 未配置 API key(环境变量 FENGTU_AI_API_KEY 或平台设置)")

// MetaStore AI 层需要的 PG 元数据面(store.PG 实现,单测 fake)。
type MetaStore interface {
	GetCase(ctx context.Context, id string) (*store.Case, error)
	ListSources(ctx context.Context, caseID string) ([]store.Source, error)
	GetSource(ctx context.Context, id string) (*store.Source, error)
	CreateAISession(ctx context.Context, s *store.AISession) error
	GetAISession(ctx context.Context, id string) (*store.AISession, error)
	ListAISessions(ctx context.Context, caseID string) ([]store.AISession, error)
	TouchAISession(ctx context.Context, id string, tokensIn, tokensOut int64) error
	AbortAISession(ctx context.Context, id string) (bool, error)
	GetAISettings(ctx context.Context) (*store.AISettings, error)
	SaveAISettings(ctx context.Context, s *store.AISettings) error
}

// EventQuerier CH 事件面(检索 + 聚合;单一检索层纪律)。
type EventQuerier interface {
	query.Querier
	query.StatsQuerier
}

// AuditAppender 审计链追加面(store.PG 实现)。
type AuditAppender interface {
	AppendAudit(ctx context.Context, caseID, actor, action, scope string, detail any) (int64, string, error)
}

// Deps agentloop 依赖(全部接口化,单测 fake 打全链)。
type Deps struct {
	Meta          MetaStore
	Events        EventQuerier
	Query         *query.Service
	Review        *review.Engine
	ReviewStore   review.Store // run_operator 落 hits(轮次账+候选)
	Ops           *operator.Registry
	Vault         *vault.Vault
	Audit         AuditAppender
	TranscriptDir string              // norma JSONL 落盘目录(data/ai)
	// WorkspaceDir 用户工作区总根(<data>/workspace;切片十三):非空即为每个
	// 会话挂 workspace_list/workspace_read 只读工具,作用域=会话案件子目录;
	// 空=不挂(测试台默认)。路径净化/内容嗅探与 web 端点共用
	// internal/workspace(唯一真源)。
	WorkspaceDir  string
	EnvLookup     func(string) string // 环境变量(nil → os.Getenv;测试注入)
	Now           func() time.Time    // nil → time.Now
	// NewProvider provider 工厂(nil → llm.NewProvider;测试注入 mock,
	// loop 契约测试不烧真钱)。
	NewProvider func(llm.Config) (llm.Provider, error)
	// Recorder LLM 录制落库面(nil = 不录制;档位见 ai_settings.record_mode,
	// 默认 metadata=只记元数据,full=opt-in 录全文)。
	Recorder LLMRecorder
	// SearchProbe 联网搜索联通性自测面(nil → tool.WebSearchProbe;
	// 测试注入 mock,不真连外网)。web_search 工具本体在 tools.go 装配。
	SearchProbe func(ctx context.Context, cfg tool.WebSearchConfig,
		query string, limit int) ([]tool.SearchResult, error)
	// ProxyClient 代理 HTTP 客户端工厂(nil → 默认实现;http/https/socks5,
	// 空=直连走 *_PROXY 环境变量——与 norma llm provider 同口径)。
	// 联通性自测(ProbeProxy)与单测注入用。
	ProxyClient func(proxy string) (*http.Client, error)
}

// Service AI 会话服务(治理闸收口处)。
type Service struct {
	deps Deps

	mu      sync.Mutex
	running map[string]context.CancelFunc // sessionID → 中断柄(abort 端点)
}

// NewService 构造。
func NewService(d Deps) *Service {
	if d.EnvLookup == nil {
		d.EnvLookup = envGet
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Service{deps: d, running: map[string]context.CancelFunc{}}
}

// maxTurns 单条消息的 tool-use 循环上限(防失控;如实写死,后续可调)。
const maxTurns = 25

// Event 对外事件(web 层 SSE 直出;不暴露 norma 类型,壳的边界)。
type Event struct {
	Kind       string `json:"kind"` // text|thinking|tool_use|tool_result|usage|result|budget_exceeded|aborted|error
	Text       string `json:"text,omitempty"`
	ToolName   string `json:"tool_name,omitempty"`
	ToolInput  string `json:"tool_input,omitempty"`
	ToolOutput string `json:"tool_output,omitempty"` // tool_result 截断呈现(≤500 rune)
	IsError    bool   `json:"is_error,omitempty"`
	TokensIn   int64  `json:"tokens_in,omitempty"`
	TokensOut  int64  `json:"tokens_out,omitempty"`
	Reason     string `json:"reason,omitempty"` // result: completed|aborted|budget_exceeded|model_error...
	ErrText    string `json:"err,omitempty"`
}

// CreateSession 建会话(绑案件;预算快照自建会话时的平台配置)。
func (s *Service) CreateSession(ctx context.Context, caseID, actor string) (*store.AISession, error) {
	cfg, err := s.resolveConfig(ctx)
	if err != nil {
		return nil, err
	}
	return s.createSession(ctx, caseID, actor, cfg.BudgetTokens, "")
}

// CreateSessionBudget 指定 token 预算建会话(切片六意图 worker:单意图
// 单会话,会话级预算=意图链四层预算的第三层)。hostScope 非空=意图
// 主机范围(切片七):会话绑定主机,只读工具强制限定该主机源集合。
func (s *Service) CreateSessionBudget(ctx context.Context, caseID, actor string,
	budgetTokens int64, hostScope string) (*store.AISession, error) {

	if budgetTokens <= 0 {
		return nil, fmt.Errorf("会话 token 预算须为正整数: %d", budgetTokens)
	}
	return s.createSession(ctx, caseID, actor, budgetTokens, hostScope)
}

// createSession 建会话内部通路(预算/主机范围由调用方定)。
func (s *Service) createSession(ctx context.Context, caseID, actor string,
	budgetTokens int64, hostScope string) (*store.AISession, error) {

	c, err := s.deps.Meta.GetCase(ctx, caseID)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, fmt.Errorf("无此案件: %s", caseID)
	}
	sess := &store.AISession{
		CaseID:       caseID,
		TranscriptID: transcript.NewSessionID(),
		Status:       "active",
		CreatedBy:    actor,
		BudgetTokens: budgetTokens,
		HostScope:    hostScope,
	}
	if err := s.deps.Meta.CreateAISession(ctx, sess); err != nil {
		return nil, err
	}
	return s.deps.Meta.GetAISession(ctx, sess.ID)
}

// GetSession 会话账。
func (s *Service) GetSession(ctx context.Context, id string) (*store.AISession, error) {
	return s.deps.Meta.GetAISession(ctx, id)
}

// HistoryMessage 会话历史回放条目(交流区刷新重放,web 层直出)。
type HistoryMessage struct {
	Role string `json:"role"` // user | ai
	Text string `json:"text"`
	TS   string `json:"ts"` // transcript 记录时刻(RFC3339Nano)
}

// History 会话历史回放:transcript(data/ai/<transcript_id>.jsonl)是唯一真账,
// 与续聊 resume 同一条 Load 路径。只回 user/assistant 的文本块;空文本帧
// (纯 tool_use/工具结果/压缩边界标记)不回放——过程帧价值在实时(SSE),
// 历史留问答结论。压缩(compaction)重录的尾部副本如实保留不去重:
// 回放忠于原账,不做任何「美化」。
func (s *Service) History(ctx context.Context, id string) ([]HistoryMessage, error) {
	sess, err := s.deps.Meta.GetAISession(ctx, id)
	if err != nil {
		return nil, err
	}
	if sess == nil {
		return nil, fmt.Errorf("无此会话: %s", id)
	}
	ts := transcript.NewStore(s.deps.TranscriptDir)
	recs, err := ts.Load(ts.MainPath(sess.TranscriptID))
	if err != nil {
		return nil, fmt.Errorf("transcript 读取失败: %w", err)
	}
	out := []HistoryMessage{} // 零历史回 [](不回 null)
	for _, r := range recs {
		if r.Type != "message" || r.Message == nil {
			continue
		}
		var role string
		switch r.Message.Role {
		case llm.RoleUser:
			role = "user"
		case llm.RoleAssistant:
			role = "ai"
		default:
			continue
		}
		text := r.Message.Text()
		if text == "" {
			continue
		}
		out = append(out, HistoryMessage{Role: role, Text: text, TS: r.Timestamp})
	}
	return out, nil
}

// ListSessions 案件会话清单。
func (s *Service) ListSessions(ctx context.Context, caseID string) ([]store.AISession, error) {
	return s.deps.Meta.ListAISessions(ctx, caseID)
}

// Abort 用户中断:立即 cancel 正在跑的 loop,账上标 aborted(幂等)。
func (s *Service) Abort(ctx context.Context, id, actor string) error {
	sess, err := s.deps.Meta.GetAISession(ctx, id)
	if err != nil {
		return err
	}
	if sess == nil {
		return fmt.Errorf("无此会话: %s", id)
	}
	s.mu.Lock()
	cancel, running := s.running[id]
	s.mu.Unlock()
	if running {
		cancel() // norma loop 如实以 aborted_streaming/aborted_tools 收尾
	}
	ok, err := s.deps.Meta.AbortAISession(ctx, id)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("无此会话: %s", id)
	}
	_, _, _ = s.deps.Audit.AppendAudit(ctx, sess.CaseID, actor,
		"ai.session.abort", id, map[string]any{"was_running": running})
	return nil
}

// Cancel 取消正在跑的 loop 但不动会话账(交互改造切片三 steer 纠偏语义:
// 会话保持 active 可续跑,transcript 延续——与 Abort 的区别:Abort 账上标
// aborted 终态不可续)。没在跑即无操作(幂等);不记审计(纠偏的审计在
// 意图层 intent.steer,锚真人)。
func (s *Service) Cancel(_ context.Context, id string) error {
	s.mu.Lock()
	cancel, running := s.running[id]
	s.mu.Unlock()
	if running {
		cancel() // norma loop 如实以 aborted_streaming/tools 收尾,会话账不动
	}
	return nil
}

// Run 跑一条消息(流式;治理闸全在此收口)。
// 返回事件流(单消费者;for-range 到完即终态)与启动前错误(闸拒/配置缺)。
func (s *Service) Run(ctx context.Context, sessionID, prompt string) (<-chan Event, error) {
	return s.run(ctx, sessionID, prompt, "")
}

// RunWithSystem 带附加 system 段跑一条消息(切片六意图 worker:意图上下文
// 作为第二段 system 提示——铁律 SystemPrompt 永在第一位,附加段只能加码
// 不能松绑)。
func (s *Service) RunWithSystem(ctx context.Context, sessionID, prompt,
	systemExtra string) (<-chan Event, error) {

	if systemExtra == "" {
		return nil, fmt.Errorf("附加 system 段必填(否则用 Run)")
	}
	return s.run(ctx, sessionID, prompt, systemExtra)
}

// run 跑一条消息(流式;治理闸全在此收口)。
func (s *Service) run(ctx context.Context, sessionID, prompt,
	systemExtra string) (<-chan Event, error) {
	if prompt == "" {
		return nil, fmt.Errorf("消息内容必填")
	}
	sess, err := s.deps.Meta.GetAISession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if sess == nil {
		return nil, fmt.Errorf("无此会话: %s", sessionID)
	}
	if sess.Status != "active" {
		return nil, fmt.Errorf("会话已 %s,不可续聊(可新建会话)", sess.Status)
	}

	cfg, err := s.resolveConfig(ctx)
	if err != nil {
		return nil, err
	}
	// 外发闸(HTTP 层面,第一刀):关=任何厂商调用前如实拒
	if !cfg.OutboundEnabled {
		return nil, ErrOutboundDisabled
	}
	if cfg.APIKey == "" {
		return nil, ErrNotConfigured
	}

	s.mu.Lock()
	if _, dup := s.running[sessionID]; dup {
		s.mu.Unlock()
		return nil, fmt.Errorf("会话已有消息在跑(并发跑同一 session 不允许;可 abort 后重试)")
	}
	runCtx, cancel := context.WithCancel(context.Background()) // 不随请求生命周期;abort 端点持柄
	s.running[sessionID] = cancel
	s.mu.Unlock()

	out := make(chan Event, 32)
	go s.drive(runCtx, cancel, sess, cfg, prompt, systemExtra, out)
	return out, nil
}

// drive loop 消费者:norma 事件 → 壳事件;预算硬停;落 token 账与审计。
func (s *Service) drive(ctx context.Context, cancel context.CancelFunc,
	sess *store.AISession, cfg ResolvedConfig, prompt, systemExtra string, out chan<- Event) {

	defer close(out)
	defer func() {
		s.mu.Lock()
		delete(s.running, sess.ID)
		s.mu.Unlock()
	}()

	ts := transcript.NewStore(s.deps.TranscriptDir)
	budget := newBudget(sess.BudgetTokens)
	hooks, rec := s.buildHooks(sess, budget)

	newProvider := s.deps.NewProvider
	if newProvider == nil {
		newProvider = llm.NewProvider
	}
	provider, err := newProvider(llm.Config{
		// 线格式按协议列(0.27.0):openai-compatible/ollama → OpenAI;
		// anthropic → norma FormatAnthropic(§7 拍板延伸)
		Format:  llmFormatFor(cfg.Protocol),
		BaseURL: cfg.BaseURL,
		APIKey:  cfg.APIKey,
		Model:   cfg.Model,
		// 全局出口代理(切片十一):LLM 厂商请求走它,空=直连(环境变量)
		Proxy: cfg.GlobalProxy,
	})
	if err != nil {
		out <- Event{Kind: "error", ErrText: "provider 装配失败: " + err.Error()}
		return
	}
	// 外发闸(库层,第二刀):gatedProvider 在任何厂商调用前再查一次闸
	provider = &gatedProvider{inner: provider, allowed: func() bool {
		c, err := s.resolveConfig(context.Background())
		return err == nil && c.OutboundEnabled
	}}
	// 录制挂钩(切片十):gatedProvider 外侧再包一层,每次厂商调用落账;
	// 档位热更(每次调用读平台设置),录制失败只 warn 不杀 loop。
	if s.deps.Recorder != nil {
		kind := "chat"
		if systemExtra != "" {
			kind = "intent" // 附加 system 段 = 意图 worker 会话(RunWithSystem)
		}
		provider = &recordingProvider{
			inner: provider, sess: sess, kind: kind, model: cfg.Model,
			rec:  s.deps.Recorder,
			now:  s.deps.Now,
			mode: func() string {
				c, err := s.resolveConfig(context.Background())
				if err != nil {
					return "metadata" // 设置读取失败如实按默认档(只记元数据)
				}
				return c.RecordMode
			},
		}
	}

	// system 段装配:铁律永远第一段;意图上下文等附加段只能跟在后面加码
	sysPrompts := []string{SystemPrompt}
	if systemExtra != "" {
		sysPrompts = append(sysPrompts, systemExtra)
	}
	maxTokens := cfg.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 4096
	}
	core := agentcore.NewSession(agentcore.Options{
		Provider:     provider,
		SystemPrompt: sysPrompts,
		Tools:        s.buildTools(sess, cfg),
		// norma 默认带的 Write/Edit/Bash 一律不注册:Tools 显式传我们的
		// 只读集;后台任务工具(TaskOutput/TaskStop/TaskList/Monitor)关掉
		DisableBackgroundTasks: true,
		CanUseTool: func(_ context.Context, name string, _ json.RawMessage, _ permission.Context) permission.Decision {
			// 统一接外发同意闸(只读工具在 ask 阶段前已被管线放行——
			// 真正挡住厂商调用的是 gatedProvider;这里兜住一切到达
			// ask 阶段的调用)
			return permission.Denied("外发同意闸:工具 " + name + " 不在只读白名单")
		},
		Hooks:            hooks,
		Transcript:       ts,
		SessionID:        sess.TranscriptID,
		MaxTurns:         maxTurns,
		MaxConcurrency:   1, // 串行执行:审计耗时配对精确,只读工具无并发需求
		MaxTokens:        maxTokens, // 厂商级:单回复上限(ai_settings.max_tokens)
		WorkingDir:       s.deps.TranscriptDir,
		ToolOutputDir:    s.deps.TranscriptDir,
		OnWarn:           func(string) {}, // 警告进坑点排查,不刷屏
		SystemReminderFunc: func() string {
			return "铁律:一切发现=疑似候选,报证据锚点(源+行号),不许断言;只读。"
		},
	})
	defer core.Close()
	// 续聊:transcript 已在盘 → 恢复消息史(norma 断点续传语义)
	if _, statErr := os.Stat(ts.MainPath(sess.TranscriptID)); statErr == nil {
		if err := core.Resume(sess.TranscriptID); err != nil {
			out <- Event{Kind: "error", ErrText: "会话恢复失败: " + err.Error()}
			return
		}
	}

	var lastText string
	finalReason := "interrupted" // 无 result 事件(硬中断)时的如实兜底
	for ev, err := range core.Prompt(ctx, prompt) {
		if err != nil {
			out <- Event{Kind: "error", ErrText: err.Error()}
			finalReason = "model_error"
			continue
		}
		switch ev.Kind {
		case harness.KindText:
			out <- Event{Kind: "text", Text: ev.Text}
		case harness.KindThinking:
			out <- Event{Kind: "thinking", Text: ev.Text}
		case harness.KindToolUse:
			if ev.ToolUse != nil {
				out <- Event{Kind: "tool_use", ToolName: ev.ToolUse.Name,
					ToolInput: string(ev.ToolUse.Input)}
			}
		case harness.KindToolResult:
			if ev.ToolResult != nil {
				var flat string
				for _, b := range ev.ToolResult.Content {
					flat += b.Text
				}
				if r := []rune(flat); len(r) > 500 {
					flat = string(r[:500]) + "…(截断呈现,全文见审计/transcript)"
				}
				out <- Event{Kind: "tool_result", ToolOutput: flat,
					IsError: ev.ToolResult.IsError}
			}
		case harness.KindUsage:
			if ev.Usage != nil {
				// norma canonical Usage(见 vendor llm/anthropic.go norm 注释):
				// InputTokens 已是全量(含缓存子集),CacheReadTokens ⊆
				// InputTokens——不得再叠加(切片七台架实测:叠加把缓存子集
				// 计了两遍,736 源案件虚报 ~1.75 倍,预算提前熔断)
				budget.observe(int64(ev.Usage.InputTokens),
					int64(ev.Usage.OutputTokens))
				out <- Event{Kind: "usage",
					TokensIn:  int64(ev.Usage.InputTokens),
					TokensOut: int64(ev.Usage.OutputTokens)}
			}
		case harness.KindResult:
			if ev.Terminal != nil {
				lastText = ev.Terminal.Text
				finalReason = string(ev.Terminal.Reason)
				in, outTok := budget.totals()
				rev := Event{Kind: "result", Text: lastText, Reason: finalReason,
					TokensIn: in, TokensOut: outTok}
				if ev.Terminal.Err != nil {
					rev.ErrText = ev.Terminal.Err.Error() // 模型侧错误如实透传
				}
				out <- rev
			}
		}
		// 预算硬停(第二道;第一道是 PreToolUse 熔断):超预算即 cancel,
		// 如实给终态事件
		if budget.exceeded() {
			cancel()
			in, outTok := budget.totals()
			out <- Event{Kind: "budget_exceeded", Reason: "budget_exceeded",
				TokensIn: in, TokensOut: outTok,
				ErrText: fmt.Sprintf("会话 token 预算熔断: 已用 %d > 预算 %d",
					in+outTok, sess.BudgetTokens)}
			break
		}
	}

	in, outTok := budget.totals()
	_ = s.deps.Meta.TouchAISession(context.Background(), sess.ID, in, outTok)
	_, _, _ = s.deps.Audit.AppendAudit(context.Background(), sess.CaseID, sess.CreatedBy,
		"ai.message", sess.ID, map[string]any{
			"reason": finalReason, "tokens_in": in, "tokens_out": outTok,
			"tool_calls": rec.calls(), "budget": sess.BudgetTokens,
		})
}
