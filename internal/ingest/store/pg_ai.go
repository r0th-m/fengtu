// AI 会话账 + 平台设置的 PG 实现(切片五;migrations/004_slice5.sql)。
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// AISession 一条 AI 会话账(消息正文在 norma transcript JSONL,这里只记账)。
type AISession struct {
	ID           string    `json:"id"`
	CaseID       string    `json:"case_id"`
	TranscriptID string    `json:"transcript_id"`
	Status       string    `json:"status"` // active | aborted
	CreatedBy    string    `json:"created_by"`
	TokensIn     int64     `json:"tokens_in"`
	TokensOut    int64     `json:"tokens_out"`
	BudgetTokens int64     `json:"budget_tokens"`
	// HostScope 主机范围(切片七,意图 worker 会话):空=全案件;
	// 具体主机键=只读工具强制限定该主机的源集合(系统闸)。
	HostScope    string    `json:"host_scope"`
	CreatedAt    time.Time `json:"created_at"`
	LastActiveAt time.Time `json:"last_active_at"`
}

// AISettings 平台级 AI 配置(单行 id=1;api_key 只存 AES-GCM 密文)。
type AISettings struct {
	ID                  int       `json:"id"`
	Provider            string    `json:"provider"`
	// Protocol 厂商线格式(018 迁移,0.27.0):openai-compatible|anthropic|ollama,
	// 默认 openai-compatible(存量行由迁移 DEFAULT 补齐,向后兼容)。
	Protocol            string    `json:"protocol"`
	BaseURL             string    `json:"base_url"`
	Model               string    `json:"model"`
	APIKeyEnc           string    `json:"-"` // 密文,永不序列化出 API
	HasKey              bool      `json:"has_key"`
	OutboundEnabled     bool      `json:"outbound_enabled"`
	SessionBudgetTokens int64     `json:"session_budget_tokens"`
	MaxTokens           int       `json:"max_tokens"`      // 厂商级:单回复上限(切片六)
	RatePerSecond       float64   `json:"rate_per_second"` // 厂商级:限速(先记账不拦截)
	// RecordMode LLM 录制档位(009 迁移):off|metadata|full,
	// 默认 metadata=只记元数据,full=opt-in 录 prompt/response 全文。
	RecordMode string `json:"record_mode"`
	// AgentConcurrency 意图引擎派发 worker 的全局并发上限(010 迁移,
	// 默认 4):超限排队,过程流如实记「排队中(并发上限 N)」。
	AgentConcurrency int `json:"agent_concurrency"`
	// 意图链分支预算三闸(014 迁移,0.24.0-convergence;默认 5/30/200):
	// 扇出(每意图派生子意图上限)/章(每 goal 子树自动派生上限)/
	// 案(每案自动派生上限);超闸转停车场,人批才展开。
	IntentFanoutLimit  int `json:"intent_fanout_limit"`
	IntentChapterLimit int `json:"intent_chapter_limit"`
	IntentCaseLimit    int `json:"intent_case_limit"`
	// GlobalProxy 全局出口代理(http/https/socks5,空=直连):
	// LLM 厂商请求 + 联网搜索请求走它。
	GlobalProxy string `json:"global_proxy"`
	// WebSearchEnabled/WebSearchBackend 联网搜索开关 + 后端
	// (ddgs 免 key;brave-free/tavily 需 search_api_key)。
	WebSearchEnabled bool   `json:"web_search_enabled"`
	WebSearchBackend string `json:"web_search_backend"`
	// SearchAPIKeyEnc 搜索后端 key,只存 AES-GCM 密文(同 api_key 纪律)。
	SearchAPIKeyEnc string `json:"-"`
	HasSearchKey    bool   `json:"search_key_set"`
	UpdatedAt  time.Time `json:"updated_at"`
	UpdatedBy  string    `json:"updated_by"`
}

func (p *PG) CreateAISession(ctx context.Context, s *AISession) error {
	err := p.pool.QueryRow(ctx, `
		INSERT INTO ai_sessions (case_id, transcript_id, created_by, budget_tokens, host_scope)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, last_active_at`,
		s.CaseID, s.TranscriptID, s.CreatedBy, s.BudgetTokens, s.HostScope).
		Scan(&s.ID, &s.CreatedAt, &s.LastActiveAt)
	if err != nil {
		return fmt.Errorf("AI 会话建账失败: %w", err)
	}
	return nil
}

const aiSessionCols = `id, case_id, transcript_id, status, created_by,
	tokens_in, tokens_out, budget_tokens, host_scope, created_at, last_active_at`

func scanAISession(row interface{ Scan(...any) error }) (*AISession, error) {
	var s AISession
	err := row.Scan(&s.ID, &s.CaseID, &s.TranscriptID, &s.Status, &s.CreatedBy,
		&s.TokensIn, &s.TokensOut, &s.BudgetTokens, &s.HostScope,
		&s.CreatedAt, &s.LastActiveAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// GetAISession 取会话(nil = 无此会话)。
func (p *PG) GetAISession(ctx context.Context, id string) (*AISession, error) {
	s, err := scanAISession(p.pool.QueryRow(ctx,
		`SELECT `+aiSessionCols+` FROM ai_sessions WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("AI 会话查询失败: %w", err)
	}
	return s, nil
}

func (p *PG) ListAISessions(ctx context.Context, caseID string) ([]AISession, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT `+aiSessionCols+` FROM ai_sessions
		 WHERE case_id = $1 ORDER BY created_at`, caseID)
	if err != nil {
		return nil, fmt.Errorf("AI 会话清单查询失败: %w", err)
	}
	defer rows.Close()
	var out []AISession
	for rows.Next() {
		s, err := scanAISession(rows)
		if err != nil {
			return nil, fmt.Errorf("AI 会话行解析失败: %w", err)
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// TouchAISession 一轮消息收尾:累计 token + 心跳(取大不取加,usage 是累计快照)。
func (p *PG) TouchAISession(ctx context.Context, id string, tokensIn, tokensOut int64) error {
	_, err := p.pool.Exec(ctx, `
		UPDATE ai_sessions
		SET tokens_in = GREATEST(tokens_in, $2),
		    tokens_out = GREATEST(tokens_out, $3),
		    last_active_at = now()
		WHERE id = $1`, id, tokensIn, tokensOut)
	if err != nil {
		return fmt.Errorf("AI 会话记账失败: %w", err)
	}
	return nil
}

// AbortAISession 标记中断(active → aborted;ok=false = 无此会话)。
func (p *PG) AbortAISession(ctx context.Context, id string) (bool, error) {
	tag, err := p.pool.Exec(ctx, `
		UPDATE ai_sessions SET status = 'aborted', last_active_at = now()
		WHERE id = $1 AND status = 'active'`, id)
	if err != nil {
		return false, fmt.Errorf("AI 会话中断落账失败: %w", err)
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if err := p.pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM ai_sessions WHERE id = $1)`, id).
			Scan(&exists); err != nil {
			return false, fmt.Errorf("AI 会话查询失败: %w", err)
		}
		if !exists {
			return false, nil
		}
		return true, nil // 已是 aborted:幂等
	}
	return true, nil
}

// GetAISettings 读平台设置(nil = 从未配置)。
func (p *PG) GetAISettings(ctx context.Context) (*AISettings, error) {
	var st AISettings
	err := p.pool.QueryRow(ctx, `
		SELECT id, provider, COALESCE(protocol, 'openai-compatible'), base_url, model,
		       api_key_enc, outbound_enabled,
		       session_budget_tokens, max_tokens, rate_per_second,
		       COALESCE(record_mode, 'metadata'),
		       COALESCE(agent_concurrency, 4), COALESCE(global_proxy, ''),
		       COALESCE(web_search_enabled, false),
		       COALESCE(web_search_backend, 'ddgs'),
		       COALESCE(search_api_key_enc, ''),
		       COALESCE(intent_fanout_limit, 5), COALESCE(intent_chapter_limit, 30),
		       COALESCE(intent_case_limit, 200),
		       updated_at, updated_by
		FROM ai_settings WHERE id = 1`).Scan(
		&st.ID, &st.Provider, &st.Protocol, &st.BaseURL, &st.Model, &st.APIKeyEnc,
		&st.OutboundEnabled, &st.SessionBudgetTokens, &st.MaxTokens,
		&st.RatePerSecond, &st.RecordMode,
		&st.AgentConcurrency, &st.GlobalProxy, &st.WebSearchEnabled,
		&st.WebSearchBackend, &st.SearchAPIKeyEnc,
		&st.IntentFanoutLimit, &st.IntentChapterLimit, &st.IntentCaseLimit,
		&st.UpdatedAt, &st.UpdatedBy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("AI 平台设置读取失败: %w", err)
	}
	st.HasKey = st.APIKeyEnc != ""
	st.HasSearchKey = st.SearchAPIKeyEnc != ""
	return &st, nil
}

// SaveAISettings 平台设置 upsert(单行 id=1)。
func (p *PG) SaveAISettings(ctx context.Context, st *AISettings) error {
	st.ID = 1
	if st.RecordMode == "" {
		st.RecordMode = "metadata" // 档位默认只记元数据(009 迁移 DEFAULT 同口径)
	}
	if st.AgentConcurrency <= 0 {
		st.AgentConcurrency = 4 // 并发上限默认(010 迁移 DEFAULT 同口径)
	}
	// 预算三闸默认(014 迁移 DEFAULT 同口径)
	if st.IntentFanoutLimit <= 0 {
		st.IntentFanoutLimit = 5
	}
	if st.IntentChapterLimit <= 0 {
		st.IntentChapterLimit = 30
	}
	if st.IntentCaseLimit <= 0 {
		st.IntentCaseLimit = 200
	}
	if st.WebSearchBackend == "" {
		st.WebSearchBackend = "ddgs" // 搜索后端默认免 key 档(010 迁移 DEFAULT 同口径)
	}
	if st.Protocol == "" {
		st.Protocol = "openai-compatible" // 018 迁移 DEFAULT 同口径
	}
	_, err := p.pool.Exec(ctx, `
		INSERT INTO ai_settings
			(id, provider, protocol, base_url, model, api_key_enc, outbound_enabled,
			 session_budget_tokens, max_tokens, rate_per_second, record_mode,
			 agent_concurrency, global_proxy, web_search_enabled,
			 web_search_backend, search_api_key_enc,
			 intent_fanout_limit, intent_chapter_limit, intent_case_limit,
			 updated_at, updated_by)
		VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
		ON CONFLICT (id) DO UPDATE SET
			provider = EXCLUDED.provider,
			protocol = EXCLUDED.protocol,
			base_url = EXCLUDED.base_url,
			model = EXCLUDED.model,
			api_key_enc = EXCLUDED.api_key_enc,
			outbound_enabled = EXCLUDED.outbound_enabled,
			session_budget_tokens = EXCLUDED.session_budget_tokens,
			max_tokens = EXCLUDED.max_tokens,
			rate_per_second = EXCLUDED.rate_per_second,
			record_mode = EXCLUDED.record_mode,
			agent_concurrency = EXCLUDED.agent_concurrency,
			global_proxy = EXCLUDED.global_proxy,
			web_search_enabled = EXCLUDED.web_search_enabled,
			web_search_backend = EXCLUDED.web_search_backend,
			search_api_key_enc = EXCLUDED.search_api_key_enc,
			intent_fanout_limit = EXCLUDED.intent_fanout_limit,
			intent_chapter_limit = EXCLUDED.intent_chapter_limit,
			intent_case_limit = EXCLUDED.intent_case_limit,
			updated_at = EXCLUDED.updated_at,
			updated_by = EXCLUDED.updated_by`,
		st.Provider, st.Protocol, st.BaseURL, st.Model, st.APIKeyEnc, st.OutboundEnabled,
		st.SessionBudgetTokens, st.MaxTokens, st.RatePerSecond, st.RecordMode,
		st.AgentConcurrency, st.GlobalProxy, st.WebSearchEnabled,
		st.WebSearchBackend, st.SearchAPIKeyEnc,
		st.IntentFanoutLimit, st.IntentChapterLimit, st.IntentCaseLimit,
		st.UpdatedAt, st.UpdatedBy)
	if err != nil {
		return fmt.Errorf("AI 平台设置落库失败: %w", err)
	}
	return nil
}
