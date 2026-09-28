// AI 平台配置解析(厂商/base_url/key/model/外发开关/预算)与 key 加密。
//
// 优先级:环境变量 > PG 平台设置 > 内置默认(DeepSeek 档)。
// key 纪律(§9,索图 ai.py 治理语义移植):
//   - 环境变量 FENGTU_AI_API_KEY 直读,不落任何库;
//   - PG ai_settings.api_key_enc 只存 AES-GCM 密文(base64(nonce‖ct)),
//     加密密钥出 FENGTU_AI_SECRET(不入库);密文在而密钥不在 → 如实报
//     「无法解密」,不静默当未配置。
package agentloop

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"


	"github.com/ye-mengwen/fengtu/internal/ingest/store"
)

// 内置默认档(DeepSeek,OpenAI 线格式)。
const (
	defaultProvider  = "deepseek"
	defaultBaseURL   = "https://api.deepseek.com/v1"
	defaultModel     = "deepseek-chat"
	defaultBudget    = 200000 // 默认会话 token 预算(§7)
	defaultMaxTokens = 4096   // 默认单回复 token 上限(厂商级,切片六)
	// DefaultAgentConcurrency 意图引擎 worker 全局并发上限默认(切片十一;
	// 010 迁移 DEFAULT 同口径)。
	DefaultAgentConcurrency = 4
	// 意图链分支预算三闸默认(0.24.0-convergence;014 迁移 DEFAULT 同口径):
	// 扇出/章/案;超闸转停车场,人批才展开。
	DefaultIntentFanoutLimit  = 5
	DefaultIntentChapterLimit = 30
	DefaultIntentCaseLimit    = 200
	// 联网搜索后端白名单(010 迁移 CHECK 同口径):ddgs 免 key,其余需 search key。
	searchBackendDDGS   = "ddgs"
	searchBackendBrave  = "brave-free"
	searchBackendTavily = "tavily"
)

func envGet(k string) string { return os.Getenv(k) }

// ResolvedConfig 一次运行用的解析后配置(env 已叠加)。
type ResolvedConfig struct {
	Provider        string  `json:"provider"`
	// Protocol 厂商线格式(0.27.0;openai-compatible|anthropic|ollama;
	// 默认 openai-compatible,018 迁移 DEFAULT 同口径)。
	Protocol        string  `json:"protocol"`
	BaseURL         string  `json:"base_url"`
	Model           string  `json:"model"`
	APIKey          string  `json:"-"` // 永不序列化
	KeySource       string  `json:"key_source"` // env|pg|none(如实呈现 key 来路,不呈现 key)
	OutboundEnabled bool    `json:"outbound_enabled"`
	BudgetTokens    int64   `json:"budget_tokens"`
	MaxTokens       int     `json:"max_tokens"`       // 厂商级:单回复上限
	RatePerSecond   float64 `json:"rate_per_second"`  // 厂商级:限速(先记账不拦截,切片六调研定稿)
	// RecordMode LLM 录制档位(切片十):off|metadata|full;默认 metadata。
	RecordMode string `json:"record_mode"`
	// AgentConcurrency 意图引擎 worker 全局并发上限(切片十一;默认 4)。
	AgentConcurrency int `json:"agent_concurrency"`
	// 意图链分支预算三闸(0.24.0;默认 5/30/200;只闸自动派生,人工不限)。
	IntentFanoutLimit  int `json:"intent_fanout_limit"`
	IntentChapterLimit int `json:"intent_chapter_limit"`
	IntentCaseLimit    int `json:"intent_case_limit"`
	// GlobalProxy 全局出口代理(http/https/socks5,空=直连):
	// LLM 厂商请求 + 联网搜索请求走它。
	GlobalProxy string `json:"global_proxy"`
	// WebSearchEnabled/WebSearchBackend 联网搜索开关 + 后端(ddgs|brave-free|tavily)。
	WebSearchEnabled bool   `json:"web_search_enabled"`
	WebSearchBackend string `json:"web_search_backend"`
	// SearchAPIKey 搜索后端 key(解密后;永不序列化)。SearchKeySet 对外只给有/无。
	SearchAPIKey string `json:"-"`
	SearchKeySet bool   `json:"search_key_set"`
}

// resolveConfig 环境变量 > PG 设置 > 默认。
func (s *Service) resolveConfig(ctx context.Context) (ResolvedConfig, error) {
	cfg := ResolvedConfig{
		Provider:     defaultProvider,
		Protocol:     ProtocolOpenAICompat, // 018 迁移 DEFAULT 同口径
		BaseURL:      defaultBaseURL,
		Model:        defaultModel,
		BudgetTokens: defaultBudget,
		MaxTokens:    defaultMaxTokens,
		KeySource:    "none",
		RecordMode:   "metadata", // 录制默认只记元数据(009 迁移 DEFAULT 同口径)
		AgentConcurrency: DefaultAgentConcurrency, // 010 迁移 DEFAULT 同口径
		WebSearchBackend: searchBackendDDGS,       // 010 迁移 DEFAULT 同口径
		IntentFanoutLimit:  DefaultIntentFanoutLimit,  // 014 迁移 DEFAULT 同口径
		IntentChapterLimit: DefaultIntentChapterLimit,
		IntentCaseLimit:    DefaultIntentCaseLimit,
	}
	st, err := s.deps.Meta.GetAISettings(ctx)
	if err != nil {
		return cfg, fmt.Errorf("AI 平台设置读取失败: %w", err)
	}
	if st != nil {
		if st.Provider != "" {
			cfg.Provider = st.Provider
		}
		if st.Protocol != "" {
			cfg.Protocol = st.Protocol
		}
		if st.BaseURL != "" {
			cfg.BaseURL = st.BaseURL
		}
		if st.Model != "" {
			cfg.Model = st.Model
		}
		if st.SessionBudgetTokens > 0 {
			cfg.BudgetTokens = st.SessionBudgetTokens
		}
		if st.MaxTokens > 0 {
			cfg.MaxTokens = st.MaxTokens
		}
		cfg.RatePerSecond = st.RatePerSecond
		cfg.OutboundEnabled = st.OutboundEnabled
		if st.RecordMode != "" {
			cfg.RecordMode = st.RecordMode
		}
		if st.AgentConcurrency > 0 {
			cfg.AgentConcurrency = st.AgentConcurrency
		}
		if st.IntentFanoutLimit > 0 {
			cfg.IntentFanoutLimit = st.IntentFanoutLimit
		}
		if st.IntentChapterLimit > 0 {
			cfg.IntentChapterLimit = st.IntentChapterLimit
		}
		if st.IntentCaseLimit > 0 {
			cfg.IntentCaseLimit = st.IntentCaseLimit
		}
		cfg.GlobalProxy = st.GlobalProxy
		cfg.WebSearchEnabled = st.WebSearchEnabled
		if st.WebSearchBackend != "" {
			cfg.WebSearchBackend = st.WebSearchBackend
		}
		cfg.SearchKeySet = st.SearchAPIKeyEnc != ""
		if st.SearchAPIKeyEnc != "" {
			key, derr := s.decryptKey(st.SearchAPIKeyEnc)
			if derr != nil {
				return cfg, fmt.Errorf("搜索后端 key %w", derr)
			}
			cfg.SearchAPIKey = key
		}
		if st.APIKeyEnc != "" {
			key, derr := s.decryptKey(st.APIKeyEnc)
			if derr != nil {
				return cfg, derr
			}
			cfg.APIKey, cfg.KeySource = key, "pg"
		}
	}
	// 环境变量覆盖(台架/私有化部署主通路;key 走 env 永不落库)
	if v := s.deps.EnvLookup("FENGTU_AI_PROVIDER"); v != "" {
		cfg.Provider = v
	}
	if v := s.deps.EnvLookup("FENGTU_AI_PROTOCOL"); v != "" {
		if !validProtocol(v) {
			return cfg, fmt.Errorf("FENGTU_AI_PROTOCOL 须为 openai-compatible|anthropic|ollama(收到 %q)", v)
		}
		cfg.Protocol = v
	}
	if v := s.deps.EnvLookup("FENGTU_AI_BASE_URL"); v != "" {
		cfg.BaseURL = v
	}
	if v := s.deps.EnvLookup("FENGTU_AI_MODEL"); v != "" {
		cfg.Model = v
	}
	if v := s.deps.EnvLookup("FENGTU_AI_API_KEY"); v != "" {
		cfg.APIKey, cfg.KeySource = v, "env"
	}
	if v := s.deps.EnvLookup("FENGTU_AI_OUTBOUND"); v != "" {
		cfg.OutboundEnabled = v == "true" || v == "1"
	}
	if v := s.deps.EnvLookup("FENGTU_AI_BUDGET_TOKENS"); v != "" {
		n, perr := strconv.ParseInt(v, 10, 64)
		if perr != nil || n <= 0 {
			return cfg, fmt.Errorf("FENGTU_AI_BUDGET_TOKENS 须为正整数: %q", v)
		}
		cfg.BudgetTokens = n
	}
	if v := s.deps.EnvLookup("FENGTU_AI_MAX_TOKENS"); v != "" {
		n, perr := strconv.Atoi(v)
		if perr != nil || n <= 0 {
			return cfg, fmt.Errorf("FENGTU_AI_MAX_TOKENS 须为正整数: %q", v)
		}
		cfg.MaxTokens = n
	}
	return cfg, nil
}

// PublicConfig 对外呈现(无 key;key 只有无/来路)。
func (s *Service) PublicConfig(ctx context.Context) (ResolvedConfig, error) {
	cfg, err := s.resolveConfig(ctx)
	cfg.APIKey = ""
	cfg.SearchAPIKey = "" // 搜索 key 同纪律:永不回显,只有 search_key_set
	if cfg.KeySource == "none" {
		cfg.KeySource = "none(未配置)"
	}
	return cfg, err
}

// SaveSettings 平台设置落库(key 给明文 → 只存密文;空串 = 不动已存 key;
// 显式 clear_key=true = 清除)。
func (s *Service) SaveSettings(ctx context.Context, actor string,
	in SettingsInput) error {

	cur, err := s.deps.Meta.GetAISettings(ctx)
	if err != nil {
		return err
	}
	st := store.AISettings{ID: 1, UpdatedBy: actor, UpdatedAt: s.deps.Now().UTC(),
		SessionBudgetTokens: defaultBudget,
		MaxTokens:           defaultMaxTokens, // 从零起步时预算落默认(CHECK >0)
		IntentFanoutLimit:   DefaultIntentFanoutLimit,
		IntentChapterLimit:  DefaultIntentChapterLimit,
		IntentCaseLimit:     DefaultIntentCaseLimit} // 014 迁移 DEFAULT 同口径
	if cur != nil {
		st = *cur
		st.UpdatedBy, st.UpdatedAt = actor, s.deps.Now().UTC()
	}
	if in.Provider != nil {
		st.Provider = *in.Provider
	}
	if in.Protocol != nil {
		if !validProtocol(*in.Protocol) {
			return fmt.Errorf("protocol 须为 openai-compatible|anthropic|ollama(收到 %q)",
				*in.Protocol)
		}
		st.Protocol = *in.Protocol
	}
	if in.BaseURL != nil {
		st.BaseURL = *in.BaseURL
	}
	if in.Model != nil {
		st.Model = *in.Model
	}
	if in.OutboundEnabled != nil {
		st.OutboundEnabled = *in.OutboundEnabled
	}
	if in.SessionBudgetTokens != nil {
		if *in.SessionBudgetTokens <= 0 {
			return fmt.Errorf("session_budget_tokens 须为正整数")
		}
		st.SessionBudgetTokens = *in.SessionBudgetTokens
	}
	if in.MaxTokens != nil {
		if *in.MaxTokens <= 0 {
			return fmt.Errorf("max_tokens 须为正整数")
		}
		st.MaxTokens = *in.MaxTokens
	}
	if in.RatePerSecond != nil {
		if *in.RatePerSecond < 0 {
			return fmt.Errorf("rate_per_second 须为非负")
		}
		st.RatePerSecond = *in.RatePerSecond
	}
	if in.RecordMode != nil {
		switch *in.RecordMode {
		case "off", "metadata", "full":
			st.RecordMode = *in.RecordMode
		default:
			return fmt.Errorf("record_mode 须为 off|metadata|full(收到 %q)", *in.RecordMode)
		}
	}
	if in.AgentConcurrency != nil {
		if *in.AgentConcurrency <= 0 {
			return fmt.Errorf("agent_concurrency 须为正整数(收到 %d)", *in.AgentConcurrency)
		}
		st.AgentConcurrency = *in.AgentConcurrency
	}
	// 意图链预算三闸(0.24.0):均须正整数,改即对之后派发生效
	if in.IntentFanoutLimit != nil {
		if *in.IntentFanoutLimit <= 0 {
			return fmt.Errorf("intent_fanout_limit 须为正整数(收到 %d)", *in.IntentFanoutLimit)
		}
		st.IntentFanoutLimit = *in.IntentFanoutLimit
	}
	if in.IntentChapterLimit != nil {
		if *in.IntentChapterLimit <= 0 {
			return fmt.Errorf("intent_chapter_limit 须为正整数(收到 %d)", *in.IntentChapterLimit)
		}
		st.IntentChapterLimit = *in.IntentChapterLimit
	}
	if in.IntentCaseLimit != nil {
		if *in.IntentCaseLimit <= 0 {
			return fmt.Errorf("intent_case_limit 须为正整数(收到 %d)", *in.IntentCaseLimit)
		}
		st.IntentCaseLimit = *in.IntentCaseLimit
	}
	if in.GlobalProxy != nil {
		p, err := validateProxyURL(*in.GlobalProxy)
		if err != nil {
			return err
		}
		st.GlobalProxy = p
	}
	if in.WebSearchEnabled != nil {
		st.WebSearchEnabled = *in.WebSearchEnabled
	}
	if in.WebSearchBackend != nil {
		switch *in.WebSearchBackend {
		case searchBackendDDGS, searchBackendBrave, searchBackendTavily:
			st.WebSearchBackend = *in.WebSearchBackend
		default:
			return fmt.Errorf("web_search_backend 须为 ddgs|brave-free|tavily(收到 %q)",
				*in.WebSearchBackend)
		}
	}
	if in.ClearSearchKey {
		st.SearchAPIKeyEnc = ""
	} else if in.SearchAPIKey != nil && *in.SearchAPIKey != "" {
		enc, err := s.encryptKey(*in.SearchAPIKey)
		if err != nil {
			return err
		}
		st.SearchAPIKeyEnc = enc
	}
	if in.ClearKey {
		st.APIKeyEnc = ""
	} else if in.APIKey != nil && *in.APIKey != "" {
		enc, err := s.encryptKey(*in.APIKey)
		if err != nil {
			return err
		}
		st.APIKeyEnc = enc
	}
	return s.deps.Meta.SaveAISettings(ctx, &st)
}

// SettingsInput 平台设置更新(指针字段:nil = 不动)。
type SettingsInput struct {
	Provider           *string  `json:"provider"`
	Protocol           *string  `json:"protocol"` // openai-compatible|anthropic|ollama
	BaseURL            *string  `json:"base_url"`
	Model              *string  `json:"model"`
	APIKey             *string  `json:"api_key"` // 明文进,密文存;空串=不动
	ClearKey           bool     `json:"clear_key"`
	OutboundEnabled    *bool    `json:"outbound_enabled"`
	SessionBudgetTokens *int64  `json:"session_budget_tokens"`
	MaxTokens          *int     `json:"max_tokens"`      // 厂商级:单回复上限
	RatePerSecond      *float64 `json:"rate_per_second"` // 厂商级:限速(先记账不拦截)
	RecordMode         *string  `json:"record_mode"`     // LLM 录制档位:off|metadata|full
	// AgentConcurrency 意图引擎 worker 全局并发上限(>0;对新派发即时生效,
	// 不追回在跑 worker——与 ARTEX「对之后启动的任务生效」同口径,如实)。
	AgentConcurrency *int `json:"agent_concurrency"`
	// 意图链分支预算三闸(0.24.0;>0;对新派生即时生效,不追回在跑;
	// 只闸自动派生,人工手写意图/线索不受限)。
	IntentFanoutLimit  *int `json:"intent_fanout_limit"`
	IntentChapterLimit *int `json:"intent_chapter_limit"`
	IntentCaseLimit    *int `json:"intent_case_limit"`
	// GlobalProxy 全局出口代理(http/https/socks5 URL;空串=直连)。
	GlobalProxy *string `json:"global_proxy"`
	// WebSearchEnabled/WebSearchBackend 联网搜索开关 + 后端(ddgs 免 key;
	// brave-free/tavily 需 search_api_key,缺 key 时工具不挂载,如实)。
	WebSearchEnabled *bool   `json:"web_search_enabled"`
	WebSearchBackend *string `json:"web_search_backend"`
	// SearchAPIKey 搜索后端 key:明文进,密文存;空串=不动;clear_search_key=清除。
	SearchAPIKey  *string `json:"search_api_key"`
	ClearSearchKey bool   `json:"clear_search_key"`
}

// validateProxyURL 代理 URL 校验(空=直连放行;否则须 http/https/socks5
// 且带主机名——与 norma llm provider 的代理校验同口径,提前在设置层拒)。
func validateProxyURL(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", nil
	}
	u, err := url.Parse(p)
	if err != nil {
		return "", fmt.Errorf("global_proxy 无法解析: %w", err)
	}
	switch u.Scheme {
	case "http", "https", "socks5":
	default:
		return "", fmt.Errorf("global_proxy 须带 scheme http://|https://|socks5://(收到 %q)", raw)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("global_proxy 缺主机名(收到 %q)", raw)
	}
	return p, nil
}

// masterKey AES-GCM 密钥(sha256(FENGTU_AI_SECRET);不入库)。
func (s *Service) masterKey() ([]byte, error) {
	secret := s.deps.EnvLookup("FENGTU_AI_SECRET")
	if secret == "" {
		return nil, fmt.Errorf("FENGTU_AI_SECRET 未设置,无法加解密 API key" +
			"(key 可改走环境变量 FENGTU_AI_API_KEY,永不落库)")
	}
	sum := sha256.Sum256([]byte(secret))
	return sum[:], nil
}

func (s *Service) encryptKey(plain string) (string, error) {
	mk, err := s.masterKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(mk)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

func (s *Service) decryptKey(enc string) (string, error) {
	mk, err := s.masterKey()
	if err != nil {
		return "", fmt.Errorf("平台设置里存有加密 API key,但%w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", fmt.Errorf("API key 密文损坏(base64): %w", err)
	}
	block, err := aes.NewCipher(mk)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("API key 密文损坏(长度过短)")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", fmt.Errorf("API key 解密失败(密钥不对或密文损坏): %w", err)
	}
	return string(plain), nil
}
