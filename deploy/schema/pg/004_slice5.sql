-- 丰图 v2 切片五:AI 沟通骨架(DESIGN §7)——norma 薄壳 + 只读工具 + 治理闸。
--
--   - ai_sessions:交流区会话账(绑案件,可续聊)。消息正文不落 PG——
--     transcript 由 norma 落 data/ai/<transcript_id>.jsonl(追加态),
--     PG 只记账:状态/累计 token/预算。判断权纪律:AI 产出 hits 走既有
--     hits 表 pending,本表不存「结论」;
--   - ai_settings:平台级 AI 配置(单行,id=1)。api_key 只存 AES-GCM
--     密文(base64(nonce‖ciphertext),密钥出环境变量 FENGTU_AI_SECRET),
--     永不明文入库(§9;索图 ai.py 治理语义移植);
--   - outbound_enabled:平台级 AI 外发开关(默认关)——关=任何厂商调用
--     前 403 如实(外发同意闸的持久态)。

CREATE TABLE IF NOT EXISTS ai_sessions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id       UUID NOT NULL REFERENCES cases(id),
    transcript_id TEXT NOT NULL UNIQUE,        -- norma transcript 会话 id(data/ai/ 下 JSONL 文件名)
    status        TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'aborted')),
    created_by    TEXT NOT NULL,               -- 开会话的真人(审计锚点)
    tokens_in     BIGINT NOT NULL DEFAULT 0,   -- 累计输入 token(含续聊各轮)
    tokens_out    BIGINT NOT NULL DEFAULT 0,
    budget_tokens BIGINT NOT NULL DEFAULT 200000, -- 会话预算(快照:建会话时取平台配置)
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_sessions_case ON ai_sessions(case_id, created_at);

CREATE TABLE IF NOT EXISTS ai_settings (
    id                   INT PRIMARY KEY DEFAULT 1 CHECK (id = 1), -- 单行(平台级)
    provider             TEXT NOT NULL DEFAULT 'deepseek',         -- 厂商标签(当前仅 OpenAI 线格式,DeepSeek 兼容)
    base_url             TEXT NOT NULL DEFAULT '',
    model                TEXT NOT NULL DEFAULT '',
    api_key_enc          TEXT NOT NULL DEFAULT '',                 -- AES-GCM 密文 base64(nonce‖ct);空=未配置
    outbound_enabled     BOOLEAN NOT NULL DEFAULT false,           -- AI 外发总开关(默认关,§7 外发同意闸)
    session_budget_tokens BIGINT NOT NULL DEFAULT 200000           -- 默认会话 token 预算(PreToolUse 熔断阈值)
        CHECK (session_budget_tokens > 0),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by           TEXT NOT NULL DEFAULT ''
);
