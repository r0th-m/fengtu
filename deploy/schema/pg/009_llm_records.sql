-- 切片十(ARTEX 布局全量复刻·LLM 录制,设计 §7 延伸):
-- llm_records 一次厂商调用的录制账(agentloop 层挂钩落库,gatedProvider
-- 外侧包 recordingProvider)。
-- 档位纪律(record_mode 落 ai_settings 单行):
--   off      = 不录;
--   metadata = 默认,只记元数据(时间/模型/token/耗时/会话+案件锚/成败);
--   full     = opt-in,追加 prompt/response 全文(截断上限在代码侧焊死)。
-- 判断权归人:录制是台账不是证据,候选仍走 hits 人工裁决。
CREATE TABLE IF NOT EXISTS llm_records (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id  UUID,                       -- 关联 ai_sessions(沟通区/意图 worker 同账)
    case_id     UUID,                       -- 冗余案件锚(列表筛选免 join;空=无案件上下文)
    kind        TEXT NOT NULL DEFAULT 'chat'
        CHECK (kind IN ('chat', 'intent')), -- chat=沟通区;intent=意图 worker(附加 system 段)
    model       TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'ok'
        CHECK (status IN ('ok', 'error')),
    err         TEXT NOT NULL DEFAULT '',
    tokens_in   BIGINT NOT NULL DEFAULT 0,  -- 本次调用厂商 usage(未返回=0,如实不猜)
    tokens_out  BIGINT NOT NULL DEFAULT 0,
    duration_ms BIGINT NOT NULL DEFAULT 0,
    prompt      TEXT,                       -- record_mode=full 才落;元数据模式 NULL
    response    TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_llm_records_created
    ON llm_records(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_llm_records_case
    ON llm_records(case_id, created_at DESC);

-- 录制档位落平台设置单行(off|metadata|full;默认 metadata=只记元数据)。
ALTER TABLE ai_settings
    ADD COLUMN IF NOT EXISTS record_mode TEXT NOT NULL DEFAULT 'metadata'
        CHECK (record_mode IN ('off', 'metadata', 'full'));
