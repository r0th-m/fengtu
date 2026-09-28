-- 0.31.0-narrative-report:研判报告(AI 生成)版本账。
--
--   - 形态二报告(结构化报告不动):LLM 按本案 grounding 数据生成,
--     opt-in(前端明示消耗 token 二次确认);生成走 agentloop 会话
--     (LLM 录制/预算熔断/外发闸同纪律),落审计 report.generate。
--   - 同案可多次生成,version 按 (case_id, kind) 递增保留历史;
--     版本号由单条 INSERT 的 SELECT COALESCE(MAX(version),0)+1 子查询算出,
--     唯一约束兜底并发双写(撞了如实报错,不静默覆盖)。
--   - content 存 LLM 产出的原文(不做任何加工,证据链如实);
--     「AI 生成初稿,定论归人」报告头/截断标注由读侧按元数据动态拼,
--     不写进库里(元数据改动不回头改原文)。
--   - 判断权归人:报告是初稿,表里没有也不许有「已定论」语义列。
CREATE TABLE IF NOT EXISTS case_reports (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id     UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL DEFAULT 'narrative'
        CHECK (kind IN ('narrative')),  -- 研判报告;结构化报告不落库(实时渲染)
    version     INT NOT NULL,
    content     TEXT NOT NULL,          -- LLM 产出原文(markdown)
    tokens_in   BIGINT NOT NULL DEFAULT 0,  -- 本次生成实际消耗(厂商 usage 汇总)
    tokens_out  BIGINT NOT NULL DEFAULT 0,
    truncated   BOOLEAN NOT NULL DEFAULT FALSE, -- token 预算熔断截断(如实)
    created_by  TEXT NOT NULL DEFAULT '',     -- 点生成的人(opt-in 归责)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (case_id, kind, version)
);

CREATE INDEX IF NOT EXISTS idx_case_reports_case
    ON case_reports(case_id, kind, version DESC);
