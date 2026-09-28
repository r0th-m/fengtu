-- 案件级 KB 勾选(0.20.0-case-kb):KB 条目不再全量全局注入每个意图 worker
-- (prompt 变长每轮多付 token),改为建任务时按案件勾选本案生效的条目。
--
--   - case_kb_entries:本案勾选的条目集(case_id × entry_id)。entry_id 是
--     文本:内置条目 id 是 YAML 里的字符串,用户条目 id 是 kb_entries 的
--     UUID 文本——两类同池,故无外键(删用户条目时级联清勾选行在代码侧做)。
--   - 注入语义:worker system「启发式参考」= 本案勾选 ∩ 全局启用(内置未
--     禁用 + 用户 enabled)。本案一条没勾(含存量案件零勾选记录)= 如实
--     不注入,不兜底全量。
--   - 改即生效:勾选变动对之后派发的 worker 生效,在跑的不追回(与并发
--     上限同口径);勾选差集落审计 kb.case_update。
CREATE TABLE IF NOT EXISTS case_kb_entries (
    case_id    UUID NOT NULL REFERENCES cases(id),
    entry_id   TEXT NOT NULL,
    chosen_by  TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (case_id, entry_id)
);

CREATE INDEX IF NOT EXISTS idx_case_kb_entries_case
    ON case_kb_entries(case_id);
