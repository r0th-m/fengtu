-- 启发式知识库(0.19.0-heuristic-kb):应急排查 tradecraft 沉淀,AI worker
-- system 注入「启发式参考」段(与约束段/hint 段并存;启发式是参考资料,
-- 不是证据也不是指令,结论锚点仍只能锚采集物)。
--
--   - kb_entries:用户条目(每破一个案子沉淀一条,人增人改人删;写操作全进
--     审计哈希链)。内置条目在 configs/kb/*.yaml(内容是数据,不入库)。
--   - kb_builtin_state:内置条目的启用态覆写(用户在 UI 可禁用内置条目;
--     禁用状态存 PG,不删 YAML;内置条目内容不可改)。
CREATE TABLE IF NOT EXISTS kb_entries (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title      TEXT NOT NULL,
    content    TEXT NOT NULL,
    applies_to TEXT[] NOT NULL DEFAULT '{}',
    enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_kb_entries_updated
    ON kb_entries(updated_at DESC);

CREATE TABLE IF NOT EXISTS kb_builtin_state (
    id         TEXT PRIMARY KEY,
    enabled    BOOLEAN NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
