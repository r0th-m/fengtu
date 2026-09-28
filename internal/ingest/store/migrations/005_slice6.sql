-- 丰图 v2 切片六:意图链引擎(DESIGN §6/§6.4)——双图 + planner/worker +
-- 四层预算 + 审批门。
--
--   - 意图图(每案件):intent_nodes + intent_edges。节点五型
--     (goal/intent/fact/finding/hint),状态机如实——closed_exhausted 不是
--     失败,是「时间耗尽,覆盖可能不全」的如实标;awaiting_approval 是
--     审批门的挂起态(AI/规则派生的批量执行意图,人批才放行);
--   - 证据图(全局+案件):evidence_anchors——意图/事实节点挂锚点,
--     锚到既有 sources/hits(复用不另造);kind=evidence(写回证据)|
--     explored(执行过程摸过的源,供源覆盖图算「查没查过」);
--   - 执行过程流:intent_events——每条意图的执行步骤逐步留痕可回看
--     (§6 执行过程流的后端);
--   - 四层预算:意图级 wall-clock(intent_nodes.budget_seconds 快照)+
--     案件级 deadline(cases.deadline_at,到点进收尾模式)+ 会话级 token
--     (复用 ai_sessions.budget_tokens)+ 厂商级(ai_settings 补
--     max_tokens 单回复上限 + rate_per_second,先记账不拦截)。

CREATE TABLE IF NOT EXISTS intent_nodes (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id       UUID NOT NULL REFERENCES cases(id),
    kind          TEXT NOT NULL
        CHECK (kind IN ('goal', 'intent', 'fact', 'finding', 'hint')),
    text          TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'awaiting_approval', 'running', 'supported',
                          'denied', 'doubt', 'closed_exhausted', 'closed')),
    created_by    TEXT NOT NULL
        CHECK (created_by IN ('human', 'ai', 'rule')),
    rule_id       TEXT NOT NULL DEFAULT '',     -- 规则播种关联(三源播种之一)
    template_id   TEXT NOT NULL DEFAULT '',     -- playbook 模板实例化来源
    template_key  TEXT NOT NULL DEFAULT '',     -- 模板内意图 key(子意图派生定位)
    scope         TEXT NOT NULL DEFAULT 'case'
        CHECK (scope IN ('case', 'all')),       -- all=批量执行意图(全案件/全源,过审批门)
    parent_id     UUID,                          -- 派生父节点(深度计算)
    depth         INT NOT NULL DEFAULT 0,        -- 派生深度(≤5 防无限展开)
    evidence      JSONB NOT NULL DEFAULT '[]',   -- 写回锚点 [{source_id,line_no,note}]
    result_text   TEXT NOT NULL DEFAULT '',      -- 评估结论摘要
    close_note    TEXT NOT NULL DEFAULT '',      -- 关闭说明(耗尽/停止/拒批如实)
    session_id    UUID,                          -- worker 执行的 AI 会话(单意图单会话)
    budget_seconds INT NOT NULL DEFAULT 600,     -- 意图级 wall-clock 快照(耗尽→closed_exhausted)
    started_at    TIMESTAMPTZ,
    finished_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_intent_nodes_case ON intent_nodes(case_id, status, created_at);
-- 规则播种去重:同案同规则只允许一条未终态(open/awaiting_approval/running)意图
CREATE UNIQUE INDEX IF NOT EXISTS idx_intent_nodes_rule_open
    ON intent_nodes(case_id, rule_id)
    WHERE rule_id <> '' AND status IN ('open', 'awaiting_approval', 'running');

CREATE TABLE IF NOT EXISTS intent_edges (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id    UUID NOT NULL REFERENCES cases(id),
    from_id    UUID NOT NULL REFERENCES intent_nodes(id),
    to_id      UUID NOT NULL REFERENCES intent_nodes(id),
    kind       TEXT NOT NULL
        CHECK (kind IN ('spawns', 'derived_from', 'yields', 'proves')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (from_id, to_id, kind)
);

CREATE INDEX IF NOT EXISTS idx_intent_edges_case ON intent_edges(case_id);

-- 证据图锚点:意图/事实/发现节点 → 既有 sources/hits(复用不另造)。
CREATE TABLE IF NOT EXISTS evidence_anchors (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id    UUID NOT NULL REFERENCES cases(id),
    node_id    UUID NOT NULL REFERENCES intent_nodes(id),
    source_id  UUID REFERENCES sources(id),     -- 可空(纯 hit 关联时)
    line_no    INT,                              -- 可空(explored 语义=摸过该源)
    hit_id     UUID,                             -- 关联既有候选(hits.id,弱关联不 FK——hits 可清理)
    kind       TEXT NOT NULL DEFAULT 'evidence'
        CHECK (kind IN ('evidence', 'explored')),
    note       TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_evidence_anchors_source ON evidence_anchors(case_id, source_id);
CREATE INDEX IF NOT EXISTS idx_evidence_anchors_node ON evidence_anchors(node_id);

-- 执行过程流(§6 执行过程流后端):每条意图的执行步骤逐步留痕。
CREATE TABLE IF NOT EXISTS intent_events (
    id         BIGSERIAL PRIMARY KEY,
    case_id    UUID NOT NULL REFERENCES cases(id),
    node_id    UUID NOT NULL REFERENCES intent_nodes(id),
    kind       TEXT NOT NULL,   -- plan|text|thinking|tool_use|tool_result|usage|eval|spawn|budget|stop|error
    text       TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_intent_events_node ON intent_events(node_id, id);

-- 案件级 deadline(可选):到点进「收尾模式」——planner 停派新意图,
-- 运行中意图写回后关闭。
ALTER TABLE cases ADD COLUMN IF NOT EXISTS deadline_at TIMESTAMPTZ;

-- 厂商级预算(先记账不拦截,2026-09-22 调研定稿):max_tokens=单回复
-- 上限(接入 agentloop Options.MaxTokens);rate_per_second 先存不用。
ALTER TABLE ai_settings ADD COLUMN IF NOT EXISTS max_tokens INT NOT NULL DEFAULT 4096
    CHECK (max_tokens > 0);
ALTER TABLE ai_settings ADD COLUMN IF NOT EXISTS rate_per_second DOUBLE PRECISION NOT NULL DEFAULT 0;
