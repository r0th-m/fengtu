-- 0.24.0-convergence:意图链三层收敛的 L1 预算闸 + L2 停车场
-- (L0 章节=playbook 意图树,已由 005/模板层承担,本迁移不动)。
--
--   - ai_settings 补三列预算闸(默认 5/30/200,设置页可改,对之后的
--     派发即时生效,不追回在跑):
--       intent_fanout_limit  每意图派生扇出上限(一次写回的总子意图数,
--                            模板子+AI 子合计;超限部分转停车场);
--       intent_chapter_limit 每章(playbook 顶层 goal 子树)自动派生意图
--                            数上限(防单分支吃光);
--       intent_case_limit    每案自动派生意图总数上限。
--     三闸只管自动派生(worker 写回路径);人工手写意图/线索不受限
--     (判断权归人)。超闸意图不落 open 队列,落 status='parked' 节点
--     + intent_parking 条目,展开/丢弃一律人批。
--   - intent_nodes.status 补 'parked'(预算闸/AI 申请的未展开意图;
--     不可派发,图上灰色虚线框,人点展开才转 open)。
--   - intent_parking:停车场账。一条 = 一条未展开线索:来源意图、
--     线索摘要、AI 归属建议(哪章=suggest_goal_id,空=建议新开章)、
--     转入原因、章节收官评估建议(verdict:AI 只建议不自动开,
--     展开仍走人点 deploy)、处置留痕(decided_by/at)。

ALTER TABLE intent_nodes DROP CONSTRAINT IF EXISTS intent_nodes_status_check;
ALTER TABLE intent_nodes ADD CONSTRAINT intent_nodes_status_check
    CHECK (status IN ('open', 'awaiting_approval', 'running', 'supported',
                      'denied', 'doubt', 'closed_exhausted', 'closed', 'parked'));

ALTER TABLE ai_settings
    ADD COLUMN IF NOT EXISTS intent_fanout_limit INT NOT NULL DEFAULT 5
        CHECK (intent_fanout_limit > 0),
    ADD COLUMN IF NOT EXISTS intent_chapter_limit INT NOT NULL DEFAULT 30
        CHECK (intent_chapter_limit > 0),
    ADD COLUMN IF NOT EXISTS intent_case_limit INT NOT NULL DEFAULT 200
        CHECK (intent_case_limit > 0);

CREATE TABLE IF NOT EXISTS intent_parking (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         UUID NOT NULL REFERENCES cases(id),
    node_id         UUID NOT NULL REFERENCES intent_nodes(id), -- parked 图节点(摘要/血缘在图上)
    source_node_id  UUID,                   -- 来源意图(转出它的那条;park_lead=发起申请的意图)
    suggest_goal_id UUID,                   -- AI 归属建议:章(goal 节点);NULL=建议新开章
    suggest_label   TEXT NOT NULL DEFAULT '', -- 归属建议人读标签(章名/新章名快照,goal 没了也可读)
    reason          TEXT NOT NULL
        CHECK (reason IN ('budget_fanout', 'budget_chapter', 'budget_case', 'park_lead')),
    verdict         TEXT NOT NULL DEFAULT ''
        CHECK (verdict IN ('', 'deploy', 'dismiss')), -- 章节收官评估建议(空=未评估;AI 只建议)
    verdict_reason  TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'parked'
        CHECK (status IN ('parked', 'deployed', 'dismissed')),
    created_by      TEXT NOT NULL DEFAULT 'ai', -- 转出方(ai|rule;park_lead=ai)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at      TIMESTAMPTZ,               -- 人处置时刻(展开/丢弃;留痕)
    decided_by      TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_intent_parking_case ON intent_parking(case_id, status);
