-- 0.29.1-goal-lifecycle:intent_nodes.status 补 goal 收官机器评估三态
-- ('closed_goal_met', 'closed_goal_partial', 'closed_goal_unmet')。
--
--   - 语义:goal 不可派发,子树内全部意图到终态后系统按证据结构置机器
--     评估档(全部 supported=met / 部分=partial / 零=unmet),措辞如实
--     「机器评估,收官定论归人」;三态同为终态,不进派发队列
--     (NextRunnable 只领 open intent)。子树重新出现未终态意图(停车场
--     展开等)重估回 open——机器评估态不作数,如实。
--   - 触发点:worker 写回/审批驳回/人工停 open/停车场展开/报告生成
--     (旧 goal 的一次性重估路径),全部幂等。
--
-- 与 014/017 同手法:整约束替换(status 枚举是 CHECK 内联清单)。

ALTER TABLE intent_nodes DROP CONSTRAINT IF EXISTS intent_nodes_status_check;
ALTER TABLE intent_nodes ADD CONSTRAINT intent_nodes_status_check
    CHECK (status IN ('open', 'awaiting_approval', 'running', 'supported',
                      'denied', 'doubt', 'closed_exhausted', 'closed', 'parked',
                      'stopped',
                      'closed_goal_met', 'closed_goal_partial',
                      'closed_goal_unmet'));
