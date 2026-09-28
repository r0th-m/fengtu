-- 0.27.0 案件封存/迁移(M4):intent_nodes.status 补 'stopped'。
--
--   - 语义:跨实例迁移导入时,源实例导出当下仍在 running/awaiting_approval
--     的意图在目标实例一律落 stopped——迁移不续跑(执行上下文/AI 会话/
--     任务账不随包),人看过证据后重新派发。stopped 是终态:planner 只领
--     open,章收官判定(chapterComplete)只把 open/awaiting_approval/
--     running 当未清,stopped 不挡收官。
--   - 迁移路径:案件封存 zip 的意图图节点状态原样随包,改写发生在导入侧
--     (internal/web/handlers_seal.go),库内不许出现来源不明的 stopped。
--
-- 与 014 同手法:整约束替换( status 枚举是 CHECK 内联清单)。

ALTER TABLE intent_nodes DROP CONSTRAINT IF EXISTS intent_nodes_status_check;
ALTER TABLE intent_nodes ADD CONSTRAINT intent_nodes_status_check
    CHECK (status IN ('open', 'awaiting_approval', 'running', 'supported',
                      'denied', 'doubt', 'closed_exhausted', 'closed', 'parked',
                      'stopped'));
