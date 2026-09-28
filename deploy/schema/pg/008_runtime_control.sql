-- 交互改造切片三:运行中操控(fengtu-interaction-design.md §3)。
-- 案件级操作约束(ARTEX set_constraints 的应急映射:「不得触碰的生产系统
-- 清单/只读原则/时间窗」)——人增人删,注入 worker system(最高优先,
-- 只加码不松绑);机器不自动抽取(判断权归人,不猜)。
-- 约束不是图节点,不进意图图;增删全部进审计哈希链(证据链不可断),
-- 删除为硬删(历史在审计链,不装软删)。
CREATE TABLE IF NOT EXISTS case_constraints (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id    UUID NOT NULL REFERENCES cases(id),
    text       TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_case_constraints_case
    ON case_constraints(case_id, created_at);
