-- 0.28.0-blackboard:派生去重闸转入停车场的两个新原因。
--
--   - dup_exact:AI 派生意图与本案现存意图归一化文本完全相同,直接拦
--     (转停车场,人可捞可丢;判断权归人);
--   - dup_similar:关键词 Jaccard ≥ 0.85 高度相似,转停车场待人裁,
--     播报板播报「疑似重复,已入停车场」。
--
-- 与 017 同手法:整约束替换(reason 枚举是 CHECK 内联清单)。

ALTER TABLE intent_parking DROP CONSTRAINT IF EXISTS intent_parking_reason_check;
ALTER TABLE intent_parking ADD CONSTRAINT intent_parking_reason_check
    CHECK (reason IN ('budget_fanout', 'budget_chapter', 'budget_case',
                      'park_lead', 'dup_exact', 'dup_similar'));
