-- 丰图 v2 事件表(DESIGN §5 骨架 + §4.2 分区纪律)。
--
--   - PARTITION BY (case_id, toDate(ts)):排查几乎都带时间窗,分区裁剪
--     吃掉大部分扫描量;ts 为 NULL(时区未知的源,如实不归一)落 1970
--     分区,不猜不塞;
--   - ORDER BY (case_id, source_id, line_no):事件溯源锚=源+行号,
--     回查单源按序走主键;
--   - fields:归一字段的 JSON 文本(M0 骨架照 §5 String(JSON);
--     热点列物化是后续切片按查询画像再做的优化,不超前);
--   - raw:原文留证(多行块含续行全文);
--   - kind:event/bad/skip——坏行、跳行同样入库(零静默),消费侧按 kind 过滤。

CREATE TABLE IF NOT EXISTS fengtu.events
(
    case_id   String,
    source_id String,
    line_no   UInt32,                          -- 原文物理行号(1 起;多行块锚起始行)
    ts        Nullable(DateTime64(3, 'UTC')),
    kind      LowCardinality(String),          -- event | bad | skip
    fields    String,                          -- 归一字段 JSON(norm;bad 行含 reason)
    raw       String
)
ENGINE = MergeTree
PARTITION BY (case_id, toDate(ts))
ORDER BY (case_id, source_id, line_no)
-- allow_nullable_key:ts 可空(时区未知源,如实不归一),NULL 落 1970 分区
SETTINGS index_granularity = 8192, allow_nullable_key = 1;
