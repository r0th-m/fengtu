-- 丰图 v2 案件生命周期(0.18.0-case-lifecycle):归档 + 删除的地基。
--
--   - cases.archived_at:归档时刻(NULL=活跃)。归档语义:任务列表默认
--     不显示(筛选「已归档」看回)、意图引擎停派新意图(在跑的如实跑完)、
--     一键分析/扫描/手写意图 409 如实拒、仪表盘统计默认不含;案件页
--     照常可开(只读看历史),解归档即全恢复。
--   - audit_chain 案件外键解除:案件删除是硬删(判断权归人——前端逐字
--     输名确认 + 后端复核名匹配才放行),但审计链是全局哈希链,删/改
--     任何一条历史条目都会断链。取舍焊死:删案不动审计链,被删案件的
--     审计条目原样保留(case_id 留删除前的 UUID 文本,案件名/源数/事件数
--     快照在 case.delete 条目的 detail 里),成为无案件上下文的历史账,
--     链校验零影响。
ALTER TABLE cases ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;

ALTER TABLE audit_chain DROP CONSTRAINT IF EXISTS audit_chain_case_id_fkey;
