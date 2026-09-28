-- 丰图 v2 切片七:一案多包(DESIGN §3 2026-09-22 修正稿)+ 意图主机范围。
--
--   - 主机建模:sources.host(从采集包根目录名经映射表 host_regex 提取,
--     散件/单文件上传为空串=未建模,如实)+ sources.package(包内聚合键,
--     同一主机二次采包路径冲突时登记路径加 #N 后缀,package 列存登记根名);
--   - 意图主机范围:intent_nodes.host_scope(空串=全案件,等价 §3 修正稿
--     的 NULL 语义;具体主机键=worker 执行查询限定在该主机的源集合);
--   - AI 会话主机范围:ai_sessions.host_scope(worker 单意图单会话,主机
--     限定随会话绑定,工具层强制过滤,不靠模型自觉)。

ALTER TABLE sources ADD COLUMN IF NOT EXISTS host TEXT NOT NULL DEFAULT '';
ALTER TABLE sources ADD COLUMN IF NOT EXISTS package TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_sources_case_host ON sources(case_id, host);

ALTER TABLE intent_nodes ADD COLUMN IF NOT EXISTS host_scope TEXT NOT NULL DEFAULT '';

ALTER TABLE ai_sessions ADD COLUMN IF NOT EXISTS host_scope TEXT NOT NULL DEFAULT '';
