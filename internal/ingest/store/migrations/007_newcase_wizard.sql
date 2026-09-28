-- 丰图 v2 交互改造·新建任务向导(设计依据 fengtu-interaction-design.md §1):
-- 案件(=应急任务容器)元数据三列——应急类型/应急背景/应急目的预设。
--
--   - incident_type:固定枚举(ransomware|webshell|intrusion|data-leak|other,
--     API 层白名单校验),空串=旧案件未经向导填写(如实,不回填);
--   - background:应急背景自由文本(向导「模板回填」的产物也在此列,
--     模板是前端数据,落库的只认最终文本);
--   - goal_presets:应急目的预设落账(JSONB 文本数组,预设勾选+自由补充
--     解析后的最终文本);创建时同步播种为意图图 goal 节点
--     (intent.Engine.SeedGoals,幂等),本列是元数据账,goal 节点是执行账。

ALTER TABLE cases ADD COLUMN IF NOT EXISTS incident_type TEXT NOT NULL DEFAULT '';
ALTER TABLE cases ADD COLUMN IF NOT EXISTS background TEXT NOT NULL DEFAULT '';
ALTER TABLE cases ADD COLUMN IF NOT EXISTS goal_presets JSONB NOT NULL DEFAULT '[]';
