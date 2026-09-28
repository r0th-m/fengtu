-- 丰图 v2 切片四:一键分析主链路 + 适用域算子 + 置信度四面(DESIGN §6.1~§6.3)。
--
--   - sources 增指纹判定四列:detect_format(判定格式)/detect_confidence(前验
--     置信度,人可见可改判)/detect_status 状态机/log_type(源品类,适用域
--     路由键)。状态机:none(无需判定:raw/evtx 原生)| auto(前验 ≥0.9
--     自动解析)| pending_confirm(前验 <0.9,待人确认,不阻塞其他源)|
--     overridden(人改判/确认)| suspect(后验绊线:全量解析失败率 >5%,
--     判定降级存疑,如实标出);
--   - hits 增 evidence_grade:置信度第二/三面——强疑似(strong,≥2 独立
--     证据点+链咬合)/疑似(suspect,单点+上下文;签名族默认档,如实标)/
--     弱信号(weak,统计依据,detail 须带排除项声明)。档位由系统按证据
--     结构算出,不包装置信度数字;
--   - 规则接受率统计(近 90 天)直接由 hits 表算出,不建新表。

ALTER TABLE sources
    ADD COLUMN IF NOT EXISTS log_type TEXT,          -- 源品类(web_access/windows_event_log/...),空=无品类
    ADD COLUMN IF NOT EXISTS detect_format TEXT,     -- 判定格式(builtin:<id> | desc:<name>)
    ADD COLUMN IF NOT EXISTS detect_confidence REAL, -- 指纹前验置信度(0..1;人改判保留原值留痕)
    ADD COLUMN IF NOT EXISTS detect_status TEXT NOT NULL DEFAULT 'none'
        CHECK (detect_status IN
            ('none','auto','pending_confirm','overridden','suspect'));

ALTER TABLE hits
    ADD COLUMN IF NOT EXISTS evidence_grade TEXT NOT NULL DEFAULT 'suspect'
        CHECK (evidence_grade IN ('strong','suspect','weak'));

CREATE INDEX IF NOT EXISTS idx_hits_case_rule_created ON hits(case_id, rule_id, created_at);
