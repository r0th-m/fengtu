-- 0.25.0-datasource-unlock:实体层(跨源/跨机实体匹配的最小可行面,
-- 树庭 §8.2/§9.2 canonical_key + qualifier 语义)。
--
--   - entities:从已解析事件抽取的实体(IP/domain/account/file_hash),
--     一行 = 一个 (案件, 主机, canonical_key) 的首见锚点;
--   - canonical_key 归一:IP 去端口、domain 小写去尾点、account 小写、
--     hash 小写;公网身份(ip 公网/dom/acct:sid/hash)= qualifier global,
--     私网 IP 与无名账户 = host_scoped(键带 @host 后缀,私网永不进
--     跨机匹配——跨机聚合只取 qualifier='global',结构性防假联动);
--   - 证据锚点:host + source_id + line_no(源行 sha256 在 sources 表);
--   - 去重幂等:UNIQUE(case_id, host, canonical_key),重跑摄入
--     ON CONFLICT DO NOTHING(锚点保首见,不滚动覆盖)。

CREATE TABLE IF NOT EXISTS entities (
    id            BIGSERIAL PRIMARY KEY,
    case_id       UUID NOT NULL REFERENCES cases(id),
    host          TEXT NOT NULL DEFAULT '',   -- 主机键(空=未建模,不参与跨机聚合)
    entity_type   TEXT NOT NULL,              -- ip | domain | account | file_hash
    raw_value     TEXT NOT NULL,              -- 原始值(留证)
    canonical_key TEXT NOT NULL,              -- 归一键(跨源/跨机比对键)
    qualifier     TEXT NOT NULL,              -- global | host_scoped
    source_id     UUID NOT NULL REFERENCES sources(id), -- 首见锚点
    line_no       INTEGER NOT NULL,           -- 原文物理行号(与 CH events.line_no 同)
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (case_id, host, canonical_key)
);

CREATE INDEX IF NOT EXISTS idx_entities_case ON entities(case_id);
-- 跨机聚合路径:qualifier='global' 过滤 + canonical_key 分组
CREATE INDEX IF NOT EXISTS idx_entities_case_qual_key
    ON entities(case_id, qualifier, canonical_key);
