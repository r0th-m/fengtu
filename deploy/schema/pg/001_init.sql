-- 丰图 v2 元数据骨架(DESIGN §5 的 M0 切片:cases / sources / ingest_jobs)。
-- 其余表(users/hits/clues/audit_chain/intent_*/scan_runs/ai_runs/settings)
-- 属后续切片,本文件不超前建。
--
-- 纪律锚点:
--   - 原文 sha256 记 sources,证据链从登记开始(读前校验由 vault 切片补);
--   - 摄入任务全程有账:行数(event/bad/skip 分列,零静默)、耗时、错误如实。

CREATE TABLE IF NOT EXISTS cases (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sources (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id       UUID NOT NULL REFERENCES cases(id),
    path          TEXT NOT NULL,              -- 摄入时所见路径(审计用,非 vault 位置)
    sha256        TEXT NOT NULL,              -- 原文 SHA256(证据链锚点)
    size_bytes    BIGINT NOT NULL,
    kind          TEXT NOT NULL,              -- 文件类别:text/evtx/raw(检测器判定)
    artifact_type TEXT NOT NULL DEFAULT '',   -- WinInfoSC 映射表判定的 artifact 类型(无则空)
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- 同案同路径重复摄入 → 冲突如实拒绝;同内容(sha256)多路径如实各登
    -- (采集包内重复内容文件是常态:实测单包 410 组,各自的溯源链都要在)
    UNIQUE (case_id, path)
);

CREATE TABLE IF NOT EXISTS ingest_jobs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id     UUID NOT NULL REFERENCES sources(id),
    case_id       UUID NOT NULL REFERENCES cases(id),
    status        TEXT NOT NULL,              -- running | done | failed
    parser        TEXT NOT NULL,              -- 解析路径(desc:<name>/builtin:<name>/evtx_sidecar/raw)
    rows_total    BIGINT NOT NULL DEFAULT 0,  -- 引擎产出记录总数
    rows_event    BIGINT NOT NULL DEFAULT 0,
    rows_bad      BIGINT NOT NULL DEFAULT 0,  -- 坏行照计(零静默)
    rows_skip     BIGINT NOT NULL DEFAULT 0,
    bytes_in      BIGINT NOT NULL DEFAULT 0,
    started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at   TIMESTAMPTZ,
    duration_ms   BIGINT,
    error         TEXT,                       -- 失败原因如实记;成功为 NULL
    note          TEXT                        -- 运行备注(worker 数/批次等)
);

CREATE INDEX IF NOT EXISTS idx_sources_case ON sources(case_id);
CREATE INDEX IF NOT EXISTS idx_ingest_jobs_source ON ingest_jobs(source_id);
CREATE INDEX IF NOT EXISTS idx_ingest_jobs_case ON ingest_jobs(case_id);
