-- 丰图 v2 切片三:登录闸 + 审计哈希链 + 待审区骨架(DESIGN §5/§9)。
--
-- 纪律锚点:
--   - 登录闸照索图 M4 语义:首启初始化管理员(bcrypt,口令 ≥8 位),
--     之后全端点要会话;审计 actor 锚真人用户名,匿名内部调用记 system;
--   - 审计哈希链:prev_hash/entry_hash 链式,追加侧持 advisory lock
--     防 seq 竞态(索图 _APPEND_LOCK 同款教训);链可全量重算校验;
--   - 判断权归人:hits 一切机器产物 status 恒 pending 起步,命中≠结论;
--   - 扫描轮次:scan_runs.round_no 每案件递增(UNIQUE 焊死),
--     hits.round_no 记录产出轮次;UNIQUE(source_id, line_no, rule_id)
--     去重幂等,规则重跑 hits_new=0。

CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,          -- bcrypt(cost 默认 10)
    role          TEXT NOT NULL DEFAULT 'admin',  -- 切片三单角色;多角色后议
    disabled      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,          -- 256-bit 随机,hex
    user_id    UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL       -- 绝对过期(默认 12h),不滑动
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS audit_chain (
    seq        BIGSERIAL PRIMARY KEY,     -- 全局序号,链序即 seq 序
    case_id    UUID REFERENCES cases(id), -- 可空:登录/首启等无案件上下文
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor      TEXT NOT NULL,             -- 真人用户名 | system
    action     TEXT NOT NULL,             -- auth.setup/auth.login/upload.complete/...
    scope      TEXT,                      -- 作用对象(source_id/hit_id 等)
    detail_json TEXT,                     -- 结构化细节(canonical JSON,键序固定)
    prev_hash  TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_chain_case ON audit_chain(case_id);

CREATE TABLE IF NOT EXISTS hits (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id       UUID NOT NULL REFERENCES cases(id),
    source_id     UUID NOT NULL REFERENCES sources(id),
    line_no       INTEGER NOT NULL,       -- 原文物理行号(溯源锚,与 CH events.line_no 同)
    rule_id       TEXT NOT NULL,
    severity      TEXT NOT NULL
        CHECK (severity IN ('info','low','medium','high')),
    matched_field TEXT NOT NULL,
    matched_value TEXT NOT NULL,
    snippet       TEXT NOT NULL,          -- 命中上下文截断留证
    ts_utc        TIMESTAMPTZ,            -- 事件归一时刻;无时区源如实 NULL
    status        TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','accepted','rejected')),
    round_no      INTEGER NOT NULL,       -- 产出该命中的扫描轮次
    detail_json   TEXT,                   -- 规则细节(文案含「命中≠结论」)
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_by   TEXT,                   -- 裁决人(真人用户名)
    reviewed_at   TIMESTAMPTZ,
    review_note   TEXT,
    -- 去重幂等:同一源同一行同一规则只记一次,重跑 hits_new=0
    UNIQUE (source_id, line_no, rule_id)
);
CREATE INDEX IF NOT EXISTS idx_hits_case_status ON hits(case_id, status);
CREATE INDEX IF NOT EXISTS idx_hits_case_round ON hits(case_id, round_no);

CREATE TABLE IF NOT EXISTS scan_runs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id       UUID NOT NULL REFERENCES cases(id),
    round_no      INTEGER NOT NULL,       -- 每案件递增(1 起)
    rule_ids_json TEXT,                   -- NULL=全量扫描;否则规则 id JSON 数组
    actor         TEXT NOT NULL,
    summary_json  TEXT,                   -- scanned/hits_new/truncated 计数摘要
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (case_id, round_no)
);
