-- 0.26.0-m4-multiuser:多用户地基——角色两档收敛 + 登录失败锁定账。
--   - 角色:admin(全权+用户管理) / operator(案件操作全部,
--     无用户管理/系统配置写权限);存量单用户 role 已是 'admin',天然平滑。
--   - 锁定:failed_attempts 连续失败计数 + locked_until 锁定期
--     (5 次锁 15 分钟,阈值在 auth 层,库只存账);登录成功清零。
--   - 幂等:initdb 裸跑 + Migrate 重放两条路都要能过(同 011 范式)。
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin', 'operator'));
