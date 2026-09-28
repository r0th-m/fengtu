// auth.Store 的 PostgreSQL 实现(单测不碰这里;真库链路由台架实测)。
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ye-mengwen/fengtu/internal/auth"
)

// HasUsers 系统是否已有用户(首启引导闸)。
func (p *PG) HasUsers(ctx context.Context) (bool, error) {
	var has bool
	err := p.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users)").Scan(&has)
	if err != nil {
		return false, fmt.Errorf("用户账目查询失败: %w", err)
	}
	return has, nil
}

// CreateUser 建用户(口令哈希为 bcrypt,由 auth 层算好);回新用户 id。
// 用户名唯一冲突(23505)如实报「用户名已存在」。
func (p *PG) CreateUser(ctx context.Context, username, passwordHash, role string) (string, error) {
	var id string
	err := p.pool.QueryRow(ctx,
		"INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id",
		username, passwordHash, role).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return "", fmt.Errorf("用户名已存在: %s", username)
		}
		return "", fmt.Errorf("用户创建失败: %w", err)
	}
	return id, nil
}

// UserForLogin 登录校验取数(无此用户 ok=false;含锁定账)。
func (p *PG) UserForLogin(ctx context.Context, username string) (*auth.User, string, bool, *time.Time, bool, error) {
	var u auth.User
	var hash string
	var disabled bool
	var lockedUntil *time.Time
	err := p.pool.QueryRow(ctx,
		"SELECT id, username, role, password_hash, disabled, locked_until FROM users WHERE username = $1",
		username).Scan(&u.ID, &u.Username, &u.Role, &hash, &disabled, &lockedUntil)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", false, nil, false, nil
		}
		return nil, "", false, nil, false, fmt.Errorf("用户查询失败: %w", err)
	}
	return &u, hash, disabled, lockedUntil, true, nil
}

// CreateSession 登记会话。
func (p *PG) CreateSession(ctx context.Context, token, userID string, expiresAt time.Time) error {
	_, err := p.pool.Exec(ctx,
		"INSERT INTO sessions (token, user_id, expires_at) VALUES ($1, $2, $3)",
		token, userID, expiresAt)
	if err != nil {
		return fmt.Errorf("会话登记失败: %w", err)
	}
	return nil
}

// SessionUser 令牌 → 用户(过期顺手焚账,无效一律 ok=false)。
func (p *PG) SessionUser(ctx context.Context, token string, now time.Time) (*auth.User, bool, error) {
	var u auth.User
	var expiresAt time.Time
	var disabled bool
	err := p.pool.QueryRow(ctx, `
		SELECT u.id, u.username, u.role, s.expires_at, u.disabled
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token = $1`, token).
		Scan(&u.ID, &u.Username, &u.Role, &expiresAt, &disabled)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("会话查询失败: %w", err)
	}
	if disabled || now.After(expiresAt) {
		_, _ = p.pool.Exec(ctx, "DELETE FROM sessions WHERE token = $1", token)
		return nil, false, nil
	}
	return &u, true, nil
}

// DeleteSession 焚会话。
func (p *PG) DeleteSession(ctx context.Context, token string) error {
	_, err := p.pool.Exec(ctx, "DELETE FROM sessions WHERE token = $1", token)
	if err != nil {
		return fmt.Errorf("会话焚毁失败: %w", err)
	}
	return nil
}

// ---- 0.26.0-m4-multiuser:多用户管理面 ----

// ListUsers 全量用户账(建号序;管理页用,量级小不分页)。
func (p *PG) ListUsers(ctx context.Context) ([]auth.UserInfo, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, username, role, disabled, failed_attempts, locked_until, created_at
		FROM users ORDER BY created_at, username`)
	if err != nil {
		return nil, fmt.Errorf("用户清单查询失败: %w", err)
	}
	defer rows.Close()
	out := []auth.UserInfo{}
	for rows.Next() {
		var u auth.UserInfo
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.Disabled,
			&u.FailedAttempts, &u.LockedUntil, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("用户行解析失败: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateUserRole 改角色(无此用户 ok=false)。
func (p *PG) UpdateUserRole(ctx context.Context, id, role string) (bool, error) {
	tag, err := p.pool.Exec(ctx, "UPDATE users SET role = $2 WHERE id = $1", id, role)
	if err != nil {
		return false, fmt.Errorf("角色更新失败: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// SetUserDisabled 禁用/解禁(无此用户 ok=false)。
func (p *PG) SetUserDisabled(ctx context.Context, id string, disabled bool) (bool, error) {
	tag, err := p.pool.Exec(ctx, "UPDATE users SET disabled = $2 WHERE id = $1", id, disabled)
	if err != nil {
		return false, fmt.Errorf("禁用状态更新失败: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// UpdatePassword 覆写口令哈希(管理员重置/本人改密共用)。
func (p *PG) UpdatePassword(ctx context.Context, id, passwordHash string) error {
	_, err := p.pool.Exec(ctx, "UPDATE users SET password_hash = $2 WHERE id = $1",
		id, passwordHash)
	if err != nil {
		return fmt.Errorf("口令更新失败: %w", err)
	}
	return nil
}

// DeleteUser 删用户,同事务焚其全部会话(无此用户 ok=false)。
func (p *PG) DeleteUser(ctx context.Context, id string) (bool, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("删除事务开启失败: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "DELETE FROM sessions WHERE user_id = $1", id); err != nil {
		return false, fmt.Errorf("会话焚毁失败: %w", err)
	}
	tag, err := tx.Exec(ctx, "DELETE FROM users WHERE id = $1", id)
	if err != nil {
		return false, fmt.Errorf("用户删除失败: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("删除事务提交失败: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// DeleteSessionsForUser 焚某用户全部会话(重置密码后旧令牌立失效)。
func (p *PG) DeleteSessionsForUser(ctx context.Context, userID string) error {
	_, err := p.pool.Exec(ctx, "DELETE FROM sessions WHERE user_id = $1", userID)
	if err != nil {
		return fmt.Errorf("会话焚毁失败: %w", err)
	}
	return nil
}

// RecordLoginFailure 失败计数 +1,达阈值置锁定期(单语句;锁定判定按
// 回读的计数算,与 CASE 同阈值,口径一致)。
func (p *PG) RecordLoginFailure(ctx context.Context, userID string, maxAttempts int,
	lockDur time.Duration, now time.Time) (bool, error) {
	var attempts int
	err := p.pool.QueryRow(ctx, `
		UPDATE users
		SET failed_attempts = failed_attempts + 1,
			locked_until = CASE WHEN failed_attempts + 1 >= $2
				THEN $3 ELSE locked_until END
		WHERE id = $1
		RETURNING failed_attempts`,
		userID, maxAttempts, now.Add(lockDur)).Scan(&attempts)
	if err != nil {
		return false, fmt.Errorf("登录失败记账失败: %w", err)
	}
	return attempts >= maxAttempts, nil
}

// RecordLoginSuccess 登录成功清零(失败计数 + 锁定期)。
func (p *PG) RecordLoginSuccess(ctx context.Context, userID string) error {
	_, err := p.pool.Exec(ctx,
		"UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1", userID)
	if err != nil {
		return fmt.Errorf("登录成功清账失败: %w", err)
	}
	return nil
}

// CountActiveAdmins 未禁用的 admin 数(最后一个活跃 admin 保护闸)。
func (p *PG) CountActiveAdmins(ctx context.Context) (int, error) {
	var n int
	err := p.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM users WHERE role = 'admin' AND NOT disabled").Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("活跃管理员计数失败: %w", err)
	}
	return n, nil
}

// PasswordHashForUser 按 id 取口令哈希(本人改密验旧;无此用户 ok=false)。
func (p *PG) PasswordHashForUser(ctx context.Context, id string) (string, bool, error) {
	var hash string
	err := p.pool.QueryRow(ctx, "SELECT password_hash FROM users WHERE id = $1", id).Scan(&hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("用户查询失败: %w", err)
	}
	return hash, true, nil
}

var _ auth.Store = (*PG)(nil)
