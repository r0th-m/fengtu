// 多用户管理面(0.26.0-m4-multiuser,DESIGN §9 延伸):
//
//   - 角色两档:admin(全权+用户管理/系统配置写)/ operator(案件操作全部);
//     权限闸在 web 层(requireAdmin),本层只管账和业务闸;
//   - 业务闸(焊死在 Service,handler 不可绕过):不许改自己角色/禁用自己/
//     删自己;最后一个未禁用 admin 不许降级/禁用/删除(防自锁门外);
//   - 管理员重置口令即焚目标全部会话(旧令牌立刻失效);
//   - 口令永不落审计/日志,本文件一切方法不接收也不返回口令哈希以外的
//     口令材料,哈希只经 Store 过手。
package auth

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// 角色两档(与 migrations/016_multiuser.sql 的 users_role_check 同表)。
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
)

// ValidRole 角色合法性(库 CHECK 之外的 Go 侧先验,错误文案友好)。
func ValidRole(role string) bool {
	return role == RoleAdmin || role == RoleOperator
}

// UserInfo 用户管理视角的账(列表/详情;永不含口令哈希)。
type UserInfo struct {
	ID             string     `json:"id"`
	Username       string     `json:"username"`
	Role           string     `json:"role"`
	Disabled       bool       `json:"disabled"`
	FailedAttempts int        `json:"failed_attempts"`
	LockedUntil    *time.Time `json:"locked_until,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// findUser 按 id 取用户账(用户量级小,ListUsers 过滤即可,不另开存储面)。
func (s *Service) findUser(ctx context.Context, id string) (*UserInfo, error) {
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	for i := range users {
		if users[i].ID == id {
			return &users[i], nil
		}
	}
	return nil, nil
}

// ListUsers 全量用户账(用户管理页)。
func (s *Service) ListUsers(ctx context.Context) ([]UserInfo, error) {
	return s.store.ListUsers(ctx)
}

// CreateUserAs 管理员建用户:复杂度 + 角色合法校验;用户名冲突由存储层
// 报「用户名已存在」(PG 23505 映射),原样透传。
func (s *Service) CreateUserAs(ctx context.Context, username, password, role string) (*UserInfo, error) {
	if err := validateCredentials(username, password); err != nil {
		return nil, err
	}
	if !ValidRole(role) {
		return nil, fmt.Errorf("角色非法: %s(可选: %s, %s)", role, RoleAdmin, RoleOperator)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("口令哈希失败: %w", err)
	}
	id, err := s.store.CreateUser(ctx, username, string(hash), role)
	if err != nil {
		return nil, err
	}
	return &UserInfo{
		ID: id, Username: username, Role: role, CreatedAt: s.now(),
	}, nil
}

// SetRole 改角色:不许改自己;最后一个未禁用 admin 不许降级(自锁门外闸)。
func (s *Service) SetRole(ctx context.Context, actorID, targetID, role string) error {
	if !ValidRole(role) {
		return fmt.Errorf("角色非法: %s(可选: %s, %s)", role, RoleAdmin, RoleOperator)
	}
	if actorID == targetID {
		return fmt.Errorf("不许改自己的角色")
	}
	target, err := s.findUser(ctx, targetID)
	if err != nil {
		return err
	}
	if target == nil {
		return fmt.Errorf("无此用户: %s", targetID)
	}
	if target.Role == RoleAdmin && !target.Disabled && role != RoleAdmin {
		if err := s.guardLastAdmin(ctx); err != nil {
			return err
		}
	}
	ok, err := s.store.UpdateUserRole(ctx, targetID, role)
	if err != nil {
		return fmt.Errorf("角色更新失败: %w", err)
	}
	if !ok {
		return fmt.Errorf("无此用户: %s", targetID)
	}
	return nil
}

// SetDisabled 禁用/解禁:不许动自己;禁用最后一个活跃 admin 拒。
func (s *Service) SetDisabled(ctx context.Context, actorID, targetID string, disabled bool) error {
	if actorID == targetID {
		return fmt.Errorf("不许改自己的禁用状态")
	}
	target, err := s.findUser(ctx, targetID)
	if err != nil {
		return err
	}
	if target == nil {
		return fmt.Errorf("无此用户: %s", targetID)
	}
	if disabled && target.Role == RoleAdmin && !target.Disabled {
		if err := s.guardLastAdmin(ctx); err != nil {
			return err
		}
	}
	ok, err := s.store.SetUserDisabled(ctx, targetID, disabled)
	if err != nil {
		return fmt.Errorf("禁用状态更新失败: %w", err)
	}
	if !ok {
		return fmt.Errorf("无此用户: %s", targetID)
	}
	return nil
}

// ResetPassword 管理员重置口令:复杂度校验 + 焚目标全部会话(旧令牌立失效)。
func (s *Service) ResetPassword(ctx context.Context, targetID, newPassword string) error {
	if err := validatePassword(newPassword); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("口令哈希失败: %w", err)
	}
	if err := s.store.UpdatePassword(ctx, targetID, string(hash)); err != nil {
		return fmt.Errorf("口令重置失败: %w", err)
	}
	if err := s.store.DeleteSessionsForUser(ctx, targetID); err != nil {
		return fmt.Errorf("旧会话焚毁失败: %w", err)
	}
	return nil
}

// ChangePassword 本人改密:验旧口令(错即「凭据不符」,与登录同口径),
// 新口令过复杂度校验。
func (s *Service) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	hash, ok, err := s.store.PasswordHashForUser(ctx, userID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("无此用户: %s", userID)
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(oldPassword)) != nil {
		return fmt.Errorf("凭据不符")
	}
	if err := validatePassword(newPassword); err != nil {
		return err
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("口令哈希失败: %w", err)
	}
	if err := s.store.UpdatePassword(ctx, userID, string(newHash)); err != nil {
		return fmt.Errorf("口令更新失败: %w", err)
	}
	return nil
}

// DeleteUserAs 删用户:不许删自己;删最后一个活跃 admin 拒;会话同事务焚。
func (s *Service) DeleteUserAs(ctx context.Context, actorID, targetID string) error {
	if actorID == targetID {
		return fmt.Errorf("不许删除自己")
	}
	target, err := s.findUser(ctx, targetID)
	if err != nil {
		return err
	}
	if target == nil {
		return fmt.Errorf("无此用户: %s", targetID)
	}
	if target.Role == RoleAdmin && !target.Disabled {
		if err := s.guardLastAdmin(ctx); err != nil {
			return err
		}
	}
	ok, err := s.store.DeleteUser(ctx, targetID)
	if err != nil {
		return fmt.Errorf("用户删除失败: %w", err)
	}
	if !ok {
		return fmt.Errorf("无此用户: %s", targetID)
	}
	return nil
}

// guardLastAdmin 最后一个未禁用 admin 保护闸:活跃 admin ≤1 时拒一切
// 使其离开活跃 admin 集的操作(降级/禁用/删除),防全员自锁门外。
func (s *Service) guardLastAdmin(ctx context.Context) error {
	n, err := s.store.CountActiveAdmins(ctx)
	if err != nil {
		return fmt.Errorf("活跃管理员计数失败: %w", err)
	}
	if n <= 1 {
		return fmt.Errorf("这是最后一个活跃管理员,拒绝操作(先再建一名 admin)")
	}
	return nil
}
