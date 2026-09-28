// Package auth 登录闸(DESIGN §9,索图 M4 语义移植):
//
//   - 首启引导:系统无任何用户时才允许建首个管理员(bcrypt,口令 ≥8 位);
//     有用户后 setup 一律拒绝;
//   - 会话:登录成功发 256-bit 随机会话令牌(cookie 由 web 层设),
//     绝对过期(默认 12h,不滑动);登出即焚;
//   - 口令上限 72 字节 = bcrypt 算法自身的输入上限,超限如实拒,
//     不截断(截断会让两个不同口令静默等价)。
//
// 存储是接口(与 ingest 同纪律):单测 fake 打全链,PG 实现在
// internal/ingest/store(pg_auth.go)。
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// MinPasswordLen 口令最小长度(照索图 M4:≥8 位)。
const MinPasswordLen = 8

// maxPasswordBytes bcrypt 输入上限(超出报错而非截断)。
const maxPasswordBytes = 72

// DefaultSessionTTL 会话绝对有效期。
const DefaultSessionTTL = 12 * time.Hour

// 登录失败锁定(0.26.0-m4-multiuser):连续 MaxFailedAttempts 次口令错误
// 锁 LockDuration;阈值判定在 auth 层,库只存账(failed_attempts/locked_until)。
const (
	MaxFailedAttempts = 5
	LockDuration      = 15 * time.Minute
)

// ErrAccountLocked 登录失败达阈值后的锁定错误(哨兵;web 层凭它区分
// 「凭据不符」与「账户已锁定」,状态码同为 401 但文案/审计 reason 不同)。
var ErrAccountLocked = errors.New("登录失败次数过多,账户已锁定,请 15 分钟后再试")

// User 会话视角的用户。
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

// Store 用户/会话存储。
type Store interface {
	HasUsers(ctx context.Context) (bool, error)
	// CreateUser 建用户,回新用户 id;用户名唯一冲突须报「用户名已存在」。
	CreateUser(ctx context.Context, username, passwordHash, role string) (string, error)
	// UserForLogin 返回 (用户, 口令哈希, 是否禁用, 锁定截止, 是否存在);
	// 无此用户 ok=false。
	UserForLogin(ctx context.Context, username string) (user *User, passwordHash string,
		disabled bool, lockedUntil *time.Time, ok bool, err error)
	CreateSession(ctx context.Context, token, userID string, expiresAt time.Time) error
	// SessionUser 令牌 → 用户;无效/过期/禁用 ok=false。
	SessionUser(ctx context.Context, token string, now time.Time) (user *User, ok bool, err error)
	DeleteSession(ctx context.Context, token string) error

	// ---- 0.26.0-m4-multiuser:多用户管理面 ----

	// ListUsers 全量用户账(用户管理页;量级小,不分页)。
	ListUsers(ctx context.Context) ([]UserInfo, error)
	// UpdateUserRole 改角色;无此用户 ok=false。
	UpdateUserRole(ctx context.Context, id, role string) (ok bool, err error)
	// SetUserDisabled 禁用/解禁;无此用户 ok=false。
	SetUserDisabled(ctx context.Context, id string, disabled bool) (ok bool, err error)
	// UpdatePassword 覆写口令哈希(管理员重置/本人改密共用)。
	UpdatePassword(ctx context.Context, id, passwordHash string) error
	// DeleteUser 删用户,同事务焚其全部会话;无此用户 ok=false。
	DeleteUser(ctx context.Context, id string) (ok bool, err error)
	// DeleteSessionsForUser 焚某用户全部会话(重置密码后用)。
	DeleteSessionsForUser(ctx context.Context, userID string) error
	// RecordLoginFailure 失败计数 +1,达 maxAttempts 置 locked_until=
	// now+lockDur(单语句);locked=本次失败后进入锁定。
	RecordLoginFailure(ctx context.Context, userID string, maxAttempts int,
		lockDur time.Duration, now time.Time) (locked bool, err error)
	// RecordLoginSuccess 登录成功清零:failed_attempts=0, locked_until=NULL。
	RecordLoginSuccess(ctx context.Context, userID string) error
	// CountActiveAdmins 未禁用的 admin 数(最后一个活跃 admin 保护闸)。
	CountActiveAdmins(ctx context.Context) (int, error)
	// PasswordHashForUser 按 id 取口令哈希(本人改密验旧);无此用户 ok=false。
	PasswordHashForUser(ctx context.Context, id string) (passwordHash string, ok bool, err error)
}

// Service 登录闸服务。
type Service struct {
	store Store
	ttl   time.Duration
	now   func() time.Time // 测试可注入
}

// NewService 构造(ttl <= 0 用默认 12h)。
func NewService(store Store, ttl time.Duration) *Service {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	return &Service{store: store, ttl: ttl, now: time.Now}
}

// SetClock 测试注入时钟。
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// NeedsSetup 首启判定(无任何用户)。
func (s *Service) NeedsSetup(ctx context.Context) (bool, error) {
	has, err := s.store.HasUsers(ctx)
	if err != nil {
		return false, err
	}
	return !has, nil
}

// validateCredentials 口令复杂度下限:≥MinPasswordLen 位且同时含字母和数字
// (0.26.0 收紧:纯字母/纯数字口令如实拒;存量 admin/password123 满足,平滑)。
func validateCredentials(username, password string) error {
	if username == "" || utf8.RuneCountInString(username) > 64 {
		return fmt.Errorf("用户名须为 1~64 字符")
	}
	if err := validatePassword(password); err != nil {
		return err
	}
	return nil
}

// validatePassword 口令复杂度校验(改密/重置/建用户共用)。
func validatePassword(password string) error {
	if utf8.RuneCountInString(password) < MinPasswordLen {
		return fmt.Errorf("口令至少 %d 位", MinPasswordLen)
	}
	if len(password) > maxPasswordBytes {
		return fmt.Errorf("口令超过 bcrypt 输入上限(%d 字节),拒绝而非截断",
			maxPasswordBytes)
	}
	var hasLetter, hasDigit bool
	for _, r := range password {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsDigit(r):
			hasDigit = true
		}
	}
	if !hasLetter || !hasDigit {
		return fmt.Errorf("口令须同时含字母和数字")
	}
	return nil
}

// Setup 首启建首个管理员(已有用户时一律拒绝,闸在 Service 也焊一道)。
func (s *Service) Setup(ctx context.Context, username, password string) error {
	if err := validateCredentials(username, password); err != nil {
		return err
	}
	needs, err := s.NeedsSetup(ctx)
	if err != nil {
		return err
	}
	if !needs {
		return fmt.Errorf("系统已初始化,首启引导关闭")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("口令哈希失败: %w", err)
	}
	if _, err := s.store.CreateUser(ctx, username, string(hash), RoleAdmin); err != nil {
		return fmt.Errorf("首个管理员创建失败: %w", err)
	}
	return nil
}

// Login 校验凭据发会话令牌;凭据不符/禁用一律同一错误(不泄露用户存在性)。
// 0.26.0 起带失败锁定:锁定期内一律 ErrAccountLocked(不校验口令,计数不涨);
// 口令错误记一次失败,达 MaxFailedAttempts 锁 LockDuration;成功清零。
func (s *Service) Login(ctx context.Context, username, password string) (string, *User, error) {
	user, hash, disabled, lockedUntil, ok, err := s.store.UserForLogin(ctx, username)
	if err != nil {
		return "", nil, err
	}
	if !ok || disabled {
		return "", nil, fmt.Errorf("凭据不符")
	}
	if lockedUntil != nil && lockedUntil.After(s.now()) {
		return "", nil, ErrAccountLocked
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		if _, err := s.store.RecordLoginFailure(ctx, user.ID,
			MaxFailedAttempts, LockDuration, s.now()); err != nil {
			return "", nil, fmt.Errorf("登录失败记账失败: %w", err)
		}
		return "", nil, fmt.Errorf("凭据不符")
	}
	if err := s.store.RecordLoginSuccess(ctx, user.ID); err != nil {
		return "", nil, fmt.Errorf("登录成功清账失败: %w", err)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("会话令牌生成失败: %w", err)
	}
	token := hex.EncodeToString(raw)
	if err := s.store.CreateSession(ctx, token, user.ID,
		s.now().Add(s.ttl)); err != nil {
		return "", nil, fmt.Errorf("会话登记失败: %w", err)
	}
	return token, user, nil
}

// Authenticate 会话令牌 → 用户(中间件每层调用)。
func (s *Service) Authenticate(ctx context.Context, token string) (*User, error) {
	if token == "" {
		return nil, nil
	}
	user, ok, err := s.store.SessionUser(ctx, token, s.now())
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	return user, nil
}

// Logout 焚会话。
func (s *Service) Logout(ctx context.Context, token string) error {
	return s.store.DeleteSession(ctx, token)
}

// ConstantTimeEqual 供需要恒定时间比较的场景(令牌比对在 SQL 层,此处备用)。
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
