// 登录闸焊死:首启一次/口令复杂度/bcrypt 真伪/会话生命周期/过期;
// 0.26.0-m4-multiuser 追加:失败锁定、用户管理业务闸(自残/最后 admin)。
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type fakeUser struct {
	id, hash, role string
	disabled       bool
	failedAttempts int
	lockedUntil    *time.Time
	createdAt      time.Time
}

type fakeStore struct {
	users    map[string]*fakeUser // 主键 username
	sessions map[string]struct{ userID string; expires time.Time }
	nextID   int
	hasUsers bool
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		users:    map[string]*fakeUser{},
		sessions: map[string]struct{ userID string; expires time.Time }{},
	}
}

func (f *fakeStore) HasUsers(context.Context) (bool, error) { return f.hasUsers, nil }

func (f *fakeStore) CreateUser(_ context.Context, username, passwordHash, role string) (string, error) {
	if _, ok := f.users[username]; ok {
		return "", fmt.Errorf("用户名已存在: %s", username)
	}
	f.nextID++
	id := fmt.Sprintf("u%d", f.nextID)
	f.users[username] = &fakeUser{id: id, hash: passwordHash, role: role}
	f.hasUsers = true
	return id, nil
}

func (f *fakeStore) UserForLogin(_ context.Context, username string) (*User, string, bool, *time.Time, bool, error) {
	u, ok := f.users[username]
	if !ok {
		return nil, "", false, nil, false, nil
	}
	return &User{ID: u.id, Username: username, Role: u.role},
		u.hash, u.disabled, u.lockedUntil, true, nil
}

func (f *fakeStore) CreateSession(_ context.Context, token, userID string, expiresAt time.Time) error {
	f.sessions[token] = struct{ userID string; expires time.Time }{userID, expiresAt}
	return nil
}

func (f *fakeStore) SessionUser(_ context.Context, token string, now time.Time) (*User, bool, error) {
	s, ok := f.sessions[token]
	if !ok || now.After(s.expires) {
		return nil, false, nil
	}
	for name, u := range f.users {
		if u.id == s.userID {
			if u.disabled {
				return nil, false, nil
			}
			return &User{ID: u.id, Username: name, Role: u.role}, true, nil
		}
	}
	return nil, false, nil
}

func (f *fakeStore) DeleteSession(_ context.Context, token string) error {
	delete(f.sessions, token)
	return nil
}

func (f *fakeStore) userByID(id string) (*fakeUser, bool) {
	for _, u := range f.users {
		if u.id == id {
			return u, true
		}
	}
	return nil, false
}

func (f *fakeStore) ListUsers(context.Context) ([]UserInfo, error) {
	out := []UserInfo{}
	for name, u := range f.users {
		out = append(out, UserInfo{
			ID: u.id, Username: name, Role: u.role, Disabled: u.disabled,
			FailedAttempts: u.failedAttempts, LockedUntil: u.lockedUntil,
			CreatedAt: u.createdAt,
		})
	}
	return out, nil
}

func (f *fakeStore) UpdateUserRole(_ context.Context, id, role string) (bool, error) {
	u, ok := f.userByID(id)
	if !ok {
		return false, nil
	}
	u.role = role
	return true, nil
}

func (f *fakeStore) SetUserDisabled(_ context.Context, id string, disabled bool) (bool, error) {
	u, ok := f.userByID(id)
	if !ok {
		return false, nil
	}
	u.disabled = disabled
	return true, nil
}

func (f *fakeStore) UpdatePassword(_ context.Context, id, passwordHash string) error {
	u, ok := f.userByID(id)
	if !ok {
		return fmt.Errorf("无此用户: %s", id)
	}
	u.hash = passwordHash
	return nil
}

func (f *fakeStore) DeleteUser(_ context.Context, id string) (bool, error) {
	victim := ""
	for name, u := range f.users {
		if u.id == id {
			victim = name
		}
	}
	if victim == "" {
		return false, nil
	}
	delete(f.users, victim)
	for token, s := range f.sessions {
		if s.userID == id {
			delete(f.sessions, token)
		}
	}
	return true, nil
}

func (f *fakeStore) DeleteSessionsForUser(_ context.Context, userID string) error {
	for token, s := range f.sessions {
		if s.userID == userID {
			delete(f.sessions, token)
		}
	}
	return nil
}

func (f *fakeStore) RecordLoginFailure(_ context.Context, userID string,
	maxAttempts int, lockDur time.Duration, now time.Time) (bool, error) {
	u, ok := f.userByID(userID)
	if !ok {
		return false, fmt.Errorf("无此用户: %s", userID)
	}
	u.failedAttempts++
	if u.failedAttempts >= maxAttempts {
		until := now.Add(lockDur)
		u.lockedUntil = &until
	}
	return u.failedAttempts >= maxAttempts, nil
}

func (f *fakeStore) RecordLoginSuccess(_ context.Context, userID string) error {
	u, ok := f.userByID(userID)
	if !ok {
		return fmt.Errorf("无此用户: %s", userID)
	}
	u.failedAttempts = 0
	u.lockedUntil = nil
	return nil
}

func (f *fakeStore) CountActiveAdmins(context.Context) (int, error) {
	n := 0
	for _, u := range f.users {
		if u.role == RoleAdmin && !u.disabled {
			n++
		}
	}
	return n, nil
}

func (f *fakeStore) PasswordHashForUser(_ context.Context, id string) (string, bool, error) {
	u, ok := f.userByID(id)
	if !ok {
		return "", false, nil
	}
	return u.hash, true, nil
}

func TestSetupOnce(t *testing.T) {
	s := NewService(newFakeStore(), 0)
	ctx := context.Background()
	needs, _ := s.NeedsSetup(ctx)
	if !needs {
		t.Fatal("空系统应需要首启引导")
	}
	if err := s.Setup(ctx, "alice", "password123"); err != nil {
		t.Fatalf("首启失败: %v", err)
	}
	if err := s.Setup(ctx, "bob", "password123"); err == nil {
		t.Fatal("二次首启应拒绝")
	}
}

func TestPasswordRules(t *testing.T) {
	s := NewService(newFakeStore(), 0)
	ctx := context.Background()
	if err := s.Setup(ctx, "alice", "short"); err == nil {
		t.Fatal("短口令应拒绝(<8)")
	}
	if err := s.Setup(ctx, "alice", strings.Repeat("a", 73)); err == nil {
		t.Fatal("超 bcrypt 上限应拒绝而非截断")
	}
	// 0.26.0 收紧:≥8 位且须同时含字母和数字
	if err := s.Setup(ctx, "alice", "password"); err == nil {
		t.Fatal("纯字母口令应拒绝")
	}
	if err := s.Setup(ctx, "alice", "12345678"); err == nil {
		t.Fatal("纯数字口令应拒绝")
	}
}

func TestLoginAndSession(t *testing.T) {
	st := newFakeStore()
	s := NewService(st, time.Hour)
	ctx := context.Background()
	if err := s.Setup(ctx, "alice", "password123"); err != nil {
		t.Fatalf("首启失败: %v", err)
	}
	if _, _, err := s.Login(ctx, "alice", "wrong-password1"); err == nil {
		t.Fatal("错口令应拒")
	}
	if _, _, err := s.Login(ctx, "nobody", "password123"); err == nil {
		t.Fatal("无此用户应拒(同一错误,不泄露存在性)")
	}
	token, user, err := s.Login(ctx, "alice", "password123")
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	if user == nil || user.Username != "alice" || user.Role != RoleAdmin {
		t.Fatalf("登录应回用户(id/username/role): %v", user)
	}
	u, err := s.Authenticate(ctx, token)
	if err != nil || u == nil || u.Username != "alice" {
		t.Fatalf("会话认证失败: u=%v err=%v", u, err)
	}
	if err := s.Logout(ctx, token); err != nil {
		t.Fatalf("登出失败: %v", err)
	}
	if u, _ := s.Authenticate(ctx, token); u != nil {
		t.Fatal("登出后会话应焚毁")
	}
}

func TestSessionExpiry(t *testing.T) {
	st := newFakeStore()
	s := NewService(st, time.Hour)
	now := time.Now()
	s.SetClock(func() time.Time { return now })
	ctx := context.Background()
	_ = s.Setup(ctx, "alice", "password123")
	token, _, _ := s.Login(ctx, "alice", "password123")
	now = now.Add(2 * time.Hour) // 时钟拨过有效期
	if u, _ := s.Authenticate(ctx, token); u != nil {
		t.Fatal("过期会话应无效")
	}
}

// TestLoginLockout 失败锁定焊死:5 次连错 → ErrAccountLocked;锁期内正确
// 口令也拒(不校验口令);锁期过后正确口令登录成功且计数清零。
func TestLoginLockout(t *testing.T) {
	st := newFakeStore()
	s := NewService(st, time.Hour)
	now := time.Now()
	s.SetClock(func() time.Time { return now })
	ctx := context.Background()
	if err := s.Setup(ctx, "alice", "password123"); err != nil {
		t.Fatalf("首启失败: %v", err)
	}
	for i := 0; i < MaxFailedAttempts-1; i++ {
		if _, _, err := s.Login(ctx, "alice", "wrong-pass1"); err == nil ||
			errors.Is(err, ErrAccountLocked) {
			t.Fatalf("第 %d 次失败应只报凭据不符: %v", i+1, err)
		}
	}
	// 第 5 次失败:报凭据不符(当次),此后锁定
	if _, _, err := s.Login(ctx, "alice", "wrong-pass1"); err == nil ||
		errors.Is(err, ErrAccountLocked) {
		t.Fatalf("第 %d 次失败应仍报凭据不符: %v", MaxFailedAttempts, err)
	}
	if _, _, err := s.Login(ctx, "alice", "password123"); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("锁定后正确口令也应拒(ErrAccountLocked): %v", err)
	}
	// 锁期内计数不涨(锁定分支不记账)
	u, _ := st.userByID("u1")
	if u.failedAttempts != MaxFailedAttempts {
		t.Fatalf("锁定期内失败计数不应再涨: %d", u.failedAttempts)
	}
	// 拨过锁定期:正确口令登录成功,计数清零
	now = now.Add(LockDuration + time.Minute)
	if _, _, err := s.Login(ctx, "alice", "password123"); err != nil {
		t.Fatalf("锁期过后应可登录: %v", err)
	}
	if u.failedAttempts != 0 || u.lockedUntil != nil {
		t.Fatalf("登录成功应清零: attempts=%d locked=%v", u.failedAttempts, u.lockedUntil)
	}
}

// TestLoginSuccessClearsFailures 未达阈值时一次成功即清零失败计数。
func TestLoginSuccessClearsFailures(t *testing.T) {
	st := newFakeStore()
	s := NewService(st, time.Hour)
	ctx := context.Background()
	_ = s.Setup(ctx, "alice", "password123")
	for i := 0; i < 3; i++ {
		_, _, _ = s.Login(ctx, "alice", "wrong-pass1")
	}
	if _, _, err := s.Login(ctx, "alice", "password123"); err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	u, _ := st.userByID("u1")
	if u.failedAttempts != 0 {
		t.Fatalf("成功后失败计数应清零: %d", u.failedAttempts)
	}
}

// 管理面夹具:admin(首启)+ 按名建用户,回 (service, store, 各用户 id)。
func setupMulti(t *testing.T) (*Service, *fakeStore, map[string]string) {
	t.Helper()
	st := newFakeStore()
	s := NewService(st, time.Hour)
	ctx := context.Background()
	if err := s.Setup(ctx, "admin", "password123"); err != nil {
		t.Fatalf("首启失败: %v", err)
	}
	ids := map[string]string{"admin": "u1"}
	return s, st, ids
}

func TestCreateUserAs(t *testing.T) {
	s, _, _ := setupMulti(t)
	ctx := context.Background()
	u, err := s.CreateUserAs(ctx, "op1", "operator1pass", RoleOperator)
	if err != nil {
		t.Fatalf("建 operator 失败: %v", err)
	}
	if u.Role != RoleOperator || u.ID == "" {
		t.Fatalf("建账不符: %+v", u)
	}
	if _, err := s.CreateUserAs(ctx, "op1", "operator1pass", RoleOperator); err == nil ||
		!strings.Contains(err.Error(), "用户名已存在") {
		t.Fatalf("重名应报「用户名已存在」: %v", err)
	}
	if _, err := s.CreateUserAs(ctx, "op2", "operator1pass", "root"); err == nil {
		t.Fatal("非法角色应拒")
	}
	if _, err := s.CreateUserAs(ctx, "op3", "nodigits", RoleOperator); err == nil {
		t.Fatal("弱口令应拒(复杂度)")
	}
}

func TestSetRoleGates(t *testing.T) {
	s, _, ids := setupMulti(t)
	ctx := context.Background()
	if err := s.SetRole(ctx, ids["admin"], ids["admin"], RoleOperator); err == nil {
		t.Fatal("不许改自己的角色")
	}
	// 唯一活跃 admin 被他人降级也拒(最后 admin 闸)
	if err := s.SetRole(ctx, "someone-else", ids["admin"], RoleOperator); err == nil {
		t.Fatal("最后一个活跃 admin 不许降级")
	}
	// 有第二个 admin 后放行
	op, err := s.CreateUserAs(ctx, "admin2", "password123", RoleAdmin)
	if err != nil {
		t.Fatalf("建第二个 admin 失败: %v", err)
	}
	if err := s.SetRole(ctx, op.ID, ids["admin"], RoleOperator); err != nil {
		t.Fatalf("有替补 admin 后降级应放行: %v", err)
	}
}

func TestSetDisabledGates(t *testing.T) {
	s, _, ids := setupMulti(t)
	ctx := context.Background()
	if err := s.SetDisabled(ctx, ids["admin"], ids["admin"], true); err == nil {
		t.Fatal("不许禁用自己")
	}
	if err := s.SetDisabled(ctx, "someone-else", ids["admin"], true); err == nil {
		t.Fatal("禁用最后一个活跃 admin 应拒")
	}
	op, err := s.CreateUserAs(ctx, "op1", "operator1pass", RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetDisabled(ctx, ids["admin"], op.ID, true); err != nil {
		t.Fatalf("禁用 operator 应放行: %v", err)
	}
	// 禁用后会话立失效(对齐 PG SessionUser 语义)
	if _, _, err := s.Login(ctx, "op1", "operator1pass"); err == nil {
		t.Fatal("禁用用户登录应拒")
	}
}

func TestResetPasswordBurnsSessions(t *testing.T) {
	s, _, ids := setupMulti(t)
	ctx := context.Background()
	op, err := s.CreateUserAs(ctx, "op1", "operator1pass", RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := s.Login(ctx, "op1", "operator1pass")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ResetPassword(ctx, op.ID, "newpass456"); err != nil {
		t.Fatalf("重置失败: %v", err)
	}
	if u, _ := s.Authenticate(ctx, token); u != nil {
		t.Fatal("重置后旧会话应焚毁")
	}
	if _, _, err := s.Login(ctx, "op1", "operator1pass"); err == nil {
		t.Fatal("旧口令应不能再登录")
	}
	if _, _, err := s.Login(ctx, "op1", "newpass456"); err != nil {
		t.Fatalf("新口令应能登录: %v", err)
	}
	if err := s.ResetPassword(ctx, op.ID, "weak"); err == nil {
		t.Fatal("弱口令重置应拒")
	}
	_ = ids
}

func TestChangePassword(t *testing.T) {
	s, _, ids := setupMulti(t)
	ctx := context.Background()
	if err := s.ChangePassword(ctx, ids["admin"], "wrong-old1", "newpass456"); err == nil {
		t.Fatal("旧口令错应拒")
	}
	if err := s.ChangePassword(ctx, ids["admin"], "password123", "nodigits"); err == nil {
		t.Fatal("新口令不过复杂度应拒")
	}
	if err := s.ChangePassword(ctx, ids["admin"], "password123", "newpass456"); err != nil {
		t.Fatalf("改密失败: %v", err)
	}
	if _, _, err := s.Login(ctx, "admin", "password123"); err == nil {
		t.Fatal("改密后旧口令应拒")
	}
	if _, _, err := s.Login(ctx, "admin", "newpass456"); err != nil {
		t.Fatalf("改密后新口令应通: %v", err)
	}
}

func TestDeleteUserGates(t *testing.T) {
	s, st, ids := setupMulti(t)
	ctx := context.Background()
	if err := s.DeleteUserAs(ctx, ids["admin"], ids["admin"]); err == nil {
		t.Fatal("不许删自己")
	}
	if err := s.DeleteUserAs(ctx, "someone-else", ids["admin"]); err == nil {
		t.Fatal("删最后一个活跃 admin 应拒")
	}
	op, err := s.CreateUserAs(ctx, "op1", "operator1pass", RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := s.Login(ctx, "op1", "operator1pass")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUserAs(ctx, ids["admin"], op.ID); err != nil {
		t.Fatalf("删 operator 应放行: %v", err)
	}
	if u, _ := s.Authenticate(ctx, token); u != nil {
		t.Fatal("删用户后其会话应焚毁")
	}
	if _, _, err := s.Login(ctx, "op1", "operator1pass"); err == nil {
		t.Fatal("被删用户应不能再登录")
	}
	// 删除同事务焚会话:fake 账面核查
	for _, sess := range st.sessions {
		if sess.userID == op.ID {
			t.Fatal("被删用户的会话账应清空")
		}
	}
}
