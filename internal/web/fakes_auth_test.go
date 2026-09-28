// auth.Store 的内存实现(web 契约测试用)。
// 0.26.0 起真模拟:按用户存角色/禁用/失败计数/锁定期,禁用即会话失效
// (对齐 PG SessionUser 语义)——fake 不真,角色闸/锁定测试就没意义。
package web

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ye-mengwen/fengtu/internal/auth"
)

type fakeAuthUser struct {
	id, hash, role string
	disabled       bool
	failedAttempts int
	lockedUntil    *time.Time
	createdAt      time.Time
}

type fakeAuthStore struct {
	mu       sync.Mutex // M4 竞态测试:fake 也必须并发安全,否则测试无效
	users    map[string]*fakeAuthUser // 主键 username
	sessions map[string]struct{ userID string; expires time.Time }
	next     int
}

func newFakeAuthStore() *fakeAuthStore {
	return &fakeAuthStore{
		users:    map[string]*fakeAuthUser{},
		sessions: map[string]struct{ userID string; expires time.Time }{},
	}
}

func (f *fakeAuthStore) HasUsers(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.users) > 0, nil
}

func (f *fakeAuthStore) CreateUser(_ context.Context, username, passwordHash, role string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.users[username]; ok {
		return "", fmt.Errorf("用户名已存在: %s", username)
	}
	f.next++
	f.users[username] = &fakeAuthUser{
		id: username, hash: passwordHash, role: role, createdAt: time.Now(),
	}
	return username, nil
}

func (f *fakeAuthStore) UserForLogin(_ context.Context, username string) (*auth.User, string, bool, *time.Time, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[username]
	if !ok {
		return nil, "", false, nil, false, nil
	}
	return &auth.User{ID: u.id, Username: username, Role: u.role},
		u.hash, u.disabled, u.lockedUntil, true, nil
}

func (f *fakeAuthStore) CreateSession(_ context.Context, token, userID string, expiresAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions[token] = struct{ userID string; expires time.Time }{userID, expiresAt}
	return nil
}

func (f *fakeAuthStore) SessionUser(_ context.Context, token string, now time.Time) (*auth.User, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[token]
	if !ok || now.After(s.expires) {
		return nil, false, nil
	}
	u, ok := f.users[s.userID]
	if !ok || u.disabled {
		return nil, false, nil
	}
	return &auth.User{ID: u.id, Username: s.userID, Role: u.role}, true, nil
}

func (f *fakeAuthStore) DeleteSession(_ context.Context, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.sessions, token)
	return nil
}

// ---- 0.26.0-m4-multiuser:多用户管理面 ----

func (f *fakeAuthStore) ListUsers(context.Context) ([]auth.UserInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []auth.UserInfo{}
	for name, u := range f.users {
		out = append(out, auth.UserInfo{
			ID: u.id, Username: name, Role: u.role, Disabled: u.disabled,
			FailedAttempts: u.failedAttempts, LockedUntil: u.lockedUntil,
			CreatedAt: u.createdAt,
		})
	}
	return out, nil
}

// byID 锁内查找(调用方须已持 f.mu)。
func (f *fakeAuthStore) byID(id string) (*fakeAuthUser, bool) {
	u, ok := f.users[id] // fake 里 id == username(见 CreateUser)
	return u, ok
}

func (f *fakeAuthStore) UpdateUserRole(_ context.Context, id, role string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID(id)
	if !ok {
		return false, nil
	}
	u.role = role
	return true, nil
}

func (f *fakeAuthStore) SetUserDisabled(_ context.Context, id string, disabled bool) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID(id)
	if !ok {
		return false, nil
	}
	u.disabled = disabled
	return true, nil
}

func (f *fakeAuthStore) UpdatePassword(_ context.Context, id, passwordHash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID(id)
	if !ok {
		return fmt.Errorf("无此用户: %s", id)
	}
	u.hash = passwordHash
	return nil
}

func (f *fakeAuthStore) DeleteUser(_ context.Context, id string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.users[id]; !ok {
		return false, nil
	}
	delete(f.users, id)
	for token, s := range f.sessions {
		if s.userID == id {
			delete(f.sessions, token)
		}
	}
	return true, nil
}

func (f *fakeAuthStore) DeleteSessionsForUser(_ context.Context, userID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for token, s := range f.sessions {
		if s.userID == userID {
			delete(f.sessions, token)
		}
	}
	return nil
}

func (f *fakeAuthStore) RecordLoginFailure(_ context.Context, userID string,
	maxAttempts int, lockDur time.Duration, now time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID(userID)
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

func (f *fakeAuthStore) RecordLoginSuccess(_ context.Context, userID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID(userID)
	if !ok {
		return fmt.Errorf("无此用户: %s", userID)
	}
	u.failedAttempts = 0
	u.lockedUntil = nil
	return nil
}

func (f *fakeAuthStore) CountActiveAdmins(context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, u := range f.users {
		if u.role == auth.RoleAdmin && !u.disabled {
			n++
		}
	}
	return n, nil
}

func (f *fakeAuthStore) PasswordHashForUser(_ context.Context, id string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID(id)
	if !ok {
		return "", false, nil
	}
	return u.hash, true, nil
}
