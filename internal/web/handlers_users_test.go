// 多用户契约测试(0.26.0-m4-multiuser):用户 CRUD 全链、角色闸、
// 登录失败锁定、自残/最后 admin 闸、重置焚会话、本人改密。
package web

import (
	"net/http"
	"strings"
	"testing"
)

// createUserAPI admin 建用户助手(回 201 的 user 对象)。
func createUserAPI(t *testing.T, e *testEnv, username, password, role string) map[string]any {
	t.Helper()
	code, out := e.do(t, "POST", "/api/users",
		map[string]string{"username": username, "password": password, "role": role})
	if code != http.StatusCreated {
		t.Fatalf("建用户 %s 失败: %d %v", username, code, out)
	}
	return out["user"].(map[string]any)
}

// loginAdmin 重新登录 admin(首启已过,只打登录端点)。
func loginAdmin(t *testing.T, e *testEnv) {
	t.Helper()
	code, out := e.do(t, "POST", "/api/auth/login",
		map[string]string{"username": "admin", "password": "password123"})
	if code != http.StatusOK {
		t.Fatalf("admin 登录失败: %d %v", code, out)
	}
}

// TestUserManagementChain 用户 CRUD 全链 + 审计动作齐。
func TestUserManagementChain(t *testing.T) {
	e := newTestEnv(t)
	e.login(t) // admin

	// 初始只有 admin
	code, out := e.do(t, "GET", "/api/users", nil)
	if code != http.StatusOK || len(out["users"].([]any)) != 1 {
		t.Fatalf("初始应 1 用户: %d %v", code, out)
	}

	// 建 operator + 校验负样本(重名/弱口令/非法角色)
	op := createUserAPI(t, e, "op", "operator1", "operator")
	if op["role"] != "operator" || op["id"] == "" {
		t.Fatalf("建账不符: %v", op)
	}
	if _, has := op["password_hash"]; has {
		t.Fatal("响应永不回口令哈希")
	}
	if code, out := e.do(t, "POST", "/api/users",
		map[string]string{"username": "op", "password": "operator1", "role": "operator"}); code !=
		http.StatusBadRequest || !strings.Contains(out["error"].(string), "用户名已存在") {
		t.Fatalf("重名应 400「用户名已存在」: %d %v", code, out)
	}
	if code, _ := e.do(t, "POST", "/api/users",
		map[string]string{"username": "x", "password": "nodigits", "role": "operator"}); code != http.StatusBadRequest {
		t.Fatalf("弱口令应 400: %d", code)
	}
	if code, _ := e.do(t, "POST", "/api/users",
		map[string]string{"username": "x", "password": "operator1", "role": "root"}); code != http.StatusBadRequest {
		t.Fatalf("非法角色应 400: %d", code)
	}

	// 改角色 + 禁用/解禁
	code, out = e.do(t, "PATCH", "/api/users/op", map[string]any{"role": "admin"})
	if code != http.StatusOK || out["user"].(map[string]any)["role"] != "admin" {
		t.Fatalf("改角色失败: %d %v", code, out)
	}
	code, out = e.do(t, "PATCH", "/api/users/op", map[string]any{"disabled": true})
	if code != http.StatusOK || out["user"].(map[string]any)["disabled"] != true {
		t.Fatalf("禁用失败: %d %v", code, out)
	}
	if code, _ := e.do(t, "PATCH", "/api/users/no-such",
		map[string]any{"role": "admin"}); code != http.StatusNotFound {
		t.Fatalf("无此用户应 404: %d", code)
	}

	// 重置密码焚会话:op 登录拿 cookie → admin 重置 → 旧 cookie 失效
	code, out = e.do(t, "PATCH", "/api/users/op", map[string]any{"disabled": false})
	if code != http.StatusOK {
		t.Fatalf("解禁失败: %d %v", code, out)
	}
	if code, _ := e.do(t, "POST", "/api/auth/login",
		map[string]string{"username": "op", "password": "operator1"}); code != http.StatusOK {
		t.Fatalf("op 登录失败: %d", code)
	}
	opCookie := e.cookie
	loginAdmin(t, e) // 切回 admin
	if code, _ := e.do(t, "POST", "/api/users/op/password",
		map[string]string{"password": "newpass456"}); code != http.StatusNoContent {
		t.Fatalf("重置密码应 204: %d", code)
	}
	e.cookie = opCookie
	if code, _ := e.do(t, "GET", "/api/auth/me", nil); code != http.StatusUnauthorized {
		t.Fatalf("重置后旧会话应焚毁: %d", code)
	}
	e.cookie = ""

	// 删除
	loginAdmin(t, e)
	if code, _ := e.do(t, "DELETE", "/api/users/op", nil); code != http.StatusNoContent {
		t.Fatalf("删用户应 204: %d", code)
	}
	if code, _ := e.do(t, "POST", "/api/auth/login",
		map[string]string{"username": "op", "password": "newpass456"}); code != http.StatusUnauthorized {
		t.Fatalf("被删用户应不能再登录: %d", code)
	}
	loginAdmin(t, e)

	// 审计动作齐(口令永不入审计)
	actions := map[string]bool{}
	for _, en := range e.audit.entries {
		actions[en.Action] = true
		if strings.Contains(en.DetailJSON, "operator1") ||
			strings.Contains(en.DetailJSON, "newpass456") {
			t.Fatalf("审计绝不可记口令: %s", en.DetailJSON)
		}
	}
	for _, want := range []string{"user.create", "user.update_role", "user.disable",
		"user.enable", "user.reset_password", "user.delete"} {
		if !actions[want] {
			t.Fatalf("审计缺动作 %s: 实有 %v", want, actions)
		}
	}
}

// TestRoleGate operator 角色闸:用户管理/系统配置写/全局 KB 写 403;
// 案件操作与只读端点放行。
func TestRoleGate(t *testing.T) {
	e := newTestEnv(t)
	e.srv.deps.AI = newFakeAI()
	e.login(t)
	createUserAPI(t, e, "op", "operator1", "operator")

	// 切 operator
	if code, out := e.do(t, "POST", "/api/auth/login",
		map[string]string{"username": "op", "password": "operator1"}); code != http.StatusOK {
		t.Fatalf("op 登录失败: %d %v", code, out)
	}
	// 登录响应带 id/username/role(前端消费契约)
	code, out := e.do(t, "GET", "/api/auth/me", nil)
	if code != http.StatusOK || out["user"].(map[string]any)["role"] != "operator" {
		t.Fatalf("auth/me 应见 operator: %d %v", code, out)
	}

	// 用户管理全拒
	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/users"}, {"POST", "/api/users"},
		{"PATCH", "/api/users/op"}, {"POST", "/api/users/op/password"},
		{"DELETE", "/api/users/op"},
	} {
		var body any
		if tc.method != "GET" && tc.method != "DELETE" {
			body = map[string]any{"username": "x", "password": "x12345678",
				"role": "admin", "disabled": true}
		}
		if code, out := e.do(t, tc.method, tc.path, body); code != http.StatusForbidden ||
			!strings.Contains(out["error"].(string), "需要管理员权限") {
			t.Fatalf("%s %s 应 403「需要管理员权限」: %d %v", tc.method, tc.path, code, out)
		}
	}
	// 系统配置写拒、读放行
	if code, _ := e.do(t, "PUT", "/api/ai/settings", map[string]any{
		"provider": "deepseek", "model": "deepseek-chat",
	}); code != http.StatusForbidden {
		t.Fatalf("operator 改 AI 设置应 403: %d", code)
	}
	if code, _ := e.do(t, "GET", "/api/ai/settings", nil); code != http.StatusOK {
		t.Fatalf("operator 读 AI 设置应 200: %d", code)
	}
	if code, _ := e.do(t, "POST", "/api/ai/settings/test-proxy",
		map[string]any{"proxy": "http://127.0.0.1:9"}); code != http.StatusForbidden {
		t.Fatalf("operator 代理自测应 403: %d", code)
	}
	// 全局 KB 写拒、读放行
	if code, _ := e.do(t, "POST", "/api/kb", map[string]any{
		"title": "x", "applies_to": []string{"execution"}, "content": "x",
	}); code != http.StatusForbidden {
		t.Fatalf("operator 写全局 KB 应 403: %d", code)
	}
	if code, _ := e.do(t, "GET", "/api/kb", nil); code != http.StatusOK {
		t.Fatalf("operator 读 KB 应 200: %d", code)
	}
	// 案件操作全角色:建案 + 案件级 KB 勾选放行
	code, out = e.do(t, "POST", "/api/cases", map[string]any{
		"name": "case-op", "incident_type": "other",
	})
	if code != http.StatusCreated {
		t.Fatalf("operator 建案应放行: %d %v", code, out)
	}
	caseID := out["case"].(map[string]any)["id"].(string)
	if code, out := e.do(t, "PUT", "/api/cases/"+caseID+"/kb",
		map[string]any{"selected": []string{}}); code != http.StatusOK {
		t.Fatalf("operator 案件级 KB 勾选应 200: %d %v", code, out)
	}
}

// TestLoginLockoutWeb 锁定全链:5 次连错 → 401 锁定文案;锁期内正确口令
// 也拒;审计 reason 分 bad_credentials/locked。
func TestLoginLockoutWeb(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	createUserAPI(t, e, "op", "operator1", "operator")
	e.cookie = "" // 登出视角,纯打登录端点

	for i := 0; i < 5; i++ {
		code, out := e.do(t, "POST", "/api/auth/login",
			map[string]string{"username": "op", "password": "wrong-pass1"})
		if code != http.StatusUnauthorized || out["error"].(string) != "凭据不符" {
			t.Fatalf("第 %d 次失败应 401「凭据不符」: %d %v", i+1, code, out)
		}
	}
	// 锁期内正确口令也拒,文案如实区分
	code, out := e.do(t, "POST", "/api/auth/login",
		map[string]string{"username": "op", "password": "operator1"})
	if code != http.StatusUnauthorized ||
		!strings.Contains(out["error"].(string), "锁定") {
		t.Fatalf("锁定后应 401 锁定文案: %d %v", code, out)
	}
	// 审计 reason:bad_credentials ×5 + locked ×1
	var bad, locked int
	for _, en := range e.audit.entries {
		if en.Action != "auth.login" || !strings.Contains(en.DetailJSON, `"ok":false`) {
			continue
		}
		if strings.Contains(en.DetailJSON, `"reason":"locked"`) {
			locked++
		} else if strings.Contains(en.DetailJSON, `"reason":"bad_credentials"`) {
			bad++
		}
	}
	if bad != 5 || locked != 1 {
		t.Fatalf("审计 reason 不符: bad=%d locked=%d", bad, locked)
	}
	// admin 不受牵连,照登
	loginAdmin(t, e)
}

// TestSelfHarmGates 自残闸:改自己角色/禁用自己/删自己一律 400。
func TestSelfHarmGates(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	if code, out := e.do(t, "PATCH", "/api/users/admin",
		map[string]any{"role": "operator"}); code != http.StatusBadRequest {
		t.Fatalf("改自己角色应 400: %d %v", code, out)
	}
	if code, out := e.do(t, "PATCH", "/api/users/admin",
		map[string]any{"disabled": true}); code != http.StatusBadRequest {
		t.Fatalf("禁用自己应 400: %d %v", code, out)
	}
	if code, out := e.do(t, "DELETE", "/api/users/admin", nil); code != http.StatusBadRequest {
		t.Fatalf("删自己应 400: %d %v", code, out)
	}
}

// TestChangePasswordWeb 本人改密:旧口令错 400;新口令弱 400;
// 改后旧口令拒、新口令通。
func TestChangePasswordWeb(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	if code, _ := e.do(t, "POST", "/api/auth/password", map[string]string{
		"old_password": "wrong-old1", "new_password": "newpass456",
	}); code != http.StatusBadRequest {
		t.Fatalf("旧口令错应 400: %d", code)
	}
	if code, _ := e.do(t, "POST", "/api/auth/password", map[string]string{
		"old_password": "password123", "new_password": "nodigits",
	}); code != http.StatusBadRequest {
		t.Fatalf("弱新口令应 400: %d", code)
	}
	if code, _ := e.do(t, "POST", "/api/auth/password", map[string]string{
		"old_password": "password123", "new_password": "newpass456",
	}); code != http.StatusOK {
		t.Fatalf("改密应 200: %d", code)
	}
	found := false
	for _, en := range e.audit.entries {
		if en.Action == "user.password_change" {
			found = true
		}
	}
	if !found {
		t.Fatal("改密应进审计(user.password_change)")
	}
	e.cookie = ""
	if code, _ := e.do(t, "POST", "/api/auth/login",
		map[string]string{"username": "admin", "password": "password123"}); code != http.StatusUnauthorized {
		t.Fatalf("旧口令应拒: %d", code)
	}
	if code, _ := e.do(t, "POST", "/api/auth/login",
		map[string]string{"username": "admin", "password": "newpass456"}); code != http.StatusOK {
		t.Fatalf("新口令应通: %d", code)
	}
}
