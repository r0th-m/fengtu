// 启发式知识库端点契约测试(0.19.0-heuristic-kb 起;0.27.1-kb-simplify):
// 合一清单(builtin+user 标 source,不再输出 enabled)、用户条目 CRUD、
// 内置条目保护(改内容/启停/删除一律 400 如实)、写操作审计
// (kb.create/update/delete;kb.toggle 随启停下线退役)、登录闸。
// 走真实 kb.Service + 内存 Store,零 AI 调用。
package web

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ye-mengwen/fengtu/internal/kb"
)

// fakeKBStore 内存版 kb.Store(web 契约测试用;真库由 store.PG 实现,台架验收)。
type fakeKBStore struct {
	mu      sync.Mutex
	users   []*kb.Entry
	states  map[string]bool
	caseSel map[string][]string // case_id → 勾选条目 id 集(0.20.0)
	nextID  int
}

func newFakeKBStore() *fakeKBStore {
	return &fakeKBStore{states: map[string]bool{}, caseSel: map[string][]string{}}
}

func (f *fakeKBStore) ListUserKB(_ context.Context) ([]*kb.Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*kb.Entry, len(f.users))
	copy(out, f.users)
	return out, nil
}

func (f *fakeKBStore) CreateKB(_ context.Context, e *kb.Entry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	e.ID = fmt.Sprintf("00000000-0000-0000-0000-%012d", f.nextID)
	e.CreatedAt = time.Now().UTC()
	e.UpdatedAt = e.CreatedAt
	f.users = append(f.users, e)
	return nil
}

func (f *fakeKBStore) UpdateKB(_ context.Context, e *kb.Entry) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, u := range f.users {
		if u.ID == e.ID {
			e.CreatedAt = u.CreatedAt
			e.UpdatedAt = time.Now().UTC()
			f.users[i] = e
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeKBStore) DeleteKB(_ context.Context, id string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, u := range f.users {
		if u.ID == id {
			f.users = append(f.users[:i], f.users[i+1:]...)
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeKBStore) SetBuiltinKBState(_ context.Context, id string, enabled bool) (time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.states[id] = enabled
	return time.Now().UTC(), nil
}

func (f *fakeKBStore) ListBuiltinKBStates(_ context.Context) (map[string]bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]bool{}
	for k, v := range f.states {
		out[k] = v
	}
	return out, nil
}

func (f *fakeKBStore) ListCaseKB(_ context.Context, caseID string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.caseSel[caseID]...), nil
}

func (f *fakeKBStore) SetCaseKB(_ context.Context, caseID, _ string, ids []string) (added, removed []string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	old := map[string]bool{}
	for _, id := range f.caseSel[caseID] {
		old[id] = true
	}
	newSet := map[string]bool{}
	for _, id := range ids {
		newSet[id] = true
		if !old[id] {
			added = append(added, id)
		}
	}
	for id := range old {
		if !newSet[id] {
			removed = append(removed, id)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	f.caseSel[caseID] = append([]string(nil), ids...)
	return added, removed, nil
}

// entriesOf 从 GET /api/kb 响应抠条目数组。
func entriesOf(t *testing.T, body map[string]any) []any {
	t.Helper()
	entries, ok := body["entries"].([]any)
	if !ok {
		t.Fatalf("清单响应缺 entries: %v", body)
	}
	return entries
}

func TestKBListMerge(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	code, body := e.do(t, "GET", "/api/kb", nil)
	if code != http.StatusOK {
		t.Fatalf("清单状态码: %d %v", code, body)
	}
	entries := entriesOf(t, body)
	if len(entries) != 2 { // 两条内置夹具
		t.Fatalf("清单条目数: %d", len(entries))
	}
	first := entries[0].(map[string]any)
	if first["source"] != "builtin" {
		t.Fatalf("内置条目应标 builtin: %v", first)
	}
	if _, has := first["enabled"]; has {
		t.Fatalf("0.27.1 起清单不再输出 enabled(启停退役): %v", first)
	}
	if _, ok := first["applies_to"].([]any); !ok {
		t.Fatalf("applies_to 应为数组: %v", first)
	}
}

func TestKBAuthGate(t *testing.T) {
	e := newTestEnv(t)
	// 未登录:登录闸 401
	code, _ := e.do(t, "GET", "/api/kb", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("未登录应 401: %d", code)
	}
}

func TestKBUserCRUDAndAudit(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)

	// 新建
	code, body := e.do(t, "POST", "/api/kb", map[string]any{
		"title": "我的沉淀", "content": "怎么找丙", "applies_to": []string{"timeline"},
	})
	if code != http.StatusCreated {
		t.Fatalf("新建状态码: %d %v", code, body)
	}
	entry := body["entry"].(map[string]any)
	id := entry["id"].(string)
	if entry["source"] != "user" {
		t.Fatalf("用户条目应标 user: %v", entry)
	}
	// 列表可见(刷新语义:合一清单重查)
	code, body = e.do(t, "GET", "/api/kb", nil)
	if code != http.StatusOK || len(entriesOf(t, body)) != 3 {
		t.Fatalf("新建后清单应 3 条: %d %v", code, body)
	}

	// 编辑(全字段)
	code, body = e.do(t, "PUT", "/api/kb/"+id, map[string]any{
		"title": "改后标题", "content": "改后正文",
		"applies_to": []string{"execution", "persistence"},
	})
	if code != http.StatusOK {
		t.Fatalf("编辑状态码: %d %v", code, body)
	}
	entry = body["entry"].(map[string]any)
	if entry["title"] != "改后标题" {
		t.Fatalf("编辑未生效: %v", entry)
	}

	// 启停语义下线(0.27.1):带 enabled 字段一律 400 如实
	code, body = e.do(t, "PUT", "/api/kb/"+id, map[string]any{"enabled": false})
	if code != http.StatusBadRequest ||
		!strings.Contains(fmt.Sprint(body["error"]), "启停已下线") {
		t.Fatalf("enabled 字段应 400 如实(启停下线): %d %v", code, body)
	}
	// 编辑字段混带 enabled 同样 400(不静默吞掉)
	code, _ = e.do(t, "PUT", "/api/kb/"+id, map[string]any{
		"title": "再来", "enabled": true,
	})
	if code != http.StatusBadRequest {
		t.Fatalf("混带 enabled 应 400: %d", code)
	}

	// 负样本:空标题 / 空标签
	code, body = e.do(t, "POST", "/api/kb", map[string]any{
		"title": " ", "content": "正文", "applies_to": []string{"timeline"},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("空标题应 400: %d %v", code, body)
	}
	code, body = e.do(t, "POST", "/api/kb", map[string]any{
		"title": "标题", "content": "正文",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("缺 applies_to 应 400: %d %v", code, body)
	}

	// 删除
	code, _ = e.do(t, "DELETE", "/api/kb/"+id, nil)
	if code != http.StatusOK {
		t.Fatalf("删除状态码: %d", code)
	}
	code, _ = e.do(t, "DELETE", "/api/kb/"+id, nil)
	if code != http.StatusNotFound {
		t.Fatalf("幽灵删除应 404: %d", code)
	}

	// 审计:kb.create / kb.update / kb.delete 全落账;kb.toggle 随启停下线不再产生
	want := map[string]bool{"kb.create": false, "kb.update": false, "kb.delete": false}
	for _, en := range e.audit.entries {
		if _, ok := want[en.Action]; ok {
			want[en.Action] = true
		}
		if en.Action == "kb.toggle" {
			t.Fatalf("启停下线后不应再产生 kb.toggle 审计: %v", en)
		}
		if en.Action == "kb.create" && en.Actor != "admin" {
			t.Fatalf("审计操作人应为登录用户: %v", en.Actor)
		}
	}
	for action, seen := range want {
		if !seen {
			t.Fatalf("审计缺 %s: %v", action, e.audit.entries)
		}
	}
}

func TestKBBuiltinProtection(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)

	// 内置条目改内容 → 400 如实
	code, body := e.do(t, "PUT", "/api/kb/t-one", map[string]any{
		"title": "想改内置", "content": "不行",
	})
	if code != http.StatusBadRequest ||
		!strings.Contains(fmt.Sprint(body["error"]), "内置条目不可改") {
		t.Fatalf("内置改内容应 400 如实: %d %v", code, body)
	}
	// 内置条目删除 → 400
	code, body = e.do(t, "DELETE", "/api/kb/t-one", nil)
	if code != http.StatusBadRequest {
		t.Fatalf("内置删除应 400: %d %v", code, body)
	}
	// 内置条目启停 → 400(0.27.1 启停下线,生效以案件勾选为准)
	code, body = e.do(t, "PUT", "/api/kb/t-one", map[string]any{"enabled": false})
	if code != http.StatusBadRequest ||
		!strings.Contains(fmt.Sprint(body["error"]), "启停已下线") {
		t.Fatalf("内置启停应 400 如实(启停下线): %d %v", code, body)
	}
	// 幽灵 id:PUT/DELETE 404
	code, _ = e.do(t, "PUT", "/api/kb/ghost-id", map[string]any{"title": "x"})
	if code != http.StatusNotFound {
		t.Fatalf("幽灵 PUT 应 404: %d", code)
	}
	// kb.toggle 审计不再产生(启停下线)
	for _, en := range e.audit.entries {
		if en.Action == "kb.toggle" {
			t.Fatalf("启停下线后不应再产生 kb.toggle 审计: %v", en)
		}
	}
}

// ---- 案件级 KB 勾选(0.20.0-case-kb) ----

func TestCaseKBSelectAndAudit(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)

	// 建案带勾选(kb_entries 随案落库;响应/审计如实带勾选数)
	code, body := e.do(t, "POST", "/api/cases", map[string]any{
		"name": "kb 勾选案", "incident_type": "intrusion",
		"kb_entries": []string{"t-one", "t-two"},
	})
	if code != http.StatusCreated {
		t.Fatalf("建案状态码: %d %v", code, body)
	}
	if body["kb_selected"] != float64(2) {
		t.Fatalf("响应应如实带勾选数: %v", body)
	}
	caseID := body["case"].(map[string]any)["id"].(string)

	// 案内勾选视图:勾选集回读 + 条目池
	code, body = e.do(t, "GET", "/api/cases/"+caseID+"/kb", nil)
	if code != http.StatusOK {
		t.Fatalf("勾选视图状态码: %d %v", code, body)
	}
	sel := body["selected"].([]any)
	if len(sel) != 2 {
		t.Fatalf("勾选集应为 2 条: %v", sel)
	}
	if len(entriesOf(t, body)) != 2 {
		t.Fatalf("条目池应为合一清单: %v", body)
	}

	// 案内覆写:去掉 t-one → 差集审计 kb.case_update
	code, body = e.do(t, "PUT", "/api/cases/"+caseID+"/kb", map[string]any{
		"selected": []string{"t-two"},
	})
	if code != http.StatusOK {
		t.Fatalf("覆写状态码: %d %v", code, body)
	}
	removed := body["removed"].([]any)
	if len(removed) != 1 || removed[0] != "t-one" {
		t.Fatalf("差集如实: %v", body)
	}
	code, body = e.do(t, "GET", "/api/cases/"+caseID+"/kb", nil)
	if len(body["selected"].([]any)) != 1 {
		t.Fatalf("覆写未生效: %v", body)
	}

	// 显式零勾选合法(本案不注入,如实)
	code, _ = e.do(t, "PUT", "/api/cases/"+caseID+"/kb", map[string]any{
		"selected": []string{},
	})
	if code != http.StatusOK {
		t.Fatalf("零勾选应合法: %d", code)
	}

	// 负样本:未知条目 id 400
	code, body = e.do(t, "PUT", "/api/cases/"+caseID+"/kb", map[string]any{
		"selected": []string{"ghost-id"},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("未知条目应 400: %d %v", code, body)
	}
	// 建案带未知条目同样 400
	code, body = e.do(t, "POST", "/api/cases", map[string]any{
		"name": "坏勾选案", "incident_type": "other",
		"kb_entries": []string{"ghost-id"},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("建案未知勾选应 400: %d %v", code, body)
	}

	// 审计:case.create 带 kb_selected;kb.case_update 带差集
	var createOK, updateOK bool
	for _, en := range e.audit.entries {
		if en.Action == "case.create" && en.Scope == "kb 勾选案" &&
			strings.Contains(en.DetailJSON, `"kb_selected":2`) {
			createOK = true
		}
		if en.Action == "kb.case_update" && en.CaseID == caseID {
			updateOK = true
		}
	}
	if !createOK || !updateOK {
		t.Fatalf("审计缺账(create=%v update=%v): %v", createOK, updateOK, e.audit.entries)
	}
}

// ---- 建案默认 KB 预勾选(0.30.0-report-ux) ----

// TestCaseKBPrecheckOnCreate POST /api/cases 不传 kb_entries(nil)时按应急
// 类型套默认预勾选(映射表 kb.PrecheckTags,与前端向导同表);显式空数组
// 仍=零勾选(判断权归人);显式勾选不变。响应/审计如实标 kb_preselected。
// 夹具条目:t-one(execution)/ t-two(timeline)。
func TestCaseKBPrecheckOnCreate(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)

	// nil(不传 kb_entries)+ webshell → 预勾选 execution/persistence → t-one
	code, body := e.do(t, "POST", "/api/cases", map[string]any{
		"name": "预勾选案-shell", "incident_type": "webshell",
	})
	if code != http.StatusCreated {
		t.Fatalf("建案状态码: %d %v", code, body)
	}
	if body["kb_preselected"] != true || body["kb_selected"] != float64(1) {
		t.Fatalf("应预勾选 1 条且如实标注: %v", body)
	}
	caseID := body["case"].(map[string]any)["id"].(string)
	code, body = e.do(t, "GET", "/api/cases/"+caseID+"/kb", nil)
	if code != http.StatusOK {
		t.Fatalf("勾选视图状态码: %d %v", code, body)
	}
	sel := body["selected"].([]any)
	if len(sel) != 1 || sel[0] != "t-one" {
		t.Fatalf("webshell 预勾选应只中 t-one(execution): %v", sel)
	}
	// 审计如实标 kb_preselected
	var auditOK bool
	for _, en := range e.audit.entries {
		if en.Action == "case.create" && en.Scope == "预勾选案-shell" &&
			strings.Contains(en.DetailJSON, `"kb_preselected":true`) {
			auditOK = true
		}
	}
	if !auditOK {
		t.Fatalf("case.create 审计应标 kb_preselected=true: %v", e.audit.entries)
	}

	// nil + intrusion(全勾哨兵)→ 全条目
	code, body = e.do(t, "POST", "/api/cases", map[string]any{
		"name": "预勾选案-入侵", "incident_type": "intrusion",
	})
	if code != http.StatusCreated || body["kb_selected"] != float64(2) {
		t.Fatalf("intrusion 应全勾 2 条: %d %v", code, body)
	}
	caseID2 := body["case"].(map[string]any)["id"].(string)
	_, body = e.do(t, "GET", "/api/cases/"+caseID2+"/kb", nil)
	if len(body["selected"].([]any)) != 2 {
		t.Fatalf("intrusion 预勾选应全勾: %v", body["selected"])
	}

	// 显式空数组 = 零勾选(判断权归人;机器不替人补勾)
	code, body = e.do(t, "POST", "/api/cases", map[string]any{
		"name": "零勾选案", "incident_type": "intrusion",
		"kb_entries": []string{},
	})
	if code != http.StatusCreated {
		t.Fatalf("显式空勾选建案状态码: %d %v", code, body)
	}
	if body["kb_preselected"] != false || body["kb_selected"] != float64(0) {
		t.Fatalf("显式空数组应零勾选且不标预勾选: %v", body)
	}
	caseID3 := body["case"].(map[string]any)["id"].(string)
	_, body = e.do(t, "GET", "/api/cases/"+caseID3+"/kb", nil)
	if len(body["selected"].([]any)) != 0 {
		t.Fatalf("显式空数组应零勾选: %v", body["selected"])
	}

	// 显式勾选不变(旧行为)
	code, body = e.do(t, "POST", "/api/cases", map[string]any{
		"name": "显式勾选案", "incident_type": "intrusion",
		"kb_entries": []string{"t-two"},
	})
	if code != http.StatusCreated || body["kb_preselected"] != false ||
		body["kb_selected"] != float64(1) {
		t.Fatalf("显式勾选不变: %d %v", code, body)
	}
}

// TestKBPrecheckEndpoint 预勾选端点:按类型返回勾选 id 集;未知类型 400;
// 未登录 401。映射表单一数据源在 kb.PrecheckTags(前端向导同源)。
func TestKBPrecheckEndpoint(t *testing.T) {
	e := newTestEnv(t)
	// 未登录 401
	code, _ := e.do(t, "GET", "/api/kb/precheck?incident_type=webshell", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("未登录应 401: %d", code)
	}
	e.login(t)
	// webshell → execution/persistence → 夹具只中 t-one
	code, body := e.do(t, "GET", "/api/kb/precheck?incident_type=webshell", nil)
	if code != http.StatusOK {
		t.Fatalf("precheck 状态码: %d %v", code, body)
	}
	sel := body["selected"].([]any)
	if len(sel) != 1 || sel[0] != "t-one" {
		t.Fatalf("webshell 预勾选应=[t-one]: %v", sel)
	}
	// 未知类型 400 如实
	code, body = e.do(t, "GET", "/api/kb/precheck?incident_type=ghost", nil)
	if code != http.StatusBadRequest {
		t.Fatalf("未知类型应 400: %d %v", code, body)
	}
}

func TestCaseKBAuthGate(t *testing.T) {
	e := newTestEnv(t)
	code, _ := e.do(t, "GET", "/api/cases/whatever/kb", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("未登录案内 KB 视图应 401: %d", code)
	}
	code, _ = e.do(t, "PUT", "/api/cases/whatever/kb", map[string]any{"selected": []string{}})
	if code != http.StatusUnauthorized {
		t.Fatalf("未登录案内 KB 覆写应 401: %d", code)
	}
}
