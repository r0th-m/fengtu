// 案件生命周期端点契约测试(0.18.0-case-lifecycle):
// 改名(PATCH /api/cases/{id})契约与负样本;归档/解归档行为(列表标记、
// analyze/scan/intent 409、恢复);删除级联(名不符 400、在跑 409、
// PG+CH+vault+workspace 清空、审计链零影响)。
package web

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ye-mengwen/fengtu/internal/audit"
)

// TestCaseRename 改名契约:生效回读 + 审计 + 负样本(空/超长/重名/无此案)。
// (mkCase 复用 handlers_workspace_test.go 的建案快路径)
func TestCaseRename(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	a := mkCase(t, e, "旧名案件")
	b := mkCase(t, e, "占位案件")

	// 改名生效(GET 详情与列表同口径回读)
	code, out := e.do(t, "PATCH", "/api/cases/"+a, map[string]any{"name": "  新名案件  "})
	if code != http.StatusOK {
		t.Fatalf("改名应 200,得 %d: %v", code, out)
	}
	if out["case"].(map[string]any)["name"] != "新名案件" {
		t.Fatalf("改名未去空白生效: %v", out["case"])
	}
	_, out = e.do(t, "GET", "/api/cases/"+a, nil)
	if out["case"].(map[string]any)["name"] != "新名案件" {
		t.Fatal("改名后详情回读旧名")
	}

	// 审计留痕
	entries, err := e.audit.AllAudit(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, en := range entries {
		if en.Action == "case.rename" && strings.Contains(en.DetailJSON, "新名案件") {
			found = true
		}
	}
	if !found {
		t.Fatal("case.rename 未进审计链(或缺新旧名快照)")
	}

	// 负样本
	for name, tc := range map[string]struct {
		id   string
		body map[string]any
		want int
	}{
		"名空":   {a, map[string]any{"name": "   "}, http.StatusBadRequest},
		"名超长":  {a, map[string]any{"name": strings.Repeat("案", 129)}, http.StatusBadRequest},
		"重名":   {a, map[string]any{"name": "占位案件"}, http.StatusConflict},
		"无此案":  {"00000000-0000-0000-0000-000000000000",
			map[string]any{"name": "x"}, http.StatusNotFound},
	} {
		code, out := e.do(t, "PATCH", "/api/cases/"+tc.id, tc.body)
		if code != tc.want {
			t.Fatalf("%s:应 %d,得 %d: %v", name, tc.want, code, out)
		}
	}
	_ = b
}

// TestCaseArchiveFlow 归档行为:analyze/scan/intent 409、列表带归档标记、
// 解归档全恢复;归档/解归档进审计。
func TestCaseArchiveFlow(t *testing.T) {
	e := newTestEnv(t)
	e.srv.deps.Intent = newFakeIntent()
	e.login(t)
	id := mkCase(t, e, "归档演练")

	// 归档
	code, out := e.do(t, "POST", "/api/cases/"+id+"/archive", nil)
	if code != http.StatusOK {
		t.Fatalf("归档应 200,得 %d: %v", code, out)
	}
	if out["case"].(map[string]any)["archived_at"] == nil {
		t.Fatal("归档后 archived_at 应为非空")
	}
	// 详情回读同口径
	_, out = e.do(t, "GET", "/api/cases/"+id, nil)
	if out["case"].(map[string]any)["archived_at"] == nil {
		t.Fatal("详情回读归档标记缺失")
	}

	// 归档案写通路一律 409 如实
	for name, tc := range map[string]struct {
		path string
		body map[string]any
	}{
		"analyze": {"/api/cases/" + id + "/analyze", nil},
		"scan":    {"/api/cases/" + id + "/scans", nil},
		"intent":  {"/api/cases/" + id + "/intents", map[string]any{"text": "x"}},
	} {
		code, out := e.do(t, "POST", tc.path, tc.body)
		if code != http.StatusConflict {
			t.Fatalf("归档案 %s 应 409,得 %d: %v", name, code, out)
		}
		if !strings.Contains(out["error"].(string), "已归档") {
			t.Fatalf("归档案 %s 409 文案应如实: %v", name, out)
		}
	}

	// 重复归档幂等(200,审计再记一条,不报错)
	code, _ = e.do(t, "POST", "/api/cases/"+id+"/archive", nil)
	if code != http.StatusOK {
		t.Fatalf("重复归档应幂等 200,得 %d", code)
	}

	// 解归档恢复:analyze 不再 409(202 起任务;空源案件秒完)
	code, out = e.do(t, "POST", "/api/cases/"+id+"/unarchive", nil)
	if code != http.StatusOK {
		t.Fatalf("解归档应 200,得 %d: %v", code, out)
	}
	if out["case"].(map[string]any)["archived_at"] != nil {
		t.Fatal("解归档后 archived_at 应为 null")
	}
	code, out = e.do(t, "POST", "/api/cases/"+id+"/intents", map[string]any{"text": "恢复后手写意图"})
	if code != http.StatusCreated {
		t.Fatalf("解归档后手写意图应 201,得 %d: %v", code, out)
	}

	// 审计:archive/unarchive 双双落账
	entries, _ := e.audit.AllAudit(t.Context())
	acts := map[string]int{}
	for _, en := range entries {
		acts[en.Action]++
	}
	if acts["case.archive"] != 2 || acts["case.unarchive"] != 1 {
		t.Fatalf("归档审计账不符: %v", acts)
	}

	// 无此案 404
	code, _ = e.do(t, "POST", "/api/cases/00000000-0000-0000-0000-000000000000/archive", nil)
	if code != http.StatusNotFound {
		t.Fatalf("无此案归档应 404,得 %d", code)
	}
}

// TestCaseDelete 删除级联全链:名不符 400 → 在跑 409 → 名匹配删除 →
// PG(详情 404)+ CH 事件 + vault 原件 + workspace 目录清空,审计链零影响。
func TestCaseDelete(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)

	// 案件带真源(上传→摄入落 fakeCH 事件 + vault 原件)
	content := []byte(nginxContent)
	sum := sha256Hex(content)
	tid := e.uploadFile(t, "删除演练", "access.log", content, "nginx_combined")
	e.waitTask(t, tid)
	_, out := e.do(t, "GET", "/api/cases", nil)
	var caseID string
	for _, x := range out["cases"].([]any) {
		m := x.(map[string]any)
		if m["name"] == "删除演练" {
			caseID = m["id"].(string)
		}
	}
	if caseID == "" {
		t.Fatal("上传后案件未落账")
	}
	if n, _ := e.ch.CountEventsForCase(t.Context(), caseID); n == 0 {
		t.Fatal("前置:案件应有事件")
	}
	if !e.srv.deps.Vault.Exists(sum) {
		t.Fatal("前置:vault 原件应在库")
	}

	// 工作区目录造数(删除应连目录清)
	wsDir := filepath.Join(t.TempDir(), "workspace")
	e.srv.deps.DataDir = filepath.Dir(wsDir)
	caseWs := filepath.Join(wsDir, caseID)
	if err := os.MkdirAll(caseWs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caseWs, "note.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 负样本 1:名不符 400(逐字确认闸)
	code, out := e.do(t, "DELETE", "/api/cases/"+caseID, map[string]any{"name": "删错名"})
	if code != http.StatusBadRequest {
		t.Fatalf("名不符应 400,得 %d: %v", code, out)
	}
	// 负样本 2:在跑意图 409(先停再删,如实列出)
	e.meta.mu.Lock()
	e.meta.runningIntents[caseID] = 1
	e.meta.mu.Unlock()
	code, out = e.do(t, "DELETE", "/api/cases/"+caseID, map[string]any{"name": "删除演练"})
	if code != http.StatusConflict {
		t.Fatalf("在跑应 409,得 %d: %v", code, out)
	}
	if out["running_intents"].(float64) != 1 {
		t.Fatalf("409 应列出在跑意图: %v", out)
	}
	e.meta.mu.Lock()
	e.meta.runningIntents[caseID] = 0
	e.meta.mu.Unlock()

	// 名匹配 → 删除成功
	code, out = e.do(t, "DELETE", "/api/cases/"+caseID, map[string]any{"name": "删除演练"})
	if code != http.StatusOK {
		t.Fatalf("删除应 200,得 %d: %v", code, out)
	}
	if out["deleted"] != true || out["events_deleted"].(float64) == 0 {
		t.Fatalf("删除账不实: %v", out)
	}
	if out["vault_removed"].(float64) != 1 || !out["workspace_removed"].(bool) {
		t.Fatalf("级联账不实: %v", out)
	}

	// PG:详情 404,列表清空
	code, _ = e.do(t, "GET", "/api/cases/"+caseID, nil)
	if code != http.StatusNotFound {
		t.Fatalf("删后详情应 404,得 %d", code)
	}
	// CH:事件清空
	if n, _ := e.ch.CountEventsForCase(t.Context(), caseID); n != 0 {
		t.Fatalf("删后事件应清零,得 %d", n)
	}
	// 磁盘:vault 原件 + 工作区目录清
	if e.srv.deps.Vault.Exists(sum) {
		t.Fatal("删后 vault 原件应清除")
	}
	if _, err := os.Stat(caseWs); !os.IsNotExist(err) {
		t.Fatal("删后工作区目录应清除")
	}

	// 审计:case.delete 落账含快照;全链重算零影响(历史条目原样保留)
	entries, _ := e.audit.AllAudit(t.Context())
	found := false
	for _, en := range entries {
		if en.Action == "case.delete" && strings.Contains(en.DetailJSON, "删除演练") &&
			strings.Contains(en.DetailJSON, "\"events\"") {
			found = true
		}
	}
	if !found {
		t.Fatal("case.delete 未落审计(或缺名/事件数快照)")
	}
	if err := audit.VerifyChain(entries); err != nil {
		t.Fatalf("删后审计链应完整: %v", err)
	}

	// 无此案 404
	code, _ = e.do(t, "DELETE", "/api/cases/"+caseID, map[string]any{"name": "删除演练"})
	if code != http.StatusNotFound {
		t.Fatalf("重复删除应 404,得 %d", code)
	}
}

// TestCaseDeleteSharedVault 同哈希跨案引用:删案不动他案证据(内容寻址,
// 引用仍在的 vault 原件如实保留)。
func TestCaseDeleteSharedVault(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	content := []byte("shared evidence line\n")
	sum := sha256Hex(content)
	t1 := e.uploadFile(t, "甲案", "a.log", content, "")
	e.waitTask(t, t1)
	t2 := e.uploadFile(t, "乙案", "b.log", content, "")
	e.waitTask(t, t2)

	_, out := e.do(t, "GET", "/api/cases", nil)
	var aID string
	for _, x := range out["cases"].([]any) {
		m := x.(map[string]any)
		if m["name"] == "甲案" {
			aID = m["id"].(string)
		}
	}
	code, out := e.do(t, "DELETE", "/api/cases/"+aID, map[string]any{"name": "甲案"})
	if code != http.StatusOK {
		t.Fatalf("删甲案应 200,得 %d: %v", code, out)
	}
	if out["vault_kept"].(float64) != 1 || out["vault_removed"].(float64) != 0 {
		t.Fatalf("共享原件应保留: %v", out)
	}
	if !e.srv.deps.Vault.Exists(sum) {
		t.Fatal("乙案还引用该哈希,vault 原件不应删")
	}
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
