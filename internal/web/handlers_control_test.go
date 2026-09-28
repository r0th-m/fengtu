// 运行中操控端点契约测试(交互改造切片三,设计 §3):
// steer 纠偏(200/400/404/409)/add_hint 线索(201/400/404)/操作约束
// CRUD(增删查+幂等+幽灵删除 404)/未装配 503/未登录 401。
package web

import (
	"net/http"
	"testing"

	"github.com/ye-mengwen/fengtu/internal/intent"
)

func TestControlEndpoints(t *testing.T) {
	e := newTestEnv(t)
	fi := newFakeIntent()
	e.srv.deps.Intent = fi
	e.login(t)
	tid := e.uploadFile(t, "control-case", "a.log",
		[]byte("10.0.0.1 - - [01/Jan/2024:00:00:00 +0000] \"GET / HTTP/1.1\" 200 1\n"), "")
	e.waitTask(t, tid)
	_, out := e.do(t, "GET", "/api/cases", nil)
	caseID := out["cases"].([]any)[0].(map[string]any)["id"].(string)

	// ---- steer 纠偏 ----
	fi.nodes["run-1"] = &intent.Node{ID: "run-1", CaseID: caseID,
		Kind: intent.KindIntent, Text: "在跑意图", Status: intent.StatusRunning,
		CreatedBy: intent.ByHuman, Scope: intent.ScopeCase}
	code, out := e.do(t, "POST", "/api/intents/run-1/steer",
		map[string]any{"text": "先查持久化"})
	if code != 200 || len(fi.steered) != 1 {
		t.Fatalf("纠偏失败: %d %v steered=%v", code, out, fi.steered)
	}
	code, _ = e.do(t, "POST", "/api/intents/run-1/steer", map[string]any{"text": " "})
	if code != http.StatusBadRequest {
		t.Fatalf("空纠偏应 400: %d", code)
	}
	code, _ = e.do(t, "POST", "/api/intents/ghost/steer", map[string]any{"text": "x"})
	if code != http.StatusNotFound {
		t.Fatalf("幽灵意图纠偏应 404: %d", code)
	}
	fi.nodes["done-1"] = &intent.Node{ID: "done-1", CaseID: caseID,
		Kind: intent.KindIntent, Text: "已收官", Status: intent.StatusSupported,
		CreatedBy: intent.ByAI, Scope: intent.ScopeCase}
	code, _ = e.do(t, "POST", "/api/intents/done-1/steer", map[string]any{"text": "x"})
	if code != http.StatusConflict {
		t.Fatalf("非在跑纠偏应 409: %d", code)
	}

	// ---- add_hint 线索 ----
	code, out = e.do(t, "POST", "/api/cases/"+caseID+"/hints",
		map[string]any{"text": "客户说 20:00 断网"})
	if code != http.StatusCreated {
		t.Fatalf("补线索失败: %d %v", code, out)
	}
	if out["node"].(map[string]any)["kind"] != intent.KindHint {
		t.Fatalf("应建 hint 节点: %v", out["node"])
	}
	code, _ = e.do(t, "POST", "/api/cases/"+caseID+"/hints", map[string]any{"text": ""})
	if code != http.StatusBadRequest {
		t.Fatalf("空线索应 400: %d", code)
	}
	code, _ = e.do(t, "POST", "/api/cases/nope/hints", map[string]any{"text": "x"})
	if code != http.StatusNotFound {
		t.Fatalf("无此案件补线索应 404: %d", code)
	}

	// ---- 操作约束 CRUD ----
	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/constraints", nil)
	if code != 200 {
		t.Fatalf("约束清单失败: %d %v", code, out)
	}
	if _, isArr := out["constraints"].([]any); !isArr {
		t.Fatalf("空清单应回 [] 不回 null: %v", out)
	}
	code, out = e.do(t, "POST", "/api/cases/"+caseID+"/constraints",
		map[string]any{"text": "生产库只读"})
	if code != http.StatusCreated {
		t.Fatalf("加约束失败: %d %v", code, out)
	}
	cid := out["constraint"].(map[string]any)["id"].(string)
	// 幂等:同文本重复加 → 同 id,清单仍 1 条
	code, out = e.do(t, "POST", "/api/cases/"+caseID+"/constraints",
		map[string]any{"text": "生产库只读"})
	if code != http.StatusCreated ||
		out["constraint"].(map[string]any)["id"].(string) != cid {
		t.Fatalf("同文本约束应幂等: %d %v", code, out)
	}
	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/constraints", nil)
	if code != 200 || len(out["constraints"].([]any)) != 1 {
		t.Fatalf("约束清单应为 1 条: %d %v", code, out)
	}
	code, _ = e.do(t, "POST", "/api/cases/"+caseID+"/constraints",
		map[string]any{"text": ""})
	if code != http.StatusBadRequest {
		t.Fatalf("空约束应 400: %d", code)
	}
	code, _ = e.do(t, "DELETE", "/api/cases/"+caseID+"/constraints/"+cid, nil)
	if code != 200 {
		t.Fatalf("删约束失败: %d", code)
	}
	code, _ = e.do(t, "DELETE", "/api/cases/"+caseID+"/constraints/"+cid, nil)
	if code != http.StatusNotFound {
		t.Fatalf("幽灵删除应 404: %d", code)
	}
}

// TestControlNotAssembled 引擎未装配:新端点一律 503 如实,不崩。
func TestControlNotAssembled(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	code, _ := e.do(t, "GET", "/api/cases/case-1/constraints", nil)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("约束清单未装配应 503: %d", code)
	}
	code, _ = e.do(t, "POST", "/api/cases/case-1/hints", map[string]any{"text": "x"})
	if code != http.StatusServiceUnavailable {
		t.Fatalf("补线索未装配应 503: %d", code)
	}
	code, _ = e.do(t, "POST", "/api/intents/n1/steer", map[string]any{"text": "x"})
	if code != http.StatusServiceUnavailable {
		t.Fatalf("纠偏未装配应 503: %d", code)
	}
	code, _ = e.do(t, "DELETE", "/api/cases/case-1/constraints/c-1", nil)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("删约束未装配应 503: %d", code)
	}
}
