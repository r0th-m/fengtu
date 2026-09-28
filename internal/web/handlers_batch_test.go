// 批量端点测试(0.29.0-batch-ops):批量裁决/批量停车场处置——
// 全成功/部分 409 如实跳过/空 ids 400/非法档位 400/逐条审计(与单条同构)。
// 判断权归人:批量也是人逐批拍板,无自动裁决;不装全成。
package web

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ye-mengwen/fengtu/internal/intent"
	"github.com/ye-mengwen/fengtu/internal/review"
)

// seedHits 喂 n 条 pending 候选(行号从 lineBase 起,避开 fake 去重键),
// 返回 id 清单。
func seedHits(t *testing.T, e *testEnv, caseID, srcID string, lineBase, n int) []string {
	t.Helper()
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		h := review.Hit{CaseID: caseID, SourceID: srcID, LineNo: lineBase + i,
			RuleID: "rule-batch", Severity: "medium", Status: "pending",
			EvidenceGrade: "suspect"}
		inserted, err := e.review.InsertHit(context.Background(), h, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if !inserted {
			t.Fatalf("候选被去重(行号撞): line=%d", lineBase+i)
		}
		ids = append(ids, e.review.hits[len(e.review.hits)-1].ID)
	}
	return ids
}

// TestBatchVerdict 批量裁决:全成功 + 逐条审计;已被裁决的如实 409 跳过;
// 不存在的如实报;空 ids/非法状态 400。
func TestBatchVerdict(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	tid := e.uploadFile(t, "batch-verdict-case", "a.log", []byte(nginxContent), "")
	e.waitTask(t, tid)
	_, out := e.do(t, "GET", "/api/cases", nil)
	caseID := out["cases"].([]any)[0].(map[string]any)["id"].(string)
	code, out := e.do(t, "GET", "/api/cases/"+caseID, nil)
	if code != 200 {
		t.Fatalf("案件详情失败: %d", code)
	}
	srcID := out["sources"].([]any)[0].(map[string]any)["id"].(string)

	ids := seedHits(t, e, caseID, srcID, 1, 3)
	// 先单条裁决第一条 → 批量里它应被如实跳过(409 语义)
	code, _ = e.do(t, "POST", "/api/hits/"+ids[0]+"/verdict",
		map[string]string{"status": "accepted"})
	if code != 200 {
		t.Fatalf("预裁决失败: %d", code)
	}

	// 批量:[已裁决, pending, pending, 不存在] → 2 成 2 跳
	code, out = e.do(t, "POST", "/api/hits/batch-verdict", map[string]any{
		"ids": []string{ids[0], ids[1], ids[2], "no-such"}, "status": "rejected",
	})
	if code != 200 {
		t.Fatalf("批量裁决应 200(逐条如实,不整批拒): %d %v", code, out)
	}
	if out["total"].(float64) != 4 || out["done"].(float64) != 2 ||
		out["skipped"].(float64) != 2 {
		t.Fatalf("计数不符: %v", out)
	}
	results := out["results"].([]any)
	if len(results) != 4 {
		t.Fatalf("应逐条回 4 条结果: %v", results)
	}
	r0 := results[0].(map[string]any)
	if r0["ok"] == true || r0["error"] == nil {
		t.Fatalf("已被裁决条应 ok=false 带原因: %v", r0)
	}
	r3 := results[3].(map[string]any)
	if r3["ok"] == true || r3["error"] == nil {
		t.Fatalf("不存在条应 ok=false 带原因: %v", r3)
	}
	for _, i := range []int{1, 2} {
		if results[i].(map[string]any)["ok"] != true {
			t.Fatalf("pending 条应成功: %v", results[i])
		}
	}
	// 落库口径:两条 rejected,预裁决那条保持 accepted
	st := map[string]string{}
	for _, h := range e.review.hits {
		st[h.ID] = h.Status
	}
	if st[ids[0]] != "accepted" || st[ids[1]] != "rejected" || st[ids[2]] != "rejected" {
		t.Fatalf("落库状态不符: %v", st)
	}

	// 审计:hit.verdict 逐条落(单条 1 + 批量 2 = 3),批量的带 batch 标
	cnt := 0
	batchMarked := 0
	for _, en := range e.audit.entries {
		if en.Action == "hit.verdict" {
			cnt++
			if strings.Contains(en.DetailJSON, "\"batch\":true") {
				batchMarked++
			}
		}
	}
	if cnt != 3 || batchMarked != 2 {
		t.Fatalf("审计应 3 条 hit.verdict(批量 2 条带 batch 标): cnt=%d batch=%d",
			cnt, batchMarked)
	}

	// 空 ids 400;非法状态 400;verdict 别名兼容
	code, _ = e.do(t, "POST", "/api/hits/batch-verdict",
		map[string]any{"ids": []string{}, "status": "accepted"})
	if code != http.StatusBadRequest {
		t.Fatalf("空 ids 应 400: %d", code)
	}
	code, _ = e.do(t, "POST", "/api/hits/batch-verdict",
		map[string]any{"ids": ids, "status": "pending"})
	if code != http.StatusBadRequest {
		t.Fatalf("非法状态应 400: %d", code)
	}
	more := seedHits(t, e, caseID, srcID, 100, 1)
	code, out = e.do(t, "POST", "/api/hits/batch-verdict",
		map[string]any{"ids": more, "verdict": "accepted"})
	if code != 200 || out["done"].(float64) != 1 {
		t.Fatalf("verdict 别名应可用: %d %v", code, out)
	}
}

// TestParkingBatch 批量停车场处置:deploy/dismiss 逐条同单条语义;
// 已处置的如实跳过;空 ids/非法 action 400。
func TestParkingBatch(t *testing.T) {
	e := newTestEnv(t)
	fi := newFakeIntent()
	e.srv.deps.Intent = fi
	e.login(t)
	tid := e.uploadFile(t, "batch-parking-case", "a.log", []byte(nginxContent), "")
	e.waitTask(t, tid)
	_, out := e.do(t, "GET", "/api/cases", nil)
	caseID := out["cases"].([]any)[0].(map[string]any)["id"].(string)

	mkParked := func(id string) {
		fi.nodes["n-"+id] = &intent.Node{ID: "n-" + id, CaseID: caseID,
			Kind: intent.KindIntent, Text: "线索 " + id, Status: intent.StatusParked,
			CreatedBy: intent.ByAI, Scope: intent.ScopeCase, CreatedAt: time.Now()}
		fi.parking = append(fi.parking, &intent.ParkingEntry{
			ID: id, CaseID: caseID, NodeID: "n-" + id, Text: "线索 " + id,
			Reason: intent.ParkReasonFanout, SuggestGoalID: "g-1", SuggestLabel: "章一",
			Status: intent.ParkingParked, CreatedBy: "ai", CreatedAt: time.Now()})
	}
	mkParked("pb-1")
	mkParked("pb-2")
	mkParked("pb-3")

	// 批量 deploy:[parked, parked, 不存在] → 2 成 1 跳
	code, out := e.do(t, "POST", "/api/parking/batch", map[string]any{
		"ids": []string{"pb-1", "pb-2", "nope"}, "action": "deploy",
	})
	if code != 200 {
		t.Fatalf("批量 deploy 应 200: %d %v", code, out)
	}
	if out["total"].(float64) != 3 || out["done"].(float64) != 2 ||
		out["skipped"].(float64) != 1 {
		t.Fatalf("计数不符: %v", out)
	}
	if fi.nodes["n-pb-1"].Status != intent.StatusOpen ||
		fi.nodes["n-pb-2"].Status != intent.StatusOpen {
		t.Fatalf("deploy 后节点应 open: %s %s",
			fi.nodes["n-pb-1"].Status, fi.nodes["n-pb-2"].Status)
	}
	// 已处置的再批量 dismiss:如实跳过
	code, out = e.do(t, "POST", "/api/parking/batch", map[string]any{
		"ids": []string{"pb-1", "pb-3"}, "action": "dismiss",
	})
	if code != 200 || out["done"].(float64) != 1 || out["skipped"].(float64) != 1 {
		t.Fatalf("已处置应如实跳过: %d %v", code, out)
	}
	results := out["results"].([]any)
	if results[0].(map[string]any)["ok"] == true {
		t.Fatalf("已 deploy 的 pb-1 dismiss 应失败: %v", results[0])
	}
	if fi.nodes["n-pb-3"].Status != intent.StatusClosed {
		t.Fatalf("dismiss 后节点应 closed: %s", fi.nodes["n-pb-3"].Status)
	}

	// 空 ids 400;非法 action 400
	code, _ = e.do(t, "POST", "/api/parking/batch",
		map[string]any{"ids": []string{}, "action": "deploy"})
	if code != http.StatusBadRequest {
		t.Fatalf("空 ids 应 400: %d", code)
	}
	code, _ = e.do(t, "POST", "/api/parking/batch",
		map[string]any{"ids": []string{"pb-3"}, "action": "explode"})
	if code != http.StatusBadRequest {
		t.Fatalf("非法 action 应 400: %d", code)
	}
}
