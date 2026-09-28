// 平台页端点契约测试(切片十):总览统计/LLM 录制/日志/全局审批。
// 纪律与全仓一致:零 AI 调用(录制账由 fake 直塞,不跑 agentloop);
// 只读端点不落账;503/404 如实。工作空间文件管理器契约见
// handlers_workspace_test.go(切片十一)。
package web

import (
	"net/http"
	"testing"
	"time"

	"github.com/ye-mengwen/fengtu/internal/ingest/store"
	"github.com/ye-mengwen/fengtu/internal/intent"
	"github.com/ye-mengwen/fengtu/internal/logbuf"
)

func TestStatsOverview(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	taskID := e.uploadFileTZ(t, "勒索案A", "access.log", []byte(nginxContent),
		"nginx_combined", "+0000")
	if task := e.waitTask(t, taskID); task["status"] != "done" {
		t.Fatalf("摄入任务应 done: %v", task)
	}

	code, body := e.do(t, "GET", "/api/stats/overview", nil)
	if code != http.StatusOK {
		t.Fatalf("总览状态码: %d %v", code, body)
	}
	stats := body["stats"].(map[string]any)
	if stats["cases"].(float64) != 1 || stats["sources"].(float64) != 1 {
		t.Fatalf("总览计数不符: %v", stats)
	}
	cs := body["case_status"].(map[string]any)
	if cs["ingested"].(float64) != 1 { // 有源无候选 = 已摄入桶
		t.Fatalf("案件状态分布不符: %v", cs)
	}
	if _, ok := stats["activity"].([]any); !ok {
		t.Fatalf("activity 缺失: %v", stats)
	}
}

func TestLLMRecords(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	e.meta.llmRecords = []store.LLMRecord{
		{ID: "r1", SessionID: "s1", CaseID: "c1", Kind: "chat", Model: "m1",
			Status: "ok", TokensIn: 10, TokensOut: 20, DurationMs: 300,
			CreatedAt: time.Now()},
		{ID: "r2", SessionID: "s2", CaseID: "c2", Kind: "intent", Model: "m1",
			Status: "error", Err: "boom", CreatedAt: time.Now()},
	}

	code, body := e.do(t, "GET", "/api/llm/records", nil)
	if code != http.StatusOK {
		t.Fatalf("录制清单状态码: %d %v", code, body)
	}
	if body["total"].(float64) != 2 {
		t.Fatalf("录制总数不符: %v", body)
	}
	if len(body["records"].([]any)) != 2 {
		t.Fatalf("录制条数不符: %v", body)
	}

	// 案件过滤
	_, body = e.do(t, "GET", "/api/llm/records?case_id=c1", nil)
	if body["total"].(float64) != 1 {
		t.Fatalf("案件过滤不符: %v", body)
	}

	// 详情 + 404 如实
	code, body = e.do(t, "GET", "/api/llm/records/r2", nil)
	if code != http.StatusOK {
		t.Fatalf("录制详情状态码: %d %v", code, body)
	}
	rec := body["record"].(map[string]any)
	if rec["status"] != "error" || rec["err"] != "boom" {
		t.Fatalf("录制详情不符: %v", rec)
	}
	if _, has := rec["prompt"]; has {
		t.Fatalf("元数据档不该有 prompt 字段: %v", rec)
	}
	code, _ = e.do(t, "GET", "/api/llm/records/nope", nil)
	if code != http.StatusNotFound {
		t.Fatalf("无此记录应 404: %d", code)
	}
}

func TestLogsTail(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)

	// 未装配 → 503 如实
	code, _ := e.do(t, "GET", "/api/logs", nil)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("未装配应 503: %d", code)
	}

	buf := logbuf.New(10)
	buf.Add("第一行")
	buf.Add("第二行 error 失败样例")
	e.srv.deps.Logs = buf
	code, body := e.do(t, "GET", "/api/logs?limit=10", nil)
	if code != http.StatusOK {
		t.Fatalf("日志状态码: %d %v", code, body)
	}
	entries := body["entries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("日志条数不符: %v", entries)
	}
	// before 游标翻更早
	first := entries[0].(map[string]any)
	_, body = e.do(t, "GET", "/api/logs?before=2", nil)
	if len(body["entries"].([]any)) != 1 {
		t.Fatalf("before 翻页不符: %v", body)
	}
	_ = first
}

func TestApprovalsGlobal(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	e.meta.awaiting = []*intent.Node{
		{ID: "n1", CaseID: "", Kind: "intent", Text: "批量扫描全部源",
			Status: "awaiting_approval", CreatedBy: "ai", Scope: "all",
			CreatedAt: time.Now()},
	}
	// 审批历史来自审计链(fake 内存链,追加一条批准)
	if _, _, err := e.audit.AppendAudit(t.Context(), "", "admin",
		"intent.approve", "n0", map[string]any{"text": "历史意图"}); err != nil {
		t.Fatal(err)
	}
	// 非审批动作不该进历史
	if _, _, err := e.audit.AppendAudit(t.Context(), "", "admin",
		"case.create", "x", nil); err != nil {
		t.Fatal(err)
	}

	code, body := e.do(t, "GET", "/api/approvals", nil)
	if code != http.StatusOK {
		t.Fatalf("审批记录状态码: %d %v", code, body)
	}
	pending := body["pending"].([]any)
	if len(pending) != 1 || pending[0].(map[string]any)["text"] != "批量扫描全部源" {
		t.Fatalf("待批清单不符: %v", pending)
	}
	history := body["history"].([]any)
	if len(history) != 1 || history[0].(map[string]any)["action"] != "intent.approve" {
		t.Fatalf("审批历史不符(非审批动作混入或漏): %v", history)
	}
	if history[0].(map[string]any)["text"] != "历史意图" {
		t.Fatalf("审批历史 text 投影不符: %v", history[0])
	}
}
