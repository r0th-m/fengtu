// 切片七焊死:list_sources 分页(大案件预算实坑修复)+ 会话主机范围闸
// (worker host_scope 的系统级限定,不靠模型自觉)。
package agentloop

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ye-mengwen/fengtu/internal/ingest/store"
	"github.com/ye-mengwen/fengtu/internal/operator"
	"github.com/ye-mengwen/fengtu/internal/review"
)

// TestListSourcesPagination 分页契约:limit/offset/total;越界 offset 钳制;
// 默认 100 上限 500。

// trunc 输出截断(短输出不炸)。
func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func TestListSourcesPagination(t *testing.T) {
	svc, meta, _, _, _ := testService(t, &mockProvider{})
	// 合成 250 源(足够翻页,又不至于拖慢)
	for i := 0; i < 250; i++ {
		meta.sources = append(meta.sources, store.Source{
			ID: fmt.Sprintf("src-%03d", i), CaseID: "case-1",
			Path: fmt.Sprintf("dir/f%03d.log", i), Kind: "text",
			LogType: "web_access", DetectStatus: "auto"})
	}
	sess := newSess(t, svc)
	ls := findTool(t, svc.buildTools(sess, ResolvedConfig{}), "list_sources")

	res := callTool(t, ls, `{}`)
	if res.IsError || !strings.Contains(res.Flatten(), `"total":250`) ||
		!strings.Contains(res.Flatten(), `"count":100`) {
		t.Fatalf("默认分页不符(应 total=250 count=100): %s", trunc(res.Flatten(), 300))
	}
	res = callTool(t, ls, `{"limit":200,"offset":100}`)
	if res.IsError || !strings.Contains(res.Flatten(), `"count":150`) {
		t.Fatalf("第二页不符(应 count=150): %s", trunc(res.Flatten(), 300))
	}
	res = callTool(t, ls, `{"limit":9999}`) // 超上限钳到 300
	if res.IsError || !strings.Contains(res.Flatten(), `"limit":300`) {
		t.Fatalf("limit 钳制不符: %s", trunc(res.Flatten(), 300))
	}
	res = callTool(t, ls, `{"offset":-1}`)
	if !res.IsError {
		t.Fatal("负 offset 应报错")
	}
	res = callTool(t, ls, `{"offset":9999}`) // 越界钳到 total,空页如实
	if res.IsError || !strings.Contains(res.Flatten(), `"count":0`) {
		t.Fatalf("越界 offset 应给空页: %s", trunc(res.Flatten(), 300))
	}
}

// TestHostScopeGate 会话主机范围闸:六个工具全部限定该主机源集合
// (list_sources 只列该主机;view_lines 越界拒;list_hits 只给该主机源的候选;
// run_operator 只路由该主机源且账上记 skipped_host_scope)。
func TestHostScopeGate(t *testing.T) {
	svc, meta, _, rs, _ := testService(t, &mockProvider{})
	ops, err := operator.LoadDir(opsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	svc.deps.Ops = ops
	rs.scanSrcs = []review.ScanSource{
		{ID: "s-h1", Kind: "evtx", LogType: "windows_event_log", Host: "10.0.0.1"},
		{ID: "s-h2", Kind: "evtx", LogType: "windows_event_log", Host: "10.0.0.2"},
	}
	meta.sources = append(meta.sources,
		store.Source{ID: "s-h1", CaseID: "case-1", Path: "h1/a.log", Kind: "text",
			LogType: "web_access", Host: "10.0.0.1", DetectStatus: "auto"},
		store.Source{ID: "s-h2", CaseID: "case-1", Path: "h2/b.log", Kind: "text",
			LogType: "web_access", Host: "10.0.0.2", DetectStatus: "auto"})
	rs.hits = append(rs.hits,
		review.Hit{ID: "h-1", CaseID: "case-1", SourceID: "s-h1", LineNo: 1,
			RuleID: "r1", Status: "pending", EvidenceGrade: "suspect"},
		review.Hit{ID: "h-2", CaseID: "case-1", SourceID: "s-h2", LineNo: 1,
			RuleID: "r1", Status: "pending", EvidenceGrade: "suspect"})

	// 绑主机 10.0.0.1 的 worker 会话
	sess, err := svc.CreateSessionBudget(t.Context(), "case-1", "worker:test", 50000, "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	tools := svc.buildTools(sess, ResolvedConfig{})

	res := callTool(t, findTool(t, tools, "list_sources"), `{}`)
	if res.IsError || !strings.Contains(res.Flatten(), `"total":1`) ||
		!strings.Contains(res.Flatten(), "s-h1") || strings.Contains(res.Flatten(), "s-h2") {
		t.Fatalf("主机范围 list_sources 不符: %s", trunc(res.Flatten(), 300))
	}
	res = callTool(t, findTool(t, tools, "view_lines"),
		`{"source_id":"s-h2","from":1,"to":2}`)
	if !res.IsError || !strings.Contains(res.Flatten(), "主机范围") {
		t.Fatalf("越界回查应被拒: %s", trunc(res.Flatten(), 300))
	}
	res = callTool(t, findTool(t, tools, "list_hits"), `{"status":"pending"}`)
	if res.IsError || !strings.Contains(res.Flatten(), "h-1") ||
		strings.Contains(res.Flatten(), "h-2") {
		t.Fatalf("主机范围 list_hits 不符: %s", trunc(res.Flatten(), 300))
	}
	res = callTool(t, findTool(t, tools, "run_operator"),
		`{"name":"host-auth-chain"}`)
	if res.IsError || !strings.Contains(res.Flatten(), `"matched_sources":1`) ||
		!strings.Contains(res.Flatten(), `"skipped_host_scope":1`) {
		t.Fatalf("主机范围 run_operator 不符: %s", trunc(res.Flatten(), 300))
	}

	// 对照:不绑主机的会话两源全见
	sess2 := newSess(t, svc)
	res = callTool(t, findTool(t, svc.buildTools(sess2, ResolvedConfig{}), "list_sources"), `{}`)
	if res.IsError || !strings.Contains(res.Flatten(), `"total":2`) {
		t.Fatalf("无主机范围会话应见全部源: %s", trunc(res.Flatten(), 300))
	}
}
