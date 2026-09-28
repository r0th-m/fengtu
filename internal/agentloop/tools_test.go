// 只读工具集单测:六个工具的参数校验/案件绑定/上限纪律/run_operator
// 落待审区全链(合成数据,文档段 IP+通用名,零案件值)。
package agentloop

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/norma/tool"

	"github.com/ye-mengwen/fengtu/internal/ingest/store"
	"github.com/ye-mengwen/fengtu/internal/operator"
	"github.com/ye-mengwen/fengtu/internal/query"
	"github.com/ye-mengwen/fengtu/internal/review"
)

func callTool(t *testing.T, tl tool.CoreTool, input string) tool.Result {
	t.Helper()
	res, err := tl.Call(context.Background(), json.RawMessage(input), &tool.ToolContext{})
	if err != nil {
		t.Fatalf("工具 %s 调用硬错误: %v", tl.Name(), err)
	}
	return res
}

func findTool(t *testing.T, tools []tool.CoreTool, name string) tool.CoreTool {
	t.Helper()
	for _, tl := range tools {
		if tl.Name() == name {
			return tl
		}
	}
	t.Fatalf("工具未注册: %s", name)
	return nil
}

func newSess(t *testing.T, svc *Service) *store.AISession {
	t.Helper()
	sess, err := svc.CreateSession(context.Background(), "case-1", "tester")
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

func TestSearchEventsTool(t *testing.T) {
	svc, _, events, _, _ := testService(t, &mockProvider{})
	events.rows = []query.Event{{SourceID: "s1", LineNo: 7, Raw: "GET /login 401"}}
	sess := newSess(t, svc)
	tl := findTool(t, svc.buildTools(sess, ResolvedConfig{}), "search_events")

	res := callTool(t, tl, `{"q":"login","cond":["status:eq:401"],"limit":5}`)
	if res.IsError {
		t.Fatalf("search_events 报错: %s", res.Flatten())
	}
	if !strings.Contains(res.Flatten(), "GET /login") {
		t.Fatalf("结果缺事件: %s", res.Flatten())
	}
	// 案件绑定:SQL 参数首个是 case-1(会话案件,模型给不了别的案件)
	if len(events.lastArgs) == 0 || events.lastArgs[0] != "case-1" {
		t.Fatalf("检索未绑定会话案件: %v", events.lastArgs)
	}
	// 负:cond 形态非法 → 错误结果(软错,回给模型)
	res = callTool(t, tl, `{"cond":["bad"]}`)
	if !res.IsError {
		t.Fatal("非法 cond 应报错")
	}
	res = callTool(t, tl, `{"ts_from":"not-a-time"}`)
	if !res.IsError {
		t.Fatal("非法 ts_from 应报错")
	}
}

func TestGetStatsTool(t *testing.T) {
	svc, _, events, _, _ := testService(t, &mockProvider{})
	events.statRows = []query.StatRow{{Key: "401", Count: 42}}
	sess := newSess(t, svc)
	tl := findTool(t, svc.buildTools(sess, ResolvedConfig{}), "get_stats")

	res := callTool(t, tl, `{"group":"status"}`)
	if res.IsError || !strings.Contains(res.Flatten(), "401") {
		t.Fatalf("get_stats 结果不符: %s", res.Flatten())
	}
	res = callTool(t, tl, `{"group":"hour"}`)
	if !res.IsError {
		t.Fatal("非法 group 应报错")
	}
}

// opsDir 写一个已实现 + 一个未实现算子的注册表目录。
func opsDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	authYAML := `
id: host-auth-chain
title: 认证链
family: host
severity: high
applicable_to:
  log_types: [windows_event_log]
params:
  fail_event: 4625
  success_event: 4624
  fail_threshold: 3
  window_seconds: 120
implemented: true
note: 测试
max_hits: 100
`
	treeYAML := `
id: host-process-tree
title: 进程树
family: host
severity: medium
applicable_to:
  log_types: [windows_event_log]
implemented: false
note: 注册未实现
max_hits: 100
`
	for name, y := range map[string]string{
		"host-auth-chain.yaml": authYAML, "host-process-tree.yaml": treeYAML} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(y), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func evtxFields(eid int, account string) string {
	return fmt.Sprintf(`{"event_id":%d,"computer":"WS-01",`+
		`"data":{"TargetUserName":%q,"LogonType":"3","IpAddress":"203.0.113.40"}}`,
		eid, account)
}

func TestRunOperatorTool(t *testing.T) {
	ops, err := operator.LoadDir(opsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	mp := &mockProvider{}
	svc, _, events, rs, _ := testService(t, mp)
	svc.deps.Ops = ops
	sess := newSess(t, svc)
	rs.scanSrcs = []review.ScanSource{
		{ID: "s-evtx", Kind: "evtx", LogType: "windows_event_log"},
		{ID: "s-web", Kind: "text", LogType: "web_access"},
	}
	// 合成:alice 4625×4(10s 间隔)+ 窗口内 4624 → 命中(阈值 3/窗口 120s)
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 1; i <= 4; i++ {
		tsCp := ts.Add(time.Duration(i*10) * time.Second)
		events.rows = append(events.rows, query.Event{
			SourceID: "s-evtx", LineNo: i, TS: &tsCp, Kind: "event",
			Fields: evtxFields(4625, "alice"), Raw: "4625 alice"})
	}
	tsCp := ts.Add(50 * time.Second)
	events.rows = append(events.rows, query.Event{
		SourceID: "s-evtx", LineNo: 9, TS: &tsCp, Kind: "event",
		Fields: evtxFields(4624, "alice"), Raw: "4624 alice"})

	tl := findTool(t, svc.buildTools(sess, ResolvedConfig{}), "run_operator")
	res := callTool(t, tl, `{"name":"host-auth-chain"}`)
	if res.IsError {
		t.Fatalf("run_operator 报错: %s", res.Flatten())
	}
	flat := res.Flatten()
	if !strings.Contains(flat, `"hits_new":1`) {
		t.Fatalf("应新增 1 条候选: %s", flat)
	}
	// 落待审区:pending + 轮次账 actor 锚「真人 via AI」+ 证据等级系统算
	if len(rs.hits) != 1 || rs.hits[0].Status != "pending" {
		t.Fatalf("候选应 pending 落待审区: %+v", rs.hits)
	}
	if rs.hits[0].CaseID != "case-1" || rs.hits[0].SourceID != "s-evtx" {
		t.Fatalf("候选锚点不符: %+v", rs.hits[0])
	}
	if len(rs.runs) != 1 || rs.runs[0] != "ai:tester" {
		t.Fatalf("轮次账 actor 不符: %v", rs.runs)
	}
	// 幂等:重跑同算子 → hits_dup
	res = callTool(t, tl, `{"name":"host-auth-chain"}`)
	if !strings.Contains(res.Flatten(), `"hits_dup":1`) {
		t.Fatalf("重跑应去重: %s", res.Flatten())
	}
	// 负:未知算子 / 未实现算子 / 适用域外单源
	res = callTool(t, tl, `{"name":"no-such-op"}`)
	if !res.IsError || !strings.Contains(res.Flatten(), "未知算子") {
		t.Fatalf("未知算子应如实报: %s", res.Flatten())
	}
	res = callTool(t, tl, `{"name":"host-process-tree"}`)
	if !res.IsError || !strings.Contains(res.Flatten(), "未实现") {
		t.Fatalf("未实现算子应如实报: %s", res.Flatten())
	}
	res = callTool(t, tl, `{"name":"host-auth-chain","source_id":"s-web"}`)
	if res.IsError || !strings.Contains(res.Flatten(), "适用域内无源") {
		t.Fatalf("适用域外单源应如实报: %s", res.Flatten())
	}
	// 未声明的覆盖键不生效且如实回执(不静默吞键);声明键正常覆盖
	res = callTool(t, tl,
		`{"name":"host-auth-chain","params":{"window_sec":1,"fail_threshold":3}}`)
	flat = res.Flatten()
	if res.IsError || !strings.Contains(flat, `"ignored_params":["window_sec"]`) {
		t.Fatalf("未声明键应进 ignored_params: %s", flat)
	}
	if !strings.Contains(flat, "window_seconds") {
		t.Fatalf("回执应带可覆盖键清单: %s", flat)
	}
}

func TestViewLinesTool(t *testing.T) {
	svc, meta, _, _, _ := testService(t, &mockProvider{})
	content := []byte("line1\nline2\nline3\nline4\nline5")
	sumBytes := sha256.Sum256(content)
	sum := hex.EncodeToString(sumBytes[:])
	if _, err := svc.deps.Vault.Put(sum, strings.NewReader(string(content))); err != nil {
		t.Fatal(err)
	}
	meta.sources = append(meta.sources, store.Source{
		ID: "s-text", CaseID: "case-1", Path: "auth.log", SHA256: sum, Kind: "text"})
	meta.sources = append(meta.sources, store.Source{
		ID: "s-evtx", CaseID: "case-1", Path: "Sec.evtx", SHA256: "x", Kind: "evtx"})
	meta.sources = append(meta.sources, store.Source{
		ID: "s-other-case", CaseID: "case-2", Path: "x.log", SHA256: sum, Kind: "text"})
	sess := newSess(t, svc)
	tl := findTool(t, svc.buildTools(sess, ResolvedConfig{}), "view_lines")

	res := callTool(t, tl, `{"source_id":"s-text","from":2,"to":4}`)
	if res.IsError || !strings.Contains(res.Flatten(), "line3") {
		t.Fatalf("回查不符: %s", res.Flatten())
	}
	// 上限纪律:单次 ≤200 行
	res = callTool(t, tl, `{"source_id":"s-text","from":1,"to":300}`)
	if !res.IsError || !strings.Contains(res.Flatten(), "200") {
		t.Fatalf("超 200 行应拒: %s", res.Flatten())
	}
	// 非文本源 / 他案件源 如实拒
	res = callTool(t, tl, `{"source_id":"s-evtx","from":1,"to":2}`)
	if !res.IsError {
		t.Fatal("evtx 源行号回查应拒")
	}
	res = callTool(t, tl, `{"source_id":"s-other-case","from":1,"to":2}`)
	if !res.IsError {
		t.Fatal("他案件源应拒(越权)")
	}
	// raw 兜底源内容嗅探(2026-09-23 通用缺陷修复):文本放行,二进制拒
	binContent := []byte{0x4D, 0x5A, 0x90, 0x00, 0x03}
	binSumBytes := sha256.Sum256(binContent)
	binSum := hex.EncodeToString(binSumBytes[:])
	if _, err := svc.deps.Vault.Put(binSum, strings.NewReader(string(binContent))); err != nil {
		t.Fatal(err)
	}
	meta.sources = append(meta.sources, store.Source{
		ID: "s-rawtext", CaseID: "case-1", Path: "1DZIY8ISYNMJ6M0Z580.readme",
		SHA256: sum, Kind: "raw"})
	meta.sources = append(meta.sources, store.Source{
		ID: "s-rawbin", CaseID: "case-1", Path: "payload.enc",
		SHA256: binSum, Kind: "raw"})
	res = callTool(t, tl, `{"source_id":"s-rawtext","from":2,"to":4}`)
	if res.IsError || !strings.Contains(res.Flatten(), "line3") {
		t.Fatalf("raw 文本源嗅探后应可回查: %s", res.Flatten())
	}
	res = callTool(t, tl, `{"source_id":"s-rawbin","from":1,"to":2}`)
	if !res.IsError || !strings.Contains(res.Flatten(), "二进制") {
		t.Fatalf("raw 二进制源应如实拒: %s", res.Flatten())
	}
}

func TestListSourcesAndHitsTools(t *testing.T) {
	svc, meta, _, rs, _ := testService(t, &mockProvider{})
	meta.sources = append(meta.sources,
		store.Source{ID: "s1", CaseID: "case-1", Path: "a.log", Kind: "text",
			LogType: "web_access", DetectStatus: "auto"})
	rs.hits = append(rs.hits, review.Hit{
		ID: "h1", CaseID: "case-1", SourceID: "s1", LineNo: 3,
		RuleID: "r1", Status: "pending", EvidenceGrade: "suspect"})
	sess := newSess(t, svc)
	tools := svc.buildTools(sess, ResolvedConfig{})

	res := callTool(t, findTool(t, tools, "list_sources"), `{}`)
	if res.IsError || !strings.Contains(res.Flatten(), "a.log") {
		t.Fatalf("list_sources 不符: %s", res.Flatten())
	}
	res = callTool(t, findTool(t, tools, "list_hits"), `{"status":"pending"}`)
	if res.IsError || !strings.Contains(res.Flatten(), "h1") {
		t.Fatalf("list_hits 不符: %s", res.Flatten())
	}
	res = callTool(t, findTool(t, tools, "list_hits"), `{"status":"bogus"}`)
	if !res.IsError {
		t.Fatal("非法 status 应报错")
	}
}

// TestSchemaNoNullRequired required 空时键必须省略(nil 切片序列化成 null,
// DeepSeek 按 JSON Schema 严校直接 400——台架实测坑,焊死)。
func TestSchemaNoNullRequired(t *testing.T) {
	s := objSchema(map[string]any{})
	if _, has := s["required"]; has {
		t.Fatal("required 为空时键必须省略(null 会被严校厂商拒)")
	}
	s = objSchema(map[string]any{}, "name")
	if req, ok := s["required"].([]string); !ok || len(req) != 1 {
		t.Fatalf("required 非空应在: %v", s["required"])
	}
	for _, tl := range []string{"search_events", "get_stats", "run_operator",
		"view_lines", "list_sources", "list_hits"} {
		svc, _, _, _, _ := testService(t, &mockProvider{})
		sess := newSess(t, svc)
		tool_ := findTool(t, svc.buildTools(sess, ResolvedConfig{}), tl)
		if v, has := tool_.InputSchema()["required"]; has && v == nil {
			t.Fatalf("%s schema required 为 null", tl)
		}
	}
}
