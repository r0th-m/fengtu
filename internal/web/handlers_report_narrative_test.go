// 研判报告端点契约测试(0.31.0-narrative-report;fake AIFace + fakeIntent):
// 生成(版本递增/token 账/审计 report.generate)/归档 409/预算钳制与熔断截断/
// 零产出 502 不落库/外发关 403/未装配 503/版本清单与详情/grounding 组装单测
// (纯函数:章节/锚点格式/doubt/截断标)。
package web

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ye-mengwen/fengtu/internal/agentloop"
	"github.com/ye-mengwen/fengtu/internal/ingest/store"
	"github.com/ye-mengwen/fengtu/internal/intent"
	"github.com/ye-mengwen/fengtu/internal/review"
)

// narrativeCase 造一个有发现+意图图的测试案(上传 nginx 日志→扫描→裁决
// accepted;fakeIntent 注入 goal/fact/doubt 三节点)。返回 caseID。
func narrativeCase(t *testing.T, e *testEnv) string {
	t.Helper()
	taskID := e.uploadFileTZ(t, "case-narrative", "access.log",
		[]byte(nginxContent), "nginx_combined", "+0000")
	if task := e.waitTask(t, taskID); task["status"] != "done" {
		t.Fatalf("摄入应 done: %v", task)
	}
	var caseID string
	for name, id := range e.meta.cases {
		if name == "case-narrative" {
			caseID = id
		}
	}
	if caseID == "" {
		t.Fatal("案件未登记")
	}
	code, out := e.do(t, "POST", "/api/cases/"+caseID+"/scans", map[string]any{})
	if code != http.StatusAccepted {
		t.Fatalf("扫描启动失败: %d %v", code, out)
	}
	if task := e.waitTask(t, out["task_id"].(string)); task["status"] != "done" {
		t.Fatalf("扫描应 done: %v", task)
	}
	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/hits?status=pending", nil)
	if code != http.StatusOK {
		t.Fatalf("待审查询失败: %d", code)
	}
	hits := out["hits"].([]any)
	if len(hits) == 0 {
		t.Fatal("应有命中候选")
	}
	hitID := hits[0].(map[string]any)["id"].(string)
	code, out = e.do(t, "POST", "/api/hits/"+hitID+"/verdict",
		map[string]string{"status": "accepted", "note": "实锤"})
	if code != http.StatusOK {
		t.Fatalf("裁决失败: %d %v", code, out)
	}
	srcID := hits[0].(map[string]any)["source_id"].(string)

	fi := newFakeIntent()
	fi.nodes["g1"] = &intent.Node{ID: "g1", CaseID: caseID, Kind: intent.KindGoal,
		Text: "确认入侵入口", Status: intent.StatusClosedGoalMet,
		CreatedBy: intent.ByHuman, Scope: intent.ScopeCase}
	fi.nodes["f1"] = &intent.Node{ID: "f1", CaseID: caseID, Kind: intent.KindFact,
		Text: "存在扫描器 UA 集中访问", Status: intent.StatusSupported,
		ParentID: "g1", CreatedBy: intent.ByAI, Scope: intent.ScopeCase,
		Evidence: []intent.Anchor{{SourceID: srcID, LineNo: 2}}}
	fi.nodes["d1"] = &intent.Node{ID: "d1", CaseID: caseID, Kind: intent.KindIntent,
		Text: "排查后台管理面爆破", Status: intent.StatusDoubt,
		ParentID: "g1", CreatedBy: intent.ByAI, Scope: intent.ScopeCase,
		ResultText: "403 一条,证据不足",
		Evidence:   []intent.Anchor{{SourceID: srcID, LineNo: 3}}}
	e.srv.deps.Intent = fi
	return caseID
}

// narrativeAIOK fake LLM 回稿:流式两段拼出全文;result.Text 只带末段
// (模拟 s37 实锤的 max_tokens 触顶续写场景——终态事件只带最后一段,
// 端点必须优先流式拼接,否则丢开头)。
func narrativeAIOK() *fakeAI {
	ai := newFakeAI()
	ai.events = []agentloop.Event{
		{Kind: "text", Text: "# 研判报告\n\n## 一、结论摘要\n\n1. 存在扫描器访问"},
		{Kind: "text", Text: "(锚点 access.log:2)"},
		{Kind: "result", Text: "(锚点 access.log:2)",
			Reason: "completed", TokensIn: 12000, TokensOut: 3000},
	}
	return ai
}

func TestNarrativeGenerateAndVersions(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	caseID := narrativeCase(t, e)
	ai := narrativeAIOK()
	e.srv.deps.AI = ai

	// 生成 v1(默认预算 30000)
	code, out := e.do(t, "POST", "/api/cases/"+caseID+"/report/narrative", nil)
	if code != http.StatusCreated {
		t.Fatalf("生成失败: %d %v", code, out)
	}
	rep := out["report"].(map[string]any)
	if int(rep["version"].(float64)) != 1 || rep["truncated"].(bool) {
		t.Fatalf("v1 账不符: %v", rep)
	}
	if ai.lastBudget != 30000 {
		t.Fatalf("默认预算应为 30000: %d", ai.lastBudget)
	}
	content := out["content"].(string)
	if !strings.Contains(content, "AI 生成初稿,定论归人") ||
		!strings.Contains(content, "token 消耗 in 12000 / out 3000") {
		t.Fatalf("报告头不符:\n%s", content[:200])
	}
	if !strings.Contains(content, "锚点 access.log:2") ||
		!strings.Contains(content, "存在扫描器访问") {
		t.Fatalf("正文应为流式全文拼接(非 result 末段): %s", content)
	}
	// grounding 组装进 prompt(案件数据唯一来源):章/结论/doubt/锚点齐
	p := ai.lastPrompt
	for _, want := range []string{"【案件数据】", "case-narrative", "确认入侵入口",
		"存在扫描器 UA 集中访问", "排查后台管理面爆破", "403 一条,证据不足",
		"access.log:2", "禁止编造", "推断", "北京时间"} {
		if !strings.Contains(p, want) {
			t.Fatalf("grounding prompt 缺 %q", want)
		}
	}
	// 审计 report.generate 含 token 消耗
	var found bool
	for _, en := range e.audit.entries {
		if en.Action == "report.generate" {
			found = true
			if !strings.Contains(en.DetailJSON, `"tokens_in":12000`) ||
				!strings.Contains(en.DetailJSON, `"version":1`) {
				t.Fatalf("审计 detail 缺 token/版本: %s", en.DetailJSON)
			}
		}
	}
	if !found {
		t.Fatal("缺 report.generate 审计锚点")
	}

	// 生成 v2(版本递增,历史保留)
	code, out = e.do(t, "POST", "/api/cases/"+caseID+"/report/narrative",
		map[string]any{"budget_tokens": 60000})
	if code != http.StatusCreated {
		t.Fatalf("v2 生成失败: %d %v", code, out)
	}
	if int(out["report"].(map[string]any)["version"].(float64)) != 2 {
		t.Fatalf("应 v2: %v", out["report"])
	}
	if ai.lastBudget != 60000 {
		t.Fatalf("可调预算应透传 60000: %d", ai.lastBudget)
	}

	// 版本清单(倒序,content 不随行)
	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/report/narrative", nil)
	if code != http.StatusOK {
		t.Fatalf("清单失败: %d", code)
	}
	reps := out["reports"].([]any)
	if len(reps) != 2 ||
		int(reps[0].(map[string]any)["version"].(float64)) != 2 ||
		int(reps[1].(map[string]any)["version"].(float64)) != 1 {
		t.Fatalf("版本清单不符: %v", reps)
	}
	if _, has := reps[0].(map[string]any)["content"]; has &&
		reps[0].(map[string]any)["content"] != "" {
		t.Fatalf("清单不应带 content: %v", reps[0])
	}

	// 版本详情(内容含报告头)
	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/report/narrative/1", nil)
	if code != http.StatusOK || !strings.Contains(out["content"].(string), "AI 生成初稿") {
		t.Fatalf("v1 详情不符: %d", code)
	}
	// 无此版本 404 / 版本号非法 400 / 无此案 404
	if code, _ = e.do(t, "GET", "/api/cases/"+caseID+"/report/narrative/99", nil); code != http.StatusNotFound {
		t.Fatalf("无此版本应 404: %d", code)
	}
	if code, _ = e.do(t, "GET", "/api/cases/"+caseID+"/report/narrative/abc", nil); code != http.StatusBadRequest {
		t.Fatalf("版本号非法应 400: %d", code)
	}
	if code, _ = e.do(t, "POST", "/api/cases/"+storeZeroUUID()+"/report/narrative", nil); code != http.StatusNotFound {
		t.Fatalf("无此案应 404: %d", code)
	}

	// 预算钳制
	if code, _ = e.do(t, "POST", "/api/cases/"+caseID+"/report/narrative",
		map[string]any{"budget_tokens": 50}); code != http.StatusBadRequest {
		t.Fatalf("预算过小应 400: %d", code)
	}
	if code, _ = e.do(t, "POST", "/api/cases/"+caseID+"/report/narrative",
		map[string]any{"budget_tokens": 999999}); code != http.StatusBadRequest {
		t.Fatalf("预算过大应 400: %d", code)
	}
}

func storeZeroUUID() string { return "00000000-0000-0000-0000-999999999999" }

func TestNarrativeArchived409(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	caseID := narrativeCase(t, e)
	e.srv.deps.AI = narrativeAIOK()

	e.meta.archived[caseID] = true
	code, out := e.do(t, "POST", "/api/cases/"+caseID+"/report/narrative", nil)
	if code != http.StatusConflict || !strings.Contains(fmt.Sprint(out), "已归档") {
		t.Fatalf("归档案生成应 409: %d %v", code, out)
	}
	// 归档案历史版本只读可看(先生成过再归档的形态:直接塞一版再验)
	e.meta.archived[caseID] = false
	code, _ = e.do(t, "POST", "/api/cases/"+caseID+"/report/narrative", nil)
	if code != http.StatusCreated {
		t.Fatalf("解归档生成失败: %d", code)
	}
	e.meta.archived[caseID] = true
	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/report/narrative", nil)
	if code != http.StatusOK || len(out["reports"].([]any)) != 1 {
		t.Fatalf("归档案清单应可读: %d %v", code, out)
	}
	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/report/narrative/1", nil)
	if code != http.StatusOK {
		t.Fatalf("归档案详情应可读: %d %v", code, out)
	}
}

func TestNarrativeBudgetTruncated(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	caseID := narrativeCase(t, e)
	ai := newFakeAI()
	// 预算熔断:无 result,只有流式残文 + budget_exceeded
	ai.events = []agentloop.Event{
		{Kind: "text", Text: "# 研判报告\n\n## 一、结论摘要\n\n1. 写到一半"},
		{Kind: "budget_exceeded", Reason: "budget_exceeded",
			TokensIn: 29000, TokensOut: 1500,
			ErrText: "会话 token 预算熔断: 已用 30500 > 预算 30000"},
	}
	e.srv.deps.AI = ai

	code, out := e.do(t, "POST", "/api/cases/"+caseID+"/report/narrative", nil)
	if code != http.StatusCreated {
		t.Fatalf("熔断残稿也应落库: %d %v", code, out)
	}
	rep := out["report"].(map[string]any)
	if !rep["truncated"].(bool) {
		t.Fatalf("应标 truncated: %v", rep)
	}
	content := out["content"].(string)
	if !strings.Contains(content, "写到一半") ||
		!strings.Contains(content, "截断") {
		t.Fatalf("截断标注缺失:\n%s", content)
	}
}

func TestNarrativeZeroOutput502(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	caseID := narrativeCase(t, e)
	ai := newFakeAI()
	ai.events = []agentloop.Event{
		{Kind: "error", ErrText: "model_error: 500 upstream"},
	}
	e.srv.deps.AI = ai

	code, out := e.do(t, "POST", "/api/cases/"+caseID+"/report/narrative", nil)
	if code != http.StatusBadGateway || !strings.Contains(fmt.Sprint(out), "不落库") {
		t.Fatalf("零产出应 502 如实: %d %v", code, out)
	}
	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/report/narrative", nil)
	if code != http.StatusOK || len(out["reports"].([]any)) != 0 {
		t.Fatalf("零产出不得落库: %v", out)
	}
}

func TestNarrativeGates(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	caseID := narrativeCase(t, e)

	// AI 未装配 → 503
	code, _ := e.do(t, "POST", "/api/cases/"+caseID+"/report/narrative", nil)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("AI 未装配应 503: %d", code)
	}
	// 外发闸关 → 403
	ai := narrativeAIOK()
	ai.runErr = agentloop.ErrOutboundDisabled
	e.srv.deps.AI = ai
	code, out := e.do(t, "POST", "/api/cases/"+caseID+"/report/narrative", nil)
	if code != http.StatusForbidden || !strings.Contains(fmt.Sprint(out), "外发") {
		t.Fatalf("外发关应 403: %d %v", code, out)
	}
	// 未配置 key → 503
	ai.runErr = agentloop.ErrNotConfigured
	code, _ = e.do(t, "POST", "/api/cases/"+caseID+"/report/narrative", nil)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("未配置应 503: %d", code)
	}
}

// TestNarrativeGroundingAssembly grounding 组装单测(纯函数):章节账/锚点
// 格式/doubt 段/截断如实标/空态如实。
func TestNarrativeGroundingAssembly(t *testing.T) {
	srcID := "s1"
	srcByID := map[string]*store.Source{
		srcID: {ID: srcID, Host: "10.0.0.1", Path: "logs/access.log", SHA256: "abc"},
	}
	nodes := []*intent.Node{
		{ID: "g1", CaseID: "c1", Kind: intent.KindGoal, Text: "入口确认",
			Status: intent.StatusClosedGoalPartial, CreatedBy: intent.ByHuman,
			Scope: intent.ScopeCase},
		{ID: "f1", CaseID: "c1", Kind: intent.KindFact, Text: "有爆破失败集中",
			Status: intent.StatusSupported, ParentID: "g1", CreatedBy: intent.ByAI,
			Scope: intent.ScopeCase,
			Evidence: []intent.Anchor{{SourceID: srcID, LineNo: 7}}},
		{ID: "d1", CaseID: "c1", Kind: intent.KindIntent, Text: "查 webshell",
			Status: intent.StatusDoubt, ParentID: "g1", CreatedBy: intent.ByAI,
			Scope: intent.ScopeCase, ResultText: "日志量不足",
			Evidence: []intent.Anchor{{SourceID: srcID, LineNo: 9}}},
	}
	ts := time.Date(2026, 9, 16, 3, 9, 42, 0, time.UTC)
	hits := []review.Hit{{
		ID: "h1", CaseID: "c1", SourceID: srcID, LineNo: 7, RuleID: "ssh-brute",
		Severity: "high", EvidenceGrade: "strong", Snippet: "Failed password",
		TsUTC: &ts, Status: "accepted", ReviewedBy: "admin",
	}}
	hitCounts := map[string]int{"accepted": 1, "pending": 2, "rejected": 0}
	hitsByID := map[string]*review.Hit{"h1": &hits[0]}

	d := buildReport(&store.Case{ID: "c1", Name: "测试案", IncidentType: "ransomware",
		Background: "演练"},
		nodes, hits, hitCounts, srcByID, hitsByID, 10, 4, true, ts)
	g := narrativeGrounding(d, collectDoubts(nodes, srcByID))

	for _, want := range []string{
		"## 案件概况", "测试案", "勒索响应", "演练", "`10.0.0.1`",
		"证据源 10 份(已被排查触及 4,覆盖缺口 6)",
		"待裁决 2 · 已确认 1 · 已排除 0",
		"## 目的章收官态", "入口确认", "机器评估部分达成",
		"## 证据支持的结论", "有爆破失败集中",
		"锚点:主机 `10.0.0.1` · 源 `logs/access.log:7`",
		"## 存疑方向(doubt · 1 条)", "查 webshell", "日志量不足",
		"## 已确认发现(人工裁决 accepted · 1 条", "ssh-brute",
		"## 攻击时间线(UTC 升序 · 共 1 条)", "2026-09-16 03:09:42",
	} {
		if !strings.Contains(g, want) {
			t.Fatalf("grounding 缺 %q:\n%s", want, g)
		}
	}

	// 空态如实:无 doubt/无发现/无时间线/无主机
	d2 := buildReport(&store.Case{ID: "c2", Name: "空案"}, nil, nil,
		map[string]int{}, map[string]*store.Source{}, nil, 0, 0, true, ts)
	g2 := narrativeGrounding(d2, nil)
	for _, want := range []string{"(无存疑方向,如实)", "(无已确认发现",
		"如实为空)", "主机未建模(散件源,如实)"} {
		if !strings.Contains(g2, want) {
			t.Fatalf("空态 grounding 缺 %q:\n%s", want, g2)
		}
	}

	// 发现超帽截断如实标(61 > 60)
	var many []review.Hit
	for i := 0; i < 61; i++ {
		h := review.Hit{ID: fmt.Sprintf("hx-%d", i), CaseID: "c1",
			SourceID: srcID, LineNo: i + 1, RuleID: "r", Severity: "low",
			Status: "accepted"}
		many = append(many, h)
	}
	d3 := buildReport(&store.Case{ID: "c1", Name: "大案"}, nil, many,
		map[string]int{"accepted": 61}, srcByID, nil, 1, 1, true, ts)
	g3 := narrativeGrounding(d3, nil)
	if !strings.Contains(g3, "只取严重度前 60") {
		t.Fatalf("超帽截断标缺失:\n%s", g3)
	}
}
