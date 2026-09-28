// 报告端点契约测试(0.30.0-report-ux 可读性重构):
// 新结构——一、结论先行(案子/时间窗/核心判断清单)/二、攻击时间线(锚点
// 事件时间升序,50 截断如实)/三、分章排查结论(goal 章分组,带 supported
// 账)/四、已确认发现(人裁决,锚点四件)/五~七 概况·覆盖·建议/八、证据
// 附录(锚点去重);每节空态如实标;markdown 同源渲染;引擎未装配区段缺失
// 如实标;无此案 404。buildReport 纯函数另有直接单测(截断/分组/空态)。
package web

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ye-mengwen/fengtu/internal/ingest/store"
	"github.com/ye-mengwen/fengtu/internal/intent"
	"github.com/ye-mengwen/fengtu/internal/review"
)

func TestReportEndpoint(t *testing.T) {
	e := newTestEnv(t)
	fi := newFakeIntent()
	e.srv.deps.Intent = fi
	e.login(t)
	tid := e.uploadFile(t, "report-case", "a.log",
		[]byte("10.0.0.1 - - [01/Jan/2024:00:00:00 +0000] \"GET / HTTP/1.1\" 200 1\n"), "")
	e.waitTask(t, tid)
	_, out := e.do(t, "GET", "/api/cases", nil)
	caseID := out["cases"].([]any)[0].(map[string]any)["id"].(string)

	// 取源(锚点 join 目标)
	code, out := e.do(t, "GET", "/api/cases/"+caseID, nil)
	if code != 200 {
		t.Fatalf("案件详情失败: %d", code)
	}
	src := out["sources"].([]any)[0].(map[string]any)
	srcID := src["id"].(string)
	srcSHA := src["sha256"].(string)

	// 喂候选:两条 accepted 带 ts(高/低各一)+ 一条 pending + 一条 rejected
	now := time.Now()
	tsEarly := time.Date(2024, 1, 1, 0, 0, 5, 0, time.UTC)
	tsLate := time.Date(2024, 1, 1, 2, 30, 0, 0, time.UTC)
	mk := func(rule, severity, status string, line int, ts *time.Time) string {
		h := review.Hit{CaseID: caseID, SourceID: srcID, LineNo: line, RuleID: rule,
			Severity: severity, Status: "pending", EvidenceGrade: "suspect",
			TsUTC: ts}
		if _, err := e.review.InsertHit(context.Background(), h, now); err != nil {
			t.Fatal(err)
		}
		id := e.review.hits[len(e.review.hits)-1].ID
		if status != "pending" {
			if _, err := e.review.SetVerdict(context.Background(), id, "boss", status, "", now); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	hitLow := mk("rule-low", "low", "accepted", 1, &tsEarly)
	mk("rule-high", "high", "accepted", 2, &tsLate)
	mk("rule-pend", "medium", "pending", 3, nil)
	mk("rule-rej", "info", "rejected", 4, nil)

	// 意图图:goal g1(收官 partial)+ 章内意图 i1(supported)/i2(denied)
	// + goal g2(open 零意图);fact:f1 源锚点挂 i1 / f2 hit 锚点挂 i1
	// (hit 带 ts → 进时间线)/ f3 无父(未挂章节,orphan)/ f4 无锚点(不收)
	fi.nodes["g1"] = &intent.Node{ID: "g1", CaseID: caseID, Kind: intent.KindGoal,
		Text: "确认入侵入口", Status: intent.StatusClosedGoalPartial,
		CreatedBy: intent.ByHuman, Scope: intent.ScopeCase, CreatedAt: now}
	fi.nodes["g2"] = &intent.Node{ID: "g2", CaseID: caseID, Kind: intent.KindGoal,
		Text: "确定影响范围", Status: intent.StatusOpen, CreatedBy: intent.ByHuman,
		Scope: intent.ScopeCase, CreatedAt: now}
	fi.nodes["i1"] = &intent.Node{ID: "i1", CaseID: caseID, Kind: intent.KindIntent,
		Text: "盘点登录失败", Status: intent.StatusSupported, CreatedBy: intent.ByAI,
		Scope: intent.ScopeCase, ParentID: "g1", CreatedAt: now}
	fi.nodes["i2"] = &intent.Node{ID: "i2", CaseID: caseID, Kind: intent.KindIntent,
		Text: "查爆破链", Status: intent.StatusDenied, CreatedBy: intent.ByAI,
		Scope: intent.ScopeCase, ParentID: "g1", CreatedAt: now}
	fi.nodes["f1"] = &intent.Node{ID: "f1", CaseID: caseID, Kind: intent.KindFact,
		Text: "源 a.log 存在 401 集中失败", Status: intent.StatusSupported,
		CreatedBy: intent.ByAI, Scope: intent.ScopeCase, ParentID: "i1",
		CreatedAt: now, Evidence: []intent.Anchor{{SourceID: srcID, LineNo: 1}}}
	fi.nodes["f2"] = &intent.Node{ID: "f2", CaseID: caseID, Kind: intent.KindFact,
		Text: "10.0.0.1 在时间窗内集中出现", Status: intent.StatusClosed,
		CreatedBy: intent.ByAI, Scope: intent.ScopeCase, ParentID: "i1",
		CreatedAt: now, Evidence: []intent.Anchor{{HitID: hitLow}}}
	// 无锚点 fact 不收(本节题即「证据支持」)
	fi.nodes["f3"] = &intent.Node{ID: "f3", CaseID: caseID, Kind: intent.KindFact,
		Text: "无锚点断言不进结论", Status: intent.StatusClosed,
		CreatedBy: intent.ByAI, Scope: intent.ScopeCase, CreatedAt: now}
	// 归属不上任何章的 fact(断链/无父,如实进 orphan)
	fi.nodes["f4"] = &intent.Node{ID: "f4", CaseID: caseID, Kind: intent.KindFact,
		Text: "散件结论(父节点已不在图)", Status: intent.StatusClosed,
		CreatedBy: intent.ByAI, Scope: intent.ScopeCase, ParentID: "ghost",
		CreatedAt: now, Evidence: []intent.Anchor{{SourceID: srcID, LineNo: 2}}}

	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/report", nil)
	if code != 200 {
		t.Fatalf("报告端点失败: %d %v", code, out)
	}
	rep := out["report"].(map[string]any)
	md := out["markdown"].(string)

	// 发现:2 条 accepted,严重度降序(high 在前),锚点四件齐
	findings := rep["findings"].([]any)
	if len(findings) != 2 {
		t.Fatalf("已确认发现应 2 条: %v", findings)
	}
	f0 := findings[0].(map[string]any)
	if f0["rule_id"] != "rule-high" || f0["reviewed_by"] != "boss" {
		t.Fatalf("严重度降序/裁决人错: %v", f0)
	}
	if f0["source_sha256"] != srcSHA || f0["source_path"] != "a.log" ||
		f0["line_no"].(float64) != 2 {
		t.Fatalf("锚点四件错(源+行+哈希): %v", f0)
	}
	// 三态计数
	if rep["hits_pending"].(float64) != 1 || rep["hits_accepted"].(float64) != 2 ||
		rep["hits_rejected"].(float64) != 1 {
		t.Fatalf("三态计数错: %v", rep)
	}

	// 分章:g1(supported 1/2,facts f1+f2)+ g2(零意图,空结论)
	chapters := rep["chapters"].([]any)
	if len(chapters) != 2 {
		t.Fatalf("章节应 2 个: %v", chapters)
	}
	ch1 := chapters[0].(map[string]any)
	if ch1["goal_text"] != "确认入侵入口" ||
		ch1["intents_total"].(float64) != 2 ||
		ch1["intents_supported"].(float64) != 1 {
		t.Fatalf("章节账错: %v", ch1)
	}
	if len(ch1["facts"].([]any)) != 2 {
		t.Fatalf("g1 章应收 f1+f2: %v", ch1["facts"])
	}
	fa := ch1["facts"].([]any)[0].(map[string]any)["evidence"].([]any)[0].(map[string]any)
	if fa["source_sha256"] != srcSHA && fa["hit_id"] == nil {
		t.Fatalf("fact 锚点应解析出哈希或 hit_id: %v", fa)
	}
	ch2 := chapters[1].(map[string]any)
	if ch2["intents_total"].(float64) != 0 || len(ch2["facts"].([]any)) != 0 {
		t.Fatalf("g2 零意图零结论: %v", ch2)
	}
	// orphan:f4 断链如实单列
	orphans := rep["orphan_facts"].([]any)
	if len(orphans) != 1 ||
		orphans[0].(map[string]any)["text"] != "散件结论(父节点已不在图)" {
		t.Fatalf("orphan 结论错: %v", orphans)
	}

	// 时间线:3 条(2 发现 ts + f2 锚 hitLow 的 ts),升序,首条最早
	tl := rep["timeline"].([]any)
	if len(tl) != 3 || rep["timeline_total"].(float64) != 3 {
		t.Fatalf("时间线应 3 条: %v", tl)
	}
	if !strings.Contains(tl[0].(map[string]any)["ts_utc"].(string), "00:00:05") {
		t.Fatalf("时间线应升序,首条最早: %v", tl[0])
	}
	if rep["timeline_truncated"].(bool) {
		t.Fatalf("3 条不应截断")
	}
	// 时间窗:最早发现 ~ 最晚发现
	if !strings.Contains(rep["window_from"].(string), "2024-01-01T00:00:05") ||
		!strings.Contains(rep["window_to"].(string), "2024-01-01T02:30:00") {
		t.Fatalf("时间窗错: %v ~ %v", rep["window_from"], rep["window_to"])
	}
	// 证据附录:源+行去重(a.log:1 被 rule-low 发现 + f1 源锚点 + f2 的
	// hit 锚点(解析回源)三条引用 → refs 3)
	ev := rep["evidence"].([]any)
	if len(ev) != 2 {
		t.Fatalf("附录应 2 条去重锚点: %v", ev)
	}
	for _, x := range ev {
		m := x.(map[string]any)
		if m["line_no"].(float64) == 1 && m["refs"].(float64) != 3 {
			t.Fatalf("a.log:1 应被引 3 次(rule-low+f1+f2→hit): %v", m)
		}
	}
	// 覆盖账(fakeIntent.Coverage:4 源 2 explored)
	if rep["sources_total"].(float64) != 4 || rep["sources_explored"].(float64) != 2 {
		t.Fatalf("覆盖账错: %v", rep)
	}

	// markdown:八节齐 + 结论先行三件套 + 章判断 + 时间线 + 附录
	for _, want := range []string{"# 应急响应报告:",
		"## 一、结论先行", "**案子是什么**", "**时间窗**", "**核心判断**",
		"## 二、攻击时间线", "## 三、分章排查结论", "## 四、已确认发现",
		"## 五、候选与裁决概况", "## 六、证据覆盖", "## 七、处置建议",
		"## 八、证据附录",
		"确认入侵入口** —— 机器评估部分达成(章内意图 supported 1/2;机器评估,收官定论归人)",
		"确定影响范围** —— 排查中(未派发意图,如实)",
		"2024-01-01 00:00:05", "2024-01-01 02:30:00",
		"未挂章节的结论", "散件结论(父节点已不在图)",
		"10.0.0.1 在时间窗内集中出现", "rule-high",
		"SHA256 `" + srcSHA + "`", "被引 3 次"} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown 缺 %q:\n%s", want, md)
		}
	}

	// 无此案 404
	code, _ = e.do(t, "GET", "/api/cases/nope/report", nil)
	if code != 404 {
		t.Fatalf("无此案应 404: %d", code)
	}

	// 意图引擎未装配:报告照出,章节/覆盖区段缺失如实标(intent_ready=false);
	// 时间线/时间窗仍可由发现 ts 出(不依赖意图引擎)
	e.srv.deps.Intent = nil
	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/report", nil)
	if code != 200 {
		t.Fatalf("引擎未装配报告也应出: %d", code)
	}
	rep = out["report"].(map[string]any)
	if rep["intent_ready"].(bool) {
		t.Fatalf("引擎未装配应 intent_ready=false")
	}
	md = out["markdown"].(string)
	if len(rep["chapters"].([]any)) != 0 ||
		!strings.Contains(md, "意图引擎未装配") {
		t.Fatalf("引擎未装配区段应缺失且如实标")
	}
	if len(rep["timeline"].([]any)) != 2 { // 仅 2 条发现 ts(fact 锚随图缺失)
		t.Fatalf("引擎未装配时间线应仅剩发现 ts 两条: %v", rep["timeline"])
	}
	if len(rep["findings"].([]any)) != 2 {
		t.Fatalf("引擎未装配不应影响发现区段")
	}
}

// TestBuildReportPure buildReport 纯函数单测:时间线排序/50 截断如实/空态/
// 章分组边界(零 goal、fact 无锚不收、源缺失如实注记)。
func TestBuildReportPure(t *testing.T) {
	now := time.Now().UTC()
	c := &store.Case{ID: "c1", Name: "纯函数案", IncidentType: "intrusion"}

	// 空态:零节点零命中零源——所有区段空态如实
	d := buildReport(c, nil, nil, map[string]int{}, nil, nil, 0, 0, false, now)
	if len(d.Chapters) != 0 || len(d.Timeline) != 0 || d.WindowFrom != nil ||
		len(d.Evidence) != 0 || len(d.Findings) != 0 {
		t.Fatalf("空态应全空: %+v", d)
	}
	md := d.markdown()
	for _, want := range []string{"时间窗缺失", "意图引擎未装配",
		"时间线如实为空", "无已确认发现", "无源锚点可附"} {
		if !strings.Contains(md, want) {
			t.Fatalf("空态 markdown 缺 %q:\n%s", want, md)
		}
	}

	// 时间线超 50 截断 + 升序 + 时间窗按截断前全量(最晚事件在截断后)
	src := &store.Source{ID: "s1", Host: "h1", Path: "p.log", SHA256: "abc"}
	srcByID := map[string]*store.Source{"s1": src}
	base := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	hits := make([]review.Hit, 0, 60)
	for i := 0; i < 60; i++ {
		ts := base.Add(time.Duration(i) * time.Minute)
		hits = append(hits, review.Hit{ID: fmt.Sprintf("hit-%02d", i), CaseID: "c1",
			SourceID: "s1", LineNo: i + 1, RuleID: "r", Severity: "low",
			Status: "accepted", TsUTC: &ts})
	}
	hitsByID := map[string]*review.Hit{}
	for i := range hits {
		hitsByID[hits[i].ID] = &hits[i]
	}
	d = buildReport(c, nil, hits, map[string]int{"accepted": 60}, srcByID,
		hitsByID, 1, 1, true, now)
	if len(d.Timeline) != reportTimelineCap || !d.TimelineTruncated ||
		d.TimelineTotal != 60 {
		t.Fatalf("时间线截断账错: len=%d total=%d trunc=%v",
			len(d.Timeline), d.TimelineTotal, d.TimelineTruncated)
	}
	for i := 1; i < len(d.Timeline); i++ {
		if d.Timeline[i].TsUTC.Before(d.Timeline[i-1].TsUTC) {
			t.Fatalf("时间线非升序: %v 后于 %v", d.Timeline[i-1].TsUTC, d.Timeline[i].TsUTC)
		}
	}
	// 窗口=全量首末(0 分 ~ 59 分),不受截断影响
	if !d.WindowFrom.Equal(base) || !d.WindowTo.Equal(base.Add(59*time.Minute)) {
		t.Fatalf("时间窗应按全量: %v ~ %v", d.WindowFrom, d.WindowTo)
	}
	if len(d.Hosts) != 1 || d.Hosts[0] != "h1" {
		t.Fatalf("主机清单错: %v", d.Hosts)
	}
	if len(d.Evidence) != 60 {
		t.Fatalf("附录应 60 条去重锚点: %d", len(d.Evidence))
	}
	md = d.markdown()
	if !strings.Contains(md, "时间线条目超 50 条") {
		t.Fatalf("截断应如实标:\n%s", md)
	}

	// 章归属:fact 沿 parent 链(intent→goal)归章;锚点源缺失如实注记
	nodes := []*intent.Node{
		{ID: "g1", CaseID: "c1", Kind: intent.KindGoal, Text: "章一",
			Status: intent.StatusClosedGoalMet, CreatedBy: intent.ByHuman,
			Scope: intent.ScopeCase},
		{ID: "i1", CaseID: "c1", Kind: intent.KindIntent, Text: "查",
			Status: intent.StatusSupported, CreatedBy: intent.ByAI,
			Scope: intent.ScopeCase, ParentID: "g1"},
		{ID: "f1", CaseID: "c1", Kind: intent.KindFact, Text: "结论一",
			Status: intent.StatusClosed, CreatedBy: intent.ByAI,
			Scope: intent.ScopeCase, ParentID: "i1",
			Evidence: []intent.Anchor{{SourceID: "ghost-src", LineNo: 7}}},
	}
	d = buildReport(c, nodes, nil, map[string]int{}, srcByID, nil, 0, 0, true, now)
	if len(d.Chapters) != 1 || d.Chapters[0].IntentsSupported != 1 ||
		len(d.Chapters[0].Facts) != 1 {
		t.Fatalf("章归属错: %+v", d.Chapters)
	}
	if !strings.Contains(d.Chapters[0].Facts[0].Evidence[0].Note, "源记录缺失") {
		t.Fatalf("源缺失应如实注记: %+v", d.Chapters[0].Facts[0].Evidence[0])
	}
}
