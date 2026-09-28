// 预算三闸 + 停车场 + 章节收官评估的单测(0.24.0-convergence):
// 闸只在自动派生路径(worker 写回 spawnChildren),人工播种不过闸;
// 超闸/park_lead → parked 节点+parking 条目+过程流/播报/审计三处留痕;
// deploy/dismiss 人批出入场;收官评估 mock AI 只建议不自动开。
package intent

import (
	"context"
	"strings"
	"testing"
	"time"
)

// testEngineLimits 装配带预算闸的引擎(fake 三件套 + 固定闸值)。
func testEngineLimits(lim BudgetLimits) (*Engine, *fakeStore, *fakeAI, *fakeAudit) {
	fs := newFakeStore()
	fa := newFakeAI()
	fau := &fakeAudit{}
	eng := NewEngine(Deps{Store: fs, AI: fa, Audit: fau,
		Debounce:     2 * time.Millisecond,
		BudgetLimits: func() BudgetLimits { return lim }})
	return eng, fs, fa, fau
}

// mkNode 直接落一个节点(测试布景;绕过引擎播种)。
func mkNode(t *testing.T, fs *fakeStore, n *Node) *Node {
	t.Helper()
	if err := ValidateNode(n); err != nil {
		t.Fatal(err)
	}
	if err := fs.CreateNode(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	return n
}

// collectLogf 过程流捕获(与 worker 的 logf 同形态:落事件 + 发播报)。
func collectLogf(eng *Engine, fs *fakeStore, caseID, nodeID string) (func(string, string), *[]string) {
	kinds := []string{}
	return func(kind, text string) {
		_ = fs.AppendEvent(context.Background(), caseID, nodeID, kind, text)
		eng.emitFeedEvent(caseID, nodeID, kind, text)
		kinds = append(kinds, kind)
	}, &kinds
}

func parkedNodes(fs *fakeStore, caseID string) []*Node {
	nodes, _ := fs.ListNodes(context.Background(), caseID)
	var out []*Node
	for _, n := range nodes {
		if n.Status == StatusParked {
			out = append(out, n)
		}
	}
	return out
}

// TestSpawnGateFanout 扇出闸:上限 2,AI 提议 4 条 → 2 进图 + 2 转停车场,
// 播报/过程流/审计留痕;NextRunnable 领不到 parked。
func TestSpawnGateFanout(t *testing.T) {
	eng, fs, _, fau := testEngineLimits(BudgetLimits{Fanout: 2, Chapter: 30, Case: 200})
	ctx := context.Background()
	parent := mkNode(t, fs, &Node{CaseID: "case-1", Kind: KindIntent, Text: "父意图",
		Status: StatusSupported, CreatedBy: ByAI, Scope: ScopeCase, Depth: 1})
	logf, kinds := collectLogf(eng, fs, "case-1", parent.ID)

	eng.spawnChildren(ctx, parent, []string{"子一", "子二", "子三", "子四"}, logf)

	nodes, _ := fs.ListNodes(ctx, "case-1")
	var open, parked int
	for _, n := range nodes {
		if n.Kind != KindIntent || n.ID == parent.ID {
			continue
		}
		switch n.Status {
		case StatusOpen:
			open++
		case StatusParked:
			parked++
		}
	}
	if open != 2 || parked != 2 {
		t.Fatalf("扇出闸后应 2 进图 2 停放,实得 open=%d parked=%d", open, parked)
	}
	entries, _ := fs.ListParking(ctx, "case-1")
	if len(entries) != 2 {
		t.Fatalf("停车场应有 2 条,实得 %d", len(entries))
	}
	for _, p := range entries {
		if p.Reason != ParkReasonFanout || p.SourceNodeID != parent.ID {
			t.Fatalf("条目原因/来源不对: %+v", p)
		}
		if p.Text == "" {
			t.Fatal("条目应带线索摘要(join 节点文本)")
		}
	}
	if !fau.has("intent.parked") {
		t.Fatal("审计缺 intent.parked")
	}
	foundParkEvent := false
	for _, k := range *kinds {
		if k == "park" {
			foundParkEvent = true
		}
	}
	if !foundParkEvent {
		t.Fatalf("过程流缺 park 步: %v", *kinds)
	}
	// 播报板如实记「转入停车场」(park 档经 feed 帧)
	feeds, _ := eng.Activity("case-1", 0)
	foundParkFeed := false
	for _, f := range feeds {
		if f.Feed != nil && strings.Contains(f.Feed.Text, "停车场") {
			foundParkFeed = true
		}
	}
	if !foundParkFeed {
		t.Fatal("播报缺「转入停车场」档")
	}
	// parked 不进派发队列:NextRunnable 领到的只能是 open 的「子一/子二」
	// (案子此刻只有两条 open;parked 两条永不出队)
	for i := 0; i < 2; i++ {
		n, _ := fs.NextRunnable(ctx, "case-1")
		if n == nil || n.Status != StatusOpen {
			t.Fatalf("NextRunnable 应只领 open,实得 %+v", n)
		}
		_, _ = fs.MarkRunning(ctx, n.ID, "sess-x", time.Now())
	}
	if n, _ := fs.NextRunnable(ctx, "case-1"); n != nil {
		t.Fatalf("open 领完后应无队列(parked 不出队),实得 %+v", n)
	}
}

// TestSpawnGateChapter 章闸:章内自动意图达上限 → 新派生转停车场,
// 归属建议=该章 goal。
func TestSpawnGateChapter(t *testing.T) {
	eng, fs, _, _ := testEngineLimits(BudgetLimits{Fanout: 5, Chapter: 2, Case: 200})
	ctx := context.Background()
	goal := mkNode(t, fs, &Node{CaseID: "case-1", Kind: KindGoal, Text: "章节一",
		Status: StatusOpen, CreatedBy: ByRule, Scope: ScopeCase})
	parent := mkNode(t, fs, &Node{CaseID: "case-1", Kind: KindIntent, Text: "父",
		Status: StatusSupported, CreatedBy: ByAI, Scope: ScopeCase,
		ParentID: goal.ID, Depth: 1})
	mkNode(t, fs, &Node{CaseID: "case-1", Kind: KindIntent, Text: "章内已有",
		Status: StatusDenied, CreatedBy: ByAI, Scope: ScopeCase,
		ParentID: goal.ID, Depth: 1})
	logf, _ := collectLogf(eng, fs, "case-1", parent.ID)

	eng.spawnChildren(ctx, parent, []string{"章外溢"}, logf)

	entries, _ := fs.ListParking(ctx, "case-1")
	if len(entries) != 1 || entries[0].Reason != ParkReasonChapter {
		t.Fatalf("应 1 条 budget_chapter 条目: %+v", entries)
	}
	if entries[0].SuggestGoalID != goal.ID || entries[0].SuggestLabel == "" {
		t.Fatalf("归属建议应指向章 goal: %+v", entries[0])
	}
}

// TestSpawnGateCase 案闸:案内自动意图达上限 → 转停车场(无章节的散件
// 分支也归案闸管)。
func TestSpawnGateCase(t *testing.T) {
	eng, fs, _, _ := testEngineLimits(BudgetLimits{Fanout: 5, Chapter: 30, Case: 2})
	ctx := context.Background()
	mkNode(t, fs, &Node{CaseID: "case-1", Kind: KindIntent, Text: "已有一",
		Status: StatusClosed, CreatedBy: ByRule, Scope: ScopeCase, Depth: 1})
	parent := mkNode(t, fs, &Node{CaseID: "case-1", Kind: KindIntent, Text: "父",
		Status: StatusSupported, CreatedBy: ByAI, Scope: ScopeCase, Depth: 1})
	logf, _ := collectLogf(eng, fs, "case-1", parent.ID)

	eng.spawnChildren(ctx, parent, []string{"溢出一"}, logf)

	entries, _ := fs.ListParking(ctx, "case-1")
	if len(entries) != 1 || entries[0].Reason != ParkReasonCase {
		t.Fatalf("应 1 条 budget_case 条目: %+v", entries)
	}
	if entries[0].SuggestGoalID != "" {
		t.Fatalf("无章节分支归属建议应为空(新开章语义): %+v", entries[0])
	}
}

// TestHumanSeedingUngated 人工播种不过闸(判断权归人):闸值全 1,
// 手写意图/线索/模板播种照常。
func TestHumanSeedingUngated(t *testing.T) {
	eng, fs, _, _ := testEngineLimits(BudgetLimits{Fanout: 1, Chapter: 1, Case: 1})
	ctx := context.Background()
	mkNode(t, fs, &Node{CaseID: "case-1", Kind: KindIntent, Text: "自动一",
		Status: StatusClosed, CreatedBy: ByAI, Scope: ScopeCase, Depth: 1}) // 案额已满

	n, err := eng.CreateHuman(ctx, "case-1", "tester", "人工核查外联", "", 0, "", "")
	if err != nil || n.Status != StatusOpen {
		t.Fatalf("人工手写意图不应过闸: %v %+v", err, n)
	}
	if _, err := eng.AddHint(ctx, "case-1", "tester", "线人提供:夜里两点有告警", ""); err != nil {
		t.Fatalf("人工线索不应过闸: %v", err)
	}
	// 模板播种(人发起的一键分析)也不过闸:另一引擎装模板试
	eng2, fs2, _, _ := testEngineLimits(BudgetLimits{Fanout: 1, Chapter: 1, Case: 1})
	eng2.deps.Templates = map[string]*Template{"t-two": twoLevelTpl}
	goal, roots, err := eng2.SeedTemplate(ctx, "case-1", "t-two", "tester")
	if err != nil || roots != 2 || goal == nil {
		t.Fatalf("模板播种(人发起)不应过闸: roots=%d err=%v", roots, err)
	}
	nodes, _ := fs2.ListNodes(ctx, "case-1")
	for _, nd := range nodes {
		if nd.Status == StatusParked {
			t.Fatalf("模板骨架不应有 parked: %+v", nd)
		}
	}
}

// TestParkLeadViaWorker AI 写回带 park_leads → 停车场登记(不展开),
// 带归属建议快照;超 maxParkLeads 如实截断。
func TestParkLeadViaWorker(t *testing.T) {
	tpl := &Template{ID: "t-one", Goal: "单根章",
		Intents: []TemplateIntent{{Key: "a", Text: "根意图"}}}
	eng, fs, fa, _ := testEngine(map[string]*Template{"t-one": tpl})
	fa.runFn = func(_, _, _ string, _ <-chan string) []AIEvent {
		return []AIEvent{{Kind: "text", Text: "查完。\n```json\n" +
			`{"verdict":"denied","summary":"认真查过,当前章无异常",` +
			`"anchors":[],"children":[],"park_leads":[` +
			`{"text":"另一网段出现同族告警","suggest":"新开章:跨网段排查"},` +
			`{"text":"DNS 隧道嫌疑","suggest":"数据外泄章"},` +
			`{"text":"第三条","suggest":""},{"text":"第四条(超上限)","suggest":""}` +
			`]}` + "\n```"}}
	}
	eng.Start(context.Background())
	defer eng.Close()
	ctx := context.Background()
	if _, _, err := eng.SeedTemplate(ctx, "case-1", "t-one", "tester"); err != nil {
		t.Fatal(err)
	}
	err := waitFor(func() bool {
		entries, _ := fs.ListParking(ctx, "case-1")
		return len(entries) >= maxParkLeads
	}, "park_leads 登记进停车场(截断到上限)")
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := fs.ListParking(ctx, "case-1")
	if len(entries) != maxParkLeads {
		t.Fatalf("park_leads 应截断到 %d 条,实得 %d", maxParkLeads, len(entries))
	}
	first := entries[0]
	if first.Reason != ParkReasonLead || first.SuggestLabel != "新开章:跨网段排查" {
		t.Fatalf("首条申请不对: %+v", first)
	}
	if first.SuggestGoalID != "" {
		t.Fatalf("新开章申请 suggest_goal_id 应空: %+v", first)
	}
	// 登记不展开: parked 节点永不被派发
	for _, n := range parkedNodes(fs, "case-1") {
		if n.Status != StatusParked {
			t.Fatalf("parked 节点状态被改: %+v", n)
		}
	}
}

// oneChapterTpl 单根章模板(收官评估测试用)。
var oneChapterTpl = &Template{ID: "t-eval", Goal: "收官章",
	Intents: []TemplateIntent{{Key: "a", Text: "根意图"}}}

// TestChapterClosingEval 章节收官评估:章内全终态 + 有待评估条目 →
// 一次 LLM 调用(预算封顶 1000)写回建议;只建议不自动开(条目仍 parked)。
func TestChapterClosingEval(t *testing.T) {
	eng, fs, fa, fau := testEngine(map[string]*Template{"t-eval": oneChapterTpl})
	eng.deps.BudgetLimits = func() BudgetLimits {
		return BudgetLimits{Fanout: 1, Chapter: 30, Case: 200} // 扇出 1:第 2 条 AI 子进停车场
	}
	fa.runFn = func(_, prompt, systemExtra string, _ <-chan string) []AIEvent {
		if systemExtra == "" { // 收官评估轮(worker 轮恒有 systemExtra)
			// 从 prompt 抠条目 id 逐条回建议(契约:```json [{id,verdict,reason}])
			var ids []string
			for _, ln := range strings.Split(prompt, "\n") {
				if strings.HasPrefix(ln, "- id=") {
					ids = append(ids, strings.Fields(strings.TrimPrefix(ln, "- id="))[0])
				}
			}
			var sb strings.Builder
			sb.WriteString("```json\n[")
			for i, id := range ids {
				if i > 0 {
					sb.WriteString(",")
				}
				sb.WriteString(`{"id":"` + id + `","verdict":"deploy","reason":"值得追"}`)
			}
			sb.WriteString("]\n```")
			return []AIEvent{{Kind: "text", Text: sb.String()}}
		}
		return []AIEvent{{Kind: "text", Text: "查完。\n```json\n" +
			`{"verdict":"denied","summary":"无异常","anchors":[],` +
			`"children":["子一","子二(超扇出闸)"],"park_leads":[]}` + "\n```"}}
	}
	eng.Start(context.Background())
	defer eng.Close()
	ctx := context.Background()
	if _, _, err := eng.SeedTemplate(ctx, "case-1", "t-eval", "tester"); err != nil {
		t.Fatal(err)
	}
	// a 跑完 → 子一进图,子二 parked(扇出闸);链到深度上限后章收官 →
	// 评估一次写回全部待评估条目(每层一条 parked,共 4 条:深度 2..5)
	err := waitFor(func() bool {
		entries, _ := fs.ListParking(ctx, "case-1")
		if len(entries) == 0 {
			return false
		}
		for _, p := range entries {
			if p.Verdict == "" {
				return false
			}
		}
		return true
	}, "收官评估建议落账(全部待评估条目)")
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := fs.ListParking(ctx, "case-1")
	for _, p := range entries {
		if p.Verdict != VerdictDeploy || p.VerdictReason != "值得追" {
			t.Fatalf("建议落账不对: %+v", p)
		}
		if p.Status != ParkingParked {
			t.Fatalf("AI 只建议不自动开:条目应仍 parked,实得 %s", p.Status)
		}
	}
	if !fau.has("intent.chapter_eval") {
		t.Fatal("审计缺 intent.chapter_eval")
	}
	// 评估会话预算封顶 1000
	foundEvalBudget := false
	for _, b := range fa.budgets {
		if b == ChapterEvalTokens {
			foundEvalBudget = true
		}
	}
	if !foundEvalBudget {
		t.Fatalf("收官评估会话预算应为 %d: %v", ChapterEvalTokens, fa.budgets)
	}
}

// TestChapterEvalNotTriggered 章未收官(有待批意图)→ 零评估调用(如实不烧)。
func TestChapterEvalNotTriggered(t *testing.T) {
	eng, fs, fa, _ := testEngine(map[string]*Template{"t-two": twoLevelTpl})
	eng.deps.BudgetLimits = func() BudgetLimits {
		return BudgetLimits{Fanout: 1, Chapter: 30, Case: 200}
	}
	eng.Start(context.Background())
	defer eng.Close()
	ctx := context.Background()
	if _, _, err := eng.SeedTemplate(ctx, "case-1", "t-two", "tester"); err != nil {
		t.Fatal(err)
	}
	// a/b 跑完 + 子二 parked;但 c(scope=all)挂待批 → 章未收官
	err := waitFor(func() bool {
		entries, _ := fs.ListParking(ctx, "case-1")
		return len(entries) >= 1
	}, "扇出闸转出停车场条目")
	if err != nil {
		t.Fatal(err)
	}
	sessionsBefore := len(fa.sessions)
	time.Sleep(150 * time.Millisecond) // 等一拍:若误触发,评估会话早开了
	entries, _ := fs.ListParking(ctx, "case-1")
	for _, p := range entries {
		if p.Verdict != "" {
			t.Fatalf("章未收官不应有评估建议: %+v", p)
		}
	}
	if len(fa.sessions) != sessionsBefore {
		t.Fatalf("章未收官不应开评估会话: 前 %d 后 %d", sessionsBefore, len(fa.sessions))
	}
}

// TestParkingDeployDismiss 人批出入场:deploy(既有章直转 open 可派发)/
// deploy 新开章(落新 goal+parent 重指)/dismiss(留痕关闭)/二次处置 409 语义。
func TestParkingDeployDismiss(t *testing.T) {
	eng, fs, _, fau := testEngineLimits(BudgetLimits{Fanout: 1, Chapter: 30, Case: 200})
	ctx := context.Background()
	goal := mkNode(t, fs, &Node{CaseID: "case-1", Kind: KindGoal, Text: "章一",
		Status: StatusOpen, CreatedBy: ByRule, Scope: ScopeCase})
	parent := mkNode(t, fs, &Node{CaseID: "case-1", Kind: KindIntent, Text: "父",
		Status: StatusSupported, CreatedBy: ByAI, Scope: ScopeCase,
		ParentID: goal.ID, Depth: 1})
	logf, _ := collectLogf(eng, fs, "case-1", parent.ID)
	eng.spawnChildren(ctx, parent, []string{"进图子", "闸下子"}, logf)

	entries, _ := fs.ListParking(ctx, "case-1")
	if len(entries) != 1 {
		t.Fatalf("应 1 条停车场条目: %+v", entries)
	}
	entry := entries[0]
	// deploy 前:NextRunnable 领的是「进图子」
	nr, _ := fs.NextRunnable(ctx, "case-1")
	if nr == nil || nr.Text != "进图子" {
		t.Fatalf("deploy 前可派发的应是进图子: %+v", nr)
	}

	// deploy(归属=既有章):节点转 open,可派发
	got, node, err := eng.DeployParking(ctx, entry.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != ParkingDeployed || node.Status != StatusOpen {
		t.Fatalf("deploy 后状态不对: entry=%s node=%s", got.Status, node.Status)
	}
	if !fau.has("intent.parking_deploy") {
		t.Fatal("审计缺 intent.parking_deploy")
	}
	// 二次处置:已被处置
	if _, _, err := eng.DeployParking(ctx, entry.ID, "admin"); err == nil ||
		!strings.Contains(err.Error(), "已被处置") {
		t.Fatalf("二次 deploy 应拒(已被处置): %v", err)
	}
	if _, err := eng.DismissParking(ctx, entry.ID, "admin"); err == nil {
		t.Fatal("deploy 后 dismiss 应拒")
	}

	// park_lead 新开章:deploy 落新 goal + parent 重指
	if err := eng.ParkLead(ctx, parent, "章外线索 X", "新开章: 外泄追查", logf); err != nil {
		t.Fatal(err)
	}
	entries, _ = fs.ListParking(ctx, "case-1")
	var lead *ParkingEntry
	for _, p := range entries {
		if p.Reason == ParkReasonLead {
			lead = p
		}
	}
	if lead == nil {
		t.Fatal("park_lead 条目缺失")
	}
	_, node2, err := eng.DeployParking(ctx, lead.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	newGoal, _ := fs.GetNode(ctx, node2.ParentID)
	if newGoal == nil || newGoal.Kind != KindGoal ||
		!strings.Contains(newGoal.Text, "外泄追查") {
		t.Fatalf("新开章应落 goal 并重指 parent: %+v", newGoal)
	}
	edges, _ := fs.ListEdges(ctx, "case-1")
	foundEdge := false
	for _, e := range edges {
		if e.FromID == newGoal.ID && e.ToID == node2.ID && e.Kind == EdgeSpawns {
			foundEdge = true
		}
	}
	if !foundEdge {
		t.Fatal("新开章与展开节点间缺 spawns 边")
	}

	// dismiss:留痕关闭
	if err := eng.ParkLead(ctx, parent, "噪音线索", "", logf); err != nil {
		t.Fatal(err)
	}
	entries, _ = fs.ListParking(ctx, "case-1")
	var noise *ParkingEntry
	for _, p := range entries {
		if p.Status == ParkingParked {
			noise = p
		}
	}
	d, err := eng.DismissParking(ctx, noise.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != ParkingDismissed {
		t.Fatalf("dismiss 后条目应 dismissed: %s", d.Status)
	}
	dn, _ := fs.GetNode(ctx, noise.NodeID)
	if dn.Status != StatusClosed || !strings.Contains(dn.CloseNote, "停车场丢弃") {
		t.Fatalf("dismiss 节点应关闭留痕: %+v", dn)
	}
	if !fau.has("intent.parking_dismiss") {
		t.Fatal("审计缺 intent.parking_dismiss")
	}
}

// TestBudgetStatus 预算可观测面:案计数(自动非 parked)/章分布/待处置数。
func TestBudgetStatus(t *testing.T) {
	eng, fs, _, _ := testEngineLimits(BudgetLimits{Fanout: 5, Chapter: 30, Case: 200})
	ctx := context.Background()
	g1 := mkNode(t, fs, &Node{CaseID: "case-1", Kind: KindGoal, Text: "章一",
		Status: StatusOpen, CreatedBy: ByRule, Scope: ScopeCase})
	g2 := mkNode(t, fs, &Node{CaseID: "case-1", Kind: KindGoal, Text: "章二",
		Status: StatusOpen, CreatedBy: ByRule, Scope: ScopeCase})
	mkNode(t, fs, &Node{CaseID: "case-1", Kind: KindIntent, Text: "a1",
		Status: StatusClosed, CreatedBy: ByAI, Scope: ScopeCase, ParentID: g1.ID, Depth: 1})
	mkNode(t, fs, &Node{CaseID: "case-1", Kind: KindIntent, Text: "a2",
		Status: StatusRunning, CreatedBy: ByRule, Scope: ScopeCase, ParentID: g1.ID, Depth: 1})
	mkNode(t, fs, &Node{CaseID: "case-1", Kind: KindIntent, Text: "b1",
		Status: StatusOpen, CreatedBy: ByAI, Scope: ScopeCase, ParentID: g2.ID, Depth: 1})
	mkNode(t, fs, &Node{CaseID: "case-1", Kind: KindIntent, Text: "人工不占额",
		Status: StatusOpen, CreatedBy: ByHuman, Scope: ScopeCase, Depth: 1})
	mkNode(t, fs, &Node{CaseID: "case-1", Kind: KindIntent, Text: "parked 不占额",
		Status: StatusParked, CreatedBy: ByAI, Scope: ScopeCase, ParentID: g1.ID, Depth: 2})
	// 一条 parked 停车场条目(待处置计数)
	pn := parkedNodes(fs, "case-1")
	if err := fs.CreateParking(ctx, &ParkingEntry{CaseID: "case-1", NodeID: pn[0].ID,
		Reason: ParkReasonFanout, CreatedBy: ByAI, Status: ParkingParked}); err != nil {
		t.Fatal(err)
	}

	st, err := eng.Budget(ctx, "case-1")
	if err != nil {
		t.Fatal(err)
	}
	if st.Limits != (BudgetLimits{Fanout: 5, Chapter: 30, Case: 200}) {
		t.Fatalf("闸值不对: %+v", st.Limits)
	}
	if st.CaseIntents != 3 {
		t.Fatalf("案意图数应 3(人工/parked 不占),实得 %d", st.CaseIntents)
	}
	if len(st.Chapters) != 2 {
		t.Fatalf("章分布应 2 章: %+v", st.Chapters)
	}
	byGoal := map[string]int{}
	for _, c := range st.Chapters {
		byGoal[c.GoalID] = c.Intents
	}
	if byGoal[g1.ID] != 2 || byGoal[g2.ID] != 1 {
		t.Fatalf("章分布不对: %+v", st.Chapters)
	}
	if st.Parked != 1 {
		t.Fatalf("待处置应 1,实得 %d", st.Parked)
	}
}
