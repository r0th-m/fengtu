// 意图链引擎契约测试:模板装载/图结构/planner 派发/worker 写回/
// 四层预算/审批门/深度闸/规则播种去重/收尾契约解析。
package intent

import (
	"context"
	"strings"
	"testing"
	"time"
)

// ---- 模板:真实 playbook 目录装载 + 结构校验 ----

func TestLoadRealPlaybooks(t *testing.T) {
	tpls, err := LoadTemplatesDir("../../configs/playbooks")
	if err != nil {
		t.Fatalf("playbook 目录装载失败: %v", err)
	}
	// 0.22.0-treecourt-port:14 册(原 2 册 + 树庭 §3.2 蒸馏 12 册)全量焊死
	want14 := []string{
		"general-triage", "ransomware-triage",
		"host-triage", "lateral-movement", "data-exfil", "linux-exfil",
		"miner", "linux-miner", "ransomware-precursor", "masq-hunt",
		"linux-triage", "linux-lateral", "linux-ransomware", "linux-webshell-chain",
	}
	if len(tpls) != len(want14) {
		t.Fatalf("playbook 数应为 %d(实得 %d)", len(want14), len(tpls))
	}
	for _, id := range want14 {
		tpl := tpls[id]
		if tpl == nil {
			t.Fatalf("模板缺失: %s", id)
		}
		if len(tpl.Roots()) == 0 {
			t.Fatalf("模板 %s 无根意图", id)
		}
	}
	// 勒索模板必须含 scope=all 的批量意图(审批门演示位)且深度 ≤5
	rt := tpls["ransomware-triage"]
	var batch *TemplateIntent
	for i := range rt.Intents {
		if rt.Intents[i].Scope == ScopeAll {
			batch = &rt.Intents[i]
		}
	}
	if batch == nil {
		t.Fatal("勒索模板缺 scope=all 批量意图(审批门无演示位)")
	}
	// 防过拟合:模板零具体案件值(不得出现真实案件标识)
	for _, tpl := range tpls {
		for _, bad := range []string{"CASEHOST99", "192.168.", "FAMALPHA", "FAMBETA", "10.99."} {
			for _, ti := range tpl.Intents {
				if strings.Contains(ti.Text+ti.Ask, bad) || strings.Contains(tpl.Goal, bad) {
					t.Fatalf("模板 %s 夹带具体案件值 %q(防过拟合)", tpl.ID, bad)
				}
			}
		}
	}
}

func TestTemplateValidateRejects(t *testing.T) {
	cases := map[string]Template{
		"after 成环": {ID: "x", Goal: "g", Intents: []TemplateIntent{
			{Key: "a", Text: "a", After: []string{"b"}},
			{Key: "b", Text: "b", After: []string{"a"}},
		}},
		"after 引用未知": {ID: "x", Goal: "g", Intents: []TemplateIntent{
			{Key: "a", Text: "a", After: []string{"ghost"}},
		}},
		"key 冲突": {ID: "x", Goal: "g", Intents: []TemplateIntent{
			{Key: "a", Text: "a"}, {Key: "a", Text: "b"},
		}},
		"深度超限": {ID: "x", Goal: "g", Intents: []TemplateIntent{
			{Key: "a", Text: "a"}, {Key: "b", Text: "b", After: []string{"a"}},
			{Key: "c", Text: "c", After: []string{"b"}},
			{Key: "d", Text: "d", After: []string{"c"}},
			{Key: "e", Text: "e", After: []string{"d"}},
			{Key: "f", Text: "f", After: []string{"e"}},
		}},
	}
	for name, tpl := range cases {
		if err := tpl.Validate(); err == nil {
			t.Fatalf("%s:应拒装却通过", name)
		}
	}
}

// ---- 播种:模板实例化图结构 + 审批门挂起 ----

func TestSeedTemplateGraphShape(t *testing.T) {
	eng, _, _, _ := testEngine(map[string]*Template{"t-two": twoLevelTpl})
	ctx := context.Background()
	goal, roots, err := eng.SeedTemplate(ctx, "case-1", "t-two", "tester")
	if err != nil {
		t.Fatal(err)
	}
	if roots != 2 {
		t.Fatalf("根意图数=%d,应=2", roots)
	}
	// 幂等:再种一次零新增
	if _, again, _ := eng.SeedTemplate(ctx, "case-1", "t-two", "tester"); again != 0 {
		t.Fatalf("模板实例化不幂等(roots=%d)", again)
	}
	nodes, edges, _ := eng.Graph(ctx, "case-1")
	if len(nodes) != 3 { // goal + a + c(b 是 a 完成后才派生)
		t.Fatalf("节点数=%d,应=3(goal+2根)", len(nodes))
	}
	var aNode, cNode *Node
	for _, n := range nodes {
		switch n.TemplateKey {
		case "a":
			aNode = n
		case "c":
			cNode = n
		}
	}
	if aNode == nil || cNode == nil {
		t.Fatal("根意图缺失")
	}
	if aNode.Status != StatusOpen {
		t.Fatalf("普通根意图应 open,得 %s", aNode.Status)
	}
	if cNode.Status != StatusAwaitingApproval {
		t.Fatalf("scope=all 根意图应挂审批门,得 %s", cNode.Status)
	}
	spawns := 0
	for _, e := range edges {
		if e.Kind == EdgeSpawns && e.FromID == goal.ID {
			spawns++
		}
	}
	if spawns != 2 {
		t.Fatalf("goal spawns 边=%d,应=2", spawns)
	}
	eng.Close()
}

// ---- worker 全链:执行→评估→写回 fact→派生子意图 ----

func TestWorkerFullCycle(t *testing.T) {
	eng, fs, fa, fau := testEngine(map[string]*Template{"t-two": twoLevelTpl})
	eng.Start(context.Background())
	defer eng.Close()
	ctx := context.Background()
	if _, _, err := eng.SeedTemplate(ctx, "case-1", "t-two", "tester"); err != nil {
		t.Fatal(err)
	}
	// 等 a 跑完(supported)、b 被派生并跑完
	err := waitFor(func() bool {
		nodes, _ := fs.ListNodes(ctx, "case-1")
		var bDone bool
		for _, n := range nodes {
			if n.TemplateKey == "b" && (n.Status == StatusSupported ||
				n.Status == StatusDenied || n.Status == StatusDoubt) {
				bDone = true
			}
		}
		return bDone
	}, "模板子意图 b 派生并跑完")
	if err != nil {
		t.Fatal(err)
	}
	nodes, edges, _ := eng.Graph(ctx, "case-1")
	var aNode, fact, aiChild *Node
	facts, proves, yields := 0, 0, 0
	for _, n := range nodes {
		if n.TemplateKey == "a" {
			aNode = n
		}
		if n.Kind == KindFact {
			facts++
			if fact == nil {
				fact = n
			}
		}
		if n.CreatedBy == ByAI && n.Kind == KindIntent {
			aiChild = n
		}
	}
	if aNode.Status != StatusSupported {
		t.Fatalf("意图 a 终态=%s,应=supported", aNode.Status)
	}
	if len(aNode.Evidence) != 1 || aNode.Evidence[0].SourceID != "src-1" {
		t.Fatalf("意图 a 锚点写回不对: %+v", aNode.Evidence)
	}
	if facts == 0 {
		t.Fatal("无 fact 写回")
	}
	if aiChild == nil {
		t.Fatal("AI 子意图未派生")
	}
	for _, e := range edges {
		if e.Kind == EdgeProves {
			proves++
		}
		if e.Kind == EdgeYields {
			yields++
		}
	}
	if proves == 0 || yields == 0 {
		t.Fatalf("血缘边缺失: yields=%d proves=%d", yields, proves)
	}
	// 证据图锚点落账(evidence 类)
	hasEvidence := false
	for _, a := range fs.anchors {
		if a.kind == "evidence" && a.anchor.SourceID == "src-1" {
			hasEvidence = true
		}
	}
	if !hasEvidence {
		t.Fatal("证据图锚点未落账")
	}
	// 执行过程流落痕
	evs, _ := fs.ListEvents(ctx, aNode.ID)
	kinds := map[string]bool{}
	for _, e := range evs {
		kinds[e.Kind] = true
	}
	for _, want := range []string{"plan", "text", "eval", "spawn"} {
		if !kinds[want] {
			t.Fatalf("过程流缺 %s 事件(有 %v)", want, kinds)
		}
	}
	// 会话级预算快照 + 单意图单会话
	if len(fa.sessions) < 2 {
		t.Fatalf("单意图单会话未成立(会话数=%d)", len(fa.sessions))
	}
	for _, b := range fa.budgets {
		if b != DefaultTokenBudget {
			t.Fatalf("worker 会话 token 预算=%d,应=%d", b, DefaultTokenBudget)
		}
	}
	// systemExtra 带意图上下文
	if !strings.Contains(fa.extras[fa.sessions[0]], "意图链任务") {
		t.Fatal("worker system 段缺意图上下文")
	}
	// 审计:intent.start/finish 在链
	for _, want := range []string{"intent.start", "intent.finish", "intent.seed_template"} {
		if !fau.has(want) {
			t.Fatalf("审计缺 %s", want)
		}
	}
}

// ---- §6.2:无锚点 supported 降级 doubt;未按契约收尾记 doubt ----

func TestVerdictDowngradeWithoutAnchors(t *testing.T) {
	eng, fs, fa, _ := testEngine(nil)
	eng.Start(context.Background())
	defer eng.Close()
	fa.runFn = func(_, _, _ string, _ <-chan string) []AIEvent {
		return []AIEvent{{Kind: "text", Text: "```json\n" +
			`{"verdict":"supported","summary":"拍脑袋说有","anchors":[],"children":[]}` +
			"\n```"}}
	}
	ctx := context.Background()
	n, err := eng.CreateHuman(ctx, "case-1", "tester", "随便查查", "", 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := waitFor(func() bool {
		got, _ := fs.GetNode(ctx, n.ID)
		return got.Status == StatusDoubt
	}, "无锚点 supported 降级 doubt"); err != nil {
		t.Fatal(err)
	}
	got, _ := fs.GetNode(ctx, n.ID)
	if !strings.Contains(got.CloseNote, "降级") {
		t.Fatalf("降级说明缺失: %q", got.CloseNote)
	}
}

func TestVerdictGarbageIsDoubt(t *testing.T) {
	eng, fs, fa, _ := testEngine(nil)
	eng.Start(context.Background())
	defer eng.Close()
	fa.runFn = func(_, _, _ string, _ <-chan string) []AIEvent {
		return []AIEvent{{Kind: "text", Text: "我不会按格式收尾"}}
	}
	ctx := context.Background()
	n, _ := eng.CreateHuman(ctx, "case-1", "tester", "随便查查", "", 0, "", "")
	if err := waitFor(func() bool {
		got, _ := fs.GetNode(ctx, n.ID)
		return got.Status == StatusDoubt
	}, "未按契约收尾记 doubt"); err != nil {
		t.Fatal(err)
	}
}

// ---- 意图级 wall-clock:耗尽 → closed_exhausted 如实标 ----

func TestWallClockExhausted(t *testing.T) {
	eng, fs, fa, _ := testEngine(nil)
	eng.Start(context.Background())
	defer eng.Close()
	fa.runFn = blockUntilAbort("已查到一半:发现可疑登录")
	ctx := context.Background()
	n, err := eng.CreateHuman(ctx, "case-1", "tester", "慢慢查", "", 1, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := waitFor(func() bool {
		got, _ := fs.GetNode(ctx, n.ID)
		return got.Status == StatusClosedExhausted
	}, "耗尽意图 closed_exhausted"); err != nil {
		t.Fatal(err)
	}
	got, _ := fs.GetNode(ctx, n.ID)
	if !strings.Contains(got.CloseNote, "时间耗尽") ||
		!strings.Contains(got.CloseNote, "覆盖可能不全") {
		t.Fatalf("耗尽如实标缺失: %q", got.CloseNote)
	}
	// 写回已得:部分结论落 fact
	nodes, _ := fs.ListNodes(ctx, "case-1")
	var fact *Node
	for _, x := range nodes {
		if x.Kind == KindFact {
			fact = x
		}
	}
	if fact == nil || !strings.Contains(fact.Text, "已查到一半") {
		t.Fatalf("耗尽未写回已得: %+v", fact)
	}
	// Abort 以预算名义发出
	if fa.aborts[fa.sessions[0]] != "intent-budget" {
		t.Fatalf("预算 Abort 名义不对: %v", fa.aborts)
	}
}

// ---- 人工停止 ----

func TestManualStop(t *testing.T) {
	eng, fs, fa, _ := testEngine(nil)
	eng.Start(context.Background())
	defer eng.Close()
	fa.runFn = blockUntilAbort("被查前的一点发现")
	ctx := context.Background()
	n, _ := eng.CreateHuman(ctx, "case-1", "tester", "慢慢查", "", 0, "", "")
	if err := waitFor(func() bool {
		got, _ := fs.GetNode(ctx, n.ID)
		return got.Status == StatusRunning
	}, "意图进入 running"); err != nil {
		t.Fatal(err)
	}
	if err := eng.Stop(ctx, n.ID, "tester"); err != nil {
		t.Fatal(err)
	}
	if err := waitFor(func() bool {
		got, _ := fs.GetNode(ctx, n.ID)
		return got.Status == StatusClosed
	}, "停止后关闭"); err != nil {
		t.Fatal(err)
	}
	got, _ := fs.GetNode(ctx, n.ID)
	if !strings.Contains(got.CloseNote, "人工停止") {
		t.Fatalf("停止说明缺失: %q", got.CloseNote)
	}
	// 不在跑再停:如实报错
	if err := eng.Stop(ctx, n.ID, "tester"); err == nil {
		t.Fatal("重复停止应如实报错")
	}
}

// ---- 审批门:挂起不派 → 批才跑/拒则关 ----

func TestApprovalGate(t *testing.T) {
	eng, fs, _, fau := testEngine(nil)
	eng.Start(context.Background())
	defer eng.Close()
	ctx := context.Background()
	// AI 派生 scope=all 意图(模拟 worker 子意图的审批门路径):
	// 直接造一个 awaiting_approval 节点(GateStatus 逻辑的产物)
	gated := &Node{CaseID: "case-1", Kind: KindIntent, Text: "批量核查全网",
		CreatedBy: ByAI, Scope: ScopeAll, Depth: 1}
	gated.Status = GateStatus(gated.CreatedBy, gated.Scope)
	if gated.Status != StatusAwaitingApproval {
		t.Fatalf("GateStatus 应挂审批门,得 %s", gated.Status)
	}
	if err := ValidateNode(gated); err != nil {
		t.Fatal(err)
	}
	if err := fs.CreateNode(ctx, gated); err != nil {
		t.Fatal(err)
	}
	eng.Wake("case-1")
	// 挂起期间不许被派(等 200ms 确认 planner 静默)
	time.Sleep(200 * time.Millisecond)
	got, _ := fs.GetNode(ctx, gated.ID)
	if got.Status != StatusAwaitingApproval {
		t.Fatalf("待批意图被擅自派发(状态 %s)", got.Status)
	}
	// 拒绝 → closed + 审计
	if _, err := eng.Approve(ctx, gated.ID, "tester", false); err != nil {
		t.Fatal(err)
	}
	got, _ = fs.GetNode(ctx, gated.ID)
	if got.Status != StatusClosed {
		t.Fatalf("拒绝后应 closed,得 %s", got.Status)
	}
	if !fau.has("intent.reject") {
		t.Fatal("拒绝未进审计")
	}
	// 再批:状态冲突如实报错
	if _, err := eng.Approve(ctx, gated.ID, "tester", true); err == nil {
		t.Fatal("非待批状态审批应如实报错")
	}
	// 批准路径:另造一条 → 批 → 被派跑完
	gated2 := &Node{CaseID: "case-1", Kind: KindIntent, Text: "批量核查二",
		CreatedBy: ByRule, Scope: ScopeAll, Depth: 1}
	gated2.Status = GateStatus(gated2.CreatedBy, gated2.Scope)
	_ = ValidateNode(gated2)
	if err := fs.CreateNode(ctx, gated2); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Approve(ctx, gated2.ID, "tester", true); err != nil {
		t.Fatal(err)
	}
	if err := waitFor(func() bool {
		got, _ := fs.GetNode(ctx, gated2.ID)
		return got.Status == StatusSupported
	}, "批准后派发跑完"); err != nil {
		t.Fatal(err)
	}
	if !fau.has("intent.approve") {
		t.Fatal("批准未进审计")
	}
}

// ---- 深度闸:深度 5 不再派生 ----

func TestDepthCap(t *testing.T) {
	eng, fs, _, _ := testEngine(nil)
	ctx := context.Background()
	deep := &Node{CaseID: "case-1", Kind: KindIntent, Text: "深度 5 意图",
		CreatedBy: ByHuman, Scope: ScopeCase, Depth: MaxDepth, Status: StatusOpen}
	if err := ValidateNode(deep); err != nil {
		t.Fatal(err)
	}
	if err := fs.CreateNode(ctx, deep); err != nil {
		t.Fatal(err)
	}
	eng.Start(context.Background())
	defer eng.Close()
	eng.Wake("case-1")
	if err := waitFor(func() bool {
		got, _ := fs.GetNode(ctx, deep.ID)
		return got.Status == StatusSupported
	}, "深度 5 意图跑完"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	nodes, _ := fs.ListNodes(ctx, "case-1")
	for _, n := range nodes {
		if n.Depth > MaxDepth {
			t.Fatalf("深度闸失效: 节点 %s 深度 %d", n.ID, n.Depth)
		}
	}
	// 人挂深度 5 的父:如实拒
	if _, err := eng.CreateHuman(ctx, "case-1", "tester", "再往下查", "", 0, deep.ID, ""); err == nil {
		t.Fatal("超深度手写意图应如实拒")
	}
}

// ---- 规则播种:同规则未终态去重 ----

func TestSeedRulesDedup(t *testing.T) {
	eng, fs, _, _ := testEngine(nil)
	defer eng.Close()
	ctx := context.Background()
	seeds := []RuleSeed{
		{RuleID: "web-bruteforce", Title: "爆破", HitsNew: 3},
		{RuleID: "web-sqli", Title: "注入", HitsNew: 0}, // 零新增不派
	}
	n, err := eng.SeedRules(ctx, "case-1", "tester", seeds)
	if err != nil || n != 1 {
		t.Fatalf("首播=%d(%v),应=1", n, err)
	}
	n, _ = eng.SeedRules(ctx, "case-1", "tester", seeds)
	if n != 0 {
		t.Fatalf("重复播种=%d,应=0(去重)", n)
	}
	nodes, _ := fs.ListNodes(ctx, "case-1")
	if len(nodes) != 1 || nodes[0].RuleID != "web-bruteforce" ||
		nodes[0].CreatedBy != ByRule {
		t.Fatalf("规则意图形态不对: %+v", nodes)
	}
}

// ---- 目的预设播种(交互改造·新建任务向导):落库即 goal,幂等,零派发 ----

func TestSeedGoals(t *testing.T) {
	eng, fs, _, fau := testEngine(nil)
	defer eng.Close()
	ctx := context.Background()

	// 正常播种:多条 goal,人提出,open
	n, err := eng.SeedGoals(ctx, "case-1", "tester",
		[]string{"确认入侵入口", " 确定影响范围 ", "确认入侵入口", "  "})
	if err != nil || n != 2 {
		t.Fatalf("首播=%d(%v),应=2(空/重复入参跳过)", n, err)
	}
	nodes, _ := fs.ListNodes(ctx, "case-1")
	if len(nodes) != 2 {
		t.Fatalf("goal 节点数=%d,应=2", len(nodes))
	}
	for _, g := range nodes {
		if g.Kind != KindGoal || g.CreatedBy != ByHuman || g.Status != StatusOpen {
			t.Fatalf("goal 形态不对: %+v", g)
		}
		if strings.TrimSpace(g.Text) != g.Text {
			t.Fatalf("goal 文本未修剪: %q", g.Text)
		}
	}
	// 幂等:同案同文本不重复种(部分重叠也只补新)
	n, _ = eng.SeedGoals(ctx, "case-1", "tester",
		[]string{"确认入侵入口", "攻击时间线"})
	if n != 1 {
		t.Fatalf("二播=%d,应=1(同文本幂等)", n)
	}
	// 审计留痕:有新增才记
	if !fau.has("intent.seed_goals") {
		t.Fatal("播种未进审计链")
	}
	// 零派发纪律:goal 不可领(NextRunnable 只领 intent)
	if r, _ := fs.NextRunnable(ctx, "case-1"); r != nil {
		t.Fatalf("goal 不应可派发,得 %+v", r)
	}
	// 隔离:他案不可见
	nodes2, _ := fs.ListNodes(ctx, "case-2")
	if len(nodes2) != 0 {
		t.Fatalf("跨案泄漏: case-2 节点数=%d", len(nodes2))
	}
}

// ---- 案件级 deadline:到点停派 + 审计一次 ----

func TestCaseDeadlineWrapUp(t *testing.T) {
	eng, fs, _, fau := testEngine(nil)
	defer eng.Close()
	ctx := context.Background()
	past := time.Now().Add(-time.Minute)
	if err := eng.SetCaseDeadline(ctx, "case-1", &past); err != nil {
		t.Fatal(err)
	}
	n := &Node{CaseID: "case-1", Kind: KindIntent, Text: "不该被派",
		CreatedBy: ByHuman, Scope: ScopeCase, Depth: 1, Status: StatusOpen}
	_ = ValidateNode(n)
	if err := fs.CreateNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	eng.Start(context.Background())
	defer eng.Close()
	eng.Wake("case-1")
	time.Sleep(200 * time.Millisecond)
	got, _ := fs.GetNode(ctx, n.ID)
	if got.Status != StatusOpen {
		t.Fatalf("deadline 到点仍派发(状态 %s)", got.Status)
	}
	if !fau.has("intent.case_deadline") {
		t.Fatal("收尾模式未进审计")
	}
}

// ---- 归档闸(0.18.0):归档案停派新意图,解归档恢复派发 ----

func TestCaseArchivedNoDispatch(t *testing.T) {
	eng, fs, _, _ := testEngine(nil)
	defer eng.Close()
	ctx := context.Background()
	fs.archived["case-1"] = true
	n := &Node{CaseID: "case-1", Kind: KindIntent, Text: "归档案不该被派",
		CreatedBy: ByHuman, Scope: ScopeCase, Depth: 1, Status: StatusOpen}
	_ = ValidateNode(n)
	if err := fs.CreateNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	eng.Start(context.Background())
	defer eng.Close()
	eng.Wake("case-1")
	time.Sleep(200 * time.Millisecond)
	got, _ := fs.GetNode(ctx, n.ID)
	if got.Status != StatusOpen {
		t.Fatalf("归档案仍派发(状态 %s)", got.Status)
	}
	// 解归档即恢复:同一意图被领走
	fs.archived["case-1"] = false
	eng.Wake("case-1")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got, _ := fs.GetNode(ctx, n.ID)
		if got.Status != StatusOpen {
			return // 已派发(running 或终态都算闸开了)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("解归档后仍未派发")
}

// ---- 收尾契约解析单测 ----

func TestExtractVerdict(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		{"围栏块", "前言\n```json\n{\"verdict\":\"denied\",\"summary\":\"无异常\"}\n```\n尾", "denied"},
		{"裸 JSON 兜底", "结论 {\"verdict\":\"doubt\",\"summary\":\"数据未覆盖\"} 完", "doubt"},
		{"取最后一个", "```json\n{\"verdict\":\"supported\",\"anchors\":[]}\n```\n后又改口\n" +
			"```json\n{\"verdict\":\"doubt\"}\n```", "doubt"},
		{"无法解析", "没有契约", ""},
	}
	for _, c := range cases {
		got := extractVerdict(c.text)
		if got.Verdict != c.want {
			t.Fatalf("%s: verdict=%q,应=%q", c.name, got.Verdict, c.want)
		}
	}
}

// ---- 切片七:意图主机范围(host_scope,§3 修正稿一案多包) ----

// TestHostScope_EachExpand 模板 host_scope=each 的根意图按已建模主机
// 逐台展开(template_key 带 @主机后缀);零主机案件如实不派。
func TestHostScope_EachExpand(t *testing.T) {
	tpl := &Template{ID: "t-each", Goal: "g", Intents: []TemplateIntent{
		{Key: "per-host", Text: "查本机驻留", HostScope: "each"},
		{Key: "cross", Text: "横向移动联动", HostScope: "all", After: []string{"per-host"}},
	}}
	if err := tpl.Validate(); err != nil {
		t.Fatal(err)
	}
	eng, fs, _, _ := testEngine(map[string]*Template{"t-each": tpl})
	defer eng.Close()
	fs.hosts["case-1"] = []string{"10.0.0.1", "10.0.0.2"}

	ctx := context.Background()
	_, roots, err := eng.SeedTemplate(ctx, "case-1", "t-each", "tester")
	if err != nil {
		t.Fatal(err)
	}
	if roots != 1 { // each 展开计一条根(内部两台)
		t.Fatalf("根意图计数不符: %d", roots)
	}
	nodes, _ := fs.ListNodes(ctx, "case-1")
	perHost := map[string]string{}
	var cross *Node
	for _, n := range nodes {
		if n.TemplateKey == "per-host@10.0.0.1" || n.TemplateKey == "per-host@10.0.0.2" {
			perHost[n.HostScope] = n.ID
		}
		if strings.HasPrefix(n.TemplateKey, "cross") {
			cross = n
		}
	}
	if len(perHost) != 2 || perHost["10.0.0.1"] == "" || perHost["10.0.0.2"] == "" {
		t.Fatalf("each 未按主机展开: %+v", nodes)
	}
	// all ≡ 全案件(host_scope 空)
	for _, n := range nodes {
		if n.TemplateKey == "cross" && n.HostScope != "" {
			t.Fatalf("host_scope=all 应归一为空(全案件): %q", n.HostScope)
		}
	}
	_ = cross // cross 是 after 子意图,播种阶段不展开

	// 零主机案件:each 如实不派
	eng2, fs2, _, _ := testEngine(map[string]*Template{"t-each": tpl})
	defer eng2.Close()
	if _, _, err := eng2.SeedTemplate(ctx, "case-2", "t-each", "tester"); err != nil {
		t.Fatal(err)
	}
	nodes2, _ := fs2.ListNodes(ctx, "case-2")
	for _, n := range nodes2 {
		if n.Kind == KindIntent {
			t.Fatalf("零主机案件 each 不应派生意图: %+v", n)
		}
	}
}

// TestHostScope_WorkerSession 主机范围意图的 worker 会话绑定主机
// (CreateSessionBudget hostScope 透传),systemExtra 带主机范围段;
// AI 子意图继承父主机范围。
func TestHostScope_WorkerSession(t *testing.T) {
	eng, fs, fa, _ := testEngine(nil)
	eng.Start(context.Background())
	defer eng.Close()
	ctx := context.Background()

	n, err := eng.CreateHuman(ctx, "case-1", "tester", "查这台机的认证链", "",
		0, "", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := waitFor(func() bool {
		got, _ := fs.GetNode(ctx, n.ID)
		return got.Status == StatusSupported || got.Status == StatusDoubt ||
			got.Status == StatusDenied
	}, "主机范围意图跑完"); err != nil {
		t.Fatal(err)
	}
	if len(fa.hostScopes) == 0 || fa.hostScopes[len(fa.hostScopes)-1] != "10.0.0.1" {
		t.Fatalf("worker 会话未绑定主机范围: %v", fa.hostScopes)
	}
	extra := fa.extras[fa.sessions[len(fa.sessions)-1]]
	if !strings.Contains(extra, "主机范围") || !strings.Contains(extra, "10.0.0.1") {
		t.Fatalf("systemExtra 缺主机范围段: %s", extra)
	}
	// 默认收尾契约 children 为空 → 无子意图;再验证一次继承路径:
	// 直接给父节点派生 AI 子意图走 spawnChildren 由引擎内部完成,
	// 这里验证节点面:父节点 host_scope 落库
	got, _ := fs.GetNode(ctx, n.ID)
	if got.HostScope != "10.0.0.1" {
		t.Fatalf("节点 host_scope 未落库: %q", got.HostScope)
	}
}

// TestHostScope_AIChildInherit AI 派生子意图继承父主机范围。
func TestHostScope_AIChildInherit(t *testing.T) {
	eng, fs, fa, _ := testEngine(nil)
	eng.Start(context.Background())
	defer eng.Close()
	fa.runFn = func(_, _, _ string, _ <-chan string) []AIEvent {
		return []AIEvent{{Kind: "text", Text: "```json\n" +
			`{"verdict":"denied","summary":"查过没有","anchors":[],` +
			`"children":["接着查同机进程树"]}` + "\n```"}}
	}
	ctx := context.Background()
	n, err := eng.CreateHuman(ctx, "case-1", "tester", "查认证面", "",
		0, "", "10.0.0.9")
	if err != nil {
		t.Fatal(err)
	}
	if err := waitFor(func() bool {
		nodes, _ := fs.ListNodes(ctx, "case-1")
		for _, x := range nodes {
			if x.ParentID == n.ID && x.Kind == KindIntent {
				return true
			}
		}
		return false
	}, "AI 子意图派生"); err != nil {
		t.Fatal(err)
	}
	nodes, _ := fs.ListNodes(ctx, "case-1")
	for _, x := range nodes {
		if x.ParentID == n.ID && x.Kind == KindIntent {
			if x.HostScope != "10.0.0.9" {
				t.Fatalf("AI 子意图未继承主机范围: %q", x.HostScope)
			}
		}
	}
}
