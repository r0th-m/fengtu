// 案件黑板(0.28.0-blackboard)契约:四段派生(proves 确认事实/doubt 摘要/
// 在查已查清单/停车场待处置)、条目上限截断如实、注入总预算 4000 rune、
// worker systemExtra 注入位置(约束之后 KB 之前)与失败降级(不杀 worker)。
package intent

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// 合成黑板素材:proves 确认的 fact / 未确认 fact / doubt 意图 / open+running
// 意图 / parked 意图 / 停车场 parked+dismissed 条目。
func bbFixture() (nodes []*Node, edges []*Edge, parking []*ParkingEntry) {
	nodes = []*Node{
		{ID: "g1", CaseID: "c1", Kind: KindGoal, Text: "合成目标", Status: StatusOpen},
		{ID: "i1", CaseID: "c1", Kind: KindIntent, Text: "查侵入点", Status: StatusSupported},
		{ID: "f1", CaseID: "c1", Kind: KindFact, Text: "侵入点是钓鱼邮件附件",
			Status: StatusClosed,
			Evidence: []Anchor{{SourceID: "src-9", LineNo: 42}, {SourceID: "src-3"}}},
		{ID: "f2", CaseID: "c1", Kind: KindFact, Text: "未确认的事实不进黑板",
			Status: StatusClosed},
		{ID: "i2", CaseID: "c1", Kind: KindIntent, Text: "查横向移动", Status: StatusDoubt,
			ResultText: "日志缺口,无法确认"},
		{ID: "i3", CaseID: "c1", Kind: KindIntent, Text: "查持久化", Status: StatusOpen},
		{ID: "i4", CaseID: "c1", Kind: KindIntent, Text: "查外联通道", Status: StatusRunning},
		{ID: "i5", CaseID: "c1", Kind: KindIntent, Text: " parked 意图不占清单",
			Status: StatusParked},
	}
	edges = []*Edge{
		{ID: "e1", CaseID: "c1", FromID: "i1", ToID: "f1", Kind: EdgeYields},
		{ID: "e2", CaseID: "c1", FromID: "f1", ToID: "i1", Kind: EdgeProves},
	}
	parking = []*ParkingEntry{
		{ID: "p1", CaseID: "c1", NodeID: "i5", Text: "章外线索一条", Status: ParkingParked},
		{ID: "p2", CaseID: "c1", NodeID: "i9", Text: "已处置的不占黑板", Status: ParkingDismissed},
	}
	return nodes, edges, parking
}

func TestBuildBlackboard(t *testing.T) {
	nodes, edges, parking := bbFixture()
	bb := buildBlackboard("c1", nodes, edges, parking)

	// 已确认事实:只有 proves 边确认的 f1;f2 无 proves 不进
	if bb.FactsTotal != 1 || len(bb.Facts) != 1 || bb.Facts[0].NodeID != "f1" {
		t.Fatalf("已确认事实应只收 proves 确认的 fact: %+v", bb.Facts)
	}
	if len(bb.Facts[0].Anchors) != 2 {
		t.Fatalf("事实锚点应随行: %+v", bb.Facts[0].Anchors)
	}
	// 存疑发现:doubt 意图的摘要
	if bb.DoubtsTotal != 1 || bb.Doubts[0].Summary != "日志缺口,无法确认" {
		t.Fatalf("存疑发现应收 doubt 意图摘要: %+v", bb.Doubts)
	}
	// 在查/已查清单:非 parked 意图 4 条,在查(open/running)排前,parked 不占
	if bb.IntentsTotal != 4 {
		t.Fatalf("意图清单应收非 parked 意图 4 条: %+v", bb.Intents)
	}
	if bb.Intents[0].Status != StatusOpen || bb.Intents[1].Status != StatusRunning {
		t.Fatalf("在查(open/running)应排前: %+v", bb.Intents)
	}
	// 停车场:只收 parked 待处置
	if bb.ParkingTotal != 1 || bb.Parking[0].ID != "p1" {
		t.Fatalf("停车场应只收待处置条目: %+v", bb.Parking)
	}
}

func TestBuildBlackboardCaps(t *testing.T) {
	var nodes []*Node
	var edges []*Edge
	// 事实段:上限 30,造 35 条 proves 确认的 fact
	for i := 0; i < bbMaxFacts+5; i++ {
		fid := fmt.Sprintf("f%d", i)
		nodes = append(nodes,
			&Node{ID: fid, CaseID: "c1", Kind: KindFact, Text: "事实", Status: StatusClosed})
		edges = append(edges, &Edge{CaseID: "c1", FromID: fid, ToID: "x", Kind: EdgeProves})
	}
	// 意图段:上限 60,造 65 条
	for i := 0; i < bbMaxIntents+5; i++ {
		nodes = append(nodes, &Node{ID: fmt.Sprintf("i%d", i), CaseID: "c1",
			Kind: KindIntent, Text: "意图", Status: StatusSupported})
	}
	bb := buildBlackboard("c1", nodes, edges, nil)
	if len(bb.Facts) != bbMaxFacts || bb.FactsTotal != bbMaxFacts+5 {
		t.Fatalf("事实段应截到 %d 条且总数如实: len=%d total=%d",
			bbMaxFacts, len(bb.Facts), bb.FactsTotal)
	}
	if len(bb.Intents) != bbMaxIntents || bb.IntentsTotal != bbMaxIntents+5 {
		t.Fatalf("意图段应截到 %d 条且总数如实: len=%d total=%d",
			bbMaxIntents, len(bb.Intents), bb.IntentsTotal)
	}
}

func TestRenderBlackboardBudget(t *testing.T) {
	// 30 条 200 字事实 ≈ 6000+ rune,超 4000 总预算:截断并如实标注
	long := strings.Repeat("证", 200)
	bb := &Blackboard{CaseID: "c1"}
	for i := 0; i < bbMaxFacts; i++ {
		bb.Facts = append(bb.Facts, BlackboardFact{NodeID: fmt.Sprintf("f%d", i),
			Text: long, Anchors: []Anchor{{SourceID: "s", LineNo: 1}}})
	}
	bb.FactsTotal = bbMaxFacts
	out := RenderBlackboard(bb)
	if !strings.Contains(out, "总预算耗尽") {
		t.Fatalf("超总预算应如实标注: %q", out[:200])
	}
	// 条目+段头不超预算(截断标注是控制元信息,固定短小,允许 300 冗余)
	if n := utf8.RuneCountInString(out); n > bbBudgetRunes+300 {
		t.Fatalf("注入文本应受总预算约束: %d rune", n)
	}
}

func TestRenderBlackboardEmpty(t *testing.T) {
	out := RenderBlackboard(&Blackboard{CaseID: "c1"})
	for _, sec := range []string{"已确认事实", "存疑发现", "在查/已查意图清单", "停车场线索"} {
		if !strings.Contains(out, sec) {
			t.Fatalf("空黑板四段段头应都在: %q", out)
		}
	}
	if !strings.Contains(out, "(暂无)") {
		t.Fatalf("空段应如实写暂无: %q", out)
	}
}

func TestSystemExtraInjectsBlackboard(t *testing.T) {
	eng, fs, _, _ := testEngine(nil)
	ctx := context.Background()
	nodes, _, parking := bbFixture()
	for _, n := range nodes {
		n.CaseID = "case-1"
		if err := fs.CreateNode(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	// fake CreateNode 回写自增 ID:proves 边用落库后的真实 ID 挂
	fact := nodes[2]  // f1(有锚点的那条 fact)
	owner := nodes[1] // i1(supported 意图)
	for _, e := range []*Edge{
		{CaseID: "case-1", FromID: owner.ID, ToID: fact.ID, Kind: EdgeYields},
		{CaseID: "case-1", FromID: fact.ID, ToID: owner.ID, Kind: EdgeProves},
	} {
		if err := fs.CreateEdge(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range parking {
		p.CaseID = "case-1"
		if err := fs.CreateParking(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	extra, err := eng.systemExtra(ctx, &Node{CaseID: "case-1", Text: "查侵入点"})
	if err != nil {
		t.Fatal(err)
	}
	// 四段内容注入:事实带锚点、doubt 摘要、在查清单标状态、停车场线索
	for _, want := range []string{"案件黑板", "已确认事实", "侵入点是钓鱼邮件附件",
		"src-9:42", "存疑发现", "日志缺口,无法确认", "[open] 查持久化",
		"停车场线索", "章外线索一条"} {
		if !strings.Contains(extra, want) {
			t.Fatalf("黑板注入缺 %q", want)
		}
	}
	// 优先级措辞如实:低于约束与 hint,标注「本案实时状态」
	if !strings.Contains(extra, "优先级低于操作约束与人工线索") ||
		!strings.Contains(extra, "本案实时状态") {
		t.Fatalf("黑板优先级/实时性应如实标注")
	}
	// 位置:约束/hint 之后,收尾契约之前(与启发式平级段域)
	if strings.Index(extra, "案件黑板") > strings.Index(extra, "收尾契约") {
		t.Fatalf("黑板段应在收尾契约之前")
	}
}

func TestSystemExtraBlackboardQueryFailure(t *testing.T) {
	// 黑板派生查询失败(停车场清单断):如实标注,不杀 worker(同 KB 口径)
	eng, fs, _, _ := testEngine(nil)
	fs.parkingErr = fmt.Errorf("合成:PG 连接断")
	extra, err := eng.systemExtra(context.Background(),
		&Node{CaseID: "case-1", Text: "查侵入点"})
	if err != nil {
		t.Fatalf("黑板查询失败不应杀 systemExtra: %v", err)
	}
	if !strings.Contains(extra, "案件黑板查询失败") {
		t.Fatalf("黑板查询失败应如实标注: %q", extra)
	}
	// 收尾契约仍在(worker 照常开工)
	if !strings.Contains(extra, "收尾契约") {
		t.Fatalf("黑板失败不应影响其余段: %q", extra)
	}
}
