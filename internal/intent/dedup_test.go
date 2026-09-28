// 派生去重闸(0.28.0-blackboard)契约:归一化完全重复直接拦、关键词
// Jaccard ≥ 0.85 疑似重复转停车场人裁、不相似放行;parked 不占比对集;
// 只闸 AI 派生(人工手写同文本照过——判断权归人)。
package intent

import (
	"context"
	"strings"
	"testing"
)

func TestNormalizeIntentText(t *testing.T) {
	// 小写 + 去标点/空白/符号,只留字母数字(中英文同口径)
	if got := NormalizeIntentText("排查 计划任务,持久化!"); got != "排查计划任务持久化" {
		t.Fatalf("归一化应去标点空白: %q", got)
	}
	if got := NormalizeIntentText("Check RDP Logon-Events"); got != "checkrdplogonevents" {
		t.Fatalf("归一化应小写并去符号: %q", got)
	}
	if NormalizeIntentText("!!!。。。") != "" {
		t.Fatalf("全标点应归一化为空")
	}
}

func TestIntentKeywordsJaccard(t *testing.T) {
	// CJK 二字组 + ASCII 词:换皮重述应有高重合
	a := IntentKeywords("检查计划任务可疑项")
	b := IntentKeywords("检查计划任务可疑项目")
	if j := KeywordJaccard(a, b); j < DupJaccardThreshold {
		t.Fatalf("换皮重述相似度应超阈: %.3f", j)
	}
	c := IntentKeywords("排查勒索软件加密痕迹")
	if j := KeywordJaccard(a, c); j >= DupJaccardThreshold {
		t.Fatalf("不同方向不应超阈: %.3f", j)
	}
	if j := KeywordJaccard(IntentKeywords(""), a); j != 0 {
		t.Fatalf("空关键词集不比(0): %.3f", j)
	}
}

func TestCheckIntentDup(t *testing.T) {
	existing := []*Node{
		{ID: "n1", Kind: KindIntent, Text: "排查计划任务持久化", Status: StatusOpen},
		{ID: "n2", Kind: KindIntent, Text: "检查计划任务可疑项", Status: StatusClosed},
		{ID: "n3", Kind: KindIntent, Text: "排查计划任务持久化", Status: StatusParked}, // parked 不占比对
		{ID: "n4", Kind: KindFact, Text: "排查计划任务持久化", Status: StatusClosed},   // 非意图不占比对
	}
	// 完全重复(归一化相同,标点差异忽略)→ DupExact
	if dv, _, hit := CheckIntentDup("排查 计划任务·持久化!", existing); dv != DupExact || hit.ID != "n1" {
		t.Fatalf("完全重复应拦(dup_exact): dv=%v hit=%+v", dv, hit)
	}
	// 高度相似 → DupSimilar
	if dv, score, hit := CheckIntentDup("检查计划任务可疑项目", existing); dv != DupSimilar || hit.ID != "n2" {
		t.Fatalf("高度相似应转人裁(dup_similar): dv=%v score=%.3f hit=%+v", dv, score, hit)
	}
	// 不相似 → 放行
	if dv, _, _ := CheckIntentDup("查外联 C2 域名解析记录", existing); dv != DupNone {
		t.Fatalf("不同方向应放行: dv=%v", dv)
	}
	// parked/非意图同文本不构成重复(它们不占比对集)
	if dv, _, _ := CheckIntentDup("排查计划任务持久化",
		existing[2:]); dv != DupNone {
		t.Fatalf("parked/fact 不占比对集: dv=%v", dv)
	}
}

// 写侧集成:AI 派生重复意图被拦进停车场(reason=dup_exact/dup_similar),
// 不相似的照常进图;人工手写同文本不过闸(判断权归人)。
func TestSpawnChildrenDedupGate(t *testing.T) {
	eng, fs, _, _ := testEngine(nil)
	ctx := context.Background()
	parent := &Node{CaseID: "c1", Kind: KindIntent, Text: "章根意图",
		Status: StatusRunning, CreatedBy: ByAI, Scope: ScopeCase, Depth: 1}
	if err := fs.CreateNode(ctx, parent); err != nil {
		t.Fatal(err)
	}
	existing := &Node{CaseID: "c1", Kind: KindIntent, Text: "排查计划任务持久化",
		Status: StatusOpen, CreatedBy: ByRule, Scope: ScopeCase, Depth: 1}
	if err := fs.CreateNode(ctx, existing); err != nil {
		t.Fatal(err)
	}
	logf := func(string, string) {}
	eng.spawnChildren(ctx, parent, []string{
		"排查计划任务持久化!",  // 完全重复 → dup_exact
		"排查计划任务持久化吗",  // 高度相似(归一化仅多一字)→ dup_similar
		"查外联 C2 域名解析记录", // 不相似 → 照常进图
	}, logf)

	var parked, opened []*Node
	for _, n := range mustNodes(t, fs, "c1") {
		if n.ParentID != parent.ID {
			continue
		}
		switch n.Status {
		case StatusParked:
			parked = append(parked, n)
		default:
			opened = append(opened, n)
		}
	}
	if len(parked) != 2 || len(opened) != 1 {
		t.Fatalf("应拦 2 条放 1 条: parked=%d open=%d", len(parked), len(opened))
	}
	if opened[0].Text != "查外联 C2 域名解析记录" {
		t.Fatalf("放行的应是不同方向: %q", opened[0].Text)
	}
	entries, err := fs.ListParking(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]int{}
	for _, p := range entries {
		reasons[p.Reason]++
	}
	if reasons[ParkReasonDupExact] != 1 || reasons[ParkReasonDupSimilar] != 1 {
		t.Fatalf("停车场原因应 dup_exact/dup_similar 各一: %+v", reasons)
	}

	// 人工手写同文本:不过闸,照常 open(判断权归人)
	if _, err := eng.CreateHuman(ctx, "c1", "admin", "排查计划任务持久化",
		ScopeCase, 0, "", ""); err != nil {
		t.Fatalf("人工手写同文本意图不应被去重闸拦: %v", err)
	}
	humanDup := 0
	for _, n := range mustNodes(t, fs, "c1") {
		if n.CreatedBy == ByHuman && n.Status == StatusOpen &&
			strings.Contains(n.Text, "计划任务") {
			humanDup++
		}
	}
	if humanDup != 1 {
		t.Fatalf("人工意图应自由进图: %d", humanDup)
	}
}

func mustNodes(t *testing.T, fs *fakeStore, caseID string) []*Node {
	t.Helper()
	nodes, err := fs.ListNodes(context.Background(), caseID)
	if err != nil {
		t.Fatal(err)
	}
	return nodes
}
