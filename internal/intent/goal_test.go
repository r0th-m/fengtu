// goal 收官状态机契约测试(0.29.1-goal-lifecycle):
//   - 全终态触发收官(met/partial/unmet 按 supported 比例定档);
//   - 有 open/running/awaiting_approval 不收;parked 不挡收官(与
//     chapterComplete 同口径);零意图 goal 不收官(没开查不装查完);
//   - 幂等(重估第二次零变化);人定状态(如手动 closed 的 goal)不动;
//   - 已收官 goal 子树重新出现未终态意图 → 如实重开回 open;
//   - 终态节点不进派发队列(NextRunnable 只领 open intent,天然免疫,
//     此处焊死 goal 收官态不被领走)。
package intent

import (
	"context"
	"testing"
	"time"
)

// mkGoalCase 造一章:goal + 给定状态的 intent 子节点(spawns 血缘由
// ParentID 承担,inChapter 按 parent 链上溯)。
func mkGoalCase(t *testing.T, fs *fakeStore, caseID, goalText string,
	statuses ...string) *Node {

	t.Helper()
	ctx := context.Background()
	goal := &Node{CaseID: caseID, Kind: KindGoal, Text: goalText,
		Status: StatusOpen, CreatedBy: ByHuman, Scope: ScopeCase, Depth: 0}
	if err := fs.CreateNode(ctx, goal); err != nil {
		t.Fatal(err)
	}
	for _, st := range statuses {
		n := &Node{CaseID: caseID, Kind: KindIntent, Text: "查 " + st,
			Status: st, CreatedBy: ByAI, Scope: ScopeCase,
			ParentID: goal.ID, Depth: 1}
		if err := fs.CreateNode(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	return goal
}

func TestReevalGoalsAllSupportedMet(t *testing.T) {
	eng, fs, _, fau := testEngine(nil)
	ctx := context.Background()
	g := mkGoalCase(t, fs, "c1", "确认入侵入口",
		StatusSupported, StatusSupported)

	n, err := eng.ReevalGoals(ctx, "c1")
	if err != nil || n != 1 {
		t.Fatalf("应收官 1 个 goal: n=%d err=%v", n, err)
	}
	got, _ := fs.GetNode(ctx, g.ID)
	if got.Status != StatusClosedGoalMet {
		t.Fatalf("全 supported 应 closed_goal_met: %s", got.Status)
	}
	if got.CloseNote == "" || got.FinishedAt == nil {
		t.Fatalf("收官应带机器评估说明与收官时刻: %+v", got)
	}
	if !fau.has("intent.goal_close") {
		t.Fatalf("收官应进审计链")
	}
	// 幂等:再估零变化
	n, err = eng.ReevalGoals(ctx, "c1")
	if err != nil || n != 0 {
		t.Fatalf("幂等重估应零变化: n=%d err=%v", n, err)
	}
	// 收官态不进派发队列(NextRunnable 只领 open intent)
	if r, _ := fs.NextRunnable(ctx, "c1"); r != nil {
		t.Fatalf("goal 收官态不应被派发: %+v", r)
	}
}

func TestReevalGoalsPartialAndUnmet(t *testing.T) {
	eng, fs, _, _ := testEngine(nil)
	ctx := context.Background()
	gp := mkGoalCase(t, fs, "c1", "章A(部分支持)",
		StatusSupported, StatusDenied, StatusDoubt)
	gu := mkGoalCase(t, fs, "c1", "章B(零支持)",
		StatusDenied, StatusClosed, StatusClosedExhausted, StatusStopped)

	n, err := eng.ReevalGoals(ctx, "c1")
	if err != nil || n != 2 {
		t.Fatalf("应收官 2 个 goal: n=%d err=%v", n, err)
	}
	got, _ := fs.GetNode(ctx, gp.ID)
	if got.Status != StatusClosedGoalPartial {
		t.Fatalf("部分 supported 应 closed_goal_partial: %s", got.Status)
	}
	got, _ = fs.GetNode(ctx, gu.ID)
	if got.Status != StatusClosedGoalUnmet {
		t.Fatalf("零 supported 应 closed_goal_unmet: %s", got.Status)
	}
}

func TestReevalGoalsUnfinishedBlocks(t *testing.T) {
	for _, st := range []string{StatusOpen, StatusRunning, StatusAwaitingApproval} {
		eng, fs, _, _ := testEngine(nil)
		ctx := context.Background()
		g := mkGoalCase(t, fs, "c1", "确认入口", StatusSupported, st)
		n, err := eng.ReevalGoals(ctx, "c1")
		if err != nil || n != 0 {
			t.Fatalf("有 %s 未终态不应收官: n=%d err=%v", st, n, err)
		}
		got, _ := fs.GetNode(ctx, g.ID)
		if got.Status != StatusOpen {
			t.Fatalf("有 %s 未终态 goal 应保持 open: %s", st, got.Status)
		}
	}
}

func TestReevalGoalsParkedDoesNotBlock(t *testing.T) {
	eng, fs, _, _ := testEngine(nil)
	ctx := context.Background()
	// parked 未展开不挡收官(与 chapterComplete 同口径)
	g := mkGoalCase(t, fs, "c1", "确认入口", StatusSupported, StatusParked)
	n, err := eng.ReevalGoals(ctx, "c1")
	if err != nil || n != 1 {
		t.Fatalf("parked 不挡收官: n=%d err=%v", n, err)
	}
	got, _ := fs.GetNode(ctx, g.ID)
	if got.Status != StatusClosedGoalMet {
		t.Fatalf("唯一已终态意图 supported,应 closed_goal_met: %s", got.Status)
	}
}

func TestReevalGoalsZeroIntentStaysOpen(t *testing.T) {
	eng, fs, _, _ := testEngine(nil)
	ctx := context.Background()
	g := mkGoalCase(t, fs, "c1", "空章(零意图)")
	n, err := eng.ReevalGoals(ctx, "c1")
	if err != nil || n != 0 {
		t.Fatalf("零意图 goal 不收官: n=%d err=%v", n, err)
	}
	got, _ := fs.GetNode(ctx, g.ID)
	if got.Status != StatusOpen {
		t.Fatalf("零意图 goal 应如实留 open: %s", got.Status)
	}
}

func TestReevalGoalsReopenOnNewWork(t *testing.T) {
	eng, fs, _, fau := testEngine(nil)
	ctx := context.Background()
	g := mkGoalCase(t, fs, "c1", "确认入口", StatusSupported)
	if _, err := eng.ReevalGoals(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	got, _ := fs.GetNode(ctx, g.ID)
	if got.Status != StatusClosedGoalMet {
		t.Fatalf("前置:应收官 met: %s", got.Status)
	}
	// 停车场展开/手写新意图:章内重新出现未终态意图 → goal 如实重开
	fresh := &Node{CaseID: "c1", Kind: KindIntent, Text: "展开的线索",
		Status: StatusOpen, CreatedBy: ByHuman, Scope: ScopeCase,
		ParentID: g.ID, Depth: 1}
	if err := fs.CreateNode(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	n, err := eng.ReevalGoals(ctx, "c1")
	if err != nil || n != 1 {
		t.Fatalf("重开应计 1 变化: n=%d err=%v", n, err)
	}
	got, _ = fs.GetNode(ctx, g.ID)
	if got.Status != StatusOpen || got.FinishedAt != nil || got.CloseNote != "" {
		t.Fatalf("应重开回 open 且清空收官痕迹: %+v", got)
	}
	if !fau.has("intent.goal_reopen") {
		t.Fatalf("重开应进审计链")
	}
	// 再收官:新意图跑完 supported → 回到 met(重估非一锤子)
	if err := fs.FinishNode(ctx, fresh.ID, StatusSupported, "查完", "",
		nil, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.ReevalGoals(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	got, _ = fs.GetNode(ctx, g.ID)
	if got.Status != StatusClosedGoalMet {
		t.Fatalf("重开后全终态应再收官 met: %s", got.Status)
	}
}

func TestReevalGoalsHumanTouchedUntouched(t *testing.T) {
	eng, fs, _, _ := testEngine(nil)
	ctx := context.Background()
	// 人手动关闭的 goal(非 open/非机器评估态):重估不动,判断权归人
	g := mkGoalCase(t, fs, "c1", "人定关闭的章", StatusSupported)
	if err := fs.FinishNode(ctx, g.ID, StatusClosed, "", "人手动收官", nil,
		time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	n, err := eng.ReevalGoals(ctx, "c1")
	if err != nil || n != 0 {
		t.Fatalf("人定状态不应被动: n=%d err=%v", n, err)
	}
	got, _ := fs.GetNode(ctx, g.ID)
	if got.Status != StatusClosed || got.CloseNote != "人手动收官" {
		t.Fatalf("人定 closed 应原样保留: %+v", got)
	}
}

func TestGoalVerdictTable(t *testing.T) {
	cases := []struct {
		total, supported int
		want             string
	}{
		{3, 3, StatusClosedGoalMet},
		{1, 1, StatusClosedGoalMet},
		{3, 1, StatusClosedGoalPartial},
		{3, 0, StatusClosedGoalUnmet},
		{2, 0, StatusClosedGoalUnmet},
	}
	for _, c := range cases {
		if got := goalVerdict(c.total, c.supported); got != c.want {
			t.Fatalf("goalVerdict(%d,%d)=%s 应 %s", c.total, c.supported, got, c.want)
		}
	}
}

func TestNormalizeChapterTitle(t *testing.T) {
	cases := []struct{ in, want string }{
		{"建议归属:横向移动排查", "横向移动排查"},   // 半角冒号
		{"建议归属:横向移动排查", "横向移动排查"},   // 全角冒号
		{"  建议归属: 新开章名称 ", "新开章名称"}, // 空白一并清
		{"确认入侵入口", "确认入侵入口"},          // 无前缀不动
		{"建议归属:", ""},                        // 剥完为空(调用方兜底线索文本)
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeChapterTitle(c.in); got != c.want {
			t.Fatalf("normalizeChapterTitle(%q)=%q 应 %q", c.in, got, c.want)
		}
	}
}
