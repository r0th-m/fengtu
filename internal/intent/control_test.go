// 切片三(运行中操控,设计 §3)焊死:steer 纠偏(中断当前轮同会话续跑)/
// kill 扩展(open 未派发直接关闭)/add_hint 线索挂图/操作约束 CRUD/
// worker system 注入(约束+线索)/约束查询失败 fail-closed。
package intent

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// ---- steer 纠偏 ----

// TestSteer 在跑意图纠偏:Cancel 中断当前轮 → 同会话续跑(纠偏文本=新 user
// 消息)→ 终态按终轮收尾契约;审计 intent.steer;过程流留 steer 步。
func TestSteer(t *testing.T) {
	eng, fs, fa, fau := testEngine(nil)
	eng.Start(context.Background())
	defer eng.Close()
	var mu sync.Mutex
	prompts := map[string][]string{} // sessID → 各轮 prompt(子意图另开会话,不混账)
	fa.runFn = func(sessID string, prompt, _ string, abort <-chan string) []AIEvent {
		mu.Lock()
		prompts[sessID] = append(prompts[sessID], prompt)
		first := len(prompts) == 1 && len(prompts[sessID]) == 1 // 全局面首轮(原意图第一轮)
		mu.Unlock()
		if first {
			<-abort // 第一轮阻塞到纠偏 Cancel
			return []AIEvent{{Kind: "text", Text: "被查了一半的旧方向"},
				{Kind: "result", Reason: "aborted_streaming"}}
		}
		return []AIEvent{{Kind: "text", Text: defaultVerdictText}}
	}
	ctx := context.Background()
	n, _ := eng.CreateHuman(ctx, "case-1", "tester", "查外联", "", 0, "", "")
	if err := waitFor(func() bool {
		got, _ := fs.GetNode(ctx, n.ID)
		return got.Status == StatusRunning
	}, "意图进入 running"); err != nil {
		t.Fatal(err)
	}
	if err := eng.Steer(ctx, n.ID, "tester", "别查外联了,先查持久化"); err != nil {
		t.Fatalf("纠偏失败: %v", err)
	}
	if err := waitFor(func() bool {
		got, _ := fs.GetNode(ctx, n.ID)
		return got.Status == StatusSupported
	}, "纠偏后续跑写回 supported"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	sp := prompts[fa.sessions[0]] // 原意图会话(子意图另开会话,不混账)
	if len(sp) != 2 {
		t.Fatalf("原意图应跑两轮(原方向+纠偏),实跑 %d: %v", len(sp), sp)
	}
	if !strings.Contains(sp[1], "别查外联了,先查持久化") ||
		!strings.Contains(sp[1], "人工纠偏") {
		t.Fatalf("第二轮 prompt 应带纠偏文本: %q", sp[1])
	}
	if len(fa.cancels) != 1 || fa.cancels[0] != fa.sessions[0] {
		t.Fatalf("纠偏应 Cancel 同一会话(非 Abort): cancels=%v aborts=%v",
			fa.cancels, fa.aborts)
	}
	if _, aborted := fa.aborts[fa.sessions[0]]; aborted {
		t.Fatalf("纠偏不应 Abort(会话账不动): %v", fa.aborts)
	}
	if !fau.has("intent.steer") {
		t.Fatal("纠偏应进审计哈希链(intent.steer)")
	}
	// 过程流留 steer 步
	evs, _ := fs.ListEvents(ctx, n.ID)
	found := false
	for _, ev := range evs {
		if ev.Kind == "steer" && strings.Contains(ev.Text, "先查持久化") {
			found = true
		}
	}
	if !found {
		t.Fatal("过程流应留 steer 步(人工纠偏)")
	}
}

// TestSteerRejected 非在跑意图纠偏如实拒;空文本拒。
func TestSteerRejected(t *testing.T) {
	eng, _, _, _ := testEngine(nil) // 不 Start:意图停在 open
	ctx := context.Background()
	n, _ := eng.CreateHuman(ctx, "case-1", "tester", "排队中", "", 0, "", "")
	if err := eng.Steer(ctx, n.ID, "tester", ""); err == nil {
		t.Fatal("空纠偏应拒")
	}
	if err := eng.Steer(ctx, n.ID, "tester", "转向"); err == nil ||
		!strings.Contains(err.Error(), "不在运行中") {
		t.Fatalf("open 意图纠偏应如实拒: %v", err)
	}
	if err := eng.Steer(ctx, "ghost", "tester", "转向"); err == nil ||
		!strings.Contains(err.Error(), "无此意图") {
		t.Fatalf("幽灵意图纠偏应拒: %v", err)
	}
}

// TestStopWinsOverSteer 人工停止抢闸后纠偏如实拒(收尾中)。
func TestStopWinsOverSteer(t *testing.T) {
	eng, fs, fa, _ := testEngine(nil)
	eng.Start(context.Background())
	defer eng.Close()
	fa.runFn = blockUntilAbort("半截")
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
	if err := eng.Steer(ctx, n.ID, "tester", "转向"); err == nil {
		t.Fatal("停止抢闸后纠偏应如实拒")
	}
	if err := waitFor(func() bool {
		got, _ := fs.GetNode(ctx, n.ID)
		return got.Status == StatusClosed
	}, "停止后关闭"); err != nil {
		t.Fatal(err)
	}
}

// ---- kill 扩展:open 未派发直接关闭 ----

func TestStopOpenIntent(t *testing.T) {
	eng, fs, _, fau := testEngine(nil) // 不 Start:无人认领,停在 open
	ctx := context.Background()
	n, _ := eng.CreateHuman(ctx, "case-1", "tester", "先别跑", "", 0, "", "")
	if err := eng.Stop(ctx, n.ID, "tester"); err != nil {
		t.Fatalf("open 意图终止失败: %v", err)
	}
	got, _ := fs.GetNode(ctx, n.ID)
	if got.Status != StatusClosed || !strings.Contains(got.CloseNote, "未派发") {
		t.Fatalf("open 终止应关闭且如实标未消耗 AI: %+v", got)
	}
	if !fau.has("intent.stop") {
		t.Fatal("终止应进审计(intent.stop)")
	}
	// 已终态再停:如实拒
	if err := eng.Stop(ctx, n.ID, "tester"); err == nil {
		t.Fatal("重复停止应如实报错")
	}
	// goal 节点不可终止(kind≠intent,goal 不派发语义不动)
	if _, err := eng.SeedGoals(ctx, "case-1", "tester", []string{"查侵入点"}); err != nil {
		t.Fatal(err)
	}
	nodes, _ := fs.ListNodes(ctx, "case-1")
	var goalID string
	for _, x := range nodes {
		if x.Kind == KindGoal {
			goalID = x.ID
		}
	}
	if err := eng.Stop(ctx, goalID, "tester"); err == nil {
		t.Fatal("goal 节点应不可终止(不派发语义)")
	}
}

// ---- add_hint 补充线索 ----

func TestAddHint(t *testing.T) {
	eng, fs, _, fau := testEngine(nil)
	ctx := context.Background()
	// 孤儿(无 goal):如实挂图,不派发
	h1, err := eng.AddHint(ctx, "case-1", "tester", "客户说 20:00 左右断网", "")
	if err != nil {
		t.Fatal(err)
	}
	if h1.Kind != KindHint || h1.Status != StatusClosed || h1.ParentID != "" {
		t.Fatalf("孤儿 hint 形态不对: %+v", h1)
	}
	if n, _ := fs.NextRunnable(ctx, "case-1"); n != nil {
		t.Fatalf("hint 不可派发: %+v", n)
	}
	// 有 goal 后缺省锚首 goal(derived_from 边)
	if _, err := eng.SeedGoals(ctx, "case-1", "tester", []string{"确定影响范围"}); err != nil {
		t.Fatal(err)
	}
	h2, err := eng.AddHint(ctx, "case-1", "tester", "运维承认昨晚重启过网关", "")
	if err != nil {
		t.Fatal(err)
	}
	nodes, _ := fs.ListNodes(ctx, "case-1")
	var goalID string
	for _, x := range nodes {
		if x.Kind == KindGoal {
			goalID = x.ID
		}
	}
	if h2.ParentID != goalID {
		t.Fatalf("hint 应锚首 goal: parent=%q goal=%q", h2.ParentID, goalID)
	}
	edges, _ := fs.ListEdges(ctx, "case-1")
	found := false
	for _, e := range edges {
		if e.FromID == goalID && e.ToID == h2.ID && e.Kind == EdgeDerivedFrom {
			found = true
		}
	}
	if !found {
		t.Fatal("goal→hint derived_from 边缺失")
	}
	// 显式父节点 / 幽灵父节点 / 空文本
	if _, err := eng.AddHint(ctx, "case-1", "tester", "显式挂", h1.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.AddHint(ctx, "case-1", "tester", "挂幽灵", "ghost"); err == nil {
		t.Fatal("幽灵父节点应拒")
	}
	if _, err := eng.AddHint(ctx, "case-1", "tester", "  ", ""); err == nil {
		t.Fatal("空线索应拒")
	}
	if !fau.has("intent.add_hint") {
		t.Fatal("线索应进审计(intent.add_hint)")
	}
}

// ---- 操作约束 CRUD ----

func TestConstraints(t *testing.T) {
	eng, _, _, fau := testEngine(nil)
	ctx := context.Background()
	c1, err := eng.AddConstraint(ctx, "case-1", "tester", "生产库 10.0.0.5 只读,禁任何写")
	if err != nil {
		t.Fatal(err)
	}
	// 幂等:同案同文本不重复落
	c2, err := eng.AddConstraint(ctx, "case-1", "tester", "生产库 10.0.0.5 只读,禁任何写")
	if err != nil {
		t.Fatal(err)
	}
	if c1.ID != c2.ID {
		t.Fatalf("同文本约束应幂等: %q vs %q", c1.ID, c2.ID)
	}
	cs, err := eng.Constraints(ctx, "case-1")
	if err != nil || len(cs) != 1 {
		t.Fatalf("约束清单应为 1 条: %v %v", len(cs), err)
	}
	// 负样本:空文本
	if _, err := eng.AddConstraint(ctx, "case-1", "tester", " "); err == nil {
		t.Fatal("空约束应拒")
	}
	// 删除 + 幽灵删除
	if err := eng.RemoveConstraint(ctx, "case-1", c1.ID, "tester"); err != nil {
		t.Fatal(err)
	}
	if err := eng.RemoveConstraint(ctx, "case-1", c1.ID, "tester"); err == nil ||
		!strings.Contains(err.Error(), "无此约束") {
		t.Fatalf("幽灵删除应拒: %v", err)
	}
	cs, _ = eng.Constraints(ctx, "case-1")
	if len(cs) != 0 {
		t.Fatalf("删除后应空: %v", cs)
	}
	if !fau.has("intent.constraint.add") || !fau.has("intent.constraint.remove") {
		t.Fatalf("约束增删应进审计: %v", fau.actions)
	}
	// 上限 20 条
	for i := 0; i < constraintMaxPerCase; i++ {
		if _, err := eng.AddConstraint(ctx, "case-2", "tester",
			fmt.Sprintf("约束 %d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := eng.AddConstraint(ctx, "case-2", "tester", "第 21 条"); err == nil {
		t.Fatal("超上限应拒")
	}
}

// ---- worker system 注入:约束 + 线索 ----

func TestSystemExtraInjectsConstraintsAndHints(t *testing.T) {
	eng, _, fa, _ := testEngine(nil)
	eng.Start(context.Background())
	defer eng.Close()
	ctx := context.Background()
	if _, err := eng.AddConstraint(ctx, "case-1", "tester", "只看 20:00-21:00 时间窗"); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.AddHint(ctx, "case-1", "tester", "客户说断网在 20:00 左右", ""); err != nil {
		t.Fatal(err)
	}
	n, _ := eng.CreateHuman(ctx, "case-1", "tester", "查侵入点", "", 0, "", "")
	if err := waitFor(func() bool {
		got, _ := eng.deps.Store.GetNode(ctx, n.ID)
		return got.Status == StatusSupported
	}, "意图写回"); err != nil {
		t.Fatal(err)
	}
	extra := fa.extras[fa.sessions[0]]
	if !strings.Contains(extra, "操作约束") ||
		!strings.Contains(extra, "只看 20:00-21:00 时间窗") {
		t.Fatalf("systemExtra 应注入操作约束: %q", extra)
	}
	if !strings.Contains(extra, "人工线索") ||
		!strings.Contains(extra, "客户说断网在 20:00 左右") {
		t.Fatalf("systemExtra 应注入人工线索: %q", extra)
	}
}

// TestSystemExtraFailClosed 约束清单查询失败:宁可不跑(fail-closed),
// 意图 closed 如实标未执行(不裸奔违反「不得触碰」类约束)。
func TestSystemExtraFailClosed(t *testing.T) {
	eng, fs, fa, _ := testEngine(nil)
	eng.Start(context.Background())
	defer eng.Close()
	fs.constraintsErr = fmt.Errorf("合成:PG 连接断")
	ctx := context.Background()
	n, _ := eng.CreateHuman(ctx, "case-1", "tester", "查侵入点", "", 0, "", "")
	if err := waitFor(func() bool {
		got, _ := fs.GetNode(ctx, n.ID)
		return got.Status == StatusClosed
	}, "fail-closed 关闭"); err != nil {
		t.Fatal(err)
	}
	got, _ := fs.GetNode(ctx, n.ID)
	if !strings.Contains(got.CloseNote, "未执行") {
		t.Fatalf("应如实标未执行: %q", got.CloseNote)
	}
	if len(fa.prompts) != 0 {
		t.Fatalf("约束查询失败不应发起任何 AI 调用: %v", fa.prompts)
	}
}
