// 图变更订阅(切片 8b)焊死:播种/手写/审批的每一类图变更都要按时按型
// 广播到订阅者;退订后不再收;重复边(幂等跳过)不广播。
package intent

import (
	"context"
	"testing"
	"time"
)

// drainKinds 收满 n 帧或超时,返回帧 kind 序列(超时如实失败)。
func drainKinds(t *testing.T, ch <-chan GraphChange, n int) []GraphChange {
	t.Helper()
	out := []GraphChange{}
	deadline := time.After(2 * time.Second)
	for len(out) < n {
		select {
		case gc, open := <-ch:
			if !open {
				t.Fatalf("订阅通道被关(溢出?):已收 %v", out)
			}
			out = append(out, gc)
		case <-deadline:
			t.Fatalf("2s 内应收满 %d 帧,实得 %d: %v", n, len(out), out)
		}
	}
	return out
}

// drainUntil 收帧直到谓词命中并返回该帧(0.23.0 起 feed 播报帧与图帧同流,
// 按型滤过不计)。超时如实失败。
func drainUntil(t *testing.T, ch <-chan GraphChange, match func(GraphChange) bool) GraphChange {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case gc, open := <-ch:
			if !open {
				t.Fatalf("订阅通道被关(溢出?)")
			}
			if match(gc) {
				return gc
			}
		case <-deadline:
			t.Fatalf("2s 内未见目标帧")
		}
	}
}

func TestGraphWatchSeedTemplate(t *testing.T) {
	eng, _, _, _ := testEngine(map[string]*Template{"t-two": twoLevelTpl})
	ctx := context.Background()
	ch, cancel := eng.SubscribeGraph("case-1")
	defer cancel()

	goal, roots, err := eng.SeedTemplate(ctx, "case-1", "t-two", "tester")
	if err != nil || roots != 2 {
		t.Fatalf("播种失败: roots=%d err=%v", roots, err)
	}
	// goal 建点 + 2×(根意图建点+spawns 边) = 5 帧图帧;
	// 0.23.0 起播报帧(feed)随行同流:根 a/c 诞生档 + c(scope=all)审批档
	first := drainUntil(t, ch, func(gc GraphChange) bool { return true })
	if first.Kind != "node_added" || first.Node.Kind != KindGoal {
		t.Fatalf("首帧应为 goal 建点: %+v", first)
	}
	na, ea, feeds := 1, 0, 0
	deadline := time.After(2 * time.Second)
	for !(na == 3 && ea == 2) {
		select {
		case f := <-ch:
			switch f.Kind {
			case "node_added":
				na++
			case "edge_added":
				ea++
				if f.Edge.Kind != EdgeSpawns || f.Edge.ID == "" {
					t.Fatalf("边帧应带 id 的 spawns: %+v", f.Edge)
				}
			case "feed":
				feeds++
			default:
				t.Fatalf("意外帧型: %+v", f)
			}
		case <-deadline:
			t.Fatalf("2s 内图帧未齐: node_added=%d edge_added=%d", na, ea)
		}
	}
	if feeds != 3 { // 诞生 a + 诞生 c + c 待审批
		t.Fatalf("播报帧应为 3(诞生×2+待审批×1): %d", feeds)
	}
	_ = goal

	// 幂等再种:零新增 → 零帧(100ms 探空)
	if _, again, _ := eng.SeedTemplate(ctx, "case-1", "t-two", "tester"); again != 0 {
		t.Fatalf("再种不幂等")
	}
	select {
	case f := <-ch:
		t.Fatalf("幂等再种不应有帧: %+v", f)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestGraphWatchHumanAndApprove(t *testing.T) {
	eng, fs, _, _ := testEngine(nil)
	ctx := context.Background()
	ch, cancel := eng.SubscribeGraph("case-1")
	defer cancel()

	// 手写意图:建点(无父无边);0.23.0 起随行诞生档播报帧
	n, err := eng.CreateHuman(ctx, "case-1", "tester", "查 3306 外连", "", 30, "", "")
	if err != nil {
		t.Fatal(err)
	}
	added := drainUntil(t, ch, func(gc GraphChange) bool { return gc.Kind == "node_added" })
	if added.Node.ID != n.ID {
		t.Fatalf("手写意图应广播建点: %+v", added)
	}
	spawn := drainUntil(t, ch, func(gc GraphChange) bool {
		return gc.Kind == "feed" && gc.Feed != nil && gc.Feed.Tier == FeedSpawn
	})
	if spawn.Feed.NodeID != n.ID {
		t.Fatalf("诞生档播报应指向新意图: %+v", spawn.Feed)
	}

	// 审批门:awaiting_approval → 批准 → 审批档播报帧 + node_updated(open)
	gated := &Node{CaseID: "case-1", Kind: KindIntent, Text: "批量核查",
		Status: StatusAwaitingApproval, CreatedBy: ByAI, Scope: ScopeAll,
		Depth: 1, BudgetSeconds: 30}
	if err := fs.CreateNode(ctx, gated); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Approve(ctx, gated.ID, "boss", true); err != nil {
		t.Fatal(err)
	}
	ap := drainUntil(t, ch, func(gc GraphChange) bool {
		return gc.Kind == "feed" && gc.Feed != nil && gc.Feed.Tier == FeedApproval
	})
	if ap.Feed.NodeID != gated.ID || ap.Feed.Status != StatusOpen {
		t.Fatalf("批准应广播审批档播报: %+v", ap.Feed)
	}
	upd := drainUntil(t, ch, func(gc GraphChange) bool { return gc.Kind == "node_updated" })
	if upd.Node.Status != StatusOpen {
		t.Fatalf("批准应广播 node_updated(open): %+v", upd)
	}

	// 退订后不再收
	cancel()
	if _, err := eng.CreateHuman(ctx, "case-1", "tester", "退订后的意图", "", 30, "", ""); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-ch:
		t.Fatalf("退订后不应有帧: %+v", f)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestGraphWatchWorkerLifecycle(t *testing.T) {
	eng, fs, _, _ := testEngine(nil) // fakeAI 默认收尾:supported+锚点+1 子意图
	ctx := context.Background()
	eng.Start(ctx)
	defer eng.Close()
	ch, cancel := eng.SubscribeGraph("case-1")
	defer cancel()

	// 手写意图(open,planner 会领)→ 建点 → running → 终态(supported)→
	// fact 建点 → yields 边 → proves 边 → AI 子意图建点 → spawns 边
	if _, err := eng.CreateHuman(ctx, "case-1", "tester", "查外连", "", 30, "", ""); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(3 * time.Second)
	var kinds []string
	var sawRunning, sawFinal, sawFact bool
	for !(sawRunning && sawFinal && sawFact) {
		select {
		case gc := <-ch:
			kinds = append(kinds, gc.Kind)
			switch gc.Kind {
			case "node_updated":
				if gc.Node.Status == StatusRunning {
					sawRunning = true
				}
				if gc.Node.Status == StatusSupported {
					sawFinal = true
				}
			case "node_added":
				if gc.Node.Kind == KindFact {
					sawFact = true
				}
			}
		case <-deadline:
			t.Fatalf("3s 内未见完整生命周期帧(running=%v final=%v fact=%v): %v",
				sawRunning, sawFinal, sawFact, kinds)
		}
	}
	_ = fs
}

// TestGraphReplay 断线游标回放焊死(交互改造切片二,ARTEX Last-Event-ID
// 语义):序号逐帧递增;游标续播只补缺帧;游标过老(挤出缓冲)/超前(进程
// 重启序号归零)/首连(since=0)一律不可续 → 调用方快照兜底。
func TestGraphReplay(t *testing.T) {
	h := newGraphHub()
	pub := func(n int) {
		for i := 0; i < n; i++ {
			h.publish("case-1", GraphChange{Kind: "node_updated",
				Node: &Node{ID: "n", CaseID: "case-1"}})
		}
	}

	// 空案件:首连不可续,latest=0
	if _, latest, ok := h.replay("case-1", 0); ok || latest != 0 {
		t.Fatalf("空案件首连应不可续: latest=%d ok=%v", latest, ok)
	}

	pub(3) // seq 1..3
	missed, latest, ok := h.replay("case-1", 1)
	if !ok || latest != 3 || len(missed) != 2 || missed[0].Seq != 2 || missed[1].Seq != 3 {
		t.Fatalf("游标 1 应补 2/3 两帧: missed=%v latest=%d ok=%v", missed, latest, ok)
	}
	// 已最新:续播零缺帧
	if missed, latest, ok = h.replay("case-1", 3); !ok || latest != 3 || len(missed) != 0 {
		t.Fatalf("已最新应续播零缺帧: missed=%v ok=%v", missed, ok)
	}
	// 游标超前(进程重启序号归零的客户端视角)→ 快照兜底
	if _, _, ok = h.replay("case-1", 99); ok {
		t.Fatalf("游标超前应不可续")
	}
	// 首连 since=0 → 快照
	if _, latest, ok = h.replay("case-1", 0); ok || latest != 3 {
		t.Fatalf("首连应不可续且回最新序号: latest=%d ok=%v", latest, ok)
	}

	// 案件隔离:别的案件序号独立
	h.publish("case-2", GraphChange{Kind: "node_added", Node: &Node{ID: "x", CaseID: "case-2"}})
	if _, latest, _ = h.replay("case-2", 0); latest != 1 {
		t.Fatalf("case-2 序号应独立从 1 起: %d", latest)
	}
	if _, _, ok = h.replay("case-2", 5); ok {
		t.Fatalf("case-2 游标超前应不可续")
	}

	// 缓冲修剪:graphReplayCap+10 帧后,最老 10 帧的游标不可续,界内可续
	h2 := newGraphHub()
	for i := 0; i < graphReplayCap+10; i++ {
		h2.publish("c", GraphChange{Kind: "node_updated", Node: &Node{ID: "n", CaseID: "c"}})
	}
	if _, _, ok = h2.replay("c", 5); ok {
		t.Fatalf("游标 5 已被挤出缓冲,应不可续")
	}
	missed, latest, ok = h2.replay("c", 10)
	if !ok || len(missed) != graphReplayCap || missed[0].Seq != 11 ||
		latest != int64(graphReplayCap+10) {
		t.Fatalf("界内游标应续播: len=%d first=%v latest=%d ok=%v",
			len(missed), missed[0].Seq, latest, ok)
	}
}
