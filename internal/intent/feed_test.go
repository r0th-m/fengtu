// 播报板(0.23.0-live-feed)焊死:三档+审批事件映射/帧序号/轮询兜底
// (feedSince 签名过滤)/摘要截断。全部走内存 fakeStore + graphHub,零 AI。
package intent

import (
	"strings"
	"testing"
	"time"
)

func feedEngine() *Engine {
	return NewEngine(Deps{Store: newFakeStore()})
}

// drainFeed 收 n 帧 feed(超时如实失败)。
func drainFeed(t *testing.T, ch <-chan GraphChange, n int) []GraphChange {
	t.Helper()
	out := []GraphChange{}
	deadline := time.Now().Add(2 * time.Second)
	for len(out) < n {
		select {
		case gc := <-ch:
			if gc.Kind == "feed" {
				out = append(out, gc)
			}
		case <-time.After(time.Until(deadline)):
			t.Fatalf("2s 内应收满 %d 帧 feed,实得 %d", n, len(out))
		}
	}
	return out
}

func TestFeedSpawnTiers(t *testing.T) {
	e := feedEngine()
	ch, cancel := e.hub.subscribe("c1")
	defer cancel()

	// 普通诞生:spawn 一档;待批诞生:spawn + approval 两档
	e.emitFeedSpawn(&Node{ID: "n1", CaseID: "c1", Kind: KindIntent,
		Text: "核查外联", Status: StatusOpen})
	e.emitFeedSpawn(&Node{ID: "n2", CaseID: "c1", Kind: KindIntent,
		Text: "全网批量扫", Status: StatusAwaitingApproval})
	// goal/fact 不进诞生档
	e.emitFeedSpawn(&Node{ID: "g1", CaseID: "c1", Kind: KindGoal, Text: "目标"})

	got := drainFeed(t, ch, 3)
	if got[0].Feed.Tier != FeedSpawn || !strings.Contains(got[0].Feed.Text, "派生了新意图: 核查外联") {
		t.Fatalf("首帧应为诞生档: %+v", got[0].Feed)
	}
	if got[1].Feed.Tier != FeedSpawn || got[2].Feed.Tier != FeedApproval ||
		got[2].Feed.Status != StatusAwaitingApproval ||
		!strings.Contains(got[2].Feed.Text, "意图待审批") {
		t.Fatalf("待批诞生应追加审批事件档: %+v / %+v", got[1].Feed, got[2].Feed)
	}
	// 帧序号案件内单调递增(去重签名)
	if !(got[0].Seq < got[1].Seq && got[1].Seq < got[2].Seq) {
		t.Fatalf("帧序号应递增: %d %d %d", got[0].Seq, got[1].Seq, got[2].Seq)
	}
	if got[0].Feed.TS.IsZero() {
		t.Fatalf("播报帧应带时间戳")
	}
}

func TestFeedEventKindMapping(t *testing.T) {
	e := feedEngine()
	ch, cancel := e.hub.subscribe("c1")
	defer cancel()

	e.emitFeedEvent("c1", "n1", "tool_use", `search {"q":"mimikatz"}`)
	e.emitFeedEvent("c1", "n1", "text", "流式碎片不进播报")
	e.emitFeedEvent("c1", "n1", "thinking", "思考也不进")
	e.emitFeedEvent("c1", "n1", "eval", "评估: supported")
	e.emitFeedEvent("c1", "n1", "unknown_kind", "未知步类如实跳过")

	got := drainFeed(t, ch, 2)
	if got[0].Feed.Tier != FeedProgress || !strings.HasPrefix(got[0].Feed.Text, "调用工具: ") {
		t.Fatalf("tool_use 应进中间发现档带前缀: %+v", got[0].Feed)
	}
	if got[0].Feed.Detail != `search {"q":"mimikatz"}` {
		t.Fatalf("Detail 应为全文: %q", got[0].Feed.Detail)
	}
	if got[1].Feed.Tier != FeedProgress || !strings.Contains(got[1].Feed.Text, "评估: supported") {
		t.Fatalf("eval 应进中间发现档: %+v", got[1].Feed)
	}
}

func TestFeedFinishFallback(t *testing.T) {
	e := feedEngine()
	ch, cancel := e.hub.subscribe("c1")
	defer cancel()

	e.emitFeedFinish("c1", "n1", StatusSupported, "发现可疑外联", "附注")
	e.emitFeedFinish("c1", "n2", StatusClosed, "", "人工停止,已写回已得")
	e.emitFeedFinish("c1", "n3", StatusDoubt, "", "")

	got := drainFeed(t, ch, 3)
	if got[0].Feed.Text != "发现可疑外联" || got[0].Feed.Status != StatusSupported ||
		got[0].Feed.Detail != "附注" {
		t.Fatalf("终结档应取 summary 且带终态: %+v", got[0].Feed)
	}
	if got[1].Feed.Text != "人工停止,已写回已得" {
		t.Fatalf("summary 空应回退 closeNote: %+v", got[1].Feed)
	}
	if got[2].Feed.Text != "(无收尾摘要,如实)" {
		t.Fatalf("双空应如实兜底: %+v", got[2].Feed)
	}
}

func TestFeedSummaryCut(t *testing.T) {
	long := strings.Repeat("长", 200)
	if got := cutRunes(long, feedTextCap); utf8len(got) != feedTextCap+1 ||
		!strings.HasSuffix(got, "…") {
		t.Fatalf("摘要应截到 %d 字+省略号: %d", feedTextCap, utf8len(got))
	}
	if got := cutRunes("短", feedTextCap); got != "短" {
		t.Fatalf("短文本不动: %q", got)
	}
}

func utf8len(s string) int { return len([]rune(s)) }

func TestFeedSince(t *testing.T) {
	e := feedEngine()
	// 混入图帧与播报帧:feedSince 只回 feed,序号过滤,latest 取全局水位
	e.hub.publish("c1", GraphChange{Kind: "node_added", Node: &Node{ID: "n1"}}) // seq1
	e.emitFeed("c1", FeedItem{NodeID: "n1", Tier: FeedSpawn, Text: "诞生"})       // seq2
	e.hub.publish("c1", GraphChange{Kind: "node_updated", Node: &Node{ID: "n1"}})
	e.emitFeed("c1", FeedItem{NodeID: "n1", Tier: FeedFinish, Text: "终结"}) // seq4

	items, latest := e.Activity("c1", 0)
	if latest != 4 || len(items) != 2 {
		t.Fatalf("since=0 应回 2 条 feed,latest=4: %d 条 latest=%d", len(items), latest)
	}
	if items[0].Seq != 2 || items[1].Seq != 4 || items[1].Feed.Tier != FeedFinish {
		t.Fatalf("feed 帧应保序且只含 feed: %+v", items)
	}
	items, latest = e.Activity("c1", 2)
	if len(items) != 1 || items[0].Seq != 4 || latest != 4 {
		t.Fatalf("since=2 应只回 seq4: %+v latest=%d", items, latest)
	}
	items, _ = e.Activity("c1", 4)
	if len(items) != 0 {
		t.Fatalf("since=latest 应空: %+v", items)
	}
	// 他案隔离
	items, latest = e.Activity("c2", 0)
	if len(items) != 0 || latest != 0 {
		t.Fatalf("他案应空: %+v latest=%d", items, latest)
	}
}
