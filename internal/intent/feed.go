// 播报板(0.23.0-live-feed):案件级 activity stream——意图诞生/中间发现/
// 意图终结/审批事件四档,后端在图变更与 worker 过程流的既有收口点聚合成
// FeedItem,经 graphHub 以 kind="feed" 帧随意图图 SSE 通道下发(复用帧
// 序号/断线游标/回放缓冲,不另起通道);轮询兜底走 FeedSince(游标之后的
// 回放帧滤 feed,帧序号即去重签名)。
//
// 纪律:
//   - 只播报,不新造事实:每一档都是既有事件(建点/写回/过程流/审批)的
//     投影,完整证据仍在节点详情与过程流;
//   - text/thinking 流式碎片不进播报(太碎),中间发现档只收关键步;
//   - 帧序号与图变更共用一案一序——游标/去重语义与既有 SSE 完全一致。
package intent

import (
	"time"
	"unicode/utf8"
)

// 播报档位(web/前端按 tier 渲染:诞生=行内停止/纠偏,终结=置信色,
// 审批=去审批入口,中间发现=可展开全文+锚点)。
const (
	FeedSpawn    = "spawn"    // 意图诞生
	FeedProgress = "progress" // 中间发现(worker 过程流关键步)
	FeedFinish   = "finish"   // 意图终结(一句话收尾+终态)
	FeedApproval = "approval" // 审批事件(待审批/已放行/已驳回)
)

// FeedItem 播报一条(TS 由 emitFeed 落;帧序号 Seq 由 graphHub.publish 赋,
// 随 GraphChange 下发,不重复占字段)。
type FeedItem struct {
	NodeID string    `json:"node_id,omitempty"`
	Tier   string    `json:"tier"`
	Status string    `json:"status,omitempty"` // finish/approval 档的节点终态(置信色)
	Text   string    `json:"text"`             // 一行摘要
	Detail string    `json:"detail,omitempty"` // 可展开全文(中间发现;空=不可展开)
	TS     time.Time `json:"ts"`
}

// feedTextCap 播报一行摘要上限(rune);全文在 Detail/节点详情。
const feedTextCap = 120

// feedEventKinds 中间发现档收录的过程流步类 → 摘要前缀。
// text/thinking 流式碎片不进播报(噪声);完整过程流不缺(节点详情逐步留痕)。
var feedEventKinds = map[string]string{
	"plan":        "",
	"tool_use":    "调用工具: ",
	"tool_result": "工具返回: ",
	"eval":        "",
	"spawn":       "派生: ",
	"budget":      "",
	"stop":        "",
	"steer":       "",
	"error":       "",
	"park":        "停车场: ", // 0.24.0:预算闸拦截/AI 申请/收官评估/出入场
}

func cutRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

// emitFeed 播报一帧(经 graphHub;Seq 由 hub 赋,TS 用引擎时钟,测试可注入)。
func (e *Engine) emitFeed(caseID string, item FeedItem) {
	item.TS = e.deps.Now().UTC()
	e.hub.publish(caseID, GraphChange{Kind: "feed", Feed: &item})
}

// emitFeedSpawn 意图诞生(emitNodeAdded 收口点调用;待批的同时落审批事件档)。
// parked 节点(0.24.0 停车场)不播「诞生」——它没诞生为可执行意图,
// 播报由 park() 的「转入停车场」档承担(如实,不双报)。
func (e *Engine) emitFeedSpawn(n *Node) {
	if n.Kind != KindIntent || n.Status == StatusParked {
		return
	}
	e.emitFeed(n.CaseID, FeedItem{NodeID: n.ID, Tier: FeedSpawn,
		Text: "派生了新意图: " + cutRunes(n.Text, feedTextCap)})
	if n.Status == StatusAwaitingApproval {
		e.emitFeed(n.CaseID, FeedItem{NodeID: n.ID, Tier: FeedApproval,
			Status: n.Status,
			Text:   "意图待审批(scope=all 批量执行,人批准才放行): " + cutRunes(n.Text, 80)})
	}
}

// emitFeedEvent worker 过程流关键步 → 中间发现档(未收录步类如实跳过)。
func (e *Engine) emitFeedEvent(caseID, nodeID, kind, text string) {
	prefix, ok := feedEventKinds[kind]
	if !ok {
		return
	}
	e.emitFeed(caseID, FeedItem{NodeID: nodeID, Tier: FeedProgress,
		Text: prefix + cutRunes(text, feedTextCap), Detail: text})
}

// emitFeedFinish 意图终结(一句话收尾+终态;置信色前端按 Status 染)。
func (e *Engine) emitFeedFinish(caseID, nodeID, status, summary, closeNote string) {
	text := summary
	if text == "" {
		text = closeNote
	}
	if text == "" {
		text = "(无收尾摘要,如实)"
	}
	e.emitFeed(caseID, FeedItem{NodeID: nodeID, Tier: FeedFinish, Status: status,
		Text: cutRunes(text, feedTextCap), Detail: closeNote})
}

// emitFeedApproval 审批落账事件(批准放行/驳回)。
func (e *Engine) emitFeedApproval(caseID, nodeID, text, status string) {
	e.emitFeed(caseID, FeedItem{NodeID: nodeID, Tier: FeedApproval,
		Status: status, Text: cutRunes(text, feedTextCap)})
}

// feedSince 轮询兜底:取回放缓冲内序号 > since 的 feed 帧(帧序号=签名;
// 被挤出缓冲的区间如实缺,客户端以 latest 续游标,不伪造连续)。
func (h *graphHub) feedSince(caseID string, since int64) (items []GraphChange, latest int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	latest = h.seq[caseID]
	for _, ch := range h.log[caseID] {
		if ch.Kind == "feed" && ch.Seq > since {
			items = append(items, ch)
		}
	}
	return items, latest
}

// Activity 播报轮询面(web 层 GET .../activity 用;语义见 hub.feedSince)。
func (e *Engine) Activity(caseID string, since int64) (items []GraphChange, latest int64) {
	return e.hub.feedSince(caseID, since)
}
