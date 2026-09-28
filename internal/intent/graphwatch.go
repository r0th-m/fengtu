// 图变更订阅(切片 8b):意图图 SSE 增量的源。引擎内一切图变更
// (建点/状态写回/建边)在此收口广播;web 层 SSE 端点按案件订阅。
//
// 纪律:
//   - 快照兜底:订阅通道只推增量,客户端首帧永远是全量快照
//     (GET .../intents/events);通道溢出 = 慢订阅者,服务端直接关流,
//     EventSource 自动重连拿新快照——丢帧不靠补发,靠重连全量;
//   - 变更即发:worker 写回/planner 播种/审批门落账的同一调用链上
//     同步广播(不另起轮询),前端「看着意图长」的实时性由此而来。
package intent

import (
	"context"
	"sync"
)

// GraphChange 意图图变更一帧(kind 决定 Node/Edge 谁在场)。
type GraphChange struct {
	// Seq 案件内单调递增帧序号(交互改造切片二·SSE 断线游标:
	// 由 graphHub.publish 赋值,SSE 以 id: 行下发,浏览器自动重连时
	// 带 Last-Event-ID 回传,服务端按游标回放缺帧)。
	Seq  int64  `json:"seq"`
	Kind string `json:"kind"` // node_added | node_updated | edge_added | feed
	Node *Node  `json:"node,omitempty"`
	Edge *Edge  `json:"edge,omitempty"`
	// Feed 播报帧(0.23.0-live-feed;kind=feed 时在场,Node/Edge 空)。
	Feed *FeedItem `json:"feed,omitempty"`
}

// graphSubCap 单订阅缓冲(突发写回风暴;溢出即关流,客户端重连快照兜底)。
const graphSubCap = 128

// graphReplayCap 断线回放环形缓冲上限(每案件最近 N 帧;游标老出缓冲
// 即不可续,回退全量快照——如实兜底,不伪造连续)。
// 0.23.0 起播报帧(kind=feed)与图变更共用一环:worker 过程流关键步
// 也占帧位,提到 512 给图帧留回放余量(喂满即快照兜底,语义不变)。
const graphReplayCap = 512

// graphHub 按案件的订阅台账 + 帧序号/回放缓冲(独立锁,不与引擎调度锁纠缠)。
type graphHub struct {
	mu   sync.Mutex
	subs map[string]map[chan GraphChange]bool
	seq  map[string]int64          // 案件 → 已发最新帧序号
	log  map[string][]GraphChange  // 案件 → 最近帧环形缓冲(回放用)
}

func newGraphHub() *graphHub {
	return &graphHub{subs: map[string]map[chan GraphChange]bool{},
		seq: map[string]int64{}, log: map[string][]GraphChange{}}
}

// subscribe 订阅案件图变更;cancel 退订(幂等)。
func (h *graphHub) subscribe(caseID string) (<-chan GraphChange, func()) {
	ch := make(chan GraphChange, graphSubCap)
	h.mu.Lock()
	if h.subs[caseID] == nil {
		h.subs[caseID] = map[chan GraphChange]bool{}
	}
	h.subs[caseID][ch] = true
	h.mu.Unlock()
	var once sync.Once
	cancel := func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subs[caseID], ch)
			h.mu.Unlock()
		})
	}
	return ch, cancel
}

// publish 广播一帧(非阻塞;慢订阅者溢出即关流——重连快照兜底,见文件头)。
// 同帧入案件回放缓冲(断线游标用):赋案件内递增 Seq,修剪到 graphReplayCap。
func (h *graphHub) publish(caseID string, ch GraphChange) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seq[caseID]++
	ch.Seq = h.seq[caseID]
	h.log[caseID] = append(h.log[caseID], ch)
	if len(h.log[caseID]) > graphReplayCap {
		// 环形修剪:丢最老(游标落在被丢区间即不可续,调用方快照兜底)
		h.log[caseID] = h.log[caseID][len(h.log[caseID])-graphReplayCap:]
	}
	for sub := range h.subs[caseID] {
		select {
		case sub <- ch:
		default:
			delete(h.subs[caseID], sub)
			close(sub)
		}
	}
}

// replay 断线游标回放(ARTEX Last-Event-ID 语义,交互改造切片二):
// since=客户端最后收到的帧序号;返回 (missed, latest, resumable)。
//   - resumable=true:missed=序号 (since, latest] 的全部缺帧,客户端免快照续播;
//   - resumable=false:游标过老(已被挤出缓冲)、游标超前(进程重启序号归零)
//     或 since=0(首连)——调用方一律走全量快照兜底(如实,不伪造连续)。
func (h *graphHub) replay(caseID string, since int64) (missed []GraphChange, latest int64, resumable bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	latest = h.seq[caseID]
	if since <= 0 || since > latest {
		return nil, latest, false
	}
	log := h.log[caseID]
	if since == latest {
		return nil, latest, true // 无缺帧,直接续播
	}
	// 缓冲最老帧序号须 ≤ since+1,否则 (since, 最老) 区间有洞,不可续
	if len(log) == 0 || log[0].Seq > since+1 {
		return nil, latest, false
	}
	for _, ch := range log {
		if ch.Seq > since {
			missed = append(missed, ch)
		}
	}
	return missed, latest, true
}

// emitNodeAdded 建点广播(节点此刻已落库,id/created_at 已回写)。
// 0.23.0:意图节点同时落播报「诞生」档(待批的追加审批事件档)。
func (e *Engine) emitNodeAdded(n *Node) {
	cp := *n
	e.hub.publish(n.CaseID, GraphChange{Kind: "node_added", Node: &cp})
	e.emitFeedSpawn(n)
}

// emitEdgeAdded 建边广播(重复边幂等跳过 ID 为空,不广播——不是新增)。
func (e *Engine) emitEdgeAdded(ed *Edge) {
	if ed == nil || ed.ID == "" {
		return
	}
	cp := *ed
	e.hub.publish(ed.CaseID, GraphChange{Kind: "edge_added", Edge: &cp})
}

// emitNodeUpdated 状态写回广播(重读库内新态;读不到如实不播——
// 客户端下次快照对齐,不伪造状态)。
func (e *Engine) emitNodeUpdated(ctx context.Context, id string) {
	n, err := e.deps.Store.GetNode(ctx, id)
	if err != nil || n == nil {
		return
	}
	e.hub.publish(n.CaseID, GraphChange{Kind: "node_updated", Node: n})
}

// SubscribeGraph 订阅案件意图图变更(web SSE 层用;退订调 cancel)。
func (e *Engine) SubscribeGraph(caseID string) (<-chan GraphChange, func()) {
	return e.hub.subscribe(caseID)
}

// GraphReplay 断线游标回放(web SSE 层用;语义见 graphHub.replay)。
func (e *Engine) GraphReplay(caseID string, since int64) (missed []GraphChange, latest int64, resumable bool) {
	return e.hub.replay(caseID, since)
}
