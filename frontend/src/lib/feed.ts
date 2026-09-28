// 播报板(0.23.0-live-feed)模型与归并:三档(spawn 意图诞生 / progress
// 中间发现 / finish 意图终结)+ 审批事件(approval)。数据源:
//   - 实时主路:SSE 意图图通道的 feed 帧(序号在 lastEventId);
//   - 轮询兜底:GET /api/cases/{id}/activity?since=<seq>(首连回填+断缝补帧)。
// 去重签名=案件内帧序号 seq(两路合一按 seq 去重排序,幂等)。
// 性能闸:FEED_CAP 上限截断,超出丢最旧并累计 dropped(面板如实标注)。

export type FeedTier = "spawn" | "progress" | "finish" | "approval";

// FeedItem 播报一条(与后端 activityItem / intent.FeedItem 对齐)。
export interface FeedItem {
  seq: number; // 案件内帧序号(去重签名;>0)
  node_id?: string;
  tier: FeedTier;
  status?: string; // finish/approval 档的节点终态(置信色)
  text: string;
  detail?: string; // 可展开全文(空=不可展开)
  ts: string;
}

export const FEED_CAP = 500;

export interface FeedState {
  items: FeedItem[]; // 按 seq 升序,最新在尾
  dropped: number; // 上限截断累计丢弃条数(如实标注)
  lastSeq: number; // 已见最大帧序号(轮询游标)
}

export const emptyFeed: FeedState = { items: [], dropped: 0, lastSeq: 0 };

// mergeFeed 合并一批播报帧(纯函数,可测):seq>0 才收,已见 seq 去重,
// 合并后按 seq 升序,超 FEED_CAP 丢最旧并累计 dropped。
export function mergeFeed(
  state: FeedState,
  incoming: FeedItem[],
  cap: number = FEED_CAP,
): FeedState {
  if (!incoming || incoming.length === 0) return state;
  let lastSeq = state.lastSeq;
  for (const it of incoming) {
    if (it.seq > lastSeq) lastSeq = it.seq;
  }
  const seen = new Set(state.items.map((i) => i.seq));
  const add = incoming.filter((i) => i.seq > 0 && !seen.has(i.seq) && i.text);
  if (add.length === 0) {
    return lastSeq === state.lastSeq ? state : { ...state, lastSeq };
  }
  let items = [...state.items, ...add].sort((a, b) => a.seq - b.seq);
  let dropped = state.dropped;
  if (items.length > cap) {
    dropped += items.length - cap;
    items = items.slice(items.length - cap);
  }
  return { items, dropped, lastSeq };
}

// feedDotColor 意图关联色点:node_id 稳定散列到调色板(同一意图同色)。
const DOT_PALETTE = [
  "bg-blue-500",
  "bg-violet-500",
  "bg-emerald-500",
  "bg-amber-500",
  "bg-rose-500",
  "bg-cyan-500",
];

export function feedDotColor(nodeId: string | undefined): string {
  if (!nodeId) return "bg-slate-300";
  let h = 0;
  for (let i = 0; i < nodeId.length; i++) {
    h = (h * 31 + nodeId.charCodeAt(i)) >>> 0;
  }
  return DOT_PALETTE[h % DOT_PALETTE.length];
}

// FINISH_CLS 终结档置信色(supported 绿 / denied 灰 / doubt·耗尽 琥珀 / closed 灰)。
export const FINISH_CLS: Record<string, string> = {
  supported: "bg-emerald-100 text-emerald-700",
  denied: "bg-slate-100 text-slate-600",
  doubt: "bg-amber-100 text-amber-700",
  closed_exhausted: "bg-amber-100 text-amber-700",
  closed: "bg-slate-100 text-slate-500",
  // 0.29.1 goal 收官机器评估态(met 绿 / partial 琥珀 / unmet 灰)
  closed_goal_met: "bg-emerald-100 text-emerald-700",
  closed_goal_partial: "bg-amber-100 text-amber-700",
  closed_goal_unmet: "bg-slate-100 text-slate-500",
};

export const TIER_LABEL: Record<string, string> = {
  spawn: "诞生",
  progress: "发现",
  finish: "终结",
  approval: "审批",
};
