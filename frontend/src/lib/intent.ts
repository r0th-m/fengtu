// 意图图(切片 8b 主视图)模型与 SSE 增量归并。
// 数据源:GET /api/cases/{id}/intents/events —— 首帧 snapshot 全量,
// 随后 node_added/node_updated/edge_added 增量;断线 EventSource 自动
// 重连拿新快照(服务端通道溢出会主动关流,重连即全量兜底)。

// IntentAnchor 证据锚点(与后端 intent.Anchor 对齐)。
export interface IntentAnchor {
  source_id?: string;
  line_no?: number;
  hit_id?: string;
  note?: string;
}

// IntentNode 意图图节点(五型:goal/intent/fact/finding/hint)。
export interface IntentNode {
  id: string;
  case_id: string;
  kind: string;
  text: string;
  status: string; // open|awaiting_approval|running|supported|denied|doubt|closed_exhausted|closed|parked(0.24.0 停车场)|closed_goal_met|closed_goal_partial|closed_goal_unmet(0.29.1 goal 收官机器评估态)
  created_by: string; // human|ai|rule
  rule_id?: string;
  template_id?: string;
  template_key?: string;
  scope: string; // case|all
  host_scope?: string;
  parent_id?: string;
  depth: number;
  evidence?: IntentAnchor[];
  result_text?: string;
  close_note?: string;
  session_id?: string;
  budget_seconds: number;
  started_at?: string | null;
  finished_at?: string | null;
  created_at: string;
}

// IntentEdge 血缘边(spawns/derived_from/yields/proves)。
export interface IntentEdge {
  id: string;
  case_id: string;
  from_id: string;
  to_id: string;
  kind: string;
  created_at: string;
}

// GraphState 图快照(nodes/edges 按 id 索引;归并是纯函数,可测)。
export interface GraphState {
  nodes: Record<string, IntentNode>;
  edges: Record<string, IntentEdge>;
  seq: number; // 单调递增,React 依赖触发用
}

export const emptyGraph: GraphState = { nodes: {}, edges: {}, seq: 0 };

// applySnapshot 全量替换(SSE 首帧/重连)。
export function applySnapshot(nodes: IntentNode[], edges: IntentEdge[]): GraphState {
  const ns: Record<string, IntentNode> = {};
  for (const n of nodes || []) ns[n.id] = n;
  const es: Record<string, IntentEdge> = {};
  for (const e of edges || []) es[e.id] = e;
  return { nodes: ns, edges: es, seq: 1 };
}

// applyChange 增量归并(node_added 插/换;node_updated 只换已知的——
// 未知 id 也收,乱序帧不丢状态;edge_added 插)。
export function applyChange(
  g: GraphState,
  kind: string,
  payload: IntentNode | IntentEdge,
): GraphState {
  if (kind === "node_added" || kind === "node_updated") {
    const n = payload as IntentNode;
    if (!n?.id) return g;
    return { ...g, nodes: { ...g.nodes, [n.id]: n }, seq: g.seq + 1 };
  }
  if (kind === "edge_added") {
    const e = payload as IntentEdge;
    if (!e?.id) return g;
    return { ...g, edges: { ...g.edges, [e.id]: e }, seq: g.seq + 1 };
  }
  return g;
}

// 子树遍历用的出边白名单:proves 是 fact→intent 的回指边,顺它会
// 把父意图卷进「子树」,折叠/统计都不走它。
const TREE_EDGE_KINDS = new Set(["spawns", "derived_from", "yields"]);

// childrenOf 直接子节点(树边方向 from→to,创建序稳定)。
export function childrenOf(g: GraphState, id: string): IntentNode[] {
  const out: IntentNode[] = [];
  for (const e of Object.values(g.edges)) {
    if (e.from_id === id && TREE_EDGE_KINDS.has(e.kind)) {
      const n = g.nodes[e.to_id];
      if (n) out.push(n);
    }
  }
  // created_at 可能缺(坏帧/字段缺失),空串兜底不崩
  out.sort((a, b) => (a.created_at || "").localeCompare(b.created_at || ""));
  return out;
}

// descendants 全部后代(BFS,visited 防环;折叠子树用)。
export function descendants(g: GraphState, id: string): Set<string> {
  const seen = new Set<string>();
  const queue = [id];
  while (queue.length > 0) {
    const cur = queue.shift()!;
    for (const e of Object.values(g.edges)) {
      if (e.from_id !== cur || !TREE_EDGE_KINDS.has(e.kind)) continue;
      if (!seen.has(e.to_id)) {
        seen.add(e.to_id);
        queue.push(e.to_id);
      }
    }
  }
  return seen;
}

// pendingApprovals 待批意图(创建序)。
export function pendingApprovals(g: GraphState): IntentNode[] {
  return Object.values(g.nodes)
    .filter((n) => n.status === "awaiting_approval")
    .sort((a, b) => (a.created_at || "").localeCompare(b.created_at || ""));
}

// STATUS_LABEL / KIND_LABEL 如实中文标(详情/图例共用)。
export const STATUS_LABEL: Record<string, string> = {
  open: "待执行",
  awaiting_approval: "待审批",
  running: "执行中",
  supported: "证据支持",
  denied: "已排除",
  doubt: "存疑",
  closed_exhausted: "时间耗尽(覆盖可能不全)",
  closed: "已关闭",
  parked: "停车场(待处置)", // 0.24.0:预算闸/AI 申请拦下的未展开线索,人批才展开
  // 0.29.1 goal 收官机器评估态(措辞如实:机器评估,收官定论归人)
  closed_goal_met: "机器评估达成(收官定论归人)",
  closed_goal_partial: "机器评估部分达成(收官定论归人)",
  closed_goal_unmet: "机器评估未达成(收官定论归人)",
};

export const KIND_LABEL: Record<string, string> = {
  goal: "目标",
  intent: "意图",
  fact: "事实",
  finding: "发现",
  hint: "线索",
};

export const EDGE_LABEL: Record<string, string> = {
  spawns: "派生",
  derived_from: "源自",
  yields: "产出",
  proves: "证明",
};
