// 血缘子图(交互改造切片三·报告 tab;设计 §4「finding lineage 子图」照抄,
// 直接复用 8c 布局引擎 lib/layout.ts + 卡片视觉):「这个结论是怎么来的」
// 一图胜千言。静态只读(无拖动/缩放),点卡片跳主图聚焦。
import { useMemo } from "react";
import { EDGE_LABEL, KIND_LABEL, STATUS_LABEL, type GraphState } from "../lib/intent";
import { lineageSubgraph } from "../lib/lineage";
import { CARD_H, CARD_W, edgePath, layoutGraph } from "../lib/layout";

// 与 IntentGraph 同色系(主图/子图视觉一致)
const KIND_BAR: Record<string, string> = {
  goal: "#0E7C7B", intent: "#3B82F6", fact: "#5F9E6E", finding: "#F59E0B", hint: "#94A3B8",
};
const EDGE_STROKE: Record<string, string> = {
  spawns: "#64748B", derived_from: "#8B5CF6", yields: "#059669", proves: "#D97706",
};

export default function LineageGraph({
  graph,
  nodeId,
  onJump,
}: {
  graph: GraphState;
  nodeId: string; // 结论节点(回溯起点)
  onJump?: (id: string) => void; // 点卡片 → 主图聚焦
}) {
  const sub = useMemo(() => lineageSubgraph(graph, nodeId), [graph, nodeId]);
  const layout = useMemo(() => layoutGraph(sub), [sub]);
  if (!sub.nodes[nodeId]) {
    return <div className="text-xs text-mute p-3">节点不在当前图内(如实,无血缘可画)</div>;
  }
  return (
    <div className="overflow-auto thin-scroll rounded-lg border border-slate-100 bg-[#FAFAF8] p-2"
      data-testid={`lineage-${nodeId}`}>
      <div className="relative" style={{ width: layout.width, height: layout.height }}>
        <svg className="absolute left-0 top-0 pointer-events-none"
          width={layout.width} height={layout.height}>
          {Object.values(sub.edges).map((e) => {
            const a = layout.pos.get(e.from_id);
            const b = layout.pos.get(e.to_id);
            if (!a || !b) return null;
            const { d, mx, my } = edgePath(a, b);
            const color = EDGE_STROKE[e.kind] || "#CBD5E1";
            return (
              <g key={e.id}>
                <path d={d} fill="none" stroke={color}
                  strokeWidth={e.kind === "proves" ? 1.4 : 1.6}
                  strokeDasharray={e.kind === "proves" ? "6 4" : undefined} opacity={0.75} />
                <text x={mx} y={my - 4} textAnchor="middle" fontSize={9} fill={color}
                  stroke="#fff" strokeWidth={3} paintOrder="stroke">
                  {EDGE_LABEL[e.kind] || e.kind}
                </text>
              </g>
            );
          })}
        </svg>
        {Object.values(sub.nodes).map((n) => {
          const p = layout.pos.get(n.id);
          if (!p) return null;
          return (
            <button
              key={n.id}
              onClick={() => onJump?.(n.id)}
              title="点击到探索链路聚焦该节点"
              className="absolute rounded-xl bg-white border border-slate-200 shadow-sm
                text-left overflow-hidden hover:border-brand/50 transition-colors"
              style={{ left: p.x, top: p.y, width: CARD_W, height: CARD_H }}
            >
              <span className="absolute left-0 top-0 bottom-0 w-1"
                style={{ background: KIND_BAR[n.kind] || "#94A3B8" }} />
              <span className="block pl-2.5 pr-1.5 pt-1 text-[10px] text-mute">
                {KIND_LABEL[n.kind] || n.kind}
                {n.host_scope ? ` · ${n.host_scope}` : ""}
              </span>
              <span className="block pl-2.5 pr-1.5 text-[11px] text-ink leading-tight
                line-clamp-2">{n.text}</span>
              <span className="block pl-2.5 text-[9px] text-mute">
                {STATUS_LABEL[n.status] || n.status}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
