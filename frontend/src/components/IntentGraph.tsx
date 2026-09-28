// 意图图主视图(切片 8c,§13 ARTEX 同款卡片节点+从左到右分层流):
//   - 卡片节点:圆角白卡,左色条按类型,类型图标+标签、标题两行截断、
//     状态 chip(running 脉冲/supported 绿/doubt·finding 琥珀/denied 灰/
//     closed_exhausted 斜纹/awaiting_approval 红角标);整卡可点(比圆点好点击);
//   - 布局:lib/layout.ts 纯函数分层(树边拓扑深度分列,列内重心排序减交叉,
//     无物理仿真);goal 左 → 意图中 → 事实/发现右;深度大容器横向滚动;
//   - 连线:贝塞尔平滑曲线,边类型标签(派生/源自/产出/证明)分色,
//     proves 虚线,箭头;
//   - SSE 实时生长:新卡飞入/状态变色闪光;双击折叠子树(+N 角标);
//     点卡右侧滑出详情(IntentDetail);滚轮缩放/背景拖拽平移;
//     左下缩放控制,右下小地图(点击跳视口)。
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../lib/api";
import {
  childrenOf,
  descendants,
  EDGE_LABEL,
  KIND_LABEL,
  STATUS_LABEL,
  type GraphState,
} from "../lib/intent";
import { CARD_H, CARD_W, edgePath, layoutGraph, type LayoutResult } from "../lib/layout";
import type { IntentGraphLive } from "../lib/useIntentGraph";
import IntentDetail from "./IntentDetail";
import Tip from "./Tip";

// 五型左色条(goal 青/intent 蓝/fact 灰绿/finding 琥珀/hint 灰)
const KIND_BAR: Record<string, string> = {
  goal: "#0E7C7B",
  intent: "#3B82F6",
  fact: "#5F9E6E",
  finding: "#F59E0B",
  hint: "#94A3B8",
};
const KIND_ICON: Record<string, string> = {
  goal: "🎯",
  intent: "🧭",
  fact: "📌",
  finding: "⚠️",
  hint: "💡",
};
// 状态 chip 样式(running 蓝脉冲/awaiting_approval 红脉冲/closed_exhausted 斜纹;
// parked 灰虚线=停车场未展开线索,0.24.0)
const STATUS_CHIP: Record<string, string> = {
  open: "bg-slate-100 text-slate-500",
  awaiting_approval: "bg-red-100 text-red-700 animate-pulse",
  running: "bg-blue-100 text-blue-700",
  supported: "bg-green-100 text-green-700",
  denied: "bg-slate-100 text-slate-400",
  doubt: "bg-amber-100 text-amber-700",
  closed_exhausted: "chip-stripes text-stone-500",
  closed: "bg-slate-100 text-slate-400",
  parked: "bg-slate-50 text-slate-400 border border-dashed border-slate-300",
  // 0.29.1 goal 收官机器评估态(met 绿 / partial 琥珀 / unmet 灰)
  closed_goal_met: "bg-green-100 text-green-700",
  closed_goal_partial: "bg-amber-100 text-amber-700",
  closed_goal_unmet: "bg-slate-100 text-slate-400",
};
const EDGE_STROKE: Record<string, string> = {
  spawns: "#64748B",
  derived_from: "#8B5CF6",
  yields: "#059669",
  proves: "#D97706",
};
const EDGE_KINDS = ["spawns", "derived_from", "yields", "proves"] as const;

function short(text: string, max = 10): string {
  const r = [...(text || "")]; // 字段缺失(坏帧)不崩
  return r.length > max ? r.slice(0, max).join("") + "…" : text || "";
}

export default function IntentGraph({
  caseId,
  live,
  onAnchor,
  focusNodeId,
  archived,
  suggestedPlaybook,
}: {
  caseId: string;
  live: IntentGraphLive;
  onAnchor: (sourceId: string, lineNo: number) => void;
  focusNodeId?: { id: string; seq: number } | null; // 外部点名聚焦(审批铃铛跳详情;seq 保证重复跳同节点也触发)
  archived?: boolean; // 归档案:隐藏手写意图/线索入口(后端同闸 409,0.18.0)
  suggestedPlaybook?: string; // 按应急类型预选的一键分析模板(0.26.1;人可改,判断权归人)
}) {
  const { graph, connected } = live;
  const boxRef = useRef<HTMLDivElement>(null);
  const [view, setView] = useState({ tx: 24, ty: 24, k: 1 });
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<string | null>(null);
  const [intentText, setIntentText] = useState("");
  const [seedErr, setSeedErr] = useState("");
  // 一键分析入口(0.26.1-analyze-button):空图时给 playbook 选择+开始钮;
  // playbook 清单从后端拉(数据驱动,新增册自动出现),预选用案件应急类型建议值。
  const [playbooks, setPlaybooks] = useState<{ id: string; title: string }[]>([]);
  const [selPlaybook, setSelPlaybook] = useState(suggestedPlaybook || "general-triage");
  const [analyzing, setAnalyzing] = useState(false);
  useEffect(() => {
    api
      .get<{ playbooks: { id: string; title: string }[] }>("/api/playbooks")
      .then((d) => setPlaybooks(d.playbooks || []))
      .catch(() => setPlaybooks([])); // 拉取失败如实:下拉为空,仍可手写意图
  }, []);
  useEffect(() => {
    if (suggestedPlaybook) setSelPlaybook(suggestedPlaybook);
  }, [suggestedPlaybook]);
  // 切片三:手写入口双模——意图(直接进图执行)/线索(add_hint:挂图不执行,
  // worker 下轮 system 可见;比直接改意图更温和的人在环路,设计 §3)
  const [seedMode, setSeedMode] = useState<"intent" | "hint">("intent");
  const [groupHost, setGroupHost] = useState(false); // 主机泳道开关
  const [fresh, setFresh] = useState<Set<string>>(new Set()); // 新卡飞入
  const [flash, setFlash] = useState<Set<string>>(new Set()); // 状态变色闪光
  const prevNodes = useRef<Map<string, string>>(new Map()); // id → 上次 status
  const didFit = useRef(false);

  // ---- 折叠子树:可见集 = 全部 - 各折叠点的后代 ----
  const hidden = useMemo(() => {
    const h = new Set<string>();
    for (const id of collapsed) {
      if (graph.nodes[id]) {
        for (const d of descendants(graph, id)) h.add(d);
      }
    }
    return h;
  }, [collapsed, graph]);

  // ---- 分层布局(纯函数;可见图变更/折叠/泳道开关 → 重排,卡片 left/top 过渡滑动) ----
  const layout: LayoutResult = useMemo(() => {
    const nodes: GraphState["nodes"] = {};
    const edges: GraphState["edges"] = {};
    for (const n of Object.values(graph.nodes)) {
      if (!hidden.has(n.id)) nodes[n.id] = n;
    }
    for (const e of Object.values(graph.edges)) {
      if (!hidden.has(e.from_id) && !hidden.has(e.to_id)) edges[e.id] = e;
    }
    return layoutGraph({ nodes, edges, seq: graph.seq }, { groupByHost: groupHost });
  }, [graph, hidden, groupHost]);

  // ---- SSE 增量观感:新卡飞入 + 状态变色闪光 ----
  useEffect(() => {
    const cur = new Map<string, string>();
    const added: string[] = [];
    const changed: string[] = [];
    for (const n of Object.values(graph.nodes)) {
      cur.set(n.id, n.status);
      const prev = prevNodes.current.get(n.id);
      if (prev === undefined && prevNodes.current.size > 0) added.push(n.id);
      else if (prev !== undefined && prev !== n.status) changed.push(n.id);
    }
    prevNodes.current = cur;
    if (added.length > 0) {
      const ids = new Set(added);
      setFresh((s) => new Set([...s, ...ids]));
      setTimeout(() => setFresh((s) => new Set([...s].filter((id) => !ids.has(id)))), 700);
    }
    if (changed.length > 0) {
      const ids = new Set(changed);
      setFlash((s) => new Set([...s, ...ids]));
      setTimeout(() => setFlash((s) => new Set([...s].filter((id) => !ids.has(id)))), 1100);
    }
  }, [graph.seq, graph.nodes]);

  const collapsedCount = useMemo(() => {
    const m = new Map<string, number>();
    for (const id of collapsed) {
      if (graph.nodes[id]) m.set(id, descendants(graph, id).size);
    }
    return m;
  }, [collapsed, graph]);

  // ---- 视图:首次有节点自动适配全图;外部聚焦居中 ----
  const fitView = useCallback((L: LayoutResult) => {
    const el = boxRef.current;
    if (!el || L.width === 0) return;
    const rect = el.getBoundingClientRect();
    const k = Math.min(1, Math.max(0.25, Math.min(rect.width / L.width, rect.height / L.height)));
    setView({
      k,
      tx: (rect.width - L.width * k) / 2,
      ty: (rect.height - L.height * k) / 2,
    });
  }, []);

  useEffect(() => {
    if (!didFit.current && layout.pos.size > 0) {
      didFit.current = true;
      fitView(layout);
    }
  }, [layout, fitView]);

  const centerOn = useCallback(
    (id: string) => {
      const p = layout.pos.get(id);
      const el = boxRef.current;
      if (!p || !el) return;
      const rect = el.getBoundingClientRect();
      setView((v) => ({
        ...v,
        tx: rect.width / 2 - (p.x + CARD_W / 2) * v.k,
        ty: rect.height / 2 - (p.y + CARD_H / 2) * v.k,
      }));
    },
    [layout],
  );

  // 外部聚焦(审批中心跳节点):选中 + 视图居中 + 展开折叠
  useEffect(() => {
    const id = focusNodeId?.id;
    if (!id || !graph.nodes[id]) return;
    setSelected(id);
    setCollapsed((s) => (s.size > 0 ? new Set() : s)); // 折叠着的先展开(简化:清全部,如实重排)
    // 布局重排后居中(等一拍 React 提交)
    setTimeout(() => centerOn(id), 60);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusNodeId]);

  // ---- 交互:滚轮缩放(光标锚定)/背景拖拽平移/双击折叠/点击详情 ----
  useEffect(() => {
    const el = boxRef.current;
    if (!el) return;
    const onWheel = (ev: WheelEvent) => {
      ev.preventDefault();
      const rect = el.getBoundingClientRect();
      const mx = ev.clientX - rect.left;
      const my = ev.clientY - rect.top;
      setView((v) => {
        const f = ev.deltaY < 0 ? 1.12 : 1 / 1.12;
        const k = Math.min(3, Math.max(0.25, v.k * f));
        const rr = k / v.k;
        return { k, tx: mx - (mx - v.tx) * rr, ty: my - (my - v.ty) * rr };
      });
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, []);

  // Esc 关详情
  useEffect(() => {
    const onKey = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") setSelected(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const panStart = useRef<{ x: number; y: number; tx: number; ty: number } | null>(null);
  const panMoved = useRef(false);

  const onBgMouseDown = (ev: React.MouseEvent) => {
    panStart.current = { x: ev.clientX, y: ev.clientY, tx: view.tx, ty: view.ty };
    panMoved.current = false;
  };
  const onMouseMove = (ev: React.MouseEvent) => {
    if (!panStart.current) return;
    const dx = ev.clientX - panStart.current.x;
    const dy = ev.clientY - panStart.current.y;
    if (Math.abs(dx) + Math.abs(dy) > 3) panMoved.current = true;
    // 先取值再进 setView:updater 可能被 React 延迟执行,那时 mouseup 已把
    // panStart 置 null(探索链路「null.tx」渲染崩溃根因,实机复现后修)
    const { tx: baseTx, ty: baseTy } = panStart.current;
    setView((v) => ({ ...v, tx: baseTx + dx, ty: baseTy + dy }));
  };
  const onMouseUp = () => {
    panStart.current = null;
  };

  const toggleCollapse = (id: string) => {
    setCollapsed((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  };

  const zoomBy = (f: number) => {
    const el = boxRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const mx = rect.width / 2;
    const my = rect.height / 2;
    setView((v) => {
      const k = Math.min(3, Math.max(0.25, v.k * f));
      const rr = k / v.k;
      return { k, tx: mx - (mx - v.tx) * rr, ty: my - (my - v.ty) * rr };
    });
  };

  const seedHuman = async () => {
    const text = intentText.trim();
    if (!text) return;
    try {
      if (seedMode === "hint") {
        await api.post(`/api/cases/${caseId}/hints`, { text });
      } else {
        await api.post(`/api/cases/${caseId}/intents`, { text });
      }
      setIntentText("");
      setSeedErr("");
      // SSE 推 node_added,图上看着冒出来
    } catch (e) {
      setSeedErr(e instanceof Error ? e.message : String(e));
    }
  };

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const n of Object.values(graph.nodes)) {
      if (n.kind === "intent") c[n.status] = (c[n.status] || 0) + 1;
    }
    return c;
  }, [graph]);

  const nodeCount = Object.keys(graph.nodes).length;

  // 小地图几何
  const mini = useMemo(() => {
    if (layout.width === 0) return null;
    const mw = 168;
    const mh = 104;
    const s = Math.min(mw / layout.width, mh / layout.height);
    return { mw, mh, s };
  }, [layout]);

  const jumpMini = (ev: React.MouseEvent<SVGSVGElement>) => {
    if (!mini) return;
    const el = boxRef.current;
    if (!el) return;
    const rect = ev.currentTarget.getBoundingClientRect();
    const wx = (ev.clientX - rect.left) / mini.s;
    const wy = (ev.clientY - rect.top) / mini.s;
    const box = el.getBoundingClientRect();
    setView((v) => ({ ...v, tx: box.width / 2 - wx * v.k, ty: box.height / 2 - wy * v.k }));
  };

  return (
    <div className="rounded-card bg-white shadow-card overflow-hidden" data-testid="intent-graph">
      {/* 头部:图例 + 活体状态 + 泳道开关 + 手写意图 */}
      <div className="flex items-center gap-3 px-4 py-2.5 border-b border-slate-100 flex-wrap">
        <span className="text-sm font-medium text-ink">探索链路</span>
        <Tip text="SSE 图增量流:快照+逐帧变更;断开自动重连(重连=新快照全量对齐)">
          <span
            className={`inline-flex items-center gap-1 text-[11px] ${
              connected ? "text-brand" : "text-amber-600"
            }`}
            data-testid="graph-live"
          >
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                connected ? "bg-brand animate-pulse" : "bg-amber-500"
              }`}
            />
            {connected ? "实时" : "重连中"}
          </span>
        </Tip>
        <span className="text-[11px] text-mute">
          节点 {nodeCount} · 执行中 {counts.running || 0} · 待批 {counts.awaiting_approval || 0}
          · 停车场 {counts.parked || 0}
        </span>
        <span className="hidden lg:inline-flex items-center gap-2 text-[10px] text-mute">
          {(["goal", "intent", "fact", "finding", "hint"] as const).map((k) => (
            <span key={k} className="inline-flex items-center gap-1">
              <span className="w-2.5 h-2.5 rounded-sm" style={{ background: KIND_BAR[k] }} />
              {KIND_LABEL[k]}
            </span>
          ))}
          <span className="inline-flex items-center gap-1 ml-1">
            {EDGE_KINDS.map((k) => (
              <span key={k} className="inline-flex items-center gap-0.5">
                <span
                  className="w-3 border-t-2"
                  style={{ borderColor: EDGE_STROKE[k], borderStyle: k === "proves" ? "dashed" : "solid" }}
                />
                {EDGE_LABEL[k]}
              </span>
            ))}
          </span>
        </span>
        <button
          onClick={() => setGroupHost((v) => !v)}
          className={`rounded-lg border px-2 py-0.5 text-[11px] transition-colors ${
            groupHost
              ? "border-brand-soft bg-brand-light text-brand"
              : "border-slate-200 text-mute hover:text-ink"
          }`}
          title="同主机域(host_scope)的意图在列内相邻排列"
          data-testid="host-lane-toggle"
        >
          主机泳道
        </button>
        <div className="flex-1" />
        {archived ? (
          <span
            className="rounded bg-slate-100 text-slate-500 px-2 py-0.5 text-[10px]"
            data-testid="archived-readonly"
            title="案件已归档:只读看历史,停派新意图;解归档后恢复"
          >
            已归档 · 只读
          </span>
        ) : (
          <>
        <div className="flex rounded-lg border border-slate-200 overflow-hidden text-[11px]"
          data-testid="seed-mode">
          {(["intent", "hint"] as const).map((m) => (
            <button
              key={m}
              onClick={() => setSeedMode(m)}
              className={`px-2 py-1 ${
                seedMode === m ? "bg-brand text-white" : "text-mute hover:text-ink"
              }`}
              title={m === "intent" ? "手写意图:直接进图执行" : "补充线索:挂图不执行,worker 下轮可见"}
            >
              {m === "intent" ? "意图" : "线索"}
            </button>
          ))}
        </div>
        <input
          value={intentText}
          onChange={(e) => setIntentText(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && void seedHuman()}
          placeholder={
            seedMode === "hint"
              ? "补充一条线索(挂图不执行,下轮排查可见)…"
              : "手写一条意图,直接进图执行…"
          }
          className="w-64 rounded-lg border border-slate-200 px-2.5 py-1 text-xs"
          data-testid="human-intent-input"
        />
        <button
          onClick={() => void seedHuman()}
          className="rounded-lg bg-brand text-white px-3 py-1 text-xs hover:bg-brand-dark"
          data-testid="seed-submit"
        >
          {seedMode === "hint" ? "补线索" : "提意图"}
        </button>
          </>
        )}
      </div>
      {seedErr && (
        <div className="mx-4 mt-2 rounded-lg bg-red-50 text-red-700 text-xs px-3 py-1.5">{seedErr}</div>
      )}

      <div
        ref={boxRef}
        className="relative overflow-hidden cursor-grab active:cursor-grabbing"
        style={{ height: "62vh", minHeight: 420 }}
        onMouseDown={onBgMouseDown}
        onMouseMove={onMouseMove}
        onMouseUp={onMouseUp}
        onMouseLeave={onMouseUp}
        onClick={() => {
          if (!panMoved.current) setSelected(null);
        }}
        data-testid="intent-graph-canvas"
      >
        {nodeCount === 0 ? (
          <div className="absolute inset-0 flex flex-col items-center justify-center text-sm text-mute gap-3">
            <div>意图图为空</div>
            {!archived && (
              <div className="flex items-center gap-2">
                <select
                  value={selPlaybook}
                  onChange={(e) => setSelPlaybook(e.target.value)}
                  className="rounded-lg border border-slate-200 px-2 py-1.5 text-xs bg-white"
                  data-testid="analyze-playbook-select"
                  title="选择排查模板(按应急类型已预选,可改)"
                >
                  {playbooks.length === 0 && <option value={selPlaybook}>{selPlaybook}</option>}
                  {playbooks.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.title || p.id}
                    </option>
                  ))}
                </select>
                <button
                  disabled={analyzing}
                  onClick={() => {
                    setSeedErr("");
                    setAnalyzing(true);
                    api
                      .post(`/api/cases/${caseId}/analyze`, { playbook: selPlaybook })
                      .catch((e) => setSeedErr(`一键分析启动失败: ${(e as Error).message}`))
                      .finally(() => setAnalyzing(false));
                  }}
                  className="rounded-lg bg-brand text-white px-3 py-1.5 text-xs hover:bg-brand-dark disabled:opacity-50"
                  data-testid="analyze-start-btn"
                >
                  {analyzing ? "启动中…" : "开始一键分析"}
                </button>
              </div>
            )}
            <div className="text-xs max-w-md text-center">
              一键分析(带 playbook)会从模板长出探索链路;右上角也可以直接手写一条意图。
              链路会在这里实时生长:飞入 → 脉冲(执行中)→ 变绿(证据支持)/琥珀(存疑·发现)。
            </div>
          </div>
        ) : (
          <div
            className="absolute left-0 top-0"
            style={{
              transform: `translate(${view.tx}px, ${view.ty}px) scale(${view.k})`,
              transformOrigin: "0 0",
              width: layout.width,
              height: layout.height,
            }}
          >
            {/* 连线层(贝塞尔+类型标签+箭头,压在卡片下) */}
            <svg
              className="absolute left-0 top-0 pointer-events-none"
              width={layout.width}
              height={layout.height}
            >
              <defs>
                {EDGE_KINDS.map((k) => (
                  <marker
                    key={k}
                    id={`arr-${k}`}
                    viewBox="0 0 8 8"
                    refX="7"
                    refY="4"
                    markerWidth="7"
                    markerHeight="7"
                    orient="auto"
                  >
                    <path d="M0,0 L8,4 L0,8 z" fill={EDGE_STROKE[k]} />
                  </marker>
                ))}
              </defs>
              {Object.values(graph.edges).map((e) => {
                const a = layout.pos.get(e.from_id);
                const b = layout.pos.get(e.to_id);
                if (!a || !b) return null; // 折叠隐藏/未知端点不画
                const { d, mx, my } = edgePath(a, b);
                const color = EDGE_STROKE[e.kind] || "#CBD5E1";
                return (
                  <g key={e.id}>
                    <path
                      d={d}
                      fill="none"
                      stroke={color}
                      strokeWidth={e.kind === "proves" ? 1.4 : 1.6}
                      strokeDasharray={e.kind === "proves" ? "6 4" : undefined}
                      markerEnd={`url(#arr-${EDGE_STROKE[e.kind] ? e.kind : "spawns"})`}
                      opacity={0.75}
                    />
                    <text
                      x={mx}
                      y={my - 4}
                      textAnchor="middle"
                      fontSize={9}
                      fill={color}
                      stroke="#fff"
                      strokeWidth={3}
                      paintOrder="stroke"
                    >
                      {EDGE_LABEL[e.kind] || e.kind}
                    </text>
                  </g>
                );
              })}
            </svg>

            {/* 卡片层 */}
            {Object.values(graph.nodes).map((n) => {
              const p = layout.pos.get(n.id);
              if (!p) return null; // 折叠隐藏
              const kids = childrenOf(graph, n.id).length;
              const isCollapsed = collapsed.has(n.id);
              return (
                <div
                  key={n.id}
                  className={`absolute rounded-xl bg-white border cursor-pointer select-none
                    transition-[left,top,box-shadow] duration-500 ease-out hover:shadow-lift
                    ${selected === n.id ? "border-brand ring-2 ring-brand/30 shadow-lift" :
                      n.status === "parked" ? "border-dashed border-slate-300 bg-slate-50/60 shadow-card" :
                      "border-slate-200 shadow-card"}
                    ${fresh.has(n.id) ? "node-flyin" : ""}
                    ${flash.has(n.id) ? "node-flash" : ""}`}
                  style={{ left: p.x, top: p.y, width: CARD_W, height: CARD_H }}
                  data-testid={`graph-node-${n.id}`}
                  data-kind={n.kind}
                  data-status={n.status}
                  onMouseDown={(ev) => ev.stopPropagation()}
                  onClick={(ev) => {
                    ev.stopPropagation();
                    setSelected(n.id);
                  }}
                  onDoubleClick={(ev) => {
                    ev.stopPropagation();
                    if (kids > 0) toggleCollapse(n.id);
                  }}
                  title={`[${KIND_LABEL[n.kind] || n.kind}] ${n.text}`}
                >
                  {/* 左色条(按类型) */}
                  <div
                    className="absolute left-0 top-0 bottom-0 w-1 rounded-l-xl"
                    style={{ background: KIND_BAR[n.kind] || "#94A3B8" }}
                  />
                  <div className="pl-3 pr-2 py-1.5 h-full flex flex-col">
                    <div className="flex items-center gap-1 min-w-0">
                      <span className="text-[10px] leading-none">{KIND_ICON[n.kind] || "▫️"}</span>
                      <span className="text-[9px] text-mute shrink-0">{KIND_LABEL[n.kind] || n.kind}</span>
                      {n.host_scope && (
                        <span className="text-[9px] text-mute font-mono truncate">
                          {short(n.host_scope)}
                        </span>
                      )}
                      <div className="flex-1" />
                      {/* hint=线索提示不执行,状态徽标无义(不显示,防「已关闭」误导) */}
                      {n.kind !== "hint" && (
                        <span
                          className={`shrink-0 inline-flex items-center gap-1 rounded-full px-1.5 py-px text-[9px] ${
                            STATUS_CHIP[n.status] || "bg-slate-100 text-slate-500"
                          }`}
                        >
                          {n.status === "running" && (
                            <span className="w-1 h-1 rounded-full bg-blue-600 run-dot" />
                          )}
                          {STATUS_LABEL[n.status] || n.status}
                        </span>
                      )}
                    </div>
                    <div className="mt-0.5 text-[11px] leading-snug text-ink line-clamp-2 break-all">
                      {n.text}
                    </div>
                  </div>
                  {/* 审批红角标 */}
                  {n.status === "awaiting_approval" && (
                    <span
                      className="absolute -top-1.5 -right-1.5 w-4 h-4 rounded-full bg-red-600 text-white
                        text-[9px] font-bold flex items-center justify-center ring-2 ring-white animate-pulse"
                      data-testid={`badge-${n.id}`}
                    >
                      !
                    </span>
                  )}
                  {/* 折叠 +N 角标 */}
                  {isCollapsed && (
                    <span
                      className="absolute -bottom-1.5 -right-1.5 min-w-4 h-4 px-0.5 rounded-full bg-brand text-white
                        text-[9px] flex items-center justify-center ring-2 ring-white"
                      data-testid={`collapsed-${n.id}`}
                    >
                      +{collapsedCount.get(n.id) || 0}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* 左下:缩放控制 */}
        {nodeCount > 0 && (
          <div className="absolute left-3 bottom-3 flex flex-col gap-1" data-testid="zoom-controls">
            <button
              onClick={(ev) => {
                ev.stopPropagation();
                zoomBy(1.25);
              }}
              onMouseDown={(ev) => ev.stopPropagation()}
              className="w-7 h-7 rounded-lg bg-white border border-slate-200 shadow-card text-sm text-ink hover:bg-paper"
              title="放大"
            >
              +
            </button>
            <button
              onClick={(ev) => {
                ev.stopPropagation();
                zoomBy(1 / 1.25);
              }}
              onMouseDown={(ev) => ev.stopPropagation()}
              className="w-7 h-7 rounded-lg bg-white border border-slate-200 shadow-card text-sm text-ink hover:bg-paper"
              title="缩小"
            >
              −
            </button>
            <button
              onClick={(ev) => {
                ev.stopPropagation();
                fitView(layout);
              }}
              onMouseDown={(ev) => ev.stopPropagation()}
              className="w-7 h-7 rounded-lg bg-white border border-slate-200 shadow-card text-[10px] text-ink hover:bg-paper"
              title="适配全图"
              data-testid="zoom-fit"
            >
              ⤢
            </button>
          </div>
        )}

        {/* 右下:小地图(点击跳视口) */}
        {mini && nodeCount > 0 && (
          <svg
            className="absolute right-3 bottom-3 rounded-lg bg-white/90 border border-slate-200 shadow-card cursor-crosshair"
            width={mini.mw}
            height={mini.mh}
            onMouseDown={(ev) => ev.stopPropagation()}
            onClick={jumpMini}
            data-testid="minimap"
          >
            {Object.values(graph.nodes).map((n) => {
              const p = layout.pos.get(n.id);
              if (!p) return null;
              return (
                <rect
                  key={n.id}
                  x={p.x * mini.s}
                  y={p.y * mini.s}
                  width={Math.max(3, CARD_W * mini.s)}
                  height={Math.max(2, CARD_H * mini.s)}
                  rx={1}
                  fill={KIND_BAR[n.kind] || "#94A3B8"}
                  opacity={0.8}
                />
              );
            })}
            {/* 视口框 */}
            <rect
              x={(-view.tx / view.k) * mini.s}
              y={(-view.ty / view.k) * mini.s}
              width={((boxRef.current?.clientWidth || 0) / view.k) * mini.s}
              height={((boxRef.current?.clientHeight || 0) / view.k) * mini.s}
              fill="none"
              stroke="#0E7C7B"
              strokeWidth={1}
              rx={2}
            />
          </svg>
        )}

        {/* 节点详情侧滑(拦截事件,不透到画布平移/点空白关详情) */}
        {selected && graph.nodes[selected] && (
          <div
            onMouseDown={(e) => e.stopPropagation()}
            onClick={(e) => e.stopPropagation()}
            onDoubleClick={(e) => e.stopPropagation()}
          >
            <IntentDetail
              node={graph.nodes[selected]}
              graph={graph}
              onClose={() => setSelected(null)}
              onSelect={setSelected}
              onAnchor={onAnchor}
            />
          </div>
        )}
      </div>
      <div className="px-4 py-1.5 border-t border-slate-100 text-[10px] text-mute">
        滚轮缩放 · 拖拽平移 · 双击折叠子树 · 点击卡片看详情;分层流:目标左 → 意图中 → 事实/发现右(按血缘拓扑分列);
        closed_exhausted=时间耗尽覆盖可能不全(如实);灰色虚线框=停车场未展开线索(人批才展开,见「停车场」tab)
      </div>
    </div>
  );
}
