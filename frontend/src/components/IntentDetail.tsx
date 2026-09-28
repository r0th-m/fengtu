// 意图节点详情侧滑(切片 8b):文本/状态/血缘/执行过程流逐步/证据锚点
// (跳内容树)/子意图导航;待批节点一键批/拒(审批门),运行中可停止。
// 过程流:GET /api/intents/{id}(节点+events);running 时 3s 轮询续看,
// 图 SSE 的 node_updated 到达也会触发刷新(节流 1.5s)。
import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import {
  childrenOf,
  EDGE_LABEL,
  KIND_LABEL,
  STATUS_LABEL,
  type GraphState,
  type IntentNode,
} from "../lib/intent";

interface IntentEvent {
  id: number;
  node_id: string;
  kind: string; // plan|text|thinking|tool_use|tool_result|eval|spawn|budget|stop|error
  text: string;
  created_at: string;
}

const EVENT_LABEL: Record<string, string> = {
  plan: "计划",
  text: "回复",
  thinking: "思考",
  tool_use: "工具调用",
  tool_result: "工具返回",
  eval: "系统评估",
  spawn: "派生子意图",
  budget: "预算",
  stop: "停止",
  steer: "人工纠偏",
  error: "错误",
};

const EVENT_CLS: Record<string, string> = {
  tool_use: "text-brand",
  tool_result: "text-slate-500",
  eval: "text-amber-700",
  error: "text-red-600",
  budget: "text-amber-700",
  spawn: "text-violet-600",
  steer: "text-violet-600",
};

export default function IntentDetail({
  node,
  graph,
  onClose,
  onSelect,
  onAnchor,
}: {
  node: IntentNode;
  graph: GraphState;
  onClose: () => void;
  onSelect: (id: string) => void;
  onAnchor: (sourceId: string, lineNo: number) => void;
}) {
  const [events, setEvents] = useState<IntentEvent[]>([]);
  const [err, setErr] = useState("");
  const [actErr, setActErr] = useState("");
  const [acting, setActing] = useState(false);
  const lastFetch = useRef(0);
  const boxRef = useRef<HTMLDivElement>(null);

  const load = useCallback(
    async (force = false) => {
      const now = Date.now();
      if (!force && now - lastFetch.current < 1500) return; // 节流
      lastFetch.current = now;
      try {
        const d = await api.get<{ events: IntentEvent[] }>(`/api/intents/${node.id}`);
        setEvents(d.events || []);
        setErr("");
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e));
      }
    },
    [node.id],
  );

  useEffect(() => {
    void load(true);
  }, [load]);

  // 图变更(node_updated)到达 → 刷新过程流(节流);running 3s 轮询
  useEffect(() => {
    void load();
  }, [graph.seq, load]);
  useEffect(() => {
    if (node.status !== "running") return;
    const t = setInterval(() => void load(true), 3000);
    return () => clearInterval(t);
  }, [node.status, load]);

  // 新过程流自动滚底
  useEffect(() => {
    boxRef.current?.scrollTo({ top: boxRef.current.scrollHeight });
  }, [events.length]);

  const decide = async (approve: boolean) => {
    setActing(true);
    setActErr("");
    try {
      await api.post(`/api/intents/${node.id}/approve`, { approve });
      // SSE 推 node_updated;批准即唤醒 planner,图上续长
    } catch (e) {
      setActErr(e instanceof Error ? e.message : String(e));
    } finally {
      setActing(false);
    }
  };
  const stop = async () => {
    setActing(true);
    setActErr("");
    try {
      await api.post(`/api/intents/${node.id}/stop`);
    } catch (e) {
      setActErr(e instanceof Error ? e.message : String(e));
    } finally {
      setActing(false);
    }
  };
  // 切片三 steer 纠偏(设计 §3 steer_work 照抄):对在跑意图发人工消息——
  // 中断当前轮,同一 AI 会话按纠偏方向续跑(transcript 延续);wall-clock
  // 预算不延长;进审计哈希链。
  const [steerText, setSteerText] = useState("");
  const steer = async () => {
    const t = steerText.trim();
    if (!t || acting) return;
    setActing(true);
    setActErr("");
    try {
      await api.post(`/api/intents/${node.id}/steer`, { text: t });
      setSteerText("");
      void load(true); // 过程流即见「人工纠偏」步
    } catch (e) {
      setActErr(e instanceof Error ? e.message : String(e));
    } finally {
      setActing(false);
    }
  };

  const kids = childrenOf(graph, node.id);
  const parent = node.parent_id ? graph.nodes[node.parent_id] : null;
  const anchors = node.evidence || [];

  return (
    <div
      className="absolute top-0 right-0 h-full w-[380px] bg-white border-l border-slate-100
        shadow-lift flex flex-col"
      data-testid="intent-detail"
    >
      <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-100">
        <span className="text-xs rounded-full bg-brand-light text-brand px-2 py-0.5">
          {KIND_LABEL[node.kind] || node.kind}
        </span>
        <span className="text-xs text-mute">{STATUS_LABEL[node.status] || node.status}</span>
        <div className="flex-1" />
        <button onClick={onClose} className="text-mute hover:text-ink text-sm px-1" title="关闭">
          ✕
        </button>
      </div>

      <div className="flex-1 overflow-auto thin-scroll">
        <div className="px-4 py-3 space-y-3">
          <div className="text-sm text-ink leading-relaxed">{node.text}</div>
          <div className="text-[11px] text-mute space-y-0.5">
            <div>
              来源 {node.created_by === "human" ? "人提出" : node.created_by === "ai" ? "AI 派生" : "规则/模板"}
              {node.template_id && ` · 模板 ${node.template_id}`}
              {node.rule_id && ` · 规则 ${node.rule_id}`}
            </div>
            <div>
              范围 {node.scope === "all" ? "全案件(批量)" : "案件内"}
              {node.host_scope && ` · 主机 ${node.host_scope}`} · 深度 {node.depth} · 预算 {node.budget_seconds}s
            </div>
            <div>
              创建 {new Date(node.created_at).toLocaleString("zh-CN", { hour12: false })}
              {node.started_at && ` · 开工 ${new Date(node.started_at).toLocaleTimeString("zh-CN", { hour12: false })}`}
              {node.finished_at && ` · 收官 ${new Date(node.finished_at).toLocaleTimeString("zh-CN", { hour12: false })}`}
            </div>
          </div>

          {node.status === "awaiting_approval" && (
            <div className="rounded-lg bg-red-50 border border-red-100 p-3" data-testid="approval-box">
              <div className="text-xs text-red-700 mb-2">
                批量执行意图(scope=all),过审批门:批准才运行,批准/拒绝进审计哈希链。
              </div>
              <div className="flex gap-2">
                <button
                  disabled={acting}
                  onClick={() => void decide(true)}
                  className="rounded-lg bg-brand text-white px-3.5 py-1.5 text-xs hover:bg-brand-dark disabled:opacity-50"
                  data-testid="approve-btn"
                >
                  批准执行
                </button>
                <button
                  disabled={acting}
                  onClick={() => void decide(false)}
                  className="rounded-lg border border-slate-200 text-mute px-3.5 py-1.5 text-xs hover:text-red-600 disabled:opacity-50"
                  data-testid="reject-btn"
                >
                  拒绝
                </button>
              </div>
            </div>
          )}
          {node.status === "running" && (
            <div className="space-y-2" data-testid="steer-box">
              <div className="flex gap-2">
                <input
                  value={steerText}
                  onChange={(e) => setSteerText(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && void steer()}
                  placeholder="纠偏:调整在跑意图的方向…"
                  className="flex-1 rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs"
                  data-testid="steer-input"
                />
                <button
                  disabled={acting || !steerText.trim()}
                  onClick={() => void steer()}
                  className="rounded-lg bg-violet-600 text-white px-3 py-1.5 text-xs
                    hover:bg-violet-700 disabled:opacity-50"
                  data-testid="steer-btn"
                >
                  纠偏
                </button>
              </div>
              <div className="text-[10px] text-mute">
                纠偏=中断当前轮,同一会话按新方向续跑(执行记录延续),预算不延长;
                进审计哈希链。要终止用下方「停止」。
              </div>
              <button
                disabled={acting}
                onClick={() => void stop()}
                className="rounded-lg border border-red-200 text-red-600 px-3 py-1.5 text-xs hover:bg-red-50 disabled:opacity-50"
                data-testid="stop-btn"
              >
                停止(写回已得后关闭)
              </button>
            </div>
          )}
          {node.status === "open" && node.kind === "intent" && (
            <button
              disabled={acting}
              onClick={() => void stop()}
              className="rounded-lg border border-red-200 text-red-600 px-3 py-1.5 text-xs hover:bg-red-50 disabled:opacity-50"
              data-testid="kill-open-btn"
              title="终止未派发意图:直接关闭,不消耗 AI;进审计哈希链"
            >
              终止(未派发即关闭,不消耗 AI)
            </button>
          )}
          {actErr && <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2">{actErr}</div>}

          {node.result_text && (
            <div>
              <div className="text-xs font-medium text-ink mb-1">结论</div>
              <div className="rounded-lg bg-paper text-xs text-slate-700 p-3 leading-relaxed whitespace-pre-wrap">
                {node.result_text}
              </div>
            </div>
          )}
          {node.close_note && (
            <div className="rounded-lg bg-amber-50 text-amber-700 text-[11px] px-3 py-2">{node.close_note}</div>
          )}

          {anchors.length > 0 && (
            <div>
              <div className="text-xs font-medium text-ink mb-1">证据锚点({anchors.length})</div>
              <div className="space-y-1">
                {anchors.map((a, i) => (
                  <button
                    key={i}
                    onClick={() => a.source_id && onAnchor(a.source_id, a.line_no || 1)}
                    className="w-full text-left rounded-lg border border-slate-100 hover:border-brand-soft
                      px-2.5 py-1.5 text-[11px] text-slate-600 transition-colors"
                    data-testid={`anchor-${i}`}
                  >
                    <span className="font-mono text-brand">
                      {a.source_id ? `${a.source_id.slice(0, 8)}…:${a.line_no ?? "-"}` : a.hit_id || "(无锚)"}
                    </span>
                    {a.note && <span className="ml-1.5">{a.note}</span>}
                  </button>
                ))}
              </div>
            </div>
          )}

          {(parent || kids.length > 0) && (
            <div>
              <div className="text-xs font-medium text-ink mb-1">血缘</div>
              <div className="space-y-1 text-[11px]">
                {parent && (
                  <button
                    onClick={() => onSelect(parent.id)}
                    className="w-full text-left rounded-lg border border-slate-100 px-2.5 py-1.5 text-slate-600 hover:border-brand-soft"
                  >
                    ↑ 父:{(parent.text || "").slice(0, 40)}
                  </button>
                )}
                {kids.map((k) => (
                  <button
                    key={k.id}
                    onClick={() => onSelect(k.id)}
                    className="w-full text-left rounded-lg border border-slate-100 px-2.5 py-1.5 text-slate-600 hover:border-brand-soft"
                  >
                    ↓ {KIND_LABEL[k.kind] || k.kind}:{(k.text || "").slice(0, 40)}
                    <span className="text-mute ml-1">({STATUS_LABEL[k.status] || k.status})</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="px-4 pb-3">
          <div className="text-xs font-medium text-ink mb-1 sticky top-0 bg-white py-1">
            执行过程流({events.length} 步)
          </div>
          {err && <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2 mb-2">{err}</div>}
          <div ref={boxRef} className="space-y-1.5 max-h-[38vh] overflow-auto thin-scroll pr-1" data-testid="event-flow">
            {events.length === 0 && !err && (
              <div className="text-[11px] text-mute">
                {node.status === "awaiting_approval"
                  ? "待审批,未开工(批准后过程流在这里逐步长)"
                  : "尚无过程流(未开工或刚认领)"}
              </div>
            )}
            {events.map((ev) => (
              <div key={ev.id} className="rounded-lg bg-paper px-2.5 py-1.5">
                <div className="flex items-center gap-2 text-[10px] text-mute mb-0.5">
                  <span className={`font-medium ${EVENT_CLS[ev.kind] || "text-slate-600"}`}>
                    {EVENT_LABEL[ev.kind] || ev.kind}
                  </span>
                  <span>{new Date(ev.created_at).toLocaleTimeString("zh-CN", { hour12: false })}</span>
                </div>
                <div className="text-[11px] text-slate-700 whitespace-pre-wrap break-all leading-relaxed">
                  {ev.text}
                </div>
              </div>
            ))}
          </div>
          <div className="text-[10px] text-mute mt-2">
            {EDGE_LABEL.proves}边(虚线琥珀)= fact 证明意图;finding 候选在「候选发现」tab 待人裁决(判断权归人)
          </div>
        </div>
      </div>
    </div>
  );
}
