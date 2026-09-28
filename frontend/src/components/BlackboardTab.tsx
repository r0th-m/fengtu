// 黑板 tab(0.28.0-blackboard):「AI 现在知道什么」的只读视图——四段
// (已确认事实带锚点跳内容树/存疑发现/在查已查清单/停车场线索),与 worker
// systemExtra 注入同一份派生逻辑(后端 buildBlackboard),前端不另算。
// 只读:展开/丢弃停车场走人批(停车场 tab);这里什么都不许点出写操作。
// 数据:GET blackboard;图活态(graph.seq)变更即重取(与 ParkingTab 同源)。
import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { STATUS_LABEL, type GraphState } from "../lib/intent";
import { PARK_REASON_LABEL } from "../lib/parking";
import type { Blackboard } from "../lib/blackboard";

export default function BlackboardTab({
  caseId,
  graph,
  onAnchor,
}: {
  caseId: string;
  graph: GraphState; // 图活态:写回/派生触发重取(与图同源,不另起轮询)
  onAnchor: (sourceId: string, lineNo: number) => void; // 锚点跳内容树
}) {
  const [bb, setBb] = useState<Blackboard | null>(null);
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    try {
      const r = await api.get<{ blackboard: Blackboard }>(
        `/api/cases/${caseId}/blackboard`);
      setBb(r.blackboard);
      setErr("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, [caseId]);

  useEffect(() => {
    void load();
  }, [load, graph.seq]);

  const sec = (
    title: string, total: number, shown: number, testid: string,
    children: React.ReactNode,
  ) => (
    <div className="mt-3" data-testid={testid}>
      <div className="text-[11px] font-medium text-ink">
        {title}
        <span className="ml-1 font-normal text-mute">
          {shown}/{total} 条{total > shown ? "(其余未列出,如实)" : ""}
        </span>
      </div>
      <div className="mt-1 space-y-1">{children}</div>
    </div>
  );

  return (
    <div className="rounded-card bg-white shadow-card p-4" data-testid="blackboard-tab">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-sm font-medium text-ink">案件黑板</span>
        <span className="text-[11px] text-mute">
          本案实时状态(每个 worker 开工时注入的同一份):兄弟分支在查什么、
          已确认什么、什么存疑;只读,处置走各功能 tab
        </span>
      </div>

      {err && (
        <div className="mt-2 rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2"
          data-testid="blackboard-error">{err}</div>
      )}

      {bb && (
        <>
          {/* 已确认事实(proves 确认;锚点点击跳内容树定位行) */}
          {sec("已确认事实", bb.facts_total, bb.facts.length, "bb-facts",
            bb.facts.length === 0 ? (
              <div className="text-xs text-mute px-1" data-testid="bb-facts-empty">
                暂无证据支持的确认事实(如实)
              </div>
            ) : (
              bb.facts.map((f) => (
                <div key={f.node_id}
                  className="rounded-lg border border-green-100 bg-green-50/40 px-3 py-1.5"
                  data-testid={`bb-fact-${f.node_id}`}>
                  <div className="text-xs text-ink leading-relaxed break-all">{f.text}</div>
                  <div className="mt-0.5 flex flex-wrap gap-x-2 gap-y-0.5">
                    {(f.anchors || []).length === 0 ? (
                      <span className="text-[10px] text-mute">锚点缺失(见节点详情,如实)</span>
                    ) : (
                      (f.anchors || []).map((a, i) =>
                        a.source_id ? (
                          <button key={i}
                            onClick={() => onAnchor(a.source_id!, a.line_no || 1)}
                            className="text-[10px] text-brand hover:underline"
                            data-testid={`bb-anchor-${f.node_id}-${i}`}>
                            锚 {a.source_id}{a.line_no ? `:${a.line_no}` : ""}
                          </button>
                        ) : null)
                    )}
                  </div>
                </div>
              ))
            ))}

          {/* 存疑发现(doubt 意图摘要) */}
          {sec("存疑发现", bb.doubts_total, bb.doubts.length, "bb-doubts",
            bb.doubts.length === 0 ? (
              <div className="text-xs text-mute px-1" data-testid="bb-doubts-empty">暂无(如实)</div>
            ) : (
              bb.doubts.map((d) => (
                <div key={d.node_id}
                  className="rounded-lg border border-amber-100 bg-amber-50/40 px-3 py-1.5"
                  data-testid={`bb-doubt-${d.node_id}`}>
                  <span className="text-xs text-ink break-all">{d.intent}</span>
                  {d.summary && (
                    <span className="text-[11px] text-mute break-all"> → {d.summary}</span>
                  )}
                </div>
              ))
            ))}

          {/* 在查/已查意图清单(在查排前,标状态) */}
          {sec("在查 / 已查意图", bb.intents_total, bb.intents.length, "bb-intents",
            bb.intents.length === 0 ? (
              <div className="text-xs text-mute px-1" data-testid="bb-intents-empty">暂无(如实)</div>
            ) : (
              bb.intents.map((it) => (
                <div key={it.node_id}
                  className="flex items-center gap-2 px-1"
                  data-testid={`bb-intent-${it.node_id}`}>
                  <span className={`rounded px-1.5 py-px text-[10px] shrink-0 ${
                    it.status === "running" || it.status === "open"
                      ? "bg-blue-100 text-blue-700"
                      : it.status === "supported"
                        ? "bg-green-100 text-green-700"
                        : it.status === "doubt"
                          ? "bg-amber-100 text-amber-700"
                          : "bg-slate-100 text-slate-500"
                  }`}>
                    {STATUS_LABEL[it.status] || it.status}
                  </span>
                  <span className="text-[11px] text-ink truncate">{it.text}</span>
                </div>
              ))
            ))}

          {/* 停车场线索(待处置;处置走停车场 tab 人批) */}
          {sec("停车场线索", bb.parking_total, bb.parking.length, "bb-parking",
            bb.parking.length === 0 ? (
              <div className="text-xs text-mute px-1" data-testid="bb-parking-empty">暂无(如实)</div>
            ) : (
              bb.parking.map((p) => (
                <div key={p.id}
                  className="rounded-lg border border-dashed border-slate-200 px-3 py-1.5 flex items-center gap-2"
                  data-testid={`bb-parking-${p.id}`}>
                  <span className="rounded bg-slate-200/70 px-1.5 py-px text-[10px] shrink-0">
                    {PARK_REASON_LABEL[p.reason] || p.reason}
                  </span>
                  <span className="text-[11px] text-mute truncate">{p.text}</span>
                </div>
              ))
            ))}
        </>
      )}
    </div>
  );
}
