// 停车场 tab(0.24.0-convergence L2 呈现面):未展开线索的候诊室——
// 顶部预算消耗条(三闸当前值 + 案/章消耗 + 待处置数),下面待处置区
// (线索摘要+来源+归属建议+收官评估建议+[展开][丢弃]人批钮)与已处置
// 留痕区。判断权归人:展开/丢弃全走人点,AI 的「建议展开/丢弃」只是建议。
// 0.29.0-batch-ops:待处置条目支持勾选 + 批量展开/批量丢弃(批量也是人
// 逐批拍板;二次确认;结果如实汇报 N 成功/M 跳过)。勾选按 id 集合保留,
// 刷新后消失的 id 自然剔除。
// 数据:GET parking/budget;图活态(graph.seq)变更即重取(parked 节点
// 出入场就是图变更,SSE 已通)。
import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import type { GraphState } from "../lib/intent";
import {
  PARK_REASON_LABEL,
  PARKING_STATUS_LABEL,
  splitParking,
  suggestText,
  type BudgetStatus,
  type ParkingEntry,
} from "../lib/parking";

// BatchResult 批量端点回执(与后端 batchItemResult 对齐)。
interface BatchResult {
  results: { id: string; ok: boolean; error?: string }[];
  total: number;
  done: number;
  skipped: number;
}

export default function ParkingTab({
  caseId,
  graph,
}: {
  caseId: string;
  graph: GraphState; // 图活态:parked 出入场触发重取(与图同源,不另起轮询)
}) {
  const [items, setItems] = useState<ParkingEntry[]>([]);
  const [budget, setBudget] = useState<BudgetStatus | null>(null);
  const [err, setErr] = useState("");
  const [acting, setActing] = useState("");
  // 勾选集(按 id;仅 parked 可勾,刷新后消失的 id 自然剔除)
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [confirming, setConfirming] = useState<"deploy" | "dismiss" | "">("");
  const [batchBusy, setBatchBusy] = useState(false);
  const [batchMsg, setBatchMsg] = useState("");

  const load = useCallback(async () => {
    try {
      const [p, b] = await Promise.all([
        api.get<{ items: ParkingEntry[] }>(`/api/cases/${caseId}/parking`),
        api.get<{ budget: BudgetStatus }>(`/api/cases/${caseId}/budget`),
      ]);
      setItems(p.items || []);
      setBudget(b.budget);
      setErr("");
      // 勾选保留:消失的 id(已处置/被删)自然剔除
      const alive = new Set((p.items || []).map((x) => x.id));
      setSelected((prev) => {
        const next = new Set([...prev].filter((id) => alive.has(id)));
        return next.size === prev.size ? prev : next;
      });
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, [caseId]);

  useEffect(() => {
    void load();
  }, [load, graph.seq]); // 图变更(含 parked 出入场帧)即重取,免轮询

  const act = async (id: string, action: "deploy" | "dismiss") => {
    setActing(id);
    setErr("");
    try {
      await api.post(`/api/parking/${id}/${action}`);
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setActing("");
    }
  };

  const { parked, decided } = splitParking(items);

  const allChecked = parked.length > 0 && parked.every((p) => selected.has(p.id));
  const toggleAll = () => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (allChecked) for (const p of parked) next.delete(p.id);
      else for (const p of parked) next.add(p.id);
      return next;
    });
  };
  const toggleOne = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // 批量处置:二次确认 → 批量端点 → 如实汇报 + 重取
  const runBatch = async (action: "deploy" | "dismiss") => {
    const ids = parked.filter((p) => selected.has(p.id)).map((p) => p.id);
    setConfirming("");
    if (ids.length === 0) return;
    setBatchBusy(true);
    setBatchMsg("");
    try {
      const r = await api.post<BatchResult>("/api/parking/batch", { ids, action });
      setBatchMsg(
        `批量${action === "deploy" ? "展开" : "丢弃"}:${r.done} 成功` +
          (r.skipped > 0 ? ` / ${r.skipped} 跳过(已被处置或不存在,如实)` : ""),
      );
      setSelected(new Set());
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBatchBusy(false);
    }
  };

  return (
    <div className="rounded-card bg-white shadow-card p-4" data-testid="parking-tab">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-sm font-medium text-ink">停车场</span>
        <span className="text-[11px] text-mute">
          预算闸拦下/AI 登记的未展开线索;展开/丢弃永远人批,AI 收官评估只建议
        </span>
      </div>

      {/* 预算消耗条(预算可观测;闸值在系统配置页改,对之后派生即时生效) */}
      {budget && (
        <div className="mt-2 rounded-lg bg-slate-50 border border-slate-100 px-3 py-2"
          data-testid="parking-budget">
          <div className="text-[11px] text-slate-600">
            自动派生意图 <b>{budget.case_intents}</b>/{budget.limits.case}
            (案) · 扇出上限 {budget.limits.fanout}/意图 · 章上限{" "}
            {budget.limits.chapter}/章 · 待处置 {budget.parked} 条
          </div>
          {budget.chapters.length > 0 && (
            <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5">
              {budget.chapters.map((c) => (
                <span key={c.goal_id} className="text-[10px] text-mute"
                  data-testid={`budget-chapter-${c.goal_id}`}>
                  章「{c.title}」{c.intents}/{c.limit}
                </span>
              ))}
            </div>
          )}
          <div className="mt-1 text-[10px] text-mute">
            人工手写意图/线索不占额(判断权归人);超闸历史见播报板「停车场」档与审计链
          </div>
        </div>
      )}

      {err && <div className="mt-2 rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2">{err}</div>}

      {/* 批量处置条:全选待处置 + 选中后出批量钮(判断权归人,逐批拍板) */}
      {parked.length > 0 && (
        <div className="mt-2 flex items-center gap-2 flex-wrap rounded-lg bg-slate-50 border border-slate-100 px-3 py-2"
          data-testid="parking-batch-bar">
          <label className="flex items-center gap-1.5 text-xs text-mute cursor-pointer">
            <input
              type="checkbox"
              data-testid="parking-select-all"
              checked={allChecked}
              onChange={toggleAll}
            />
            全选待处置({parked.length})
          </label>
          {selected.size > 0 && (
            <>
              <span className="text-xs text-ink" data-testid="parking-batch-count">
                已选 {selected.size} 条
              </span>
              <button
                data-testid="parking-batch-deploy"
                disabled={batchBusy}
                onClick={() => setConfirming("deploy")}
                className="rounded-lg bg-brand text-white text-xs font-medium px-3 py-1
                  hover:bg-brand-dark disabled:opacity-50"
              >
                批量展开
              </button>
              <button
                data-testid="parking-batch-dismiss"
                disabled={batchBusy}
                onClick={() => setConfirming("dismiss")}
                className="rounded-lg border border-slate-300 text-slate-600 text-xs font-medium
                  px-3 py-1 hover:border-red-300 hover:text-red-600 disabled:opacity-50"
              >
                批量丢弃
              </button>
              <button
                data-testid="parking-batch-clear"
                onClick={() => setSelected(new Set())}
                className="text-xs text-mute hover:text-ink"
              >
                清空选择
              </button>
            </>
          )}
          {batchMsg && (
            <span className="text-xs text-slate-600" data-testid="parking-batch-result">
              {batchMsg}
            </span>
          )}
        </div>
      )}

      {/* 待处置区 */}
      <div className="mt-3 space-y-2">
        {parked.length === 0 ? (
          <div className="text-xs text-mute p-3 text-center" data-testid="parking-empty">
            停车场为空:没有待处置的未展开线索(预算闸未触发、AI 未登记章外线索,如实)
          </div>
        ) : (
          parked.map((p) => (
            <div key={p.id} className="rounded-lg border border-dashed border-slate-300 bg-slate-50/50 p-3"
              data-testid={`parking-item-${p.id}`}>
              <div className="flex items-start gap-2">
                <input
                  type="checkbox"
                  data-testid={`parking-check-${p.id}`}
                  checked={selected.has(p.id)}
                  onChange={() => toggleOne(p.id)}
                  className="mt-0.5 shrink-0 cursor-pointer"
                />
                <div className="text-xs text-ink leading-relaxed break-all flex-1 min-w-0">{p.text}</div>
              </div>
              <div className="mt-1 flex items-center gap-2 flex-wrap text-[10px] text-mute">
                <span className="rounded bg-slate-200/70 px-1.5 py-px">
                  {PARK_REASON_LABEL[p.reason] || p.reason}
                </span>
                <span>归属建议:{suggestText(p)}</span>
                <span>{new Date(p.created_at).toLocaleString("zh-CN", { hour12: false })}</span>
              </div>
              {p.verdict && (
                <div className={`mt-1.5 rounded px-2 py-1 text-[11px] ${
                  p.verdict === "deploy"
                    ? "bg-green-50 text-green-700"
                    : "bg-slate-100 text-slate-500"
                }`}
                  data-testid={`parking-verdict-${p.id}`}>
                  章节收官评估建议:{p.verdict === "deploy" ? "建议展开" : "建议丢弃"}
                  {p.verdict_reason ? `——${p.verdict_reason}` : ""}(AI 只建议,你拍板)
                </div>
              )}
              <div className="mt-2 flex gap-2">
                <button
                  disabled={acting === p.id}
                  onClick={() => void act(p.id, "deploy")}
                  className="rounded-lg bg-brand text-white px-2.5 py-0.5 text-[11px] hover:bg-brand-dark disabled:opacity-50"
                  data-testid={`parking-deploy-${p.id}`}
                >
                  展开(按归属建议挂章,转正常意图派发)
                </button>
                <button
                  disabled={acting === p.id}
                  onClick={() => void act(p.id, "dismiss")}
                  className="rounded-lg border border-slate-200 text-mute px-2.5 py-0.5 text-[11px] hover:text-red-600 disabled:opacity-50"
                  data-testid={`parking-dismiss-${p.id}`}
                >
                  丢弃(留痕)
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* 已处置留痕区(判断权归人的历史账,不隐藏) */}
      {decided.length > 0 && (
        <div className="mt-4" data-testid="parking-decided">
          <div className="text-[11px] text-mute mb-1.5">已处置留痕({decided.length})</div>
          <div className="space-y-1.5">
            {decided.map((p) => (
              <div key={p.id}
                className="rounded-lg border border-slate-100 px-3 py-1.5 flex items-center gap-2"
                data-testid={`parking-decided-${p.id}`}>
                <span className={`rounded px-1.5 py-px text-[10px] ${
                  p.status === "deployed"
                    ? "bg-green-100 text-green-700"
                    : "bg-slate-100 text-slate-400"
                }`}>
                  {PARKING_STATUS_LABEL[p.status] || p.status}
                </span>
                <span className="text-[11px] text-mute truncate flex-1">{p.text}</span>
                <span className="text-[10px] text-mute shrink-0">
                  {p.decided_by || "?"}
                  {p.decided_at
                    ? ` · ${new Date(p.decided_at).toLocaleString("zh-CN", { hour12: false })}`
                    : ""}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
      {/* 批量处置二次确认(判断权归人;显示条数) */}
      {confirming && (
        <div
          className="fixed inset-0 z-50 bg-black/30 flex items-center justify-center p-4"
          onClick={() => setConfirming("")}
        >
          <div
            className="w-full max-w-sm rounded-card bg-white shadow-lg p-5 space-y-3"
            onClick={(e) => e.stopPropagation()}
            data-testid="parking-batch-confirm-dialog"
          >
            <h3 className="text-sm font-semibold text-ink">
              批量{confirming === "deploy" ? "展开" : "丢弃"}停车场线索
            </h3>
            <p className="text-xs text-slate-600 leading-relaxed">
              将对已选 <b>{parked.filter((p) => selected.has(p.id)).length}</b> 条待处置线索执行
              「{confirming === "deploy" ? "展开(视同人批,转正常意图派发)" : "丢弃(留痕)"}」。
              逐条同单条语义(已被处置的如实跳过),每条进审计链。
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setConfirming("")}
                className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs text-mute hover:text-ink"
              >
                取消
              </button>
              <button
                onClick={() => void runBatch(confirming)}
                disabled={batchBusy}
                className="rounded-lg bg-brand text-white px-3 py-1.5 text-xs hover:bg-brand-dark
                  disabled:opacity-40"
                data-testid="parking-batch-confirm-go"
              >
                确认{confirming === "deploy" ? "展开" : "丢弃"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
