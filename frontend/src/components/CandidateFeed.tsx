// 候选发现视图(案件页主视图):筛选条极简(状态/等级)+ 卡片流。
// 0.29.0-batch-ops:待裁决候选支持勾选 + 批量接受/批量排除(判断权归人,
// 批量也是人逐批拍板;二次确认;结果如实汇报 N 成功/M 跳过)。勾选按 id 集合
// 保留,刷新后消失的 id 自然剔除。
import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import type { Hit, OperatorInfo, RuleInfo, SourceInfo } from "../lib/types";
import HitCard from "./HitCard";

// BatchResult 批量端点回执(与后端 batchItemResult 对齐)。
interface BatchResult {
  results: { id: string; ok: boolean; error?: string }[];
  total: number;
  done: number;
  skipped: number;
}

const STATUS_TABS = [
  { key: "pending", label: "待裁决" },
  { key: "", label: "全部" },
  { key: "accepted", label: "已接受" },
  { key: "rejected", label: "已排除" },
] as const;

const GRADE_FILTERS = [
  { key: "", label: "全部等级" },
  { key: "strong", label: "强疑似" },
  { key: "suspect", label: "疑似" },
  { key: "weak", label: "弱信号" },
] as const;

export default function CandidateFeed({
  caseId,
  sources,
  onAnchor,
}: {
  caseId: string;
  sources: SourceInfo[];
  onAnchor: (sourceId: string, lineNo: number) => void;
}) {
  const [hits, setHits] = useState<Hit[]>([]);
  const [titles, setTitles] = useState<Record<string, string>>({});
  const [status, setStatus] = useState<string>("pending");
  const [grade, setGrade] = useState<string>("");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(true);
  // 勾选集(按 id;仅 pending 可勾,刷新后消失的 id 自然剔除)
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [confirming, setConfirming] = useState<"accepted" | "rejected" | "">("");
  const [batchBusy, setBatchBusy] = useState(false);
  const [batchMsg, setBatchMsg] = useState("");

  const load = useCallback(async () => {
    try {
      const q = status ? `?status=${status}&limit=500` : "?limit=500";
      const [h, r, o] = await Promise.all([
        api.get<{ hits: Hit[] }>(`/api/cases/${caseId}/hits${q}`),
        api.get<{ rules: RuleInfo[] }>("/api/rules"),
        api.get<{ operators: OperatorInfo[] }>("/api/operators"),
      ]);
      const t: Record<string, string> = {};
      for (const x of r.rules || []) t[x.id] = x.title;
      for (const x of o.operators || []) t[x.id] = x.title;
      setHits(h.hits || []);
      setTitles(t);
      setErr("");
      // 勾选保留:消失的 id(被裁决后流出当前筛选/被删)自然剔除
      const alive = new Set((h.hits || []).map((x) => x.id));
      setSelected((prev) => {
        const next = new Set([...prev].filter((id) => alive.has(id)));
        return next.size === prev.size ? prev : next;
      });
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [caseId, status]);

  useEffect(() => {
    setLoading(true);
    void load();
  }, [load]);

  const verdictFn = useCallback(
    async (hitId: string, s: "accepted" | "rejected") => {
      const d = await api.post<{ hit: Hit }>(`/api/hits/${hitId}/verdict`, { status: s });
      return d.hit;
    },
    [],
  );

  const onUpdated = useCallback((updated: Hit) => {
    setHits((prev) => prev.map((h) => (h.id === updated.id ? updated : h)));
  }, []);

  const pathOf = useMemo(() => {
    const m: Record<string, string> = {};
    for (const s of sources) m[s.id] = s.path;
    return m;
  }, [sources]);

  const shown = grade ? hits.filter((h) => h.evidence_grade === grade) : hits;
  // 可勾选 = 当前展示的 pending(已裁决的勾选无意义,CAS 也不落)
  const selectable = shown.filter((h) => h.status === "pending");
  const allChecked =
    selectable.length > 0 && selectable.every((h) => selected.has(h.id));

  const toggleAll = () => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (allChecked) for (const h of selectable) next.delete(h.id);
      else for (const h of selectable) next.add(h.id);
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

  // 批量裁决:二次确认(confirming 档)→ 批量端点 → 如实汇报 + 重取
  const runBatch = async (s: "accepted" | "rejected") => {
    const ids = shown.filter((h) => selected.has(h.id)).map((h) => h.id);
    setConfirming("");
    if (ids.length === 0) return;
    setBatchBusy(true);
    setBatchMsg("");
    try {
      const r = await api.post<BatchResult>("/api/hits/batch-verdict", {
        ids, status: s,
      });
      setBatchMsg(
        `批量${s === "accepted" ? "接受" : "排除"}:${r.done} 成功` +
          (r.skipped > 0 ? ` / ${r.skipped} 跳过(已被裁决或不存在,如实)` : ""),
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
    <div className="space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <div className="flex rounded-lg bg-white shadow-card p-0.5">
          {STATUS_TABS.map((t) => (
            <button
              key={t.key}
              onClick={() => setStatus(t.key)}
              className={`rounded-md px-3 py-1.5 text-xs transition-colors ${
                status === t.key ? "bg-brand text-white" : "text-mute hover:text-ink"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
        <div className="flex rounded-lg bg-white shadow-card p-0.5">
          {GRADE_FILTERS.map((g) => (
            <button
              key={g.key}
              onClick={() => setGrade(g.key)}
              className={`rounded-md px-2.5 py-1.5 text-xs transition-colors ${
                grade === g.key ? "bg-brand-light text-brand font-medium" : "text-mute hover:text-ink"
              }`}
            >
              {g.label}
            </button>
          ))}
        </div>
        <span className="text-xs text-mute ml-auto">
          {shown.length} 条候选(命中≠结论)
        </span>
      </div>

      {/* 批量裁决条:本页全选(仅 pending 可勾)+ 选中后出批量钮 */}
      {selectable.length > 0 && (
        <div className="flex items-center gap-2 flex-wrap rounded-card bg-white shadow-card px-3 py-2"
          data-testid="batch-bar">
          <label className="flex items-center gap-1.5 text-xs text-mute cursor-pointer">
            <input
              type="checkbox"
              data-testid="batch-select-all"
              checked={allChecked}
              onChange={toggleAll}
            />
            全选本页待裁决({selectable.length})
          </label>
          {selected.size > 0 && (
            <>
              <span className="text-xs text-ink" data-testid="batch-count">
                已选 {selected.size} 条
              </span>
              <button
                data-testid="batch-accept"
                disabled={batchBusy}
                onClick={() => setConfirming("accepted")}
                className="rounded-lg bg-brand text-white text-xs font-medium px-3 py-1.5
                  hover:bg-brand-dark disabled:opacity-50"
              >
                批量接受
              </button>
              <button
                data-testid="batch-reject"
                disabled={batchBusy}
                onClick={() => setConfirming("rejected")}
                className="rounded-lg border border-slate-300 text-slate-600 text-xs font-medium
                  px-3 py-1.5 hover:border-red-300 hover:text-red-600 disabled:opacity-50"
              >
                批量排除
              </button>
              <button
                data-testid="batch-clear"
                onClick={() => setSelected(new Set())}
                className="text-xs text-mute hover:text-ink"
              >
                清空选择
              </button>
            </>
          )}
          {batchMsg && (
            <span className="text-xs text-slate-600" data-testid="batch-result">
              {batchMsg}
            </span>
          )}
        </div>
      )}

      {err && <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2">{err}</div>}
      {loading && <div className="text-xs text-mute py-6 text-center">候选加载中…</div>}
      {!loading && shown.length === 0 && !err && (
        <div className="rounded-card bg-white shadow-card p-8 text-center text-sm text-mute">
          该筛选下暂无候选
          {status === "pending" && "——没有待裁决项,或尚未跑一键分析/扫描"}
        </div>
      )}
      {shown.map((h) => (
        <div key={h.id} className="flex items-start gap-2">
          {h.status === "pending" && (
            <input
              type="checkbox"
              data-testid={`batch-check-${h.id}`}
              checked={selected.has(h.id)}
              onChange={() => toggleOne(h.id)}
              className="mt-5 shrink-0 cursor-pointer"
            />
          )}
          <div className="flex-1 min-w-0">
            <HitCard
              hit={h}
              ruleTitle={titles[h.rule_id] || ""}
              sourcePath={pathOf[h.source_id] || h.source_id}
              verdictFn={verdictFn}
              onAnchor={onAnchor}
              onUpdated={onUpdated}
            />
          </div>
        </div>
      ))}

      {/* 批量裁决二次确认(判断权归人;显示条数) */}
      {confirming && (
        <div
          className="fixed inset-0 z-50 bg-black/30 flex items-center justify-center p-4"
          onClick={() => setConfirming("")}
        >
          <div
            className="w-full max-w-sm rounded-card bg-white shadow-lg p-5 space-y-3"
            onClick={(e) => e.stopPropagation()}
            data-testid="batch-confirm-dialog"
          >
            <h3 className="text-sm font-semibold text-ink">
              批量{confirming === "accepted" ? "接受" : "排除"}候选
            </h3>
            <p className="text-xs text-slate-600 leading-relaxed">
              将对已选 <b>{shown.filter((h) => selected.has(h.id)).length}</b> 条候选执行
              「{confirming === "accepted" ? "接受" : "排除"}」裁决。
              逐条走人裁决语义(仅待裁决可落,已被他人裁决的如实跳过),
              每条都进审计链。裁决一次性,不可改判。
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
                data-testid="batch-confirm-go"
              >
                确认{confirming === "accepted" ? "接受" : "排除"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
