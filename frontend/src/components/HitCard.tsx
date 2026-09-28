// 候选发现卡片:等级色 badge + 一句话 + 命中算子/规则 + 证据锚点
// (源+行号,点击跳内容树对应行)+「接受/排除」裁决按钮(醒目,交互主线)。
import { useState } from "react";
import type { Hit } from "../lib/types";
import { GradeBadge, SeverityDot } from "./GradeBadge";
import Tip from "./Tip";

export interface HitCardProps {
  hit: Hit;
  ruleTitle: string; // 规则/算子标题(rule_id → title,父组件解析)
  sourcePath: string; // 源显示路径(source_id → path)
  verdictFn: (hitId: string, status: "accepted" | "rejected") => Promise<Hit>;
  onAnchor: (sourceId: string, lineNo: number) => void;
  onUpdated?: (h: Hit) => void;
}

export default function HitCard({ hit, ruleTitle, sourcePath, verdictFn, onAnchor, onUpdated }: HitCardProps) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function decide(status: "accepted" | "rejected") {
    if (busy || hit.status !== "pending") return;
    setBusy(true);
    setErr("");
    try {
      const updated = await verdictFn(hit.id, status);
      onUpdated?.(updated);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const decided = hit.status !== "pending";

  return (
    <div
      data-testid={`hit-card-${hit.id}`}
      className={`rounded-card bg-white shadow-card p-4 transition-opacity ${
        decided ? "opacity-70" : ""
      }`}
    >
      <div className="flex items-center gap-2 flex-wrap">
        <GradeBadge grade={hit.evidence_grade} />
        <SeverityDot severity={hit.severity} />
        <span className="text-xs text-mute">第 {hit.round_no} 轮</span>
        <div className="flex-1" />
        {decided ? (
          <span
            data-testid={`verdict-state-${hit.id}`}
            className={`text-xs font-medium rounded-full px-2.5 py-1 ring-1 ${
              hit.status === "accepted"
                ? "bg-brand-light text-brand ring-brand/30"
                : "bg-slate-100 text-slate-500 ring-slate-200"
            }`}
          >
            {hit.status === "accepted" ? "已接受" : "已排除"}
            {hit.reviewed_by ? ` · ${hit.reviewed_by}` : ""}
          </span>
        ) : (
          <div className="flex items-center gap-2">
            <button
              data-testid={`accept-${hit.id}`}
              disabled={busy}
              onClick={() => void decide("accepted")}
              className="rounded-lg bg-brand text-white text-xs font-medium px-3.5 py-1.5
                hover:bg-brand-dark transition-colors disabled:opacity-50 shadow-sm"
            >
              接受
            </button>
            <button
              data-testid={`reject-${hit.id}`}
              disabled={busy}
              onClick={() => void decide("rejected")}
              className="rounded-lg border border-slate-300 text-slate-600 text-xs font-medium
                px-3.5 py-1.5 hover:border-red-300 hover:text-red-600 transition-colors
                disabled:opacity-50"
            >
              排除
            </button>
          </div>
        )}
      </div>

      {/* 一句话:命中规则/算子标题 + 命中内容摘要 */}
      <div className="mt-2.5 text-sm font-medium leading-relaxed">
        {ruleTitle || hit.rule_id}
      </div>
      <div className="mt-1 text-xs text-mute">
        <Tip text={`命中字段 ${hit.matched_field},匹配值「${hit.matched_value}」(子串匹配,大小写不敏感)`}>
          <span>
            命中 <b className="text-ink font-medium">{hit.rule_id}</b> · {hit.matched_field}
          </span>
        </Tip>
      </div>
      {hit.snippet && (
        <pre className="mt-2 rounded-lg bg-paper border border-slate-100 px-3 py-2 text-xs
          font-mono text-slate-700 whitespace-pre-wrap break-all leading-relaxed max-h-28 overflow-auto thin-scroll">
          {hit.snippet}
        </pre>
      )}

      {/* 证据锚点:源 + 行号,点击跳内容树对应行 */}
      <div className="mt-2.5 flex items-center gap-2 flex-wrap">
        <button
          data-testid={`anchor-${hit.id}`}
          onClick={() => onAnchor(hit.source_id, hit.line_no)}
          className="inline-flex items-center gap-1 rounded-lg bg-brand-light/60 text-brand
            text-xs px-2.5 py-1 hover:bg-brand-light transition-colors font-mono"
          title={`${sourcePath}:${hit.line_no}`}
        >
          <span className="font-sans">⚓</span>
          {sourcePath.split("/").pop()}:{hit.line_no}
        </button>
        <span className="text-[11px] text-mute truncate flex-1" title={sourcePath}>
          {sourcePath}
        </span>
        {hit.ts_utc && (
          <span className="text-[11px] text-mute">
            {new Date(hit.ts_utc).toLocaleString("zh-CN", { hour12: false })}
          </span>
        )}
      </div>
      {err && (
        <div className="mt-2 rounded-lg bg-red-50 text-red-700 text-xs px-3 py-1.5">{err}</div>
      )}
      <div className="mt-2 text-[11px] text-slate-400">
        命中≠结论:机器候选,判断权归人
      </div>
    </div>
  );
}
