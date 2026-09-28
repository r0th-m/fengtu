// 审批记录页(切片十,照抄 ARTEX system/intercept/approvals 全局页形态,
// 应急映射):待处理区(跨案件 awaiting_approval 意图,批准/拒绝直连
// 既有 POST /api/intents/{id}/approve) + 全部记录(审计哈希链只读投影,
// 5s 轮询)。判断权归人:批准/拒绝永远是人点的按钮,进审计哈希链。
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Check, ClipboardList, RefreshCw, ShieldAlert, X } from "lucide-react";
import { api } from "../lib/api";
import type { ApprovalHistoryItem, ApprovalPendingItem } from "../lib/types";

const ACTION_LABEL: Record<string, string> = {
  "intent.approve": "批准",
  "intent.reject": "拒绝",
  "intent.stop": "人工停止",
};
const CREATED_BY_LABEL: Record<string, string> = {
  human: "人提出", ai: "AI 派生", rule: "规则/模板",
};

export default function ApprovalsPage() {
  const [pending, setPending] = useState<ApprovalPendingItem[]>([]);
  const [history, setHistory] = useState<ApprovalHistoryItem[]>([]);
  const [err, setErr] = useState("");
  const [acting, setActing] = useState("");

  const load = useCallback(async () => {
    try {
      const d = await api.get<{
        pending: ApprovalPendingItem[];
        history: ApprovalHistoryItem[];
      }>("/api/approvals");
      setPending(d.pending || []);
      setHistory(d.history || []);
      setErr("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [load]);

  // 批准/拒绝(与案件内审批 tab 同一端点同一语义;409 并发裁决如实显)
  const decide = async (id: string, approve: boolean) => {
    setActing(id);
    setErr("");
    try {
      await api.post(`/api/intents/${id}/approve`, { approve });
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setActing("");
    }
  };

  return (
    <div className="max-w-[1200px] mx-auto space-y-4" data-testid="approvals-page">
      <div className="flex items-center gap-2 flex-wrap">
        <h1 className="text-xl font-semibold tracking-tight flex items-center gap-2">
          <ClipboardList className="w-5 h-5 text-mute" />
          审批记录
          {pending.length > 0 && (
            <span className="rounded-md bg-red-100 px-1.5 py-0.5 text-[11px] text-red-700 font-normal"
              data-testid="approvals-pending-badge">
              {pending.length} 待审批
            </span>
          )}
        </h1>
        <div className="flex-1" />
        <button
          onClick={() => void load()}
          className="rounded-md p-1.5 text-mute hover:bg-slate-100 hover:text-ink transition-colors"
          title="刷新"
          data-testid="approvals-refresh"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>
      <p className="text-xs text-mute -mt-2">
        AI/规则派生的批量执行意图(scope=all)创建即挂起,人批准才运行——批准前执行一直阻塞;
        历史=审计哈希链只读投影(5s 轮询)
      </p>

      {err && (
        <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2">{err}</div>
      )}

      {/* 待处理(照抄 ARTEX「待处理(N)」区) */}
      {pending.length > 0 && (
        <section className="rounded-card bg-white shadow-card overflow-hidden"
          data-testid="approvals-pending-section">
          <div className="border-b border-slate-100 bg-red-50/40 px-4 py-2.5 flex items-center gap-1.5
            text-xs font-semibold text-red-700">
            <ShieldAlert className="w-3.5 h-3.5" />
            待处理({pending.length})
          </div>
          <div className="divide-y divide-slate-50">
            {pending.map((n) => (
              <div key={n.id} className="px-4 py-3" data-testid={`approval-pending-${n.id}`}>
                <div className="text-[13px] text-ink leading-relaxed">{n.text}</div>
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1 mt-1.5 text-[11px] text-mute">
                  <Link to={`/cases/${n.case_id}`} className="text-brand hover:underline">
                    {n.case_name || n.case_id.slice(0, 8)}
                  </Link>
                  <span>{CREATED_BY_LABEL[n.created_by] || n.created_by}</span>
                  {n.scope === "all" && (
                    <span className="rounded bg-red-100 text-red-700 px-1.5 py-px">批量执行(全案件)</span>
                  )}
                  {n.host_scope && <span>主机 {n.host_scope}</span>}
                  <span>{new Date(n.created_at).toLocaleString("zh-CN", { hour12: false })}</span>
                </div>
                <div className="flex gap-2 mt-2">
                  <button
                    disabled={acting === n.id}
                    onClick={() => void decide(n.id, true)}
                    data-testid={`approval-allow-${n.id}`}
                    className="inline-flex items-center gap-1 rounded-lg bg-brand text-white text-xs
                      font-medium px-3 py-1.5 hover:bg-brand-dark transition-colors disabled:opacity-50"
                  >
                    <Check className="w-3.5 h-3.5" />
                    批准
                  </button>
                  <button
                    disabled={acting === n.id}
                    onClick={() => void decide(n.id, false)}
                    data-testid={`approval-deny-${n.id}`}
                    className="inline-flex items-center gap-1 rounded-lg border border-red-200
                      text-red-600 text-xs font-medium px-3 py-1.5 hover:bg-red-50 transition-colors
                      disabled:opacity-50"
                  >
                    <X className="w-3.5 h-3.5" />
                    拒绝
                  </button>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* 全部记录(照抄 ARTEX「全部记录」区:表格形态) */}
      <section className="rounded-card bg-white shadow-card overflow-hidden">
        <div className="border-b border-slate-100 bg-slate-50/60 px-4 py-2.5 text-xs font-semibold text-ink">
          全部记录({history.length})
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-100 text-left text-[11px] text-mute">
              <th className="font-medium px-4 py-2.5">时间</th>
              <th className="font-medium px-3 py-2.5">裁决</th>
              <th className="font-medium px-3 py-2.5">操作人</th>
              <th className="font-medium px-3 py-2.5">案件</th>
              <th className="font-medium px-4 py-2.5">意图</th>
            </tr>
          </thead>
          <tbody data-testid="approvals-history">
            {history.map((h) => (
              <tr key={h.seq} className="border-b border-slate-50 last:border-0 hover:bg-brand-light/30">
                <td className="px-4 py-2.5 text-xs text-mute whitespace-nowrap">
                  {new Date(h.ts).toLocaleString("zh-CN", { hour12: false })}
                </td>
                <td className="px-3 py-2.5">
                  <span className={`rounded-full px-2 py-0.5 text-[11px] ring-1 whitespace-nowrap ${
                    h.action === "intent.approve"
                      ? "bg-emerald-50 text-emerald-700 ring-emerald-200"
                      : "bg-red-50 text-red-600 ring-red-200"
                  }`}>
                    {ACTION_LABEL[h.action] || h.action}
                  </span>
                </td>
                <td className="px-3 py-2.5 text-xs text-slate-600">{h.actor}</td>
                <td className="px-3 py-2.5 text-xs">
                  {h.case_id ? (
                    <Link to={`/cases/${h.case_id}`} className="text-brand hover:underline">
                      {h.case_name || h.case_id.slice(0, 8)}
                    </Link>
                  ) : (
                    <span className="text-mute">—</span>
                  )}
                </td>
                <td className="px-4 py-2.5 text-xs text-ink max-w-[420px] truncate" title={h.text}>
                  {h.text || "—"}
                </td>
              </tr>
            ))}
            {history.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-10 text-center text-sm text-mute">
                  暂无审批记录
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>
    </div>
  );
}
