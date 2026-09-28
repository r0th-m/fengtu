// 审批 tab(交互改造切片二,落地顺序第 2/3 条;设计 §3 照抄 ARTEX
// 审批数据流):待批队列=阻塞式一等呈现(挂起即执行阻塞,批准前 planner
// 不派发;409 并发裁决如实显)+ 审批历史(审计链 5s 轮询 + 签名去重)。
// 待批队列数据来自案件页活态图(SSE 实时),历史来自审计哈希链(只读)。
import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { pendingApprovals, type GraphState, type IntentNode } from "../lib/intent";
import { startPolling } from "../lib/poll";
import type { AuditEntry } from "../lib/types";

// CREATED_BY_LABEL 来源如实标(人提出的意图不过审批门,出现在队列里的
// 只会是 ai/rule,但字段如实呈现不假设)。
const CREATED_BY_LABEL: Record<string, string> = {
  human: "人提出", ai: "AI 派生", rule: "规则/模板",
};
const ACTION_LABEL: Record<string, string> = {
  "intent.approve": "批准", "intent.reject": "拒绝", "intent.stop": "人工停止",
};

// waitLabel 已等待时长(创建至今;审批挂起期间执行一直阻塞)。
function waitLabel(createdAt: string, now: number): string {
  const ms = now - new Date(createdAt).getTime();
  if (!(ms >= 0)) return "未知";
  const m = Math.floor(ms / 60000);
  if (m < 1) return "刚刚";
  if (m < 60) return `${m} 分钟`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} 小时 ${m % 60} 分`;
  return `${Math.floor(h / 24)} 天 ${h % 24} 小时`;
}

function PendingCard({
  n, now, acting, onDecide, onJump,
}: {
  n: IntentNode; now: number; acting: string;
  onDecide: (id: string, approve: boolean) => void;
  onJump: (id: string) => void;
}) {
  return (
    <div className="rounded-lg border border-red-200 bg-red-50/40 p-3"
      data-testid={`approval-pending-${n.id}`}>
      <button onClick={() => onJump(n.id)}
        className="text-left text-[13px] text-ink leading-relaxed hover:text-brand w-full">
        {n.text}
      </button>
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 mt-1.5 text-[11px] text-mute">
        <span>{CREATED_BY_LABEL[n.created_by] || n.created_by}</span>
        {n.scope === "all" && (
          <span className="rounded bg-red-100 text-red-700 px-1.5 py-px">批量执行(全案件)</span>
        )}
        {n.host_scope && <span>主机 {n.host_scope}</span>}
        <span>深度 {n.depth}</span>
        <span>{new Date(n.created_at).toLocaleString("zh-CN", { hour12: false })}</span>
        <span className="text-red-600">已阻塞等待 {waitLabel(n.created_at, now)}</span>
      </div>
      <div className="text-[11px] text-red-600/80 mt-1">
        执行阻塞中——批准前该意图不会被派发;批/拒进审计哈希链。
      </div>
      <div className="flex gap-2 mt-2">
        <button
          disabled={acting === n.id}
          onClick={() => onDecide(n.id, true)}
          className="rounded-lg bg-brand text-white px-3 py-1 text-xs hover:bg-brand-dark
            disabled:opacity-50"
          data-testid={`approval-approve-${n.id}`}
        >
          批准执行
        </button>
        <button
          disabled={acting === n.id}
          onClick={() => onDecide(n.id, false)}
          className="rounded-lg border border-slate-200 text-mute px-3 py-1 text-xs
            hover:text-red-600 disabled:opacity-50"
          data-testid={`approval-reject-${n.id}`}
        >
          拒绝
        </button>
      </div>
    </div>
  );
}

export default function ApprovalsTab({
  caseId, graph, onJump,
}: {
  caseId: string;
  graph: GraphState; // 案件页活态图(SSE)
  onJump: (nodeId: string) => void; // 跳主图聚焦
}) {
  const [err, setErr] = useState("");
  const [acting, setActing] = useState("");
  const [history, setHistory] = useState<AuditEntry[]>([]);
  const [histErr, setHistErr] = useState("");
  const [now, setNow] = useState(Date.now());
  const pending = pendingApprovals(graph);

  // 已等待时长 30s 一跳
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 30000);
    return () => clearInterval(t);
  }, []);

  // 审批历史:审计链 5s 轮询 + 签名去重(ARTEX 数据流形态)
  useEffect(() => {
    const stop = startPolling({
      fetcher: () =>
        api.get<{ entries: AuditEntry[] }>(
          `/api/audit/chain?case_id=${encodeURIComponent(caseId)}&limit=300`),
      onChange: (data) => {
        const entries = (data as { entries: AuditEntry[] }).entries || [];
        setHistory(
          entries
            .filter((en) => en.Action in ACTION_LABEL)
            .sort((a, b) => (b.TS || "").localeCompare(a.TS || "")),
        );
        setHistErr("");
      },
      onError: setHistErr,
      intervalMs: 5000,
    });
    return stop;
  }, [caseId]);

  const decide = async (id: string, approve: boolean) => {
    setActing(id);
    setErr("");
    try {
      await api.post(`/api/intents/${id}/approve`, { approve });
      // SSE 推 node_updated,待批队列自动续
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e)); // 409 并发裁决等如实显
    } finally {
      setActing("");
    }
  };

  return (
    <div className="space-y-4" data-testid="approvals-tab">
      <div className="rounded-card bg-white shadow-card p-4">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-sm font-medium text-ink">待批队列</span>
          {pending.length > 0 && (
            <span className="min-w-[18px] h-[18px] rounded-full bg-red-600 text-white
              text-[10px] leading-[18px] text-center px-1" data-testid="approvals-tab-count">
              {pending.length}
            </span>
          )}
        </div>
        <div className="text-[11px] text-mute mb-3">
          AI/规则派生的批量执行意图(scope=all)创建即挂起,人批准才运行——
          批准前执行一直阻塞;人提出的意图自由执行,不在此列。
        </div>
        {err && (
          <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2 mb-2">{err}</div>
        )}
        {pending.length === 0 ? (
          <div className="text-xs text-mute p-3 text-center">无待批意图</div>
        ) : (
          <div className="space-y-2">
            {pending.map((n) => (
              <PendingCard key={n.id} n={n} now={now} acting={acting}
                onDecide={(id, ok) => void decide(id, ok)} onJump={onJump} />
            ))}
          </div>
        )}
      </div>

      <div className="rounded-card bg-white shadow-card p-4">
        <div className="text-sm font-medium text-ink mb-1">审批历史</div>
        <div className="text-[11px] text-mute mb-3">
          审计哈希链只读投影(批准/拒绝/人工停止;5s 轮询,内容不变不重绘)。
        </div>
        {histErr && (
          <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2 mb-2">{histErr}</div>
        )}
        {history.length === 0 ? (
          <div className="text-xs text-mute p-3 text-center">暂无审批记录</div>
        ) : (
          <div className="space-y-1.5" data-testid="approval-history">
            {history.map((en) => {
              let text = "";
              try {
                text = JSON.parse(en.DetailJSON || "{}").text || "";
              } catch {
                /* detail 非预期形态如实留空 */
              }
              return (
                <div key={en.Seq} className="flex items-baseline gap-2 text-xs">
                  <span className="text-mute shrink-0">
                    {new Date(en.TS).toLocaleString("zh-CN", { hour12: false })}
                  </span>
                  <span className={
                    en.Action === "intent.approve" ? "text-green-700 shrink-0" : "text-red-600 shrink-0"
                  }>
                    {ACTION_LABEL[en.Action]}
                  </span>
                  <span className="text-mute shrink-0">{en.Actor}</span>
                  <span className="text-ink truncate">{text || en.Scope}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
