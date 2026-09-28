// 审批中心铃铛(切片 8b):挂起意图计数 + 下拉一键批/拒。
// 数据来自案件页持有的意图图活态(SSE 实时)——批准落账后 planner 被唤醒,
// 图上看着该意图变 open → running 续长;批准/拒绝进审计哈希链(后端)。
import { useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import { pendingApprovals, type GraphState } from "../lib/intent";

export default function ApprovalBell({
  graph,
  onJump,
}: {
  graph: GraphState;
  onJump: (nodeId: string) => void; // 点条目 → 意图图上选中该节点
}) {
  const [open, setOpen] = useState(false);
  const [err, setErr] = useState("");
  const [acting, setActing] = useState("");
  const boxRef = useRef<HTMLDivElement>(null);
  const pending = pendingApprovals(graph);

  // 点外收起
  useEffect(() => {
    if (!open) return;
    const onDown = (ev: MouseEvent) => {
      if (boxRef.current && !boxRef.current.contains(ev.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  const decide = async (id: string, approve: boolean) => {
    setActing(id);
    setErr("");
    try {
      await api.post(`/api/intents/${id}/approve`, { approve });
      // SSE 推 node_updated,列表/图自动续
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setActing("");
    }
  };

  return (
    <div className="relative" ref={boxRef}>
      <button
        onClick={() => setOpen((o) => !o)}
        className={`relative rounded-lg px-2.5 py-1.5 text-sm transition-colors ${
          pending.length > 0 ? "text-red-600 hover:bg-red-50" : "text-mute hover:bg-white"
        }`}
        title={pending.length > 0 ? `${pending.length} 条意图待审批` : "审批中心(无待批)"}
        data-testid="approval-bell"
      >
        🔔
        {pending.length > 0 && (
          <span
            className="absolute -top-1 -right-1 min-w-[16px] h-4 rounded-full bg-red-600 text-white
              text-[10px] leading-4 text-center px-0.5"
            data-testid="approval-count"
          >
            {pending.length}
          </span>
        )}
      </button>
      {open && (
        <div
          className="absolute right-0 top-10 z-30 w-[420px] rounded-card bg-white border border-slate-100
            shadow-lift p-3"
          data-testid="approval-panel"
        >
          <div className="flex items-center gap-2 mb-2">
            <span className="text-sm font-medium text-ink">审批中心</span>
            <span className="text-[11px] text-mute">
              批量执行意图(scope=all)挂起待人批;批准即续跑,批/拒进审计
            </span>
          </div>
          {err && <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2 mb-2">{err}</div>}
          {pending.length === 0 ? (
            <div className="text-xs text-mute p-3 text-center">无待批意图</div>
          ) : (
            <div className="space-y-2 max-h-80 overflow-auto thin-scroll">
              {pending.map((n) => (
                <div
                  key={n.id}
                  className="rounded-lg border border-red-100 bg-red-50/40 p-2.5"
                  data-testid={`pending-${n.id}`}
                >
                  <button
                    onClick={() => {
                      setOpen(false);
                      onJump(n.id);
                    }}
                    className="text-left text-xs text-ink leading-relaxed hover:text-brand w-full"
                  >
                    {n.text}
                  </button>
                  <div className="flex items-center gap-2 mt-1.5">
                    <span className="text-[10px] text-mute flex-1">
                      {n.created_by === "ai" ? "AI 派生" : "规则/模板"} · 深度 {n.depth} ·{" "}
                      {new Date(n.created_at).toLocaleString("zh-CN", { hour12: false })}
                    </span>
                    <button
                      disabled={acting === n.id}
                      onClick={() => void decide(n.id, true)}
                      className="rounded-lg bg-brand text-white px-2.5 py-0.5 text-[11px] hover:bg-brand-dark disabled:opacity-50"
                      data-testid={`approve-${n.id}`}
                    >
                      批准
                    </button>
                    <button
                      disabled={acting === n.id}
                      onClick={() => void decide(n.id, false)}
                      className="rounded-lg border border-slate-200 text-mute px-2.5 py-0.5 text-[11px] hover:text-red-600 disabled:opacity-50"
                      data-testid={`reject-${n.id}`}
                    >
                      拒绝
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
