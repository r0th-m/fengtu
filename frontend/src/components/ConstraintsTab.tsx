// 约束管理 tab(交互改造切片三,设计 §3 set_constraints 应急映射):
// 案件级操作约束(「不得触碰的生产系统清单/只读原则/时间窗」)——人增人删,
// 机器不自动抽取(判断权归人);注入 worker system 最高优先,对之后认领的
// 意图生效;增删进审计哈希链(硬删,历史在链上)。
// 数据流:5s 轮询 + JSON 签名去重(照抄 ARTEX 形态,lib/poll)。
import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { startPolling } from "../lib/poll";
import type { CaseConstraint } from "../lib/types";

export default function ConstraintsTab({ caseId }: { caseId: string }) {
  const [items, setItems] = useState<CaseConstraint[]>([]);
  const [err, setErr] = useState("");
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const stop = startPolling({
      fetcher: () =>
        api.get<{ constraints: CaseConstraint[] }>(
          `/api/cases/${caseId}/constraints`),
      onChange: (data) => {
        setItems((data as { constraints: CaseConstraint[] }).constraints || []);
        setErr("");
      },
      onError: setErr,
      intervalMs: 5000,
    });
    return stop;
  }, [caseId]);

  const add = async () => {
    const t = text.trim();
    if (!t || busy) return;
    setBusy(true);
    setErr("");
    try {
      await api.post(`/api/cases/${caseId}/constraints`, { text: t });
      setText("");
      const d = await api.get<{ constraints: CaseConstraint[] }>(
        `/api/cases/${caseId}/constraints`);
      setItems(d.constraints || []);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (id: string) => {
    if (busy) return;
    if (!window.confirm("删除该约束?删除动作进审计哈希链,对之后认领的意图生效。")) return;
    setBusy(true);
    setErr("");
    try {
      await api.del(`/api/cases/${caseId}/constraints/${id}`);
      setItems((prev) => prev.filter((c) => c.id !== id));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded-card bg-white shadow-card p-4" data-testid="constraints-tab">
      <div className="text-sm font-medium text-ink mb-1">操作约束</div>
      <div className="text-[11px] text-mute mb-3">
        人定的排查红线(如「不得触碰的生产系统清单/只读原则/时间窗」),注入 AI worker 的
        system 提示、最高优先,对之后认领的意图生效;增删进审计哈希链。
        机器不自动抽取——约束由人增删,判断权归人。
      </div>
      <div className="flex gap-2 mb-3">
        <input
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && void add()}
          placeholder="如:生产库 10.0.0.5 只读,禁任何写操作…"
          className="flex-1 rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs"
          data-testid="constraint-input"
        />
        <button
          disabled={busy || !text.trim()}
          onClick={() => void add()}
          className="rounded-lg bg-brand text-white px-3.5 py-1.5 text-xs hover:bg-brand-dark
            disabled:opacity-50"
          data-testid="constraint-add"
        >
          加约束
        </button>
      </div>
      {err && (
        <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2 mb-2">{err}</div>
      )}
      {items.length === 0 ? (
        <div className="text-xs text-mute p-3 text-center" data-testid="constraints-empty">
          暂无约束(不约束=AI 在只读工具集内自由排查;红线由人显式立)
        </div>
      ) : (
        <div className="space-y-1.5" data-testid="constraints-list">
          {items.map((c) => (
            <div key={c.id}
              className="flex items-baseline gap-2 rounded-lg border border-slate-100 px-3 py-2"
              data-testid={`constraint-${c.id}`}>
              <span className="flex-1 text-xs text-ink leading-relaxed">{c.text}</span>
              <span className="text-[10px] text-mute shrink-0">
                {c.created_by} · {new Date(c.created_at).toLocaleString("zh-CN", { hour12: false })}
              </span>
              <button
                disabled={busy}
                onClick={() => void remove(c.id)}
                className="text-[11px] text-mute hover:text-red-600 shrink-0 disabled:opacity-50"
                data-testid={`constraint-del-${c.id}`}
              >
                删除
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
