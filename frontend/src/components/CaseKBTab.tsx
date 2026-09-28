// 案件 KB 勾选管理 tab(0.20.0-case-kb;0.27.1-kb-simplify 启停下线):本案
// 生效的启发式条目 = 本案勾选(全局启停概念退役,知识库页只管条目内容)。
// 改即生效——对之后派发的 worker 生效,在跑的不追回(与并发上限同口径,如实
// 标注);勾选差集落审计 kb.case_update。存量案件(零勾选)如实提示:本案当前
// 不注入启发式参考,去勾选。头部「全选/全不选」作用于全部条目池。
import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import type { KBEntry } from "../lib/types";

interface CaseKBResp {
  entries: KBEntry[];
  selected: string[];
  note: string;
}

export default function CaseKBTab({ caseId }: { caseId: string }) {
  const [entries, setEntries] = useState<KBEntry[]>([]);
  const [checked, setChecked] = useState<string[]>([]);
  const [saved, setSaved] = useState<string[]>([]); // 库里的勾选集(脏位判断)
  const [note, setNote] = useState("");
  const [err, setErr] = useState("");
  const [ok, setOk] = useState("");
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);

  const load = useCallback(async () => {
    try {
      const d = await api.get<CaseKBResp>(`/api/cases/${caseId}/kb`);
      setEntries(d.entries || []);
      setChecked(d.selected || []);
      setSaved(d.selected || []);
      setNote(d.note || "");
      setErr("");
      setLoaded(true);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, [caseId]);

  useEffect(() => {
    void load();
  }, [load]);

  const dirty =
    checked.length !== saved.length || checked.some((id) => !saved.includes(id));

  const save = async () => {
    if (busy) return;
    setBusy(true);
    setErr("");
    setOk("");
    try {
      const d = await api.put<{ note?: string; added: string[]; removed: string[] }>(
        `/api/cases/${caseId}/kb`,
        { selected: checked },
      );
      setSaved(checked);
      setOk(
        `已保存(新增勾选 ${d.added?.length ?? 0} / 取消 ${d.removed?.length ?? 0},` +
          `审计 kb.case_update);对之后派发的 worker 生效,在跑的不追回`,
      );
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const toggle = (id: string) =>
    setChecked((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id],
    );

  // 全选/全不选(作用于全部条目池;勾选集以条目 id 为准)
  const selectAll = () => setChecked(entries.map((e) => e.id));
  const selectNone = () => setChecked([]);

  return (
    <div className="rounded-card bg-white shadow-card p-4" data-testid="case-kb-tab">
      <div className="flex items-center justify-between mb-1">
        <div className="text-sm font-medium text-ink">知识库条目(本案勾选)</div>
        <div className="flex gap-2">
          <button
            onClick={selectAll}
            disabled={entries.length === 0}
            className="rounded-lg border border-slate-200 px-2.5 py-1 text-[11px] text-mute
              hover:text-ink disabled:opacity-40"
            data-testid="case-kb-select-all"
          >
            全选
          </button>
          <button
            onClick={selectNone}
            disabled={checked.length === 0}
            className="rounded-lg border border-slate-200 px-2.5 py-1 text-[11px] text-mute
              hover:text-ink disabled:opacity-40"
            data-testid="case-kb-select-none"
          >
            全不选
          </button>
        </div>
      </div>
      <div className="text-[11px] text-mute mb-3">
        {note ||
          "本案生效 = 本案勾选(0.27.1 起不再有全局启停,知识库页只管条目内容);" +
            "勾选改即生效,对之后派发的 worker 生效,在跑的不追回。"}
      </div>

      {loaded && saved.length === 0 && (
        <div
          className="mb-3 rounded-lg bg-amber-50 text-amber-700 text-xs px-3 py-2"
          data-testid="case-kb-empty-hint"
        >
          本案当前未勾选任何知识库条目——AI worker 将不注入启发式参考段(如实,不兜底全量);
          在下方勾选后保存即生效。
        </div>
      )}

      {err && (
        <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2 mb-2" data-testid="case-kb-error">
          {err}
        </div>
      )}
      {ok && (
        <div className="rounded-lg bg-emerald-50 text-emerald-700 text-xs px-3 py-2 mb-2" data-testid="case-kb-ok">
          {ok}
        </div>
      )}

      <div className="space-y-1.5 mb-3" data-testid="case-kb-list">
        {entries.map((en) => {
          const on = checked.includes(en.id);
          return (
            <label
              key={en.id}
              className={`flex items-center gap-2.5 rounded-lg border px-3 py-2 cursor-pointer
                transition-colors ${
                  on
                    ? "border-brand/50 bg-brand-light/40"
                    : "border-slate-200 hover:bg-slate-50"
                }`}
              data-testid={`case-kb-row-${en.id}`}
            >
              <input
                type="checkbox"
                checked={on}
                onChange={() => toggle(en.id)}
                className="accent-brand"
                data-testid={`case-kb-check-${en.id}`}
              />
              <span className="text-xs font-medium text-ink">{en.title}</span>
              <span
                className={`rounded-full px-1.5 py-0.5 text-[10px] font-medium
                  ${en.source === "builtin" ? "bg-slate-100 text-slate-600" : "bg-brand-light text-brand"}`}
              >
                {en.source === "builtin" ? "内置" : "用户"}
              </span>
              {en.applies_to.map((t) => (
                <span
                  key={t}
                  className="rounded-full bg-slate-50 border border-slate-200 px-1.5 py-0.5
                    text-[10px] text-slate-500"
                >
                  {t}
                </span>
              ))}
              {on && (
                <span className="ml-auto text-[10px] text-brand shrink-0">本案生效</span>
              )}
            </label>
          );
        })}
        {entries.length === 0 && loaded && (
          <div className="text-xs text-mute p-3 text-center" data-testid="case-kb-none">
            知识库暂无条目(在「系统 → 知识库」新建)
          </div>
        )}
      </div>

      <div className="flex items-center gap-3">
        <button
          disabled={busy || !dirty}
          onClick={() => void save()}
          className="rounded-lg bg-brand text-white px-4 py-1.5 text-xs hover:bg-brand-dark
            disabled:opacity-50"
          data-testid="case-kb-save"
        >
          保存勾选
        </button>
        <span className="text-[11px] text-mute" data-testid="case-kb-stats">
          本案生效 {checked.length} 条(勾选即生效;条目池 {entries.length} 条)
        </span>
      </div>
    </div>
  );
}
