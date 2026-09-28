// 知识库页(0.19.0-heuristic-kb 起;0.27.1-kb-simplify 启停下线):启发式
// 知识库 = 应急排查 tradecraft 沉淀(「怎么找答案」,不是模板步骤)。内置条目
// (configs/kb YAML)只读,用户条目(PG)可增改删。0.27.1 起本页纯管条目内容
// (列表/新建/编辑/删除)——启停概念整体退役,条目生效以新建任务/案件页勾选
// 为准(不再全量全局注入,省 token)。风格对齐系统配置/日志页。
import { useCallback, useEffect, useState } from "react";
import { BookOpen, Plus } from "lucide-react";
import { api } from "../lib/api";
import type { KBEntry } from "../lib/types";

// KNOWN_TAGS 适用场景多选集(与内置条目口径一致;后端不枚举,前端给常用面)。
const KNOWN_TAGS = [
  { key: "execution", label: "执行证据" },
  { key: "sample-recovery", label: "样本找回" },
  { key: "timeline", label: "时间线" },
  { key: "persistence", label: "持久化" },
  { key: "entry-point", label: "侵入点" },
];

interface Draft {
  id: string | null; // null=新建
  title: string;
  applies_to: string[];
  content: string;
}

export default function KBPage() {
  const [entries, setEntries] = useState<KBEntry[]>([]);
  const [note, setNote] = useState("");
  const [err, setErr] = useState("");
  const [draft, setDraft] = useState<Draft | null>(null);
  const [deleting, setDeleting] = useState<KBEntry | null>(null);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const d = await api.get<{ entries: KBEntry[]; note: string }>("/api/kb");
      setEntries(d.entries || []);
      setNote(d.note || "");
      setErr("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const submitDraft = async () => {
    if (!draft) return;
    setBusy(true);
    setErr("");
    try {
      const body = {
        title: draft.title.trim(),
        applies_to: draft.applies_to,
        content: draft.content.trim(),
      };
      if (draft.id === null) {
        await api.post("/api/kb", body);
      } else {
        await api.put(`/api/kb/${encodeURIComponent(draft.id)}`, body);
      }
      setDraft(null);
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const submitDelete = async () => {
    if (!deleting) return;
    setBusy(true);
    setErr("");
    try {
      await api.del(`/api/kb/${encodeURIComponent(deleting.id)}`);
      setDeleting(null);
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="max-w-[1200px] mx-auto space-y-4" data-testid="kb-page">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight flex items-center gap-2">
            <BookOpen className="w-5 h-5 text-mute" />
            知识库
          </h1>
          <p className="text-sm text-mute">
            {note || "启发式知识库(排查方法论沉淀;这里只管条目内容)"}
          </p>
        </div>
        <button
          onClick={() =>
            setDraft({ id: null, title: "", applies_to: [], content: "" })
          }
          className="rounded-lg bg-brand text-white px-3 py-1.5 text-xs hover:bg-brand-dark
            flex items-center gap-1.5 shrink-0"
          data-testid="kb-create"
        >
          <Plus className="w-3.5 h-3.5" />
          新建条目
        </button>
      </div>

      <div className="text-[11px] text-mute" data-testid="kb-stats">
        共 {entries.length} 条 · 这里只管条目内容(列表/新建/编辑/删除);
        条目生效在新建任务/案件页勾选(勾选即注入,本案零勾选不注入,
        上限 20 条按更新时间截断)
      </div>

      {err && (
        <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2" data-testid="kb-error">
          {err}
        </div>
      )}

      {/* 条目列表:标题/场景标签/来源徽标/更新时间 + 行操作(0.27.1 无启停开关) */}
      <div className="space-y-2" data-testid="kb-list">
        {entries.map((en) => (
          <div
            key={en.id}
            className="rounded-lg border border-slate-200 bg-white px-4 py-3"
            data-testid={`kb-row-${en.id}`}
          >
            <div className="flex items-center gap-2.5 flex-wrap">
              <span className="text-sm font-medium text-ink">{en.title}</span>
              <span
                className={`rounded-full px-2 py-0.5 text-[10px] font-medium
                  ${en.source === "builtin"
                    ? "bg-slate-100 text-slate-600"
                    : "bg-brand-light text-brand"}`}
                data-testid={`kb-source-${en.id}`}
              >
                {en.source === "builtin" ? "内置" : "用户"}
              </span>
              {en.applies_to.map((t) => (
                <span
                  key={t}
                  className="rounded-full bg-slate-50 border border-slate-200 px-2 py-0.5
                    text-[10px] text-slate-500"
                >
                  {KNOWN_TAGS.find((k) => k.key === t)?.label || t}
                </span>
              ))}
              <span className="ml-auto text-[11px] text-mute tabular-nums">
                更新 {new Date(en.updated_at).toLocaleString("zh-CN", { hour12: false })}
              </span>
              <button
                onClick={() =>
                  setExpanded((cur) => ({ ...cur, [en.id]: !cur[en.id] }))
                }
                className="text-[11px] text-brand hover:underline"
                data-testid={`kb-expand-${en.id}`}
              >
                {expanded[en.id] ? "收起" : "正文"}
              </button>
              {en.source === "user" && (
                <>
                  <button
                    onClick={() =>
                      setDraft({
                        id: en.id,
                        title: en.title,
                        applies_to: en.applies_to,
                        content: en.content,
                      })
                    }
                    className="text-[11px] text-brand hover:underline"
                    data-testid={`kb-edit-${en.id}`}
                  >
                    编辑
                  </button>
                  <button
                    onClick={() => setDeleting(en)}
                    className="text-[11px] text-red-600 hover:underline"
                    data-testid={`kb-del-${en.id}`}
                  >
                    删除
                  </button>
                </>
              )}
            </div>
            {expanded[en.id] && (
              <pre
                className="mt-2 whitespace-pre-wrap break-all rounded-lg bg-slate-50
                  border border-slate-100 p-3 text-xs text-slate-600 leading-relaxed"
                data-testid={`kb-content-${en.id}`}
              >
                {en.content}
              </pre>
            )}
          </div>
        ))}
        {entries.length === 0 && (
          <div className="text-center text-sm text-mute py-10">暂无条目</div>
        )}
      </div>

      {/* 新建/编辑对话框(title + applies_to 多选 + content) */}
      {draft && (
        <div
          className="fixed inset-0 z-50 bg-black/30 flex items-center justify-center p-4"
          onClick={() => setDraft(null)}
        >
          <div
            className="w-full max-w-lg rounded-card bg-white shadow-lg p-5 space-y-3"
            onClick={(e) => e.stopPropagation()}
            data-testid="kb-dialog"
          >
            <h3 className="text-sm font-semibold">
              {draft.id === null ? "新建知识库条目" : "编辑知识库条目"}
            </h3>
            <p className="text-[11px] text-mute leading-relaxed">
              写「怎么找答案」的启发式方法论,不写具体案件值(防过拟合);
              每破一个案子沉淀一条。注入 AI 时只是参考,不是证据也不是指令。
            </p>
            <input
              autoFocus
              value={draft.title}
              onChange={(e) => setDraft({ ...draft, title: e.target.value })}
              maxLength={200}
              placeholder="标题(如:某类痕迹的排查通道)"
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm
                focus:outline-none focus:ring-2 focus:ring-brand/40"
              data-testid="kb-title-input"
            />
            <div className="flex flex-wrap gap-1.5" data-testid="kb-tags">
              {KNOWN_TAGS.map((t) => {
                const on = draft.applies_to.includes(t.key);
                return (
                  <button
                    key={t.key}
                    onClick={() =>
                      setDraft({
                        ...draft,
                        applies_to: on
                          ? draft.applies_to.filter((k) => k !== t.key)
                          : [...draft.applies_to, t.key],
                      })
                    }
                    data-testid={`kb-tag-${t.key}`}
                    className={`rounded-full px-2.5 py-1 text-[11px] border transition-colors
                      ${on
                        ? "bg-brand-light text-brand border-brand/40"
                        : "bg-white text-mute border-slate-200 hover:text-ink"}`}
                  >
                    {t.label}
                  </button>
                );
              })}
            </div>
            <textarea
              value={draft.content}
              onChange={(e) => setDraft({ ...draft, content: e.target.value })}
              rows={8}
              placeholder="启发式正文:机制是什么、取证价值在哪、何时优先、怎么查"
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm
                focus:outline-none focus:ring-2 focus:ring-brand/40"
              data-testid="kb-content-input"
            />
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setDraft(null)}
                className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs text-mute hover:text-ink"
              >
                取消
              </button>
              <button
                onClick={() => void submitDraft()}
                disabled={
                  busy || !draft.title.trim() || !draft.content.trim() ||
                  draft.applies_to.length === 0
                }
                className="rounded-lg bg-brand text-white px-3 py-1.5 text-xs hover:bg-brand-dark
                  disabled:opacity-40"
                data-testid="kb-submit"
              >
                保存
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 删除二次确认(判断权归人;硬删,历史在审计链) */}
      {deleting && (
        <div
          className="fixed inset-0 z-50 bg-black/30 flex items-center justify-center p-4"
          onClick={() => setDeleting(null)}
        >
          <div
            className="w-full max-w-sm rounded-card bg-white shadow-lg p-5 space-y-3"
            onClick={(e) => e.stopPropagation()}
            data-testid="kb-delete-dialog"
          >
            <h3 className="text-sm font-semibold text-red-700">删除知识库条目</h3>
            <p className="text-xs text-slate-600 leading-relaxed">
              将删除「<span className="font-medium">{deleting.title}</span>」。
              硬删不可恢复,删除动作记录在审计链。内置条目不可删除。
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setDeleting(null)}
                className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs text-mute hover:text-ink"
              >
                取消
              </button>
              <button
                onClick={() => void submitDelete()}
                disabled={busy}
                className="rounded-lg bg-red-600 text-white px-3 py-1.5 text-xs hover:bg-red-700
                  disabled:opacity-40"
                data-testid="kb-delete-confirm"
              >
                确认删除
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
