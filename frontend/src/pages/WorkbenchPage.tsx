// 任务页(ARTEX tasks/page.tsx 列表形态复刻):页头标题/计数 + 搜索 +
// 状态筛选 + 主操作按钮「新建应急任务」+ 表格行,8s 轮询。
// 切片十退役说明:大拖包入口(HeroUpload「选择文件并分析」)已删——
// 任务统一走「新建应急任务」向导创建,上传在向导里做(判断权归人:
// 建任务=人的显式动作,不再是拖包即建)。
// 侧边栏/全局头由 AppShell 提供,本页不再自带 TopBar。
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Archive, ArchiveRestore, Pencil, Plus, Search, Trash2, Upload } from "lucide-react";
import { api, importCase } from "../lib/api";
import type { CaseInfo } from "../lib/types";
import ActivityFeed from "../components/ActivityFeed";
import Tip from "../components/Tip";
import { incidentTypeById } from "../lib/taskWizard";

type CaseStatusKey = "pending" | "reviewed" | "ingested" | "empty";

const isArchived = (c: CaseInfo) => !!c.archived_at;

function caseStatus(c: CaseInfo): { key: CaseStatusKey; label: string; cls: string; tip: string } {
  if ((c.pending_candidates ?? 0) > 0) {
    return {
      key: "pending",
      label: "待复核",
      cls: "bg-amber-50 text-amber-700 ring-amber-200",
      tip: "有未裁决的机器候选(状态=pending),需要人工裁决——判断权归人",
    };
  }
  if ((c.candidates ?? 0) > 0) {
    return {
      key: "reviewed",
      label: "已复核",
      cls: "bg-brand-light text-brand ring-brand/20",
      tip: "全部候选均已有人裁决(accepted/rejected),无 pending",
    };
  }
  if (c.sources > 0) {
    return {
      key: "ingested",
      label: "已摄入",
      cls: "bg-slate-100 text-slate-600 ring-slate-200",
      tip: "有源数据但尚无候选命中(未扫描或零命中,如实)",
    };
  }
  return {
    key: "empty",
    label: "空案件",
    cls: "bg-slate-50 text-slate-400 ring-slate-200",
    tip: "尚无数据源,走「新建应急任务」向导上传采集包",
  };
}

const STATUS_FILTERS: { value: CaseStatusKey | "all" | "archived"; label: string }[] = [
  { value: "all", label: "全部状态" },
  { value: "pending", label: "待复核" },
  { value: "reviewed", label: "已复核" },
  { value: "ingested", label: "已摄入" },
  { value: "empty", label: "空案件" },
  { value: "archived", label: "已归档" },
];

export default function WorkbenchPage() {
  const [cases, setCases] = useState<CaseInfo[]>([]);
  const [err, setErr] = useState("");
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<CaseStatusKey | "all" | "archived">("all");
  // 行操作(0.18.0 案件生命周期):改名对话框 / 删除双确认对话框
  const [renaming, setRenaming] = useState<CaseInfo | null>(null);
  const [renameText, setRenameText] = useState("");
  const [deleting, setDeleting] = useState<CaseInfo | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState("");
  const [opErr, setOpErr] = useState("");
  const [busy, setBusy] = useState(false);
  // 封存包导入(M4;POST /api/cases/import,登录即可)
  const fileRef = useRef<HTMLInputElement>(null);
  const [importing, setImporting] = useState(false);
  const [note, setNote] = useState("");

  const load = useCallback(async () => {
    try {
      const d = await api.get<{ cases: CaseInfo[] }>("/api/cases");
      setCases(d.cases || []);
      setErr("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    let stop = false;
    async function tick() {
      try {
        const d = await api.get<{ cases: CaseInfo[] }>("/api/cases");
        if (!stop) {
          setCases(d.cases || []);
          setErr("");
        }
      } catch (e) {
        if (!stop) setErr(e instanceof Error ? e.message : String(e));
      }
    }
    void tick();
    const t = setInterval(tick, 8000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  }, []);

  // 改名(PATCH /api/cases/{id};Enter 保存 Esc 取消)
  const submitRename = async () => {
    if (!renaming) return;
    const name = renameText.trim();
    if (!name) return;
    setBusy(true);
    setOpErr("");
    try {
      await api.patch(`/api/cases/${renaming.id}`, { name });
      setRenaming(null);
      await load();
    } catch (e) {
      setOpErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  // 归档/解归档(POST /api/cases/{id}/archive|unarchive)
  const toggleArchive = async (c: CaseInfo) => {
    setBusy(true);
    setErr("");
    try {
      await api.post(`/api/cases/${c.id}/${isArchived(c) ? "unarchive" : "archive"}`);
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  // 删除(双确认:逐字输名,前后端双闸;不可逆)
  const submitDelete = async () => {
    if (!deleting || deleteConfirm !== deleting.name) return;
    setBusy(true);
    setOpErr("");
    try {
      await api.del(`/api/cases/${deleting.id}`, { name: deleteConfirm });
      setDeleting(null);
      setDeleteConfirm("");
      await load();
    } catch (e) {
      setOpErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  // 导入封存包(multipart 字段 file;成功绿条报新案名 + 刷新列表,错误原文红条)
  const onImportFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    e.target.value = ""; // 重置,允许重复选同一文件
    if (!f) return;
    setImporting(true);
    setErr("");
    setNote("");
    try {
      const d = await importCase(f);
      setNote(`已导入「${d.case.name}」(源 ${d.sources} 个)`);
      await load();
    } catch (e2) {
      setErr(e2 instanceof Error ? e2.message : String(e2));
    } finally {
      setImporting(false);
    }
  };

  // 搜索 + 状态筛选(照抄 ARTEX 列表页:客户端过滤,量小不需要后端分页)
  // 归档口径(0.18.0):默认任何视图都不含已归档;筛选「已归档」只看归档案。
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return cases.filter((c) => {
      if (statusFilter === "archived") {
        if (!isArchived(c)) return false;
      } else {
        if (isArchived(c)) return false;
        if (statusFilter !== "all" && caseStatus(c).key !== statusFilter) return false;
      }
      if (!q) return true;
      const typeLabel = c.incident_type
        ? (incidentTypeById(c.incident_type)?.label ?? c.incident_type)
        : "";
      return (
        c.name.toLowerCase().includes(q) ||
        typeLabel.toLowerCase().includes(q) ||
        c.id.toLowerCase().includes(q)
      );
    });
  }, [cases, query, statusFilter]);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-[1fr_300px] gap-6 max-w-[1500px] mx-auto">
      <div className="space-y-5 min-w-0">
        <section>
          {/* 页头(照抄 ARTEX tasks 列表页:标题+计数 / 搜索 / 筛选 / 主操作) */}
          <div className="flex items-center gap-3 flex-wrap mb-3">
            <h2 className="text-base font-semibold">应急案件</h2>
            <span className="text-xs text-mute" data-testid="case-count">
              {filtered.length} / {cases.length} 个
            </span>
            <div className="flex-1" />
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-mute" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="搜索案件名 / 类型 / ID…"
                data-testid="case-search"
                className="rounded-lg border border-slate-200 bg-white pl-8 pr-3 py-1.5 text-xs w-56
                  focus:outline-none focus:ring-2 focus:ring-brand/40"
              />
            </div>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as CaseStatusKey | "all" | "archived")}
              data-testid="case-status-filter"
              className="rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-xs text-slate-600
                focus:outline-none focus:ring-2 focus:ring-brand/40"
            >
              {STATUS_FILTERS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
            <input
              ref={fileRef}
              type="file"
              accept=".zip"
              className="hidden"
              data-testid="case-import-input"
              onChange={(e) => void onImportFile(e)}
            />
            <button
              onClick={() => fileRef.current?.click()}
              disabled={importing}
              title="导入封存包(.zip)"
              data-testid="case-import-btn"
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white
                text-xs text-slate-600 px-3 py-1.5 hover:text-ink hover:border-slate-300
                transition-colors disabled:opacity-40"
            >
              <Upload className="w-3.5 h-3.5" />
              {importing ? "导入中…" : "导入封存包"}
            </button>
            <Link
              to="/cases/new"
              className="inline-flex items-center gap-1.5 rounded-lg bg-brand text-white text-xs
                font-medium px-3.5 py-1.5 hover:bg-brand-dark transition-colors shadow-sm"
            >
              <Plus className="w-3.5 h-3.5" />
              新建应急任务
            </Link>
          </div>
          {err && (
            <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2 mb-3">{err}</div>
          )}
          {note && (
            <div
              className="rounded-lg bg-emerald-50 text-emerald-700 text-xs px-3 py-2 mb-3"
              data-testid="case-import-note"
            >
              {note}
            </div>
          )}
          {/* 表格(照抄 ARTEX Table 形态:白卡容器 + 行 hover + 行点击进入详情) */}
          <div className="rounded-card bg-white shadow-card overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-100 text-left text-[11px] text-mute">
                  <th className="font-medium px-4 py-2.5">案件名称</th>
                  <th className="font-medium px-3 py-2.5">应急类型</th>
                  <th className="font-medium px-3 py-2.5">状态</th>
                  <th className="font-medium px-3 py-2.5 text-right">
                    <Tip text="源数:该案 sources 表登记的数据源(文件)总数">源</Tip>
                  </th>
                  <th className="font-medium px-3 py-2.5 text-right">
                    <Tip text="候选数:扫描命中进待审区的机器候选总数(hits 表计数);命中≠结论">
                      候选
                    </Tip>
                  </th>
                  <th className="font-medium px-3 py-2.5 text-right">
                    <Tip text="待裁决:状态=pending 的候选数,需人工接受/排除">待裁决</Tip>
                  </th>
                  <th className="font-medium px-4 py-2.5">创建时间</th>
                  <th className="font-medium px-3 py-2.5 text-right">操作</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((c) => {
                  const st = caseStatus(c);
                  return (
                    <tr
                      key={c.id}
                      className="border-b border-slate-50 last:border-0 hover:bg-brand-light/30
                        transition-colors cursor-pointer group"
                      data-testid={`case-row-${c.id}`}
                    >
                      <td className="px-4 py-3">
                        <Link
                          to={`/cases/${c.id}`}
                          className="font-medium text-ink group-hover:text-brand transition-colors
                            block truncate max-w-[320px]"
                          title={c.name}
                        >
                          {c.name}
                        </Link>
                        <div className="text-[10px] text-mute font-mono truncate max-w-[320px]">
                          {c.id}
                        </div>
                      </td>
                      <td className="px-3 py-3">
                        {c.incident_type && incidentTypeById(c.incident_type) ? (
                          <span className="rounded-full px-2 py-0.5 text-[11px] bg-brand-light/60
                            text-brand ring-1 ring-brand/20 whitespace-nowrap">
                            {incidentTypeById(c.incident_type)!.label}
                          </span>
                        ) : (
                          <span className="text-mute text-xs">—</span>
                        )}
                      </td>
                      <td className="px-3 py-3">
                        {isArchived(c) ? (
                          <span
                            className="rounded-full px-2 py-0.5 text-[11px] ring-1 whitespace-nowrap
                              bg-slate-100 text-slate-500 ring-slate-200"
                            data-testid={`archived-badge-${c.id}`}
                            title="已归档:停派新意图/禁起新分析,页面只读可看;解归档即恢复"
                          >
                            已归档
                          </span>
                        ) : (
                          <Tip text={st.tip}>
                            <span className={`rounded-full px-2 py-0.5 text-[11px] ring-1 whitespace-nowrap ${st.cls}`}>
                              {st.label}
                            </span>
                          </Tip>
                        )}
                      </td>
                      <td className="px-3 py-3 text-right tabular-nums text-xs">{c.sources}</td>
                      <td className="px-3 py-3 text-right tabular-nums text-xs">
                        {c.candidates ?? 0}
                      </td>
                      <td
                        className={`px-3 py-3 text-right tabular-nums text-xs ${
                          (c.pending_candidates ?? 0) > 0
                            ? "text-amber-600 font-semibold"
                            : ""
                        }`}
                      >
                        {c.pending_candidates ?? 0}
                      </td>
                      <td className="px-4 py-3 text-xs text-mute whitespace-nowrap">
                        {new Date(c.created_at).toLocaleString("zh-CN", { hour12: false })}
                      </td>
                      {/* 行操作(0.18.0):改名/归档·解归档/删除;图标+title */}
                      <td className="px-3 py-3">
                        <div className="flex items-center justify-end gap-1">
                          <button
                            title="改名"
                            data-testid={`rename-${c.id}`}
                            className="rounded-md p-1.5 text-mute hover:bg-slate-100 hover:text-ink transition-colors"
                            onClick={(e) => {
                              e.preventDefault();
                              e.stopPropagation();
                              setRenaming(c);
                              setRenameText(c.name);
                              setOpErr("");
                            }}
                          >
                            <Pencil className="w-3.5 h-3.5" />
                          </button>
                          <button
                            title={isArchived(c) ? "解归档(恢复派发与分析)" : "归档(列表默认隐藏,停派新意图)"}
                            data-testid={`archive-${c.id}`}
                            disabled={busy}
                            className="rounded-md p-1.5 text-mute hover:bg-slate-100 hover:text-ink transition-colors
                              disabled:opacity-40"
                            onClick={(e) => {
                              e.preventDefault();
                              e.stopPropagation();
                              void toggleArchive(c);
                            }}
                          >
                            {isArchived(c) ? (
                              <ArchiveRestore className="w-3.5 h-3.5" />
                            ) : (
                              <Archive className="w-3.5 h-3.5" />
                            )}
                          </button>
                          <button
                            title="删除(不可逆,需逐字输名确认)"
                            data-testid={`delete-${c.id}`}
                            className="rounded-md p-1.5 text-mute hover:bg-red-50 hover:text-red-600 transition-colors"
                            onClick={(e) => {
                              e.preventDefault();
                              e.stopPropagation();
                              setDeleting(c);
                              setDeleteConfirm("");
                              setOpErr("");
                            }}
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
                {filtered.length === 0 && (
                  <tr>
                    <td colSpan={8} className="px-4 py-10 text-center text-sm text-mute">
                      {cases.length === 0 && !err
                        ? "还没有任务——点右上「新建应急任务」创建(上传在向导里做)"
                        : "无匹配案件(调整搜索或筛选)"}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>
      <ActivityFeed />

      {/* 改名对话框(Enter 保存 / Esc 取消;口径与创建一致:非空去空白 ≤128 字) */}
      {renaming && (
        <div
          className="fixed inset-0 z-50 bg-black/30 flex items-center justify-center p-4"
          onClick={() => setRenaming(null)}
        >
          <div
            className="w-full max-w-sm rounded-card bg-white shadow-lg p-5 space-y-3"
            onClick={(e) => e.stopPropagation()}
            data-testid="rename-dialog"
          >
            <h3 className="text-sm font-semibold">任务改名</h3>
            <input
              autoFocus
              value={renameText}
              onChange={(e) => setRenameText(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void submitRename();
                if (e.key === "Escape") setRenaming(null);
              }}
              maxLength={128}
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm
                focus:outline-none focus:ring-2 focus:ring-brand/40"
              data-testid="rename-input"
            />
            {opErr && <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2">{opErr}</div>}
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setRenaming(null)}
                className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs text-mute hover:text-ink"
              >
                取消
              </button>
              <button
                onClick={() => void submitRename()}
                disabled={busy || !renameText.trim()}
                className="rounded-lg bg-brand text-white px-3 py-1.5 text-xs hover:bg-brand-dark
                  disabled:opacity-40"
                data-testid="rename-submit"
              >
                保存
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 删除双确认对话框(判断权归人:逐字输入案件名才放行;删除不可逆,
          级联清 PG 元数据 + CH 事件 + vault 原件 + 案件工作区) */}
      {deleting && (
        <div
          className="fixed inset-0 z-50 bg-black/30 flex items-center justify-center p-4"
          onClick={() => setDeleting(null)}
        >
          <div
            className="w-full max-w-md rounded-card bg-white shadow-lg p-5 space-y-3"
            onClick={(e) => e.stopPropagation()}
            data-testid="delete-dialog"
          >
            <h3 className="text-sm font-semibold text-red-700">删除任务(不可逆)</h3>
            <p className="text-xs text-slate-600 leading-relaxed">
              将删除「<span className="font-medium">{deleting.name}</span>」的全部数据:
              元数据(源/候选/意图/扫描账)、事件库该案事件、vault 原件(他案仍引用的保留)、
              案件工作区目录。该案历史审计条目保留在全局审计链。
              <br />
              请逐字输入案件名 <code className="rounded bg-slate-100 px-1">{deleting.name}</code> 确认:
            </p>
            <input
              autoFocus
              value={deleteConfirm}
              onChange={(e) => setDeleteConfirm(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void submitDelete();
                if (e.key === "Escape") setDeleting(null);
              }}
              placeholder={deleting.name}
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm font-mono
                focus:outline-none focus:ring-2 focus:ring-red-300"
              data-testid="delete-confirm-input"
            />
            {opErr && <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2">{opErr}</div>}
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setDeleting(null)}
                className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs text-mute hover:text-ink"
              >
                取消
              </button>
              <button
                onClick={() => void submitDelete()}
                disabled={busy || deleteConfirm !== deleting.name}
                className="rounded-lg bg-red-600 text-white px-3 py-1.5 text-xs hover:bg-red-700
                  disabled:opacity-40"
                data-testid="delete-submit"
                title={deleteConfirm !== deleting.name ? "案件名逐字匹配才放行" : "确认删除(不可逆)"}
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
