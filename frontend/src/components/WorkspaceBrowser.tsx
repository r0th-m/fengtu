// 工作空间文件浏览器(切片十三,案件工作区隔离):从 WorkspacePage 抽出的
// 共用组件——全局工作空间页两层导航的第二层与案件页「工作区」tab 复用同一份
// (不抄两份)。props:caseID 非空=案件工作区(/api/cases/{id}/workspace/*),
// 空=未分配遗留区;rootLabel=面包屑根名(案件名/「未分配」);onHome 非空时
// 面包屑前加「工作空间 /」入口(点它回案件列表层)。
// 文件管理器本体=切片十一 ARTEX 复刻全套:面包屑逐级进目录、目录/文件混排
// 表格、新建文件夹、多文件上传、右侧抽屉预览/编辑(dirty+保存)、下载、
// 删除(二次 confirm)、刷新。写操作落审计(后端口径不动);文本按内容嗅探,
// 二进制/>8MB 如实只给下载。
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Download,
  FileText,
  Folder,
  FolderPlus,
  HardDrive,
  RefreshCw,
  Save,
  ShieldCheck,
  Trash2,
  Upload,
} from "lucide-react";
import { api, wsBase, workspaceDownload, workspaceUpload } from "../lib/api";
import type { WorkspaceEntry, WorkspaceFileView } from "../lib/types";

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}
function fmtTime(ms: number): string {
  return new Date(ms).toLocaleString("zh-CN", {
    year: "2-digit", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", hour12: false,
  });
}

interface EditState {
  file: WorkspaceFileView;
  content: string;
  dirty: boolean;
  saving: boolean;
}

export default function WorkspaceBrowser({
  caseID,
  rootLabel,
  onHome,
}: {
  caseID?: string;
  rootLabel: string;
  onHome?: () => void;
}) {
  const base = wsBase(caseID);
  const [path, setPath] = useState("");
  const [entries, setEntries] = useState<WorkspaceEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [edit, setEdit] = useState<EditState | null>(null);
  const [mkdirOpen, setMkdirOpen] = useState(false);
  const [mkdirName, setMkdirName] = useState("");
  const [err, setErr] = useState("");
  const [okMsg, setOkMsg] = useState("");
  const uploadRef = useRef<HTMLInputElement>(null);

  const flash = (msg: string) => {
    setOkMsg(msg);
    setTimeout(() => setOkMsg(""), 3000);
  };

  const load = useCallback(async (p: string) => {
    setLoading(true);
    try {
      const d = await api.get<{ path: string; entries: WorkspaceEntry[] }>(
        `${base}/list?path=${encodeURIComponent(p)}`,
      );
      setEntries(d.entries || []);
      setPath(d.path ?? p);
      setErr("");
    } catch (e) {
      setErr(`读取目录失败:${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setLoading(false);
    }
  }, [base]);

  useEffect(() => {
    void load("");
  }, [load]);

  // 面包屑:根名=rootLabel(案件名/未分配),逐级可点(ARTEX 同款);
  // onHome 非空时前面再挂「工作空间 /」回案件列表层
  const crumbs = useMemo(() => {
    const parts = path ? path.split("/") : [];
    const acc: { name: string; path: string }[] = [{ name: rootLabel, path: "" }];
    let cur = "";
    for (const part of parts) {
      cur = cur ? `${cur}/${part}` : part;
      acc.push({ name: part, path: cur });
    }
    return acc;
  }, [path, rootLabel]);

  const openFile = async (e: WorkspaceEntry) => {
    try {
      const f = await api.get<WorkspaceFileView>(
        `${base}/file?path=${encodeURIComponent(e.path)}`,
      );
      setEdit({ file: f, content: f.content ?? "", dirty: false, saving: false });
    } catch (ex) {
      setErr(`打开文件失败:${ex instanceof Error ? ex.message : String(ex)}`);
    }
  };

  const saveFile = async () => {
    if (!edit) return;
    setEdit({ ...edit, saving: true });
    try {
      await api.put(`${base}/file`, {
        path: edit.file.path, content: edit.content,
      });
      flash("已保存");
      setEdit((cur) => (cur ? { ...cur, dirty: false, saving: false } : cur));
      void load(path);
    } catch (ex) {
      setErr(`保存失败:${ex instanceof Error ? ex.message : String(ex)}`);
      setEdit((cur) => (cur ? { ...cur, saving: false } : cur));
    }
  };

  const del = async (e: WorkspaceEntry) => {
    if (!window.confirm(
      `确认删除${e.dir ? "目录" : "文件"} “${e.name}”?${e.dir ? "(含其下所有内容)" : ""}删除进审计链。`,
    )) return;
    try {
      await api.del(`${base}/entry?path=${encodeURIComponent(e.path)}`);
      flash("已删除");
      void load(path);
    } catch (ex) {
      setErr(`删除失败:${ex instanceof Error ? ex.message : String(ex)}`);
    }
  };

  const doUpload = async (files: FileList | null) => {
    if (!files || files.length === 0) return;
    try {
      const r = await workspaceUpload(path, Array.from(files), caseID);
      flash(`已上传 ${r.uploaded} 个文件`);
      void load(path);
    } catch (ex) {
      setErr(`上传失败:${ex instanceof Error ? ex.message : String(ex)}`);
    } finally {
      if (uploadRef.current) uploadRef.current.value = "";
    }
  };

  const doMkdir = async () => {
    const name = mkdirName.trim();
    if (!name) return;
    const target = path ? `${path}/${name}` : name;
    try {
      await api.post(`${base}/mkdir`, { path: target });
      flash("已创建目录");
      setMkdirOpen(false);
      setMkdirName("");
      void load(path);
    } catch (ex) {
      setErr(`创建失败:${ex instanceof Error ? ex.message : String(ex)}`);
    }
  };

  const downloadEntry = (p: string, name: string) =>
    workspaceDownload(p, name, caseID).catch((ex) =>
      setErr(`下载失败:${ex instanceof Error ? ex.message : String(ex)}`));

  return (
    <div className="space-y-4" data-testid="workspace-browser">
      {/* 头部:面包屑 + 操作(照抄 ARTEX:HardDrive + crumbs / 新建/上传/刷新) */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-1 text-sm">
          <HardDrive className="w-4 h-4 text-mute mr-1 shrink-0" />
          {onHome && (
            <span className="flex items-center gap-1">
              <button
                type="button"
                onClick={onHome}
                className="max-w-[160px] truncate rounded px-1.5 py-0.5 text-mute hover:bg-slate-100"
                data-testid="ws-home"
              >
                工作空间
              </button>
              <span className="text-mute">/</span>
            </span>
          )}
          {crumbs.map((c, i) => (
            <span key={c.path} className="flex items-center gap-1">
              {i > 0 && <span className="text-mute">/</span>}
              <button
                type="button"
                onClick={() => void load(c.path)}
                className={`max-w-[160px] truncate rounded px-1.5 py-0.5 hover:bg-slate-100 ${
                  i === crumbs.length - 1 ? "text-ink font-medium" : "text-mute"
                }`}
                data-testid={`ws-crumb-${i}`}
              >
                {c.name}
              </button>
            </span>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setMkdirOpen(true)}
            className="flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs text-ink hover:bg-slate-50"
            data-testid="ws-mkdir-btn"
          >
            <FolderPlus className="w-3.5 h-3.5" /> 新建文件夹
          </button>
          <button
            onClick={() => uploadRef.current?.click()}
            className="flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs text-ink hover:bg-slate-50"
            data-testid="ws-upload-btn"
          >
            <Upload className="w-3.5 h-3.5" /> 上传
          </button>
          <button
            onClick={() => void load(path)}
            className="rounded-md p-1.5 text-mute hover:bg-slate-100 hover:text-ink transition-colors"
            title="刷新"
            data-testid="ws-refresh"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
          <input
            ref={uploadRef}
            type="file"
            multiple
            className="hidden"
            data-testid="ws-upload-input"
            onChange={(e) => void doUpload(e.target.files)}
          />
        </div>
      </div>
      <p className="text-xs text-mute -mt-2 flex items-center gap-1.5">
        <ShieldCheck className="w-3.5 h-3.5 text-brand shrink-0" />
        {caseID
          ? "案件工作区:放在这里的补充材料,本案 AI 会话只读可见(参考材料不是证据,锚点仍只能锚采集物);写操作进审计链。"
          : "未分配区(旧全局工作区遗留,不属任何案件);写操作进审计链。"}
        与案件原件金库 vault/ 物理隔离;文本按内容嗅探,二进制/&gt;8MB 只能下载。
      </p>

      {err && (
        <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2" data-testid="ws-error">
          {err}
        </div>
      )}
      {okMsg && (
        <div className="rounded-lg bg-brand-light text-brand text-xs px-3 py-2" data-testid="ws-ok">
          {okMsg}
        </div>
      )}

      {/* 目录/文件混排表格(照抄 ARTEX:名称/大小/修改时间/操作) */}
      <div className="rounded-card bg-white shadow-card overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-100 text-left text-[11px] text-mute">
              <th className="font-medium px-4 py-2.5">名称</th>
              <th className="font-medium px-3 py-2.5 w-28 text-right">大小</th>
              <th className="font-medium px-3 py-2.5 w-40">修改时间</th>
              <th className="font-medium px-4 py-2.5 w-24 text-right">操作</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.path}
                className="border-b border-slate-50 last:border-0 hover:bg-brand-light/30 transition-colors"
                data-testid={`ws-row-${e.name}`}>
                <td className="px-4 py-2.5 max-w-[420px]">
                  <button
                    type="button"
                    onClick={() => (e.dir ? void load(e.path) : void openFile(e))}
                    className="flex items-center gap-2 text-left hover:underline min-w-0"
                    data-testid={`ws-entry-${e.name}`}
                  >
                    {e.dir ? (
                      <Folder className="w-4 h-4 shrink-0 text-blue-500" />
                    ) : (
                      <FileText className="w-4 h-4 shrink-0 text-slate-400" />
                    )}
                    <span className="truncate font-mono text-xs">{e.name}</span>
                  </button>
                </td>
                <td className="px-3 py-2.5 text-right text-xs font-mono tabular-nums text-mute whitespace-nowrap">
                  {e.dir ? "—" : fmtSize(e.size)}
                </td>
                <td className="px-3 py-2.5 text-xs text-mute whitespace-nowrap">
                  {fmtTime(e.mtime)}
                </td>
                <td className="px-4 py-2.5">
                  <div className="flex items-center justify-end gap-1">
                    {!e.dir && (
                      <button
                        className="rounded p-1 text-mute hover:bg-slate-100 hover:text-ink"
                        title="下载"
                        data-testid={`ws-dl-${e.name}`}
                        onClick={() => void downloadEntry(e.path, e.name)}
                      >
                        <Download className="w-3.5 h-3.5" />
                      </button>
                    )}
                    <button
                      className="rounded p-1 text-red-500 hover:bg-red-50"
                      title="删除"
                      data-testid={`ws-del-${e.name}`}
                      onClick={() => void del(e)}
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {entries.length === 0 && (
              <tr>
                <td colSpan={4} className="px-4 py-10 text-center text-sm text-mute">
                  {loading ? "加载中…" : "空目录"}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* 文件查看/编辑右侧抽屉(ARTEX Sheet;二进制/超大如实只给下载) */}
      {edit && (
        <div className="fixed inset-0 z-40" data-testid="ws-drawer">
          <div className="absolute inset-0 bg-black/20" onClick={() => setEdit(null)} />
          <div className="absolute top-0 right-0 h-full w-full sm:w-[640px] bg-white shadow-lift flex flex-col">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-100">
              <FileText className="w-4 h-4 shrink-0 text-mute" />
              <span className="truncate font-mono text-sm" title={edit.file.path}>
                {edit.file.path}
              </span>
              <span className="text-xs text-mute shrink-0">{fmtSize(edit.file.size)}</span>
              <div className="flex-1" />
              <button
                onClick={() => setEdit(null)}
                className="text-mute hover:text-ink text-sm px-1"
                title="关闭"
                data-testid="ws-drawer-close"
              >
                ✕
              </button>
            </div>

            {edit.file.binary || edit.file.too_large ? (
              <div className="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center">
                <p className="text-sm text-mute" data-testid="ws-noedit-note">
                  {edit.file.too_large
                    ? "文件过大(>8MB),不支持在线预览/编辑,只能下载。"
                    : "二进制文件(按内容嗅探,非扩展名),不支持在线预览/编辑,只能下载。"}
                </p>
                <button
                  onClick={() => void downloadEntry(edit.file.path, edit.file.name)}
                  className="flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs hover:bg-slate-50"
                  data-testid="ws-download-binary"
                >
                  <Download className="w-3.5 h-3.5" /> 下载文件
                </button>
              </div>
            ) : (
              <>
                <div className="min-h-0 flex-1 p-3">
                  <textarea
                    value={edit.content}
                    onChange={(ev) =>
                      setEdit({ ...edit, content: ev.target.value, dirty: true })
                    }
                    spellCheck={false}
                    className="h-full w-full min-h-[50vh] resize-none rounded-lg border border-slate-200 p-3 font-mono text-xs leading-relaxed focus:outline-none focus:ring-1 focus:ring-brand/40"
                    data-testid="ws-editor"
                  />
                </div>
                <div className="flex items-center justify-between border-t border-slate-100 px-4 py-3">
                  <span className="text-xs text-mute" data-testid="ws-dirty-state">
                    {edit.dirty ? "未保存的修改" : "已同步"}
                  </span>
                  <div className="flex gap-2">
                    <button
                      onClick={() => void downloadEntry(edit.file.path, edit.file.name)}
                      className="flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs hover:bg-slate-50"
                      data-testid="ws-download"
                    >
                      <Download className="w-3.5 h-3.5" /> 下载
                    </button>
                    <button
                      onClick={() => void saveFile()}
                      disabled={!edit.dirty || edit.saving}
                      className="flex items-center gap-1.5 rounded-lg bg-brand px-3.5 py-1.5 text-xs text-white hover:bg-brand-dark disabled:opacity-50"
                      data-testid="ws-save"
                    >
                      <Save className="w-3.5 h-3.5" /> {edit.saving ? "保存中…" : "保存"}
                    </button>
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* 新建文件夹对话框(ARTEX Dialog) */}
      {mkdirOpen && (
        <div className="fixed inset-0 z-40 flex items-center justify-center" data-testid="ws-mkdir-dialog">
          <div className="absolute inset-0 bg-black/20" onClick={() => setMkdirOpen(false)} />
          <div className="relative rounded-card bg-white shadow-lift w-full max-w-sm p-4 space-y-3">
            <h2 className="text-sm font-medium">新建文件夹</h2>
            <input
              autoFocus
              value={mkdirName}
              onChange={(e) => setMkdirName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && void doMkdir()}
              placeholder="文件夹名称(当前目录下)"
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-brand/40"
              data-testid="ws-mkdir-input"
            />
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setMkdirOpen(false)}
                className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs hover:bg-slate-50"
              >
                取消
              </button>
              <button
                onClick={() => void doMkdir()}
                disabled={!mkdirName.trim()}
                className="rounded-lg bg-brand px-3.5 py-1.5 text-xs text-white hover:bg-brand-dark disabled:opacity-50"
                data-testid="ws-mkdir-confirm"
              >
                创建
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
