// 工作空间页(切片十三,按案件隔离;文件管理器本体在
// components/WorkspaceBrowser.tsx,与案件页「工作区」tab 复用同一份):
// 两层导航——第一层案件列表卡片(案件名+应急类型徽标+源/候选数),
// 点卡进第二层该案的文件管理器(面包屑根=「工作空间 / <案件名>」,
// 点「工作空间」回案件列表)。旧全局根下遗留文件给「未分配」入口
// (有遗留才出现,不丢用户文件;案件目录在服务端已滤出未分配区)。
// 证据链纪律不变:工作区与案件原件金库 vault/ 物理隔离;写操作进审计。
import { useCallback, useEffect, useState } from "react";
import { FolderOpen, HardDrive, Inbox } from "lucide-react";
import { api } from "../lib/api";
import type { CaseInfo, WorkspaceEntry } from "../lib/types";
import WorkspaceBrowser from "../components/WorkspaceBrowser";
import { incidentTypeById } from "../lib/taskWizard";

interface Scope {
  caseID?: string; // 空=未分配遗留区
  label: string;
}

export default function WorkspacePage() {
  const [cases, setCases] = useState<CaseInfo[]>([]);
  const [unassigned, setUnassigned] = useState<WorkspaceEntry[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");
  const [scope, setScope] = useState<Scope | null>(null); // null=案件列表层

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const d = await api.get<{ cases: CaseInfo[] }>("/api/cases");
      setCases(d.cases || []);
      // 未分配区:旧全局根遗留文件(服务端已滤掉案件目录;空=不显示入口)
      const u = await api.get<{ entries: WorkspaceEntry[] }>(
        "/api/workspace/list?path=",
      );
      setUnassigned(u.entries || []);
      setErr("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // 第二层:案件(或未分配区)文件管理器
  if (scope) {
    return (
      <div className="max-w-[1400px] mx-auto" data-testid="workspace-page">
        <WorkspaceBrowser
          caseID={scope.caseID}
          rootLabel={scope.label}
          onHome={() => { setScope(null); void load(); }}
        />
      </div>
    );
  }

  return (
    <div className="max-w-[1400px] mx-auto space-y-4" data-testid="workspace-page">
      <div className="flex items-center gap-2 text-sm">
        <HardDrive className="w-4 h-4 text-mute" />
        <span className="text-ink font-medium" data-testid="ws-crumb-0">工作空间</span>
      </div>
      <p className="text-xs text-mute -mt-2">
        工作区按案件隔离:选案件进入该案专属工作区;放在里面的补充材料,该案
        AI 会话只读可见(参考材料不是证据)。与案件原件金库 vault/ 物理隔离,
        写操作进审计链。
      </p>
      {err && (
        <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2" data-testid="ws-error">
          {err}
        </div>
      )}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3" data-testid="ws-case-list">
        {cases.map((c) => {
          const t = c.incident_type
            ? incidentTypeById(c.incident_type)?.label || c.incident_type
            : "";
          return (
            <button
              key={c.id}
              type="button"
              onClick={() => setScope({ caseID: c.id, label: c.name || c.id })}
              className="rounded-card bg-white shadow-card p-4 text-left hover:shadow-lift transition-shadow"
              data-testid={`ws-case-${c.id}`}
            >
              <div className="flex items-center gap-2 min-w-0">
                <FolderOpen className="w-4 h-4 shrink-0 text-blue-500" />
                <span className="truncate text-sm font-medium text-ink">{c.name || c.id}</span>
                {t && (
                  <span className="shrink-0 rounded bg-brand/10 text-brand px-1.5 py-0.5 text-[10px]">
                    {t}
                  </span>
                )}
              </div>
              <p className="mt-1.5 text-[11px] text-mute">
                源 {c.sources} · 候选 {c.candidates ?? 0}
              </p>
            </button>
          );
        })}
        {unassigned && unassigned.length > 0 && (
          <button
            type="button"
            onClick={() => setScope({ label: "未分配" })}
            className="rounded-card bg-white shadow-card p-4 text-left hover:shadow-lift transition-shadow border border-dashed border-slate-300"
            data-testid="ws-unassigned"
          >
            <div className="flex items-center gap-2">
              <Inbox className="w-4 h-4 shrink-0 text-slate-400" />
              <span className="text-sm font-medium text-ink">未分配</span>
            </div>
            <p className="mt-1.5 text-[11px] text-mute">
              旧全局工作区遗留({unassigned.length} 项,不属任何案件)
            </p>
          </button>
        )}
      </div>
      {!loading && cases.length === 0 && !(unassigned && unassigned.length > 0) && (
        <p className="text-sm text-mute" data-testid="ws-empty">暂无案件;先建应急任务。</p>
      )}
    </div>
  );
}
