// 案件页(切片四 ARTEX detail/page.tsx 骨架复刻):full-bleed(AppShell 不套
// 全局头/内边距),自带 sticky 任务头 = 折叠触发钮 + 返回 + 任务名 + id chip +
// 应急类型徽标 + 状态机外显 + SSE 实况 + 审批铃铛 + tab 条(shadcn TabsList
// 形态:灰底容器+白块激活,替代原 pill 按钮);审批红点角标沿用。
// 意图图=活体主视图(默认 tab,探索链路实时生长);聊天 dock 右栏常驻。
// 图活态(useIntentGraph SSE)挂在本页层级——切 tab 不拆流,铃铛与图共用一份。
// 切片十:?analyze=1 上传直达链路随 HeroUpload 一并退役(任务统一走
// 「新建应急任务」向导,上传在向导里做);任务流面板随之删除。
import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Download, Pencil } from "lucide-react";
import { api, exportCase } from "../lib/api";
import { useIntentGraph } from "../lib/useIntentGraph";
import { pendingApprovals, type GraphState } from "../lib/intent";
import type { CaseInfo, NavAnchor, SourceInfo } from "../lib/types";
import { SidebarTrigger } from "../components/AppShell";
import ErrorBoundary from "../components/ErrorBoundary";
import IntentGraph from "../components/IntentGraph";
import LiveFeed from "../components/LiveFeed";
import CandidateFeed from "../components/CandidateFeed";
import ContentTree from "../components/ContentTree";
import SearchPanel from "../components/SearchPanel";
import TimelinePanel from "../components/TimelinePanel";
import ApprovalBell from "../components/ApprovalBell";
import ApprovalsTab from "../components/ApprovalsTab";
import ParkingTab from "../components/ParkingTab";
import BlackboardTab from "../components/BlackboardTab";
import ConstraintsTab from "../components/ConstraintsTab";
import CaseKBTab from "../components/CaseKBTab";
import ReportTab from "../components/ReportTab";
import WorkspaceBrowser from "../components/WorkspaceBrowser";
import ChatDock from "../components/ChatDock";
import { incidentTypeById, suggestPlaybook } from "../lib/taskWizard";

// 任务页 tab 骨架(交互改造切片二,落地顺序第 2 条;设计 §2 照抄 ARTEX
// detail/page.tsx:sticky 任务头 + tab 条;探索链路默认;审批红点角标)。
type Tab = "graph" | "candidates" | "tree" | "search" | "timeline" | "approvals" | "parking" | "blackboard" | "constraints" | "kb" | "report" | "workspace";

const TABS: { key: Tab; label: string }[] = [
  { key: "graph", label: "探索链路" },
  { key: "candidates", label: "候选发现" },
  { key: "tree", label: "内容树" },
  { key: "search", label: "检索" },
  { key: "timeline", label: "时间线" },
  { key: "approvals", label: "审批" },
  { key: "parking", label: "停车场" }, // 0.24.0:预算闸拦下/AI 登记的未展开线索,人批出入
  { key: "blackboard", label: "黑板" }, // 0.28.0:本案实时状态四段只读视图(AI 知道什么)
  { key: "constraints", label: "约束" },
  { key: "kb", label: "知识库" },
  { key: "workspace", label: "工作区" },
  { key: "report", label: "报告" },
];

// deriveStatus 任务状态外显(设计 §2 状态机外显;全部由图活态如实推导,
// 无在跑/待执行即如实「静默」,不装忙碌)。
function deriveStatus(graph: GraphState): { label: string; cls: string } {
  const nodes = Object.values(graph.nodes);
  const running = nodes.filter((n) => n.status === "running").length;
  const awaiting = nodes.filter((n) => n.status === "awaiting_approval").length;
  const open = nodes.filter((n) => n.status === "open").length;
  if (running > 0) return { label: `探索中 · ${running} 执行中`, cls: "bg-blue-100 text-blue-700" };
  if (awaiting > 0) return { label: `待审批 ${awaiting}`, cls: "bg-red-100 text-red-700" };
  if (open > 0) return { label: `待执行 ${open}`, cls: "bg-slate-100 text-slate-600" };
  return { label: "静默(无在跑/待执行意图)", cls: "bg-slate-100 text-slate-500" };
}

export default function CasePage() {
  const { id = "" } = useParams();
  const [caseInfo, setCaseInfo] = useState<CaseInfo | null>(null);
  const [sources, setSources] = useState<SourceInfo[]>([]);
  const [tab, setTab] = useState<Tab>("graph"); // 默认即意图图(8b 拍板)
  const [anchor, setAnchor] = useState<NavAnchor | null>(null);
  const [focus, setFocus] = useState<{ id: string; seq: number } | null>(null);
  const [err, setErr] = useState("");
  // 行内改名(0.18.0;Enter 保存 Esc 取消,PATCH /api/cases/{id})
  const [editingName, setEditingName] = useState(false);
  const [nameText, setNameText] = useState("");
  const [nameErr, setNameErr] = useState("");
  // 封存包导出中(M4;GET /api/cases/{id}/export → zip 下载)
  const [exporting, setExporting] = useState(false);
  const seqRef = useRef(0);
  const live = useIntentGraph(id);
  const pending = pendingApprovals(live.graph);
  // 停车场待处置数(0.24.0):parked 节点即图内未展开线索,SSE 同源免轮询
  const parkedCount = Object.values(live.graph.nodes).filter(
    (n) => n.kind === "intent" && n.status === "parked",
  ).length;
  const status = deriveStatus(live.graph);
  const typeLabel = caseInfo?.incident_type
    ? incidentTypeById(caseInfo.incident_type)?.label || caseInfo.incident_type
    : "";
  const archived = !!caseInfo?.archived_at;

  const submitRename = useCallback(async () => {
    const name = nameText.trim();
    if (!name) return;
    try {
      const d = await api.patch<{ case: CaseInfo }>(`/api/cases/${id}`, { name });
      setCaseInfo(d.case);
      setEditingName(false);
      setNameErr("");
    } catch (e) {
      setNameErr(e instanceof Error ? e.message : String(e));
    }
  }, [id, nameText]);

  const load = useCallback(async () => {
    try {
      const d = await api.get<{ case: CaseInfo; sources: SourceInfo[] }>(`/api/cases/${id}`);
      setCaseInfo(d.case);
      setSources(d.sources || []);
      setErr("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, [id]);

  // 导出封存包(M4;文件名走后端 Content-Disposition,取不到用案件名兜底)
  const doExport = useCallback(async () => {
    setExporting(true);
    setErr("");
    try {
      await exportCase(id, `丰图案件-${caseInfo?.name || id}.zip`);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setExporting(false);
    }
  }, [id, caseInfo?.name]);

  useEffect(() => {
    void load();
  }, [load]);

  // 锚点跳转:切内容树 + 定位行(seq 递增保证重复跳同锚也触发)
  const onAnchor = useCallback((sourceId: string, lineNo: number) => {
    seqRef.current += 1;
    setAnchor({ sourceId, lineNo, seq: seqRef.current });
    setTab("tree");
  }, []);

  // 审批中心跳节点:切探索链路 + 聚焦选中
  const onJumpNode = useCallback((nodeId: string) => {
    seqRef.current += 1;
    setFocus({ id: nodeId, seq: seqRef.current });
    setTab("graph");
  }, []);

  return (
    <div className="min-h-full">
      {/* sticky 任务头(照抄 ARTEX detail/page.tsx:top-0 三层——标题行/元信息行/
          tab 条;full-bleed 由 AppShell 让路,折叠触发钮在这里进场) */}
      <div className="sticky top-0 z-30 bg-paper/95 backdrop-blur border-b border-slate-200">
        <div className="px-4 lg:px-6 pt-2.5">
          <div className="flex items-center gap-2 flex-wrap">
            <SidebarTrigger className="-ml-1" />
            <Link
              to="/function/tasks"
              title="返回任务列表"
              data-testid="case-back"
              className="rounded-md p-1.5 text-mute hover:bg-slate-100 hover:text-ink transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
            </Link>
            {editingName ? (
              <span className="inline-flex items-center gap-1">
                <input
                  autoFocus
                  value={nameText}
                  onChange={(e) => setNameText(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") void submitRename();
                    if (e.key === "Escape") setEditingName(false);
                  }}
                  maxLength={128}
                  className="rounded-md border border-slate-300 px-2 py-0.5 text-sm w-64
                    focus:outline-none focus:ring-2 focus:ring-brand/40"
                  data-testid="case-rename-input"
                />
              </span>
            ) : (
              <>
                <span className="text-sm font-semibold text-ink truncate max-w-[420px]"
                  data-testid="case-title">
                  {caseInfo?.name || id}
                </span>
                <button
                  title="任务改名"
                  data-testid="case-rename-btn"
                  className="rounded-md p-1 text-mute hover:bg-slate-100 hover:text-ink transition-colors"
                  onClick={() => {
                    setNameText(caseInfo?.name || "");
                    setNameErr("");
                    setEditingName(true);
                  }}
                >
                  <Pencil className="w-3.5 h-3.5" />
                </button>
              </>
            )}
            {archived && (
              <span
                className="rounded bg-slate-100 text-slate-500 px-1.5 py-0.5 text-[10px]"
                data-testid="case-archived-badge"
                title="已归档:停派新意图/禁起新分析,只读看历史;解归档在任务列表行操作"
              >
                已归档
              </span>
            )}
            <code className="hidden sm:inline rounded bg-slate-100 px-1.5 py-0.5 font-mono
              text-[10px] text-mute">
              {id}
            </code>
            {typeLabel && (
              <span className="rounded bg-brand/10 text-brand px-1.5 py-0.5 text-[10px]"
                data-testid="case-type-badge">
                {typeLabel}
              </span>
            )}
            <span className={`rounded px-1.5 py-0.5 text-[10px] ${status.cls}`}
              data-testid="case-status">
              {status.label}
            </span>
            <div className="flex-1" />
            <button
              onClick={() => void doExport()}
              disabled={exporting}
              title={exporting ? "导出中…" : "导出封存包"}
              data-testid="case-export-btn"
              className="rounded-md p-1.5 text-mute hover:bg-slate-100 hover:text-ink transition-colors
                disabled:opacity-40"
            >
              <Download className="w-4 h-4" />
            </button>
            <span
              className={`inline-flex items-center gap-1 text-[10px] ${live.connected ? "text-brand" : "text-amber-600"}`}
              title="意图图 SSE 实况;断开时浏览器自动重连,断线游标补帧/快照兜底"
              data-testid="sse-live"
            >
              <span className={`inline-block w-1.5 h-1.5 rounded-full ${live.connected ? "bg-brand" : "bg-amber-400 animate-pulse"}`} />
              {live.connected ? "实时" : "重连中"}
            </span>
            <ApprovalBell graph={live.graph} onJump={onJumpNode} />
          </div>
          <p className="truncate text-[11px] text-mute mt-1" data-testid="case-meta">
            源 {caseInfo?.sources ?? "…"} · 候选 {caseInfo?.candidates ?? "…"} ·
            待裁决 {caseInfo?.pending_candidates ?? "…"}
            {nameErr && <span className="text-red-600 ml-2">{nameErr}</span>}
          </p>
          {/* tab 条:shadcn TabsList 形态(灰底圆角容器 + 白块激活),
              红点角标沿用(判断权归人入口) */}
          <div className="overflow-x-auto thin-scroll -mb-px">
            <div className="inline-flex items-center gap-0.5 rounded-lg bg-slate-100 p-1 my-2 min-w-max"
              role="tablist">
              {TABS.map((t) => (
                <TabBtn key={t.key} active={tab === t.key} onClick={() => setTab(t.key)}>
                  {t.label}
                  {(t.key === "graph" || t.key === "approvals") && pending.length > 0 && (
                    <span className="ml-1.5 inline-block min-w-[15px] h-[15px] rounded-full bg-red-600
                      text-white text-[9px] leading-[15px] text-center px-0.5 align-middle"
                      data-testid={t.key === "approvals" ? "approvals-tab-badge" : undefined}>
                      {pending.length}
                    </span>
                  )}
                  {t.key === "parking" && parkedCount > 0 && (
                    <span className="ml-1.5 inline-block min-w-[15px] h-[15px] rounded-full bg-slate-500
                      text-white text-[9px] leading-[15px] text-center px-0.5 align-middle"
                      data-testid="parking-tab-badge">
                      {parkedCount}
                    </span>
                  )}
                </TabBtn>
              ))}
            </div>
          </div>
        </div>
      </div>
      <main className="px-4 lg:px-6 py-4">
        {err && <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2 mb-3">{err}</div>}
        <div className="grid grid-cols-1 xl:grid-cols-[1fr_360px] gap-5 items-start">
          <div className="min-w-0">
            {tab === "graph" && (
              <ErrorBoundary title="探索链路">
                <IntentGraph caseId={id} live={live} onAnchor={onAnchor} focusNodeId={focus}
                  archived={archived}
                  suggestedPlaybook={suggestPlaybook(caseInfo?.incident_type)} />
              </ErrorBoundary>
            )}
            {tab === "candidates" && (
              <CandidateFeed caseId={id} sources={sources} onAnchor={onAnchor} />
            )}
            {tab === "tree" && <ContentTree caseId={id} anchor={anchor} />}
            {tab === "search" && (
              <SearchPanel caseId={id} sources={sources} onAnchor={onAnchor} />
            )}
            {tab === "timeline" && (
              <TimelinePanel caseId={id} sources={sources} onAnchor={onAnchor} />
            )}
            {tab === "approvals" && (
              <ApprovalsTab caseId={id} graph={live.graph} onJump={onJumpNode} />
            )}
            {tab === "parking" && (
              <ErrorBoundary title="停车场">
                <ParkingTab caseId={id} graph={live.graph} />
              </ErrorBoundary>
            )}
            {tab === "blackboard" && (
              <ErrorBoundary title="黑板">
                <BlackboardTab caseId={id} graph={live.graph} onAnchor={onAnchor} />
              </ErrorBoundary>
            )}
            {tab === "constraints" && <ConstraintsTab caseId={id} />}
            {tab === "kb" && <CaseKBTab caseId={id} />}
            {tab === "workspace" && (
              // 切片十三:案件工作区入口(与全局工作空间页复用同一组件,
              // 不抄两份;放这里的补充材料本案 AI 会话只读可见)
              <WorkspaceBrowser caseID={id} rootLabel={caseInfo?.name || id} />
            )}
            {tab === "report" && (
              <ErrorBoundary title="报告">
                <ReportTab caseId={id} graph={live.graph} onAnchor={onAnchor}
                  onJumpNode={onJumpNode} />
              </ErrorBoundary>
            )}
          </div>
          {/* 右栏:播报板(0.23.0,交流区上方;可折叠/吸底) + 交流区;
              sticky 容器上移一层,聊天 dock 撑满剩余高度 */}
          <div className="flex flex-col gap-3 sticky top-[7rem] h-[calc(100vh-8.5rem)]">
            <ErrorBoundary title="播报板">
              <LiveFeed caseId={id} graph={live.graph} onAnchor={onAnchor}
                onApprovals={() => setTab("approvals")} />
            </ErrorBoundary>
            <ChatDock caseId={id} sources={sources} onAnchor={onAnchor} />
          </div>
        </div>
      </main>
    </div>
  );
}

// TabBtn:shadcn TabsTrigger 形态(灰底容器内白块激活;语义=案件页 tab 切换)。
function TabBtn({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      role="tab"
      aria-selected={active}
      onClick={onClick}
      className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
        active ? "bg-white text-ink shadow-sm" : "text-mute hover:text-ink"
      }`}
    >
      {children}
    </button>
  );
}
