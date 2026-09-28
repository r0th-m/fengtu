// AppShell 全局骨架(ARTEX 布局复刻,应急语义;交互改造切片四→切片十)。
// 照抄 ARTEX (main)/layout.tsx + _components/sidebar/app-sidebar.tsx +
// _components/sidebar/nav-main.tsx + navigation/sidebar/sidebar-items.ts:
//   1) 左侧可折叠分组导航边栏(品牌头/「功能」「系统」两组分组导航/底部
//      用户卡),折叠态存 localStorage(ARTEX 用 cookie sidebar_state,同语义);
//   2) 分组形态照抄 sidebar-items.ts:组 label 小字大写 + 图标菜单项 +
//      激活态高亮 + 审批记录待批计数徽标(照抄 InterceptPendingBadge 轮询);
//   3) 主区 slim 头(h-12:折叠触发钮 + 版本号,/api/health 免登);
//   4) 案件详情页 full-bleed(照抄 isFullBleed):不套全局头/内边距。
// 技术栈不换:Vite+React+Tailwind 手写复刻 shadcn sidebar 观感,
// 不引 Next.js/shadcn 本体(embed 单二进制铁律);图标=lucide-react(ARTEX 同款)。
// 渗透语义一律不带:流量/工具执行/资产/MCP/Skill/拦截规则 丰图无对应语义,不进导航。
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import { Link, Outlet, useLocation, useNavigate } from "react-router-dom";
import {
  BookOpen,
  Bug,
  ClipboardList,
  FolderOpen,
  KeyRound,
  LayoutDashboard,
  LogOut,
  PanelLeft,
  Radio,
  ScrollText,
  Settings2,
  Target,
  Users,
} from "lucide-react";
import { api } from "../lib/api";
import type { Session } from "../App";

const COLLAPSED_KEY = "fengtu_sidebar_collapsed";

// SidebarContext:full-bleed 页(案件详情)自带 sticky 头里的折叠触发钮
// 与边栏共用一份折叠态(照抄 ARTEX SidebarProvider 的共享语义)。
interface SidebarCtx {
  collapsed: boolean;
  toggle: () => void;
}
const SidebarContext = createContext<SidebarCtx>({ collapsed: false, toggle: () => {} });
export function useSidebar() {
  return useContext(SidebarContext);
}

// isFullBleed 照抄 ARTEX main-content.tsx:案件详情页自带头部/tabs/内边距,
// 全局头和 padding 不再叠加;/cases/new 是表单页,仍走全局头。
export function isFullBleed(pathname: string): boolean {
  return /^\/cases\/(?!new$).+/.test(pathname.replace(/\/+$/, ""));
}

interface NavItem {
  to: string;
  id: string; // data-testid = nav-<id>
  label: string;
  icon: typeof LayoutDashboard;
  // active 判定:exact 或前缀(案件详情/新建向导高亮任务=案件列表所在)。
  match: (pathname: string) => boolean;
  // badge:审批记录待批计数(照抄 ARTEX approvals 的 InterceptPendingBadge)。
  pendingBadge?: boolean;
  // adminOnly:仅管理员可见(M4 用户管理;渲染处按 session.role 过滤,
  // 路由层/后端另有闸)。
  adminOnly?: boolean;
}

// NAV_GROUPS 照抄 ARTEX sidebar-items.ts 的分组形态(功能/系统两组),
// 条目只放丰图真实存在的应急语义。
const NAV_GROUPS: { label: string; items: NavItem[] }[] = [
  {
    label: "功能",
    items: [
      {
        to: "/dashboard", id: "dashboard", label: "仪表盘", icon: LayoutDashboard,
        match: (p) => p === "/dashboard" || p === "/",
      },
      {
        to: "/function/tasks", id: "tasks", label: "任务", icon: Target,
        match: (p) => p === "/function/tasks" || p === "/cases/new" || isFullBleed(p),
      },
      {
        to: "/function/findings", id: "findings", label: "发现", icon: Bug,
        match: (p) => p === "/function/findings",
      },
      {
        to: "/function/llm-records", id: "llm-records", label: "LLM 录制", icon: Radio,
        match: (p) => p === "/function/llm-records",
      },
      {
        to: "/function/workspace", id: "workspace", label: "工作空间", icon: FolderOpen,
        match: (p) => p === "/function/workspace",
      },
    ],
  },
  {
    label: "系统",
    items: [
      {
        to: "/system/approvals", id: "approvals", label: "审批记录", icon: ClipboardList,
        match: (p) => p === "/system/approvals", pendingBadge: true,
      },
      {
        to: "/system/logs", id: "logs", label: "日志", icon: ScrollText,
        match: (p) => p === "/system/logs",
      },
      {
        to: "/system/kb", id: "kb", label: "知识库", icon: BookOpen,
        match: (p) => p === "/system/kb",
      },
      {
        to: "/system/users", id: "users", label: "用户", icon: Users,
        match: (p) => p === "/system/users", adminOnly: true,
      },
      {
        to: "/system/settings", id: "settings", label: "系统配置", icon: Settings2,
        match: (p) => p === "/system/settings",
      },
    ],
  },
];

export function SidebarTrigger({ className = "" }: { className?: string }) {
  const { toggle } = useSidebar();
  return (
    <button
      onClick={toggle}
      aria-label="折叠/展开侧边栏"
      data-testid="sidebar-trigger"
      className={`rounded-md p-1.5 text-mute hover:bg-slate-100 hover:text-ink transition-colors ${className}`}
    >
      <PanelLeft className="w-4 h-4" />
    </button>
  );
}

// PendingApprovalBadge 照抄 ARTEX nav-main.tsx InterceptPendingBadge:
// 轮询待批数,>0 时琥珀色计数徽标;失败静默不装。
// 0.24.0:合并停车场待处置数(同口径「等人拍板」入口;构成在 title 如实标注)。
function PendingApprovalBadge() {
  const [count, setCount] = useState(0);
  const [parked, setParked] = useState(0);
  useEffect(() => {
    let live = true;
    async function poll() {
      try {
        const d = await api.get<{ pending: unknown[]; parked?: number }>("/api/approvals");
        if (live) {
          setCount((d.pending || []).length);
          setParked(d.parked || 0);
        }
      } catch {
        /* 失败静默(照抄 ARTEX ignore) */
      }
    }
    void poll();
    const t = setInterval(poll, 10000);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, []);
  if (count + parked === 0) return null;
  return (
    <span
      data-testid="nav-approvals-badge"
      title={`待审批 ${count} 条 + 停车场待处置 ${parked} 条(停车处置入口:案件页「停车场」tab)`}
      className="ml-auto flex h-[18px] min-w-[18px] items-center justify-center rounded-full
        bg-amber-500 px-1 text-[10px] font-semibold leading-none text-white shadow-sm"
    >
      {count + parked > 99 ? "99+" : count + parked}
    </span>
  );
}

export default function AppShell({ session }: { session: Session }) {
  const loc = useLocation();
  const nav = useNavigate();
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem(COLLAPSED_KEY) === "1",
  );
  const [version, setVersion] = useState("");
  // 个人改密对话框(M4;POST /api/auth/password,任何登录用户改自己密码)
  const [pwOpen, setPwOpen] = useState(false);
  const [pwOld, setPwOld] = useState("");
  const [pwNew, setPwNew] = useState("");
  const [pwConfirm, setPwConfirm] = useState("");
  const [pwErr, setPwErr] = useState("");
  const [pwOK, setPwOK] = useState(false);
  const [pwBusy, setPwBusy] = useState(false);

  const toggle = useCallback(() => {
    setCollapsed((c) => {
      localStorage.setItem(COLLAPSED_KEY, c ? "0" : "1");
      return !c;
    });
  }, []);

  useEffect(() => {
    // 版本号照抄 ARTEX main-content(/api/health,失败静默不装)。
    api
      .get<{ version?: string }>("/api/health")
      .then((h) => setVersion((h.version ?? "").replace(/^v(?=\d)/, "")))
      .catch(() => setVersion(""));
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.post("/api/auth/logout");
    } finally {
      nav("/login", { replace: true });
      window.location.reload(); // 清会话态(沿用原 TopBar 语义)
    }
  }, [nav]);

  // 提交改密:前端先核确认一致(不提交),后端把关旧口令/强度,错误原文。
  const submitPassword = useCallback(async () => {
    setPwErr("");
    setPwOK(false);
    if (pwNew !== pwConfirm) {
      setPwErr("两次输入的新密码不一致");
      return;
    }
    setPwBusy(true);
    try {
      await api.post("/api/auth/password", { old_password: pwOld, new_password: pwNew });
      setPwOK(true);
      setPwOld("");
      setPwNew("");
      setPwConfirm("");
      // 提示「已更新」短暂停留后自动关框
      setTimeout(() => {
        setPwOpen(false);
        setPwOK(false);
      }, 1200);
    } catch (e) {
      setPwErr(e instanceof Error ? e.message : String(e));
    } finally {
      setPwBusy(false);
    }
  }, [pwOld, pwNew, pwConfirm]);

  const fullBleed = isFullBleed(loc.pathname);

  return (
    <SidebarContext.Provider value={{ collapsed, toggle }}>
      <div className="h-full flex">
        {/* 侧边栏:品牌头 + 分组导航 + 用户卡(照抄 app-sidebar 三段式) */}
        <aside
          data-testid="app-sidebar"
          data-collapsed={collapsed ? "1" : "0"}
          className={`shrink-0 h-screen sticky top-0 flex flex-col bg-white border-r
            border-slate-200 transition-[width] duration-200 overflow-hidden
            ${collapsed ? "w-16" : "w-60"}`}
        >
          <div className={`flex items-center gap-2.5 h-14 shrink-0 ${collapsed ? "justify-center" : "px-4"}`}>
            <Link to="/dashboard" className="flex items-center gap-2.5 select-none min-w-0">
              <span className="w-8 h-8 rounded-lg bg-brand text-white flex items-center justify-center
                text-sm font-bold shrink-0">
                丰
              </span>
              {!collapsed && (
                <span className="min-w-0">
                  <span className="block text-sm font-bold text-ink leading-tight">丰图</span>
                  <span className="block text-[10px] text-mute leading-tight truncate">
                    应急响应平台
                  </span>
                </span>
              )}
            </Link>
          </div>
          <nav className="flex-1 overflow-y-auto thin-scroll py-3 px-2 space-y-4">
            {NAV_GROUPS.map((g) => (
              <div key={g.label}>
                {!collapsed && (
                  <div className="px-2 mb-1 text-[10px] font-medium uppercase tracking-wider text-mute">
                    {g.label}
                  </div>
                )}
                <div className="space-y-0.5">
                  {g.items
                    .filter((it) => !it.adminOnly || session.role === "admin")
                    .map((it) => {
                    const active = it.match(loc.pathname);
                    const Icon = it.icon;
                    return (
                      <Link
                        key={it.to}
                        to={it.to}
                        title={collapsed ? it.label : undefined}
                        data-testid={`nav-${it.id}`}
                        className={`flex items-center gap-2.5 rounded-lg text-sm transition-colors
                          ${collapsed ? "justify-center px-0 py-2.5" : "px-2.5 py-2"}
                          ${
                            active
                              ? "bg-brand-light text-brand font-medium"
                              : "text-slate-600 hover:bg-slate-100 hover:text-ink"
                          }`}
                      >
                        <Icon className="w-4 h-4 shrink-0" />
                        {!collapsed && <span className="truncate">{it.label}</span>}
                        {!collapsed && it.pendingBadge && <PendingApprovalBadge />}
                      </Link>
                    );
                  })}
                </div>
              </div>
            ))}
          </nav>
          {/* 底部用户卡(照抄 SidebarFooter/NavUser:用户名 + 登出) */}
          <div className={`border-t border-slate-100 p-2.5 shrink-0 flex items-center gap-2
            ${collapsed ? "flex-col" : ""}`}>
            <span className="w-7 h-7 rounded-full bg-brand/10 text-brand flex items-center
              justify-center text-xs font-semibold shrink-0" data-testid="nav-user">
              {session.username.slice(0, 1).toUpperCase()}
            </span>
            {!collapsed && (
              <span className="flex-1 min-w-0 text-xs text-ink truncate">{session.username}</span>
            )}
            <button
              onClick={() => {
                setPwOpen(true);
                setPwErr("");
                setPwOK(false);
                setPwOld("");
                setPwNew("");
                setPwConfirm("");
              }}
              title="修改密码"
              data-testid="change-password-btn"
              className="rounded-md p-1.5 text-mute hover:bg-slate-100 hover:text-ink transition-colors"
            >
              <KeyRound className="w-4 h-4" />
            </button>
            <button
              onClick={logout}
              title="登出"
              data-testid="logout-btn"
              className="rounded-md p-1.5 text-mute hover:bg-red-50 hover:text-red-600 transition-colors"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </aside>

        {/* 主区:full-bleed 页(案件详情)不套全局头/内边距(照抄 isFullBleed) */}
        <div className="flex-1 min-w-0 flex flex-col">
          {!fullBleed && (
            <header
              data-testid="global-header"
              className="h-12 shrink-0 sticky top-0 z-40 flex items-center gap-2
                border-b border-slate-200 bg-paper/80 backdrop-blur px-4"
            >
              <SidebarTrigger />
              <div className="w-px h-4 bg-slate-200 mx-1" />
              <div className="flex-1" />
              {version && (
                <span className="text-xs text-mute tabular-nums" data-testid="version-badge">
                  版本 · {version}
                </span>
              )}
            </header>
          )}
          <div className={`flex-1 min-h-0 ${fullBleed ? "" : "p-4 md:p-6"}`}>
            <Outlet />
          </div>
        </div>

        {/* 个人改密对话框(M4;照 KBPage 手写范式:旧密码/新密码/确认新密码,
            前端先核确认一致不提交,后端把关旧口令与强度,错误原文) */}
        {pwOpen && (
          <div
            className="fixed inset-0 z-50 bg-black/30 flex items-center justify-center p-4"
            onClick={() => setPwOpen(false)}
          >
            <div
              className="w-full max-w-sm rounded-card bg-white shadow-lg p-5 space-y-3"
              onClick={(e) => e.stopPropagation()}
              data-testid="change-password-dialog"
            >
              <h3 className="text-sm font-semibold">修改密码</h3>
              <input
                autoFocus
                type="password"
                value={pwOld}
                onChange={(e) => setPwOld(e.target.value)}
                placeholder="旧密码"
                autoComplete="current-password"
                className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm
                  focus:outline-none focus:ring-2 focus:ring-brand/40"
                data-testid="change-pw-old"
              />
              <input
                type="password"
                value={pwNew}
                onChange={(e) => setPwNew(e.target.value)}
                placeholder="新密码(≥8 位,含字母+数字)"
                autoComplete="new-password"
                className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm
                  focus:outline-none focus:ring-2 focus:ring-brand/40"
                data-testid="change-pw-new"
              />
              <input
                type="password"
                value={pwConfirm}
                onChange={(e) => setPwConfirm(e.target.value)}
                placeholder="确认新密码"
                autoComplete="new-password"
                className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm
                  focus:outline-none focus:ring-2 focus:ring-brand/40"
                data-testid="change-pw-confirm"
              />
              {pwErr && (
                <div
                  className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2"
                  data-testid="change-pw-error"
                >
                  {pwErr}
                </div>
              )}
              {pwOK && (
                <div
                  className="rounded-lg bg-emerald-50 text-emerald-700 text-xs px-3 py-2"
                  data-testid="change-pw-ok"
                >
                  已更新
                </div>
              )}
              <div className="flex justify-end gap-2">
                <button
                  onClick={() => setPwOpen(false)}
                  className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs text-mute hover:text-ink"
                >
                  取消
                </button>
                <button
                  onClick={() => void submitPassword()}
                  disabled={pwBusy || !pwOld || !pwNew || !pwConfirm}
                  className="rounded-lg bg-brand text-white px-3 py-1.5 text-xs hover:bg-brand-dark
                    disabled:opacity-40"
                  data-testid="change-pw-submit"
                >
                  保存
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </SidebarContext.Provider>
  );
}
