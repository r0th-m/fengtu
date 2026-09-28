// 路由壳:/login、/dashboard(仪表盘)、/function/{tasks,findings,llm-records,
// workspace}、/system/{approvals,logs,settings}、/cases/new(新建任务向导)、
// /cases/:id(案件页)。会话看 cookie(HttpOnly);前端只问 /api/auth/me,
// 401 一律跳登录页。受保护页全部包进 AppShell(ARTEX 侧边栏骨架);
// /login 独立无壳;/ 重定向 /dashboard(ARTEX 同款入口)。
import { useCallback, useEffect, useState } from "react";
import { Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { api, setUnauthorizedHandler } from "./lib/api";
import AppShell from "./components/AppShell";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import WorkbenchPage from "./pages/WorkbenchPage";
import FindingsPage from "./pages/FindingsPage";
import LLMRecordsPage from "./pages/LLMRecordsPage";
import WorkspacePage from "./pages/WorkspacePage";
import ApprovalsPage from "./pages/ApprovalsPage";
import LogsPage from "./pages/LogsPage";
import KBPage from "./pages/KBPage";
import SettingsPage from "./pages/SettingsPage";
import NewCasePage from "./pages/NewCasePage";
import CasePage from "./pages/CasePage";
import UsersPage from "./pages/UsersPage";

export interface Session {
  username: string;
  role: string; // admin|operator(M4:/api/auth/me 与登录响应携带;用户管理入口/路由闸按此过滤)
}

export default function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [booting, setBooting] = useState(true);
  const nav = useNavigate();
  const loc = useLocation();

  useEffect(() => {
    setUnauthorizedHandler(() => setSession(null));
    api
      .get<{ user: { username: string; role: string } }>("/api/auth/me")
      .then((d) => setSession({ username: d.user.username, role: d.user.role }))
      .catch(() => setSession(null))
      .finally(() => setBooting(false));
  }, []);

  useEffect(() => {
    if (!booting && !session && loc.pathname !== "/login") {
      nav("/login", { replace: true });
    }
  }, [booting, session, loc.pathname, nav]);

  const onLogin = useCallback((s: Session) => setSession(s), []);

  if (booting) {
    return (
      <div className="h-full flex items-center justify-center text-mute text-sm">
        会话校验中…
      </div>
    );
  }

  return (
    <Routes>
      <Route path="/login" element={<LoginPage onLogin={onLogin} />} />
      {session ? (
        <Route element={<AppShell session={session} />}>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/function/tasks" element={<WorkbenchPage />} />
          <Route path="/function/findings" element={<FindingsPage />} />
          <Route path="/function/llm-records" element={<LLMRecordsPage />} />
          <Route path="/function/workspace" element={<WorkspacePage />} />
          <Route path="/system/approvals" element={<ApprovalsPage />} />
          <Route path="/system/logs" element={<LogsPage />} />
          <Route path="/system/kb" element={<KBPage />} />
          <Route path="/system/settings" element={<SettingsPage />} />
          {/* 用户管理仅 admin(M4):路由层焊一道闸,operator 直访回仪表盘;
              后端仍把关 403(前端闸只是体验,不是权限边界) */}
          <Route
            path="/system/users"
            element={
              session.role === "admin" ? <UsersPage /> : <Navigate to="/dashboard" replace />
            }
          />
          <Route path="/cases/new" element={<NewCasePage />} />
          <Route path="/cases/:id" element={<CasePage />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>
      ) : (
        <Route path="*" element={<Navigate to="/login" replace />} />
      )}
    </Routes>
  );
}
