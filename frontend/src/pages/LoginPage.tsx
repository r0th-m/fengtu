// 登录页:居中卡片,品牌「丰图」+「按图索骥·应急取证分析」。
// 失败如实带后端文案(凭据不符);含首启引导(仅系统未初始化时可用,后端把关)。
import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import type { Session } from "../App";

export default function LoginPage({ onLogin }: { onLogin: (s: Session) => void }) {
  const nav = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [setupMode, setSetupMode] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      if (setupMode) {
        await api.post("/api/auth/setup", { username, password });
      }
      const d = await api.post<{ user: { username: string; role: string } }>(
        "/api/auth/login",
        { username, password },
      );
      onLogin({ username: d.user.username, role: d.user.role });
      nav("/", { replace: true });
    } catch (e2) {
      setErr(e2 instanceof Error ? e2.message : String(e2));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="h-full flex items-center justify-center bg-paper px-4">
      <div className="w-full max-w-sm rounded-card bg-white shadow-card p-8">
        <div className="text-center mb-8">
          <div className="text-3xl font-bold text-brand tracking-wide">丰图</div>
          <div className="mt-2 text-sm text-mute">按图索骥 · 应急取证分析</div>
        </div>
        <form onSubmit={submit} className="space-y-4">
          <div>
            <label className="block text-xs text-mute mb-1">用户名</label>
            <input
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm
                focus:outline-none focus:ring-2 focus:ring-brand/40 focus:border-brand"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoFocus
              autoComplete="username"
            />
          </div>
          <div>
            <label className="block text-xs text-mute mb-1">密码</label>
            <input
              type="password"
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm
                focus:outline-none focus:ring-2 focus:ring-brand/40 focus:border-brand"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete={setupMode ? "new-password" : "current-password"}
            />
          </div>
          {err && (
            <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2 leading-relaxed">
              {err}
            </div>
          )}
          <button
            type="submit"
            disabled={busy || !username || !password}
            className="w-full rounded-lg bg-brand text-white text-sm font-medium py-2.5
              hover:bg-brand-dark transition-colors disabled:opacity-50"
          >
            {busy ? "提交中…" : setupMode ? "初始化并登录" : "登录"}
          </button>
        </form>
        <div className="mt-4 text-center">
          <button
            className="text-xs text-mute hover:text-brand transition-colors"
            onClick={() => setSetupMode(!setupMode)}
          >
            {setupMode ? "返回登录" : "首次部署?首启引导"}
          </button>
        </div>
        <div className="mt-6 text-center text-[11px] text-slate-400 leading-relaxed">
          机器产出均为疑似候选,判断权归人
        </div>
      </div>
    </div>
  );
}
