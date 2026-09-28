// 用户管理页(M4;仅 admin,后端把关 403「需要管理员权限」,前端路由闸只是
// 体验层):账号列表(角色/状态/创建时间)+ 新建 + 行操作(重置密码/禁用启用/
// 改角色/删除确认)。错误一律后端原文红条,成功绿条如实。
// 自伤保护在后端(不能删/禁用/降级自己,不能动最后一个 admin),前端如实呈现 400。
// 对话框照 KBPage 手写范式(无共享 Modal 组件)。
import { useCallback, useEffect, useState } from "react";
import { KeyRound, Plus, Trash2, UserCheck, Users, UserX } from "lucide-react";
import { api } from "../lib/api";
import type { UserInfo } from "../lib/types";

// userStatus 状态外显:禁用 > 锁定(locked_until 未到点)> 启用,如实。
function userStatus(u: UserInfo): { label: string; cls: string } {
  if (u.disabled) return { label: "已禁用", cls: "bg-slate-100 text-slate-500" };
  if (u.locked_until && new Date(u.locked_until).getTime() > Date.now()) {
    return {
      label: `锁定中 · 至 ${new Date(u.locked_until).toLocaleString("zh-CN", { hour12: false })}`,
      cls: "bg-amber-50 text-amber-700",
    };
  }
  return { label: "启用", cls: "bg-emerald-50 text-emerald-700" };
}

export default function UsersPage() {
  const [users, setUsers] = useState<UserInfo[]>([]);
  const [err, setErr] = useState("");
  const [note, setNote] = useState("");
  // 新建对话框草稿;role 默认 operator(最小权限)
  const [creating, setCreating] = useState<{
    username: string;
    password: string;
    role: string;
  } | null>(null);
  // 重置密码对话框(目标用户 + 新密码)
  const [resetting, setResetting] = useState<UserInfo | null>(null);
  const [resetPw, setResetPw] = useState("");
  // 删除确认对话框
  const [deleting, setDeleting] = useState<UserInfo | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const d = await api.get<{ users: UserInfo[] }>("/api/users");
      setUsers(d.users || []);
      setErr("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // 新建(POST /api/users;密码强度后端把关,错误原文红条)
  const submitCreate = async () => {
    if (!creating) return;
    setBusy(true);
    setErr("");
    setNote("");
    try {
      await api.post("/api/users", {
        username: creating.username.trim(),
        password: creating.password,
        role: creating.role,
      });
      setCreating(null);
      setNote(`已创建用户「${creating.username.trim()}」`);
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  // 禁用 ↔ 启用(PATCH /api/users/{id} {disabled})
  const toggleDisabled = async (u: UserInfo) => {
    setErr("");
    setNote("");
    try {
      await api.patch(`/api/users/${encodeURIComponent(u.id)}`, { disabled: !u.disabled });
      setNote(u.disabled ? `已启用「${u.username}」` : `已禁用「${u.username}」(会话即刻失效)`);
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  // 改角色(PATCH /api/users/{id} {role};下拉即改)
  const changeRole = async (u: UserInfo, role: string) => {
    setErr("");
    setNote("");
    try {
      await api.patch(`/api/users/${encodeURIComponent(u.id)}`, { role });
      setNote(`「${u.username}」角色已改为 ${role}`);
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
      await load(); // 失败回滚下拉显示
    }
  };

  // 管理员重置密码(POST /api/users/{id}/password;会焚该用户会话)
  const submitReset = async () => {
    if (!resetting) return;
    setBusy(true);
    setErr("");
    setNote("");
    try {
      await api.post(`/api/users/${encodeURIComponent(resetting.id)}/password`, {
        password: resetPw,
      });
      setNote(`已重置「${resetting.username}」的密码(其会话已焚,需重新登录)`);
      setResetting(null);
      setResetPw("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  // 删除(DELETE /api/users/{id};确认对话框,判断权归人)
  const submitDelete = async () => {
    if (!deleting) return;
    setBusy(true);
    setErr("");
    setNote("");
    try {
      await api.del(`/api/users/${encodeURIComponent(deleting.id)}`);
      setNote(`已删除用户「${deleting.username}」`);
      setDeleting(null);
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="max-w-[1200px] mx-auto space-y-4" data-testid="users-page">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight flex items-center gap-2">
            <Users className="w-5 h-5 text-mute" />
            用户管理
          </h1>
          <p className="text-sm text-mute">
            账号与角色(仅管理员可见;操作进审计链,后端把关自伤保护)
          </p>
        </div>
        <button
          onClick={() => setCreating({ username: "", password: "", role: "operator" })}
          className="rounded-lg bg-brand text-white px-3 py-1.5 text-xs hover:bg-brand-dark
            flex items-center gap-1.5 shrink-0"
          data-testid="user-create-btn"
        >
          <Plus className="w-3.5 h-3.5" />
          新建用户
        </button>
      </div>

      <div className="text-[11px] text-mute" data-testid="users-stats">
        共 {users.length} 个账号
      </div>

      {err && (
        <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2" data-testid="users-error">
          {err}
        </div>
      )}
      {note && (
        <div
          className="rounded-lg bg-emerald-50 text-emerald-700 text-xs px-3 py-2"
          data-testid="users-note"
        >
          {note}
        </div>
      )}

      {/* 账号列表:角色徽标/状态/创建时间 + 行操作 */}
      <div className="rounded-card bg-white shadow-card overflow-hidden" data-testid="users-list">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-100 text-left text-[11px] text-mute">
              <th className="font-medium px-4 py-2.5">用户名</th>
              <th className="font-medium px-3 py-2.5">角色</th>
              <th className="font-medium px-3 py-2.5">状态</th>
              <th className="font-medium px-3 py-2.5">创建时间</th>
              <th className="font-medium px-3 py-2.5 text-right">操作</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => {
              const st = userStatus(u);
              return (
                <tr
                  key={u.id}
                  className="border-b border-slate-50 last:border-0 hover:bg-brand-light/30 transition-colors"
                  data-testid={`user-row-${u.username}`}
                >
                  <td className="px-4 py-3 font-medium text-ink">{u.username}</td>
                  <td className="px-3 py-3">
                    <span
                      className={`rounded-full px-2 py-0.5 text-[11px] ring-1 whitespace-nowrap
                        ${u.role === "admin"
                          ? "bg-brand-light text-brand ring-brand/20"
                          : "bg-slate-100 text-slate-600 ring-slate-200"}`}
                      data-testid={`user-role-badge-${u.username}`}
                    >
                      {u.role === "admin" ? "管理员" : "操作员"}
                    </span>
                  </td>
                  <td className="px-3 py-3">
                    <span
                      className={`rounded-full px-2 py-0.5 text-[11px] whitespace-nowrap ${st.cls}`}
                      data-testid={`user-status-${u.username}`}
                    >
                      {st.label}
                    </span>
                  </td>
                  <td className="px-3 py-3 text-xs text-mute whitespace-nowrap">
                    {new Date(u.created_at).toLocaleString("zh-CN", { hour12: false })}
                  </td>
                  <td className="px-3 py-3">
                    <div className="flex items-center justify-end gap-1">
                      {/* 改角色(下拉即改,失败回滚显示) */}
                      <select
                        value={u.role}
                        onChange={(e) => void changeRole(u, e.target.value)}
                        title="改角色(admin=管理员,operator=操作员)"
                        data-testid={`user-role-${u.username}`}
                        className="rounded-lg border border-slate-200 bg-white px-1.5 py-1 text-[11px]
                          text-slate-600 focus:outline-none focus:ring-2 focus:ring-brand/40"
                      >
                        <option value="admin">admin</option>
                        <option value="operator">operator</option>
                      </select>
                      <button
                        title="重置密码(该用户会话即刻焚毁)"
                        data-testid={`user-reset-${u.username}`}
                        className="rounded-md p-1.5 text-mute hover:bg-slate-100 hover:text-ink transition-colors"
                        onClick={() => {
                          setResetting(u);
                          setResetPw("");
                          setErr("");
                        }}
                      >
                        <KeyRound className="w-3.5 h-3.5" />
                      </button>
                      <button
                        title={u.disabled ? "启用该账号" : "禁用该账号(会话即刻失效)"}
                        data-testid={`user-toggle-${u.username}`}
                        className={`rounded-md p-1.5 transition-colors
                          ${u.disabled
                            ? "text-mute hover:bg-emerald-50 hover:text-emerald-600"
                            : "text-mute hover:bg-amber-50 hover:text-amber-600"}`}
                        onClick={() => void toggleDisabled(u)}
                      >
                        {u.disabled ? (
                          <UserCheck className="w-3.5 h-3.5" />
                        ) : (
                          <UserX className="w-3.5 h-3.5" />
                        )}
                      </button>
                      <button
                        title="删除该账号(不可恢复)"
                        data-testid={`user-delete-${u.username}`}
                        className="rounded-md p-1.5 text-mute hover:bg-red-50 hover:text-red-600 transition-colors"
                        onClick={() => {
                          setDeleting(u);
                          setErr("");
                        }}
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
            {users.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-10 text-center text-sm text-mute">
                  暂无账号
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* 新建用户对话框(照 KBPage 手写范式;密码强度后端把关,错误原文红条) */}
      {creating && (
        <div
          className="fixed inset-0 z-50 bg-black/30 flex items-center justify-center p-4"
          onClick={() => setCreating(null)}
        >
          <div
            className="w-full max-w-sm rounded-card bg-white shadow-lg p-5 space-y-3"
            onClick={(e) => e.stopPropagation()}
            data-testid="user-dialog"
          >
            <h3 className="text-sm font-semibold">新建用户</h3>
            <p className="text-[11px] text-mute leading-relaxed">
              密码至少 8 位且含字母+数字(后端把关,不符原文报错);
              角色默认 operator(最小权限)。
            </p>
            <input
              autoFocus
              value={creating.username}
              onChange={(e) => setCreating({ ...creating, username: e.target.value })}
              maxLength={64}
              placeholder="用户名"
              autoComplete="off"
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm
                focus:outline-none focus:ring-2 focus:ring-brand/40"
              data-testid="user-username-input"
            />
            <input
              type="password"
              value={creating.password}
              onChange={(e) => setCreating({ ...creating, password: e.target.value })}
              placeholder="密码(≥8 位,含字母+数字)"
              autoComplete="new-password"
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm
                focus:outline-none focus:ring-2 focus:ring-brand/40"
              data-testid="user-password-input"
            />
            <select
              value={creating.role}
              onChange={(e) => setCreating({ ...creating, role: e.target.value })}
              className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm
                text-slate-600 focus:outline-none focus:ring-2 focus:ring-brand/40"
              data-testid="user-role-select"
            >
              <option value="operator">operator(操作员)</option>
              <option value="admin">admin(管理员)</option>
            </select>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setCreating(null)}
                className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs text-mute hover:text-ink"
              >
                取消
              </button>
              <button
                onClick={() => void submitCreate()}
                disabled={busy || !creating.username.trim() || !creating.password}
                className="rounded-lg bg-brand text-white px-3 py-1.5 text-xs hover:bg-brand-dark
                  disabled:opacity-40"
                data-testid="user-submit"
              >
                创建
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 重置密码对话框(管理员重置;成功即焚该用户全部会话) */}
      {resetting && (
        <div
          className="fixed inset-0 z-50 bg-black/30 flex items-center justify-center p-4"
          onClick={() => setResetting(null)}
        >
          <div
            className="w-full max-w-sm rounded-card bg-white shadow-lg p-5 space-y-3"
            onClick={(e) => e.stopPropagation()}
            data-testid="user-reset-dialog"
          >
            <h3 className="text-sm font-semibold">
              重置「<span className="font-medium">{resetting.username}</span>」的密码
            </h3>
            <p className="text-[11px] text-mute leading-relaxed">
              重置成功后该用户的全部会话即刻焚毁,需用新密码重新登录。
            </p>
            <input
              autoFocus
              type="password"
              value={resetPw}
              onChange={(e) => setResetPw(e.target.value)}
              placeholder="新密码(≥8 位,含字母+数字)"
              autoComplete="new-password"
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm
                focus:outline-none focus:ring-2 focus:ring-brand/40"
              data-testid="user-reset-input"
            />
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setResetting(null)}
                className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs text-mute hover:text-ink"
              >
                取消
              </button>
              <button
                onClick={() => void submitReset()}
                disabled={busy || !resetPw}
                className="rounded-lg bg-brand text-white px-3 py-1.5 text-xs hover:bg-brand-dark
                  disabled:opacity-40"
                data-testid="user-reset-submit"
              >
                重置
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 删除确认对话框(判断权归人;不可恢复) */}
      {deleting && (
        <div
          className="fixed inset-0 z-50 bg-black/30 flex items-center justify-center p-4"
          onClick={() => setDeleting(null)}
        >
          <div
            className="w-full max-w-sm rounded-card bg-white shadow-lg p-5 space-y-3"
            onClick={(e) => e.stopPropagation()}
            data-testid="user-delete-dialog"
          >
            <h3 className="text-sm font-semibold text-red-700">删除用户</h3>
            <p className="text-xs text-slate-600 leading-relaxed">
              将删除「<span className="font-medium">{deleting.username}</span>」。
              删除不可恢复,该用户会话即刻失效,删除动作记录在审计链。
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
                data-testid="user-delete-confirm"
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
