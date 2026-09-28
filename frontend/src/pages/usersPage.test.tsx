// 用户管理页契约测试(M4):列表渲染(角色徽标/状态)、新建提交体、
// 禁用/改角色/重置密码/删除行操作、非 admin 403 后端原文红条。
// 全部 mock api(mockApi 白名单范式),零真实调用。
import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { api, ApiError } from "../lib/api";
import UsersPage from "./UsersPage";

afterEach(() => vi.restoreAllMocks());

function mount() {
  return render(
    <MemoryRouter>
      <UsersPage />
    </MemoryRouter>,
  );
}

// mockList 用户清单白名单(get);操作动词由各用例单独 spy。
function mockList(users: unknown[]) {
  vi.spyOn(api, "get").mockImplementation((p: string) => {
    if (p === "/api/users") return Promise.resolve({ users }) as never;
    return Promise.reject(new Error("unexpected GET " + p));
  });
}

const U1 = { id: "u1", username: "admin", role: "admin", disabled: false, failed_attempts: 0, locked_until: null, created_at: "2026-09-01T00:00:00Z" };
const U2 = { id: "u2", username: "op1", role: "operator", disabled: false, failed_attempts: 0, locked_until: null, created_at: "2026-09-02T00:00:00Z" };
const U3 = { id: "u3", username: "badguy", role: "operator", disabled: true, failed_attempts: 5, locked_until: "2999-01-01T00:00:00Z", created_at: "2026-09-03T00:00:00Z" };

describe("UsersPage(用户管理,M4)", () => {
  it("列表渲染:角色徽标区分 admin/operator,锁定行显示到点,禁用行如实", async () => {
    mockList([U1, U2, U3]);
    mount();
    await waitFor(() => expect(screen.getByTestId("user-row-admin")).toBeTruthy());
    expect(screen.getByTestId("user-row-op1")).toBeTruthy();
    expect(screen.getByTestId("user-row-badguy")).toBeTruthy();
    expect(screen.getByTestId("user-role-badge-admin").textContent).toBe("管理员");
    expect(screen.getByTestId("user-role-badge-op1").textContent).toBe("操作员");
    expect(screen.getByTestId("user-status-admin").textContent).toBe("启用");
    // 禁用优先于锁定展示
    expect(screen.getByTestId("user-status-badguy").textContent).toBe("已禁用");
  });

  it("锁定中(未禁用)显示到点", async () => {
    mockList([{ ...U3, id: "u4", username: "locked1", disabled: false }]);
    mount();
    await waitFor(() => expect(screen.getByTestId("user-row-locked1")).toBeTruthy());
    expect(screen.getByTestId("user-status-locked1").textContent).toContain("锁定中 · 至");
  });

  it("新建用户:提交体 {username,password,role},成功后刷新", async () => {
    mockList([U1]);
    const post = vi.spyOn(api, "post").mockResolvedValue({ user: { id: "u9" } } as never);
    mount();
    await waitFor(() => expect(screen.getByTestId("user-create-btn")).toBeTruthy());
    fireEvent.click(screen.getByTestId("user-create-btn"));
    expect(screen.getByTestId("user-dialog")).toBeTruthy();
    fireEvent.change(screen.getByTestId("user-username-input"), { target: { value: "newguy" } });
    fireEvent.change(screen.getByTestId("user-password-input"), { target: { value: "pass1234" } });
    fireEvent.change(screen.getByTestId("user-role-select"), { target: { value: "admin" } });
    fireEvent.click(screen.getByTestId("user-submit"));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/users",
        { username: "newguy", password: "pass1234", role: "admin" }));
    await waitFor(() => expect(screen.queryByTestId("user-dialog")).toBeNull());
  });

  it("新建失败:密码强度等后端文案原样红条,对话框不关", async () => {
    mockList([U1]);
    vi.spyOn(api, "post").mockRejectedValue(new Error("密码至少 8 位且含字母+数字"));
    mount();
    await waitFor(() => expect(screen.getByTestId("user-create-btn")).toBeTruthy());
    fireEvent.click(screen.getByTestId("user-create-btn"));
    fireEvent.change(screen.getByTestId("user-username-input"), { target: { value: "newguy" } });
    fireEvent.change(screen.getByTestId("user-password-input"), { target: { value: "weak" } });
    fireEvent.click(screen.getByTestId("user-submit"));
    await waitFor(() =>
      expect(screen.getByTestId("users-error").textContent).toBe("密码至少 8 位且含字母+数字"));
    expect(screen.getByTestId("user-dialog")).toBeTruthy();
  });

  it("禁用 ↔ 启用:PATCH {disabled:true/false} 打对端点", async () => {
    mockList([U1, U2, U3]);
    const patch = vi.spyOn(api, "patch").mockResolvedValue({ user: U2 } as never);
    mount();
    await waitFor(() => expect(screen.getByTestId("user-row-op1")).toBeTruthy());
    fireEvent.click(screen.getByTestId("user-toggle-op1"));
    await waitFor(() =>
      expect(patch).toHaveBeenCalledWith("/api/users/u2", { disabled: true }));
    fireEvent.click(screen.getByTestId("user-toggle-badguy"));
    await waitFor(() =>
      expect(patch).toHaveBeenCalledWith("/api/users/u3", { disabled: false }));
  });

  it("改角色:下拉即 PATCH {role}", async () => {
    mockList([U1, U2]);
    const patch = vi.spyOn(api, "patch").mockResolvedValue({ user: U2 } as never);
    mount();
    await waitFor(() => expect(screen.getByTestId("user-row-op1")).toBeTruthy());
    fireEvent.change(screen.getByTestId("user-role-op1"), { target: { value: "admin" } });
    await waitFor(() =>
      expect(patch).toHaveBeenCalledWith("/api/users/u2", { role: "admin" }));
  });

  it("重置密码:对话框输新密码,POST /api/users/{id}/password", async () => {
    mockList([U1, U2]);
    const post = vi.spyOn(api, "post").mockResolvedValue({} as never);
    mount();
    await waitFor(() => expect(screen.getByTestId("user-row-op1")).toBeTruthy());
    fireEvent.click(screen.getByTestId("user-reset-op1"));
    expect(screen.getByTestId("user-reset-dialog")).toBeTruthy();
    fireEvent.change(screen.getByTestId("user-reset-input"), { target: { value: "newpass99" } });
    fireEvent.click(screen.getByTestId("user-reset-submit"));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/users/u2/password", { password: "newpass99" }));
    await waitFor(() => expect(screen.queryByTestId("user-reset-dialog")).toBeNull());
    expect(screen.getByTestId("users-note").textContent).toContain("已重置「op1」");
  });

  it("删除:确认对话框放行 DELETE,取消不发请求", async () => {
    mockList([U1, U2]);
    const del = vi.spyOn(api, "del").mockResolvedValue({} as never);
    mount();
    await waitFor(() => expect(screen.getByTestId("user-row-op1")).toBeTruthy());
    fireEvent.click(screen.getByTestId("user-delete-op1"));
    expect(screen.getByTestId("user-delete-dialog")).toBeTruthy();
    // 取消:不发请求
    fireEvent.click(screen.getByText("取消"));
    expect(screen.queryByTestId("user-delete-dialog")).toBeNull();
    expect(del).not.toHaveBeenCalled();
    // 确认:DELETE 打对端点
    fireEvent.click(screen.getByTestId("user-delete-op1"));
    fireEvent.click(screen.getByTestId("user-delete-confirm"));
    await waitFor(() => expect(del).toHaveBeenCalledWith("/api/users/u2"));
  });

  it("自伤/最后 admin 保护:后端 400 文案原样红条", async () => {
    mockList([U1]);
    vi.spyOn(api, "del").mockRejectedValue(new ApiError(400, "不能删除最后一个管理员"));
    mount();
    await waitFor(() => expect(screen.getByTestId("user-row-admin")).toBeTruthy());
    fireEvent.click(screen.getByTestId("user-delete-admin"));
    fireEvent.click(screen.getByTestId("user-delete-confirm"));
    await waitFor(() =>
      expect(screen.getByTestId("users-error").textContent).toBe("不能删除最后一个管理员"));
  });

  it("非 admin 访问:403「需要管理员权限」原样红条", async () => {
    vi.spyOn(api, "get").mockRejectedValue(new ApiError(403, "需要管理员权限"));
    mount();
    await waitFor(() =>
      expect(screen.getByTestId("users-error").textContent).toBe("需要管理员权限"));
  });
});
