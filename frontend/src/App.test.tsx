// App 路由闸契约测试(M4):/system/users 仅 admin 可达——
// admin 直访渲染用户页;operator 直访被 Navigate 回 /dashboard(前端闸,
// 后端仍把关 403)。全部 mock api,零真实调用。
import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { api } from "./lib/api";
import App from "./App";

afterEach(() => vi.restoreAllMocks());

// mockBoot 会话 + 目标页依赖查询的白名单(意外调用即炸,防串味)。
function mockBoot(role: string) {
  vi.spyOn(api, "get").mockImplementation((p: string) => {
    if (p === "/api/auth/me") {
      return Promise.resolve({ user: { id: "u1", username: "who", role } }) as never;
    }
    if (p === "/api/users") return Promise.resolve({ users: [] }) as never;
    if (p === "/api/stats/overview") {
      return Promise.resolve({
        stats: { cases: 0, sources: 0, candidates: 0, pending_candidates: 0,
          pending_approvals: 0, llm_records: 0,
          activity: [{ day: "2026-09-25", count: 1 }] },
        case_status: { pending: 0, reviewed: 0, ingested: 0, empty: 0 },
        activity_note: "",
      }) as never;
    }
    if (p === "/api/health") return Promise.resolve({}) as never;
    if (p === "/api/approvals") return Promise.resolve({ pending: [], history: [] }) as never;
    return Promise.reject(new Error("unexpected GET " + p));
  });
}

describe("App 路由闸(M4 用户管理)", () => {
  it("admin 直访 /system/users 渲染用户页,导航含「用户」入口", async () => {
    mockBoot("admin");
    render(
      <MemoryRouter initialEntries={["/system/users"]}>
        <App />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByTestId("users-page")).toBeTruthy());
    expect(screen.getByTestId("nav-users")).toBeTruthy();
  });

  it("operator 直访 /system/users 被重定向回 /dashboard(不见用户页/入口)", async () => {
    mockBoot("operator");
    render(
      <MemoryRouter initialEntries={["/system/users"]}>
        <App />
      </MemoryRouter>,
    );
    // 落到仪表盘(activity-bars 是 DashboardPage 的标志块)
    await waitFor(() => expect(screen.getByTestId("activity-bars")).toBeTruthy());
    expect(screen.queryByTestId("users-page")).toBeNull();
    expect(screen.queryByTestId("nav-users")).toBeNull();
  });
});
