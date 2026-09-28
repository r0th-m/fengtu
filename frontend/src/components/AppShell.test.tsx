// AppShell 骨架焊死(切片十,ARTEX 侧边栏全量复刻):
// 「功能/系统」两组分组导航(照抄 sidebar-items.ts 形态:仪表盘/任务/发现/
// LLM 录制/工作空间 + 审批记录/日志/系统配置)、折叠持久化、审批待批徽标、
// full-bleed(案件详情不套全局头)、版本徽标、登出。
import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import AppShell, { isFullBleed } from "./AppShell";
import { api } from "../lib/api";

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

function renderShell(initialPath: string, role = "admin") {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <Routes>
        <Route element={<AppShell session={{ username: "admin", role }} />}>
          <Route path="/" element={<div>根</div>} />
          <Route path="/dashboard" element={<div>仪表盘页</div>} />
          <Route path="/function/tasks" element={<div>任务页</div>} />
          <Route path="/cases/new" element={<div>新建页</div>} />
          <Route path="/cases/:id" element={<div>案件页</div>} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}

describe("AppShell(ARTEX 侧边栏骨架)", () => {
  it("两组分组导航全部条目 + 用户卡 + 版本徽标(/api/health)", async () => {
    vi.spyOn(api, "get").mockImplementation((p: string) => {
      if (p === "/api/health") return Promise.resolve({ ok: "true", version: "0.14.0-artex-pages" });
      if (p === "/api/approvals") return Promise.resolve({ pending: [], history: [] });
      return Promise.reject(new Error("unexpected " + p));
    });
    renderShell("/dashboard");
    // 功能组
    expect(screen.getByTestId("nav-dashboard").textContent).toContain("仪表盘");
    expect(screen.getByTestId("nav-tasks").textContent).toContain("任务");
    expect(screen.getByTestId("nav-findings").textContent).toContain("发现");
    expect(screen.getByTestId("nav-llm-records").textContent).toContain("LLM 录制");
    expect(screen.getByTestId("nav-workspace").textContent).toContain("工作空间");
    // 系统组
    expect(screen.getByTestId("nav-approvals").textContent).toContain("审批记录");
    expect(screen.getByTestId("nav-logs").textContent).toContain("日志");
    expect(screen.getByTestId("nav-settings").textContent).toContain("系统配置");
    // 组 label
    expect(screen.getByText("功能")).toBeTruthy();
    expect(screen.getByText("系统")).toBeTruthy();
    expect(screen.getByTestId("nav-user").textContent).toBe("A"); // 首字母头像
    await waitFor(() =>
      expect(screen.getByTestId("version-badge").textContent).toContain("0.14.0-artex-pages"));
    expect(api.get).toHaveBeenCalledWith("/api/health");
  });

  it("审批待批徽标:>0 显示计数,0 不显示(照抄 InterceptPendingBadge)", async () => {
    vi.spyOn(api, "get").mockImplementation((p: string) => {
      if (p === "/api/approvals") {
        return Promise.resolve({ pending: [{ id: "n1" }, { id: "n2" }], history: [] });
      }
      return Promise.resolve({});
    });
    renderShell("/dashboard");
    await waitFor(() =>
      expect(screen.getByTestId("nav-approvals-badge").textContent).toBe("2"));
  });

  it("徽标合并停车场待处置计数(0.24.0;构成在 title 如实标注)", async () => {
    vi.spyOn(api, "get").mockImplementation((p: string) => {
      if (p === "/api/approvals") {
        return Promise.resolve({ pending: [{ id: "n1" }], history: [], parked: 3 });
      }
      return Promise.resolve({});
    });
    renderShell("/dashboard");
    await waitFor(() =>
      expect(screen.getByTestId("nav-approvals-badge").textContent).toBe("4"));
    expect(screen.getByTestId("nav-approvals-badge").getAttribute("title"))
      .toContain("停车场待处置 3");
  });

  it("版本拉取失败静默(不装版本号)", async () => {
    vi.spyOn(api, "get").mockRejectedValue(new Error("boom"));
    renderShell("/dashboard");
    await waitFor(() => expect(api.get).toHaveBeenCalled());
    expect(screen.queryByTestId("version-badge")).toBeNull();
  });

  it("折叠切换:图标态隐藏文案 + localStorage 持久化 + 再点恢复", () => {
    vi.spyOn(api, "get").mockResolvedValue({});
    renderShell("/dashboard");
    const aside = screen.getByTestId("app-sidebar");
    expect(aside.getAttribute("data-collapsed")).toBe("0");
    fireEvent.click(screen.getByTestId("sidebar-trigger"));
    expect(aside.getAttribute("data-collapsed")).toBe("1");
    expect(localStorage.getItem("fengtu_sidebar_collapsed")).toBe("1");
    expect(screen.queryByText("系统配置")).toBeNull(); // 折叠态只剩图标
    fireEvent.click(screen.getByTestId("sidebar-trigger"));
    expect(aside.getAttribute("data-collapsed")).toBe("0");
    expect(localStorage.getItem("fengtu_sidebar_collapsed")).toBe("0");
    expect(screen.getByText("系统配置")).toBeTruthy();
  });

  it("导航激活:仪表盘/案件详情高亮任务(案件列表所在)", () => {
    vi.spyOn(api, "get").mockResolvedValue({});
    const { unmount } = renderShell("/dashboard");
    expect(screen.getByTestId("nav-dashboard").className).toContain("bg-brand-light");
    expect(screen.getByTestId("nav-tasks").className).not.toContain("bg-brand-light");
    unmount();
    renderShell("/cases/abc");
    expect(screen.getByTestId("nav-tasks").className).toContain("bg-brand-light");
    expect(screen.getByTestId("nav-dashboard").className).not.toContain("bg-brand-light");
  });

  it("登出调 /api/auth/logout", async () => {
    vi.spyOn(api, "get").mockResolvedValue({});
    const post = vi.spyOn(api, "post").mockResolvedValue({});
    renderShell("/dashboard");
    fireEvent.click(screen.getByTestId("logout-btn"));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/auth/logout"));
  });

  it("用户入口仅 admin 可见(M4):admin 见 nav-users,operator 不见", () => {
    vi.spyOn(api, "get").mockResolvedValue({});
    const { unmount } = renderShell("/dashboard", "admin");
    expect(screen.getByTestId("nav-users").textContent).toContain("用户");
    unmount();
    renderShell("/dashboard", "operator");
    expect(screen.queryByTestId("nav-users")).toBeNull();
    // 其余系统组条目 operator 仍可见(过滤只针对 adminOnly)
    expect(screen.getByTestId("nav-settings")).toBeTruthy();
  });

  it("个人改密:确认不一致不提交;一致提交 {old_password,new_password} 并提示已更新", async () => {
    vi.spyOn(api, "get").mockResolvedValue({});
    const post = vi.spyOn(api, "post").mockResolvedValue({});
    renderShell("/dashboard");
    fireEvent.click(screen.getByTestId("change-password-btn"));
    expect(screen.getByTestId("change-password-dialog")).toBeTruthy();
    fireEvent.change(screen.getByTestId("change-pw-old"), { target: { value: "oldpass1" } });
    fireEvent.change(screen.getByTestId("change-pw-new"), { target: { value: "newpass1" } });
    // 确认不一致:不提交,红条如实
    fireEvent.change(screen.getByTestId("change-pw-confirm"), { target: { value: "newpass2" } });
    fireEvent.click(screen.getByTestId("change-pw-submit"));
    expect(screen.getByTestId("change-pw-error").textContent).toContain("不一致");
    expect(post).not.toHaveBeenCalledWith("/api/auth/password", expect.anything());
    // 一致:提交体正确,成功提示「已更新」
    fireEvent.change(screen.getByTestId("change-pw-confirm"), { target: { value: "newpass1" } });
    fireEvent.click(screen.getByTestId("change-pw-submit"));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/auth/password",
        { old_password: "oldpass1", new_password: "newpass1" }));
    await waitFor(() => expect(screen.getByTestId("change-pw-ok").textContent).toBe("已更新"));
  });

  it("个人改密:旧口令错误后端原文红条", async () => {
    vi.spyOn(api, "get").mockResolvedValue({});
    vi.spyOn(api, "post").mockRejectedValue(new Error("旧密码错误"));
    renderShell("/dashboard");
    fireEvent.click(screen.getByTestId("change-password-btn"));
    fireEvent.change(screen.getByTestId("change-pw-old"), { target: { value: "wrongold1" } });
    fireEvent.change(screen.getByTestId("change-pw-new"), { target: { value: "newpass1" } });
    fireEvent.change(screen.getByTestId("change-pw-confirm"), { target: { value: "newpass1" } });
    fireEvent.click(screen.getByTestId("change-pw-submit"));
    await waitFor(() =>
      expect(screen.getByTestId("change-pw-error").textContent).toBe("旧密码错误"));
  });
});

describe("isFullBleed(照抄 ARTEX main-content)", () => {
  it("案件详情 full-bleed,平台页/新建不 full-bleed", () => {
    expect(isFullBleed("/cases/abc")).toBe(true);
    expect(isFullBleed("/cases/abc/")).toBe(true);
    expect(isFullBleed("/cases/new")).toBe(false);
    expect(isFullBleed("/dashboard")).toBe(false);
    expect(isFullBleed("/function/tasks")).toBe(false);
    expect(isFullBleed("/system/logs")).toBe(false);
  });

  it("full-bleed 页不渲染全局头(页面自带 sticky 任务头)", () => {
    vi.spyOn(api, "get").mockResolvedValue({});
    const { unmount } = renderShell("/cases/abc");
    expect(screen.queryByTestId("global-header")).toBeNull();
    expect(screen.getByText("案件页")).toBeTruthy();
    unmount();
    renderShell("/dashboard");
    expect(screen.getByTestId("global-header")).toBeTruthy();
  });
});
