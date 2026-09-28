// 任务列表生命周期操作契约测试(0.18.0-case-lifecycle):
// 归档筛选(默认隐藏/「已归档」看回+徽标)、改名对话框(Enter 保存)、
// 删除双确认(输错名不放行/输对放行并刷新)。全部 mock api,零 AI 调用。
import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { api } from "../lib/api";
import WorkbenchPage from "./WorkbenchPage";

afterEach(() => vi.restoreAllMocks());

function mount() {
  return render(
    <MemoryRouter>
      <WorkbenchPage />
    </MemoryRouter>,
  );
}

const C1 = { id: "c1", name: "勒索案A", created_at: "2026-09-01T00:00:00Z", sources: 2, candidates: 1, pending_candidates: 1, incident_type: "ransomware", archived_at: null };
const C2 = { id: "c2", name: "归档案B", created_at: "2026-09-02T00:00:00Z", sources: 1, candidates: 0, pending_candidates: 0, incident_type: "intrusion", archived_at: "2026-09-20T00:00:00Z" };

// mockList 案件清单 + ActivityFeed 两个辅查询(tasks/audit)。
function mockList(cases: unknown[]) {
  vi.spyOn(api, "get").mockImplementation((p: string) => {
    if (p === "/api/cases") return Promise.resolve({ cases }) as never;
    if (p === "/api/tasks") return Promise.resolve({ tasks: [] }) as never;
    if (p.startsWith("/api/audit/chain")) return Promise.resolve({ entries: [] }) as never;
    return Promise.reject(new Error("unexpected GET " + p));
  });
}

describe("WorkbenchPage 生命周期操作", () => {
  it("归档案默认隐藏,「已归档」筛选看回 + 徽标", async () => {
    mockList([C1, C2]);
    mount();
    await waitFor(() => expect(screen.getByTestId("case-row-c1")).toBeTruthy());
    // 默认:归档案不出现
    expect(screen.queryByTestId("case-row-c2")).toBeNull();
    // 筛选「已归档」:只看归档案,带徽标
    fireEvent.change(screen.getByTestId("case-status-filter"), { target: { value: "archived" } });
    await waitFor(() => expect(screen.getByTestId("case-row-c2")).toBeTruthy());
    expect(screen.queryByTestId("case-row-c1")).toBeNull();
    expect(screen.getByTestId("archived-badge-c2").textContent).toBe("已归档");
  });

  it("行操作改名:对话框 Enter 保存,PATCH 发出并刷新", async () => {
    mockList([C1]);
    const patchSpy = vi.spyOn(api, "patch").mockResolvedValue({ case: { ...C1, name: "勒索案A-改" } } as never);
    mount();
    await waitFor(() => expect(screen.getByTestId("case-row-c1")).toBeTruthy());
    fireEvent.click(screen.getByTestId("rename-c1"));
    const input = screen.getByTestId("rename-input") as HTMLInputElement;
    expect(input.value).toBe("勒索案A");
    fireEvent.change(input, { target: { value: "勒索案A-改" } });
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() =>
      expect(patchSpy).toHaveBeenCalledWith("/api/cases/c1", { name: "勒索案A-改" }));
    // 对话框关闭
    await waitFor(() => expect(screen.queryByTestId("rename-dialog")).toBeNull());
  });

  it("改名 Esc 取消不发请求", async () => {
    mockList([C1]);
    const patchSpy = vi.spyOn(api, "patch").mockResolvedValue({} as never);
    mount();
    await waitFor(() => expect(screen.getByTestId("case-row-c1")).toBeTruthy());
    fireEvent.click(screen.getByTestId("rename-c1"));
    fireEvent.keyDown(screen.getByTestId("rename-input"), { key: "Escape" });
    expect(screen.queryByTestId("rename-dialog")).toBeNull();
    expect(patchSpy).not.toHaveBeenCalled();
  });

  it("归档/解归档按钮按状态打对端点", async () => {
    mockList([C1, C2]);
    const postSpy = vi.spyOn(api, "post").mockResolvedValue({} as never);
    mount();
    await waitFor(() => expect(screen.getByTestId("case-row-c1")).toBeTruthy());
    fireEvent.click(screen.getByTestId("archive-c1"));
    await waitFor(() => expect(postSpy).toHaveBeenCalledWith("/api/cases/c1/archive"));
    // 归档案行的按钮是解归档
    fireEvent.change(screen.getByTestId("case-status-filter"), { target: { value: "archived" } });
    await waitFor(() => expect(screen.getByTestId("case-row-c2")).toBeTruthy());
    fireEvent.click(screen.getByTestId("archive-c2"));
    await waitFor(() => expect(postSpy).toHaveBeenCalledWith("/api/cases/c2/unarchive"));
  });

  it("删除双确认:输错名不放行,输对名 DELETE 带名放行", async () => {
    mockList([C1]);
    const delSpy = vi.spyOn(api, "del").mockResolvedValue({ deleted: true } as never);
    mount();
    await waitFor(() => expect(screen.getByTestId("case-row-c1")).toBeTruthy());
    fireEvent.click(screen.getByTestId("delete-c1"));
    const input = screen.getByTestId("delete-confirm-input");
    const submit = screen.getByTestId("delete-submit") as HTMLButtonElement;
    // 输错名:按钮禁用,回车也不发
    fireEvent.change(input, { target: { value: "勒索案" } });
    expect(submit.disabled).toBe(true);
    fireEvent.keyDown(input, { key: "Enter" });
    expect(delSpy).not.toHaveBeenCalled();
    // 输对名:放行
    fireEvent.change(input, { target: { value: "勒索案A" } });
    expect((screen.getByTestId("delete-submit") as HTMLButtonElement).disabled).toBe(false);
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() =>
      expect(delSpy).toHaveBeenCalledWith("/api/cases/c1", { name: "勒索案A" }));
    await waitFor(() => expect(screen.queryByTestId("delete-dialog")).toBeNull());
  });
});
