// 案件 KB 勾选管理 tab 契约测试(0.20.0-case-kb;0.27.1-kb-simplify):勾选
// 视图渲染(勾选即生效徽标,不再有全局禁用标注——启停退役)、存量案件零勾选
// 提示、勾选交互 + 保存 PUT、差集回执、全选/全不选。全部 mock api,零 AI 调用。
import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { api } from "../lib/api";
import CaseKBTab from "./CaseKBTab";
import type { KBEntry } from "../lib/types";

afterEach(() => vi.restoreAllMocks());

const E1: KBEntry = {
  id: "e1", title: "执行证据通道", content: "正文一",
  applies_to: ["execution"], source: "builtin",
  created_at: "2026-09-25T10:00:00Z", updated_at: "2026-09-25T10:00:00Z",
};
const E2: KBEntry = {
  id: "e2", title: "时间线锚定", content: "正文二",
  applies_to: ["timeline"], source: "user",
  created_at: "2026-09-25T11:00:00Z", updated_at: "2026-09-25T11:00:00Z",
};
const E3: KBEntry = {
  id: "e3", title: "持久化面", content: "正文三",
  applies_to: ["persistence"], source: "builtin",
  created_at: "2026-09-25T12:00:00Z", updated_at: "2026-09-25T12:00:00Z",
};

function mockGet(entries: KBEntry[], selected: string[]) {
  return vi.spyOn(api, "get").mockImplementation((p: string) => {
    if (p === "/api/cases/c-1/kb") {
      return Promise.resolve({ entries, selected, note: "n" });
    }
    return Promise.reject(new Error("unexpected GET " + p));
  });
}

function mount() {
  return render(
    <MemoryRouter>
      <CaseKBTab caseId="c-1" />
    </MemoryRouter>,
  );
}

describe("CaseKBTab", () => {
  it("勾选视图:勾选即生效徽标/统计口径(0.27.1 无全局禁用标注)", async () => {
    mockGet([E1, E2, E3], ["e1", "e3"]);
    mount();
    await waitFor(() => expect(screen.getByTestId("case-kb-row-e1")).toBeTruthy());
    // 勾选即生效(不再交集全局启用):e1/e3 都是本案生效
    expect(screen.getByTestId("case-kb-row-e1").textContent).toContain("本案生效");
    expect(screen.getByTestId("case-kb-row-e3").textContent).toContain("本案生效");
    expect(screen.getByTestId("case-kb-row-e2").textContent).not.toContain("本案生效");
    // 全局禁用相关标注不再出现(启停退役)
    expect(screen.queryByText(/全局禁用/)).toBeNull();
    expect(screen.getByTestId("case-kb-stats").textContent).toContain("本案生效 2 条");
    expect(screen.getByTestId("case-kb-stats").textContent).toContain("条目池 3 条");
    // 有勾选 → 不显示零勾选提示
    expect(screen.queryByTestId("case-kb-empty-hint")).toBeNull();
    // 未改动 → 保存钮禁用
    expect((screen.getByTestId("case-kb-save") as HTMLButtonElement).disabled).toBe(true);
  });

  it("存量案件零勾选:如实提示不注入,引导去勾选", async () => {
    mockGet([E1, E2], []);
    mount();
    await waitFor(() => expect(screen.getByTestId("case-kb-empty-hint")).toBeTruthy());
    expect(screen.getByTestId("case-kb-empty-hint").textContent).toContain("不注入启发式参考");
  });

  it("勾选交互 + 保存:PUT 整体覆写,差集回执呈现", async () => {
    mockGet([E1, E2], ["e1"]);
    const put = vi.spyOn(api, "put").mockResolvedValue({
      selected: ["e2"], added: ["e2"], removed: ["e1"], note: "n",
    });
    mount();
    await waitFor(() => expect(screen.getByTestId("case-kb-row-e1")).toBeTruthy());
    // 取消 e1、勾上 e2
    fireEvent.click(screen.getByTestId("case-kb-check-e1"));
    fireEvent.click(screen.getByTestId("case-kb-check-e2"));
    // 有改动 → 保存可点
    expect((screen.getByTestId("case-kb-save") as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(screen.getByTestId("case-kb-save"));
    await waitFor(() =>
      expect(put).toHaveBeenCalledWith("/api/cases/c-1/kb", { selected: ["e2"] }));
    await waitFor(() => expect(screen.getByTestId("case-kb-ok")).toBeTruthy());
    expect(screen.getByTestId("case-kb-ok").textContent).toContain("kb.case_update");
    expect(screen.getByTestId("case-kb-ok").textContent).toContain("在跑的不追回");
  });

  it("全选/全不选:作用于全部条目池,随后可保存", async () => {
    mockGet([E1, E2, E3], ["e1"]);
    const put = vi.spyOn(api, "put").mockResolvedValue({
      selected: [], added: [], removed: ["e1"], note: "n",
    });
    mount();
    await waitFor(() => expect(screen.getByTestId("case-kb-row-e1")).toBeTruthy());
    // 全选 → 三条全勾
    fireEvent.click(screen.getByTestId("case-kb-select-all"));
    expect((screen.getByTestId("case-kb-check-e1") as HTMLInputElement).checked).toBe(true);
    expect((screen.getByTestId("case-kb-check-e2") as HTMLInputElement).checked).toBe(true);
    expect((screen.getByTestId("case-kb-check-e3") as HTMLInputElement).checked).toBe(true);
    expect(screen.getByTestId("case-kb-stats").textContent).toContain("本案生效 3 条");
    // 全不选 → 清空,保存 PUT 空集
    fireEvent.click(screen.getByTestId("case-kb-select-none"));
    expect((screen.getByTestId("case-kb-check-e1") as HTMLInputElement).checked).toBe(false);
    expect((screen.getByTestId("case-kb-save") as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(screen.getByTestId("case-kb-save"));
    await waitFor(() =>
      expect(put).toHaveBeenCalledWith("/api/cases/c-1/kb", { selected: [] }));
  });

  it("后端报错原样呈现", async () => {
    mockGet([E1], []);
    vi.spyOn(api, "put").mockRejectedValue(new Error("未知知识库条目: ghost"));
    mount();
    await waitFor(() => expect(screen.getByTestId("case-kb-row-e1")).toBeTruthy());
    fireEvent.click(screen.getByTestId("case-kb-check-e1"));
    fireEvent.click(screen.getByTestId("case-kb-save"));
    await waitFor(() =>
      expect(screen.getByTestId("case-kb-error").textContent).toContain("未知知识库条目"));
  });
});
