// 新建任务向导 KB 勾选区契约测试(0.20.0-case-kb;0.27.1-kb-simplify;
// 0.30.0-report-ux 预勾选收口后端):可选池=全部条目(启停退役);
// 预勾选走 GET /api/kb/precheck(映射表单一数据源在后端 kb.PrecheckTags,
// 前端不再自持表;换类型重套);人可增删、全选/全不选;提交随案落库
// (kb_entries)。全部 mock api,零 AI 调用。
import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { api } from "../lib/api";
import NewCasePage from "./NewCasePage";
import type { KBEntry } from "../lib/types";

afterEach(() => vi.restoreAllMocks());

const A1: KBEntry = {
  id: "a1", title: "执行证据通道", content: "一",
  applies_to: ["execution"], source: "builtin",
  created_at: "2026-09-25T10:00:00Z", updated_at: "2026-09-25T10:00:00Z",
};
const A2: KBEntry = {
  id: "a2", title: "时间线锚定", content: "二",
  applies_to: ["timeline"], source: "user",
  created_at: "2026-09-25T11:00:00Z", updated_at: "2026-09-25T11:00:00Z",
};
const A3: KBEntry = {
  id: "a3", title: "持久化面", content: "三",
  applies_to: ["persistence"], source: "builtin",
  created_at: "2026-09-25T12:00:00Z", updated_at: "2026-09-25T12:00:00Z",
};
const A4: KBEntry = {
  id: "a4", title: "侵入点通道", content: "四",
  applies_to: ["entry-point"], source: "builtin",
  created_at: "2026-09-25T13:00:00Z", updated_at: "2026-09-25T13:00:00Z",
};

// 预勾选 mock(模拟后端 kb.PrecheckTags 同口径;前端不测映射本身——
// 映射归后端单测焊死,这里只测「端点返回什么就勾什么」)。
const PRECHECK: Record<string, string[]> = {
  intrusion: ["a1", "a2", "a3", "a4"],
  webshell: ["a1", "a3"],
  ransomware: ["a1", "a2", "a3", "a4"],
  "data-leak": ["a2", "a3"],
  other: ["a1", "a2", "a3", "a4"],
};

function mockKB(entries: KBEntry[]) {
  return vi.spyOn(api, "get").mockImplementation((p: string) => {
    if (p === "/api/kb") return Promise.resolve({ entries, note: "n" });
    if (p.startsWith("/api/kb/precheck?incident_type=")) {
      const typ = p.slice("/api/kb/precheck?incident_type=".length);
      return Promise.resolve({ incident_type: typ, selected: PRECHECK[typ] ?? [] });
    }
    return Promise.reject(new Error("unexpected GET " + p));
  });
}

function mount() {
  return render(
    <MemoryRouter>
      <NewCasePage />
    </MemoryRouter>,
  );
}

function checked(id: string): boolean {
  return (screen.getByTestId(`kb-check-${id}`) as HTMLInputElement).checked;
}

describe("NewCasePage KB 勾选区", () => {
  it("可选池=全部条目(0.27.1 启停退役);默认入侵排查=precheck 端点勾选集", async () => {
    mockKB([A1, A2, A3, A4]);
    mount();
    await waitFor(() => expect(screen.getByTestId("kb-opt-a1")).toBeTruthy());
    expect(screen.getByTestId("kb-opt-a4")).toBeTruthy(); // 全部条目都进池
    // 默认类型 intrusion(端点返回全勾)
    await waitFor(() => expect(checked("a4")).toBe(true));
    expect(checked("a1")).toBe(true);
    expect(checked("a2")).toBe(true);
    expect(checked("a3")).toBe(true);
    expect(screen.getByTestId("kb-hint").textContent).toContain("已勾 4 / 4 条");
  });

  it("换类型重套预勾选(端点口径 WebShell=a1/a3);人可增删", async () => {
    mockKB([A1, A2, A3, A4]);
    mount();
    await waitFor(() => expect(screen.getByTestId("kb-opt-a1")).toBeTruthy());
    await waitFor(() => expect(checked("a4")).toBe(true));
    fireEvent.click(screen.getByText("WebShell 排查"));
    await waitFor(() => expect(checked("a2")).toBe(false));
    expect(checked("a1")).toBe(true);  // 端点返回 a1/a3
    expect(checked("a3")).toBe(true);
    expect(checked("a4")).toBe(false);
    // 人手动取消 a1
    fireEvent.click(screen.getByTestId("kb-check-a1"));
    expect(checked("a1")).toBe(false);
    expect(screen.getByTestId("kb-hint").textContent).toContain("已勾 1 / 4 条");
  });

  it("全选/全不选:作用于全部条目池;换类型仍重套端点预勾选", async () => {
    mockKB([A1, A2, A3, A4]);
    mount();
    await waitFor(() => expect(screen.getByTestId("kb-opt-a1")).toBeTruthy());
    // 换到 WebShell(端点预勾 a1/a3)→ 全选应勾满 4 条
    fireEvent.click(screen.getByText("WebShell 排查"));
    await waitFor(() =>
      expect(screen.getByTestId("kb-hint").textContent).toContain("已勾 2 / 4 条"));
    fireEvent.click(screen.getByTestId("kb-select-all"));
    expect(checked("a1")).toBe(true);
    expect(checked("a2")).toBe(true);
    expect(checked("a3")).toBe(true);
    expect(checked("a4")).toBe(true);
    expect(screen.getByTestId("kb-hint").textContent).toContain("已勾 4 / 4 条");
    // 全不选 → 清空(本案不注入,合法)
    fireEvent.click(screen.getByTestId("kb-select-none"));
    expect(checked("a1")).toBe(false);
    expect(checked("a3")).toBe(false);
    expect(screen.getByTestId("kb-hint").textContent).toContain("已勾 0 / 4 条");
    // 全不选后换类型仍重套预勾选(端点口径)
    fireEvent.click(screen.getByText("勒索响应"));
    await waitFor(() => expect(checked("a2")).toBe(true));
    expect(checked("a1")).toBe(true);
    expect(checked("a3")).toBe(true);
    expect(checked("a4")).toBe(true);
  });

  it("预勾选端点失败:如实清空+提示,不兜底全勾(判断权归人)", async () => {
    vi.spyOn(api, "get").mockImplementation((p: string) => {
      if (p === "/api/kb") return Promise.resolve({ entries: [A1], note: "n" });
      if (p.startsWith("/api/kb/precheck")) {
        return Promise.reject(new Error("应急类型非法"));
      }
      return Promise.reject(new Error("unexpected GET " + p));
    });
    mount();
    await waitFor(() => expect(screen.getByTestId("kb-opt-a1")).toBeTruthy());
    await waitFor(() =>
      expect(screen.getByText(/预勾选装载失败/)).toBeTruthy());
    expect(checked("a1")).toBe(false); // 清空不兜底
  });

  it("提交:kb_entries 随案落库(当前勾选集)", async () => {
    mockKB([A1, A2, A3]);
    const post = vi.spyOn(api, "post").mockResolvedValue({
      case: { id: "c-new", name: "测试案" }, goals_seeded: 0, kb_selected: 2,
    });
    mount();
    await waitFor(() => expect(screen.getByTestId("kb-opt-a1")).toBeTruthy());
    fireEvent.click(screen.getByText("WebShell 排查"));
    await waitFor(() => expect(checked("a3")).toBe(true));
    fireEvent.click(screen.getByTestId("kb-check-a1")); // 取消 a1,剩 a3
    fireEvent.change(
      screen.getByPlaceholderText(/勒索响应-财务服务器/),
      { target: { value: "测试案" } },
    );
    fireEvent.click(screen.getByTestId("wizard-submit"));
    await waitFor(() => expect(post).toHaveBeenCalled());
    const [path, body] = post.mock.calls[0] as [string, Record<string, unknown>];
    expect(path).toBe("/api/cases");
    expect(body.kb_entries).toEqual(["a3"]);
    expect(body.incident_type).toBe("webshell");
  });
});
