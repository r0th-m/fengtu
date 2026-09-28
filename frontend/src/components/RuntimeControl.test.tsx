// 运行中操控 UI 焊死(交互改造切片三,设计 §3):
// 约束 tab(清单/新增/删除/空态/错误如实) + 意图详情(纠偏框只在在跑时出现、
// open 可终止、终态无任何操控钮)。
import { describe, expect, it, vi, afterEach, beforeAll } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import ConstraintsTab from "./ConstraintsTab";
import IntentDetail from "./IntentDetail";
import { api } from "../lib/api";
import { emptyGraph, type IntentNode } from "../lib/intent";

// jsdom 无 Element.scrollTo(IntentDetail 过程流自动滚底用);桩掉,不断言滚动。
beforeAll(() => {
  (window.HTMLElement.prototype as unknown as { scrollTo: () => void }).scrollTo =
    () => {};
});

afterEach(() => vi.restoreAllMocks());

describe("ConstraintsTab 操作约束", () => {
  it("空态如实 + 新增调 API + 清单呈现", async () => {
    const get = vi.spyOn(api, "get").mockResolvedValue({ constraints: [] });
    const post = vi.spyOn(api, "post").mockResolvedValue({
      constraint: { id: "c-1", case_id: "c1", text: "生产库只读",
        created_by: "admin", created_at: "2026-09-23T01:00:00Z" },
    });
    render(<ConstraintsTab caseId="c1" />);
    await waitFor(() => expect(screen.getByTestId("constraints-empty")).toBeTruthy());
    fireEvent.change(screen.getByTestId("constraint-input"), {
      target: { value: "生产库只读" },
    });
    fireEvent.click(screen.getByTestId("constraint-add"));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/cases/c1/constraints",
        { text: "生产库只读" }));
    expect(get).toHaveBeenCalledWith("/api/cases/c1/constraints");
  });

  it("清单呈现 + 删除(确认后)调 DELETE", async () => {
    vi.spyOn(api, "get").mockResolvedValue({
      constraints: [{ id: "c-1", case_id: "c1", text: "只看 20-21 点时间窗",
        created_by: "admin", created_at: "2026-09-23T01:00:00Z" }],
    });
    const del = vi.spyOn(api, "del").mockResolvedValue({});
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<ConstraintsTab caseId="c1" />);
    await waitFor(() => expect(screen.getByText("只看 20-21 点时间窗")).toBeTruthy());
    fireEvent.click(screen.getByTestId("constraint-del-c-1"));
    await waitFor(() =>
      expect(del).toHaveBeenCalledWith("/api/cases/c1/constraints/c-1"));
  });

  it("拉取失败如实显错(原文)", async () => {
    vi.spyOn(api, "get").mockRejectedValue(new Error("意图链引擎未启用"));
    render(<ConstraintsTab caseId="c1" />);
    await waitFor(() => expect(screen.getByText("意图链引擎未启用")).toBeTruthy());
  });
});

function mkNode(over: Partial<IntentNode>): IntentNode {
  return {
    id: "n1", case_id: "c1", kind: "intent", text: "查外联", status: "running",
    created_by: "human", scope: "case", depth: 1, budget_seconds: 600,
    created_at: new Date().toISOString(), ...over,
  };
}

describe("IntentDetail 运行中操控", () => {
  it("running:纠偏框在,发送调 steer API;停止钮同在", async () => {
    vi.spyOn(api, "get").mockResolvedValue({ events: [] });
    const post = vi.spyOn(api, "post").mockResolvedValue({});
    render(<IntentDetail node={mkNode({})} graph={emptyGraph}
      onClose={() => {}} onSelect={() => {}} onAnchor={() => {}} />);
    expect(screen.getByTestId("steer-box")).toBeTruthy();
    fireEvent.change(screen.getByTestId("steer-input"), {
      target: { value: "先查持久化" },
    });
    fireEvent.click(screen.getByTestId("steer-btn"));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/intents/n1/steer",
        { text: "先查持久化" }));
    expect(screen.getByTestId("stop-btn")).toBeTruthy();
  });

  it("open:可终止(kill 未派发,零 AI 消耗),无纠偏框", async () => {
    vi.spyOn(api, "get").mockResolvedValue({ events: [] });
    const post = vi.spyOn(api, "post").mockResolvedValue({});
    render(<IntentDetail node={mkNode({ status: "open" })} graph={emptyGraph}
      onClose={() => {}} onSelect={() => {}} onAnchor={() => {}} />);
    expect(screen.queryByTestId("steer-box")).toBeNull();
    fireEvent.click(screen.getByTestId("kill-open-btn"));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/intents/n1/stop"));
  });

  it("终态:纠偏/停止/终止一概不出现(不装可操控)", () => {
    vi.spyOn(api, "get").mockResolvedValue({ events: [] });
    render(<IntentDetail node={mkNode({ status: "supported" })} graph={emptyGraph}
      onClose={() => {}} onSelect={() => {}} onAnchor={() => {}} />);
    expect(screen.queryByTestId("steer-box")).toBeNull();
    expect(screen.queryByTestId("stop-btn")).toBeNull();
    expect(screen.queryByTestId("kill-open-btn")).toBeNull();
  });
});
