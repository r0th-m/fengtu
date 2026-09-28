// 候选发现批量裁决测试(0.29.0-batch-ops):勾选列/本页全选/批量钮二次确认/
// 结果如实汇报(N 成功/M 跳过)/勾选保留(消失的 id 自然剔除)。全部 mock api。
import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import CandidateFeed from "./CandidateFeed";
import { api } from "../lib/api";
import type { Hit } from "../lib/types";

afterEach(() => vi.restoreAllMocks());

function hit(id: string, status = "pending"): Hit {
  return {
    id, case_id: "c1", source_id: "s1", line_no: 1, rule_id: "r1",
    severity: "medium", matched_field: "ua", matched_value: "sqlmap",
    snippet: "", ts_utc: null, status, round_no: 1,
    evidence_grade: "suspect", created_at: "2026-09-26T00:00:00Z",
  };
}

function mockGet(hits: Hit[]) {
  return vi.spyOn(api, "get").mockImplementation((p: string) => {
    if (p.startsWith("/api/cases/c1/hits")) return Promise.resolve({ hits });
    if (p === "/api/rules") return Promise.resolve({ rules: [] });
    if (p === "/api/operators") return Promise.resolve({ operators: [] });
    return Promise.reject(new Error("unexpected GET " + p));
  });
}

function renderFeed() {
  return render(
    <CandidateFeed caseId="c1" sources={[{ id: "s1", path: "/a.log" } as never]}
      onAnchor={() => {}} />,
  );
}

describe("CandidateFeed 批量裁决", () => {
  it("勾选列 + 全选本页 + 批量接受走批量端点(二次确认)", async () => {
    mockGet([hit("h1"), hit("h2"), hit("h3", "accepted")]);
    const post = vi.spyOn(api, "post").mockResolvedValue({
      results: [{ id: "h1", ok: true }, { id: "h2", ok: true }],
      total: 2, done: 2, skipped: 0,
    });
    renderFeed();
    await waitFor(() => expect(screen.getByTestId("hit-card-h1")).toBeTruthy());
    // 已裁决的 h3 无勾选框
    expect(screen.queryByTestId("batch-check-h3")).toBeNull();
    // 全选本页 pending
    fireEvent.click(screen.getByTestId("batch-select-all"));
    expect(screen.getByTestId("batch-count").textContent).toContain("已选 2 条");
    // 批量接受 → 二次确认 → 确认
    fireEvent.click(screen.getByTestId("batch-accept"));
    const dlg = screen.getByTestId("batch-confirm-dialog");
    expect(dlg.textContent).toContain("2");
    expect(post).not.toHaveBeenCalled(); // 未确认前不发请求
    fireEvent.click(screen.getByTestId("batch-confirm-go"));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/hits/batch-verdict",
        { ids: ["h1", "h2"], status: "accepted" }));
    await waitFor(() =>
      expect(screen.getByTestId("batch-result").textContent).toContain("2 成功"));
  });

  it("逐条勾选 + 批量排除;部分跳过如实汇报", async () => {
    mockGet([hit("h1"), hit("h2")]);
    const post = vi.spyOn(api, "post").mockResolvedValue({
      results: [
        { id: "h1", ok: true },
        { id: "h2", ok: false, error: "该候选已被他人裁决(现状态 accepted)" },
      ],
      total: 2, done: 1, skipped: 1,
    });
    renderFeed();
    await waitFor(() => expect(screen.getByTestId("batch-check-h1")).toBeTruthy());
    fireEvent.click(screen.getByTestId("batch-check-h1"));
    fireEvent.click(screen.getByTestId("batch-check-h2"));
    fireEvent.click(screen.getByTestId("batch-reject"));
    fireEvent.click(screen.getByTestId("batch-confirm-go"));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/hits/batch-verdict",
        { ids: ["h1", "h2"], status: "rejected" }));
    await waitFor(() => {
      const msg = screen.getByTestId("batch-result").textContent;
      expect(msg).toContain("1 成功");
      expect(msg).toContain("1 跳过");
    });
  });

  it("勾选保留:重取后消失的 id 自然剔除,仍在的保留", async () => {
    const get = mockGet([hit("h1"), hit("h2")]);
    vi.spyOn(api, "post").mockResolvedValue({});
    renderFeed();
    await waitFor(() => expect(screen.getByTestId("batch-check-h1")).toBeTruthy());
    fireEvent.click(screen.getByTestId("batch-check-h1"));
    fireEvent.click(screen.getByTestId("batch-check-h2"));
    expect(screen.getByTestId("batch-count").textContent).toContain("已选 2 条");
    // 模拟刷新:h1 已被裁决流出 pending 列表,h2 仍在
    get.mockImplementation((p: string) => {
      if (p.startsWith("/api/cases/c1/hits")) return Promise.resolve({ hits: [hit("h2")] });
      if (p === "/api/rules") return Promise.resolve({ rules: [] });
      if (p === "/api/operators") return Promise.resolve({ operators: [] });
      return Promise.reject(new Error("unexpected GET " + p));
    });
    // 触发重取(切筛选再切回)
    fireEvent.click(screen.getByText("全部"));
    await waitFor(() => expect(screen.queryByTestId("batch-check-h1")).toBeNull());
    fireEvent.click(screen.getByText("待裁决"));
    await waitFor(() => expect(screen.getByTestId("batch-check-h2")).toBeTruthy());
    expect(screen.getByTestId("batch-count").textContent).toContain("已选 1 条");
  });

  it("取消二次确认不发请求", async () => {
    mockGet([hit("h1")]);
    const post = vi.spyOn(api, "post").mockResolvedValue({});
    renderFeed();
    await waitFor(() => expect(screen.getByTestId("batch-check-h1")).toBeTruthy());
    fireEvent.click(screen.getByTestId("batch-check-h1"));
    fireEvent.click(screen.getByTestId("batch-accept"));
    fireEvent.click(screen.getByText("取消"));
    expect(post).not.toHaveBeenCalled();
    expect(screen.queryByTestId("batch-confirm-dialog")).toBeNull();
  });
});
