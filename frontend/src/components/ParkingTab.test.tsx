// 停车场 tab(0.24.0-convergence)焊死:预算消耗条/待处置列表(原因/归属
// 建议/收官评估建议)/展开·丢弃人批钮/已处置留痕区/空态如实。全部 mock api,
// 零 AI 调用。
import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import ParkingTab from "./ParkingTab";
import { api } from "../lib/api";
import { emptyGraph } from "../lib/intent";
import type { ParkingEntry } from "../lib/parking";

afterEach(() => vi.restoreAllMocks());

const BUDGET = {
  budget: {
    limits: { fanout: 5, chapter: 30, case: 200 },
    case_intents: 12,
    chapters: [{ goal_id: "g1", title: "章一", intents: 9, limit: 30 }],
    parked: 2,
  },
};

function entry(id: string, extra?: Partial<ParkingEntry>): ParkingEntry {
  return {
    id, case_id: "c1", node_id: "n-" + id, text: "可疑线索 " + id,
    reason: "budget_fanout", status: "parked", created_by: "ai",
    created_at: "2026-09-26T00:00:00Z", ...extra,
  };
}

function mockGet(items: ParkingEntry[]) {
  return vi.spyOn(api, "get").mockImplementation((p: string) => {
    if (p === "/api/cases/c1/parking") return Promise.resolve({ items });
    if (p === "/api/cases/c1/budget") return Promise.resolve(BUDGET);
    return Promise.reject(new Error("unexpected GET " + p));
  });
}

describe("ParkingTab 停车场", () => {
  it("空态如实 + 预算条呈现三闸与消耗", async () => {
    mockGet([]);
    render(<ParkingTab caseId="c1" graph={emptyGraph} />);
    await waitFor(() => expect(screen.getByTestId("parking-empty")).toBeTruthy());
    expect(screen.getByTestId("parking-empty").textContent).toContain("停车场为空");
    const bar = screen.getByTestId("parking-budget");
    expect(bar.textContent).toContain("12");
    expect(bar.textContent).toContain("200");
    expect(bar.textContent).toContain("章「章一」9/30");
  });

  it("待处置:原因/归属建议/收官评估建议渲染;展开走人批端点", async () => {
    mockGet([
      entry("pk1", { suggest_label: "章一", verdict: "deploy", verdict_reason: "值得追" }),
      entry("pk2", { reason: "park_lead", suggest_label: "新开章:外泄追查" }),
    ]);
    const post = vi.spyOn(api, "post").mockResolvedValue({});
    render(<ParkingTab caseId="c1" graph={emptyGraph} />);
    await waitFor(() => expect(screen.getByTestId("parking-item-pk1")).toBeTruthy());
    expect(screen.getByTestId("parking-item-pk1").textContent).toContain("扇出超闸");
    expect(screen.getByTestId("parking-item-pk1").textContent).toContain("章一");
    expect(screen.getByTestId("parking-verdict-pk1").textContent).toContain("建议展开");
    expect(screen.getByTestId("parking-verdict-pk1").textContent).toContain("值得追");
    expect(screen.getByTestId("parking-item-pk2").textContent).toContain("AI 章外线索申请");
    expect(screen.getByTestId("parking-item-pk2").textContent).toContain("新开章:外泄追查");
    fireEvent.click(screen.getByTestId("parking-deploy-pk1"));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/parking/pk1/deploy"));
  });

  it("丢弃走人批端点;已处置进留痕区且无操作钮", async () => {
    mockGet([
      entry("pk1"),
      entry("pk2", { status: "dismissed", decided_by: "admin",
        decided_at: "2026-09-26T01:00:00Z" }),
    ]);
    const post = vi.spyOn(api, "post").mockResolvedValue({});
    render(<ParkingTab caseId="c1" graph={emptyGraph} />);
    await waitFor(() => expect(screen.getByTestId("parking-dismiss-pk1")).toBeTruthy());
    fireEvent.click(screen.getByTestId("parking-dismiss-pk1"));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/parking/pk1/dismiss"));
    const decided = screen.getByTestId("parking-decided-pk2");
    expect(decided.textContent).toContain("已丢弃");
    expect(decided.textContent).toContain("admin");
    expect(screen.queryByTestId("parking-deploy-pk2")).toBeNull();
  });

  it("端点失败如实报错,不装", async () => {
    vi.spyOn(api, "get").mockRejectedValue(new Error("意图链引擎未启用"));
    render(<ParkingTab caseId="c1" graph={emptyGraph} />);
    await waitFor(() =>
      expect(screen.getByText(/意图链引擎未启用/)).toBeTruthy());
  });

  it("批量处置(0.29.0):全选 + 批量展开二次确认走批量端点 + 如实汇报", async () => {
    mockGet([entry("pk1"), entry("pk2")]);
    const post = vi.spyOn(api, "post").mockResolvedValue({
      results: [{ id: "pk1", ok: true }, { id: "pk2", ok: true }],
      total: 2, done: 2, skipped: 0,
    });
    render(<ParkingTab caseId="c1" graph={emptyGraph} />);
    await waitFor(() => expect(screen.getByTestId("parking-item-pk1")).toBeTruthy());
    // 全选待处置
    fireEvent.click(screen.getByTestId("parking-select-all"));
    expect(screen.getByTestId("parking-batch-count").textContent).toContain("已选 2 条");
    // 批量展开 → 二次确认 → 确认
    fireEvent.click(screen.getByTestId("parking-batch-deploy"));
    const dlg = screen.getByTestId("parking-batch-confirm-dialog");
    expect(dlg.textContent).toContain("2");
    expect(post).not.toHaveBeenCalled(); // 未确认前不发请求
    fireEvent.click(screen.getByTestId("parking-batch-confirm-go"));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/parking/batch",
        { ids: ["pk1", "pk2"], action: "deploy" }));
    await waitFor(() =>
      expect(screen.getByTestId("parking-batch-result").textContent)
        .toContain("2 成功"));
  });

  it("批量丢弃:部分跳过如实汇报;勾选在重取后保留仍在的 id", async () => {
    const get = mockGet([entry("pk1"), entry("pk2")]);
    const post = vi.spyOn(api, "post").mockResolvedValue({
      results: [
        { id: "pk1", ok: true },
        { id: "pk2", ok: false, error: "停车场条目已被处置(当前 deployed),不重复丢弃" },
      ],
      total: 2, done: 1, skipped: 1,
    });
    const utils = render(<ParkingTab caseId="c1" graph={emptyGraph} />);
    await waitFor(() => expect(screen.getByTestId("parking-check-pk1")).toBeTruthy());
    fireEvent.click(screen.getByTestId("parking-check-pk1"));
    fireEvent.click(screen.getByTestId("parking-check-pk2"));
    fireEvent.click(screen.getByTestId("parking-batch-dismiss"));
    fireEvent.click(screen.getByTestId("parking-batch-confirm-go"));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/parking/batch",
        { ids: ["pk1", "pk2"], action: "dismiss" }));
    await waitFor(() => {
      const msg = screen.getByTestId("parking-batch-result").textContent;
      expect(msg).toContain("1 成功");
      expect(msg).toContain("1 跳过");
    });    // 勾选剔除:模拟重取后 pk1 消失,pk2 仍在 → 只保留 pk2
    // (批量成功后已清空勾选,这里重选再触发重取验证剔除语义)
    fireEvent.click(screen.getByTestId("parking-check-pk2"));
    get.mockImplementation((p: string) => {
      if (p === "/api/cases/c1/parking") return Promise.resolve({ items: [entry("pk2")] });
      if (p === "/api/cases/c1/budget") return Promise.resolve(BUDGET);
      return Promise.reject(new Error("unexpected GET " + p));
    });
    // 触发重取:graph.seq 变更(rerender 同实例)
    utils.rerender(<ParkingTab caseId="c1" graph={{ ...emptyGraph, seq: 9 }} />);
    await waitFor(() => {
      expect(screen.queryByTestId("parking-check-pk1")).toBeNull();
      expect(screen.getByTestId("parking-check-pk2")).toBeTruthy();
    });
    expect(screen.getByTestId("parking-batch-count").textContent).toContain("已选 1 条");
  });
});
