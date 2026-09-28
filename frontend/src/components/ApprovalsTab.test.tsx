// 审批 tab 焊死:待批阻塞呈现(文案/红点计数/已等待)/批准调用 API/
// 审批历史轮询(审计链 intent.* 投影)/空态如实。
import { describe, expect, it, vi, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import ApprovalsTab from "./ApprovalsTab";
import { api } from "../lib/api";
import { applyChange, emptyGraph, type IntentNode } from "../lib/intent";

function pendingNode(id: string, text: string): IntentNode {
  return {
    id, case_id: "c1", kind: "intent", text, status: "awaiting_approval",
    created_by: "ai", scope: "all", depth: 2, budget_seconds: 600,
    created_at: new Date(Date.now() - 5 * 60000).toISOString(),
  };
}

afterEach(() => vi.restoreAllMocks());

describe("ApprovalsTab 审批", () => {
  it("待批卡:阻塞文案+红点计数+批量标+批准按钮;点批准调 API", async () => {
    const g = applyChange(emptyGraph, "node_added", pendingNode("n1", "批量核查邻机波及"));
    vi.spyOn(api, "get").mockResolvedValue({ entries: [] });
    const post = vi.spyOn(api, "post").mockResolvedValue({});
    render(<ApprovalsTab caseId="c1" graph={g} onJump={() => {}} />);
    expect(screen.getByTestId("approvals-tab-count").textContent).toBe("1");
    expect(screen.getByText(/执行阻塞中——批准前该意图不会被派发/)).toBeTruthy();
    expect(screen.getByText("批量执行(全案件)")).toBeTruthy();
    expect(screen.getByText(/已阻塞等待 5 分钟/)).toBeTruthy();
    fireEvent.click(screen.getByTestId("approval-approve-n1"));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/intents/n1/approve", { approve: true }));
  });

  it("空队列:如实「无待批意图」", () => {
    vi.spyOn(api, "get").mockResolvedValue({ entries: [] });
    render(<ApprovalsTab caseId="c1" graph={emptyGraph} onJump={() => {}} />);
    expect(screen.getByText("无待批意图")).toBeTruthy();
    expect(screen.queryByTestId("approvals-tab-count")).toBeNull();
  });

  it("审批历史:审计链 intent.* 投影,批准绿/拒红,非审批动作不进", async () => {
    vi.spyOn(api, "get").mockResolvedValue({
      entries: [
        { Seq: 9, CaseID: "c1", TS: "2026-09-23T01:00:00Z", Actor: "boss",
          Action: "intent.approve", Scope: "n1",
          DetailJSON: '{"text":"批量核查"}' },
        { Seq: 8, CaseID: "c1", TS: "2026-09-23T00:59:00Z", Actor: "boss",
          Action: "intent.reject", Scope: "n2", DetailJSON: '{"text":"全网扫描"}' },
        { Seq: 7, CaseID: "c1", TS: "2026-09-23T00:58:00Z", Actor: "sys",
          Action: "scan.run", Scope: "c1", DetailJSON: "{}" }, // 非审批,不进
      ],
    });
    render(<ApprovalsTab caseId="c1" graph={emptyGraph} onJump={() => {}} />);
    await waitFor(() => expect(screen.getByText("批量核查")).toBeTruthy());
    expect(screen.getByText("批准")).toBeTruthy();
    expect(screen.getByText("拒绝")).toBeTruthy();
    expect(screen.queryByText("scan.run")).toBeNull();
  });
});
