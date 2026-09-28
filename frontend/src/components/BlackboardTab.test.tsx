// 黑板 tab(0.28.0-blackboard)焊死:四段渲染(事实锚点跳内容树/存疑发现/
// 在查已查标状态/停车场原因标)、截断如实、空态如实、端点失败如实报错。
// 全部 mock api,零 AI 调用。
import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import BlackboardTab from "./BlackboardTab";
import { api } from "../lib/api";
import { emptyGraph } from "../lib/intent";
import type { Blackboard } from "../lib/blackboard";

afterEach(() => vi.restoreAllMocks());

function bb(extra?: Partial<Blackboard>): Blackboard {
  return {
    case_id: "c1",
    facts: [], facts_total: 0,
    doubts: [], doubts_total: 0,
    intents: [], intents_total: 0,
    parking: [], parking_total: 0,
    ...extra,
  };
}

function mockGet(board: Blackboard) {
  return vi.spyOn(api, "get").mockImplementation((p: string) => {
    if (p === "/api/cases/c1/blackboard") return Promise.resolve({ blackboard: board });
    return Promise.reject(new Error("unexpected GET " + p));
  });
}

describe("BlackboardTab 案件黑板", () => {
  it("四段渲染:事实带锚点/存疑摘要/意图标状态/停车场原因标", async () => {
    mockGet(bb({
      facts: [{ node_id: "f1", text: "侵入点是钓鱼邮件附件",
        anchors: [{ source_id: "src-9", line_no: 42 }] }],
      facts_total: 1,
      doubts: [{ node_id: "i2", intent: "查横向移动", summary: "日志缺口" }],
      doubts_total: 1,
      intents: [
        { node_id: "i3", text: "查持久化", status: "open" },
        { node_id: "i4", text: "查外联", status: "supported" },
      ],
      intents_total: 2,
      parking: [{ id: "p1", node_id: "n1", text: "章外线索",
        reason: "dup_similar", created_at: "2026-09-26T00:00:00Z" }],
      parking_total: 1,
    }));
    const onAnchor = vi.fn();
    render(<BlackboardTab caseId="c1" graph={emptyGraph} onAnchor={onAnchor} />);
    await waitFor(() => expect(screen.getByTestId("bb-fact-f1")).toBeTruthy());
    expect(screen.getByTestId("bb-fact-f1").textContent).toContain("侵入点是钓鱼邮件附件");
    expect(screen.getByTestId("bb-doubt-i2").textContent).toContain("日志缺口");
    expect(screen.getByTestId("bb-intent-i3").textContent).toContain("待执行");
    expect(screen.getByTestId("bb-intent-i4").textContent).toContain("证据支持");
    expect(screen.getByTestId("bb-parking-p1").textContent).toContain("疑似重复");
    // 锚点点击 → 跳内容树定位行
    fireEvent.click(screen.getByTestId("bb-anchor-f1-0"));
    expect(onAnchor).toHaveBeenCalledWith("src-9", 42);
  });

  it("空态如实 + 上限截断如实标", async () => {
    mockGet(bb({ facts_total: 35 })); // 全集 35,注入 0(被上限截)
    render(<BlackboardTab caseId="c1" graph={emptyGraph} onAnchor={() => {}} />);
    await waitFor(() => expect(screen.getByTestId("bb-facts-empty")).toBeTruthy());
    expect(screen.getByTestId("bb-doubts-empty").textContent).toContain("暂无");
    // 截断如实:0/35 条(其余未列出)
    expect(screen.getByTestId("bb-facts").textContent).toContain("0/35");
    expect(screen.getByTestId("bb-facts").textContent).toContain("其余未列出");
  });

  it("端点失败如实报错,不装", async () => {
    vi.spyOn(api, "get").mockRejectedValue(new Error("意图链引擎未启用"));
    render(<BlackboardTab caseId="c1" graph={emptyGraph} onAnchor={() => {}} />);
    await waitFor(() =>
      expect(screen.getByTestId("blackboard-error").textContent).toContain("意图链引擎未启用"));
  });
});
