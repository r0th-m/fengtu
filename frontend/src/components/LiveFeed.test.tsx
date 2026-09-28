// 播报板(0.23.0-live-feed)焊死:三档+审批渲染/就地介入(停止/纠偏行内
// 标注,复用现有端点)/吸底不抢滚动/折叠记忆/空态如实/上限丢弃标注。
// 数据源 hook 打 mock(归并逻辑在 lib/feed.test.ts 单测)。
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import LiveFeed from "./LiveFeed";
import { api } from "../lib/api";
import { applyChange, emptyGraph, type IntentNode } from "../lib/intent";
import { emptyFeed, type FeedItem, type FeedState } from "../lib/feed";

const h = vi.hoisted(() => ({ feed: { items: [], dropped: 0, lastSeq: 0 } as FeedState }));
vi.mock("../lib/useActivityFeed", () => ({
  useActivityFeed: () => ({ feed: h.feed, connected: true }),
}));

function node(id: string, status: string): IntentNode {
  return {
    id, case_id: "c1", kind: "intent", text: "核查外联", status,
    created_by: "ai", scope: "case", depth: 1, budget_seconds: 600,
    created_at: "2026-09-26T00:00:00Z",
  };
}

function it_(seq: number, tier: FeedItem["tier"], text: string, extra?: Partial<FeedItem>): FeedItem {
  return { seq, tier, text, ts: "2026-09-26T01:02:03Z", ...extra };
}

beforeEach(() => {
  localStorage.clear();
  h.feed = emptyFeed;
});
afterEach(() => vi.restoreAllMocks());

describe("LiveFeed 播报板", () => {
  it("空态如实「等待意图引擎产出」", () => {
    render(<LiveFeed caseId="c1" graph={emptyGraph} onAnchor={() => {}} onApprovals={() => {}} />);
    expect(screen.getByTestId("livefeed-empty").textContent).toContain("等待意图引擎产出");
  });

  it("三档渲染:诞生/中间发现/终结(置信色);时间戳+档位标", () => {
    h.feed = {
      items: [
        it_(1, "spawn", "派生了新意图: 核查外联", { node_id: "n1" }),
        it_(2, "progress", "调用工具: search", { node_id: "n1", detail: "search 全文" }),
        it_(3, "finish", "发现可疑外联", { node_id: "n1", status: "supported" }),
      ],
      dropped: 0, lastSeq: 3,
    };
    render(<LiveFeed caseId="c1" graph={emptyGraph} onAnchor={() => {}} onApprovals={() => {}} />);
    expect(screen.getByText("派生了新意图: 核查外联")).toBeTruthy();
    expect(screen.getByText("调用工具: search")).toBeTruthy();
    expect(screen.getByText("发现可疑外联")).toBeTruthy();
    expect(screen.getByTestId("feed-status-3").textContent).toBe("证据支持");
    expect(screen.getByTestId("feed-status-3").className).toContain("emerald");
  });

  it("折叠记忆:收起进 localStorage,重挂载保持折叠", () => {
    h.feed = { items: [it_(1, "spawn", "x", { node_id: "n1" })], dropped: 0, lastSeq: 1 };
    const { unmount } = render(
      <LiveFeed caseId="c1" graph={emptyGraph} onAnchor={() => {}} onApprovals={() => {}} />);
    expect(screen.getByTestId("livefeed-body")).toBeTruthy();
    fireEvent.click(screen.getByTestId("livefeed-toggle"));
    expect(screen.queryByTestId("livefeed-body")).toBeNull();
    expect(localStorage.getItem("fengtu.livefeed.collapsed")).toBe("1");
    unmount();
    render(<LiveFeed caseId="c1" graph={emptyGraph} onAnchor={() => {}} onApprovals={() => {}} />);
    expect(screen.queryByTestId("livefeed-body")).toBeNull(); // 记忆折叠
  });

  it("就地介入:停止调现有端点,行内即时标「已停止」", async () => {
    const g = applyChange(emptyGraph, "node_added", node("n1", "running"));
    h.feed = { items: [it_(1, "spawn", "派生了新意图: 核查外联", { node_id: "n1" })], dropped: 0, lastSeq: 1 };
    const post = vi.spyOn(api, "post").mockResolvedValue({});
    render(<LiveFeed caseId="c1" graph={g} onAnchor={() => {}} onApprovals={() => {}} />);
    fireEvent.click(screen.getByTestId("feed-stop-1"));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/intents/n1/stop"));
    await waitFor(() =>
      expect(screen.getByTestId("feed-acted-1").textContent).toBe("已停止"));
  });

  it("就地介入:纠偏开行内输入,发送调 steer 端点并标「已纠偏」", async () => {
    const g = applyChange(emptyGraph, "node_added", node("n1", "running"));
    h.feed = { items: [it_(1, "spawn", "派生了新意图: 核查外联", { node_id: "n1" })], dropped: 0, lastSeq: 1 };
    const post = vi.spyOn(api, "post").mockResolvedValue({});
    render(<LiveFeed caseId="c1" graph={g} onAnchor={() => {}} onApprovals={() => {}} />);
    fireEvent.click(screen.getByTestId("feed-steer-1"));
    fireEvent.change(screen.getByTestId("feed-steer-input-1"), { target: { value: "先看 3306" } });
    fireEvent.click(screen.getByTestId("feed-steer-send-1"));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/intents/n1/steer", { text: "先看 3306" }));
    await waitFor(() =>
      expect(screen.getByTestId("feed-acted-1").textContent).toBe("已纠偏"));
  });

  it("审批事件:待审批带 [去审批],点击切审批 tab", () => {
    const g = applyChange(emptyGraph, "node_added", node("n9", "awaiting_approval"));
    h.feed = {
      items: [it_(5, "approval", "意图待审批: 全网扫", { node_id: "n9", status: "awaiting_approval" })],
      dropped: 0, lastSeq: 5,
    };
    const onApprovals = vi.fn();
    render(<LiveFeed caseId="c1" graph={g} onAnchor={() => {}} onApprovals={onApprovals} />);
    fireEvent.click(screen.getByTestId("feed-goto-approval-5"));
    expect(onApprovals).toHaveBeenCalled();
  });

  it("中间发现可展开:全文 + 节点证据锚点跳内容树", () => {
    const n = { ...node("n1", "supported"), evidence: [{ source_id: "src-123456789", line_no: 42 }] };
    const g = applyChange(emptyGraph, "node_added", n);
    h.feed = {
      items: [it_(2, "progress", "工具返回: 3 条", { node_id: "n1", detail: "命中 3 行全文" })],
      dropped: 0, lastSeq: 2,
    };
    const onAnchor = vi.fn();
    render(<LiveFeed caseId="c1" graph={g} onAnchor={onAnchor} onApprovals={() => {}} />);
    fireEvent.click(screen.getByTestId("feed-expand-2"));
    expect(screen.getByTestId("feed-detail-2").textContent).toContain("命中 3 行全文");
    fireEvent.click(screen.getByTestId("feed-anchor-2-0"));
    expect(onAnchor).toHaveBeenCalledWith("src-123456789", 42);
  });

  it("上限截断如实标注 dropped", () => {
    h.feed = { items: [it_(900, "finish", "收尾", { status: "denied" })], dropped: 500, lastSeq: 900 };
    render(<LiveFeed caseId="c1" graph={emptyGraph} onAnchor={() => {}} onApprovals={() => {}} />);
    expect(screen.getByTestId("livefeed-dropped").textContent).toContain("丢弃最旧 500 条");
  });

  it("吸底不抢滚动:在底部时追新,上翻后停吸", () => {
    h.feed = { items: [it_(1, "progress", "一")], dropped: 0, lastSeq: 1 };
    const { rerender } = render(
      <LiveFeed caseId="c1" graph={emptyGraph} onAnchor={() => {}} onApprovals={() => {}} />);
    const body = screen.getByTestId("livefeed-body");
    Object.defineProperty(body, "scrollHeight", { value: 1000, configurable: true });
    Object.defineProperty(body, "clientHeight", { value: 200, configurable: true });
    // 用户上翻(scrollTop=100 → 距底 700 > 40 → 停吸)
    body.scrollTop = 100;
    fireEvent.scroll(body);
    h.feed = { items: [it_(1, "progress", "一"), it_(2, "progress", "二")], dropped: 0, lastSeq: 2 };
    rerender(<LiveFeed caseId="c1" graph={emptyGraph} onAnchor={() => {}} onApprovals={() => {}} />);
    expect(body.scrollTop).toBe(100); // 不抢滚动
    // 回到底部附近 → 恢复吸底
    body.scrollTop = 790;
    fireEvent.scroll(body);
    h.feed = { items: [...h.feed.items, it_(3, "progress", "三")], dropped: 0, lastSeq: 3 };
    rerender(<LiveFeed caseId="c1" graph={emptyGraph} onAnchor={() => {}} onApprovals={() => {}} />);
    expect(body.scrollTop).toBe(1000); // 吸到底
  });
});
