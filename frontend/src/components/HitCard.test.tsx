// 候选卡裁决交互测试:接受/排除按钮 → verdictFn 调用 → 卡片状态更新;
// 锚点点击 → onAnchor 回调(源+行号);裁决失败如实显错。
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import HitCard from "./HitCard";
import type { Hit } from "../lib/types";

function makeHit(over: Partial<Hit> = {}): Hit {
  return {
    id: "hit-1",
    case_id: "case-1",
    source_id: "src-1",
    line_no: 4217,
    rule_id: "scanner-ua",
    severity: "medium",
    matched_field: "ua",
    matched_value: "sqlmap",
    snippet: "GET /admin HTTP/1.1 sqlmap/1.7",
    ts_utc: null,
    status: "pending",
    round_no: 2,
    evidence_grade: "suspect",
    created_at: "2026-09-22T00:00:00Z",
    ...over,
  };
}

function renderCard(hit: Hit, over: Partial<Parameters<typeof HitCard>[0]> = {}) {
  const props = {
    hit,
    ruleTitle: "扫描器指纹",
    sourcePath: "Forensic_1.2.3.4_H/logs/nginx/access.log",
    verdictFn: vi.fn(async (id: string, status: "accepted" | "rejected") => ({
      ...hit, status, reviewed_by: "analyst",
    })),
    onAnchor: vi.fn(),
    ...over,
  };
  const utils = render(<HitCard {...props} />);
  return { props, ...utils };
}

describe("HitCard 候选卡", () => {
  it("渲染:等级 badge/规则标题/片段/锚点(源+行号)/裁决按钮齐全", () => {
    renderCard(makeHit());
    expect(screen.getByText("疑似")).toBeTruthy(); // suspect badge
    expect(screen.getByText("扫描器指纹")).toBeTruthy();
    expect(screen.getByText(/sqlmap\/1\.7/)).toBeTruthy();
    expect(screen.getByTestId("anchor-hit-1").textContent).toContain("access.log:4217");
    expect(screen.getByTestId("accept-hit-1")).toBeTruthy();
    expect(screen.getByTestId("reject-hit-1")).toBeTruthy();
    // 纪律:「确认」类措辞禁出现
    expect(screen.queryByText("确认")).toBeNull();
  });

  it("点「接受」→ verdictFn(accepted) → 卡片变已接受且带裁决人", async () => {
    const onUpdated = vi.fn();
    const { props } = renderCard(makeHit(), { onUpdated });
    fireEvent.click(screen.getByTestId("accept-hit-1"));
    await waitFor(() => expect(props.verdictFn).toHaveBeenCalledWith("hit-1", "accepted"));
    await waitFor(() =>
      expect(onUpdated.mock.calls[0][0].status).toBe("accepted"));
  });

  it("点「排除」→ verdictFn(rejected)", async () => {
    const { props } = renderCard(makeHit());
    fireEvent.click(screen.getByTestId("reject-hit-1"));
    await waitFor(() => expect(props.verdictFn).toHaveBeenCalledWith("hit-1", "rejected"));
  });

  it("已裁决卡片:不再显示裁决按钮,显示终态", () => {
    renderCard(makeHit({ status: "accepted", reviewed_by: "analyst" }));
    expect(screen.queryByTestId("accept-hit-1")).toBeNull();
    expect(screen.getByTestId("verdict-state-hit-1").textContent).toContain("已接受");
    expect(screen.getByTestId("verdict-state-hit-1").textContent).toContain("analyst");
  });

  it("裁决失败:如实显错,不装成功", async () => {
    const verdictFn = vi.fn(async () => {
      throw new Error("裁决状态非法");
    });
    renderCard(makeHit(), { verdictFn });
    fireEvent.click(screen.getByTestId("accept-hit-1"));
    await waitFor(() => expect(screen.getByText(/裁决状态非法/)).toBeTruthy());
  });

  it("锚点点击 → onAnchor(source_id, line_no)", () => {
    const { props } = renderCard(makeHit());
    fireEvent.click(screen.getByTestId("anchor-hit-1"));
    expect(props.onAnchor).toHaveBeenCalledWith("src-1", 4217);
  });

  it("pending 卡连点两次只发一次裁决(busy 防重)", async () => {
    let release: (h: Hit) => void = () => {};
    const verdictFn = vi.fn(
      () => new Promise<Hit>((res) => {
        release = res;
      }),
    );
    renderCard(makeHit(), { verdictFn });
    const btn = screen.getByTestId("accept-hit-1");
    fireEvent.click(btn);
    fireEvent.click(btn);
    expect(verdictFn).toHaveBeenCalledTimes(1);
    release(makeHit({ status: "accepted" }));
    await waitFor(() => expect(verdictFn).toHaveBeenCalledTimes(1));
  });
});
