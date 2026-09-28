// 检索面板交互测试(切片 8b):条件构造 → query 串形态(q/cond 多值/时间窗/
// 重复 source_id 源多选)焊死;结果锚点跳内容树;响应时间如实显示;
// 后端报错原文呈现。
import { describe, expect, it, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import SearchPanel from "./SearchPanel";
import { api } from "../lib/api";
import type { SourceInfo } from "../lib/types";

vi.mock("../lib/api", () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn() },
}));

const SOURCES: SourceInfo[] = [
  { id: "src-a", case_id: "c1", path: "pkg/logs/a.log", sha256: "x", size_bytes: 1,
    kind: "text", artifact_type: "", log_type: "web_access", host: "", package: "pkg",
    detect_format: "nginx", detect_confidence: 0.99, detect_status: "auto" },
  { id: "src-b", case_id: "c1", path: "pkg/logs/b.log", sha256: "y", size_bytes: 1,
    kind: "text", artifact_type: "", log_type: "web_access", host: "", package: "pkg",
    detect_format: "nginx", detect_confidence: 0.99, detect_status: "auto" },
];

const HIT = {
  source_id: "src-a", line_no: 4217, ts: "2026-08-01T10:00:02Z", kind: "event",
  fields: '{"status":"404","ua":"sqlmap/1.7"}', raw: "GET /admin 404 sqlmap",
};

function lastUrl(): string {
  const calls = (api.get as ReturnType<typeof vi.fn>).mock.calls;
  return calls[calls.length - 1][0] as string;
}

describe("SearchPanel", () => {
  beforeEach(() => {
    (api.get as ReturnType<typeof vi.fn>).mockReset();
    (api.get as ReturnType<typeof vi.fn>).mockResolvedValue({ events: [HIT] });
  });

  it("全文词 + 字段条件 + 源多选 → query 串形态正确", async () => {
    const onAnchor = vi.fn();
    render(<SearchPanel caseId="c1" sources={SOURCES} onAnchor={onAnchor} />);

    // 全文词
    fireEvent.change(screen.getByTestId("search-q"), { target: { value: "sqlmap" } });
    // 字段条件 status:eq:404
    fireEvent.click(screen.getByTestId("cond-add"));
    const row = screen.getByTestId("cond-0");
    const [field, value] = [...row.querySelectorAll("input")];
    fireEvent.change(field, { target: { value: "status" } });
    fireEvent.change(row.querySelector("select")!, { target: { value: "eq" } });
    fireEvent.change(value, { target: { value: "404" } });
    // 源多选两个
    fireEvent.click(screen.getByTestId("src-picker"));
    const boxes = screen.getAllByRole("checkbox");
    fireEvent.click(boxes[0]);
    fireEvent.click(boxes[1]);

    fireEvent.click(screen.getByTestId("search-run"));
    await waitFor(() => expect(screen.getByTestId("search-meta")).toBeTruthy());

    const url = lastUrl();
    expect(url).toContain("/api/query?");
    expect(url).toContain("case_id=c1");
    expect(url).toContain("q=sqlmap");
    expect(url).toContain("cond=status%3Aeq%3A404");
    // 源多选 = 重复 source_id 参数(后端 → SourceIDs 集合)
    expect(url.match(/source_id=/g)).toHaveLength(2);
    expect(url).toContain("source_id=src-a");
    expect(url).toContain("source_id=src-b");
    // 全期 = 不带时间窗
    expect(url).not.toContain("ts_from");

    // 结果:命中行 + 响应时间如实 + 锚点跳内容树
    expect(screen.getByTestId("search-meta").textContent).toMatch(/1 条命中/);
    expect(screen.getByTestId("search-elapsed").textContent).toMatch(/耗时 \d+ ms/);
    fireEvent.click(screen.getByTestId("jump-0"));
    expect(onAnchor).toHaveBeenCalledWith("src-a", 4217);

    // 归一字段展开
    fireEvent.click(screen.getByText(/GET \/admin 404 sqlmap/));
    expect(screen.getByText(/status: 404/)).toBeTruthy();
  });

  it("近 1 小时时间窗 → ts_from/ts_to 都带上", async () => {
    render(<SearchPanel caseId="c1" sources={SOURCES} onAnchor={vi.fn()} />);
    fireEvent.click(screen.getByTestId("time-1h"));
    fireEvent.click(screen.getByTestId("search-run"));
    await waitFor(() => expect(lastUrl()).toContain("ts_from="));
    expect(lastUrl()).toContain("ts_to=");
  });

  it("后端报错原文呈现(不包装)", async () => {
    (api.get as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("字段名非法: \"bad-name\""));
    render(<SearchPanel caseId="c1" sources={SOURCES} onAnchor={vi.fn()} />);
    fireEvent.click(screen.getByTestId("search-run"));
    await waitFor(() => screen.getByText(/字段名非法/));
  });
});
