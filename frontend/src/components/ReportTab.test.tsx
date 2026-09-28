// 报告 tab 焊死(0.30.0-report-ux 新结构):结论先行(案子/时间窗/核心判断
// 清单)/攻击时间线(升序+截断标)/分章结论(章头 supported 账+血缘展开)/
// 已确认发现锚点四件可跳/证据附录去重清单/机器评估声明/处置建议「需人核」/
// 空态如实/下载按钮/加载失败如实显错。
import { describe, expect, it, vi, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import ReportTab from "./ReportTab";
import { api } from "../lib/api";
import { applyChange, emptyGraph, type GraphState } from "../lib/intent";
import type { ReportData } from "../lib/types";

function reportFixture(): ReportData {
  return {
    case_id: "c1", case_name: "测试案件", incident_type: "ransomware",
    background: "【发现经过】测试", generated_at: "2026-09-23T01:00:00Z",
    hosts: ["10.0.0.1"],
    window_from: "2024-01-01T00:00:05Z", window_to: "2024-01-01T02:30:00Z",
    chapters: [{
      goal_id: "g1", goal_text: "确认入侵入口", status: "closed_goal_partial",
      intents_total: 2, intents_supported: 1,
      facts: [{ id: "f1", text: "存在 401 集中失败", evidence: [
        { source_id: "s1", line_no: 42, host: "10.0.0.1", source_path: "logs/access.log",
          source_sha256: "abcdef" },
      ] }],
    }],
    orphan_facts: [{ id: "f9", text: "散件结论", evidence: [] }],
    findings: [{
      id: "h1", rule_id: "scanner-ua", severity: "high", evidence_grade: "strong",
      snippet: "sqlmap/1.7", ts_utc: null, reviewed_by: "boss",
      source_id: "s1", line_no: 42, host: "10.0.0.1",
      source_path: "logs/access.log",
      source_sha256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    }],
    timeline: [{
      ts_utc: "2024-01-01T00:00:05Z", kind: "fact", text: "存在 401 集中失败",
      fact_id: "f1", host: "10.0.0.1", source_id: "s1",
      source_path: "logs/access.log", line_no: 42, source_sha256: "abcdef",
    }],
    timeline_total: 1, timeline_truncated: false,
    evidence: [{
      host: "10.0.0.1", source_id: "s1", source_path: "logs/access.log",
      line_no: 42,
      source_sha256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      refs: 2,
    }],
    evidence_truncated: false,
    hits_pending: 1, hits_accepted: 1, hits_rejected: 2,
    findings_truncated: false, sources_total: 10, sources_explored: 4,
    intent_ready: true, advice: ["隔离已确认受影响主机(断网不关机,保内存证据)"],
  };
}

function graphWithFact(): GraphState {
  let g = emptyGraph;
  g = applyChange(g, "node_added", {
    id: "g1", case_id: "c1", kind: "goal", text: "确认入侵入口", status: "supported",
    created_by: "human", scope: "case", depth: 0, budget_seconds: 600,
    created_at: "2026-09-23T00:00:00Z",
  });
  g = applyChange(g, "node_added", {
    id: "f1", case_id: "c1", kind: "fact", text: "存在 401 集中失败", status: "supported",
    created_by: "ai", scope: "case", depth: 1, budget_seconds: 600,
    created_at: "2026-09-23T00:01:00Z",
  });
  g = applyChange(g, "edge_added", {
    id: "e1", case_id: "c1", from_id: "g1", to_id: "f1", kind: "yields",
    created_at: "2026-09-23T00:01:00Z",
  });
  return g;
}

afterEach(() => vi.restoreAllMocks());

describe("ReportTab 报告(0.30.0 新结构)", () => {
  it("八区块:结论先行/时间线/分章/发现/概况/覆盖/建议/附录+机器评估声明", async () => {
    vi.spyOn(api, "get").mockResolvedValue({ report: reportFixture(), markdown: "# md" });
    render(<ReportTab caseId="c1" graph={graphWithFact()}
      onAnchor={() => {}} onJumpNode={() => {}} />);
    await waitFor(() => expect(screen.getByText(/应急响应报告:测试案件/)).toBeTruthy());
    expect(screen.getByText("勒索响应")).toBeTruthy(); // 类型徽标
    // 一、结论先行
    expect(screen.getByTestId("report-tldr")).toBeTruthy();
    expect(screen.getByText(/主机 1 台\(10\.0\.0\.1\)/)).toBeTruthy();
    expect(screen.getByTestId("report-window").textContent).toContain("~");
    expect(screen.getByTestId("report-judgment-g1").textContent)
      .toContain("确认入侵入口");
    expect(screen.getByTestId("report-judgment-g1").textContent)
      .toContain("supported 1/2");
    // 二、攻击时间线
    expect(screen.getByTestId("report-timeline-0").textContent)
      .toContain("存在 401 集中失败");
    // 三、分章排查结论
    expect(screen.getByTestId("report-chapter-g1").textContent)
      .toContain("存在 401 集中失败");
    expect(screen.getByTestId("report-orphans").textContent).toContain("散件结论");
    // 四、已确认发现:锚点四件
    const anchor = screen.getByTestId("report-anchor-h1");
    expect(anchor.textContent).toContain("10.0.0.1");
    expect(anchor.textContent).toContain("logs/access.log:42");
    expect(anchor.textContent).toContain("sha256:abcdef012345");
    // 五~八
    expect(screen.getByText(/待裁决 1 · 已确认 1 · 已排除 2/)).toBeTruthy();
    expect(screen.getByText(/覆盖缺口 6/)).toBeTruthy();
    expect(screen.getByText(/模板建议\(按应急类型\),需人核/)).toBeTruthy();
    expect(screen.getByTestId("report-evidence-0").textContent).toContain("被引 2 次");
    expect(screen.getByText(/最终定论与收官归人/)).toBeTruthy();
    expect(screen.getByTestId("report-download")).toBeTruthy();
  });

  it("锚点点击 → onAnchor(source_id, line_no)", async () => {
    vi.spyOn(api, "get").mockResolvedValue({ report: reportFixture(), markdown: "" });
    const onAnchor = vi.fn();
    render(<ReportTab caseId="c1" graph={graphWithFact()}
      onAnchor={onAnchor} onJumpNode={() => {}} />);
    await waitFor(() => expect(screen.getByTestId("report-anchor-h1")).toBeTruthy());
    fireEvent.click(screen.getByTestId("report-anchor-h1"));
    expect(onAnchor).toHaveBeenCalledWith("s1", 42);
  });

  it("血缘按钮展开子图(复用布局引擎,goal→fact 链在图)", async () => {
    vi.spyOn(api, "get").mockResolvedValue({ report: reportFixture(), markdown: "" });
    render(<ReportTab caseId="c1" graph={graphWithFact()}
      onAnchor={() => {}} onJumpNode={() => {}} />);
    await waitFor(() => expect(screen.getByTestId("report-lineage-f1")).toBeTruthy());
    fireEvent.click(screen.getByTestId("report-lineage-f1"));
    await waitFor(() => expect(screen.getByTestId("lineage-f1")).toBeTruthy());
    expect(screen.getByTestId("lineage-f1").textContent).toContain("确认入侵入口");
    expect(screen.getByTestId("lineage-f1").textContent).toContain("存在 401 集中失败");
  });

  it("空态如实:无时间窗/零章节/零时间线/零附录", async () => {
    const d = reportFixture();
    d.window_from = null;
    d.window_to = null;
    d.chapters = [];
    d.orphan_facts = [];
    d.timeline = [];
    d.timeline_total = 0;
    d.evidence = [];
    d.findings = [];
    vi.spyOn(api, "get").mockResolvedValue({ report: d, markdown: "" });
    render(<ReportTab caseId="c1" graph={emptyGraph}
      onAnchor={() => {}} onJumpNode={() => {}} />);
    await waitFor(() => expect(screen.getByTestId("report-tldr")).toBeTruthy());
    expect(screen.getByText(/时间窗缺失\(如实\)/)).toBeTruthy();
    expect(screen.getByText(/未播种子目标,无章节可归纳/)).toBeTruthy();
    expect(screen.getByText(/时间线如实为空/)).toBeTruthy();
    expect(screen.getByText(/无已确认发现/)).toBeTruthy();
    expect(screen.getByText(/无源锚点可附\(如实\)/)).toBeTruthy();
  });

  it("加载失败:如实显错不装死", async () => {
    vi.spyOn(api, "get").mockRejectedValue(new Error("无此案件: c1"));
    render(<ReportTab caseId="c1" graph={emptyGraph}
      onAnchor={() => {}} onJumpNode={() => {}} />);
    await waitFor(() => expect(screen.getByText("无此案件: c1")).toBeTruthy());
  });

  it("双子页签(0.31.0):默认结构化报告;切研判报告页签出 NarrativePanel", async () => {
    vi.spyOn(api, "get").mockImplementation((path: string) => {
      if (path.endsWith("/report/narrative")) {
        return Promise.resolve({ reports: [] });
      }
      return Promise.resolve({ report: reportFixture(), markdown: "# md" });
    });
    render(<ReportTab caseId="c1" graph={graphWithFact()}
      onAnchor={() => {}} onJumpNode={() => {}} />);
    // 默认=结构化报告(八区块在,页签栏在)
    await waitFor(() => expect(screen.getByTestId("report-tldr")).toBeTruthy());
    expect(screen.getByTestId("report-subtab-structured")).toBeTruthy();
    expect(screen.getByTestId("report-subtab-narrative")).toBeTruthy();
    // 切研判报告:结构化区块退场,NarrativePanel 登场(空态引导)
    fireEvent.click(screen.getByTestId("report-subtab-narrative"));
    await waitFor(() => expect(screen.getByTestId("narrative-panel")).toBeTruthy());
    expect(screen.queryByTestId("report-tldr")).toBeNull();
    await waitFor(() =>
      expect(screen.getByText(/还没有研判报告/)).toBeTruthy());
    expect(screen.getByTestId("narrative-generate").textContent)
      .toContain("消耗 token");
    // 切回结构化
    fireEvent.click(screen.getByTestId("report-subtab-structured"));
    await waitFor(() => expect(screen.getByTestId("report-tldr")).toBeTruthy());
    expect(screen.queryByTestId("narrative-panel")).toBeNull();
  });
});
