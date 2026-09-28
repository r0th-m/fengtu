// 研判报告子页签焊死(0.31.0-narrative-report):空态/生成(明示 token 消耗+
// 二次确认,取消不生成)/版本清单(倒序+截断标)/查看内容/生成失败如实显错。
import { describe, expect, it, vi, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import NarrativePanel from "./NarrativePanel";
import { api } from "../lib/api";
import type { CaseReportMeta } from "../lib/types";

function metaFixture(version: number, truncated = false): CaseReportMeta {
  return {
    id: `r${version}`, case_id: "c1", kind: "narrative", version,
    tokens_in: 12000, tokens_out: 3000, truncated,
    created_by: "admin", created_at: "2026-09-26T10:00:00Z",
  };
}

afterEach(() => vi.restoreAllMocks());

describe("NarrativePanel 研判报告", () => {
  it("空态:无版本时引导生成,明示消耗 token", async () => {
    vi.spyOn(api, "get").mockResolvedValue({ reports: [] });
    render(<NarrativePanel caseId="c1" />);
    await waitFor(() =>
      expect(screen.getByText(/还没有研判报告/)).toBeTruthy());
    const btn = screen.getByTestId("narrative-generate");
    expect(btn.textContent).toContain("消耗 token");
    expect(screen.getByText(/版本清单|历史版本/)).toBeTruthy();
  });

  it("生成:二次确认 → POST → 新版本入列 + 内容呈现", async () => {
    const rep = metaFixture(1);
    vi.spyOn(api, "get").mockImplementation((path: string) => {
      if (path.endsWith("/report/narrative")) {
        return Promise.resolve({ reports: [rep] });
      }
      return Promise.reject(new Error("unexpected " + path));
    });
    const post = vi.spyOn(api, "post").mockResolvedValue({
      report: rep, content: "> ⚠️ 本报告为 **AI 生成初稿,定论归人**\n\n# 研判报告\n正文",
    });
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<NarrativePanel caseId="c1" />);
    await waitFor(() => expect(screen.getByTestId("narrative-generate")).toBeTruthy());
    fireEvent.click(screen.getByTestId("narrative-generate"));
    await waitFor(() =>
      expect(screen.getByTestId("narrative-content").textContent)
        .toContain("AI 生成初稿,定论归人"));
    expect(post).toHaveBeenCalledWith("/api/cases/c1/report/narrative", {});
    // 确认文案明示 token 消耗
    expect(window.confirm).toHaveBeenCalledWith(expect.stringContaining("token"));
    await waitFor(() =>
      expect(screen.getByTestId("narrative-version-1")).toBeTruthy());
    expect(screen.getByTestId("narrative-content").textContent).toContain("正文");
    expect(screen.getByTestId("narrative-download")).toBeTruthy();
  });

  it("确认框取消 → 不发 POST(不烧 token)", async () => {
    vi.spyOn(api, "get").mockResolvedValue({ reports: [] });
    const post = vi.spyOn(api, "post").mockResolvedValue({});
    vi.spyOn(window, "confirm").mockReturnValue(false);
    render(<NarrativePanel caseId="c1" />);
    await waitFor(() => expect(screen.getByTestId("narrative-generate")).toBeTruthy());
    fireEvent.click(screen.getByTestId("narrative-generate"));
    expect(post).not.toHaveBeenCalled();
  });

  it("版本清单:倒序 + 截断标;点版本看内容", async () => {
    const v2 = metaFixture(2, true);
    const v1 = metaFixture(1);
    vi.spyOn(api, "get").mockImplementation((path: string) => {
      if (path.endsWith("/report/narrative")) {
        return Promise.resolve({ reports: [v2, v1] });
      }
      if (path.endsWith("/report/narrative/1")) {
        return Promise.resolve({ report: v1, content: "v1 内容" });
      }
      return Promise.reject(new Error("unexpected " + path));
    });
    render(<NarrativePanel caseId="c1" />);
    await waitFor(() => expect(screen.getByTestId("narrative-version-2")).toBeTruthy());
    // 截断标
    expect(screen.getByTestId("narrative-version-2").textContent).toContain("截断");
    // token 账呈现
    expect(screen.getByTestId("narrative-version-2").textContent)
      .toContain("12000/3000");
    fireEvent.click(screen.getByTestId("narrative-version-1"));
    await waitFor(() =>
      expect(screen.getByTestId("narrative-content").textContent)
        .toContain("v1 内容"));
  });

  it("生成失败如实显错(归档 409 文案原样)", async () => {
    vi.spyOn(api, "get").mockResolvedValue({ reports: [] });
    vi.spyOn(api, "post").mockRejectedValue(
      new Error("案件已归档(只读可看历史版本,不生成新研判报告)"));
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<NarrativePanel caseId="c1" />);
    await waitFor(() => expect(screen.getByTestId("narrative-generate")).toBeTruthy());
    fireEvent.click(screen.getByTestId("narrative-generate"));
    await waitFor(() =>
      expect(screen.getByTestId("narrative-error").textContent)
        .toContain("已归档"));
  });
});
