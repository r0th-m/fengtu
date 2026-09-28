// 案件封存包导出/导入契约测试(M4):
// CasePage 头部导出按钮存在 + 点击走 GET /api/cases/{id}/export(blob 下载,
// jsdom 只断言请求不断言下载落盘);WorkbenchPage 页头导入按钮存在 +
// 选 zip 后 FormData POST /api/cases/import,成功绿条报新案名并刷新列表。
// CasePage 重组件全部 stub(渲染级),零 AI 调用。
import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { api } from "../lib/api";
import CasePage from "./CasePage";
import WorkbenchPage from "./WorkbenchPage";

// CasePage 的图活态与重组件全部 stub——本文件只焊头部导出按钮。
vi.mock("../lib/useIntentGraph", () => ({
  useIntentGraph: () => ({ graph: { nodes: {}, edges: {}, seq: 0 }, connected: true }),
}));
vi.mock("../components/IntentGraph", () => ({ default: () => null }));
vi.mock("../components/LiveFeed", () => ({ default: () => null }));
vi.mock("../components/CandidateFeed", () => ({ default: () => null }));
vi.mock("../components/ContentTree", () => ({ default: () => null }));
vi.mock("../components/SearchPanel", () => ({ default: () => null }));
vi.mock("../components/TimelinePanel", () => ({ default: () => null }));
vi.mock("../components/ApprovalBell", () => ({ default: () => null }));
vi.mock("../components/ApprovalsTab", () => ({ default: () => null }));
vi.mock("../components/ParkingTab", () => ({ default: () => null }));
vi.mock("../components/ConstraintsTab", () => ({ default: () => null }));
vi.mock("../components/CaseKBTab", () => ({ default: () => null }));
vi.mock("../components/ReportTab", () => ({ default: () => null }));
vi.mock("../components/WorkspaceBrowser", () => ({ default: () => null }));
vi.mock("../components/ChatDock", () => ({ default: () => null }));

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// stubDownload:jsdom 无 createObjectURL,a[download] 不落盘,补齐后只断言请求。
function stubDownload() {
  (URL as unknown as Record<string, unknown>).createObjectURL = vi.fn(() => "blob:mock");
  (URL as unknown as Record<string, unknown>).revokeObjectURL = vi.fn();
}

describe("CasePage 封存包导出(M4)", () => {
  it("导出按钮存在;点击走 GET /api/cases/{id}/export(blob 下载)", async () => {
    vi.spyOn(api, "get").mockImplementation((p: string) => {
      if (p === "/api/cases/c1") {
        return Promise.resolve({
          case: { id: "c1", name: "勒索案A", created_at: "2026-09-01T00:00:00Z", sources: 2 },
          sources: [],
        }) as never;
      }
      return Promise.reject(new Error("unexpected GET " + p));
    });
    const fetchMock = vi.fn(
      async (_url: string, _init?: RequestInit) =>
        new Response("ZIP", {
          status: 200,
          headers: { "Content-Disposition": 'attachment; filename="case-c1.zip"' },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    stubDownload();
    render(
      <MemoryRouter initialEntries={["/cases/c1"]}>
        <Routes>
          <Route path="/cases/:id" element={<CasePage />} />
        </Routes>
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByTestId("case-export-btn")).toBeTruthy());
    fireEvent.click(screen.getByTestId("case-export-btn"));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith("/api/cases/c1/export",
        expect.objectContaining({ credentials: "same-origin" })));
  });
});

describe("WorkbenchPage 封存包导入(M4)", () => {
  const C1 = { id: "c1", name: "勒索案A", created_at: "2026-09-01T00:00:00Z", sources: 2, candidates: 0, pending_candidates: 0 };

  function mockList() {
    vi.spyOn(api, "get").mockImplementation((p: string) => {
      if (p === "/api/cases") return Promise.resolve({ cases: [C1] }) as never;
      if (p === "/api/tasks") return Promise.resolve({ tasks: [] }) as never;
      if (p.startsWith("/api/audit/chain")) return Promise.resolve({ entries: [] }) as never;
      return Promise.reject(new Error("unexpected GET " + p));
    });
  }

  it("导入按钮存在;选 zip 后 multipart POST /api/cases/import,成功绿条报新案名", async () => {
    mockList();
    const fetchMock = vi.fn(
      async (_url: string, _init?: RequestInit) =>
        new Response(JSON.stringify({ case: { id: "c9", name: "导入案X" }, sources: 3 }), {
          status: 202,
          headers: { "Content-Type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    render(
      <MemoryRouter>
        <WorkbenchPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByTestId("case-import-btn")).toBeTruthy());
    const file = new File(["zip-bytes"], "pack.zip", { type: "application/zip" });
    fireEvent.change(screen.getByTestId("case-import-input"), { target: { files: [file] } });
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith("/api/cases/import",
        expect.objectContaining({ method: "POST" })));
    // multipart 字段名 = file
    const body = fetchMock.mock.calls[0][1]?.body as FormData;
    expect(body.get("file")).toBeTruthy();
    // 成功绿条报新案名,列表刷新(api.get 被再调)
    await waitFor(() =>
      expect(screen.getByTestId("case-import-note").textContent).toContain("已导入「导入案X」"));
  });

  it("导入失败:后端文案原样红条", async () => {
    mockList();
    vi.stubGlobal("fetch", vi.fn(
      async () =>
        new Response(JSON.stringify({ error: "封存包校验失败:缺 manifest" }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        }),
    ));
    render(
      <MemoryRouter>
        <WorkbenchPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByTestId("case-import-btn")).toBeTruthy());
    const file = new File(["zip-bytes"], "bad.zip", { type: "application/zip" });
    fireEvent.change(screen.getByTestId("case-import-input"), { target: { files: [file] } });
    await waitFor(() =>
      expect(screen.getByText("封存包校验失败:缺 manifest")).toBeTruthy());
  });
});
