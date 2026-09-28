// 知识库页契约测试(0.19.0-heuristic-kb 起;0.27.1-kb-simplify 启停下线):
// 列表渲染(builtin/用户徽标 + 场景标签)、新建、编辑、删除二次确认;
// 0.27.1 起页面纯管条目内容——无启用/禁用开关(启停语义退役,生效以案件
// 勾选为准,本文件焊死「无开关」)。全部 mock api,零 AI 调用。
import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { api } from "../lib/api";
import KBPage from "./KBPage";
import type { KBEntry } from "../lib/types";

afterEach(() => vi.restoreAllMocks());

const BUILTIN: KBEntry = {
  id: "wer-crash-report",
  title: "WER 崩溃报告:执行证据与样本找回通道",
  content: "hdmp 含完整内存镜像。",
  applies_to: ["execution", "sample-recovery"],
  source: "builtin",
  created_at: "2026-09-25T10:00:00Z",
  updated_at: "2026-09-25T10:00:00Z",
};

const USER: KBEntry = {
  id: "u-1",
  title: "我的沉淀",
  content: "怎么找丙。",
  applies_to: ["timeline"],
  source: "user",
  created_at: "2026-09-25T11:00:00Z",
  updated_at: "2026-09-25T11:00:00Z",
};

function mockList(entries: KBEntry[]) {
  return vi.spyOn(api, "get").mockImplementation((p: string) => {
    if (p === "/api/kb") return Promise.resolve({ entries, note: "n" });
    return Promise.reject(new Error("unexpected GET " + p));
  });
}

function mount() {
  return render(
    <MemoryRouter>
      <KBPage />
    </MemoryRouter>,
  );
}

describe("KBPage", () => {
  it("列表渲染:标题/场景标签/来源徽标/更新时间;0.27.1 起无启停开关", async () => {
    mockList([BUILTIN, USER]);
    mount();
    await waitFor(() => expect(screen.getByTestId("kb-row-wer-crash-report")).toBeTruthy());
    expect(screen.getByTestId("kb-source-wer-crash-report").textContent).toBe("内置");
    expect(screen.getByTestId("kb-source-u-1").textContent).toBe("用户");
    expect(screen.getByText("执行证据")).toBeTruthy();
    expect(screen.getByText("样本找回")).toBeTruthy();
    expect(screen.getByTestId("kb-stats").textContent).toContain("共 2 条");
    // 管理口径文案:只管内容,生效以勾选为准
    expect(screen.getByTestId("kb-stats").textContent).toContain("只管条目内容");
    // 启停下线:无任何开关(role=switch / kb-toggle-*)
    expect(screen.queryByRole("switch")).toBeNull();
    expect(screen.queryByTestId("kb-toggle-wer-crash-report")).toBeNull();
    expect(screen.queryByTestId("kb-toggle-u-1")).toBeNull();
    // 用户条目有编辑/删除;内置条目没有
    expect(screen.getByTestId("kb-edit-u-1")).toBeTruthy();
    expect(screen.getByTestId("kb-del-u-1")).toBeTruthy();
    expect(screen.queryByTestId("kb-edit-wer-crash-report")).toBeNull();
    expect(screen.queryByTestId("kb-del-wer-crash-report")).toBeNull();
    // 正文展开
    fireEvent.click(screen.getByTestId("kb-expand-wer-crash-report"));
    expect(screen.getByTestId("kb-content-wer-crash-report").textContent).toContain("hdmp");
  });

  it("新建用户条目:POST 发出并刷新", async () => {
    const get = mockList([BUILTIN]);
    const post = vi.spyOn(api, "post").mockResolvedValue({ entry: USER });
    mount();
    await waitFor(() => expect(screen.getByTestId("kb-row-wer-crash-report")).toBeTruthy());
    fireEvent.click(screen.getByTestId("kb-create"));
    fireEvent.change(screen.getByTestId("kb-title-input"), {
      target: { value: "我的沉淀" },
    });
    fireEvent.click(screen.getByTestId("kb-tag-timeline"));
    fireEvent.change(screen.getByTestId("kb-content-input"), {
      target: { value: "怎么找丙。" },
    });
    fireEvent.click(screen.getByTestId("kb-submit"));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/kb", {
        title: "我的沉淀",
        applies_to: ["timeline"],
        content: "怎么找丙。",
      }));
    await waitFor(() => expect(get.mock.calls.length).toBeGreaterThanOrEqual(2));
  });

  it("编辑用户条目:PUT 全字段发出(不含 enabled)", async () => {
    mockList([USER]);
    const put = vi.spyOn(api, "put").mockResolvedValue({ entry: USER });
    mount();
    await waitFor(() => expect(screen.getByTestId("kb-row-u-1")).toBeTruthy());
    fireEvent.click(screen.getByTestId("kb-edit-u-1"));
    fireEvent.change(screen.getByTestId("kb-title-input"), {
      target: { value: "改后标题" },
    });
    fireEvent.click(screen.getByTestId("kb-submit"));
    await waitFor(() =>
      expect(put).toHaveBeenCalledWith("/api/kb/u-1", {
        title: "改后标题",
        applies_to: ["timeline"],
        content: "怎么找丙。",
      }));
  });

  it("整页不发任何带 enabled 的请求(启停下线焊死)", async () => {
    mockList([BUILTIN, USER]);
    const put = vi.spyOn(api, "put").mockResolvedValue({ entry: USER });
    mount();
    await waitFor(() => expect(screen.getByTestId("kb-row-u-1")).toBeTruthy());
    fireEvent.click(screen.getByTestId("kb-edit-u-1"));
    fireEvent.click(screen.getByTestId("kb-submit"));
    await waitFor(() => expect(put).toHaveBeenCalled());
    for (const call of put.mock.calls) {
      expect(call[1]).not.toHaveProperty("enabled");
    }
  });

  it("删除:二次确认后 DELETE 发出", async () => {
    mockList([USER]);
    const del = vi.spyOn(api, "del").mockResolvedValue({ deleted: "u-1" });
    mount();
    await waitFor(() => expect(screen.getByTestId("kb-row-u-1")).toBeTruthy());
    fireEvent.click(screen.getByTestId("kb-del-u-1"));
    expect(screen.getByTestId("kb-delete-dialog")).toBeTruthy();
    expect(del).not.toHaveBeenCalled(); // 未确认不发请求
    fireEvent.click(screen.getByTestId("kb-delete-confirm"));
    await waitFor(() => expect(del).toHaveBeenCalledWith("/api/kb/u-1"));
  });

  it("后端报错原样呈现(编辑被拒口径)", async () => {
    mockList([USER]);
    vi.spyOn(api, "put").mockRejectedValue(new Error("条目启停已下线(0.27.1)"));
    mount();
    await waitFor(() => expect(screen.getByTestId("kb-row-u-1")).toBeTruthy());
    fireEvent.click(screen.getByTestId("kb-edit-u-1"));
    fireEvent.click(screen.getByTestId("kb-submit"));
    await waitFor(() =>
      expect(screen.getByTestId("kb-error").textContent).toContain("启停已下线"));
  });
});
