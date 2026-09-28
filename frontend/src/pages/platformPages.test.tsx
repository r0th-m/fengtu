// 平台页契约测试(切片十):七个新页面各焊关键交互——
// 仪表盘统计卡、发现页筛选、LLM 录制清单+详情+档位开关、工作空间清单、
// 日志过滤/级别、系统配置保存、审批批准通路。全部 mock api,零 AI 调用。
import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { api } from "../lib/api";
import DashboardPage from "./DashboardPage";
import FindingsPage from "./FindingsPage";
import LLMRecordsPage from "./LLMRecordsPage";
import WorkspacePage from "./WorkspacePage";
import LogsPage from "./LogsPage";
import SettingsPage from "./SettingsPage";
import ApprovalsPage from "./ApprovalsPage";

afterEach(() => vi.restoreAllMocks());

function mount(el: React.ReactElement) {
  return render(<MemoryRouter>{el}</MemoryRouter>);
}

// mockApi 按路径前缀分派(测试只认白名单路径,意外调用即炸,防串味)。
// 最长前缀优先:/api/cases/c1/workspace/list 不能被 /api/cases 误吞。
function mockApi(routes: Record<string, unknown>) {
  const keys = Object.keys(routes).sort((a, b) => b.length - a.length);
  return vi.spyOn(api, "get").mockImplementation((p: string) => {
    for (const prefix of keys) {
      if (p.startsWith(prefix)) return Promise.resolve(routes[prefix]);
    }
    return Promise.reject(new Error("unexpected GET " + p));
  });
}

const CASES = {
  cases: [
    { id: "c1", name: "勒索案A", created_at: "2026-09-01T00:00:00Z", sources: 2, candidates: 1, pending_candidates: 1, incident_type: "ransomware" },
    { id: "c2", name: "入侵案B", created_at: "2026-09-02T00:00:00Z", sources: 1, candidates: 0, pending_candidates: 0, incident_type: "intrusion" },
  ],
};

describe("DashboardPage", () => {
  it("统计卡 + 状态分布 + 活动柱", async () => {
    mockApi({
      "/api/stats/overview": {
        stats: { cases: 2, sources: 3, candidates: 5, pending_candidates: 2, pending_approvals: 1, llm_records: 7,
          activity: [{ day: "2026-09-24", count: 4 }] },
        case_status: { pending: 1, reviewed: 0, ingested: 1, empty: 0 },
        activity_note: "n",
      },
    });
    mount(<DashboardPage />);
    await waitFor(() => expect(screen.getByTestId("activity-bars")).toBeTruthy());
    expect(screen.getByText("待裁决")).toBeTruthy();
    expect(screen.getByText("待审批")).toBeTruthy();
    expect(screen.getByTestId("case-status-bar")).toBeTruthy();
    expect(screen.getByText(/LLM 录制账 7 条/)).toBeTruthy();
  });
});

describe("FindingsPage", () => {
  it("跨案件汇总 + 状态筛选", async () => {
    mockApi({
      "/api/cases/c1/hits": {
        hits: [
          { id: "h1", case_id: "c1", source_id: "s1", line_no: 2, rule_id: "scanner-ua",
            severity: "medium", matched_field: "ua", matched_value: "sqlmap", snippet: "sqlmap/1.7.8",
            ts_utc: null, status: "pending", round_no: 1, evidence_grade: "suspect",
            created_at: "2026-09-20T10:00:00Z" },
          { id: "h2", case_id: "c1", source_id: "s1", line_no: 3, rule_id: "scanner-ua",
            severity: "high", matched_field: "ua", matched_value: "Nikto", snippet: "Nikto/2.1.6",
            ts_utc: null, status: "accepted", round_no: 1, evidence_grade: "strong",
            created_at: "2026-09-20T10:01:00Z" },
        ],
      },
      "/api/cases": CASES,
    });
    mount(<FindingsPage />);
    await waitFor(() => expect(screen.getByTestId("finding-row-h1")).toBeTruthy());
    expect(screen.getByTestId("finding-row-h2")).toBeTruthy();
    // 状态筛选:只看已接受 → 只剩 h2
    fireEvent.change(screen.getByTestId("finding-status-filter"), { target: { value: "accepted" } });
    expect(screen.queryByTestId("finding-row-h1")).toBeNull();
    expect(screen.getByTestId("finding-row-h2")).toBeTruthy();
  });

  it("候选数为 0 的案不发 hits 请求(省 N+1)", async () => {
    const get = mockApi({ "/api/cases": CASES });
    mount(<FindingsPage />);
    await waitFor(() => expect(get).toHaveBeenCalled());
    await waitFor(() =>
      expect(screen.getByText(/暂无候选发现|\/ 1 条|1 \/ 1 条/)).toBeTruthy());
    expect(get).not.toHaveBeenCalledWith("/api/cases/c2/hits?limit=200");
  });
});

describe("LLMRecordsPage", () => {
  const RECS = {
    records: [
      { id: "r1", session_id: "sess-aaaa", case_id: "c1", kind: "chat", model: "deepseek-chat",
        status: "ok", tokens_in: 100, tokens_out: 40, duration_ms: 1200,
        created_at: "2026-09-24T10:00:00Z" },
      { id: "r2", session_id: "sess-bbbb", case_id: "c1", kind: "intent", model: "deepseek-chat",
        status: "error", err: "厂商 500", tokens_in: 0, tokens_out: 0, duration_ms: 300,
        created_at: "2026-09-24T10:01:00Z" },
    ],
    total: 2,
  };
  const SETTINGS = {
    settings: { provider: "deepseek", base_url: "https://api.deepseek.com/v1", model: "deepseek-chat",
      key_source: "env", outbound_enabled: true, budget_tokens: 200000, max_tokens: 4096,
      rate_per_second: 0, record_mode: "metadata" },
  };

  it("清单 + 总数 + 详情(元数据档如实无全文)", async () => {
    mockApi({
      "/api/llm/records/r1": { record: RECS.records[0], note: "" },
      "/api/llm/records": RECS,
      "/api/ai/settings": SETTINGS,
      "/api/cases": CASES,
    });
    mount(<LLMRecordsPage />);
    await waitFor(() => expect(screen.getByTestId("llm-record-r1")).toBeTruthy());
    expect(screen.getByTestId("llm-records-total").textContent).toBe("2");
    fireEvent.click(screen.getByTestId("llm-record-r1"));
    await waitFor(() => expect(screen.getByTestId("llm-record-detail")).toBeTruthy());
    expect(screen.getByText(/元数据档录制/)).toBeTruthy();
  });

  it("档位切换 PUT record_mode(失败回滚由组件负责)", async () => {
    mockApi({
      "/api/llm/records": RECS,
      "/api/ai/settings": SETTINGS,
      "/api/cases": CASES,
    });
    const put = vi.spyOn(api, "put").mockResolvedValue({});
    mount(<LLMRecordsPage />);
    await waitFor(() => expect(screen.getByTestId("record-mode-select")).toBeTruthy());
    fireEvent.change(screen.getByTestId("record-mode-select"), { target: { value: "full" } });
    await waitFor(() =>
      expect(put).toHaveBeenCalledWith("/api/ai/settings", { record_mode: "full" }));
  });
});

describe("WorkspacePage(切片十三:案件隔离两层导航)", () => {
  const MT = Date.parse("2026-09-20T10:00:00Z");
  const CASE_ROOT = {
    path: "",
    entries: [
      { name: "sub", path: "sub", dir: true, size: 0, mtime: MT },
      { name: "a.txt", path: "a.txt", dir: false, size: 2048, mtime: MT },
    ],
  };
  const NO_LEGACY = { path: "", entries: [] };

  // enterCase 第一层点卡进 c1 案件工作区(第二层文件管理器)。
  async function enterCase() {
    await waitFor(() => expect(screen.getByTestId("ws-case-c1")).toBeTruthy());
    fireEvent.click(screen.getByTestId("ws-case-c1"));
    await waitFor(() => expect(screen.getByTestId("workspace-browser")).toBeTruthy());
  }

  it("第一层:案件卡渲染(案件名+应急类型徽标),无遗留则不显示未分配入口", async () => {
    mockApi({ "/api/cases": CASES, "/api/workspace/list": NO_LEGACY });
    mount(<WorkspacePage />);
    await waitFor(() => expect(screen.getByTestId("ws-case-c1")).toBeTruthy());
    expect(screen.getByTestId("ws-case-c2")).toBeTruthy();
    expect(screen.getByTestId("ws-case-c1").textContent).toContain("勒索案A");
    expect(screen.getByTestId("ws-case-c1").textContent).toContain("勒索响应");
    expect(screen.getByTestId("ws-case-c2").textContent).toContain("入侵排查");
    expect(screen.queryByTestId("ws-unassigned")).toBeNull();
  });

  it("两层导航:进案件 → 案件作用域端点 + 面包屑根=案件名;点「工作空间」回列表", async () => {
    const get = mockApi({
      "/api/cases/c1/workspace/list?path=sub": {
        path: "sub",
        entries: [{ name: "b.log", path: "sub/b.log", dir: false, size: 10, mtime: MT }],
      },
      "/api/cases/c1/workspace/list": CASE_ROOT,
      "/api/cases": CASES,
      "/api/workspace/list": NO_LEGACY,
    });
    mount(<WorkspacePage />);
    await enterCase();
    // 案件作用域端点(不是旧全局)
    expect(get).toHaveBeenCalledWith("/api/cases/c1/workspace/list?path=");
    await waitFor(() => expect(screen.getByTestId("ws-entry-a.txt")).toBeTruthy());
    expect(screen.getByTestId("ws-crumb-0").textContent).toBe("勒索案A");
    // 逐级进目录,面包屑长出第二级
    fireEvent.click(screen.getByTestId("ws-entry-sub"));
    await waitFor(() => expect(screen.getByTestId("ws-entry-b.log")).toBeTruthy());
    expect(screen.getByTestId("ws-crumb-1").textContent).toBe("sub");
    expect(get).toHaveBeenCalledWith("/api/cases/c1/workspace/list?path=sub");
    // 点「工作空间」回案件列表层
    fireEvent.click(screen.getByTestId("ws-home"));
    await waitFor(() => expect(screen.getByTestId("ws-case-c1")).toBeTruthy());
    expect(screen.queryByTestId("workspace-browser")).toBeNull();
  });

  it("未分配遗留入口:全局根有遗留时出现,点入走旧全局端点", async () => {
    const get = mockApi({
      "/api/cases": CASES,
      "/api/workspace/list": {
        path: "",
        entries: [{ name: "legacy.txt", path: "legacy.txt", dir: false, size: 5, mtime: MT }],
      },
    });
    mount(<WorkspacePage />);
    await waitFor(() => expect(screen.getByTestId("ws-unassigned")).toBeTruthy());
    fireEvent.click(screen.getByTestId("ws-unassigned"));
    await waitFor(() => expect(screen.getByTestId("ws-entry-legacy.txt")).toBeTruthy());
    expect(get).toHaveBeenCalledWith("/api/workspace/list?path=");
    expect(screen.getByTestId("ws-crumb-0").textContent).toBe("未分配");
  });

  it("案件文件抽屉:预览 → 编辑 dirty → 保存 PUT(案件作用域端点)", async () => {
    mockApi({
      "/api/cases/c1/workspace/file": {
        name: "a.txt", path: "a.txt", size: 5, mtime: MT,
        binary: false, too_large: false, content: "hello",
      },
      "/api/cases/c1/workspace/list": CASE_ROOT,
      "/api/cases": CASES,
      "/api/workspace/list": NO_LEGACY,
    });
    const put = vi.spyOn(api, "put").mockResolvedValue({});
    mount(<WorkspacePage />);
    await enterCase();
    await waitFor(() => expect(screen.getByTestId("ws-entry-a.txt")).toBeTruthy());
    fireEvent.click(screen.getByTestId("ws-entry-a.txt"));
    await waitFor(() => expect(screen.getByTestId("ws-editor")).toBeTruthy());
    expect((screen.getByTestId("ws-editor") as HTMLTextAreaElement).value).toBe("hello");
    fireEvent.change(screen.getByTestId("ws-editor"), { target: { value: "hello v2" } });
    expect(screen.getByTestId("ws-dirty-state").textContent).toBe("未保存的修改");
    fireEvent.click(screen.getByTestId("ws-save"));
    await waitFor(() =>
      expect(put).toHaveBeenCalledWith("/api/cases/c1/workspace/file",
        { path: "a.txt", content: "hello v2" }));
  });

  it("二进制如实只给下载;删除 confirm + 新建文件夹全走案件作用域端点", async () => {
    mockApi({
      "/api/cases/c1/workspace/file": {
        name: "a.bin", path: "a.bin", size: 99, mtime: MT,
        binary: true, too_large: false,
      },
      "/api/cases/c1/workspace/list": {
        path: "",
        entries: [{ name: "a.bin", path: "a.bin", dir: false, size: 99, mtime: MT }],
      },
      "/api/cases": CASES,
      "/api/workspace/list": NO_LEGACY,
    });
    const del = vi.spyOn(api, "del").mockResolvedValue({});
    const post = vi.spyOn(api, "post").mockResolvedValue({});
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    mount(<WorkspacePage />);
    await enterCase();
    await waitFor(() => expect(screen.getByTestId("ws-entry-a.bin")).toBeTruthy());
    fireEvent.click(screen.getByTestId("ws-entry-a.bin"));
    await waitFor(() => expect(screen.getByTestId("ws-noedit-note")).toBeTruthy());
    expect(screen.getByTestId("ws-noedit-note").textContent).toContain("二进制");
    expect(screen.queryByTestId("ws-editor")).toBeNull();
    fireEvent.click(screen.getByTestId("ws-drawer-close"));
    fireEvent.click(screen.getByTestId("ws-del-a.bin"));
    await waitFor(() =>
      expect(del).toHaveBeenCalledWith("/api/cases/c1/workspace/entry?path=a.bin"));
    expect(confirm).toHaveBeenCalled();
    fireEvent.click(screen.getByTestId("ws-mkdir-btn"));
    fireEvent.change(screen.getByTestId("ws-mkdir-input"), { target: { value: "docs" } });
    fireEvent.click(screen.getByTestId("ws-mkdir-confirm"));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/cases/c1/workspace/mkdir", { path: "docs" }));
  });
});

describe("LogsPage", () => {
  it("终端流渲染 + 级别过滤 + 统计", async () => {
    mockApi({
      "/api/logs": {
        entries: [
          { seq: 1, ts: "2026-09-24T10:00:00Z", line: "丰图 server 启动" },
          { seq: 2, ts: "2026-09-24T10:00:01Z", line: "摄入失败: 坏包" },
          { seq: 3, ts: "2026-09-24T10:00:02Z", line: "warn 警告样例" },
        ],
        note: "进程内环形账",
      },
    });
    mount(<LogsPage />);
    await waitFor(() => expect(screen.getByText("丰图 server 启动")).toBeTruthy());
    expect(screen.getByTestId("log-stats").textContent).toContain("1 警告");
    expect(screen.getByTestId("log-stats").textContent).toContain("1 错误");
    fireEvent.click(screen.getByTestId("log-level-error"));
    expect(screen.queryByText("丰图 server 启动")).toBeNull();
    expect(screen.getByText("摄入失败: 坏包")).toBeTruthy();
  });
});

describe("SettingsPage", () => {
  const SETTINGS = {
    settings: { provider: "deepseek", protocol: "openai-compatible",
      base_url: "https://api.deepseek.com/v1", model: "deepseek-chat",
      key_source: "env", outbound_enabled: true, budget_tokens: 200000, max_tokens: 4096,
      rate_per_second: 0, record_mode: "metadata",
      agent_concurrency: 4, global_proxy: "", web_search_enabled: false,
      web_search_backend: "ddgs", search_key_set: false,
      intent_fanout_limit: 5, intent_chapter_limit: 30, intent_case_limit: 200 },
  };
  // 0.27.0 厂商预设表(后端常量表的测试投影)
  const PRESETS = {
    presets: [
      { id: "deepseek", name: "DeepSeek", protocol: "openai-compatible",
        base_url: "https://api.deepseek.com/v1", needs_key: true, note: "OpenAI 兼容;默认档" },
      { id: "moonshot", name: "Moonshot(Kimi)", protocol: "openai-compatible",
        base_url: "https://api.moonshot.cn/v1", needs_key: true, note: "Moonshot 兼容端点" },
      { id: "anthropic", name: "Anthropic(Claude)", protocol: "anthropic",
        base_url: "https://api.anthropic.com", needs_key: true, note: "Anthropic 原生线格式" },
      { id: "ollama", name: "Ollama(本地)", protocol: "ollama",
        base_url: "http://localhost:11434/v1", needs_key: false, note: "本地免 key" },
      { id: "custom", name: "自定义", protocol: "openai-compatible",
        base_url: "", needs_key: true, note: "自填 base_url" },
    ],
  };

  it("AI 设置搬入:呈现 + 保存 PUT(不带空 key)", async () => {
    mockApi({ "/api/ai/settings/presets": PRESETS, "/api/ai/settings": SETTINGS,
      "/api/health": { version: "0.14.0-artex-pages" } });
    const put = vi.spyOn(api, "put").mockResolvedValue({});
    mount(<SettingsPage />);
    await waitFor(() => expect(screen.getByTestId("ai-model")).toBeTruthy());
    expect((screen.getByTestId("ai-provider") as HTMLSelectElement).value).toBe("deepseek");
    expect((screen.getByTestId("ai-protocol") as HTMLSelectElement).value)
      .toBe("openai-compatible");
    expect(screen.getByTestId("settings-version").textContent).toContain("0.14.0-artex-pages");
    fireEvent.click(screen.getByTestId("ai-save"));
    await waitFor(() => expect(put).toHaveBeenCalled());
    const [, body] = put.mock.calls[0] as [string, Record<string, unknown>];
    expect(body.provider).toBe("deepseek");
    expect(body.protocol).toBe("openai-compatible");
    expect(body.api_key).toBeUndefined(); // 留空=不动已存 key
  });

  it("厂商预设联动:选 Moonshot 自动填 base_url/协议;协议非自定义不可改", async () => {
    mockApi({ "/api/ai/settings/presets": PRESETS, "/api/ai/settings": SETTINGS,
      "/api/health": {} });
    mount(<SettingsPage />);
    await waitFor(() => expect(screen.getByTestId("ai-provider")).toBeTruthy());
    expect((screen.getByTestId("ai-protocol") as HTMLSelectElement).disabled).toBe(true);
    fireEvent.change(screen.getByTestId("ai-provider"), { target: { value: "moonshot" } });
    await waitFor(() =>
      expect((screen.getByTestId("ai-base-url") as HTMLInputElement).value)
        .toBe("https://api.moonshot.cn/v1"));
    expect((screen.getByTestId("ai-protocol") as HTMLSelectElement).value)
      .toBe("openai-compatible");
    expect(screen.getByTestId("ai-preset-note").textContent).toContain("Moonshot");
  });

  it("拉取模型:成功出 datalist 可选;失败给原始错误;手输模型保存", async () => {
    mockApi({ "/api/ai/settings/presets": PRESETS, "/api/ai/settings": SETTINGS,
      "/api/health": {} });
    const post = vi.spyOn(api, "post").mockResolvedValue({
      ok: true, models: ["deepseek-chat", "deepseek-reasoner"],
      detail: "拉到 2 个模型", protocol: "openai-compatible" });
    const put = vi.spyOn(api, "put").mockResolvedValue({});
    mount(<SettingsPage />);
    await waitFor(() => expect(screen.getByTestId("ai-fetch-models")).toBeTruthy());
    fireEvent.click(screen.getByTestId("ai-fetch-models"));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/ai/settings/fetch-models", {
        base_url: "https://api.deepseek.com/v1", protocol: "openai-compatible" }));
    await waitFor(() =>
      expect(screen.getByTestId("ai-fetch-result").textContent).toContain("拉到 2 个模型"));
    // datalist 选项在场
    const list = screen.getByTestId("ai-model-list");
    expect(list.querySelectorAll("option").length).toBe(2);
    // 手输模型(不局限于拉到的清单)
    fireEvent.change(screen.getByTestId("ai-model"), { target: { value: "deepseek-reasoner" } });
    fireEvent.click(screen.getByTestId("ai-save"));
    await waitFor(() => expect(put).toHaveBeenCalled());
    const [, body] = put.mock.calls[0] as [string, Record<string, unknown>];
    expect(body.model).toBe("deepseek-reasoner");
  });

  it("拉取模型失败:原始错误如实呈现(不猜)", async () => {
    mockApi({ "/api/ai/settings/presets": PRESETS, "/api/ai/settings": SETTINGS,
      "/api/health": {} });
    vi.spyOn(api, "post").mockResolvedValue({
      ok: false, models: [], detail: "HTTP 401: Invalid API key",
      protocol: "openai-compatible" });
    mount(<SettingsPage />);
    await waitFor(() => expect(screen.getByTestId("ai-fetch-models")).toBeTruthy());
    fireEvent.click(screen.getByTestId("ai-fetch-models"));
    await waitFor(() =>
      expect(screen.getByTestId("ai-fetch-result").textContent)
        .toContain("拉取失败:HTTP 401: Invalid API key"));
    expect(screen.getByTestId("ai-model-list").querySelectorAll("option").length).toBe(0);
  });

  it("向后兼容:provider 对不上预设显示「自定义」,协议可手选", async () => {
    const legacy = { settings: { ...SETTINGS.settings, provider: "my-selfhost",
      protocol: "openai-compatible" } };
    mockApi({ "/api/ai/settings/presets": PRESETS, "/api/ai/settings": legacy,
      "/api/health": {} });
    mount(<SettingsPage />);
    await waitFor(() => expect(screen.getByTestId("ai-provider")).toBeTruthy());
    expect((screen.getByTestId("ai-provider") as HTMLSelectElement).value).toBe("custom");
    expect((screen.getByTestId("ai-protocol") as HTMLSelectElement).disabled).toBe(false);
    expect(screen.getByTestId("ai-preset-note").textContent).toContain("自定义");
  });

  it("Ollama 预设:免 key 提示在场", async () => {
    mockApi({ "/api/ai/settings/presets": PRESETS, "/api/ai/settings": SETTINGS,
      "/api/health": {} });
    mount(<SettingsPage />);
    await waitFor(() => expect(screen.getByTestId("ai-provider")).toBeTruthy());
    fireEvent.change(screen.getByTestId("ai-provider"), { target: { value: "ollama" } });
    await waitFor(() =>
      expect((screen.getByTestId("ai-base-url") as HTMLInputElement).value)
        .toBe("http://localhost:11434/v1"));
    expect(screen.getByTestId("ai-preset-note").textContent).toContain("免 API key");
    expect(screen.getByText(/本档免 key/)).toBeTruthy();
  });

  it("Agent 并发上限卡:呈现当前值 + 保存 PUT agent_concurrency", async () => {
    mockApi({ "/api/ai/settings": SETTINGS, "/api/health": {} });
    const put = vi.spyOn(api, "put").mockResolvedValue({});
    mount(<SettingsPage />);
    await waitFor(() => expect(screen.getByTestId("agent-concurrency")).toBeTruthy());
    expect((screen.getByTestId("agent-concurrency") as HTMLInputElement).value).toBe("4");
    fireEvent.change(screen.getByTestId("agent-concurrency"), { target: { value: "2" } });
    fireEvent.click(screen.getByTestId("agent-concurrency-save"));
    await waitFor(() =>
      expect(put).toHaveBeenCalledWith("/api/ai/settings", { agent_concurrency: 2 }));
  });

  it("意图链预算闸卡(0.24.0):回填三闸 + 保存 PUT 三项", async () => {
    mockApi({ "/api/ai/settings": SETTINGS, "/api/health": {} });
    const put = vi.spyOn(api, "put").mockResolvedValue({});
    mount(<SettingsPage />);
    await waitFor(() => expect(screen.getByTestId("intent-fanout")).toBeTruthy());
    expect((screen.getByTestId("intent-fanout") as HTMLInputElement).value).toBe("5");
    expect((screen.getByTestId("intent-chapter-limit") as HTMLInputElement).value).toBe("30");
    expect((screen.getByTestId("intent-case-limit") as HTMLInputElement).value).toBe("200");
    fireEvent.change(screen.getByTestId("intent-case-limit"), { target: { value: "150" } });
    fireEvent.click(screen.getByTestId("intent-limits-save"));
    await waitFor(() =>
      expect(put).toHaveBeenCalledWith("/api/ai/settings", {
        intent_fanout_limit: 5, intent_chapter_limit: 30, intent_case_limit: 150,
      }));
  });

  it("全局代理卡:保存 + 联通性自测回执如实呈现", async () => {
    mockApi({ "/api/ai/settings": SETTINGS, "/api/health": {} });
    const put = vi.spyOn(api, "put").mockResolvedValue({});
    const post = vi.spyOn(api, "post").mockResolvedValue({
      ok: false, detail: "connect: connection refused", target: "https://api.deepseek.com/v1",
    });
    mount(<SettingsPage />);
    await waitFor(() => expect(screen.getByTestId("global-proxy")).toBeTruthy());
    fireEvent.change(screen.getByTestId("global-proxy"),
      { target: { value: "http://127.0.0.1:7890" } });
    fireEvent.click(screen.getByTestId("global-proxy-save"));
    await waitFor(() =>
      expect(put).toHaveBeenCalledWith("/api/ai/settings",
        { global_proxy: "http://127.0.0.1:7890" }));
    // 自测:表单值直测;失败也是 200 + ok:false,如实呈现
    fireEvent.click(screen.getByTestId("global-proxy-test"));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/ai/settings/test-proxy",
        { global_proxy: "http://127.0.0.1:7890" }));
    await waitFor(() =>
      expect(screen.getByText(/自测失败.*connection refused/)).toBeTruthy());
  });

  it("联网搜索卡:开关/后端/key + 保存 + 自测;口径文案在场", async () => {
    const wsOn = { settings: { ...SETTINGS.settings,
      web_search_enabled: true, web_search_backend: "tavily", search_key_set: true } };
    mockApi({ "/api/ai/settings": wsOn, "/api/health": {} });
    const put = vi.spyOn(api, "put").mockResolvedValue({});
    const post = vi.spyOn(api, "post").mockResolvedValue({
      ok: true, detail: "返回 3 条结果", backend: "tavily" });
    mount(<SettingsPage />);
    await waitFor(() => expect(screen.getByTestId("web-search-enabled")).toBeTruthy());
    // 证据链口径写死在卡描述里
    expect(screen.getByText(/参考不是证据/)).toBeTruthy();
    // 带 key 后端:呈现 key 输入(已设置,不回显)
    expect((screen.getByTestId("web-search-backend") as HTMLSelectElement).value).toBe("tavily");
    fireEvent.change(screen.getByTestId("search-api-key"), { target: { value: "tvly-x" } });
    fireEvent.click(screen.getByTestId("web-search-save"));
    await waitFor(() =>
      expect(put).toHaveBeenCalledWith("/api/ai/settings", {
        web_search_enabled: true, web_search_backend: "tavily", search_api_key: "tvly-x" }));
    fireEvent.click(screen.getByTestId("web-search-test"));
    await waitFor(() =>
      expect(screen.getByText(/联通正常.*返回 3 条结果/)).toBeTruthy());
  });

  it("ddgs 后端免 key:不呈现 key 输入", async () => {
    mockApi({ "/api/ai/settings": SETTINGS, "/api/health": {} });
    mount(<SettingsPage />);
    await waitFor(() => expect(screen.getByTestId("web-search-backend")).toBeTruthy());
    expect(screen.queryByTestId("search-api-key")).toBeNull();
  });

  it("AI 未启用如实显示(不装)", async () => {
    vi.spyOn(api, "get").mockImplementation((p: string) => {
      if (p.startsWith("/api/ai/settings")) return Promise.reject(new Error("AI 未启用"));
      return Promise.resolve({ version: "x" });
    });
    mount(<SettingsPage />);
    await waitFor(() => expect(screen.getByTestId("ai-unavailable")).toBeTruthy());
    expect(screen.getAllByText("未启用").length).toBe(1); // 占位卡只剩自动更新
  });
});

describe("ApprovalsPage", () => {
  it("待处理区批准通路 + 历史投影", async () => {
    mockApi({
      "/api/approvals": {
        pending: [
          { id: "n1", case_id: "c1", case_name: "勒索案A", text: "批量扫描全部源",
            created_by: "ai", scope: "all", created_at: "2026-09-24T09:00:00Z" },
        ],
        history: [
          { seq: 9, ts: "2026-09-23T08:00:00Z", actor: "admin", action: "intent.reject",
            case_id: "c2", case_name: "入侵案B", text: "旧意图" },
        ],
      },
    });
    const post = vi.spyOn(api, "post").mockResolvedValue({});
    mount(<ApprovalsPage />);
    await waitFor(() => expect(screen.getByTestId("approval-pending-n1")).toBeTruthy());
    expect(screen.getByTestId("approvals-pending-badge").textContent).toContain("1");
    expect(screen.getByText("批量扫描全部源")).toBeTruthy();
    expect(screen.getByText("旧意图")).toBeTruthy(); // 历史区
    fireEvent.click(screen.getByTestId("approval-allow-n1"));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/intents/n1/approve", { approve: true }));
  });
});
