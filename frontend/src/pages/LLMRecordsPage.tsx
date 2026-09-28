// LLM 录制页(切片十,照抄 ARTEX function/llm-records/page.tsx 形态):
// 工具栏(会话搜索/案件筛选/每页条数/录制档位开关 + 分页器) +
// 录制清单表(时间/案件/会话/类型/模型/token/耗时/状态) +
// 行点选详情面板(full 档有 prompt/response 全文,元数据档如实标注)。
// 档位写 PUT /api/ai/settings {record_mode}(optimistic + 失败回滚,
// 照抄 ARTEX 开关语义);录制是台账不是证据,零 AI 调用由后端熔断保证。
import { useCallback, useEffect, useState } from "react";
import { ChevronLeft, ChevronRight, Radio, Search, X } from "lucide-react";
import { api } from "../lib/api";
import type { AISettings, CaseInfo, LLMRecord } from "../lib/types";

const MODE_LABEL: Record<string, { label: string; tip: string }> = {
  off: { label: "已关闭", tip: "不录制任何 LLM 调用" },
  metadata: {
    label: "元数据",
    tip: "默认档:只记时间/模型/token/耗时/会话+案件锚/成败,不录内容",
  },
  full: { label: "全文(opt-in)", tip: "追加录 prompt/response 全文(截断 8000 字符)" },
};
const KIND_LABEL: Record<string, string> = { chat: "沟通区", intent: "意图 worker" };

export default function LLMRecordsPage() {
  const [records, setRecords] = useState<LLMRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [cases, setCases] = useState<CaseInfo[]>([]);
  const [settings, setSettings] = useState<AISettings | null>(null);
  const [err, setErr] = useState("");
  const [sessionQ, setSessionQ] = useState("");
  const [caseFilter, setCaseFilter] = useState("");
  const [pageSize, setPageSize] = useState(25);
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<LLMRecord | null>(null);
  const [detailErr, setDetailErr] = useState("");

  const caseName = useCallback(
    (id: string) => cases.find((c) => c.id === id)?.name || (id ? id.slice(0, 8) : "—"),
    [cases],
  );

  const load = useCallback(async () => {
    try {
      const qs = new URLSearchParams();
      if (caseFilter) qs.set("case_id", caseFilter);
      qs.set("limit", String(pageSize));
      qs.set("offset", String(offset));
      const d = await api.get<{ records: LLMRecord[]; total: number }>(
        `/api/llm/records?${qs}`,
      );
      setRecords(d.records || []);
      setTotal(d.total);
      setErr("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, [caseFilter, pageSize, offset]);

  useEffect(() => {
    void load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [load]);

  useEffect(() => {
    api.get<{ cases: CaseInfo[] }>("/api/cases")
      .then((d) => setCases(d.cases || []))
      .catch(() => {});
    api.get<{ settings: AISettings }>("/api/ai/settings")
      .then((d) => setSettings(d.settings))
      .catch(() => setSettings(null)); // AI 未启用 503:如实,null=档位区显示不可用
  }, []);

  // 录制档位切换(optimistic + 失败回滚,照抄 ARTEX 开关语义)
  const setMode = async (mode: string) => {
    const prev = settings;
    if (!prev) return;
    setSettings({ ...prev, record_mode: mode });
    try {
      await api.put("/api/ai/settings", { record_mode: mode });
    } catch (e) {
      setSettings(prev);
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  const openDetail = async (r: LLMRecord) => {
    setDetailErr("");
    try {
      const d = await api.get<{ record: LLMRecord }>(`/api/llm/records/${r.id}`);
      setSelected(d.record);
    } catch (e) {
      setDetailErr(e instanceof Error ? e.message : String(e));
    }
  };

  const filtered = records.filter(
    (r) => !sessionQ || r.session_id.toLowerCase().includes(sessionQ.trim().toLowerCase()),
  );
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const page = Math.floor(offset / pageSize) + 1;

  return (
    <div className="max-w-[1400px] mx-auto space-y-4" data-testid="llm-records-page">
      <div className="flex items-center gap-2 flex-wrap">
        <h1 className="text-xl font-semibold tracking-tight flex items-center gap-2">
          <Radio className="w-5 h-5 text-mute" />
          LLM 录制
          <span className="rounded-md bg-slate-100 px-1.5 py-0.5 text-[11px] text-mute font-normal"
            data-testid="llm-records-total">
            {total}
          </span>
        </h1>
        <div className="flex-1" />
        {/* 录制档位(照抄 ARTEX 工具栏开关;三档,元数据默认) */}
        <div className="flex items-center gap-2 rounded-md border border-slate-200 px-2.5 py-1"
          data-testid="record-mode-switch">
          <span className="text-[11px] text-mute">录制</span>
          {settings ? (
            <select
              value={settings.record_mode}
              onChange={(e) => void setMode(e.target.value)}
              data-testid="record-mode-select"
              className="h-6 rounded border border-slate-200 bg-white px-1 text-xs text-slate-700"
              title={MODE_LABEL[settings.record_mode]?.tip}
            >
              {Object.entries(MODE_LABEL).map(([v, m]) => (
                <option key={v} value={v}>{m.label}</option>
              ))}
            </select>
          ) : (
            <span className="text-[11px] text-amber-600">AI 未启用,档位不可用(如实)</span>
          )}
        </div>
      </div>
      <p className="text-xs text-mute -mt-2">
        每次厂商调用一条账;{MODE_LABEL[settings?.record_mode ?? "metadata"]?.tip};
        录制是台账不是证据
      </p>

      {/* 工具栏(照抄 ARTEX:搜索/筛选/每页 + 分页器) */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-mute" />
          <input
            value={sessionQ}
            onChange={(e) => setSessionQ(e.target.value)}
            placeholder="会话 ID 过滤(本页内)…"
            data-testid="llm-session-filter"
            className="h-8 rounded-lg border border-slate-200 bg-white pl-8 pr-3 text-xs w-52
              focus:outline-none focus:ring-2 focus:ring-brand/40"
          />
        </div>
        <select
          value={caseFilter}
          onChange={(e) => {
            setCaseFilter(e.target.value);
            setOffset(0);
          }}
          data-testid="llm-case-filter"
          className="h-8 rounded-lg border border-slate-200 bg-white px-2 text-xs text-slate-600 max-w-56"
        >
          <option value="">全部案件</option>
          {cases.map((c) => (
            <option key={c.id} value={c.id}>{c.name}</option>
          ))}
        </select>
        <select
          value={pageSize}
          onChange={(e) => {
            setPageSize(Number(e.target.value));
            setOffset(0);
          }}
          className="h-8 rounded-lg border border-slate-200 bg-white px-2 text-xs text-slate-600"
        >
          {[25, 50, 100].map((n) => (
            <option key={n} value={n}>每页 {n}</option>
          ))}
        </select>
        <div className="ml-auto flex items-center gap-1 text-[11px] text-mute">
          <span className="tabular-nums" data-testid="llm-pager">
            {total === 0 ? "0" : `${offset + 1}–${Math.min(offset + pageSize, total)}`} / {total}
          </span>
          <button
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - pageSize))}
            className="rounded p-1 hover:bg-slate-100 disabled:opacity-30"
            aria-label="上一页"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <button
            disabled={offset + pageSize >= total}
            onClick={() => setOffset(offset + pageSize)}
            className="rounded p-1 hover:bg-slate-100 disabled:opacity-30"
            aria-label="下一页"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
          <span>{page} / {pages} 页</span>
        </div>
      </div>

      {err && (
        <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2">{err}</div>
      )}

      {/* 清单表(照抄 ARTEX:白卡容器 + sticky 表头 + 行点选) */}
      <div className="rounded-card bg-white shadow-card overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-100 text-left text-[11px] text-mute">
              <th className="font-medium px-4 py-2.5">时间</th>
              <th className="font-medium px-3 py-2.5">案件</th>
              <th className="font-medium px-3 py-2.5">会话</th>
              <th className="font-medium px-3 py-2.5">类型</th>
              <th className="font-medium px-3 py-2.5">模型</th>
              <th className="font-medium px-3 py-2.5 text-right">Token 入/出</th>
              <th className="font-medium px-3 py-2.5 text-right">耗时</th>
              <th className="font-medium px-4 py-2.5">状态</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((r) => (
              <tr
                key={r.id}
                onClick={() => void openDetail(r)}
                className={`border-b border-slate-50 last:border-0 cursor-pointer transition-colors
                  ${selected?.id === r.id ? "bg-brand-light/50" : "hover:bg-brand-light/30"}`}
                data-testid={`llm-record-${r.id}`}
              >
                <td className="px-4 py-2.5 text-xs text-mute whitespace-nowrap">
                  {new Date(r.created_at).toLocaleString("zh-CN", { hour12: false })}
                </td>
                <td className="px-3 py-2.5 text-xs whitespace-nowrap">{caseName(r.case_id)}</td>
                <td className="px-3 py-2.5 text-[11px] font-mono text-mute">
                  {r.session_id ? r.session_id.slice(0, 8) : "—"}
                </td>
                <td className="px-3 py-2.5">
                  <span className="rounded border border-slate-200 px-1.5 py-px text-[10px] text-slate-600 whitespace-nowrap">
                    {KIND_LABEL[r.kind] || r.kind}
                  </span>
                </td>
                <td className="px-3 py-2.5 text-xs font-mono">{r.model || "—"}</td>
                <td className="px-3 py-2.5 text-right text-xs tabular-nums">
                  {r.tokens_in} / {r.tokens_out}
                </td>
                <td className={`px-3 py-2.5 text-right text-xs tabular-nums ${r.duration_ms > 30000 ? "text-amber-600" : ""}`}>
                  {(r.duration_ms / 1000).toFixed(1)}s
                </td>
                <td className="px-4 py-2.5">
                  <span className={`rounded-full px-2 py-0.5 text-[11px] ring-1 ${
                    r.status === "ok"
                      ? "bg-emerald-50 text-emerald-700 ring-emerald-200"
                      : "bg-red-50 text-red-700 ring-red-200"
                  }`}>
                    {r.status === "ok" ? "OK" : "Error"}
                  </span>
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={8} className="px-4 py-10 text-center text-sm text-mute">
                  暂无录制记录——AI 会话跑起来后,每次厂商调用落一条账
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* 详情面板(照抄 ARTEX 下半详情卡:徽标头 + 左右 Request/Response) */}
      {detailErr && (
        <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2">{detailErr}</div>
      )}
      {selected && (
        <div className="rounded-card bg-white shadow-card" data-testid="llm-record-detail">
          <div className="flex items-center gap-2 flex-wrap border-b border-slate-100 px-4 py-2.5">
            <span className="rounded border border-slate-200 px-1.5 py-px text-[10px] font-mono text-slate-600">
              #{selected.id.slice(0, 8)}
            </span>
            <span className="rounded border border-slate-200 px-1.5 py-px text-[10px] text-slate-600">
              {KIND_LABEL[selected.kind] || selected.kind}
            </span>
            <span className="text-[11px] font-mono text-mute">{selected.model}</span>
            <span className="text-[11px] text-mute">
              {new Date(selected.created_at).toLocaleString("zh-CN", { hour12: false })} ·
              {" "}{(selected.duration_ms / 1000).toFixed(1)}s · token {selected.tokens_in}/{selected.tokens_out}
            </span>
            {selected.err && (
              <span className="text-[11px] text-red-600">{selected.err}</span>
            )}
            <button
              onClick={() => setSelected(null)}
              className="ml-auto rounded p-1 text-mute hover:bg-slate-100"
              aria-label="关闭详情"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          {selected.prompt != null || selected.response != null ? (
            <div className="grid md:grid-cols-2 md:divide-x divide-slate-100">
              <div className="p-4">
                <div className="text-[11px] font-medium text-mute mb-1.5">Request(messages JSON)</div>
                <pre className="font-mono text-xs whitespace-pre-wrap break-all max-h-72 overflow-y-auto thin-scroll">
                  {selected.prompt ?? ""}
                </pre>
              </div>
              <div className="p-4">
                <div className="text-[11px] font-medium text-mute mb-1.5">Response</div>
                <pre className="font-mono text-xs whitespace-pre-wrap break-all max-h-72 overflow-y-auto thin-scroll">
                  {selected.response ?? ""}
                </pre>
              </div>
            </div>
          ) : (
            <div className="px-4 py-6 text-center text-xs text-mute">
              元数据档录制:只有时间/模型/token/耗时/锚点,无 prompt/response 全文(如实;
              要全文到系统配置把 record_mode 切到「全文(opt-in)」后再跑的调用才有)
            </div>
          )}
        </div>
      )}
    </div>
  );
}
