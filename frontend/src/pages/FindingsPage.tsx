// 发现页(切片十,照抄 ARTEX function/findings/page.tsx 形态,应急语义):
// 跨案件候选发现汇总——统计卡行 + 筛选栏(搜索/状态/严重度/案件) + 表格。
// 数据:/api/cases + 逐案 /api/cases/{id}/hits(每案取最新 200 条,如实标注;
// 全局聚合端点没有,客户端归并,案件量小适用)。命中≠结论,裁决在案件页
// 候选发现 tab(判断权归人;本页只读 + 跳案)。
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Bug, Info, Search, ShieldAlert, TriangleAlert } from "lucide-react";
import { api } from "../lib/api";
import type { CaseInfo, Hit } from "../lib/types";

const PER_CASE_LIMIT = 200; // 每案取最新 200 条(头部注释同口径,如实)

const SEV_TONE: Record<string, string> = {
  high: "bg-red-50 text-red-700 ring-red-200",
  medium: "bg-amber-50 text-amber-700 ring-amber-200",
  low: "bg-slate-50 text-slate-600 ring-slate-200",
  info: "bg-slate-50 text-slate-500 ring-slate-200",
};
const STATUS_LABEL: Record<string, { label: string; cls: string }> = {
  pending: { label: "待裁决", cls: "bg-amber-50 text-amber-700 ring-amber-200" },
  accepted: { label: "已接受", cls: "bg-brand-light text-brand ring-brand/20" },
  rejected: { label: "已排除", cls: "bg-slate-100 text-slate-500 ring-slate-200" },
};
const GRADE_LABEL: Record<string, string> = {
  strong: "强疑似", suspect: "疑似", weak: "弱信号",
};

interface HitWithCase extends Hit {
  case_name: string;
}

export default function FindingsPage() {
  const [cases, setCases] = useState<CaseInfo[]>([]);
  const [hits, setHits] = useState<HitWithCase[]>([]);
  const [truncatedCases, setTruncatedCases] = useState(0);
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [caseFilter, setCaseFilter] = useState("all");

  useEffect(() => {
    let stop = false;
    async function load() {
      try {
        const d = await api.get<{ cases: CaseInfo[] }>("/api/cases");
        const cs = d.cases || [];
        // 只拉有候选的案(候选数=0 的案跳过,省 N+1)
        const withHits = cs.filter((c) => (c.candidates ?? 0) > 0);
        const perCase = await Promise.all(
          withHits.map(async (c) => {
            const r = await api.get<{ hits: Hit[] }>(
              `/api/cases/${c.id}/hits?limit=${PER_CASE_LIMIT}`,
            );
            return { name: c.name, hits: r.hits || [], total: c.candidates ?? 0 };
          }),
        );
        if (stop) return;
        const merged: HitWithCase[] = [];
        let trunc = 0;
        for (const pc of perCase) {
          if (pc.total > pc.hits.length) trunc++;
          for (const h of pc.hits) merged.push({ ...h, case_name: pc.name });
        }
        merged.sort((a, b) => b.created_at.localeCompare(a.created_at));
        setCases(cs);
        setHits(merged);
        setTruncatedCases(trunc);
        setErr("");
      } catch (e) {
        if (!stop) setErr(e instanceof Error ? e.message : String(e));
      } finally {
        if (!stop) setLoading(false);
      }
    }
    void load();
    const t = setInterval(load, 15000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return hits.filter((h) => {
      if (status !== "all" && h.status !== status) return false;
      if (severity !== "all" && h.severity !== severity) return false;
      if (caseFilter !== "all" && h.case_id !== caseFilter) return false;
      if (!q) return true;
      return (
        h.rule_id.toLowerCase().includes(q) ||
        h.snippet.toLowerCase().includes(q) ||
        h.matched_value.toLowerCase().includes(q) ||
        h.case_name.toLowerCase().includes(q)
      );
    });
  }, [hits, query, status, severity, caseFilter]);

  const pendingN = hits.filter((h) => h.status === "pending").length;
  const sevN = (sev: string) => hits.filter((h) => h.severity === sev).length;

  return (
    <div className="max-w-[1400px] mx-auto space-y-4" data-testid="findings-page">
      <div>
        <h1 className="text-xl font-semibold tracking-tight flex items-center gap-2">
          <Bug className="w-5 h-5 text-mute" />
          发现
          <span className="rounded-md bg-slate-100 px-1.5 py-0.5 text-[11px] text-mute font-normal">
            {hits.length}
          </span>
        </h1>
        <p className="text-sm text-mute">
          跨案件候选汇总(每案取最新 {PER_CASE_LIMIT} 条;
          命中≠结论,裁决在案件页「候选发现」tab)
        </p>
      </div>

      {/* 统计卡(照抄 ARTEX findings 6 卡行,应急口径 4 卡) */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { icon: Bug, label: "候选总数", v: hits.length, tone: "text-ink" },
          { icon: ShieldAlert, label: "待裁决", v: pendingN, tone: pendingN > 0 ? "text-amber-600" : "text-ink" },
          { icon: TriangleAlert, label: "高危", v: sevN("high"), tone: sevN("high") > 0 ? "text-red-600" : "text-ink" },
          { icon: Info, label: "中危", v: sevN("medium"), tone: "text-ink" },
        ].map((c) => (
          <div key={c.label} className="rounded-card bg-white shadow-card p-4">
            <div className="flex items-center gap-1.5 text-[10px] text-mute">
              <c.icon className="w-3 h-3" />
              {c.label}
            </div>
            <div className={`mt-1 text-2xl font-semibold tabular-nums ${c.tone}`}>{c.v}</div>
          </div>
        ))}
      </div>

      {/* 筛选栏(照抄 ARTEX:flex-wrap 工具栏 + 图标搜索框) */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-mute" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="搜索规则 / 摘要 / 命中值 / 案件…"
            data-testid="finding-search"
            className="h-8 rounded-lg border border-slate-200 bg-white pl-8 pr-3 text-xs w-64
              focus:outline-none focus:ring-2 focus:ring-brand/40"
          />
        </div>
        <select value={status} onChange={(e) => setStatus(e.target.value)}
          data-testid="finding-status-filter"
          className="h-8 rounded-lg border border-slate-200 bg-white px-2 text-xs text-slate-600">
          <option value="all">全部状态</option>
          <option value="pending">待裁决</option>
          <option value="accepted">已接受</option>
          <option value="rejected">已排除</option>
        </select>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}
          data-testid="finding-severity-filter"
          className="h-8 rounded-lg border border-slate-200 bg-white px-2 text-xs text-slate-600">
          <option value="all">全部严重度</option>
          <option value="high">高危</option>
          <option value="medium">中危</option>
          <option value="low">低危</option>
          <option value="info">信息</option>
        </select>
        <select value={caseFilter} onChange={(e) => setCaseFilter(e.target.value)}
          data-testid="finding-case-filter"
          className="h-8 rounded-lg border border-slate-200 bg-white px-2 text-xs text-slate-600 max-w-56">
          <option value="all">全部案件</option>
          {cases.map((c) => (
            <option key={c.id} value={c.id}>{c.name}</option>
          ))}
        </select>
        <span className="text-[11px] text-mute ml-auto">
          {filtered.length} / {hits.length} 条
          {truncatedCases > 0 && ` · ${truncatedCases} 案候选超 ${PER_CASE_LIMIT} 条只取最新(如实)`}
        </span>
      </div>

      {err && (
        <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2">{err}</div>
      )}

      {/* 表格(照抄工作台/ARTEX Table 形态) */}
      <div className="rounded-card bg-white shadow-card overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-100 text-left text-[11px] text-mute">
              <th className="font-medium px-4 py-2.5">严重度</th>
              <th className="font-medium px-3 py-2.5">规则 / 摘要</th>
              <th className="font-medium px-3 py-2.5">案件</th>
              <th className="font-medium px-3 py-2.5">证据级</th>
              <th className="font-medium px-3 py-2.5">状态</th>
              <th className="font-medium px-4 py-2.5">时间</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((h) => (
              <tr key={h.id}
                className="border-b border-slate-50 last:border-0 hover:bg-brand-light/30 transition-colors"
                data-testid={`finding-row-${h.id}`}>
                <td className="px-4 py-2.5">
                  <span className={`rounded-full px-2 py-0.5 text-[11px] ring-1 whitespace-nowrap ${SEV_TONE[h.severity] || SEV_TONE.info}`}>
                    {h.severity}
                  </span>
                </td>
                <td className="px-3 py-2.5 max-w-[420px]">
                  <div className="text-xs font-mono text-ink truncate">{h.rule_id}</div>
                  <div className="text-[11px] text-mute truncate" title={h.snippet}>
                    {h.snippet || h.matched_value || "—"}
                  </div>
                </td>
                <td className="px-3 py-2.5">
                  <Link to={`/cases/${h.case_id}`}
                    className="text-xs text-brand hover:underline whitespace-nowrap">
                    {h.case_name}
                  </Link>
                </td>
                <td className="px-3 py-2.5 text-[11px] text-mute whitespace-nowrap">
                  {GRADE_LABEL[h.evidence_grade] || h.evidence_grade || "—"}
                </td>
                <td className="px-3 py-2.5">
                  <span className={`rounded-full px-2 py-0.5 text-[11px] ring-1 whitespace-nowrap ${(STATUS_LABEL[h.status] || STATUS_LABEL.pending).cls}`}>
                    {(STATUS_LABEL[h.status] || { label: h.status }).label}
                  </span>
                </td>
                <td className="px-4 py-2.5 text-xs text-mute whitespace-nowrap">
                  {new Date(h.created_at).toLocaleString("zh-CN", { hour12: false })}
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-10 text-center text-sm text-mute">
                  {loading ? "加载中…" : hits.length === 0
                    ? "暂无候选发现——扫描/分析产出候选后在此汇总"
                    : "无匹配候选(调整筛选)"}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
