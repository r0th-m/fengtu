// 仪表盘(切片十,照抄 ARTEX dashboard/page.tsx 形态,应急语义映射):
// Row1 统计卡(案件/数据源/候选命中/待裁决/待审批) + Row2 双卡
// (近 7 天活动柱 + 案件状态分布) + Row3 待批意图列表卡。
// 数据:GET /api/stats/overview(纯读聚合,10s 轮询);渗透专属的
// 资产/流量/Token 卡不带(丰图无对应语义,不装)。
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Bug,
  ClipboardList,
  Database,
  FolderOpen,
  LayoutDashboard,
  ShieldAlert,
} from "lucide-react";
import { api } from "../lib/api";
import type { CaseStatusBuckets, OverviewStats } from "../lib/types";

interface OverviewResp {
  stats: OverviewStats;
  case_status: CaseStatusBuckets;
  activity_note: string;
}

function StatCard({
  icon: Icon,
  label,
  value,
  sub,
  tone = "text-ink",
}: {
  icon: typeof Bug;
  label: string;
  value: number | string;
  sub?: string;
  tone?: string;
}) {
  return (
    <div className="rounded-card bg-white shadow-card p-4">
      <div className="flex items-center gap-1.5 text-[10px] text-mute">
        <Icon className="w-3 h-3" />
        {label}
      </div>
      <div className={`mt-1 text-2xl font-semibold tabular-nums ${tone}`}>{value}</div>
      {sub && <div className="mt-0.5 text-[10px] text-mute">{sub}</div>}
    </div>
  );
}

const STATUS_LABEL: [keyof CaseStatusBuckets, string, string][] = [
  ["pending", "待复核", "bg-amber-400"],
  ["reviewed", "已复核", "bg-brand"],
  ["ingested", "已摄入", "bg-slate-300"],
  ["empty", "空案件", "bg-slate-200"],
];

export default function DashboardPage() {
  const [data, setData] = useState<OverviewResp | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    let stop = false;
    async function load() {
      try {
        const d = await api.get<OverviewResp>("/api/stats/overview");
        if (!stop) {
          setData(d);
          setErr("");
        }
      } catch (e) {
        if (!stop) setErr(e instanceof Error ? e.message : String(e));
      }
    }
    void load();
    const t = setInterval(load, 10000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  }, []);

  const s = data?.stats;
  const maxDay = Math.max(1, ...(s?.activity ?? []).map((d) => d.count));
  const bucketTotal =
    (data?.case_status.pending ?? 0) +
      (data?.case_status.reviewed ?? 0) +
      (data?.case_status.ingested ?? 0) +
      (data?.case_status.empty ?? 0) || 1;

  return (
    <div className="max-w-[1200px] mx-auto space-y-4" data-testid="dashboard-page">
      <div>
        <h1 className="text-lg font-semibold tracking-tight flex items-center gap-2">
          <LayoutDashboard className="w-4.5 h-4.5 text-mute" />
          总览
        </h1>
        <p className="text-xs text-mute">案件全局状态 · 10s 轮询</p>
      </div>
      {err && (
        <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2">{err}</div>
      )}

      {/* Row 1:统计卡(照抄 ARTEX 5 卡行;数字 tabular-nums) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        <StatCard icon={FolderOpen} label="案件" value={s?.cases ?? "…"} sub="应急案件总数" />
        <StatCard icon={Database} label="数据源" value={s?.sources ?? "…"} sub="已登记源(金库原件)" />
        <StatCard
          icon={Bug}
          label="候选命中"
          value={s?.candidates ?? "…"}
          sub="命中≠结论(机器候选)"
        />
        <StatCard
          icon={ShieldAlert}
          label="待裁决"
          value={s?.pending_candidates ?? "…"}
          sub="需人工接受/排除"
          tone={s && s.pending_candidates > 0 ? "text-amber-600" : "text-ink"}
        />
        <StatCard
          icon={ClipboardList}
          label="待审批"
          value={s?.pending_approvals ?? "…"}
          sub="批量执行意图挂起中"
          tone={s && s.pending_approvals > 0 ? "text-red-600" : "text-ink"}
        />
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        {/* 近 7 天活动(自绘横条,审计链日条数;ARTEX 用 recharts,
            丰图不引图表库——条形 div 同语义) */}
        <div className="rounded-card bg-white shadow-card p-4">
          <div className="text-sm font-medium text-ink mb-1">近 7 天活动</div>
          <div className="text-[10px] text-mute mb-3">
            {data?.activity_note ?? "审计链日条数(UTC 日界)"}
          </div>
          {(s?.activity ?? []).length === 0 ? (
            <div className="text-xs text-mute py-6 text-center">近 7 天无平台活动</div>
          ) : (
            <div className="space-y-1.5" data-testid="activity-bars">
              {s!.activity.map((d) => (
                <div key={d.day} className="flex items-center gap-2 text-xs">
                  <span className="w-20 shrink-0 text-mute font-mono text-[10px]">{d.day}</span>
                  <div className="flex-1 h-3.5 rounded bg-slate-100 overflow-hidden">
                    <div
                      className="h-full bg-brand/70 rounded"
                      style={{ width: `${Math.max(4, (d.count / maxDay) * 100)}%` }}
                    />
                  </div>
                  <span className="w-8 text-right tabular-nums text-mute">{d.count}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* 案件状态分布(口径与工作台一致) */}
        <div className="rounded-card bg-white shadow-card p-4">
          <div className="text-sm font-medium text-ink mb-1">案件状态分布</div>
          <div className="text-[10px] text-mute mb-3">
            待复核=有待裁决候选;已复核=候选全部裁决;已摄入=有源无候选
          </div>
          <div className="h-3.5 rounded-full overflow-hidden flex bg-slate-100 mb-3"
            data-testid="case-status-bar">
            {STATUS_LABEL.map(([k, , cls]) =>
              (data?.case_status[k] ?? 0) > 0 ? (
                <div
                  key={k}
                  className={cls}
                  style={{ width: `${(((data?.case_status[k] ?? 0) / bucketTotal) * 100).toFixed(1)}%` }}
                />
              ) : null,
            )}
          </div>
          <div className="grid grid-cols-2 gap-1.5">
            {STATUS_LABEL.map(([k, label, cls]) => (
              <div key={k} className="flex items-center gap-1.5 text-xs">
                <span className={`inline-block w-2 h-2 rounded-sm ${cls}`} />
                <span className="text-slate-600">{label}</span>
                <span className="ml-auto tabular-nums text-mute">
                  {data?.case_status[k] ?? 0}
                </span>
              </div>
            ))}
          </div>
          <div className="mt-3 pt-3 border-t border-slate-100 flex items-center gap-3 text-[11px]">
            <Link to="/function/tasks" className="text-brand hover:underline">
              全部任务 →
            </Link>
            <Link to="/system/approvals" className="text-brand hover:underline">
              审批记录 →
            </Link>
            <span className="ml-auto text-mute">
              LLM 录制账 {s?.llm_records ?? 0} 条
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
