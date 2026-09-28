// 报告 tab(0.30.0-report-ux 可读性重构;0.31.0 起双子页签):
//   - 「结构化报告」(形态一,默认):模板化骨架不走 LLM——一、结论先行
//     (案子/时间窗/核心判断清单) 二、攻击时间线 三、分章排查结论 四、已确认
//     发现 五、裁决概况 六、证据覆盖 七、处置建议 八、证据附录;md 可下载。
//   - 「研判报告」(形态二,NarrativePanel):LLM 生成初稿,opt-in 烧 token,
//     版本递增保留历史;AI 生成初稿,定论归人。
// 纪律:发现=人工裁决 accepted;目标/结论=机器评估,收官定论归人——
// 本页不新下任何结论,全站禁「确认(动词)」措辞。
import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { STATUS_LABEL, type GraphState } from "../lib/intent";
import { incidentTypeById } from "../lib/taskWizard";
import type {
  ReportData,
  ReportFact,
  ReportFinding,
} from "../lib/types";
import { GradeBadge } from "./GradeBadge";
import LineageGraph from "./LineageGraph";
import NarrativePanel from "./NarrativePanel";

const GOAL_STATUS_CHIP: Record<string, string> = {
  open: "bg-slate-100 text-slate-500",
  running: "bg-blue-100 text-blue-700",
  supported: "bg-green-100 text-green-700",
  denied: "bg-slate-100 text-slate-400",
  doubt: "bg-amber-100 text-amber-700",
  closed_exhausted: "bg-stone-100 text-stone-500",
  closed: "bg-slate-100 text-slate-400",
  awaiting_approval: "bg-red-100 text-red-700",
  // 0.29.1 goal 收官机器评估态(met 绿 / partial 琥珀 / unmet 灰)
  closed_goal_met: "bg-green-100 text-green-700",
  closed_goal_partial: "bg-amber-100 text-amber-700",
  closed_goal_unmet: "bg-slate-100 text-slate-400",
};

function goalChip(status: string): string {
  return GOAL_STATUS_CHIP[status] || "bg-slate-100 text-slate-500";
}

function FindingRow({
  f, onAnchor,
}: {
  f: ReportFinding;
  onAnchor: (sourceId: string, lineNo: number) => void;
}) {
  return (
    <div className="rounded-lg border border-slate-100 p-3" data-testid={`report-finding-${f.id}`}>
      <div className="flex items-center gap-2 flex-wrap">
        <GradeBadge grade={f.evidence_grade} />
        <span className="text-xs font-medium text-ink">{f.rule_id}</span>
        <span className="text-[10px] text-mute">[{f.severity}]</span>
        {f.ts_utc && (
          <span className="text-[10px] text-mute">
            {new Date(f.ts_utc).toLocaleString("zh-CN", { hour12: false })}(UTC 事件时间)
          </span>
        )}
        <span className="flex-1" />
        <span className="text-[10px] text-mute">裁决人 {f.reviewed_by || "未知"}</span>
      </div>
      {f.snippet && (
        <div className="mt-1 text-xs text-slate-700 font-mono break-all">{f.snippet}</div>
      )}
      <button
        onClick={() => onAnchor(f.source_id, f.line_no)}
        className="mt-1.5 inline-block rounded bg-slate-100 px-1.5 py-0.5 text-[10px] text-mute
          hover:text-brand hover:bg-brand/10 transition-colors"
        data-testid={`report-anchor-${f.id}`}
        title={`SHA256 ${f.source_sha256}`}
      >
        {f.host ? `${f.host} · ` : ""}
        {f.source_path}:{f.line_no} · sha256:{f.source_sha256.slice(0, 12)}…
      </button>
    </div>
  );
}

// FactCard 结论卡(分章与未挂章节共用;血缘子图展开复用 8c 布局引擎)。
function FactCard({
  f, graph, lineageFor, setLineageFor, onAnchor, onJumpNode,
}: {
  f: ReportFact;
  graph: GraphState;
  lineageFor: string | null;
  setLineageFor: (id: string | null) => void;
  onAnchor: (sourceId: string, lineNo: number) => void;
  onJumpNode: (nodeId: string) => void;
}) {
  return (
    <div className="rounded-lg border border-slate-100 p-3">
      <div className="flex items-start gap-2">
        <span className="text-xs text-ink leading-relaxed flex-1">{f.text}</span>
        <button
          onClick={() => setLineageFor(lineageFor === f.id ? null : f.id)}
          className="shrink-0 rounded-lg border border-slate-200 px-2 py-0.5 text-[11px]
            text-mute hover:text-brand hover:border-brand/40"
          data-testid={`report-lineage-${f.id}`}
        >
          {lineageFor === f.id ? "收起血缘" : "血缘"}
        </button>
      </div>
      {f.evidence.length > 0 && (
        <div className="mt-1.5 flex flex-wrap gap-1.5">
          {f.evidence.map((a, i) =>
            a.source_id ? (
              <button key={i}
                onClick={() => onAnchor(a.source_id!, a.line_no || 1)}
                className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] text-mute
                  hover:text-brand hover:bg-brand/10"
                title={`SHA256 ${a.source_sha256 || ""}`}>
                {a.host ? `${a.host} · ` : ""}
                {a.source_path}:{a.line_no}
              </button>
            ) : (
              <span key={i} className="rounded bg-slate-50 px-1.5 py-0.5 text-[10px] text-mute">
                {a.hit_id ? `候选 ${a.hit_id}` : a.note || "锚点"}
              </span>
            ))}
        </div>
      )}
      {lineageFor === f.id && (
        <div className="mt-2">
          <LineageGraph graph={graph} nodeId={f.id} onJump={onJumpNode} />
        </div>
      )}
    </div>
  );
}

export default function ReportTab({
  caseId,
  graph,
  onAnchor,
  onJumpNode,
}: {
  caseId: string;
  graph: GraphState; // 血缘子图数据(案件页活态图)
  onAnchor: (sourceId: string, lineNo: number) => void;
  onJumpNode: (nodeId: string) => void;
}) {
  const [data, setData] = useState<ReportData | null>(null);
  const [markdown, setMarkdown] = useState("");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);
  const [lineageFor, setLineageFor] = useState<string | null>(null);
  const [sub, setSub] = useState<"structured" | "narrative">("structured");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const d = await api.get<{ report: ReportData; markdown: string }>(
        `/api/cases/${caseId}/report`);
      setData(d.report);
      setMarkdown(d.markdown || "");
      setErr("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  useEffect(() => {
    void load();
  }, [load]);

  const download = () => {
    const blob = new Blob([markdown], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `丰图报告-${data?.case_name || caseId}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // 双子页签(0.31.0):结构化报告(模板化,不走 LLM)/ 研判报告(AI 初稿,
  // opt-in 烧 token;NarrativePanel 选中才挂载,不选中不发请求)。
  const tabBar = (
    <div className="flex gap-1 rounded-card bg-white shadow-card p-1.5 w-fit"
      data-testid="report-subtabs">
      <button onClick={() => setSub("structured")}
        className={`rounded-lg px-3 py-1 text-xs transition-colors ${sub === "structured"
          ? "bg-brand text-white" : "text-mute hover:text-brand"}`}
        data-testid="report-subtab-structured">
        结构化报告
      </button>
      <button onClick={() => setSub("narrative")}
        className={`rounded-lg px-3 py-1 text-xs transition-colors ${sub === "narrative"
          ? "bg-brand text-white" : "text-mute hover:text-brand"}`}
        data-testid="report-subtab-narrative">
        研判报告(AI 初稿)
      </button>
    </div>
  );
  if (sub === "narrative") {
    return (
      <div className="space-y-4" data-testid="report-tab">
        {tabBar}
        <NarrativePanel caseId={caseId} />
      </div>
    );
  }

  if (err) {
    return (
      <div className="space-y-4" data-testid="report-tab">
        {tabBar}
        <div className="rounded-card bg-white shadow-card p-4">
          <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2">{err}</div>
        </div>
      </div>
    );
  }
  if (!data) {
    return (
      <div className="space-y-4" data-testid="report-tab">
        {tabBar}
        <div className="rounded-card bg-white shadow-card p-4 text-xs text-mute">
          {loading ? "报告生成中…" : "加载中…"}
        </div>
      </div>
    );
  }
  const typeLabel = incidentTypeById(data.incident_type)?.label || data.incident_type || "未设置";
  const fmtTs = (s: string) =>
    new Date(s).toLocaleString("zh-CN", { hour12: false });

  return (
    <div className="space-y-4" data-testid="report-tab">
      {tabBar}
      <div className="rounded-card bg-white shadow-card p-4">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm font-medium text-ink">应急响应报告:{data.case_name}</span>
          <span className="rounded bg-brand/10 text-brand px-1.5 py-0.5 text-[10px]">
            {typeLabel}
          </span>
          <span className="flex-1" />
          <button onClick={() => void load()}
            className="rounded-lg border border-slate-200 px-2.5 py-1 text-xs text-mute
              hover:text-brand hover:border-brand/40">
            刷新
          </button>
          <button onClick={download}
            className="rounded-lg bg-brand text-white px-2.5 py-1 text-xs hover:bg-brand-dark"
            data-testid="report-download">
            下载 Markdown
          </button>
        </div>
        <div className="text-[11px] text-mute mt-2">
          生成时间 {fmtTs(data.generated_at)}
          (UTC 口径)· 模板化生成不走 LLM:发现以人工裁决为准,目标/结论为机器评估,
          最终定论与收官归人。
        </div>
        {data.background && (
          <div className="mt-2 rounded-lg bg-[#FAFAF8] border border-slate-100 p-2.5
            text-xs text-slate-700 whitespace-pre-wrap">{data.background}</div>
        )}
      </div>

      {/* 一、结论先行 */}
      <div className="rounded-card bg-white shadow-card p-4" data-testid="report-tldr">
        <div className="text-sm font-medium text-ink mb-2">一、结论先行</div>
        <div className="text-xs text-slate-700 space-y-2">
          <div>
            <span className="text-mute">案子是什么:</span>
            {typeLabel};
            {data.hosts.length > 0
              ? `主机 ${data.hosts.length} 台(${data.hosts.join("、")})`
              : "主机未建模(散件源,如实)"};
            证据源 {data.sources_total} 份(已被排查触及 {data.sources_explored});
            已确认发现 {data.hits_accepted} 条(人工裁决),待裁决候选 {data.hits_pending} 条。
          </div>
          <div data-testid="report-window">
            <span className="text-mute">时间窗:</span>
            {data.window_from && data.window_to
              ? `${fmtTs(data.window_from)} ~ ${fmtTs(data.window_to)}(UTC;从结论/发现锚点的事件时间聚合)`
              : "从锚点可解析出事件时间的条目为零,时间窗缺失(如实)"}
          </div>
          <div>
            <div className="text-mute mb-1">核心判断(机器评估,收官定论归人):</div>
            {!data.intent_ready ? (
              <div className="text-mute">意图引擎未装配,目标/结论账缺失(如实)</div>
            ) : data.chapters.length === 0 ? (
              <div className="text-mute">未播种子目标,无章节可归纳(如实)</div>
            ) : (
              <div className="space-y-1.5">
                {data.chapters.map((ch) => (
                  <div key={ch.goal_id} className="flex items-center gap-2"
                    data-testid={`report-judgment-${ch.goal_id}`}>
                    <span className={`rounded px-1.5 py-0.5 text-[10px] shrink-0 ${goalChip(ch.status)}`}>
                      {STATUS_LABEL[ch.status] || ch.status}
                    </span>
                    <button onClick={() => onJumpNode(ch.goal_id)}
                      className="text-ink hover:text-brand text-left">{ch.goal_text}</button>
                    <span className="text-[10px] text-mute shrink-0">
                      {ch.intents_total > 0
                        ? `章内意图 supported ${ch.intents_supported}/${ch.intents_total}`
                        : "未派发意图(如实)"}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 二、攻击时间线 */}
      <div className="rounded-card bg-white shadow-card p-4" data-testid="report-timeline">
        <div className="text-sm font-medium text-ink mb-1">
          二、攻击时间线(按事件时间升序 · {data.timeline_total} 条)
        </div>
        <div className="text-[11px] text-mute mb-2">
          仅收锚点可解析出事件时间的发现/结论;锚点可跳内容树回查原文。
        </div>
        {data.timeline.length === 0 ? (
          <div className="text-xs text-mute">
            无从锚点解析出事件时间的条目——时间线如实为空
          </div>
        ) : (
          <div className="space-y-1.5">
            {data.timeline.map((it, i) => (
              <div key={i} className="flex items-start gap-2 text-xs"
                data-testid={`report-timeline-${i}`}>
                <span className="text-mute font-mono shrink-0">{fmtTs(it.ts_utc)}</span>
                <span className={`shrink-0 rounded px-1 py-0 text-[10px] ${
                  it.kind === "finding"
                    ? "bg-red-50 text-red-700" : "bg-blue-50 text-blue-700"}`}>
                  {it.kind === "finding" ? "发现" : "结论"}
                </span>
                <span className="text-slate-700 flex-1 break-all">{it.text}</span>
                <button
                  onClick={() => onAnchor(it.source_id, it.line_no)}
                  className="shrink-0 rounded bg-slate-100 px-1.5 py-0.5 text-[10px] text-mute
                    hover:text-brand hover:bg-brand/10"
                  title={`SHA256 ${it.source_sha256}`}>
                  {it.host ? `${it.host} · ` : ""}{it.source_path}:{it.line_no}
                </button>
              </div>
            ))}
          </div>
        )}
        {data.timeline_truncated && (
          <div className="text-[11px] text-amber-700 mt-2">
            时间线条目超 50 条,报告截断(如实;完整事件回待审区/检索页按时间过滤)。
          </div>
        )}
      </div>

      {/* 三、分章排查结论 */}
      <div className="rounded-card bg-white shadow-card p-4" data-testid="report-chapters">
        <div className="text-sm font-medium text-ink mb-1">
          三、分章排查结论(证据支持的事实,按目的章节分组;机器评估)
        </div>
        <div className="text-[11px] text-mute mb-2">「血缘」回溯该结论的证明链(起点→结论)。</div>
        {!data.intent_ready ? (
          <div className="text-xs text-mute">意图引擎未装配,本节缺失(如实)</div>
        ) : data.chapters.length === 0 && data.orphan_facts.length === 0 ? (
          <div className="text-xs text-mute">无 goal 章节且无结论(如实)</div>
        ) : (
          <div className="space-y-3">
            {data.chapters.map((ch) => (
              <div key={ch.goal_id} className="rounded-xl ring-1 ring-slate-100 p-3"
                data-testid={`report-chapter-${ch.goal_id}`}>
                <div className="flex items-center gap-2 flex-wrap mb-2">
                  <span className={`rounded px-1.5 py-0.5 text-[10px] ${goalChip(ch.status)}`}>
                    {STATUS_LABEL[ch.status] || ch.status}
                  </span>
                  <button onClick={() => onJumpNode(ch.goal_id)}
                    className="text-xs font-medium text-ink hover:text-brand text-left">
                    {ch.goal_text}
                  </button>
                  <span className="text-[10px] text-mute">
                    {ch.intents_total > 0
                      ? `章内意图 supported ${ch.intents_supported}/${ch.intents_total}`
                      : "未派发意图(如实)"}
                  </span>
                </div>
                {ch.facts.length === 0 ? (
                  <div className="text-xs text-mute">本章无证据支持的结论(如实)</div>
                ) : (
                  <div className="space-y-2">
                    {ch.facts.map((f) => (
                      <FactCard key={f.id} f={f} graph={graph}
                        lineageFor={lineageFor} setLineageFor={setLineageFor}
                        onAnchor={onAnchor} onJumpNode={onJumpNode} />
                    ))}
                  </div>
                )}
              </div>
            ))}
            {data.orphan_facts.length > 0 && (
              <div className="rounded-xl ring-1 ring-slate-100 p-3" data-testid="report-orphans">
                <div className="text-xs font-medium text-mute mb-2">
                  未挂章节的结论(归属不上任何 goal,如实单列)
                </div>
                <div className="space-y-2">
                  {data.orphan_facts.map((f) => (
                    <FactCard key={f.id} f={f} graph={graph}
                      lineageFor={lineageFor} setLineageFor={setLineageFor}
                      onAnchor={onAnchor} onJumpNode={onJumpNode} />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* 四、已确认发现 */}
      <div className="rounded-card bg-white shadow-card p-4">
        <div className="text-sm font-medium text-ink mb-1">
          四、已确认发现(人工裁决 accepted · {data.hits_accepted} 条)
        </div>
        <div className="text-[11px] text-mute mb-2">
          待裁决候选不进报告;每条锚点=主机+源+行+SHA256,点击跳内容树回查原文。
        </div>
        {data.findings.length === 0 ? (
          <div className="text-xs text-mute">无已确认发现</div>
        ) : (
          <div className="space-y-2">
            {data.findings.map((f) => (
              <FindingRow key={f.id} f={f} onAnchor={onAnchor} />
            ))}
          </div>
        )}
        {data.findings_truncated && (
          <div className="text-[11px] text-amber-700 mt-2">
            已确认发现超 500 条,报告截断(完整清单见候选发现页,如实)。
          </div>
        )}
      </div>

      {/* 五、候选与裁决概况 */}
      <div className="rounded-card bg-white shadow-card p-4">
        <div className="text-sm font-medium text-ink mb-2">五、候选与裁决概况</div>
        <div className="text-xs text-slate-700">
          待裁决 {data.hits_pending} · 已确认 {data.hits_accepted} · 已排除 {data.hits_rejected}
        </div>
      </div>

      {/* 六、证据覆盖 */}
      <div className="rounded-card bg-white shadow-card p-4">
        <div className="text-sm font-medium text-ink mb-2">六、证据覆盖</div>
        {data.intent_ready ? (
          <div className="text-xs text-slate-700">
            源总数 {data.sources_total} · 已被排查触及 {data.sources_explored} ·
            覆盖缺口 {data.sources_total - data.sources_explored}(如实)
          </div>
        ) : (
          <div className="text-xs text-mute">意图引擎未装配,覆盖账缺失(如实)</div>
        )}
      </div>

      {/* 七、处置建议 */}
      <div className="rounded-card bg-white shadow-card p-4">
        <div className="text-sm font-medium text-ink mb-1">七、处置建议</div>
        <div className="text-[11px] text-mute mb-2">模板建议(按应急类型),需人核。</div>
        <ul className="list-disc pl-5 space-y-1 text-xs text-slate-700">
          {data.advice.map((a, i) => (
            <li key={i}>{a}</li>
          ))}
        </ul>
      </div>

      {/* 八、证据附录 */}
      <div className="rounded-card bg-white shadow-card p-4" data-testid="report-evidence">
        <div className="text-sm font-medium text-ink mb-1">
          八、证据附录(锚点去重清单 · {data.evidence.length} 条)
        </div>
        <div className="text-[11px] text-mute mb-2">
          锚点四件=主机+源+行+SHA256;「被引」=发现+结论引用次数。
        </div>
        {data.evidence.length === 0 ? (
          <div className="text-xs text-mute">无源锚点可附(如实)</div>
        ) : (
          <div className="space-y-1">
            {data.evidence.map((e, i) => (
              <div key={i} className="flex items-center gap-2 text-xs"
                data-testid={`report-evidence-${i}`}>
                <button
                  onClick={() => onAnchor(e.source_id, e.line_no)}
                  className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] text-mute
                    hover:text-brand hover:bg-brand/10 font-mono"
                  title={`SHA256 ${e.source_sha256}`}>
                  {e.host ? `${e.host} · ` : ""}
                  {e.source_path}:{e.line_no} · sha256:{e.source_sha256.slice(0, 12)}…
                </button>
                <span className="text-[10px] text-mute">被引 {e.refs} 次</span>
              </div>
            ))}
          </div>
        )}
        {data.evidence_truncated && (
          <div className="text-[11px] text-amber-700 mt-2">附录锚点超 200 条,截断(如实)。</div>
        )}
      </div>
    </div>
  );
}
