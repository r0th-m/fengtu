// 研判报告子页签(形态二,0.31.0-narrative-report):AI 生成初稿,定论归人。
// - 生成 opt-in:按钮明示消耗 token(默认预算 30000,可调走后端钳制),
//   window.confirm 二次确认;后端走 agentloop(LLM 录制/熔断/外发闸同纪律);
// - 版本递增保留历史:左侧版本清单(版本/时间/token/截断标),点击看内容;
// - 内容=后端拼好的成稿(报告头「AI 生成初稿,定论归人」+ LLM 原文),
//   markdown 可下载;
// - 闸态如实呈现:归档案 409 / 外发关 403 / AI 未配置 503 / LLM 零产出 502。
import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import type { CaseReportMeta } from "../lib/types";

export default function NarrativePanel({ caseId }: { caseId: string }) {
  const [reports, setReports] = useState<CaseReportMeta[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [content, setContent] = useState("");
  const [err, setErr] = useState("");
  const [loadingList, setLoadingList] = useState(true);
  const [loadingContent, setLoadingContent] = useState(false);
  const [generating, setGenerating] = useState(false);

  const loadList = useCallback(async () => {
    setLoadingList(true);
    try {
      const d = await api.get<{ reports: CaseReportMeta[] }>(
        `/api/cases/${caseId}/report/narrative`);
      setReports(d.reports || []);
      setErr("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setLoadingList(false);
    }
  }, [caseId]);

  useEffect(() => {
    void loadList();
  }, [loadList]);

  const view = async (version: number) => {
    setSelected(version);
    setContent("");
    setLoadingContent(true);
    setErr("");
    try {
      const d = await api.get<{ report: CaseReportMeta; content: string }>(
        `/api/cases/${caseId}/report/narrative/${version}`);
      setContent(d.content || "");
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setLoadingContent(false);
    }
  };

  const generate = async () => {
    // opt-in 二次确认:明示消耗 token(判断权归人,生成动作进审计)
    if (!window.confirm(
      "生成研判报告将调用 LLM,消耗 token(单次预算默认 30000,超了如实截断标注)。" +
      "生成的是 AI 初稿,定论归人。确认生成?")) return;
    setGenerating(true);
    setErr("");
    try {
      const d = await api.post<{ report: CaseReportMeta; content: string }>(
        `/api/cases/${caseId}/report/narrative`, {});
      await loadList();
      setSelected(d.report.version);
      setContent(d.content || "");
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setGenerating(false);
    }
  };

  const download = () => {
    if (selected == null || !content) return;
    const blob = new Blob([content], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `研判报告-v${selected}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const fmtTs = (s: string) =>
    new Date(s).toLocaleString("zh-CN", { hour12: false });

  return (
    <div className="space-y-4" data-testid="narrative-panel">
      <div className="rounded-card bg-white shadow-card p-4">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm font-medium text-ink">研判报告(AI 生成初稿)</span>
          <span className="rounded bg-amber-50 text-amber-700 px-1.5 py-0.5 text-[10px]">
            定论归人
          </span>
          <span className="flex-1" />
          {selected != null && content && (
            <button onClick={download}
              className="rounded-lg border border-slate-200 px-2.5 py-1 text-xs text-mute
                hover:text-brand hover:border-brand/40"
              data-testid="narrative-download">
              下载 v{selected} Markdown
            </button>
          )}
          <button onClick={() => void generate()} disabled={generating}
            className="rounded-lg bg-brand text-white px-2.5 py-1 text-xs hover:bg-brand-dark
              disabled:opacity-50"
            data-testid="narrative-generate">
            {generating ? "生成中(烧 token,约 1~3 分钟)…" : "生成研判报告(消耗 token)"}
          </button>
        </div>
        <div className="text-[11px] text-mute mt-2">
          LLM 按本案 grounding(目的章/带锚点结论/存疑方向/已确认发现/时间线/覆盖账)
          生成;所有结论须带锚点引用,无锚点的一律「推断/疑似」措辞——采信前逐条回查
          源原文。同案可多次生成,版本递增保留历史。
        </div>
      </div>

      {err && (
        <div className="rounded-card bg-white shadow-card p-4">
          <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2"
            data-testid="narrative-error">{err}</div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-[240px_1fr] gap-4">
        {/* 版本清单 */}
        <div className="rounded-card bg-white shadow-card p-3" data-testid="narrative-list">
          <div className="text-xs font-medium text-ink mb-2">历史版本({reports.length})</div>
          {loadingList ? (
            <div className="text-xs text-mute">加载中…</div>
          ) : reports.length === 0 ? (
            <div className="text-xs text-mute">
              还没有研判报告。点右上「生成研判报告」出第一版(消耗 token)。
            </div>
          ) : (
            <div className="space-y-1.5">
              {reports.map((r) => (
                <button key={r.id} onClick={() => void view(r.version)}
                  className={`w-full text-left rounded-lg border px-2.5 py-1.5 text-xs
                    transition-colors ${selected === r.version
                      ? "border-brand/40 bg-brand/5 text-ink"
                      : "border-slate-100 text-mute hover:border-brand/30"}`}
                  data-testid={`narrative-version-${r.version}`}>
                  <div className="flex items-center gap-1.5">
                    <span className="font-medium text-ink">v{r.version}</span>
                    {r.truncated && (
                      <span className="rounded bg-amber-50 text-amber-700 px-1 py-0 text-[10px]">
                        截断
                      </span>
                    )}
                  </div>
                  <div className="text-[10px] mt-0.5">{fmtTs(r.created_at)}</div>
                  <div className="text-[10px]">
                    {r.created_by} · token {r.tokens_in}/{r.tokens_out}
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* 内容区(markdown 原文等宽呈现;报告头含初稿声明) */}
        <div className="rounded-card bg-white shadow-card p-4" data-testid="narrative-content">
          {selected == null ? (
            <div className="text-xs text-mute">从左侧选一版查看,或生成新版本。</div>
          ) : loadingContent ? (
            <div className="text-xs text-mute">内容加载中…</div>
          ) : content ? (
            <pre className="text-xs text-slate-700 whitespace-pre-wrap break-all
              font-sans leading-relaxed">{content}</pre>
          ) : (
            <div className="text-xs text-mute">(内容为空,如实)</div>
          )}
        </div>
      </div>
    </div>
  );
}
