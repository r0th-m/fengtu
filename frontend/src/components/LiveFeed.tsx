// 播报板(0.23.0-live-feed):案件页右栏、交流区上方的实时流水面板。
// 图的回答是结构,播报板的回答是时间流与介入时机:
//   - 诞生档(派生了新意图):行内 [停止][纠偏],复用现有 stop/steer 端点,
//     成功后行内状态即时标注(不跳图);
//   - 中间发现档(worker 过程流关键步):可展开全文 + 节点证据锚点(跳内容树);
//   - 终结档:supported/doubt/denied 一句话收尾 + 置信色;
//   - 审批事件:待审批带 [去审批](切审批 tab),批/驳结果也进流。
// 形态:可折叠(折叠状态记 localStorage);最新在底部,吸底不抢滚动
// (用户上翻时停吸);上限 500 条,超出丢最旧并如实标注;空态如实。
import { useEffect, useRef, useState } from "react";
import { ChevronDown, ChevronRight, ChevronUp } from "lucide-react";
import { api } from "../lib/api";
import {
  FEED_CAP,
  feedDotColor,
  FINISH_CLS,
  TIER_LABEL,
  type FeedItem,
} from "../lib/feed";
import { STATUS_LABEL, type GraphState } from "../lib/intent";
import { useActivityFeed } from "../lib/useActivityFeed";

const COLLAPSE_KEY = "fengtu.livefeed.collapsed";

export default function LiveFeed({
  caseId,
  graph,
  onAnchor,
  onApprovals,
}: {
  caseId: string;
  graph: GraphState;
  onAnchor: (sourceId: string, lineNo: number) => void;
  onApprovals: () => void;
}) {
  const { feed, connected } = useActivityFeed(caseId);
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem(COLLAPSE_KEY) === "1",
  );
  const [expanded, setExpanded] = useState<Record<number, boolean>>({});
  const [steerFor, setSteerFor] = useState<number | null>(null);
  const [steerText, setSteerText] = useState("");
  const [acting, setActing] = useState(false);
  // 就地介入行内状态(node_id → 标注;图 SSE 的 node_updated 到达后由图态接管)
  const [acted, setActed] = useState<Record<string, string>>({});
  const [actErr, setActErr] = useState("");
  const boxRef = useRef<HTMLDivElement>(null);
  const atBottomRef = useRef(true);

  const toggleCollapse = () => {
    setCollapsed((c) => {
      localStorage.setItem(COLLAPSE_KEY, c ? "0" : "1");
      return !c;
    });
  };

  // 吸底:用户滚动离开底部即停吸(不抢滚动),回底恢复
  const onScroll = () => {
    const el = boxRef.current;
    if (!el) return;
    atBottomRef.current =
      el.scrollHeight - el.scrollTop - el.clientHeight < 40;
  };
  useEffect(() => {
    const el = boxRef.current;
    if (el && atBottomRef.current) el.scrollTop = el.scrollHeight;
  }, [feed.items.length, collapsed]);

  const nodeOf = (it: FeedItem) =>
    it.node_id ? graph.nodes[it.node_id] : undefined;

  const stop = async (it: FeedItem) => {
    if (!it.node_id || acting) return;
    setActing(true);
    setActErr("");
    try {
      await api.post(`/api/intents/${it.node_id}/stop`);
      setActed((m) => ({ ...m, [it.node_id!]: "已停止" }));
    } catch (e) {
      setActErr(e instanceof Error ? e.message : String(e));
    } finally {
      setActing(false);
    }
  };

  const steer = async (it: FeedItem) => {
    const t = steerText.trim();
    if (!it.node_id || !t || acting) return;
    setActing(true);
    setActErr("");
    try {
      await api.post(`/api/intents/${it.node_id}/steer`, { text: t });
      setActed((m) => ({ ...m, [it.node_id!]: "已纠偏" }));
      setSteerFor(null);
      setSteerText("");
    } catch (e) {
      setActErr(e instanceof Error ? e.message : String(e));
    } finally {
      setActing(false);
    }
  };

  const items = feed.items;

  return (
    <section
      className="rounded-card bg-white shadow-card flex flex-col min-h-0"
      data-testid="live-feed"
    >
      <button
        onClick={toggleCollapse}
        className="flex items-center gap-2 px-3.5 py-2.5 border-b border-slate-100 text-left"
        data-testid="livefeed-toggle"
        title="播报板:意图引擎的实时流水(诞生/中间发现/终结/审批)"
      >
        <span className="text-sm font-medium">播报板</span>
        <span
          className={`inline-block w-1.5 h-1.5 rounded-full ${connected ? "bg-brand" : "bg-amber-400"}`}
          title={connected ? "SSE 实时在流" : "SSE 未在流(轮询兜底中)"}
          data-testid="livefeed-conn"
        />
        <span className="text-[11px] text-mute">
          {items.length > 0 ? `${items.length} 条` : "实时流水"}
        </span>
        <span className="flex-1" />
        {collapsed ? (
          <ChevronDown className="w-4 h-4 text-mute" />
        ) : (
          <ChevronUp className="w-4 h-4 text-mute" />
        )}
      </button>

      {!collapsed && (
        <>
          <div
            ref={boxRef}
            onScroll={onScroll}
            className="overflow-auto thin-scroll px-3.5 py-2 space-y-1.5 max-h-[300px]"
            data-testid="livefeed-body"
          >
            {items.length === 0 && (
              <div className="text-xs text-mute leading-relaxed py-2" data-testid="livefeed-empty">
                等待意图引擎产出(意图诞生/中间发现/终结/审批事件会实时出现在这里)
              </div>
            )}
            {items.map((it, idx) => {
              const node = nodeOf(it);
              const note = it.node_id ? acted[it.node_id] : undefined;
              return (
                <div key={it.seq} className="text-[11px] leading-relaxed" data-testid={`feed-item-${it.seq}`}>
                  <div className="flex items-start gap-1.5">
                    <span
                      className={`mt-1 inline-block w-1.5 h-1.5 rounded-full shrink-0 ${feedDotColor(it.node_id)}`}
                      title={it.node_id ? `意图 ${it.node_id.slice(0, 8)}…` : "案件级"}
                    />
                    <span className="text-slate-400 shrink-0 font-mono">
                      {it.ts
                        ? new Date(it.ts).toLocaleTimeString("zh-CN", { hour12: false })
                        : "--:--:--"}
                    </span>
                    <span className="rounded bg-slate-100 text-slate-500 px-1 shrink-0 text-[10px]">
                      {TIER_LABEL[it.tier] || it.tier}
                    </span>
                    {it.tier === "finish" && it.status && (
                      <span
                        className={`rounded px-1 shrink-0 text-[10px] ${FINISH_CLS[it.status] || "bg-slate-100 text-slate-500"}`}
                        data-testid={`feed-status-${it.seq}`}
                      >
                        {STATUS_LABEL[it.status] || it.status}
                      </span>
                    )}
                    <span className="text-slate-700 break-all min-w-0">{it.text}</span>
                    {it.detail && (
                      <button
                        className="shrink-0 text-mute hover:text-ink"
                        title={expanded[idx] ? "收起" : "展开全文与锚点"}
                        data-testid={`feed-expand-${it.seq}`}
                        onClick={() =>
                          setExpanded((m) => ({ ...m, [idx]: !m[idx] }))
                        }
                      >
                        {expanded[idx] ? (
                          <ChevronUp className="w-3.5 h-3.5" />
                        ) : (
                          <ChevronRight className="w-3.5 h-3.5" />
                        )}
                      </button>
                    )}
                  </div>

                  {/* 就地介入:诞生档行内停止/纠偏(复用现有端点,不跳图) */}
                  {it.tier === "spawn" && node && (
                    <div className="ml-7 mt-0.5 flex items-center gap-1.5 flex-wrap">
                      {note ? (
                        <span className="rounded bg-slate-100 text-slate-500 px-1.5 py-0.5 text-[10px]"
                          data-testid={`feed-acted-${it.seq}`}>
                          {note}
                        </span>
                      ) : (
                        <>
                          {(node.status === "open" || node.status === "running") && (
                            <button
                              disabled={acting}
                              onClick={() => void stop(it)}
                              className="rounded border border-red-200 text-red-600 px-1.5 py-0.5 text-[10px]
                                hover:bg-red-50 disabled:opacity-50"
                              data-testid={`feed-stop-${it.seq}`}
                            >
                              停止
                            </button>
                          )}
                          {node.status === "running" && (
                            <button
                              disabled={acting}
                              onClick={() => {
                                setSteerFor(steerFor === idx ? null : idx);
                                setSteerText("");
                              }}
                              className="rounded border border-violet-200 text-violet-600 px-1.5 py-0.5 text-[10px]
                                hover:bg-violet-50 disabled:opacity-50"
                              data-testid={`feed-steer-${it.seq}`}
                            >
                              纠偏
                            </button>
                          )}
                          {(node.status === "open" || node.status === "running") && (
                            <span className="text-[10px] text-slate-400">
                              {STATUS_LABEL[node.status] || node.status}
                            </span>
                          )}
                        </>
                      )}
                    </div>
                  )}
                  {steerFor === idx && (
                    <div className="ml-7 mt-1 flex gap-1.5">
                      <input
                        value={steerText}
                        onChange={(e) => setSteerText(e.target.value)}
                        onKeyDown={(e) => e.key === "Enter" && void steer(it)}
                        placeholder="纠偏:调整在跑意图的方向…"
                        className="flex-1 rounded border border-slate-200 px-1.5 py-0.5 text-[11px]"
                        data-testid={`feed-steer-input-${it.seq}`}
                      />
                      <button
                        disabled={acting || !steerText.trim()}
                        onClick={() => void steer(it)}
                        className="rounded bg-violet-600 text-white px-2 py-0.5 text-[10px]
                          hover:bg-violet-700 disabled:opacity-50"
                        data-testid={`feed-steer-send-${it.seq}`}
                      >
                        发送
                      </button>
                    </div>
                  )}

                  {/* 审批事件:待审批带 [去审批](切审批 tab) */}
                  {it.tier === "approval" &&
                    it.status === "awaiting_approval" &&
                    node?.status === "awaiting_approval" && (
                      <div className="ml-7 mt-0.5">
                        <button
                          onClick={onApprovals}
                          className="rounded bg-red-600 text-white px-1.5 py-0.5 text-[10px] hover:bg-red-700"
                          data-testid={`feed-goto-approval-${it.seq}`}
                        >
                          去审批
                        </button>
                      </div>
                    )}

                  {/* 中间发现展开:全文 + 节点证据锚点(跳内容树) */}
                  {expanded[idx] && it.detail && (
                    <div className="ml-7 mt-1 rounded bg-paper border border-slate-100 px-2 py-1.5"
                      data-testid={`feed-detail-${it.seq}`}>
                      <div className="whitespace-pre-wrap break-all text-slate-600">
                        {it.detail}
                      </div>
                      {(node?.evidence || []).length > 0 && (
                        <div className="mt-1 flex flex-wrap gap-1">
                          {(node?.evidence || []).map((a, i) => (
                            <button
                              key={i}
                              onClick={() => a.source_id && onAnchor(a.source_id, a.line_no || 1)}
                              className="rounded bg-brand-light/60 text-brand font-mono text-[10px]
                                px-1.5 py-0.5 hover:bg-brand-light"
                              data-testid={`feed-anchor-${it.seq}-${i}`}
                            >
                              ⚓ {a.source_id ? `${a.source_id.slice(0, 8)}…:${a.line_no ?? "-"}` : a.hit_id || "(无锚)"}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
          <div className="px-3.5 pb-2 flex items-center gap-2 flex-wrap">
            {feed.dropped > 0 && (
              <span className="text-[10px] text-amber-600" data-testid="livefeed-dropped">
                已达上限 {FEED_CAP} 条,丢弃最旧 {feed.dropped} 条(完整过程流见节点详情)
              </span>
            )}
            {actErr && (
              <span className="text-[10px] text-red-600" data-testid="livefeed-acterr">
                {actErr}
              </span>
            )}
          </div>
        </>
      )}
    </section>
  );
}
