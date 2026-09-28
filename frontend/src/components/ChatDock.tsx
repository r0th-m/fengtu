// 聊天 dock(案件页右栏常驻):案件级 AI 对话,POST SSE 流式渲染;
// AI 答案中的锚点(source_id+行号)解析成可点 chip 跳内容树;
// 输入框上方一行小字:「AI 产出均为疑似候选,判断权归人」。
// AI 未启用/外发关时如实呈现后端 503/403 原文,不装死。
import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import { extractAnchors } from "../lib/anchors";
import { postSse } from "../lib/sse";
import type { AISession, SourceInfo } from "../lib/types";

interface Msg {
  role: "user" | "ai";
  text: string;
  pending?: boolean;
  note?: string; // tool 事件等过程帧摘要(零黑盒)
}

export default function ChatDock({
  caseId,
  sources,
  onAnchor,
}: {
  caseId: string;
  sources: SourceInfo[];
  onAnchor: (sourceId: string, lineNo: number) => void;
}) {
  const [sessionId, setSessionId] = useState("");
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [avail, setAvail] = useState<"unknown" | "ok" | "off">("unknown");
  const [availNote, setAvailNote] = useState("");
  const boxRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  // 会话:取最近一个,没有就建(会话绑案件;AI 未配置如实 503);
  // 取到既有会话后回放历史(GET /api/ai/sessions/{id}.messages,
  // 后端从 transcript 真账重建)——刷新不丢消息。
  useEffect(() => {
    let stop = false;
    (async () => {
      try {
        const d = await api.get<{ sessions: AISession[] }>(`/api/cases/${caseId}/ai/sessions`);
        if (stop) return;
        if (d.sessions.length > 0) {
          const sid = d.sessions[d.sessions.length - 1].id;
          setSessionId(sid);
          try {
            const h = await api.get<{ messages?: { role: string; text: string }[] }>(
              `/api/ai/sessions/${sid}`,
            );
            if (stop) return;
            const hist = (h.messages || []).filter(
              (m) => (m.role === "user" || m.role === "ai") && m.text,
            );
            if (hist.length > 0) {
              setMsgs(hist.map((m) => ({ role: m.role as "user" | "ai", text: m.text })));
            }
          } catch {
            /* 历史回放失败不挡聊天(如实:仅本轮无历史,发送仍可用) */
          }
        } else {
          const c = await api.post<{ session: AISession }>("/api/ai/sessions", { case_id: caseId });
          if (!stop) setSessionId(c.session.id);
        }
        setAvail("ok");
      } catch (e) {
        if (stop) return;
        setAvail("off");
        setAvailNote(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      stop = true;
    };
  }, [caseId]);

  useEffect(() => {
    boxRef.current?.scrollTo({ top: boxRef.current.scrollHeight });
  }, [msgs]);

  const sourceIds = sources.map((s) => s.id);

  const send = useCallback(async () => {
    const content = input.trim();
    if (!content || !sessionId || busy) return;
    setInput("");
    setBusy(true);
    setMsgs((m) => [...m, { role: "user", text: content }, { role: "ai", text: "", pending: true }]);
    const abort = new AbortController();
    abortRef.current = abort;
    try {
      await postSse(
        `/api/ai/sessions/${sessionId}/messages`,
        { content },
        (f) => {
          if (f.event === "text") {
            try {
              const d = JSON.parse(f.data);
              const delta = d.text ?? d.delta ?? "";
              if (delta) {
                setMsgs((m) => {
                  const n = [...m];
                  const last = n[n.length - 1];
                  n[n.length - 1] = { ...last, text: last.text + delta };
                  return n;
                });
              }
            } catch {
              /* 坏帧跳过 */
            }
          } else if (f.event === "tool_use" || f.event === "tool_result") {
            // 过程帧摘要(零黑盒转圈:AI 在干什么可见)
            let note = f.event === "tool_use" ? "调用工具" : "工具返回";
            try {
              const d = JSON.parse(f.data);
              note = d.name ? `工具: ${d.name}` : note;
            } catch {
              /* 保留默认 */
            }
            setMsgs((m) => {
              const n = [...m];
              n[n.length - 1] = { ...n[n.length - 1], note };
              return n;
            });
          } else if (f.event === "error") {
            setMsgs((m) => {
              const n = [...m];
              n[n.length - 1] = { ...n[n.length - 1], text: n[n.length - 1].text + `\n[错误] ${f.data}` };
              return n;
            });
          }
        },
        abort.signal,
      );
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setMsgs((m) => {
        const n = [...m];
        n[n.length - 1] = { ...n[n.length - 1], text: n[n.length - 1].text || `[请求失败] ${msg}` };
        return n;
      });
    } finally {
      setMsgs((m) => {
        const n = [...m];
        if (n.length > 0) n[n.length - 1] = { ...n[n.length - 1], pending: false, note: undefined };
        return n;
      });
      setBusy(false);
      abortRef.current = null;
    }
  }, [input, sessionId, busy]);

  return (
    // 高度由父容器(右栏 sticky 列,播报板在上)分配:flex-1 撑满剩余。
    <div className="rounded-card bg-white shadow-card flex flex-col flex-1 min-h-0">
      <div className="px-3.5 py-2.5 border-b border-slate-100 flex items-center gap-2">
        <span className="text-sm font-medium">交流区</span>
        <span className="text-[11px] text-mute">案件级 AI 对话</span>
        <div className="flex-1" />
        {busy && (
          <button
            onClick={() => abortRef.current?.abort()}
            className="text-[11px] rounded border border-slate-200 px-2 py-0.5 text-mute hover:text-red-600"
          >
            中断
          </button>
        )}
      </div>

      <div ref={boxRef} className="flex-1 overflow-auto thin-scroll px-3.5 py-3 space-y-3">
        {avail === "off" && (
          <div className="rounded-lg bg-amber-50 text-amber-700 text-xs px-3 py-2 leading-relaxed">
            AI 不可用(如实):{availNote}
          </div>
        )}
        {avail === "ok" && msgs.length === 0 && (
          <div className="text-xs text-mute leading-relaxed px-1">
            问案情、让它按锚点排查——它的一切发现只是疑似候选,锚点可点跳原文核对。
          </div>
        )}
        {msgs.map((m, i) => (
          <div key={i} className={m.role === "user" ? "text-right" : ""}>
            <div
              className={`inline-block max-w-[95%] rounded-xl px-3 py-2 text-xs leading-relaxed text-left
                whitespace-pre-wrap break-words ${
                  m.role === "user"
                    ? "bg-brand text-white"
                    : "bg-paper border border-slate-100 text-ink"
                }`}
            >
              {m.text || (m.pending ? "…" : "")}
              {m.pending && (
                <span className="block mt-1 text-[10px] text-mute">
                  {m.note || "思考中"}
                  <span className="animate-pulse"> ▍</span>
                </span>
              )}
            </div>
            {m.role === "ai" && !m.pending && m.text && (
              <AnchorChips text={m.text} sourceIds={sourceIds} sources={sources} onAnchor={onAnchor} />
            )}
          </div>
        ))}
      </div>

      <div className="border-t border-slate-100 px-3.5 pt-1.5 pb-3">
        <div className="text-[10px] text-slate-400 mb-1.5">
          AI 产出均为疑似候选,判断权归人
        </div>
        <div className="flex gap-2">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                void send();
              }
            }}
            rows={2}
            disabled={avail !== "ok"}
            placeholder={avail === "ok" ? "输入问题,Enter 发送(Shift+Enter 换行)" : "AI 未启用"}
            className="flex-1 rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs resize-none
              focus:outline-none focus:ring-2 focus:ring-brand/40 disabled:bg-slate-50"
          />
          <button
            onClick={() => void send()}
            disabled={busy || !input.trim() || avail !== "ok"}
            className="self-end rounded-lg bg-brand text-white text-xs font-medium px-4 py-2
              hover:bg-brand-dark transition-colors disabled:opacity-40"
          >
            发送
          </button>
        </div>
      </div>
    </div>
  );
}

// AnchorChips AI 答案里的锚点(source_id+行号)chip 行。
function AnchorChips({
  text,
  sourceIds,
  sources,
  onAnchor,
}: {
  text: string;
  sourceIds: string[];
  sources: SourceInfo[];
  onAnchor: (sourceId: string, lineNo: number) => void;
}) {
  const anchors = extractAnchors(text, sourceIds);
  if (anchors.length === 0) return null;
  const pathOf = (id: string) => sources.find((s) => s.id === id)?.path ?? id;
  return (
    <div className="mt-1 flex flex-wrap gap-1">
      {anchors.map((a) => (
        <button
          key={`${a.sourceId}:${a.lineNo}`}
          onClick={() => onAnchor(a.sourceId, a.lineNo)}
          className="inline-flex items-center gap-1 rounded bg-brand-light/60 text-brand
            text-[10px] font-mono px-1.5 py-0.5 hover:bg-brand-light transition-colors"
          title={`${pathOf(a.sourceId)}:${a.lineNo}`}
        >
          ⚓ {pathOf(a.sourceId).split("/").pop()}:{a.lineNo}
        </button>
      ))}
    </div>
  );
}
