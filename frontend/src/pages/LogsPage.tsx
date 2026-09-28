// 日志页(切片十,照抄 ARTEX system/logs/page.tsx 终端式滚动区形态):
// 过滤输入 + 级别按钮组(按行文本关键词前端标色,后端不猜级别) +
// 暂停/继续 + 「加载更早」(before=seq 游标) + 自动吸底。
// 数据源:GET /api/logs(进程内环形账,5s 轮询;重启清零,如实标注)。
import { useCallback, useEffect, useRef, useState } from "react";
import { ScrollText } from "lucide-react";
import { api } from "../lib/api";
import type { LogEntry } from "../lib/types";

// levelOf 级别前端标色(行文本关键词;后端如实不解析,标错也只是颜色)。
function levelOf(line: string): "error" | "warn" | "info" {
  const l = line.toLowerCase();
  if (l.includes("error") || l.includes("失败") || l.includes("fatal")) return "error";
  if (l.includes("warn") || l.includes("警告") || l.includes("503")) return "warn";
  return "info";
}
const LEVEL_DOT = { info: "bg-slate-400", warn: "bg-amber-400", error: "bg-red-500" };
const LEVEL_TEXT = { info: "text-slate-600", warn: "text-amber-700", error: "text-red-600" };

export default function LogsPage() {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [note, setNote] = useState("");
  const [err, setErr] = useState("");
  const [filter, setFilter] = useState("");
  const [level, setLevel] = useState<"all" | "info" | "warn" | "error">("all");
  const [paused, setPaused] = useState(false);
  const boxRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    try {
      const d = await api.get<{ entries: LogEntry[]; note: string }>(
        "/api/logs?limit=500",
      );
      setEntries(d.entries || []);
      setNote(d.note || "");
      setErr("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void load();
    const t = setInterval(() => {
      if (!paused) void load();
    }, 5000);
    return () => clearInterval(t);
  }, [load, paused]);

  // 自动吸底(距底 <40px 视为贴底才跟随,照抄 ARTEX stick 语义)
  useEffect(() => {
    const el = boxRef.current;
    if (!el) return;
    if (el.scrollHeight - el.scrollTop - el.clientHeight < 40) {
      el.scrollTop = el.scrollHeight;
    }
  }, [entries]);

  const loadOlder = async () => {
    if (entries.length === 0) return;
    const minSeq = Math.min(...entries.map((e) => e.seq));
    try {
      const d = await api.get<{ entries: LogEntry[] }>(
        `/api/logs?limit=500&before=${minSeq}`,
      );
      if ((d.entries || []).length > 0) {
        setEntries((cur) => {
          const seen = new Set(cur.map((e) => e.seq));
          return [...d.entries.filter((e) => !seen.has(e.seq)), ...cur];
        });
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  const shown = entries.filter((e) => {
    if (level !== "all" && levelOf(e.line) !== level) return false;
    if (filter && !e.line.toLowerCase().includes(filter.trim().toLowerCase())) return false;
    return true;
  });
  const warnN = entries.filter((e) => levelOf(e.line) === "warn").length;
  const errN = entries.filter((e) => levelOf(e.line) === "error").length;

  return (
    <div className="max-w-[1400px] mx-auto space-y-4" data-testid="logs-page">
      <div>
        <h1 className="text-xl font-semibold tracking-tight flex items-center gap-2">
          <ScrollText className="w-5 h-5 text-mute" />
          日志
        </h1>
        <p className="text-sm text-mute">
          平台运行日志(进程内环形账;{note || "重启清零,持久日志在 systemd journal"})
        </p>
      </div>

      {/* 工具栏(照抄 ARTEX:过滤/级别组/暂停/统计) */}
      <div className="flex flex-wrap items-center gap-2">
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="过滤文本…"
          data-testid="log-filter"
          className="h-8 rounded-lg border border-slate-200 bg-white px-3 text-xs w-56
            focus:outline-none focus:ring-2 focus:ring-brand/40"
        />
        <div className="flex gap-0.5 rounded-md border border-slate-200 bg-slate-50 p-0.5">
          {(["all", "info", "warn", "error"] as const).map((lv) => (
            <button
              key={lv}
              onClick={() => setLevel(lv)}
              data-testid={`log-level-${lv}`}
              className={`rounded px-2.5 py-1 text-xs transition-colors ${
                level === lv
                  ? "bg-white text-ink shadow-sm"
                  : "text-mute hover:text-ink"
              }`}
            >
              {lv === "all" ? "全部" : lv}
            </button>
          ))}
        </div>
        <button
          onClick={() => setPaused((p) => !p)}
          data-testid="log-pause"
          className="rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-xs text-slate-600
            hover:bg-slate-50"
        >
          {paused ? "已暂停(点击继续)" : "暂停滚动"}
        </button>
        <span className="ml-auto text-[11px] text-mute" data-testid="log-stats">
          {shown.length} 行 · <span className="text-amber-600">{warnN} 警告</span> ·{" "}
          <span className="text-red-600">{errN} 错误</span>
        </span>
      </div>

      {err && (
        <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2">{err}</div>
      )}

      {/* 终端式滚动区(照抄 ARTEX:mono 字体 + 级别色点 + 时间戳) */}
      <div
        ref={boxRef}
        data-testid="log-stream"
        className="rounded-lg border border-slate-200 bg-white p-2 font-mono text-xs
          leading-relaxed h-[calc(100vh-16rem)] overflow-y-auto thin-scroll"
      >
        <button
          onClick={() => void loadOlder()}
          className="w-full text-center text-[11px] text-brand hover:underline py-1"
          data-testid="log-load-older"
        >
          加载更早日志
        </button>
        {shown.map((e) => {
          const lv = levelOf(e.line);
          return (
            <div key={e.seq} className="flex items-start gap-2 px-1 py-px">
              <span className={`mt-1.5 inline-block w-1.5 h-1.5 rounded-full shrink-0 ${LEVEL_DOT[lv]}`} />
              <span className="text-mute shrink-0 tabular-nums">
                {new Date(e.ts).toLocaleTimeString("zh-CN", { hour12: false })}
              </span>
              <span className={`whitespace-pre-wrap break-all ${LEVEL_TEXT[lv]}`}>{e.line}</span>
            </div>
          );
        })}
        {shown.length === 0 && (
          <div className="text-center text-sm text-mute py-10">
            暂无日志行(环形账只记当前进程输出)
          </div>
        )}
      </div>
    </div>
  );
}
