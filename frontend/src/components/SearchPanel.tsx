// 检索面板(切片 8b,用户点名补回:「以前树庭和索图都可以按不同维度搜索」):
// 全文词 + 字段条件构造器(eq/contains)+ 时间窗(全期/近1h/近24h/自定义)+
// 源多选。走既有 GET /api/query,零新 API;响应时间客户端计时如实展示;
// 结果带锚点跳内容树;无时区源/字段缺失族如实标注。
import { useCallback, useMemo, useState } from "react";
import { api } from "../lib/api";
import type { QueryEvent, SourceInfo } from "../lib/types";

interface Cond {
  field: string;
  op: "eq" | "contains";
  value: string;
}

const FIELD_PRESETS = ["src_ip", "method", "path", "status", "ua"];

type TimeMode = "all" | "1h" | "24h" | "custom";

const PAGE = 200;

export default function SearchPanel({
  caseId,
  sources,
  onAnchor,
}: {
  caseId: string;
  sources: SourceInfo[];
  onAnchor: (sourceId: string, lineNo: number) => void;
}) {
  const [q, setQ] = useState("");
  const [conds, setConds] = useState<Cond[]>([]);
  const [timeMode, setTimeMode] = useState<TimeMode>("all");
  const [customFrom, setCustomFrom] = useState("");
  const [customTo, setCustomTo] = useState("");
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [srcOpen, setSrcOpen] = useState(false);
  const [events, setEvents] = useState<QueryEvent[] | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);
  const [offset, setOffset] = useState(0);
  const [expand, setExpand] = useState<number | null>(null);

  const srcName = useMemo(() => {
    const m = new Map<string, string>();
    for (const s of sources) m.set(s.id, s.path);
    return m;
  }, [sources]);

  const windowRFC = useCallback((): [string, string] => {
    const now = new Date();
    if (timeMode === "1h") return [new Date(now.getTime() - 3600e3).toISOString(), now.toISOString()];
    if (timeMode === "24h")
      return [new Date(now.getTime() - 24 * 3600e3).toISOString(), now.toISOString()];
    if (timeMode === "custom") {
      const f = customFrom ? new Date(customFrom).toISOString() : "";
      const t = customTo ? new Date(customTo).toISOString() : "";
      return [f, t];
    }
    return ["", ""];
  }, [timeMode, customFrom, customTo]);

  const run = useCallback(
    async (off: number) => {
      setLoading(true);
      setErr("");
      const t0 = performance.now();
      try {
        const p = new URLSearchParams();
        p.set("case_id", caseId);
        if (q.trim()) p.set("q", q.trim());
        for (const c of conds) {
          if (c.field.trim() && c.value.trim()) {
            p.append("cond", `${c.field.trim()}:${c.op}:${c.value.trim()}`);
          }
        }
        const [f, t] = windowRFC();
        if (f) p.set("ts_from", f);
        if (t) p.set("ts_to", t);
        for (const id of picked) p.append("source_id", id); // 重复参数=源多选
        p.set("limit", String(PAGE));
        p.set("offset", String(off));
        const d = await api.get<{ events: QueryEvent[] }>(`/api/query?${p.toString()}`);
        setEvents(d.events || []);
        setOffset(off);
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e));
        setEvents(null);
      } finally {
        setElapsed(Math.round(performance.now() - t0));
        setLoading(false);
      }
    },
    [caseId, q, conds, windowRFC, picked],
  );

  const toggleSrc = (id: string) => {
    setPicked((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  };

  return (
    <div className="rounded-card bg-white shadow-card p-4" data-testid="search-panel">
      {/* 条件区 */}
      <div className="space-y-2.5">
        <div className="flex items-center gap-2">
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && void run(0)}
            placeholder="全文词(raw 子串,大小写不敏感;留空=只按条件/时间窗)"
            className="flex-1 rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
            data-testid="search-q"
          />
          <button
            onClick={() => void run(0)}
            disabled={loading}
            className="rounded-lg bg-brand text-white px-4 py-1.5 text-sm hover:bg-brand-dark disabled:opacity-50"
            data-testid="search-run"
          >
            {loading ? "检索中…" : "检索"}
          </button>
        </div>

        {/* 字段条件构造器 */}
        <div className="space-y-1.5">
          {conds.map((c, i) => (
            <div key={i} className="flex items-center gap-1.5" data-testid={`cond-${i}`}>
              <input
                list="field-presets"
                value={c.field}
                onChange={(e) =>
                  setConds((cs) => cs.map((x, j) => (j === i ? { ...x, field: e.target.value } : x)))
                }
                placeholder="字段"
                className="w-32 rounded-lg border border-slate-200 px-2 py-1 text-xs font-mono"
              />
              <select
                value={c.op}
                onChange={(e) =>
                  setConds((cs) =>
                    cs.map((x, j) => (j === i ? { ...x, op: e.target.value as Cond["op"] } : x)),
                  )
                }
                className="rounded-lg border border-slate-200 px-1.5 py-1 text-xs"
              >
                <option value="eq">精确</option>
                <option value="contains">包含</option>
              </select>
              <input
                value={c.value}
                onChange={(e) =>
                  setConds((cs) => cs.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)))
                }
                onKeyDown={(e) => e.key === "Enter" && void run(0)}
                placeholder="值"
                className="flex-1 rounded-lg border border-slate-200 px-2 py-1 text-xs font-mono"
              />
              <button
                onClick={() => setConds((cs) => cs.filter((_, j) => j !== i))}
                className="text-mute hover:text-red-600 text-xs px-1"
              >
                ✕
              </button>
            </div>
          ))}
          <datalist id="field-presets">
            {FIELD_PRESETS.map((f) => (
              <option key={f} value={f} />
            ))}
          </datalist>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setConds((cs) => [...cs, { field: "", op: "contains", value: "" }])}
              className="rounded-lg border border-dashed border-slate-300 text-mute px-2.5 py-0.5 text-xs hover:text-brand hover:border-brand-soft"
              data-testid="cond-add"
            >
              + 字段条件
            </button>
            <span className="text-[10px] text-mute">
              多条件 AND;字段作用于归一 fields——该字段缺失的族/源天然不命中(如实,不参与字段过滤)
            </span>
          </div>
        </div>

        {/* 时间窗 + 源多选 */}
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs text-mute">时间窗</span>
          {(
            [
              ["all", "全期"],
              ["1h", "近 1 小时"],
              ["24h", "近 24 小时"],
              ["custom", "自定义"],
            ] as [TimeMode, string][]
          ).map(([k, label]) => (
            <button
              key={k}
              onClick={() => setTimeMode(k)}
              className={`rounded-lg px-2.5 py-1 text-xs transition-colors ${
                timeMode === k ? "bg-brand text-white" : "text-mute hover:bg-slate-100"
              }`}
              data-testid={`time-${k}`}
            >
              {label}
            </button>
          ))}
          {timeMode === "custom" && (
            <>
              <input
                type="datetime-local"
                value={customFrom}
                onChange={(e) => setCustomFrom(e.target.value)}
                className="rounded-lg border border-slate-200 px-2 py-1 text-xs"
                step={1}
              />
              <span className="text-xs text-mute">至</span>
              <input
                type="datetime-local"
                value={customTo}
                onChange={(e) => setCustomTo(e.target.value)}
                className="rounded-lg border border-slate-200 px-2 py-1 text-xs"
                step={1}
              />
            </>
          )}
          <span className="text-[10px] text-mute">无时区源 ts 为 null,不参与时间窗(如实)</span>
          <div className="flex-1" />
          <div className="relative">
            <button
              onClick={() => setSrcOpen((o) => !o)}
              className="rounded-lg border border-slate-200 px-2.5 py-1 text-xs text-slate-600 hover:border-brand-soft"
              data-testid="src-picker"
            >
              源 {picked.size > 0 ? `已选 ${picked.size}` : "全部"} ▾
            </button>
            {srcOpen && (
              <div className="absolute right-0 top-8 z-20 w-96 max-h-64 overflow-auto thin-scroll
                rounded-lg bg-white border border-slate-200 shadow-lift p-2">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[11px] text-mute">限定源集合(不选=全部)</span>
                  <button
                    onClick={() => setPicked(new Set())}
                    className="text-[11px] text-brand hover:underline"
                  >
                    清空
                  </button>
                </div>
                {sources.map((s) => (
                  <label
                    key={s.id}
                    className="flex items-center gap-2 px-1 py-0.5 rounded hover:bg-brand-light/50 cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      checked={picked.has(s.id)}
                      onChange={() => toggleSrc(s.id)}
                    />
                    <span className="text-[11px] font-mono text-slate-700 truncate" title={s.path}>
                      {s.path}
                    </span>
                  </label>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 结果栏 */}
      {err && <div className="mt-3 rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2">{err}</div>}
      {events !== null && (
        <div className="mt-3">
          <div className="flex items-center gap-2 text-[11px] text-mute mb-1.5" data-testid="search-meta">
            <span>
              {events.length} 条命中{events.length >= PAGE ? `(本页上限 ${PAGE},可翻页)` : ""}
            </span>
            <span>·</span>
            <span data-testid="search-elapsed">耗时 {elapsed} ms(客户端计时,含网络)</span>
            {offset > 0 && <span>· 偏移 {offset}</span>}
          </div>
          <div className="rounded-lg border border-slate-100 overflow-hidden">
            {events.length === 0 && (
              <div className="text-xs text-mute p-4 text-center">零命中(如实)</div>
            )}
            {events.map((ev, i) => (
              <div key={`${ev.source_id}-${ev.line_no}`} className="border-b border-slate-50 last:border-0">
                <div
                  className="flex items-center gap-2 px-3 py-1.5 hover:bg-brand-light/30 cursor-pointer"
                  onClick={() => setExpand(expand === i ? null : i)}
                >
                  <span className="text-[10px] text-slate-400 w-36 shrink-0">
                    {ev.ts ? new Date(ev.ts).toLocaleString("zh-CN", { hour12: false }) : "无时区"}
                  </span>
                  <span
                    className="text-[10px] font-mono text-mute w-44 shrink-0 truncate"
                    title={srcName.get(ev.source_id) || ev.source_id}
                  >
                    {(srcName.get(ev.source_id) || ev.source_id).split("/").pop()}:{ev.line_no}
                  </span>
                  <span className="text-xs font-mono text-slate-700 truncate flex-1">
                    {ev.raw || ev.fields}
                  </span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onAnchor(ev.source_id, ev.line_no);
                    }}
                    className="shrink-0 rounded border border-slate-200 px-1.5 py-0.5 text-[10px] text-brand hover:bg-brand-light"
                    data-testid={`jump-${i}`}
                  >
                    锚点
                  </button>
                </div>
                {expand === i && ev.fields && ev.fields !== "{}" && (
                  <div className="px-3 pb-2">
                    <div className="rounded-lg bg-paper p-2 text-[11px] font-mono text-slate-600 whitespace-pre-wrap break-all">
                      {prettyFields(ev.fields)}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
          <div className="flex items-center justify-between mt-2">
            <button
              disabled={offset <= 0 || loading}
              onClick={() => void run(Math.max(0, offset - PAGE))}
              className="rounded border border-slate-200 px-2.5 py-1 text-xs text-mute hover:text-brand disabled:opacity-40"
            >
              ← 上 {PAGE} 条
            </button>
            <button
              disabled={events.length < PAGE || loading}
              onClick={() => void run(offset + PAGE)}
              className="rounded border border-slate-200 px-2.5 py-1 text-xs text-mute hover:text-brand disabled:opacity-40"
            >
              下 {PAGE} 条 →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// prettyFields 归一字段展开(JSON key: value 逐行;坏 JSON 原样)。
function prettyFields(raw: string): string {
  try {
    const m = JSON.parse(raw) as Record<string, unknown>;
    return Object.entries(m)
      .map(([k, v]) => `${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`)
      .join("\n");
  } catch {
    return raw;
  }
}
