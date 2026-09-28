// 时间线面板(切片 8b):全源按 ts 小时桶密度条 + 桶内事件列表,点条查桶、
// 点行跳锚点;无时区源单列如实标(不参与时间线/时间窗)。
// 数据:GET /api/cases/{id}/timeline(桶=小时);桶内事件走既有 GET /api/query。
import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import type { QueryEvent, SourceInfo } from "../lib/types";

interface Bucket {
  key: string; // 小时桶起 Unix 秒(UTC)
  count: number;
}

interface NoTZ {
  key: string; // source_id
  count: number;
}

export default function TimelinePanel({
  caseId,
  sources,
  onAnchor,
}: {
  caseId: string;
  sources: SourceInfo[];
  onAnchor: (sourceId: string, lineNo: number) => void;
}) {
  const [buckets, setBuckets] = useState<Bucket[]>([]);
  const [notz, setNotz] = useState<NoTZ[]>([]);
  const [err, setErr] = useState("");
  const [picked, setPicked] = useState<Bucket | null>(null);
  const [events, setEvents] = useState<QueryEvent[]>([]);
  const [evErr, setEvErr] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api
      .get<{ buckets: Bucket[]; notz_sources: NoTZ[] }>(`/api/cases/${caseId}/timeline`)
      .then((d) => {
        setBuckets(d.buckets || []);
        setNotz(d.notz_sources || []);
      })
      .catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, [caseId]);

  const srcName = useMemo(() => {
    const m = new Map<string, string>();
    for (const s of sources) m.set(s.id, s.path);
    return m;
  }, [sources]);

  const max = useMemo(() => Math.max(1, ...buckets.map((b) => b.count)), [buckets]);

  // 点条:查该小时桶的事件(ts_from/to=桶窗,经既有检索层)
  const pickBucket = useCallback(
    async (b: Bucket) => {
      setPicked(b);
      setLoading(true);
      setEvErr("");
      const t0 = Number(b.key);
      try {
        const p = new URLSearchParams({
          case_id: caseId,
          ts_from: new Date(t0 * 1000).toISOString(),
          ts_to: new Date((t0 + 3599) * 1000).toISOString(),
          limit: "100",
        });
        const d = await api.get<{ events: QueryEvent[] }>(`/api/query?${p.toString()}`);
        setEvents(d.events || []);
      } catch (e) {
        setEvErr(e instanceof Error ? e.message : String(e));
        setEvents([]);
      } finally {
        setLoading(false);
      }
    },
    [caseId],
  );

  return (
    <div className="rounded-card bg-white shadow-card p-4" data-testid="timeline-panel">
      <div className="flex items-center gap-2 mb-2">
        <span className="text-sm font-medium text-ink">时间线</span>
        <span className="text-[11px] text-mute">
          全源按小时聚合(只含有时区源;无时区源下方单列,如实)
        </span>
      </div>
      {err && <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2 mb-2">{err}</div>}

      {buckets.length === 0 && !err ? (
        <div className="text-xs text-mute p-6 text-center">
          没有带时区的事件(无时区源不参与时间线,见下方单列)
        </div>
      ) : (
        <div className="rounded-lg border border-slate-100 p-2 overflow-x-auto thin-scroll">
          <div className="flex items-end gap-px h-32 min-w-full" data-testid="timeline-bars">
            {buckets.map((b) => {
              const t = Number(b.key) * 1000;
              const active = picked?.key === b.key;
              return (
                <button
                  key={b.key}
                  onClick={() => void pickBucket(b)}
                  title={`${new Date(t).toLocaleString("zh-CN", { hour12: false })} · ${b.count} 事件`}
                  className="group relative flex-1 min-w-[3px] rounded-t transition-colors"
                  style={{
                    height: `${Math.max(3, (b.count / max) * 100)}%`,
                    background: active ? "#0E7C7B" : "#9CCFCE",
                  }}
                  data-testid={`bar-${b.key}`}
                />
              );
            })}
          </div>
          <div className="flex justify-between text-[10px] text-mute mt-1 px-0.5">
            <span>
              {buckets.length > 0 &&
                new Date(Number(buckets[0].key) * 1000).toLocaleString("zh-CN", { hour12: false })}
            </span>
            <span>{buckets.length} 个小时桶</span>
            <span>
              {buckets.length > 0 &&
                new Date(Number(buckets[buckets.length - 1].key) * 1000).toLocaleString("zh-CN", {
                  hour12: false,
                })}
            </span>
          </div>
        </div>
      )}

      {/* 桶内事件列表 */}
      {picked && (
        <div className="mt-3" data-testid="bucket-events">
          <div className="text-xs text-ink mb-1.5">
            {new Date(Number(picked.key) * 1000).toLocaleString("zh-CN", { hour12: false })} 桶内事件(
            {loading ? "查询中…" : `${events.length} 条${events.length >= 100 ? ",上限 100" : ""}`})
          </div>
          {evErr && <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2">{evErr}</div>}
          <div className="rounded-lg border border-slate-100 max-h-72 overflow-auto thin-scroll">
            {events.map((ev) => (
              <button
                key={`${ev.source_id}-${ev.line_no}`}
                onClick={() => onAnchor(ev.source_id, ev.line_no)}
                className="w-full text-left flex items-center gap-2 px-3 py-1.5 border-b border-slate-50
                  last:border-0 hover:bg-brand-light/30"
              >
                <span className="text-[10px] text-slate-400 w-36 shrink-0">
                  {ev.ts ? new Date(ev.ts).toLocaleString("zh-CN", { hour12: false }) : "无时区"}
                </span>
                <span className="text-[10px] font-mono text-mute w-44 shrink-0 truncate">
                  {(srcName.get(ev.source_id) || ev.source_id).split("/").pop()}:{ev.line_no}
                </span>
                <span className="text-xs font-mono text-slate-700 truncate">{ev.raw || ev.fields}</span>
              </button>
            ))}
            {!loading && events.length === 0 && !evErr && (
              <div className="text-xs text-mute p-3 text-center">桶内零事件(如实)</div>
            )}
          </div>
        </div>
      )}

      {/* 无时区源单列 */}
      {notz.length > 0 && (
        <div className="mt-3" data-testid="notz-sources">
          <div className="text-xs text-ink mb-1.5">
            无时区源({notz.length})——不参与时间线与时间窗过滤(如实,不静默)
          </div>
          <div className="rounded-lg border border-amber-100 bg-amber-50/50 divide-y divide-amber-100/60">
            {notz.map((s) => (
              <div key={s.key} className="flex items-center gap-2 px-3 py-1.5 text-[11px]">
                <span className="font-mono text-slate-700 truncate flex-1" title={srcName.get(s.key)}>
                  {srcName.get(s.key) || s.key}
                </span>
                <span className="text-mute shrink-0">{s.count} 事件</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
