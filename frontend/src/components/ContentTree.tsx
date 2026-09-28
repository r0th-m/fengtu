// 内容树视图:采集项目录树(主机→包→目录→文件,按路径聚合)+ 右栏原文查看器
// (行号滚动定位;锚点直达)。数据:GET /api/cases/{id}/artifact-tree;
// 原文:GET /api/sources/{id}/lines?page&size(≤1000 行/窗)。
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../lib/api";
import { watchTask } from "../lib/watch";
import type { NavAnchor, QueryEvent, SourceLine, TreeNode } from "../lib/types";
import Tip from "./Tip";

const PAGE = 200;

function statusCls(s?: string): string {
  switch (s) {
    case "已解析":
      return "text-brand";
    case "待确认":
    case "存疑":
      return "text-amber-600";
    case "解析失败":
      return "text-red-600";
    default:
      return "text-mute";
  }
}

function DirNode({
  node,
  depth,
  open,
  toggle,
  onPick,
  onConfirm,
  pickedId,
}: {
  node: TreeNode;
  depth: number;
  open: Record<string, boolean>;
  toggle: (p: string) => void;
  onPick: (n: TreeNode) => void;
  onConfirm: (n: TreeNode) => void;
  pickedId: string;
}) {
  if (node.type === "source") {
    return (
      <button
        onClick={() => onPick(node)}
        className={`w-full text-left flex items-center gap-1.5 px-2 py-1 rounded-md text-xs
          hover:bg-brand-light/50 transition-colors ${
            pickedId === node.source_id ? "bg-brand-light text-brand" : "text-slate-700"
          }`}
        style={{ paddingLeft: `${depth * 14 + 8}px` }}
        title={node.path}
      >
        <span className="truncate flex-1 font-mono">{node.name}</span>
        {node.status === "待确认" && (
          <span
            role="button"
            tabIndex={0}
            onClick={(e) => {
              e.stopPropagation();
              onConfirm(node);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.stopPropagation();
                onConfirm(node);
              }
            }}
            className="shrink-0 rounded border border-amber-300 text-amber-700 px-1.5 py-px
              text-[10px] hover:bg-amber-50 cursor-pointer"
            title="指纹置信度 <0.9,停下来问人(§6.2);点此改判为 raw-text 原文并重解析(异步任务,202)"
          >
            改判
          </span>
        )}
        <span className={`shrink-0 text-[10px] ${statusCls(node.status)}`}>{node.status}</span>
      </button>
    );
  }
  const isOpen = open[node.path] ?? depth < 2; // 默认展开主机/包两层
  return (
    <div>
      <button
        onClick={() => toggle(node.path)}
        className="w-full text-left flex items-center gap-1 px-2 py-1 rounded-md text-xs
          hover:bg-slate-100 transition-colors text-ink font-medium"
        style={{ paddingLeft: `${depth * 14 + 8}px` }}
        title={node.path}
      >
        <span className="text-mute w-3 shrink-0">{isOpen ? "▾" : "▸"}</span>
        <span className="truncate font-mono">{node.name}</span>
      </button>
      {isOpen &&
        node.children?.map((c) => (
          <DirNode
            key={c.path}
            node={c}
            depth={depth + 1}
            open={open}
            toggle={toggle}
            onPick={onPick}
            onConfirm={onConfirm}
            pickedId={pickedId}
          />
        ))}
    </div>
  );
}

// findPath 树里找 source 节点的祖先链(锚点跳来时逐层展开)。
function findPath(nodes: TreeNode[], sourceId: string, trail: string[] = []): string[] | null {
  for (const n of nodes) {
    const cur = [...trail, n.path];
    if (n.type === "source" && n.source_id === sourceId) return cur;
    if (n.children) {
      const r = findPath(n.children, sourceId, cur);
      if (r) return r;
    }
  }
  return null;
}

export default function ContentTree({
  caseId,
  anchor,
}: {
  caseId: string;
  anchor: NavAnchor | null;
}) {
  const [tree, setTree] = useState<TreeNode[]>([]);
  const [err, setErr] = useState("");
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [picked, setPicked] = useState<TreeNode | null>(null);
  const [confirmNote, setConfirmNote] = useState("");
  const [confirmErr, setConfirmErr] = useState("");

  const loadTree = useCallback(() => {
    api
      .get<{ tree: TreeNode[] }>(`/api/cases/${caseId}/artifact-tree`)
      .then((d) => setTree(d.tree || []))
      .catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, [caseId]);

  useEffect(() => {
    loadTree();
  }, [loadTree]);

  // 树刷新后同步 picked 到新节点对象(改判任务终态后状态/行数已变)
  useEffect(() => {
    if (!picked?.source_id) return;
    let found: TreeNode | null = null;
    const walk = (ns: TreeNode[]) => {
      for (const n of ns) {
        if (n.type === "source" && n.source_id === picked.source_id) found = n;
        if (n.children) walk(n.children);
      }
    };
    walk(tree);
    if (found && found !== picked) setPicked(found);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tree]);

  // 待确认源改判(判断权归人:这是对「格式判定」的人改判,非候选结论确认):
  // POST /api/sources/{id}/detect {format:"desc:raw-text", reparse:true}
  // → 202 + task_id 异步改判解析;订任务流,终态后刷新树。
  const confirmRawText = useCallback(
    (node: TreeNode) => {
      if (!node.source_id) return;
      setConfirmNote("");
      setConfirmErr("");
      api
        .post<{ task_id?: string; note?: string }>(
          `/api/sources/${node.source_id}/detect`,
          { format: "desc:raw-text", reparse: true },
        )
        .then((d) => {
          if (d.task_id) {
            setConfirmNote(`已提交改判解析任务(${d.task_id}):${node.path}——终态后本树自动刷新`);
            const un = watchTask(d.task_id, (t) => {
              if (t.status === "done" || t.status === "failed") {
                un();
                setConfirmNote(
                  t.status === "done"
                    ? `改判解析完成:${node.path}`
                    : "",
                );
                if (t.status === "failed") {
                  setConfirmErr(`改判解析失败(${node.path}):${t.err || "未知错误"}`);
                }
                loadTree();
              }
            });
          } else {
            setConfirmNote(d.note || "判定已改");
            loadTree();
          }
        })
        .catch((e) =>
          setConfirmErr(`改判提交失败(${node.path}):${e instanceof Error ? e.message : String(e)}`),
        );
    },
    [loadTree],
  );

  const toggle = useCallback(
    (p: string) => setOpen((o) => ({ ...o, [p]: !(o[p] ?? false) })),
    [],
  );

  // 锚点直达:展开祖先链 + 选中源 + 定位行
  useEffect(() => {
    if (!anchor || tree.length === 0) return;
    const trail = findPath(tree, anchor.sourceId);
    if (trail) {
      setOpen((o) => {
        const n = { ...o };
        for (const p of trail.slice(0, -1)) n[p] = true;
        return n;
      });
    }
    let found: TreeNode | null = null;
    const walk = (ns: TreeNode[]) => {
      for (const n of ns) {
        if (n.type === "source" && n.source_id === anchor.sourceId) found = n;
        if (n.children) walk(n.children);
      }
    };
    walk(tree);
    if (found) setPicked(found);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [anchor, tree]);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-[340px_1fr] gap-4 items-start">
      <div className="rounded-card bg-white shadow-card p-2 max-h-[70vh] overflow-auto thin-scroll">
        {err && <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2 m-1">{err}</div>}
        {confirmErr && (
          <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2 m-1">{confirmErr}</div>
        )}
        {confirmNote && (
          <div className="rounded-lg bg-amber-50 text-amber-700 text-xs px-3 py-2 m-1">{confirmNote}</div>
        )}
        {tree.length === 0 && !err && (
          <div className="text-xs text-mute p-4 text-center">内容树加载中…</div>
        )}
        {tree.map((n) => (
          <DirNode
            key={n.path}
            node={n}
            depth={0}
            open={open}
            toggle={toggle}
            onPick={setPicked}
            onConfirm={confirmRawText}
            pickedId={picked?.source_id || ""}
          />
        ))}
      </div>
      <Viewer node={picked} anchor={anchor} caseId={caseId} onConfirm={confirmRawText} />
    </div>
  );
}

function Viewer({
  node,
  anchor,
  caseId,
  onConfirm,
}: {
  node: TreeNode | null;
  anchor: NavAnchor | null;
  caseId: string;
  onConfirm: (n: TreeNode) => void;
}) {
  // 锚点行号仅当锚指向当前源时生效(手动切源不沿用旧锚)
  const anchorLine = anchor && node && anchor.sourceId === node.source_id ? anchor.lineNo : null;
  const anchorSeq = anchor?.seq ?? 0;
  const isText = !node || node.kind === "text";
  const [lines, setLines] = useState<SourceLine[]>([]);
  const [events, setEvents] = useState<QueryEvent[]>([]);
  const [from, setFrom] = useState(1);
  const [err, setErr] = useState("");
  const [note, setNote] = useState("");
  const [jumpTo, setJumpTo] = useState("");
  const highlight = useRef<number | null>(null);
  const boxRef = useRef<HTMLDivElement>(null);

  const loadRange = useCallback(
    async (f: number, hl: number | null) => {
      if (!node?.source_id) return;
      try {
        const d = await api.get<{ lines: SourceLine[]; note?: string }>(
          `/api/sources/${node.source_id}/lines?from=${f}&to=${f + PAGE - 1}`,
        );
        setLines(d.lines || []);
        setEvents([]);
        setFrom(f);
        setNote(d.note || "");
        setErr("");
        highlight.current = hl;
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e));
        setLines([]);
      }
    },
    [node?.source_id],
  );

  // 非文本源(evtx 等):原文行号回查不可用,走事件视图(CH 检索层,
  // raw 列原文随事件返回——后端 422 文案指路的那条)。
  // 锚点定位:事件位次 ≤ 行号-1(bad/skip 行无事件),按 offset=行号-1-100
  // 估窗 200 条,目标行不在窗内如实标注(不硬翻页,防大源扫穿)。
  const loadEvents = useCallback(
    async (offset: number, hl: number | null) => {
      if (!node?.source_id) return;
      try {
        const d = await api.get<{ events: QueryEvent[] }>(
          `/api/query?case_id=${caseId}&source_id=${node.source_id}` +
            `&limit=${PAGE}&offset=${Math.max(0, offset)}`,
        );
        const evs = d.events || [];
        setEvents(evs);
        setLines([]);
        setFrom(Math.max(0, offset) + 1); // 事件位次(1 起,如实标注非物理行号)
        setErr("");
        let n = "非文本源:原文行号回查不可用,此为事件视图(CH raw 列原文);位次=事件序号,非物理行号";
        if (hl != null && !evs.some((e) => e.line_no === hl)) {
          n += `;锚点行 ${hl} 不在本窗(bad/skip 行无事件,位次<行号),用「跳行」邻近估算或检索层精查`;
        }
        setNote(n);
        highlight.current = hl;
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e));
        setEvents([]);
      }
    },
    [node?.source_id, caseId],
  );

  const load = useCallback(
    (hint: number | null, hl: number | null) => {
      if (node && node.kind !== "text") {
        const offset = hint && hint > 1 ? Math.max(0, hint - 1 - 100) : 0;
        void loadEvents(offset, hl);
      } else {
        void loadRange(hint && hint > 0 ? hint : 1, hl);
      }
    },
    [node, loadEvents, loadRange],
  );

  // 选中源:从头看;锚点带行号:定位到行所在窗
  useEffect(() => {
    if (!node?.source_id) return;
    load(anchorLine && anchorLine > 0 ? anchorLine : null, anchorLine);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [node?.source_id]);

  // 锚点行号变化(同一片源重复跳)
  useEffect(() => {
    if (!node?.source_id || !anchorLine || anchorLine < 1 || anchorSeq === 0) return;
    load(anchorLine, anchorLine);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [anchorSeq]);

  // 渲染后滚到高亮行
  useEffect(() => {
    if (highlight.current == null || !boxRef.current) return;
    const el = boxRef.current.querySelector(`[data-line="${highlight.current}"]`);
    el?.scrollIntoView({ block: "center" });
  }, [lines, events]);

  const totalLines = useMemo(() => node?.lines ?? 0, [node]);

  if (!node) {
    return (
      <div className="rounded-card bg-white shadow-card p-8 text-center text-sm text-mute min-h-[300px]
        flex items-center justify-center">
        从左侧内容树选一个文件查看原文(候选卡/聊天里的锚点也会跳到这里)
      </div>
    );
  }

  return (
    <div className="rounded-card bg-white shadow-card p-3">
      <div className="flex items-center gap-2 flex-wrap mb-2 px-1">
        <span className="text-xs font-mono text-ink truncate max-w-[40%]" title={node.path}>
          {node.path}
        </span>
        <Tip text={`类别 ${node.kind || "-"};采集项 ${node.artifact_type || "-"};判定 ${node.detect_format || "-"}(置信度 ${node.detect_confidence ?? "-"}:前验抽样成功率+后验绊线,§6.2)`}>
          <span className={`text-[11px] ${statusCls(node.status)}`}>
            {node.status}
          </span>
        </Tip>
        <Tip text={isText ? "行数=摄入任务账 rows_total(物理行号 1 起,溯源锚)" : "行数=摄入任务账 rows_total;非文本源行号=事件在源内的序号锚"}>
          <span className="text-[11px] text-mute">约 {totalLines} 行</span>
        </Tip>
        {node.status === "待确认" && (
          <Tip text="指纹置信度 <0.9,机器不停下来猜(§6.2);改判 desc:raw-text=按原文逐行入事件(ts 不猜,全文可检索),异步重解析,判定留审计">
            <button
              onClick={() => onConfirm(node)}
              className="rounded border border-amber-300 bg-amber-50 text-amber-700 px-2 py-0.5
                text-[11px] hover:bg-amber-100 transition-colors"
              data-testid="override-raw-text"
            >
              改判为 raw-text 原文并解析
            </button>
          </Tip>
        )}
        <div className="flex-1" />
        <input
          value={jumpTo}
          onChange={(e) => setJumpTo(e.target.value.replace(/\D/g, ""))}
          placeholder="行号"
          className="w-16 rounded border border-slate-200 px-1.5 py-0.5 text-xs"
          onKeyDown={(e) => {
            if (e.key === "Enter" && jumpTo) {
              const n = parseInt(jumpTo, 10);
              load(isText ? Math.max(1, n - 20) : n, n);
            }
          }}
        />
        <button
          onClick={() => {
            if (!jumpTo) return;
            const n = parseInt(jumpTo, 10);
            load(isText ? Math.max(1, n - 20) : n, n);
          }}
          className="rounded border border-slate-200 px-2 py-0.5 text-xs text-mute hover:text-brand"
        >
          跳转
        </button>
      </div>
      {err && <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2 mb-2">{err}</div>}
      {note && (
        <div className="rounded-lg bg-amber-50 text-amber-700 text-[11px] px-3 py-1.5 mb-2">{note}</div>
      )}
      <div
        ref={boxRef}
        className="rounded-lg bg-[#FBFBF9] border border-slate-100 max-h-[60vh] overflow-auto thin-scroll"
      >
        {lines.length === 0 && events.length === 0 && !err && (
          <div className="text-xs text-mute p-4 text-center">无内容(如实)</div>
        )}
        <table className="w-full text-xs font-mono leading-relaxed">
          <tbody>
            {lines.map((l) => (
              <tr
                key={l.no}
                data-line={l.no}
                className={l.no === highlight.current ? "bg-amber-100/70" : "hover:bg-brand-light/30"}
              >
                <td className="select-none text-right pr-3 pl-2 py-0 text-slate-400 w-12 align-top">
                  {l.no}
                </td>
                <td className="pr-3 py-0 whitespace-pre-wrap break-all text-slate-700">{l.text}</td>
              </tr>
            ))}
            {events.map((ev) => (
              <tr
                key={ev.line_no}
                data-line={ev.line_no}
                className={ev.line_no === highlight.current ? "bg-amber-100/70" : "hover:bg-brand-light/30"}
              >
                <td className="select-none text-right pr-3 pl-2 py-0 text-slate-400 w-12 align-top">
                  {ev.line_no}
                </td>
                <td className="pr-3 py-0 whitespace-pre-wrap break-all text-slate-700">
                  {ev.ts && (
                    <span className="text-slate-400">
                      {new Date(ev.ts).toLocaleString("zh-CN", { hour12: false })}{" "}
                    </span>
                  )}
                  {ev.raw || ev.fields}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex items-center justify-between mt-2 px-1">
        <button
          disabled={from <= 1}
          onClick={() =>
            isText ? void loadRange(Math.max(1, from - PAGE), null) : void loadEvents(Math.max(0, from - 1 - PAGE), null)}
          className="rounded border border-slate-200 px-2.5 py-1 text-xs text-mute
            hover:text-brand disabled:opacity-40"
        >
          ← 上 {PAGE} {isText ? "行" : "条"}
        </button>
        <span className="text-[11px] text-mute">
          {isText
            ? lines.length > 0
              ? `${from} ~ ${from + lines.length - 1} 行`
              : ""
            : events.length > 0
              ? `事件位次 ${from} ~ ${from + events.length - 1}(非物理行号)`
              : ""}
        </span>
        <button
          disabled={isText ? lines.length < PAGE : events.length < PAGE}
          onClick={() =>
            isText ? void loadRange(from + PAGE, null) : void loadEvents(from - 1 + PAGE, null)}
          className="rounded border border-slate-200 px-2.5 py-1 text-xs text-mute
            hover:text-brand disabled:opacity-40"
        >
          下 {PAGE} {isText ? "行" : "条"} →
        </button>
      </div>
    </div>
  );
}
