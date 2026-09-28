// 分层流布局引擎(切片 8c,ARTEX 同款:goal 左 → 意图中 → 事实/发现右)。
// 纯函数、确定性:同一图输入恒得同一坐标(重渲染不跳、SSE 增量只动该动的)。
//   - 深度:按树边(spawns/derived_from/yields)算最长路分层,goal=0;
//     proves 回指边不参与分层(顺它会乱列);
//   - 分列:depth → x 列,深度>6 自然超出可视宽,容器横向滚动即可;
//   - 列内:重心(barycenter)排序减少边交叉(父列已定位,均值取父行位置),
//     正/反/正三扫收敛;可选「主机泳道」:同 host_scope 在列内相邻。
import type { GraphState } from "./intent";

export const CARD_W = 180; // 卡片固定宽
export const CARD_H = 64; // 卡片固定高
export const COL_GAP = 96; // 列间距(连线+类型标签走得开)
export const ROW_GAP = 18; // 列内卡片间距
export const PAD = 24; // 画布内边距

export interface LayoutPos {
  x: number;
  y: number;
  depth: number; // 所在列
  row: number; // 列内行号
}

export interface LayoutResult {
  pos: Map<string, LayoutPos>;
  width: number; // 世界宽(列铺满)
  height: number; // 世界高(最高列)
  maxDepth: number;
}

// 树边白名单(与 intent.ts 子树遍历一致;proves 回指不算)。
const TREE_EDGE_KINDS = new Set(["spawns", "derived_from", "yields"]);

export interface LayoutOpts {
  groupByHost?: boolean; // 主机泳道:同 host_scope 列内相邻
}

// layoutGraph 主入口:可见图 → 每节点 x/y/列/行 + 世界尺寸。
export function layoutGraph(g: GraphState, opts: LayoutOpts = {}): LayoutResult {
  const ids = Object.keys(g.nodes);
  const pos = new Map<string, LayoutPos>();
  if (ids.length === 0) return { pos, width: 0, height: 0, maxDepth: 0 };

  // ---- 1. 深度分层(Kahn 最长路;树边 from→to) ----
  const treeOut = new Map<string, string[]>(); // from → [to]
  const indeg = new Map<string, number>();
  for (const id of ids) {
    treeOut.set(id, []);
    indeg.set(id, 0);
  }
  for (const e of Object.values(g.edges)) {
    if (!TREE_EDGE_KINDS.has(e.kind)) continue;
    if (!g.nodes[e.from_id] || !g.nodes[e.to_id]) continue;
    if (e.from_id === e.to_id) continue; // 自环不理
    treeOut.get(e.from_id)!.push(e.to_id);
    indeg.set(e.to_id, indeg.get(e.to_id)! + 1);
  }
  const depth = new Map<string, number>();
  const queue: string[] = [];
  for (const id of ids) {
    depth.set(id, 0); // 根(无入树边)天然 0;goal 通常在此
    if (indeg.get(id) === 0) queue.push(id);
  }
  const seen = new Set<string>();
  while (queue.length > 0) {
    const cur = queue.shift()!;
    seen.add(cur);
    for (const nxt of treeOut.get(cur)!) {
      depth.set(nxt, Math.max(depth.get(nxt)!, depth.get(cur)! + 1));
      indeg.set(nxt, indeg.get(nxt)! - 1);
      if (indeg.get(nxt) === 0) queue.push(nxt);
    }
  }
  // 环残留(不该有,防挂死):回退后端 depth 字段,保证有坐标
  for (const id of ids) {
    if (!seen.has(id)) depth.set(id, Math.max(0, g.nodes[id].depth || 0));
  }

  // 孤儿右移:图上有 goal 时,不连 goal 的孤立组件(规则播种根意图等)
  // 整组右移一列——goal 独占最左列(「goal 左 → 意图中」分层流);
  // hint 孤儿留最左(ARTEX:起点/提示最左)。
  if (ids.some((id) => g.nodes[id].kind === "goal")) {
    const reach = new Set<string>();
    const q = ids.filter((id) => g.nodes[id].kind === "goal");
    for (const r of q) reach.add(r);
    while (q.length > 0) {
      const cur = q.shift()!;
      for (const nxt of treeOut.get(cur)!) {
        if (!reach.has(nxt)) {
          reach.add(nxt);
          q.push(nxt);
        }
      }
    }
    for (const id of ids) {
      if (!reach.has(id) && g.nodes[id].kind !== "hint") {
        depth.set(id, depth.get(id)! + 1);
      }
    }
  }

  // ---- 2. 分列 ----
  let maxDepth = 0;
  for (const d of depth.values()) maxDepth = Math.max(maxDepth, d);
  const cols: string[][] = [];
  for (let d = 0; d <= maxDepth; d++) cols.push([]);
  for (const id of ids) cols[depth.get(id)!].push(id);

  // 列 0 初始序:goal 在前,其余按创建序(确定性)
  const kindRank = (id: string) => (g.nodes[id].kind === "goal" ? 0 : 1);
  // created_at 可能缺(坏帧/字段缺失,防渲染整树崩——探索链路白屏事故后立)
  const created = (id: string) => g.nodes[id].created_at || "";
  cols[0].sort((a, b) => kindRank(a) - kindRank(b) || created(a).localeCompare(created(b)));

  // ---- 3. 列内重心排序(正/反/正三扫) ----
  const rowOf = new Map<string, number>(); // 当前行号
  const setRows = (col: string[]) => col.forEach((id, i) => rowOf.set(id, i));
  setRows(cols[0]);

  // parentsOf/childrenOf(树边,限图内)
  const parentsOf = (id: string) => {
    const out: string[] = [];
    for (const e of Object.values(g.edges)) {
      if (e.to_id === id && TREE_EDGE_KINDS.has(e.kind) && rowOf.has(e.from_id)) {
        out.push(e.from_id);
      }
    }
    return out;
  };
  const childrenOfId = (id: string) => {
    const out: string[] = [];
    for (const e of Object.values(g.edges)) {
      if (e.from_id === id && TREE_EDGE_KINDS.has(e.kind) && rowOf.has(e.to_id)) {
        out.push(e.to_id);
      }
    }
    return out;
  };
  const bary = (id: string, refs: string[]) =>
    refs.length === 0 ? Infinity : refs.reduce((s, r) => s + rowOf.get(r)!, 0) / refs.length;

  // 主机泳道:稳定聚簇——同 host_scope 的卡片在列内相邻(以首现位落组)
  const clusterHost = (col: string[]): string[] => {
    if (!opts.groupByHost) return col;
    const groups = new Map<string, string[]>();
    const seq: (string | string[])[] = [];
    for (const id of col) {
      const hs = g.nodes[id].host_scope;
      if (!hs) {
        seq.push(id);
        continue;
      }
      if (!groups.has(hs)) {
        groups.set(hs, []);
        seq.push(groups.get(hs)!);
      }
      groups.get(hs)!.push(id);
    }
    return seq.flat();
  };

  const sortCol = (col: string[], keyFn: (id: string) => number) => {
    col.sort((a, b) => keyFn(a) - keyFn(b) || created(a).localeCompare(created(b)));
  };

  for (let d = 1; d <= maxDepth; d++) {
    sortCol(cols[d], (id) => bary(id, parentsOf(id)));
    cols[d] = clusterHost(cols[d]);
    setRows(cols[d]);
  }
  for (let d = maxDepth - 1; d >= 0; d--) {
    sortCol(cols[d], (id) => bary(id, childrenOfId(id)));
    setRows(cols[d]);
  }
  for (let d = 1; d <= maxDepth; d++) {
    sortCol(cols[d], (id) => bary(id, parentsOf(id)));
    cols[d] = clusterHost(cols[d]);
    setRows(cols[d]);
  }

  // ---- 4. 坐标:列定 x,行定 y;矮列相对最高列垂直居中 ----
  const colSpan = cols.map((c) => c.length * (CARD_H + ROW_GAP) - ROW_GAP);
  const maxSpan = Math.max(...colSpan);
  for (let d = 0; d <= maxDepth; d++) {
    const offset = (maxSpan - colSpan[d]) / 2;
    for (let i = 0; i < cols[d].length; i++) {
      const id = cols[d][i];
      pos.set(id, {
        x: PAD + d * (CARD_W + COL_GAP),
        y: PAD + offset + i * (CARD_H + ROW_GAP),
        depth: d,
        row: i,
      });
    }
  }

  return {
    pos,
    width: PAD * 2 + (maxDepth + 1) * (CARD_W + COL_GAP) - COL_GAP,
    height: PAD * 2 + maxSpan,
    maxDepth,
  };
}

// edgePath 贝塞尔平滑曲线(右缘中点 → 左缘中点;反向边自然鼓包)。
// 返回 path d 与 t=0.5 中点(边类型标签落点)。
export function edgePath(
  a: { x: number; y: number },
  b: { x: number; y: number },
): { d: string; mx: number; my: number } {
  const x0 = a.x + CARD_W;
  const y0 = a.y + CARD_H / 2;
  const x1 = b.x;
  const y1 = b.y + CARD_H / 2;
  const dx = Math.max(40, Math.abs(x1 - x0) / 2);
  const c1x = x0 + dx;
  const c2x = x1 - dx;
  // B(0.5) = (P0 + 3·C1 + 3·C2 + P3) / 8
  return {
    d: `M ${x0} ${y0} C ${c1x} ${y0}, ${c2x} ${y1}, ${x1} ${y1}`,
    mx: (x0 + 3 * c1x + 3 * c2x + x1) / 8,
    my: (y0 + 3 * y0 + 3 * y1 + y1) / 8,
  };
}
