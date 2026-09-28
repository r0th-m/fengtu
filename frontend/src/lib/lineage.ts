// 血缘子图(交互改造切片三·报告 tab,设计 §4「finding lineage 子图」照抄):
// 从结论节点沿血缘回溯全部祖先(含 proves 回指边——「这个结论是怎么来的」
// 必须带上证明它的事实),产出子图 GraphState 交给 layoutGraph 画小图。
// 纯函数、确定性、环安全(visited)。
import { emptyGraph, type GraphState } from "./intent";

// lineageSubgraph 回溯子图:目标节点 + 全部祖先 + 子图内部的边。
// 未知节点如实回空图(不伪造血缘)。
export function lineageSubgraph(g: GraphState, id: string): GraphState {
  if (!g.nodes[id]) return emptyGraph;
  // 回溯:to_id == 当前 的边指向「我从哪来」(spawns/derived_from/yields
  // 都是父→子;proves 是 fact→意图的回指,顺它找到证明链)。
  const seen = new Set<string>([id]);
  const queue = [id];
  while (queue.length > 0) {
    const cur = queue.shift()!;
    for (const e of Object.values(g.edges)) {
      if (e.to_id !== cur) continue;
      if (!g.nodes[e.from_id] || seen.has(e.from_id)) continue;
      seen.add(e.from_id);
      queue.push(e.from_id);
    }
  }
  const nodes: GraphState["nodes"] = {};
  const edges: GraphState["edges"] = {};
  for (const nid of seen) nodes[nid] = g.nodes[nid];
  for (const e of Object.values(g.edges)) {
    if (seen.has(e.from_id) && seen.has(e.to_id)) edges[e.id] = e;
  }
  return { nodes, edges, seq: 1 };
}
