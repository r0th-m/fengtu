// 血缘子图焊死:回溯到 goal 全链/proves 回指边照收/无关分支不进/
// 环安全/未知节点空图。
import { describe, expect, it } from "vitest";
import { lineageSubgraph } from "./lineage";
import { applyChange, emptyGraph, type GraphState, type IntentEdge, type IntentNode } from "./intent";

function node(id: string, kind = "intent"): IntentNode {
  return {
    id, case_id: "c", kind, text: `节点${id}`, status: "open",
    created_by: "ai", scope: "case", depth: 0, budget_seconds: 600,
    created_at: "2026-09-23T00:00:00Z",
  };
}
function edge(id: string, from: string, to: string, kind: string): IntentEdge {
  return { id, case_id: "c", from_id: from, to_id: to, kind, created_at: "2026-09-23T00:00:00Z" };
}
// 图形态:goal → i1 → i2 → fact(yields);fact proves i2;i1 另有无关子 i3。
function sample(): GraphState {
  let g = emptyGraph;
  for (const n of [node("goal", "goal"), node("i1"), node("i2"), node("fact", "fact"), node("i3")]) {
    g = applyChange(g, "node_added", n);
  }
  for (const e of [
    edge("e1", "goal", "i1", "spawns"),
    edge("e2", "i1", "i2", "spawns"),
    edge("e3", "i2", "fact", "yields"),
    edge("e4", "fact", "i2", "proves"),
    edge("e5", "i1", "i3", "spawns"),
  ]) {
    g = applyChange(g, "edge_added", e);
  }
  return g;
}

describe("lineageSubgraph 血缘子图", () => {
  it("fact 回溯:goal/i1/i2/fact 全链 + proves 回指边照收;无关 i3 不进", () => {
    const sub = lineageSubgraph(sample(), "fact");
    expect(Object.keys(sub.nodes).sort()).toEqual(["fact", "goal", "i1", "i2"]);
    expect(Object.keys(sub.edges).sort()).toEqual(["e1", "e2", "e3", "e4"]);
  });

  it("i2 回溯:含证明它的 fact(proves 方向回溯)", () => {
    const sub = lineageSubgraph(sample(), "i2");
    expect(Object.keys(sub.nodes).sort()).toEqual(["fact", "goal", "i1", "i2"]);
  });

  it("goal 自身:孤点无边", () => {
    const sub = lineageSubgraph(sample(), "goal");
    expect(Object.keys(sub.nodes)).toEqual(["goal"]);
    expect(Object.keys(sub.edges)).toEqual([]);
  });

  it("环安全:回指成环不死循环", () => {
    let g = emptyGraph;
    g = applyChange(g, "node_added", node("a"));
    g = applyChange(g, "node_added", node("b"));
    g = applyChange(g, "edge_added", edge("x1", "a", "b", "yields"));
    g = applyChange(g, "edge_added", edge("x2", "b", "a", "proves"));
    const sub = lineageSubgraph(g, "a");
    expect(Object.keys(sub.nodes).sort()).toEqual(["a", "b"]);
  });

  it("未知节点:如实空图", () => {
    const sub = lineageSubgraph(sample(), "ghost");
    expect(Object.keys(sub.nodes)).toEqual([]);
  });
});
