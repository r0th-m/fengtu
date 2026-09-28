// 意图图归并/子树/待批清单焊死(切片 8b)。
import { describe, expect, it } from "vitest";
import {
  applyChange,
  applySnapshot,
  childrenOf,
  descendants,
  emptyGraph,
  pendingApprovals,
  STATUS_LABEL,
  type IntentEdge,
  type IntentNode,
} from "./intent";

function node(id: string, over: Partial<IntentNode> = {}): IntentNode {
  return {
    id, case_id: "c1", kind: "intent", text: "意图 " + id, status: "open",
    created_by: "rule", scope: "case", depth: 1, budget_seconds: 600,
    created_at: "2026-09-22T00:00:0" + id + "Z", ...over,
  };
}

function edge(id: string, from: string, to: string, kind = "spawns"): IntentEdge {
  return { id, case_id: "c1", from_id: from, to_id: to, kind, created_at: "2026-09-22T00:00:00Z" };
}

describe("applySnapshot/applyChange", () => {
  it("快照全量替换 + 增量归并", () => {
    let g = applySnapshot([node("1"), node("2")], [edge("e1", "1", "2")]);
    expect(Object.keys(g.nodes)).toHaveLength(2);
    expect(Object.keys(g.edges)).toHaveLength(1);

    // node_added:新节点进图,seq 单调
    const g2 = applyChange(g, "node_added", node("3"));
    expect(g2.nodes["3"].text).toBe("意图 3");
    expect(g2.seq).toBe(g.seq + 1);
    expect(g.nodes["3"]).toBeUndefined(); // 纯函数不改旧态

    // node_updated:状态写回覆盖
    const g3 = applyChange(g2, "node_updated", node("2", { status: "running" }));
    expect(g3.nodes["2"].status).toBe("running");

    // edge_added
    const g4 = applyChange(g3, "edge_added", edge("e2", "2", "3", "yields"));
    expect(g4.edges["e2"].kind).toBe("yields");

    // 未知帧型/坏帧不改状态
    const g5 = applyChange(g4, "heartbeat", {} as IntentNode);
    expect(g5).toBe(g4);
    const g6 = applyChange(g4, "node_added", {} as IntentNode);
    expect(g6).toBe(g4);
  });
});

describe("子树遍历(proves 回指边不算子树)", () => {
  const g = applySnapshot(
    [
      node("goal", { kind: "goal", depth: 0 }),
      node("a"),
      node("b"),
      node("f", { kind: "fact" }),
    ],
    [
      edge("e1", "goal", "a"),
      edge("e2", "a", "b"),
      edge("e3", "a", "f", "yields"),
      edge("e4", "f", "a", "proves"), // 回指:顺它会把 a 卷进 f 的子树
    ],
  );

  it("childrenOf 只走树边", () => {
    expect(childrenOf(g, "a").map((n) => n.id).sort()).toEqual(["b", "f"]);
    expect(childrenOf(g, "f")).toEqual([]); // proves 不算
  });

  it("descendants BFS 防环", () => {
    expect([...descendants(g, "goal")].sort()).toEqual(["a", "b", "f"]);
    expect([...descendants(g, "f")]).toEqual([]);
  });

  it("空图不炸", () => {
    expect(childrenOf(emptyGraph, "x")).toEqual([]);
    expect([...descendants(emptyGraph, "x")]).toEqual([]);
  });
});

describe("pendingApprovals", () => {
  it("只收待批,按创建序", () => {
    const g = applySnapshot(
      [
        node("2", { status: "awaiting_approval" }),
        node("1", { status: "awaiting_approval" }),
        node("3", { status: "running" }),
      ],
      [],
    );
    expect(pendingApprovals(g).map((n) => n.id)).toEqual(["1", "2"]);
  });

  it("created_at 缺失(坏帧/字段缺失)不崩,空串兜底", () => {
    const bad = node("x", { status: "awaiting_approval" });
    delete (bad as Partial<IntentNode>).created_at;
    const g = applySnapshot([node("1", { status: "awaiting_approval" }), bad], []);
    expect(() => pendingApprovals(g)).not.toThrow();
    expect(pendingApprovals(g)).toHaveLength(2);
  });
});

describe("字段缺失防御(探索链路白屏事故后立)", () => {
  it("childrenOf 遇缺 created_at 的子节点不崩", () => {
    const bad = node("b");
    delete (bad as Partial<IntentNode>).created_at;
    const g = applySnapshot([node("a"), bad], [edge("e1", "a", "b")]);
    expect(() => childrenOf(g, "a")).not.toThrow();
    expect(childrenOf(g, "a").map((n) => n.id)).toEqual(["b"]);
  });
});

describe("parked 停车场状态(0.24.0)", () => {
  it("STATUS_LABEL 有 parked 中文标;parked 不进待批列表", () => {
    expect(STATUS_LABEL.parked).toContain("停车场");
    const g = applySnapshot([node("p1", { status: "parked" })], []);
    expect(pendingApprovals(g)).toHaveLength(0); // 停车场走案件页 tab 人批,不占审批门
  });
});

describe("goal 收官机器评估态(0.29.1)", () => {
  it("STATUS_LABEL 三态齐且措辞如实(机器评估,收官定论归人)", () => {
    expect(STATUS_LABEL.closed_goal_met).toContain("机器评估达成");
    expect(STATUS_LABEL.closed_goal_partial).toContain("部分达成");
    expect(STATUS_LABEL.closed_goal_unmet).toContain("未达成");
    for (const k of ["closed_goal_met", "closed_goal_partial", "closed_goal_unmet"]) {
      expect(STATUS_LABEL[k]).toContain("收官定论归人");
    }
    // 收官态是终态,不进待批列表(也不该进派发——后端 NextRunnable 只领 open intent)
    const g = applySnapshot([node("g1", { status: "closed_goal_met" })], []);
    expect(pendingApprovals(g)).toHaveLength(0);
  });
});
