// 分层流布局引擎焊死(切片 8c):深度分列/列内无重叠/重心减交叉/
// proves 不分层/主机泳道相邻/确定性/环防护/边中点。
import { describe, expect, it } from "vitest";
import { applySnapshot, type IntentEdge, type IntentNode } from "./intent";
import { CARD_H, CARD_W, COL_GAP, edgePath, layoutGraph, ROW_GAP } from "./layout";

function node(id: string, over: Partial<IntentNode> = {}): IntentNode {
  return {
    id, case_id: "c1", kind: "intent", text: "意图 " + id, status: "open",
    created_by: "rule", scope: "case", depth: 1, budget_seconds: 600,
    created_at: "2026-09-22T00:00:0" + (id.replace(/\D/g, "") || "0") + "Z", ...over,
  };
}

function edge(id: string, from: string, to: string, kind = "spawns"): IntentEdge {
  return { id, case_id: "c1", from_id: from, to_id: to, kind, created_at: "2026-09-22T00:00:00Z" };
}

describe("深度分列(goal 左 → 意图/事实右)", () => {
  const g = applySnapshot(
    [
      node("g0", { kind: "goal", depth: 0, created_at: "2026-09-22T00:00:00Z" }),
      node("a1", { created_at: "2026-09-22T00:00:01Z" }),
      node("b2", { created_at: "2026-09-22T00:00:02Z" }),
      node("f3", { kind: "fact", created_at: "2026-09-22T00:00:03Z" }),
    ],
    [
      edge("e1", "g0", "a1"),
      edge("e2", "a1", "b2"),
      edge("e3", "b2", "f3", "yields"),
      edge("e4", "f3", "b2", "proves"), // 回指不分层
    ],
  );
  const L = layoutGraph(g);

  it("深度按树边最长路递增,proves 不影响", () => {
    expect(L.pos.get("g0")!.depth).toBe(0);
    expect(L.pos.get("a1")!.depth).toBe(1);
    expect(L.pos.get("b2")!.depth).toBe(2);
    expect(L.pos.get("f3")!.depth).toBe(3); // yields 分层,proves 不拉回去
    expect(L.maxDepth).toBe(3);
  });

  it("x 随深度严格右移(列距=卡宽+列缝)", () => {
    const dx = L.pos.get("a1")!.x - L.pos.get("g0")!.x;
    expect(dx).toBe(CARD_W + COL_GAP);
    expect(L.pos.get("b2")!.x - L.pos.get("a1")!.x).toBe(CARD_W + COL_GAP);
    expect(L.pos.get("f3")!.x - L.pos.get("b2")!.x).toBe(CARD_W + COL_GAP);
  });

  it("世界尺寸如实(宽=列铺,高=最高列)", () => {
    expect(L.width).toBe(48 + 4 * (CARD_W + COL_GAP) - COL_GAP);
    expect(L.height).toBeGreaterThan(CARD_H);
  });
});

describe("列内排序", () => {
  it("同列无重叠(行距 >= 卡高+行缝)", () => {
    const g = applySnapshot(
      [
        node("g0", { kind: "goal", depth: 0, created_at: "2026-09-22T00:00:00Z" }),
        node("a1", { created_at: "2026-09-22T00:00:01Z" }),
        node("a2", { created_at: "2026-09-22T00:00:02Z" }),
        node("a3", { created_at: "2026-09-22T00:00:03Z" }),
      ],
      [edge("e1", "g0", "a1"), edge("e2", "g0", "a2"), edge("e3", "g0", "a3")],
    );
    const L = layoutGraph(g);
    const ys = ["a1", "a2", "a3"].map((id) => L.pos.get(id)!.y).sort((x, y) => x - y);
    for (let i = 1; i < ys.length; i++) {
      expect(ys[i] - ys[i - 1]).toBeGreaterThanOrEqual(CARD_H + ROW_GAP);
    }
  });

  it("重心排序减交叉:创建序会交叉的,重排后不交叉", () => {
    // 父列:p1(行0) p2(行1);子列创建序 c1(父 p2) 先于 c2(父 p1)——
    // 按创建序摆会交叉,重心排序应把 c2 放上面。
    const g = applySnapshot(
      [
        node("g0", { kind: "goal", depth: 0, created_at: "2026-09-22T00:00:00Z" }),
        node("p1", { created_at: "2026-09-22T00:00:01Z" }),
        node("p2", { created_at: "2026-09-22T00:00:02Z" }),
        node("c1", { created_at: "2026-09-22T00:00:03Z" }), // 父 p2(下行)
        node("c2", { created_at: "2026-09-22T00:00:04Z" }), // 父 p1(上行)
      ],
      [
        edge("e1", "g0", "p1"),
        edge("e2", "g0", "p2"),
        edge("e3", "p2", "c1"),
        edge("e4", "p1", "c2"),
      ],
    );
    const L = layoutGraph(g);
    expect(L.pos.get("p1")!.row).toBeLessThan(L.pos.get("p2")!.row);
    expect(L.pos.get("c2")!.row).toBeLessThan(L.pos.get("c1")!.row);
  });

  it("主机泳道:同 host_scope 列内相邻", () => {
    const g = applySnapshot(
      [
        node("g0", { kind: "goal", depth: 0, created_at: "2026-09-22T00:00:00Z" }),
        node("h1", { host_scope: "web-1", created_at: "2026-09-22T00:00:01Z" }),
        node("x1", { host_scope: "db-1", created_at: "2026-09-22T00:00:02Z" }),
        node("h2", { host_scope: "web-1", created_at: "2026-09-22T00:00:03Z" }),
        node("x2", { created_at: "2026-09-22T00:00:04Z" }), // 无主机域,落自己位
      ],
      [
        edge("e1", "g0", "h1"),
        edge("e2", "g0", "x1"),
        edge("e3", "g0", "h2"),
        edge("e4", "g0", "x2"),
      ],
    );
    const L = layoutGraph(g, { groupByHost: true });
    const rows = ["h1", "x1", "h2", "x2"].map((id) => L.pos.get(id)!.row);
    const rh1 = rows[0];
    const rh2 = rows[2];
    expect(Math.abs(rh1 - rh2)).toBe(1); // web-1 两张相邻
    // 无主机域的不被拉进组
    const scopes = ["h1", "x1", "h2", "x2"]
      .slice()
      .sort((a, b) => L.pos.get(a)!.row - L.pos.get(b)!.row)
      .map((id) => g.nodes[id].host_scope || "-");
    expect(scopes.join(",")).toMatch(/web-1,web-1/);
    expect(rows.length).toBe(4);
  });
});

describe("稳健性", () => {
  it("空图不炸", () => {
    const L = layoutGraph(applySnapshot([], []));
    expect(L.pos.size).toBe(0);
    expect(L.width).toBe(0);
  });

  it("孤儿节点(无 goal/无边)落 0 列", () => {
    const g = applySnapshot(
      [node("s1", { created_at: "2026-09-22T00:00:01Z" }), node("s2", { created_at: "2026-09-22T00:00:02Z" })],
      [],
    );
    const L = layoutGraph(g);
    expect(L.pos.get("s1")!.depth).toBe(0);
    expect(L.pos.get("s2")!.depth).toBe(0);
    expect(L.pos.get("s1")!.y).not.toBe(L.pos.get("s2")!.y);
  });

  it("树边成环不挂死,全节点有坐标", () => {
    const g = applySnapshot(
      [
        node("a1", { created_at: "2026-09-22T00:00:01Z" }),
        node("a2", { created_at: "2026-09-22T00:00:02Z" }),
        node("a3", { created_at: "2026-09-22T00:00:03Z" }),
      ],
      [edge("e1", "a1", "a2"), edge("e2", "a2", "a3"), edge("e3", "a3", "a1")],
    );
    const L = layoutGraph(g);
    expect(L.pos.size).toBe(3);
    for (const p of L.pos.values()) {
      expect(Number.isFinite(p.x)).toBe(true);
      expect(Number.isFinite(p.y)).toBe(true);
    }
  });

  it("确定性:同图两次布局逐坐标一致", () => {
    const mk = () =>
      applySnapshot(
        [
          node("g0", { kind: "goal", depth: 0, created_at: "2026-09-22T00:00:00Z" }),
          node("a1", { created_at: "2026-09-22T00:00:01Z" }),
          node("a2", { created_at: "2026-09-22T00:00:02Z" }),
        ],
        [edge("e1", "g0", "a1"), edge("e2", "g0", "a2")],
      );
    const l1 = layoutGraph(mk());
    const l2 = layoutGraph(mk());
    for (const [id, p] of l1.pos) {
      expect(l2.pos.get(id)).toEqual(p);
    }
  });
});

describe("孤儿右移(goal 独占最左列)", () => {
  it("规则播种根意图(不连 goal)整组右移一列;hint 孤儿留最左", () => {
    const g = applySnapshot(
      [
        node("g0", { kind: "goal", depth: 0, created_at: "2026-09-22T00:00:00Z" }),
        node("a1", { created_at: "2026-09-22T00:00:01Z" }), // goal 派生
        node("r1", { created_at: "2026-09-22T00:00:02Z" }), // 孤儿根意图
        node("r2", { created_at: "2026-09-22T00:00:03Z" }), // 孤儿子意图
        node("h1", { kind: "hint", created_at: "2026-09-22T00:00:04Z" }), // 孤儿线索
      ],
      [edge("e1", "g0", "a1"), edge("e2", "r1", "r2")],
    );
    const L = layoutGraph(g);
    expect(L.pos.get("g0")!.depth).toBe(0);
    expect(L.pos.get("a1")!.depth).toBe(1);
    expect(L.pos.get("r1")!.depth).toBe(1); // 0 → 1
    expect(L.pos.get("r2")!.depth).toBe(2); // 1 → 2(整组联动)
    expect(L.pos.get("h1")!.depth).toBe(0); // hint 与 goal 同列(起点/提示最左)
    expect(L.pos.get("r1")!.x).toBeGreaterThan(L.pos.get("g0")!.x);
  });

  it("无 goal 时孤儿不右移", () => {
    const g = applySnapshot(
      [node("s1", { created_at: "2026-09-22T00:00:01Z" })],
      [],
    );
    expect(layoutGraph(g).pos.get("s1")!.depth).toBe(0);
  });
});

describe("edgePath 贝塞尔", () => {
  it("正向边:右缘中点 → 左缘中点,中点落在两列之间", () => {
    const { d, mx, my } = edgePath({ x: 0, y: 0 }, { x: CARD_W + COL_GAP, y: 100 });
    expect(d.startsWith(`M ${CARD_W} ${CARD_H / 2}`)).toBe(true);
    expect(d.endsWith(`${CARD_W + COL_GAP} ${100 + CARD_H / 2}`)).toBe(true);
    expect(mx).toBeGreaterThan(CARD_W);
    expect(mx).toBeLessThan(CARD_W + COL_GAP);
    expect(my).toBeCloseTo((0 + 100) / 2 + CARD_H / 2, 1);
  });

  it("反向边(proves 右→左)也出合法曲线,不 NaN", () => {
    const { d, mx, my } = edgePath({ x: 800, y: 200 }, { x: 24, y: 0 });
    expect(d).not.toMatch(/NaN/);
    expect(Number.isFinite(mx)).toBe(true);
    expect(Number.isFinite(my)).toBe(true);
  });
});

// 字段缺失防御(探索链路白屏事故后立):created_at 缺失的节点进布局
// 不许抛异常(空串兜底排序),保证整树不崩、坐标照常产出。
describe("字段缺失防御", () => {
  it("created_at 缺失不崩,坐标照常", () => {
    const bad = node("a1");
    delete (bad as Partial<IntentNode>).created_at;
    const g = applySnapshot(
      [node("g0", { kind: "goal", depth: 0 }), bad],
      [edge("e1", "g0", "a1")],
    );
    let L: ReturnType<typeof layoutGraph> | null = null;
    expect(() => {
      L = layoutGraph(g);
    }).not.toThrow();
    expect(L!.pos.get("a1")).toBeTruthy();
    expect(L!.pos.get("g0")!.depth).toBe(0);
  });
});
