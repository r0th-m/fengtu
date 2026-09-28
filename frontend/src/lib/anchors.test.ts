// 锚点解析:已知 source_id + 邻近行号 → chip;无行号不造锚(防臆造)。
import { describe, expect, it } from "vitest";
import { extractAnchors } from "./anchors";

const S1 = "11111111-2222-3333-4444-555555555555";
const S2 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

describe("extractAnchors", () => {
  it("source_id + 「行 123」→ 锚", () => {
    const text = `在源 ${S1} 行 4217 发现可疑登录。`;
    expect(extractAnchors(text, [S1])).toEqual([
      { sourceId: S1, lineNo: 4217, raw: "行 4217" },
    ]);
  });

  it("支持 line 42 / :42 / line_no=42 / L42 形态", () => {
    for (const [frag, want] of [
      [`${S1} line 42`, 42],
      [`${S1}:987`, 987],
      [`${S1} line_no=65535`, 65535],
      [`${S1} L77`, 77],
    ] as const) {
      const got = extractAnchors(frag as string, [S1]);
      expect(got.length).toBe(1);
      expect(got[0].lineNo).toBe(want);
    }
  });

  it("无行号不造锚;未知 source_id 不造锚", () => {
    expect(extractAnchors(`源 ${S1} 有可疑内容`, [S1])).toEqual([]);
    expect(extractAnchors(`源 ${S2} 行 5`, [S1])).toEqual([]);
  });

  it("多个锚去重;行号 0 不收", () => {
    const text = `${S1} 行 10 与 ${S1} 行 10,另有 ${S2}:30,以及 ${S1} 行 0`;
    const got = extractAnchors(text, [S1, S2]);
    expect(got).toHaveLength(2);
    expect(got.map((a) => a.lineNo).sort((a, b) => a - b)).toEqual([10, 30]);
  });
});
