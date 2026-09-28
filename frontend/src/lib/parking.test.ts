// 停车场呈现助手(0.24.0)焊死:分区/标签/归属建议文案。
import { describe, expect, it } from "vitest";
import {
  PARKING_STATUS_LABEL,
  PARK_REASON_LABEL,
  splitParking,
  suggestText,
  type ParkingEntry,
} from "./parking";

function entry(id: string, status: string, extra?: Partial<ParkingEntry>): ParkingEntry {
  return {
    id, case_id: "c1", node_id: "n-" + id, text: "线索" + id,
    reason: "budget_fanout", status, created_by: "ai",
    created_at: "2026-09-26T00:00:00Z", ...extra,
  };
}

describe("splitParking 待处置/已处置分区", () => {
  it("parked 进待处置,deployed/dismissed 进留痕,顺序保持", () => {
    const { parked, decided } = splitParking([
      entry("1", "parked"), entry("2", "deployed"), entry("3", "parked"), entry("4", "dismissed"),
    ]);
    expect(parked.map((p) => p.id)).toEqual(["1", "3"]);
    expect(decided.map((p) => p.id)).toEqual(["2", "4"]);
  });
  it("空/缺数组不崩", () => {
    const { parked, decided } = splitParking(undefined as unknown as ParkingEntry[]);
    expect(parked).toEqual([]);
    expect(decided).toEqual([]);
  });
});

describe("suggestText 归属建议文案", () => {
  it("有标签用标签;新开章(无 goal)如实标;标签缺而 goal 在=如实降级", () => {
    expect(suggestText(entry("1", "parked", { suggest_label: "章一" }))).toBe("章一");
    expect(suggestText(entry("2", "parked"))).toBe("建议新开章");
    expect(suggestText(entry("3", "parked", { suggest_goal_id: "g-9" })))
      .toBe("(章已删除,仅剩 id)");
  });
});

describe("标签表", () => {
  it("四种转入原因 + 三种处置状态都有中文标", () => {
    for (const k of ["budget_fanout", "budget_chapter", "budget_case", "park_lead"]) {
      expect(PARK_REASON_LABEL[k]).toBeTruthy();
    }
    for (const k of ["parked", "deployed", "dismissed"]) {
      expect(PARKING_STATUS_LABEL[k]).toBeTruthy();
    }
  });
});
