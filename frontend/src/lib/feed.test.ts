// 播报归并(0.23.0-live-feed)焊死:seq 签名去重/保序/上限截断如实计数/
// 色点稳定/空输入不动。
import { describe, expect, it } from "vitest";
import {
  emptyFeed,
  FEED_CAP,
  feedDotColor,
  mergeFeed,
  type FeedItem,
} from "./feed";

function item(seq: number, text = `帧${seq}`): FeedItem {
  return { seq, tier: "progress", text, ts: "2026-09-26T00:00:00Z" };
}

describe("mergeFeed 播报归并", () => {
  it("追加按 seq 升序,lastSeq 取最大", () => {
    let s = mergeFeed(emptyFeed, [item(2), item(1)]);
    expect(s.items.map((i) => i.seq)).toEqual([1, 2]);
    expect(s.lastSeq).toBe(2);
    s = mergeFeed(s, [item(5), item(3)]);
    expect(s.items.map((i) => i.seq)).toEqual([1, 2, 3, 5]);
    expect(s.lastSeq).toBe(5);
  });

  it("签名(seq)去重:SSE 与轮询两路重复帧幂等", () => {
    let s = mergeFeed(emptyFeed, [item(1), item(2)]);
    s = mergeFeed(s, [item(2, "重复帧"), item(3)]);
    expect(s.items.map((i) => i.seq)).toEqual([1, 2, 3]);
    expect(s.items[1].text).toBe("帧2"); // 先到先得,不覆写
  });

  it("seq≤0 / 空文本帧不收;空批次返回原态", () => {
    const s = mergeFeed(emptyFeed, [
      { seq: 0, tier: "spawn", text: "无序号", ts: "" },
      { seq: 7, tier: "spawn", text: "", ts: "" },
    ]);
    expect(s.items).toEqual([]);
    expect(mergeFeed(s, [])).toBe(s);
    // seq>0 但空文本:帧序号仍推进游标(如实,不反复拉同一批)
    const s2 = mergeFeed(emptyFeed, [{ seq: 7, tier: "spawn", text: "", ts: "" }]);
    expect(s2.lastSeq).toBe(7);
  });

  it("上限截断:超 cap 丢最旧并累计 dropped(如实标注)", () => {
    const cap = 3;
    let s = mergeFeed(emptyFeed, [item(1), item(2), item(3)], cap);
    expect(s.dropped).toBe(0);
    s = mergeFeed(s, [item(4), item(5)], cap);
    expect(s.items.map((i) => i.seq)).toEqual([3, 4, 5]);
    expect(s.dropped).toBe(2);
    expect(s.lastSeq).toBe(5);
  });

  it("默认上限 FEED_CAP=500", () => {
    expect(FEED_CAP).toBe(500);
  });
});

describe("feedDotColor 意图关联色点", () => {
  it("同一 node_id 稳定同色,空 id 灰", () => {
    expect(feedDotColor("n-1")).toBe(feedDotColor("n-1"));
    expect(feedDotColor(undefined)).toBe("bg-slate-300");
    expect(feedDotColor("n-1")).toMatch(/^bg-/);
  });
});
