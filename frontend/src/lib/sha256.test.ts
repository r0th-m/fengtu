// SHA-256 增量实现:FIPS 已知向量 + 分块喂入等价性焊死。
import { describe, expect, it } from "vitest";
import { Sha256, hashFile } from "./sha256";

function hex(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

describe("Sha256", () => {
  it("空串 / abc / 56 字节(边界)已知向量", () => {
    const cases: [string, string][] = [
      ["", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
      ["abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"],
      [
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
      ],
    ];
    for (const [input, want] of cases) {
      const h = new Sha256();
      h.update(hex(input));
      expect(h.hexDigest()).toBe(want);
    }
  });

  it("百万个 a(经典向量)", () => {
    const h = new Sha256();
    const chunk = new Uint8Array(1000).fill(97);
    for (let i = 0; i < 1000; i++) h.update(chunk);
    expect(h.hexDigest()).toBe(
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  });

  it("分块喂入 == 整段喂入(含 64 字节块界不对齐)", () => {
    const data = new Uint8Array(1000);
    for (let i = 0; i < data.length; i++) data[i] = (i * 31 + 7) & 0xff;
    const whole = new Sha256();
    whole.update(data);
    const want = whole.hexDigest(); // digest 会写填充,只许算一次
    for (const step of [1, 7, 63, 64, 65, 200]) {
      const part = new Sha256();
      for (let off = 0; off < data.length; off += step) {
        part.update(data.subarray(off, Math.min(off + step, data.length)));
      }
      expect(part.hexDigest()).toBe(want);
    }
  });

  it("hashFile 对 Blob 流式算与整段一致", async () => {
    const data = new Uint8Array(20 * 1024 * 1024 + 123); // > 8MB 块,走多轮
    for (let i = 0; i < data.length; i++) data[i] = i & 0xff;
    const ref = new Sha256();
    ref.update(data);
    const got = await hashFile(new Blob([data]));
    expect(got).toBe(ref.hexDigest());
  });
});
