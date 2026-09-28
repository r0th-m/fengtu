// 增量 SHA-256(纯 TS):浏览器 crypto.subtle 只能整段一次性算,
// 大文件会整读进内存;上传对账需要全文件哈希,这里按块喂。
// 实现照 FIPS 180-4,单测焊死已知向量(abc / 百万 a / 空串)。

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));

export class Sha256 {
  private h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  private buf = new Uint8Array(64);
  private bufLen = 0;
  private total = 0;

  update(data: Uint8Array): void {
    this.total += data.length;
    let off = 0;
    if (this.bufLen > 0) {
      const need = 64 - this.bufLen;
      const take = Math.min(need, data.length);
      this.buf.set(data.subarray(0, take), this.bufLen);
      this.bufLen += take;
      off += take;
      if (this.bufLen === 64) {
        this.compress(this.buf);
        this.bufLen = 0;
      }
    }
    while (off + 64 <= data.length) {
      this.compress(data.subarray(off, off + 64));
      off += 64;
    }
    if (off < data.length) {
      this.buf.set(data.subarray(off), 0);
      this.bufLen = data.length - off;
    }
  }

  private compress(block: Uint8Array): void {
    const w = new Uint32Array(64);
    for (let i = 0; i < 16; i++) {
      w[i] =
        (block[i * 4] << 24) |
        (block[i * 4 + 1] << 16) |
        (block[i * 4 + 2] << 8) |
        block[i * 4 + 3];
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = this.h;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    this.h[0] = (this.h[0] + a) >>> 0;
    this.h[1] = (this.h[1] + b) >>> 0;
    this.h[2] = (this.h[2] + c) >>> 0;
    this.h[3] = (this.h[3] + d) >>> 0;
    this.h[4] = (this.h[4] + e) >>> 0;
    this.h[5] = (this.h[5] + f) >>> 0;
    this.h[6] = (this.h[6] + g) >>> 0;
    this.h[7] = (this.h[7] + h) >>> 0;
  }

  hexDigest(): string {
    const bitLenHi = Math.floor(this.total / 0x20000000);
    const bitLenLo = (this.total << 3) >>> 0;
    this.update(new Uint8Array([0x80]));
    while (this.bufLen !== 56) {
      this.update(new Uint8Array([0]));
    }
    const lenBlock = new Uint8Array(8);
    new DataView(lenBlock.buffer).setUint32(0, bitLenHi);
    new DataView(lenBlock.buffer).setUint32(4, bitLenLo);
    this.update(lenBlock);
    let out = "";
    for (const v of this.h) out += v.toString(16).padStart(8, "0");
    return out;
  }
}

// blobToArrayBuffer 读 Blob 为 ArrayBuffer;优先原生 arrayBuffer(),
// 无实现的宿主(老浏览器/jsdom)回退 FileReader。
export function blobToArrayBuffer(b: Blob): Promise<ArrayBuffer> {
  if (typeof b.arrayBuffer === "function") return b.arrayBuffer();
  return new Promise((resolve, reject) => {
    const fr = new FileReader();
    fr.onload = () => resolve(fr.result as ArrayBuffer);
    fr.onerror = () => reject(fr.error ?? new Error("FileReader 读失败"));
    fr.readAsArrayBuffer(b);
  });
}

// hashFile 按 8MB 块流式算文件 SHA-256(hex)。
export async function hashFile(
  file: Blob,
  onProgress?: (done: number, total: number) => void,
): Promise<string> {
  const h = new Sha256();
  const CHUNK = 8 * 1024 * 1024;
  let off = 0;
  while (off < file.size) {
    const slice = file.slice(off, Math.min(off + CHUNK, file.size));
    h.update(new Uint8Array(await blobToArrayBuffer(slice)));
    off += slice.size;
    onProgress?.(off, file.size);
  }
  return h.hexDigest();
}
