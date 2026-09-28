// AI 文本锚点解析:SystemPrompt 要求模型报「源 source_id + 行号 line_no」。
// 自由文本里捞锚点:已知 source_id(UUID)出现处,向后 120 字符内找行号
// (行 123 / line 123 / :123 / L123 / line_no=123)。找不到行号不造锚(防臆造,
// 与 prompt 同纪律:没有锚点的话不许有)。

export interface Anchor {
  sourceId: string;
  lineNo: number;
  raw: string; // 原文片段(chip 悬停用)
}

const LINE_RE = /(?:line_no|line|lines|行号|行)\s*[:=]?\s*#?(\d{1,9})|[:#L](\d{1,9})\b/i;

export function extractAnchors(text: string, knownSourceIds: string[]): Anchor[] {
  const out: Anchor[] = [];
  const seen = new Set<string>();
  for (const sid of knownSourceIds) {
    let from = 0;
    for (;;) {
      const idx = text.indexOf(sid, from);
      if (idx < 0) break;
      from = idx + sid.length;
      const window = text.slice(idx + sid.length, idx + sid.length + 120);
      const m = window.match(LINE_RE);
      const num = m ? m[1] || m[2] : null;
      if (!num) continue;
      const lineNo = parseInt(num, 10);
      if (lineNo < 1) continue;
      const key = `${sid}:${lineNo}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ sourceId: sid, lineNo, raw: m![0].trim() });
    }
  }
  return out;
}
