// SSE 工具:GET 走原生 EventSource(任务进度流);
// POST 流(AI 对话)走 fetch + ReadableStream 手工解析(EventSource 不支持 POST)。

export interface SseFrame {
  event: string;
  data: string;
}

// parseSseChunk 增量解析 SSE 文本流(跨块半行缓冲)。
// 返回完整帧;残余半帧留在 state.buf。
export interface SseState {
  buf: string;
}

export function parseSseChunk(state: SseState, chunk: string): SseFrame[] {
  state.buf += chunk;
  const frames: SseFrame[] = [];
  let idx: number;
  while ((idx = state.buf.indexOf("\n\n")) >= 0) {
    const raw = state.buf.slice(0, idx);
    state.buf = state.buf.slice(idx + 2);
    let event = "message";
    const dataLines: string[] = [];
    for (const line of raw.split("\n")) {
      if (line.startsWith("event:")) event = line.slice(6).trim();
      else if (line.startsWith("data:")) dataLines.push(line.slice(5).trimStart());
      // 心跳 ": ping" 与未知字段忽略
    }
    if (dataLines.length > 0 || event !== "message") {
      frames.push({ event, data: dataLines.join("\n") });
    }
  }
  return frames;
}

// postSse POST 请求并按 SSE 帧回调;abort 信号中断读取。
export async function postSse(
  path: string,
  body: unknown,
  onFrame: (f: SseFrame) => void,
  signal?: AbortSignal,
): Promise<void> {
  const resp = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    credentials: "same-origin",
    signal,
  });
  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`;
    try {
      msg = (await resp.json()).error || msg;
    } catch {
      /* 保留默认 */
    }
    throw new Error(msg);
  }
  if (!resp.body) throw new Error("响应无流式体");
  const reader = resp.body.getReader();
  const dec = new TextDecoder();
  const state: SseState = { buf: "" };
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    for (const f of parseSseChunk(state, dec.decode(value, { stream: true }))) {
      onFrame(f);
    }
  }
}
