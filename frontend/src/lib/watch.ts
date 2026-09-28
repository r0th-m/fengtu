// watchTask 生产实现:EventSource 订 /api/tasks/{id}/events(快照式流,
// 终态帧后服务端关闭)。退订 = close。
import type { Task } from "./types";

export function watchTask(taskId: string, onTask: (t: Task) => void): () => void {
  const es = new EventSource(`/api/tasks/${taskId}/events`);
  es.onmessage = (ev) => {
    try {
      onTask(JSON.parse(ev.data) as Task);
    } catch {
      /* 坏帧如实跳过,终态帧不丢(服务端快照重发) */
    }
  };
  return () => es.close();
}
