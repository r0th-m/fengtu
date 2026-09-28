// 上传流状态机(hero 拖拽区核心,纯逻辑可测):
//
//   hashing(本地算 SHA-256 对账码) → init(开上传会话)
//   → uploading(按块 PUT) → ingesting(服务端摄入任务,SSE 进度)
//   → done(case_id) | failed
//
// 纪律:零黑盒转圈——每个阶段都有可读进度文案;失败如实带后端原文。
// 依赖全部注入(哈希/请求/任务订阅),vitest 用 fake 打全状态机。

import type { Task } from "./types";
import { blobToArrayBuffer } from "./sha256";

export type UploadStage =
  | "idle"
  | "hashing"
  | "init"
  | "uploading"
  | "ingesting"
  | "done"
  | "failed";

export interface UploadState {
  stage: UploadStage;
  fileName: string;
  sha256: string; // 全文件对账码(hashing 完成后;向导包卡展示用)
  progress: string; // 人读进度文案(零黑盒转圈)
  percent: number; // 0..100(仅 hashing/uploading 有确定百分比)
  taskId: string; // 摄入任务 id(ingesting 起)
  caseId: string;
  error: string;
}

export const idleState: UploadState = {
  stage: "idle",
  fileName: "",
  sha256: "",
  progress: "",
  percent: 0,
  taskId: "",
  caseId: "",
  error: "",
};

export interface UploadDeps {
  hashFile: (file: Blob, onProgress?: (done: number, total: number) => void) => Promise<string>;
  initUpload: (body: {
    case_name: string;
    filename: string;
    size: number;
    sha256: string;
  }) => Promise<{ upload_id: string; chunk_size: number }>;
  putChunk: (uploadId: string, index: number, data: ArrayBuffer) => Promise<void>;
  completeUpload: (uploadId: string) => Promise<{ task_id: string }>;
  watchTask: (taskId: string, onTask: (t: Task) => void) => () => void; // 返回退订
  findCaseIdByName: (name: string) => Promise<string | null>;
}

export class UploadFlow {
  state: UploadState = { ...idleState };
  private unwatch: (() => void) | null = null;

  constructor(
    private deps: UploadDeps,
    private onChange: (s: UploadState) => void,
  ) {}

  private set(patch: Partial<UploadState>) {
    this.state = { ...this.state, ...patch };
    this.onChange(this.state);
  }

  // caseNameFromFile 案件名 = 文件名去扩展(后端 EnsureCase 同名复用)。
  static caseNameFromFile(name: string): string {
    return name.replace(/\.(zip|tar|gz|tgz|log|txt|evtx)$/i, "");
  }

  async start(file: File, caseName?: string): Promise<void> {
    if (this.state.stage !== "idle" && this.state.stage !== "done" && this.state.stage !== "failed") {
      return; // 已在流程中,不并发
    }
    // 案件名:显式传入(新建任务向导——多包挂同一任务)优先;
    // 缺省 = 文件名去扩展(hero 拖拽区,后端 EnsureCase 同名复用)。
    const caseNameEff = caseName?.trim() || UploadFlow.caseNameFromFile(file.name);
    this.set({ ...idleState, stage: "hashing", fileName: file.name,
      progress: `本地计算 SHA-256 对账码: ${file.name}` });
    try {
      const sha256 = await this.deps.hashFile(file, (done, total) => {
        this.set({
          percent: Math.round((done / Math.max(total, 1)) * 100),
          progress: `本地计算 SHA-256 对账码(${Math.round((done / Math.max(total, 1)) * 100)}%)`,
        });
      });

      this.set({ stage: "init", sha256, progress: "开启上传会话", percent: 0 });
      const meta = await this.deps.initUpload({
        case_name: caseNameEff, filename: file.name, size: file.size, sha256,
      });

      const total = Math.max(1, Math.ceil(file.size / meta.chunk_size));
      this.set({ stage: "uploading", progress: `分块上传中(0/${total})` });
      for (let i = 0; i < total; i++) {
        const off = i * meta.chunk_size;
        const buf = await blobToArrayBuffer(file.slice(off, off + meta.chunk_size));
        await this.deps.putChunk(meta.upload_id, i, buf);
        this.set({
          percent: Math.round(((i + 1) / total) * 100),
          progress: `分块上传中(${i + 1}/${total})`,
        });
      }

      this.set({ stage: "ingesting", progress: "齐块对账,派发摄入任务" });
      const { task_id } = await this.deps.completeUpload(meta.upload_id);
      this.set({ taskId: task_id, progress: "摄入任务进行中" });

      await new Promise<void>((resolve, reject) => {
        this.unwatch = this.deps.watchTask(task_id, (t) => {
          if (t.status === "running") {
            this.set({ progress: t.progress || "摄入任务进行中" });
            return;
          }
          this.unwatch?.();
          this.unwatch = null;
          if (t.status === "done") {
            resolve();
          } else {
            reject(new Error(t.err || "摄入任务失败"));
          }
        });
      });

      const caseId = await this.deps.findCaseIdByName(caseNameEff);
      if (!caseId) {
        throw new Error(`摄入完成但未找到案件「${caseNameEff}」(如实)`);
      }
      this.set({ stage: "done", caseId, progress: "摄入完成", percent: 100 });
    } catch (e) {
      this.unwatch?.();
      this.unwatch = null;
      this.set({ stage: "failed", error: e instanceof Error ? e.message : String(e),
        progress: "上传流失败" });
    }
  }

  reset() {
    this.unwatch?.();
    this.unwatch = null;
    this.set({ ...idleState });
  }
}
