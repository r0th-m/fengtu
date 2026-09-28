// 上传流状态机测试(fake 依赖打全链:成功/摄入失败/案件未找到)。
import { describe, expect, it } from "vitest";
import { idleState, UploadFlow, UploadDeps, UploadState } from "./uploadFlow";
import type { Task } from "./types";

function makeFile(name = "Forensic_1.2.3.4_HOST.zip", size = 1024): File {
  return new File([new Uint8Array(size)], name, { type: "application/zip" });
}

function makeDeps(over: Partial<UploadDeps> = {}): {
  deps: UploadDeps;
  taskCbs: ((t: Task) => void)[];
} {
  const taskCbs: ((t: Task) => void)[] = [];
  const deps: UploadDeps = {
    hashFile: async (_f, onp) => {
      onp?.(512, 1024);
      onp?.(1024, 1024);
      return "a".repeat(64);
    },
    initUpload: async () => ({ upload_id: "up-1", chunk_size: 512 }),
    putChunk: async () => {},
    completeUpload: async () => ({ task_id: "task-1" }),
    watchTask: (_id, cb) => {
      taskCbs.push(cb);
      return () => {};
    },
    findCaseIdByName: async () => "case-1",
    ...over,
  };
  return { deps, taskCbs };
}

function runTask(cbs: ((t: Task) => void)[], status: string, extra: Partial<Task> = {}) {
  for (const cb of cbs) {
    cb({ id: "task-1", kind: "ingest", status, progress: "包摄入中(3/9)",
      created_at: "", ...extra } as Task);
  }
}

async function flush() {
  // 等微任务链(状态机 await 链)走完
  for (let i = 0; i < 20; i++) await Promise.resolve();
}

// waitStage 轮询等到目标阶段(FileReader 是宏任务,微任务 flush 等不到)。
async function waitStage(flow: UploadFlow, stage: string, ms = 3000) {
  const t0 = Date.now();
  while (flow.state.stage !== stage && flow.state.stage !== "failed") {
    if (Date.now() - t0 > ms) throw new Error(`等阶段 ${stage} 超时,停在 ${flow.state.stage}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

describe("UploadFlow 状态机", () => {
  it("成功链:hashing → init → uploading → ingesting → done(case_id)", async () => {
    const { deps, taskCbs } = makeDeps();
    const seen: string[] = [];
    const flow = new UploadFlow(deps, (s: UploadState) => seen.push(s.stage));
    const p = flow.start(makeFile());
    await waitStage(flow, "ingesting");
    expect(flow.state.stage).toBe("ingesting"); // 等任务终态
    runTask(taskCbs, "running");
    runTask(taskCbs, "done");
    await p;
    expect(flow.state.stage).toBe("done");
    expect(flow.state.caseId).toBe("case-1");
    // 阶段序列:hashing 必先于 uploading 必先于 ingesting
    const order = ["hashing", "init", "uploading", "ingesting", "done"];
    const filtered = seen.filter((s) => order.includes(s));
    expect(filtered).toEqual([...filtered].sort(
      (a, b) => order.indexOf(a) - order.indexOf(b)));
    expect(flow.state.taskId).toBe("task-1");
  });

  it("分块数按 chunk_size 上取整,百分比单调", async () => {
    const putSizes: number[] = [];
    const { deps, taskCbs } = makeDeps({
      putChunk: async (_u, i) => {
        putSizes.push(i);
      },
    });
    const pcts: number[] = [];
    const flow = new UploadFlow(deps, (s) => {
      if (s.stage === "uploading") pcts.push(s.percent);
    });
    const p = flow.start(makeFile("a.zip", 1025)); // 3 块(512+512+1)
    await waitStage(flow, "ingesting");
    expect(putSizes).toEqual([0, 1, 2]);
    expect(pcts).toEqual([...pcts].sort((a, b) => a - b));
    runTask(taskCbs, "done");
    await p;
    expect(flow.state.stage).toBe("done");
  });

  it("摄入任务失败 → failed,错误如实带后端原文", async () => {
    const { deps, taskCbs } = makeDeps();
    const flow = new UploadFlow(deps, () => {});
    const p = flow.start(makeFile());
    await waitStage(flow, "ingesting");
    runTask(taskCbs, "failed", { err: "哈希清单契约失配(missing=2),拒收" });
    await p;
    expect(flow.state.stage).toBe("failed");
    expect(flow.state.error).toContain("哈希清单契约失配");
  });

  it("摄入 done 但案件查无 → failed(如实,不装成功)", async () => {
    const { deps, taskCbs } = makeDeps({ findCaseIdByName: async () => null });
    const flow = new UploadFlow(deps, () => {});
    const p = flow.start(makeFile("casehost-a.zip"));
    await waitStage(flow, "ingesting");
    runTask(taskCbs, "done");
    await p;
    expect(flow.state.stage).toBe("failed");
    expect(flow.state.error).toContain("casehost-a");
  });

  it("哈希阶段抛错 → failed;reset 回 idle", async () => {
    const { deps } = makeDeps({
      hashFile: async () => {
        throw new Error("读文件失败");
      },
    });
    const flow = new UploadFlow(deps, () => {});
    await flow.start(makeFile());
    await waitStage(flow, "failed");
    expect(flow.state.stage).toBe("failed");
    expect(flow.state.error).toBe("读文件失败");
    flow.reset();
    expect(flow.state).toEqual(idleState);
  });

  it("案件名 = 文件名去扩展", () => {
    expect(UploadFlow.caseNameFromFile("Forensic_10.0.0.1_HOST-A.zip")).toBe(
      "Forensic_10.0.0.1_HOST-A");
    expect(UploadFlow.caseNameFromFile("casehost-a.zip")).toBe("casehost-a");
    expect(UploadFlow.caseNameFromFile("plain")).toBe("plain");
  });
});
