// 活动流(工作台右栏):最近任务 + 审计链里的裁决/意图/上传/分析动态。
// 数据:/api/tasks(进程内存账,如实标注重启即空)+ /api/audit/chain?limit=60。
import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { AuditEntry, Task } from "../lib/types";

const ACTION_LABEL: Record<string, string> = {
  "hit.verdict": "裁决",
  "analyze.run": "一键分析",
  "scan.run": "扫描",
  "upload.completed": "上传",
  "upload.rejected": "上传拒收",
  "ai.session.create": "AI 会话",
  "ai.message": "AI 对话",
  "ai.tool_call": "AI 工具",
  "source.detect": "格式改判",
  "source.reparse": "重解析",
  "intent.start": "意图启动",
  "intent.finish": "意图收尾",
  "intent.approve": "意图批准",
  "intent.reject": "意图驳回",
  "intent.stop": "意图停止",
};

function taskLabel(t: Task): string {
  const kind: Record<string, string> = {
    ingest: "摄入",
    scan: "扫描",
    analyze: "一键分析",
    parse: "改判解析",
  };
  return kind[t.kind] || t.kind;
}

export default function ActivityFeed() {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [entries, setEntries] = useState<AuditEntry[]>([]);

  useEffect(() => {
    let stop = false;
    async function load() {
      try {
        const [t, a] = await Promise.all([
          api.get<{ tasks: Task[] }>("/api/tasks"),
          api.get<{ entries: AuditEntry[] }>("/api/audit/chain?limit=60"),
        ]);
        if (stop) return;
        setTasks([...t.tasks].reverse().slice(0, 8));
        setEntries(
          a.entries
            .filter((e) => e.Action !== "auth.login" && e.Action !== "auth.logout")
            .slice(-12)
            .reverse(),
        );
      } catch {
        /* 活动流失败不挡主页面;下次轮询再试 */
      }
    }
    void load();
    const timer = setInterval(load, 5000);
    return () => {
      stop = true;
      clearInterval(timer);
    };
  }, []);

  return (
    <aside className="space-y-4">
      <section className="rounded-card bg-white shadow-card p-4">
        <h3 className="text-sm font-medium mb-3">最近任务</h3>
        {tasks.length === 0 && (
          <div className="text-xs text-mute leading-relaxed">
            暂无任务账(任务台账为进程内存态,服务重启后清空——结果数据不受影响)
          </div>
        )}
        <ul className="space-y-2">
          {tasks.map((t) => (
            <li key={t.id} className="text-xs leading-relaxed">
              <span
                className={`inline-block w-1.5 h-1.5 rounded-full mr-1.5 align-middle ${
                  t.status === "done"
                    ? "bg-brand"
                    : t.status === "failed"
                      ? "bg-red-500"
                      : "bg-amber-400 animate-pulse"
                }`}
              />
              <span className="font-medium">{taskLabel(t)}</span>
              <span className="text-mute ml-1.5">
                {t.status === "running" ? t.progress || "进行中" : t.status === "done" ? "完成" : t.err || "失败"}
              </span>
            </li>
          ))}
        </ul>
      </section>
      <section className="rounded-card bg-white shadow-card p-4">
        <h3 className="text-sm font-medium mb-3">动态(审计链)</h3>
        {entries.length === 0 && <div className="text-xs text-mute">暂无动态</div>}
        <ul className="space-y-2">
          {entries.map((e) => (
            <li key={e.Seq} className="text-xs leading-relaxed">
              <span className="inline-block rounded bg-brand-light text-brand px-1.5 py-0.5 mr-1.5 text-[11px]">
                {ACTION_LABEL[e.Action] || e.Action}
              </span>
              <span className="text-mute">
                {e.Actor} · {new Date(e.TS).toLocaleString("zh-CN", { hour12: false })}
              </span>
              {e.Action === "hit.verdict" && (
                <span className="block text-mute mt-0.5 truncate" title={e.DetailJSON}>
                  {formatVerdict(e.DetailJSON)}
                </span>
              )}
            </li>
          ))}
        </ul>
      </section>
    </aside>
  );
}

function formatVerdict(detailJSON: string): string {
  try {
    const d = JSON.parse(detailJSON);
    return `${d.rule_id ?? ""} ${d.status === "accepted" ? "→ 接受" : d.status === "rejected" ? "→ 排除" : ""}`;
  } catch {
    return "";
  }
}
