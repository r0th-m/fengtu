// useIntentGraph:案件意图图 SSE 订阅(快照 + 增量;断线自动重连拿新快照)。
// 挂在案件页层级——切 tab 不拆流,审批铃铛与意图图共用同一份活态。
import { useEffect, useState } from "react";
import {
  applyChange,
  applySnapshot,
  emptyGraph,
  type GraphState,
  type IntentEdge,
  type IntentNode,
} from "./intent";

export interface IntentGraphLive {
  graph: GraphState;
  connected: boolean; // SSE 在流(如实;断开重连间隙为 false)
}

export function useIntentGraph(caseId: string): IntentGraphLive {
  const [graph, setGraph] = useState<GraphState>(emptyGraph);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    setGraph(emptyGraph);
    setConnected(false);
    const es = new EventSource(`/api/cases/${caseId}/intents/events`);
    es.addEventListener("snapshot", (ev) => {
      try {
        const d = JSON.parse((ev as MessageEvent).data) as {
          nodes: IntentNode[];
          edges: IntentEdge[];
        };
        setGraph(applySnapshot(d.nodes, d.edges));
        setConnected(true);
      } catch {
        /* 坏帧如实跳过,后续增量帧/重连快照对齐 */
      }
    });
    for (const kind of ["node_added", "node_updated", "edge_added"] as const) {
      es.addEventListener(kind, (ev) => {
        try {
          const payload = JSON.parse((ev as MessageEvent).data);
          setGraph((g) => applyChange(g, kind, payload));
        } catch {
          /* 同上 */
        }
      });
    }
    es.onerror = () => setConnected(false); // 浏览器自动重连,重连即新快照
    return () => es.close();
  }, [caseId]);

  return { graph, connected };
}
