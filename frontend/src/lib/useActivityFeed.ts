// useActivityFeed:播报板数据源(0.23.0-live-feed)。
//   - 实时主路:EventSource 订阅意图图 SSE(与探索链路同端点),只收 feed
//     帧,序号取 lastEventId;断线浏览器自动重连(游标回放由服务端兜底);
//   - 轮询兜底:8s 一次 GET .../activity?since=<lastSeq>(首连回填 +
//     断缝补帧),与 SSE 帧按 seq 签名去重合并(mergeFeed)。
// 挂在案件页右栏(播报板面板内);切 tab 不拆流(面板常驻)。
import { useEffect, useRef, useState } from "react";
import { api } from "./api";
import { emptyFeed, mergeFeed, type FeedItem, type FeedState } from "./feed";

export interface ActivityFeedLive {
  feed: FeedState;
  connected: boolean; // SSE 在流(如实;断开重连间隙/无 EventSource 为 false)
}

export function useActivityFeed(caseId: string): ActivityFeedLive {
  const [feed, setFeed] = useState<FeedState>(emptyFeed);
  const [connected, setConnected] = useState(false);
  const lastSeqRef = useRef(0);

  useEffect(() => {
    setFeed(emptyFeed);
    setConnected(false);
    lastSeqRef.current = 0;
    let stop = false;

    const apply = (incoming: FeedItem[]) => {
      setFeed((s) => {
        const n = mergeFeed(s, incoming);
        if (n.lastSeq > lastSeqRef.current) lastSeqRef.current = n.lastSeq;
        return n;
      });
    };

    // 实时主路:SSE feed 帧(序号在 lastEventId 行)
    let es: EventSource | null = null;
    if (typeof EventSource !== "undefined") {
      es = new EventSource(`/api/cases/${caseId}/intents/events`);
      es.addEventListener("feed", (ev) => {
        try {
          const d = JSON.parse((ev as MessageEvent).data) as Omit<FeedItem, "seq">;
          const seq = Number((ev as MessageEvent).lastEventId) || 0;
          apply([{ ...d, seq }]);
        } catch {
          /* 坏帧如实跳过,轮询兜底补 */
        }
      });
      es.onopen = () => setConnected(true);
      es.onerror = () => setConnected(false); // 浏览器自动重连(游标回放)
    }

    // 轮询兜底:首连回填(since=0 取回放缓冲存量)+ 断缝补帧
    const poll = async () => {
      try {
        const d = await api.get<{ items: FeedItem[] }>(
          `/api/cases/${caseId}/activity?since=${lastSeqRef.current}`,
        );
        if (!stop) apply(d.items || []);
      } catch {
        /* 兜底失败不挡面板;下个周期再试 */
      }
    };
    void poll();
    const timer = setInterval(poll, 8000);

    return () => {
      stop = true;
      es?.close();
      clearInterval(timer);
    };
  }, [caseId]);

  return { feed, connected };
}
