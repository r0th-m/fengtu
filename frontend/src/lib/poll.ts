// 轮询 + JSON 签名去重(交互改造切片二,照抄 ARTEX 数据流工程形态:
// 列表/头部 5-10s 轮询,签名相同不触发 onChange —— 重渲染不打断阅读/拖动)。
// 纯逻辑可测;组件层只管喂 fetcher 与渲染。

export interface PollOptions {
  fetcher: () => Promise<unknown>; // 拉数(返回任意可 JSON 化的数据)
  onChange: (data: unknown) => void; // 签名变化才回调(首轮必回调)
  onError?: (msg: string) => void; // 拉取失败如实上报(原文)
  intervalMs: number;
  immediate?: boolean; // 缺省 true:立即拉首轮
}

// startPolling 启动轮询,返回停止函数。单飞:上一趟未回不并发。
export function startPolling(opts: PollOptions): () => void {
  let stopped = false;
  let inflight = false;
  let lastSig: string | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;

  const tick = async () => {
    if (stopped || inflight) return;
    inflight = true;
    try {
      const data = await opts.fetcher();
      if (stopped) return;
      const sig = JSON.stringify(data) ?? "null";
      if (sig !== lastSig) {
        lastSig = sig;
        opts.onChange(data);
      }
    } catch (e) {
      if (!stopped) opts.onError?.(e instanceof Error ? e.message : String(e));
    } finally {
      inflight = false;
    }
  };
  const loop = () => {
    if (stopped) return;
    timer = setTimeout(() => {
      void tick().finally(loop);
    }, opts.intervalMs);
  };
  if (opts.immediate !== false) {
    void tick().finally(loop);
  } else {
    loop();
  }
  return () => {
    stopped = true;
    if (timer) clearTimeout(timer);
  };
}
