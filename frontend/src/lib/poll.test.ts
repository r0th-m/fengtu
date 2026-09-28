// 轮询+签名去重焊死:同签名不重发(不打断)/变化才回调/失败如实上报/
// 单飞不并发/停止后不再拉。
import { describe, expect, it, vi } from "vitest";
import { startPolling } from "./poll";

describe("startPolling 轮询+签名去重", () => {
  it("首轮必回调;同签名后续轮不回调;变化才回调", async () => {
    vi.useFakeTimers();
    let value = 1;
    const onChange = vi.fn();
    const stop = startPolling({
      fetcher: async () => ({ v: value }),
      onChange,
      intervalMs: 1000,
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(onChange).toHaveBeenCalledTimes(1); // 首轮

    await vi.advanceTimersByTimeAsync(1000); // 同签名
    expect(onChange).toHaveBeenCalledTimes(1);

    value = 2;
    await vi.advanceTimersByTimeAsync(1000); // 变化
    expect(onChange).toHaveBeenCalledTimes(2);
    expect(onChange.mock.calls[1][0]).toEqual({ v: 2 });
    stop();
    vi.useRealTimers();
  });

  it("失败如实上报原文,后续轮继续", async () => {
    vi.useFakeTimers();
    let fail = true;
    const onChange = vi.fn();
    const onError = vi.fn();
    const stop = startPolling({
      fetcher: async () => {
        if (fail) throw new Error("网络断开(如实)");
        return { ok: 1 };
      },
      onChange,
      onError,
      intervalMs: 500,
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(onError).toHaveBeenCalledWith("网络断开(如实)");
    expect(onChange).not.toHaveBeenCalled();
    fail = false;
    await vi.advanceTimersByTimeAsync(500);
    expect(onChange).toHaveBeenCalledTimes(1);
    stop();
    vi.useRealTimers();
  });

  it("单飞:上一趟未回完不并发;stop 后不再拉", async () => {
    vi.useFakeTimers();
    let calls = 0;
    let release: () => void = () => {};
    const stop = startPolling({
      fetcher: () => {
        calls++;
        return new Promise((res) => {
          release = () => res({ n: calls });
        });
      },
      onChange: () => {},
      intervalMs: 100,
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(calls).toBe(1);
    await vi.advanceTimersByTimeAsync(1000); // 悬挂中,不并发
    expect(calls).toBe(1);
    release();
    await vi.advanceTimersByTimeAsync(0);
    stop();
    await vi.advanceTimersByTimeAsync(1000);
    expect(calls).toBe(1);
    vi.useRealTimers();
  });
});
