// worker 全局并发闸(切片十一 0.16.0,对应 ARTEX server/goals.go admitTask
// 并发上限的意图侧落法):
//
//   - 上限来自平台设置 ai_settings.agent_concurrency(默认 4),Deps
//     .ConcurrencyLimit 每次取槽现读——改配置对之后的派发即时生效;
//     调低不追回在跑 worker(与 ARTEX「对之后启动的任务生效」同口径,如实);
//   - 超上限的意图不抢跑:planner 在取槽处排队等位,过程流如实记一条
//     「排队中(并发上限 N)」;槽位空出(worker 收尾释放)即按等待先后补位;
//   - 等位期间人工停止/纠偏在跑的 worker,等位方最迟 poll 间隔(默认 2s)
//     后重估——worker 流被 Abort/Cancel 时写回在 agentloop drive 收尾之后,
//     释放点不变,这里只做唤醒加速,不改语义。
package intent

import (
	"context"
	"sync"
	"time"
)

// DefaultConcurrency worker 全局并发上限默认(010 迁移 ai_settings
// .agent_concurrency DEFAULT 同口径)。
const DefaultConcurrency = 4

// slotPollInterval 等位重估间隔(上限调大无需显式唤醒,周期重估兜底,如实)。
const slotPollInterval = 2 * time.Second

// workerSlots 动态上限信号量:上限每次现读(limitFn),不用固定容量 channel
// (配置热改无法改容量)。广播式唤醒:释放/poke 关闭当前 changed 频道,
// 所有等位者重估。
type workerSlots struct {
	mu      sync.Mutex
	running int
	changed chan struct{}
	poll    time.Duration // 等位重估间隔(≤0 用 slotPollInterval;测试可缩)
}

func newWorkerSlots() *workerSlots {
	return &workerSlots{changed: make(chan struct{}), poll: slotPollInterval}
}

// acquire 取一个运行槽:有空位立即占用(onWait 不调);满了排队等位——
// 首次转入等待时调一次 onWait(当前上限)(如实呈现「排队中」的时机:等位
// 期间就可见,不是排到才补记),之后到有空位或 ctx 取消(ok=false)。
// release 用完必调且只调一次。onWait 可 nil。
func (s *workerSlots) acquire(ctx context.Context, limitFn func() int,
	onWait func(limit int)) (release func(), waited, ok bool) {

	poll := s.poll
	if poll <= 0 {
		poll = slotPollInterval
	}
	notified := false
	for {
		s.mu.Lock()
		limit := limitFn()
		if limit < 1 {
			limit = 1
		}
		if s.running < limit {
			s.running++
			s.mu.Unlock()
			return s.releaseOnce, waited, true
		}
		if !notified && onWait != nil {
			onWait(limit) // 持锁回调须快(本工程内只写一条过程流事件)
			notified = true
		}
		ch := s.changed
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, waited, false
		case <-ch: // 有槽释放/被 poke:立即重估
		case <-time.After(poll): // 上限调大等外部变化:周期重估兜底
		}
		waited = true
	}
}

// releaseOnce 释放一个槽并广播唤醒等位者(只应被 acquire 的返回值调用一次)。
func (s *workerSlots) releaseOnce() {
	s.mu.Lock()
	if s.running > 0 {
		s.running--
	}
	close(s.changed)
	s.changed = make(chan struct{})
	s.mu.Unlock()
}

// poke 广播唤醒全部等位者重估(不改变占用数)。用于「在跑 worker 被人工
// 停止/纠偏中断」场景:等位方立即重估而不是干等 poll 间隔。
func (s *workerSlots) poke() {
	s.mu.Lock()
	close(s.changed)
	s.changed = make(chan struct{})
	s.mu.Unlock()
}

// runningCount 当前占用(观测/测试用)。
func (s *workerSlots) runningCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}
