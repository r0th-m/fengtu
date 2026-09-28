// 意图级 wall-clock 预算(四层预算第一层):耗尽 → 先写 reason 再 Abort
// (worker 据此定 closed_exhausted 如实标,不是失败)。
package intent

import (
	"sync"
	"time"
)

// budgetTimer 带「先写中断理由」语义的计时器(time.AfterFunc 直接调回调,
// reason 必须在 Abort 前落,worker 收尾才读得到)。
type budgetTimer struct {
	once sync.Once
	t    *time.Timer
}

func newBudgetTimer(seconds int, h *runHandle, abort func()) *budgetTimer {
	bt := &budgetTimer{}
	bt.t = time.AfterFunc(time.Duration(seconds)*time.Second, func() {
		bt.once.Do(func() {
			h.setReason("budget")
			abort()
		})
	})
	return bt
}

func (bt *budgetTimer) Stop() { bt.t.Stop() }
