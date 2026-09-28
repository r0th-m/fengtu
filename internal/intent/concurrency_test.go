// worker 全局并发闸单测(切片十一):取槽/释放/上限热读/排队事件可见性。
package intent

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestWorkerSlotsBasic 信号量本体:占用满则等,释放即补;上限现读(调大即放)。
func TestWorkerSlotsBasic(t *testing.T) {
	s := newWorkerSlots()
	s.poll = 5 * time.Millisecond
	limit := 1
	fn := func() int { return limit }

	rel1, waited, ok := s.acquire(context.Background(), fn, nil)
	if !ok || waited {
		t.Fatal("空槽应立即可得且不标记等待")
	}
	if s.runningCount() != 1 {
		t.Fatalf("占用数应=1: %d", s.runningCount())
	}

	// 满槽:第二个等位;onWait 应以当前上限如实回调一次
	waitCalls := atomic.Int32{}
	got := make(chan func(), 1)
	go func() {
		rel, _, ok := s.acquire(context.Background(), fn, func(l int) {
			waitCalls.Add(1)
			if l != 1 {
				t.Errorf("onWait 上限应=1: %d", l)
			}
		})
		if ok {
			got <- rel
		}
	}()
	if err := waitFor(func() bool { return waitCalls.Load() == 1 }, "onWait 回调"); err != nil {
		t.Fatal(err)
	}

	// 上限热读:调大即放(不等释放)
	limit = 2
	select {
	case rel := <-got:
		rel()
	case <-time.After(2 * time.Second):
		t.Fatal("上限调大后等位者应补位")
	}

	// 释放补位:调回 1,等位者占满,再释放
	limit = 1
	done := make(chan struct{})
	go func() { _, _, ok := s.acquire(context.Background(), fn, nil); if ok { close(done) } }()
	select {
	case <-done:
		t.Fatal("满槽不应放行")
	case <-time.After(50 * time.Millisecond):
	}
	rel1()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("释放后等位者应补位")
	}
	if s.runningCount() != 1 {
		t.Fatalf("释放后占用数应=1: %d", s.runningCount())
	}
}

// TestWorkerSlotsCtxCancel 引擎关闭途中(ctx 取消):等位如实放弃,不领槽。
func TestWorkerSlotsCtxCancel(t *testing.T) {
	s := newWorkerSlots()
	rel, _, _ := s.acquire(context.Background(), func() int { return 1 }, nil) // 先占满
	defer rel()
	ctx, cancel := context.WithCancel(context.Background())
	res := make(chan bool, 1)
	go func() { _, _, ok := s.acquire(ctx, func() int { return 1 }, nil); res <- ok }()
	cancel()
	select {
	case ok := <-res:
		if ok {
			t.Fatal("ctx 取消应如实不领槽")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ctx 取消后等位者应退出")
	}
}

// TestWorkerConcurrencyLimitEngine 引擎级:上限 1 时两案件意图一串行一排队,
// 排队节点过程流如实见「排队中(并发上限 1)」;在跑的收尾后排队者补位。
func TestWorkerConcurrencyLimitEngine(t *testing.T) {
	fs := newFakeStore()
	fa := newFakeAI()
	fau := &fakeAudit{}
	gate := make(chan struct{}) // 在跑 worker 全阻塞,测试控制放行
	fa.runFn = func(_, _, _ string, abort <-chan string) []AIEvent {
		select {
		case <-gate:
		case <-abort:
		}
		return []AIEvent{{Kind: "text", Text: defaultVerdictText}}
	}
	eng := NewEngine(Deps{
		Store: fs, AI: fa, Audit: fau, Debounce: 2 * time.Millisecond,
		ConcurrencyLimit: func() int { return 1 },
	})
	eng.slots.poll = 10 * time.Millisecond
	eng.Start(context.Background())
	defer eng.Close()

	ctx := context.Background()
	if _, err := eng.CreateHuman(ctx, "case-A", "tester", "查 A", ScopeCase, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.CreateHuman(ctx, "case-B", "tester", "查 B", ScopeCase, 0, "", ""); err != nil {
		t.Fatal(err)
	}

	// 上限 1:只许一个 worker 开跑
	if err := waitFor(func() bool {
		fa.mu.Lock()
		defer fa.mu.Unlock()
		return len(fa.sessions) == 1
	}, "首个 worker 开跑"); err != nil {
		t.Fatal(err)
	}
	// 另一个案件排队:过程流如实见「排队中(并发上限 1)」,且不许抢跑
	if err := waitFor(func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		for _, evs := range fs.events {
			for _, ev := range evs {
				if ev.Kind == "queue" && strings.Contains(ev.Text, "排队中(并发上限 1)") {
					return true
				}
			}
		}
		return false
	}, "排队事件上账"); err != nil {
		t.Fatal(err)
	}
	fa.mu.Lock()
	if len(fa.sessions) != 1 {
		fa.mu.Unlock()
		t.Fatalf("上限 1 不应有第二个 worker 抢跑: %d 个会话", len(fa.sessions))
	}
	fa.mu.Unlock()

	// 在跑 worker 收尾 → 排队者补位,两边都到终态
	close(gate)
	if err := waitFor(func() bool {
		fa.mu.Lock()
		defer fa.mu.Unlock()
		return len(fa.sessions) >= 2 // 同案子意图链路也会开新会话,==2 是竞态窗口
	}, "排队 worker 补位"); err != nil {
		t.Fatal(err)
	}
	if err := waitFor(func() bool {
		for _, cid := range []string{"case-A", "case-B"} {
			ns, _ := fs.ListNodes(ctx, cid)
			done := false
			for _, n := range ns {
				if n.Kind == KindIntent && n.Status == StatusSupported {
					done = true
				}
			}
			if !done {
				return false
			}
		}
		return true
	}, "两案件意图均收尾"); err != nil {
		t.Fatal(err)
	}
}

// TestWorkerConcurrencyDefault 未配置(Deps.ConcurrencyLimit nil)→ 默认 4。
func TestWorkerConcurrencyDefault(t *testing.T) {
	eng, _, _, _ := testEngine(nil)
	if got := eng.limitFn(); got != DefaultConcurrency {
		t.Fatalf("默认并发上限应=%d: %d", DefaultConcurrency, got)
	}
}
