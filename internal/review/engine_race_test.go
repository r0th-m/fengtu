// 裁决 CAS 并发焊死(M4):同一候选并发裁决恰好一成一冲突(409 语义,
// ErrVerdictConflict errors.Is 可判);不同候选并发互不影响;
// 顺序二次裁决(改判)一律拒绝——裁决一次性。
package review

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/ye-mengwen/fengtu/internal/query"
)

// raceHits 造 n 条 pending 候选(两事件两行,去重键互异)。
func raceHits(t *testing.T, n int) (*Engine, *fakeStore, []Hit) {
	t.Helper()
	// 自带无预算帽规则(scannerUAYAML max_hits=3,并发测试要 >3 条候选)
	r, err := CompileRule("race.yaml", `
id: race-ua
title: 并发测试规则
severity: low
target: any
match:
  ua: ["sqlmap"]
note: 并发测试用
`)
	if err != nil {
		t.Fatalf("规则编译失败: %v", err)
	}
	var rows []query.Event
	for i := 0; i < n; i++ {
		rows = append(rows, query.Event{
			SourceID: "s1", LineNo: i + 1, Kind: "event",
			Fields: `{"ua":"sqlmap"}`, Raw: "x",
		})
	}
	st := newFakeStore()
	eng, err := NewEngine([]*Rule{r}, query.NewService(&fakeQuerier{rows: rows}), st)
	if err != nil {
		t.Fatalf("引擎构造失败: %v", err)
	}
	if _, err := eng.Scan(context.Background(), "case-race", "alice", nil); err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	hits, err := eng.Hits(context.Background(), "case-race", HitFilter{})
	if err != nil || len(hits) != n {
		t.Fatalf("应有 %d 条候选: %d %v", n, len(hits), err)
	}
	return eng, st, hits
}

func TestVerdictConcurrentSameHit(t *testing.T) {
	eng, _, hits := raceHits(t, 1)
	ctx := context.Background()
	const N = 8
	var wg sync.WaitGroup
	errs := make([]error, N)
	var start sync.WaitGroup
	start.Add(1)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start.Wait() // 同一起跑线,尽量挤进 CAS 窗口
			_, errs[i] = eng.Verdict(ctx, hits[0].ID,
				fmt.Sprintf("u%d", i), "accepted", "")
		}(i)
	}
	start.Done()
	wg.Wait()
	var okN, conflictN int
	for _, err := range errs {
		switch {
		case err == nil:
			okN++
		case errors.Is(err, ErrVerdictConflict):
			conflictN++
		default:
			t.Fatalf("并发裁决出现意外错误: %v", err)
		}
	}
	if okN != 1 || conflictN != N-1 {
		t.Fatalf("并发裁决应恰好一成 %d 冲突: 成 %d 冲突 %d", N-1, okN, conflictN)
	}
	// 账面:唯一胜者的裁决落地,负者不留痕
	h, err := eng.store.GetHit(ctx, hits[0].ID)
	if err != nil || h == nil {
		t.Fatalf("候选回查失败: %v", err)
	}
	if h.Status != "accepted" || h.ReviewedBy == "" {
		t.Fatalf("裁决账不符: %+v", h)
	}
}

func TestVerdictConcurrentDistinctHits(t *testing.T) {
	eng, _, hits := raceHits(t, 4)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make([]error, len(hits))
	for i := range hits {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = eng.Verdict(ctx, hits[i].ID, "bob", "rejected", "")
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("不同候选并发裁决互不影响,第 %d 条不应失败: %v", i, err)
		}
	}
	left, _ := eng.Hits(ctx, "case-race", HitFilter{Status: "pending"})
	if len(left) != 0 {
		t.Fatalf("全部裁决后 pending 应清空: %d", len(left))
	}
}

// TestVerdictNoReverdict 行为变更焊死(M4):裁决一次性——对已终态候选
// 再裁决(改判)一律 ErrVerdictConflict(web 层映 409),不再
// last-writer-wins 静默覆盖。
func TestVerdictNoReverdict(t *testing.T) {
	eng, _, hits := raceHits(t, 1)
	ctx := context.Background()
	if _, err := eng.Verdict(ctx, hits[0].ID, "alice", "accepted", ""); err != nil {
		t.Fatalf("首次裁决失败: %v", err)
	}
	if _, err := eng.Verdict(ctx, hits[0].ID, "bob", "rejected", "改判"); !errors.Is(err, ErrVerdictConflict) {
		t.Fatalf("二次裁决应报裁决冲突: %v", err)
	}
	h, _ := eng.store.GetHit(ctx, hits[0].ID)
	if h.Status != "accepted" || h.ReviewedBy != "alice" {
		t.Fatalf("改判被拒后原裁决应保持: %+v", h)
	}
}
