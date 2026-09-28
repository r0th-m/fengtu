// goal 生命周期收官(0.29.1-goal-lifecycle):goal 节点不可派发,过去永远停
// open——报告「目的达成」全是「排查中」、图上挂着一堆永不收官的 open。补齐:
// 子树内全部意图到终态(supported/denied/doubt/closed/closed_exhausted/
// stopped;parked 未展开不挡收官,与 chapterComplete 同口径)且无
// open/running/awaiting_approval 时,goal 自动置机器评估终态:
//   - closed_goal_met     子树意图全部 supported;
//   - closed_goal_partial 部分 supported;
//   - closed_goal_unmet   零 supported。
// 措辞如实:这是「机器按证据结构的评估」,收官定论归人(报告标签写死)。
// 触发点(全部幂等,同一函数重估全案件 goal):worker 写回/审批驳回/人工停
// open/停车场展开/报告生成(旧 goal 的一次性重估路径)。
package intent

import (
	"context"
	"fmt"
)

// isGoalClosedStatus goal 机器评估终态判定。
func isGoalClosedStatus(s string) bool {
	return s == StatusClosedGoalMet || s == StatusClosedGoalPartial ||
		s == StatusClosedGoalUnmet
}

// goalVerdict 按子树意图终态分布定 goal 机器评估档(纯函数可测)。
// 入参为各终态计数;调用方保证 total>0(零意图 goal 不收官——还没开查,
// 如实留 open)。
func goalVerdict(total, supported int) string {
	switch {
	case supported == total:
		return StatusClosedGoalMet
	case supported == 0:
		return StatusClosedGoalUnmet
	default:
		return StatusClosedGoalPartial
	}
}

// ReevalGoals 重估案件全部 goal 的收官态(幂等):
//   - open/closed_goal_* 的 goal 才参与(其他状态如实不动);
//   - 子树(沿 parent 链归属该 goal)内非 parked 意图:有未终态
//     (open/running/awaiting_approval)→ goal 回 open(已收官的如实重开,
//     机器评估态不作数);全终态且至少一条 → 置机器评估档;
//   - 零意图 goal 不收官(没开查不能装查完),维持 open。
// 返回状态发生变化的 goal 数(0=幂等无操作)。
func (e *Engine) ReevalGoals(ctx context.Context, caseID string) (int, error) {
	nodes, err := e.deps.Store.ListNodes(ctx, caseID)
	if err != nil {
		return 0, fmt.Errorf("goal 收官重估:节点清单查询失败: %w", err)
	}
	index := map[string]*Node{}
	for _, n := range nodes {
		index[n.ID] = n
	}
	changed := 0
	for _, g := range nodes {
		if g.Kind != KindGoal {
			continue
		}
		if g.Status != StatusOpen && !isGoalClosedStatus(g.Status) {
			continue // 人定状态(如手动关闭)不动,判断权归人
		}
		total, supported, denied, doubt, closed, exhausted, stopped := 0, 0, 0, 0, 0, 0, 0
		unfinished := 0
		for _, n := range nodes {
			if n.Kind != KindIntent || n.Status == StatusParked {
				continue
			}
			if !inChapter(index, n, g.ID) {
				continue
			}
			total++
			switch n.Status {
			case StatusOpen, StatusAwaitingApproval, StatusRunning:
				unfinished++
			case StatusSupported:
				supported++
			case StatusDenied:
				denied++
			case StatusDoubt:
				doubt++
			case StatusClosedExhausted:
				exhausted++
			case StatusStopped:
				stopped++
			default: // closed 等其余终态
				closed++
			}
		}
		if total == 0 {
			continue // 零意图:没开查,如实留 open(不装收官)
		}
		if unfinished > 0 {
			if g.Status == StatusOpen {
				continue // 已在 open,幂等
			}
			// 重开:子树重新出现未终态意图(停车场展开等),机器评估态作废
			ok, err := e.deps.Store.SetGoalStatus(ctx, g.ID, StatusOpen, "", nil)
			if err != nil {
				return changed, fmt.Errorf("goal 重开落账失败(%s): %w", g.ID, err)
			}
			if ok {
				changed++
				e.emitNodeUpdated(ctx, g.ID)
				_, _, _ = e.deps.Audit.AppendAudit(ctx, caseID, "engine",
					"intent.goal_reopen", g.ID, map[string]any{
						"text": g.Text, "was": g.Status, "unfinished": unfinished})
			}
			continue
		}
		status := goalVerdict(total, supported)
		if status == g.Status {
			continue // 幂等:档未变不重写
		}
		note := fmt.Sprintf("机器评估:章内 %d 条意图全终态(supported %d · denied %d · "+
			"doubt %d · closed %d · 耗尽 %d · stopped %d)——收官定论归人",
			total, supported, denied, doubt, closed, exhausted, stopped)
		now := e.deps.Now().UTC()
		ok, err := e.deps.Store.SetGoalStatus(ctx, g.ID, status, note, &now)
		if err != nil {
			return changed, fmt.Errorf("goal 收官落账失败(%s): %w", g.ID, err)
		}
		if !ok {
			continue // 并发/状态已变:如实以库为准
		}
		changed++
		e.emitNodeUpdated(ctx, g.ID)
		e.emitFeedFinish(caseID, g.ID, status, "",
			"章节收官(机器评估,定论归人): "+cutRunes(g.Text, 60))
		_, _, _ = e.deps.Audit.AppendAudit(ctx, caseID, "engine",
			"intent.goal_close", g.ID, map[string]any{
				"text": g.Text, "status": status, "intents": total,
				"supported": supported, "denied": denied, "doubt": doubt})
	}
	return changed, nil
}

// reevalGoalsQuiet 触发点收口:重估失败如实记事件流(有 logf 时),
// 不中断主流程(收官是派生账,不挡写回/审批)。
func (e *Engine) reevalGoalsQuiet(ctx context.Context, caseID string,
	logf func(string, string)) {

	if _, err := e.ReevalGoals(ctx, caseID); err != nil && logf != nil {
		logf("error", "goal 收官重估失败(下触发点再试,如实): "+err.Error())
	}
}
