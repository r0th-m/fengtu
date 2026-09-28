// 停车场(0.24.0-convergence,L2)+ 分支预算闸(L1):意图链三层收敛的
// 数据层与治理面(L0 章节=playbook 意图树,见 templates.go)。
//
// 设计依据(用户拍板的三层收敛):
//   - 应急意图链会发散爆炸(假设空间开放,无渗透的资产 scope 收敛),
//     三层收敛:L0 章节(playbook 册=章节骨架,AI 章内自由派生)、
//     L1 预算三闸(扇出/章/案,防单分支吃光)、L2 停车场(不属当前章或
//     超闸的线索不丢弃不展开,人批才开——先严后松);
//   - 预算三闸只闸自动派生(worker 写回路径 spawnChildren);人工手写
//     意图/线索不受限(判断权归人)。模板播种(一键分析/规则扫描)是人
//     发起的章节骨架,不过闸(闸口如实收窄在派生爆炸点);
//   - 超闸/申请新开章的线索:落 status=parked 图节点(灰色虚线框,不可
//     派发)+ intent_parking 条目(来源/摘要/归属建议/原因),过程流与
//     播报板如实记「转入停车场」;
//   - 展开权永远在人:deploy=人点(视同人批,直转 open 走派发);章节
//     收官评估(章内意图全终态后一次 LLM 调用,预算封顶)只写「建议
//     展开/丢弃+理由」,不自动开;
//   - 一切出入进审计哈希链(intent.parked / intent.parking_deploy /
//     intent.parking_dismiss / intent.chapter_eval)。
package intent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// StatusParked 停车场节点状态(014 迁移 CHECK 同口径):未展开线索,
// 不可派发(NextRunnable 只领 open),人点展开才转 open。
const StatusParked = "parked"

// 停车场转入原因(014 迁移 CHECK 同口径)。
const (
	ParkReasonFanout  = "budget_fanout"  // 每意图派生扇出超闸
	ParkReasonChapter = "budget_chapter" // 章意图数超闸
	ParkReasonCase    = "budget_case"    // 案件意图总数超闸
	ParkReasonLead    = "park_lead"      // AI 调查中发现章外线索,主动申请
	// 派生去重闸原因 dup_exact/dup_similar(0.28.0-blackboard,019 迁移
	// CHECK 同口径)见 dedup.go。
)

// 停车场条目状态/收官评估建议(014 迁移 CHECK 同口径)。
const (
	ParkingParked    = "parked"
	ParkingDeployed  = "deployed"
	ParkingDismissed = "dismissed"

	VerdictDeploy  = "deploy"
	VerdictDismiss = "dismiss"
)

// 预算闸默认(与 014 迁移 DEFAULT / agentloop 默认档同口径)。
const (
	DefaultFanoutLimit  = 5   // 每意图派生扇出上限(与 maxAIChildren 同档)
	DefaultChapterLimit = 30  // 每章自动派生意图上限
	DefaultCaseLimit    = 200 // 每案自动派生意图上限
)

// ChapterEvalTokens 章节收官评估的固定 token 预算(一次 LLM 调用;
// 保险丝语义,防评估刷钱——评估 prompt 短,1000 足够回一批建议)。
const ChapterEvalTokens = 1000

// maxParkLeads 单次写回最多受理的 AI 停车场申请(防烂模型刷停车场)。
const maxParkLeads = 3

// BudgetLimits 预算三闸(现读平台设置,改即对之后派发生效;不追回在跑)。
type BudgetLimits struct {
	Fanout  int `json:"fanout"`  // 每意图派生扇出上限(模板子+AI 子合计)
	Chapter int `json:"chapter"` // 每章(goal 子树)自动派生意图上限
	Case    int `json:"case"`    // 每案自动派生意图上限
}

// DefaultBudgetLimits 默认闸(5/30/200;Deps.BudgetLimits nil 时用)。
func DefaultBudgetLimits() BudgetLimits {
	return BudgetLimits{Fanout: DefaultFanoutLimit, Chapter: DefaultChapterLimit,
		Case: DefaultCaseLimit}
}

// ParkingEntry 停车场一条(与 intent_parking 表对齐;node_id 锚图节点,
// Text 是读出时 join 图节点的快照呈现,不另存——节点文本不可变)。
type ParkingEntry struct {
	ID            string     `json:"id"`
	CaseID        string     `json:"case_id"`
	NodeID        string     `json:"node_id"` // parked 图节点
	Text          string     `json:"text"`    // 线索摘要(join intent_nodes.text)
	SourceNodeID  string     `json:"source_node_id,omitempty"`
	SuggestGoalID string     `json:"suggest_goal_id,omitempty"` // 归属建议:章(goal 节点);空=建议新开章
	SuggestLabel  string     `json:"suggest_label,omitempty"`   // 归属建议人读标签(章名/新章名快照)
	Reason        string     `json:"reason"`                    // budget_fanout|budget_chapter|budget_case|park_lead
	Verdict       string     `json:"verdict,omitempty"`         // 收官评估建议 deploy|dismiss(空=未评估;AI 只建议)
	VerdictReason string     `json:"verdict_reason,omitempty"`
	Status        string     `json:"status"` // parked|deployed|dismissed
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	DecidedAt     *time.Time `json:"decided_at,omitempty"`
	DecidedBy     string     `json:"decided_by,omitempty"`
}

// ChapterBudget 一章的预算消耗(预算可观测面)。
type ChapterBudget struct {
	GoalID  string `json:"goal_id"`
	Title   string `json:"title"`
	Intents int    `json:"intents"` // 章内自动派生意图数(不含 parked)
	Limit   int    `json:"limit"`
}

// BudgetStatus 案件预算消耗(GET /api/cases/{id}/budget 返回形)。
type BudgetStatus struct {
	Limits      BudgetLimits    `json:"limits"`
	CaseIntents int             `json:"case_intents"` // 案内自动派生意图数(不含 parked)
	Chapters    []ChapterBudget `json:"chapters"`
	Parked      int             `json:"parked"` // 停车场待处置条数
}

// limits 现读预算闸(Deps.BudgetLimits nil/读取异常 → 默认,不带病猜;
// 单项 ≤0 落默认,与并发上限同口径)。
func (e *Engine) limits() BudgetLimits {
	l := DefaultBudgetLimits()
	if e.deps.BudgetLimits != nil {
		if got := e.deps.BudgetLimits(); got.Fanout > 0 && got.Chapter > 0 && got.Case > 0 {
			l = got
		}
	}
	return l
}

// chapterOf 章归属:沿 parent 链上溯到 goal 节点(章节=playbook 顶层 goal
// 子树);无 goal 祖先=无章节(散件分支,如实 nil——章闸不适用,案闸仍管)。
func chapterOf(index map[string]*Node, n *Node) *Node {
	cur := n
	for i := 0; i < 100; i++ { // 环防御(深度上限 5,正常几步到顶)
		if cur.Kind == KindGoal {
			return cur
		}
		if cur.ParentID == "" {
			return nil
		}
		p := index[cur.ParentID]
		if p == nil {
			return nil
		}
		cur = p
	}
	return nil
}

// inChapter 节点是否挂在 goal 子树(parent 链上溯命中)。
func inChapter(index map[string]*Node, n *Node, goalID string) bool {
	cur := n
	for i := 0; i < 100; i++ {
		if cur.ID == goalID {
			return true
		}
		if cur.ParentID == "" {
			return false
		}
		p := index[cur.ParentID]
		if p == nil {
			return false
		}
		cur = p
	}
	return false
}

// spawnGate 预算闸判定结果(reason 空=放行)。
type spawnGate struct {
	reason       string
	detail       string // 人读说明(过程流/播报原文;park_lead 无闸措辞)
	goal         *Node  // 归属建议(章;nil=无章节/建议新开章)
	suggestLabel string // park_lead 的 AI 归属建议原话(新开章名等)
}

// checkSpawnGates 自动派生三闸(只闸 worker 写回路径;人工不过闸):
// 扇出(该意图的 intent 子节点总数,含本轮已派生与已 parked——试派生
// 也占扇出账;调用方每派生/park 一条须把新节点续进 nodes 快照)→
// 章(章内自动派生非 parked 意图数)→ 案(案内自动派生非 parked 意图数)。
// 顺序即优先级:先贴身的闸先报。
func (e *Engine) checkSpawnGates(lim BudgetLimits, node *Node, nodes []*Node) *spawnGate {

	index := map[string]*Node{}
	for _, n := range nodes {
		index[n.ID] = n
	}
	goal := chapterOf(index, node)

	// 扇出闸:intent 子节点总数(快照含本轮已派生/parked)
	fanout := 0
	for _, n := range nodes {
		if n.Kind == KindIntent && n.ParentID == node.ID {
			fanout++
		}
	}
	if fanout >= lim.Fanout {
		return &spawnGate{reason: ParkReasonFanout, goal: goal,
			detail: fmt.Sprintf("意图派生扇出超上限(%d/%d)", fanout, lim.Fanout)}
	}

	// 章闸/案闸:自动派生(ai/rule)且非 parked 的意图计数
	if goal != nil {
		chapterCount := 0
		for _, n := range nodes {
			if n.Kind == KindIntent && n.CreatedBy != ByHuman &&
				n.Status != StatusParked && inChapter(index, n, goal.ID) {
				chapterCount++
			}
		}
		if chapterCount >= lim.Chapter {
			return &spawnGate{reason: ParkReasonChapter, goal: goal,
				detail: fmt.Sprintf("章「%s」意图数超上限(%d/%d)",
					cutRunes(goal.Text, 30), chapterCount, lim.Chapter)}
		}
	}
	caseCount := 0
	for _, n := range nodes {
		if n.Kind == KindIntent && n.CreatedBy != ByHuman && n.Status != StatusParked {
			caseCount++
		}
	}
	if caseCount >= lim.Case {
		return &spawnGate{reason: ParkReasonCase, goal: goal,
			detail: fmt.Sprintf("案件意图总数超上限(%d/%d)", caseCount, lim.Case)}
	}
	return nil
}

// park 线索转入停车场:parked 图节点(不可派发,血缘边保留)+ 停车场条目 +
// 过程流/播报/审计三处留痕。child 应已是待落库形态(Status 由本函数置 parked)。
func (e *Engine) park(ctx context.Context, parent *Node, child *Node,
	gate *spawnGate, logf func(string, string)) error {

	child.Status = StatusParked
	if err := ValidateNode(child); err != nil {
		return err
	}
	if err := e.deps.Store.CreateNode(ctx, child); err != nil {
		return fmt.Errorf("停车场节点落库失败: %w", err)
	}
	e.emitNodeAdded(child)
	if parent != nil {
		ed := &Edge{CaseID: child.CaseID, FromID: parent.ID, ToID: child.ID, Kind: EdgeSpawns}
		if err := e.deps.Store.CreateEdge(ctx, ed); err != nil {
			return fmt.Errorf("停车场血缘边落库失败: %w", err)
		}
		e.emitEdgeAdded(ed)
	}
	entry := &ParkingEntry{CaseID: child.CaseID, NodeID: child.ID,
		Reason: gate.reason, CreatedBy: child.CreatedBy, Status: ParkingParked,
		SuggestLabel: gate.suggestLabel}
	if parent != nil {
		entry.SourceNodeID = parent.ID
	}
	if gate.goal != nil {
		entry.SuggestGoalID = gate.goal.ID
		if entry.SuggestLabel == "" {
			entry.SuggestLabel = cutRunes(gate.goal.Text, 60)
		}
	}
	if err := e.deps.Store.CreateParking(ctx, entry); err != nil {
		return fmt.Errorf("停车场条目落库失败: %w", err)
	}
	_, _, _ = e.deps.Audit.AppendAudit(ctx, child.CaseID, "engine", "intent.parked",
		child.ID, map[string]any{"text": child.Text, "reason": gate.reason,
			"suggest_goal": entry.SuggestGoalID, "parking_id": entry.ID})
	// 过程流+播报板如实记(park 步挂在来源意图上;park_lead 带申请措辞)
	text := "转入停车场: " + cutRunes(child.Text, 80)
	switch {
	case gate.reason == ParkReasonLead:
		text = "AI 申请登记章外线索," + text
	case gate.reason == ParkReasonDupExact:
		text = "重复意图拦截(" + gate.detail + ")," + text
	case gate.reason == ParkReasonDupSimilar:
		text = "疑似重复,已入停车场待人裁(" + gate.detail + ")," + text
	case gate.detail != "":
		text = "预算闸:" + gate.detail + ",未展开," + text
	}
	if parent != nil && logf != nil {
		logf("park", text)
	} else {
		e.emitFeedEvent(child.CaseID, child.ID, "park", text)
	}
	return nil
}

// ParkLead AI 调查中主动登记的章外线索(worker 写回路径 verdict.park_leads;
// 不过预算闸——它是「申请」不是「展开」,展开仍走人点 deploy)。
// suggest=AI 给的归属建议原话(哪章/新开章;人读标签,新开章建议
// suggest_goal_id 留空)。
func (e *Engine) ParkLead(ctx context.Context, source *Node, text, suggest string,
	logf func(string, string)) error {

	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	if utf8.RuneCountInString(text) > 300 {
		text = string([]rune(text)[:300])
	}
	suggest = strings.TrimSpace(suggest)
	if utf8.RuneCountInString(suggest) > 60 {
		suggest = string([]rune(suggest)[:60])
	}
	child := &Node{CaseID: source.CaseID, Kind: KindIntent, Text: text,
		CreatedBy: ByAI, Scope: source.Scope, HostScope: source.HostScope,
		ParentID: source.ID, Depth: source.Depth + 1,
		TemplateID: source.TemplateID, BudgetSeconds: source.BudgetSeconds}
	if child.Depth > MaxDepth {
		child.Depth = MaxDepth // 停车场节点不派生,深度只是布局参考,截断不拒
	}
	return e.park(ctx, source, child, &spawnGate{reason: ParkReasonLead,
		suggestLabel: suggest}, logf)
}

// Parking 案件停车场清单(API 呈现;含已处置留痕,创建序)。
func (e *Engine) Parking(ctx context.Context, caseID string) ([]*ParkingEntry, error) {
	return e.deps.Store.ListParking(ctx, caseID)
}

// normalizeChapterTitle 章节名规范化(0.29.1):AI 归属建议原话常把收尾契约
// 示例字面抄进来(「建议归属:横向排查」),deploy 落 goal 文本前剥掉前缀;
// 历史存量不动(图节点文本不可变纪律,只净化新落库)。
func normalizeChapterTitle(s string) string {
	s = strings.TrimSpace(s)
	for _, p := range []string{"建议归属:", "建议归属:"} {
		if rest, ok := strings.CutPrefix(s, p); ok {
			s = strings.TrimSpace(rest)
			break
		}
	}
	return s
}

// DeployParking 人点展开(先严后松的人批版:AI/闸只建议,展开永远人点):
//   - 归属建议=既有章:parked 节点直转 open(视同人批,不再过审批门),
//     血缘边进站时已落,图结构不搬家(闸场景下建议章即来源章,如实);
//   - 归属建议=新开章:先落新 goal 节点(章名=AI 建议标签,空则线索文本
//     兜底),parked 节点改挂新章(spawns 边 + parent 重指)再转 open;
//   - 转 open 即唤醒 planner 走正常派发;展开后其子派生仍过预算三闸
//     (预算是持续约束,不是一次通行证)。
func (e *Engine) DeployParking(ctx context.Context, id, actor string) (*ParkingEntry, *Node, error) {
	entry, err := e.deps.Store.GetParking(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if entry == nil {
		return nil, nil, fmt.Errorf("无此停车场条目: %s", id)
	}
	if entry.Status != ParkingParked {
		return nil, nil, fmt.Errorf("停车场条目已被处置(当前 %s),不重复展开", entry.Status)
	}
	node, err := e.deps.Store.GetNode(ctx, entry.NodeID)
	if err != nil {
		return nil, nil, err
	}
	if node == nil {
		return nil, nil, fmt.Errorf("停车场条目的图节点不存在(数据损坏,如实): %s", entry.NodeID)
	}
	if node.Status != StatusParked {
		return nil, nil, fmt.Errorf("停车场节点已不在 parked 状态(当前 %s),以库为准", node.Status)
	}

	parentID := ""
	if entry.SuggestGoalID == "" {
		// 新开章:goal 文本=AI 建议标签(规范化剥「建议归属:」前缀,0.29.1;
		// 空则线索文本兜底),人提出(人点的展开)
		title := normalizeChapterTitle(entry.SuggestLabel)
		if title == "" {
			title = cutRunes(node.Text, 60)
		}
		goal := &Node{CaseID: entry.CaseID, Kind: KindGoal, Text: title,
			Status: StatusOpen, CreatedBy: ByHuman, Scope: ScopeCase,
			BudgetSeconds: e.deps.BudgetSeconds}
		if err := ValidateNode(goal); err != nil {
			return nil, nil, err
		}
		if err := e.deps.Store.CreateNode(ctx, goal); err != nil {
			return nil, nil, err
		}
		e.emitNodeAdded(goal)
		ed := &Edge{CaseID: entry.CaseID, FromID: goal.ID, ToID: node.ID, Kind: EdgeSpawns}
		if err := e.deps.Store.CreateEdge(ctx, ed); err != nil {
			return nil, nil, err
		}
		e.emitEdgeAdded(ed)
		parentID = goal.ID
		entry.SuggestGoalID = goal.ID // 落账后归属即新章
	}
	ok, err := e.deps.Store.ParkedNodeDecision(ctx, node.ID, true, "", parentID,
		e.deps.Now().UTC())
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, fmt.Errorf("停车场节点已被处理(并发处置),当前状态以库为准")
	}
	if _, err := e.deps.Store.DecideParking(ctx, id, true, actor, e.deps.Now().UTC()); err != nil {
		return nil, nil, err
	}
	entry.Status = ParkingDeployed
	_, _, _ = e.deps.Audit.AppendAudit(ctx, entry.CaseID, actor, "intent.parking_deploy",
		id, map[string]any{"node": node.ID, "text": node.Text,
			"suggest_goal": entry.SuggestGoalID, "reason": entry.Reason})
	e.emitNodeUpdated(ctx, node.ID)
	e.emitFeedApproval(entry.CaseID, node.ID,
		"停车场展开(人批放行): "+cutRunes(node.Text, 80), StatusOpen)
	// 展开让章内重新出现未终态意图:已收官 goal 如实重开(0.29.1,幂等)
	e.reevalGoalsQuiet(ctx, entry.CaseID, nil)
	e.Wake(entry.CaseID)
	// 返回展开后的新态(调用方/测试以库为准,不拿决策前快照)
	if fresh, gerr := e.deps.Store.GetNode(ctx, node.ID); gerr == nil && fresh != nil {
		node = fresh
	}
	return entry, node, nil
}

// DismissParking 人点丢弃(留痕:节点转 closed 如实标「停车场丢弃」,
// 条目转 dismissed,decided_by/at 落账,审计哈希链)。
func (e *Engine) DismissParking(ctx context.Context, id, actor string) (*ParkingEntry, error) {
	entry, err := e.deps.Store.GetParking(ctx, id)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("无此停车场条目: %s", id)
	}
	if entry.Status != ParkingParked {
		return nil, fmt.Errorf("停车场条目已被处置(当前 %s),不重复丢弃", entry.Status)
	}
	ok, err := e.deps.Store.ParkedNodeDecision(ctx, entry.NodeID, false,
		"停车场丢弃(人工裁决,留痕)", "", e.deps.Now().UTC())
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("停车场节点已被处理(并发处置),当前状态以库为准")
	}
	if _, err := e.deps.Store.DecideParking(ctx, id, false, actor, e.deps.Now().UTC()); err != nil {
		return nil, err
	}
	entry.Status = ParkingDismissed
	_, _, _ = e.deps.Audit.AppendAudit(ctx, entry.CaseID, actor, "intent.parking_dismiss",
		id, map[string]any{"node": entry.NodeID, "text": entry.Text, "reason": entry.Reason})
	e.emitNodeUpdated(ctx, entry.NodeID)
	e.emitFeedApproval(entry.CaseID, entry.NodeID,
		"停车场丢弃(人工裁决,留痕): "+cutRunes(entry.Text, 80), StatusClosed)
	return entry, nil
}

// Budget 预算可观测面(案意图数 x/上限 + 章分布 + 停车场待处置数)。
func (e *Engine) Budget(ctx context.Context, caseID string) (*BudgetStatus, error) {
	lim := e.limits()
	nodes, err := e.deps.Store.ListNodes(ctx, caseID)
	if err != nil {
		return nil, err
	}
	index := map[string]*Node{}
	for _, n := range nodes {
		index[n.ID] = n
	}
	st := &BudgetStatus{Limits: lim, Chapters: []ChapterBudget{}}
	for _, n := range nodes {
		if n.Kind == KindIntent && n.CreatedBy != ByHuman && n.Status != StatusParked {
			st.CaseIntents++
		}
	}
	for _, n := range nodes {
		if n.Kind != KindGoal {
			continue
		}
		cb := ChapterBudget{GoalID: n.ID, Title: cutRunes(n.Text, 60), Limit: lim.Chapter}
		for _, m := range nodes {
			if m.Kind == KindIntent && m.CreatedBy != ByHuman &&
				m.Status != StatusParked && inChapter(index, m, n.ID) {
				cb.Intents++
			}
		}
		st.Chapters = append(st.Chapters, cb)
	}
	entries, err := e.deps.Store.ListParking(ctx, caseID)
	if err != nil {
		return nil, err
	}
	for _, p := range entries {
		if p.Status == ParkingParked {
			st.Parked++
		}
	}
	return st, nil
}

// ---- 章节收官评估(先严后松的人批版) ----

// chapterComplete 章内意图全终态(open/awaiting_approval/running 均未清;
// parked 不算——它没展开,不挡收官)。
func chapterComplete(index map[string]*Node, nodes []*Node, goalID string) bool {
	for _, n := range nodes {
		if n.Kind != KindIntent || n.Status == StatusParked {
			continue
		}
		if !inChapter(index, n, goalID) {
			continue
		}
		switch n.Status {
		case StatusOpen, StatusAwaitingApproval, StatusRunning:
			return false
		}
	}
	return true
}

// evalVerdict 收官评估的一条建议(机器解析契约)。
type evalVerdict struct {
	ID      string `json:"id"`
	Verdict string `json:"verdict"` // deploy|dismiss
	Reason  string `json:"reason"`
}

// maybeEvalChapter 章节收官评估触发点(worker 写回/人工停 open/审批驳回后):
// 章内意图全终态 且 该章有待评估停车场条目 → 一次 LLM 调用(预算封顶
// ChapterEvalTokens)产出「建议展开/建议丢弃+理由」写入条目;**只建议,
// 展开仍走人点 deploy**。无待评估条目/章未收官/节点无章节归属 → 如实零调用。
func (e *Engine) maybeEvalChapter(ctx context.Context, node *Node, logf func(string, string)) {
	nodes, err := e.deps.Store.ListNodes(ctx, node.CaseID)
	if err != nil {
		return
	}
	index := map[string]*Node{}
	for _, n := range nodes {
		index[n.ID] = n
	}
	goal := chapterOf(index, node)
	if goal == nil || !chapterComplete(index, nodes, goal.ID) {
		return
	}
	entries, err := e.deps.Store.ListParking(ctx, node.CaseID)
	if err != nil {
		return
	}
	var pending []*ParkingEntry
	for _, p := range entries {
		if p.Status == ParkingParked && p.Verdict == "" && p.SuggestGoalID == goal.ID {
			pending = append(pending, p)
		}
	}
	if len(pending) == 0 {
		return
	}
	if err := e.evalChapterParking(ctx, goal, pending, logf); err != nil && logf != nil {
		logf("error", "章节收官评估失败(条目保持未评估,如实): "+err.Error())
	}
}

// evalChapterParking 一次收官评估调用(单会话,预算封顶;解析失败如实报错,
// 条目保持未评估,下次收官触发点再试)。
func (e *Engine) evalChapterParking(ctx context.Context, goal *Node,
	pending []*ParkingEntry, logf func(string, string)) error {

	var sb strings.Builder
	sb.WriteString("你是应急响应意图链的章节收官评估员。章节「" + goal.Text +
		"」的全部意图已执行完毕。以下停车场线索是排查过程中被预算闸拦下或 AI 主动登记的" +
		"章外/超闸线索,未展开。请逐条给出处置建议:\n" +
		"- deploy=值得展开排查(与本案目标相关、线索具体);\n" +
		"- dismiss=建议丢弃(噪音/与本案无关/已被章内结论覆盖)。\n\n线索清单:\n")
	for _, p := range pending {
		sb.WriteString("- id=" + p.ID + " 原因=" + p.Reason + " 摘要=" + p.Text + "\n")
	}
	sb.WriteString("\n只回一个 json 代码块,结构:\n```json\n" +
		`[{"id":"条目id","verdict":"deploy|dismiss","reason":"≤60字理由"}]` + "\n```\n" +
		"逐条都要有,不许漏;不确定就给 dismiss 并如实说理由。你只给建议,展开由人决定。")

	sessID, err := e.deps.AI.CreateSessionBudget(ctx, goal.CaseID, "chapter-eval",
		ChapterEvalTokens, "")
	if err != nil {
		return fmt.Errorf("收官评估会话开账失败: %w", err)
	}
	ch, err := e.deps.AI.RunWithSystem(ctx, sessID, sb.String(), "")
	if err != nil {
		return fmt.Errorf("收官评估启动失败: %w", err)
	}
	var texts []string
	for ev := range ch {
		if ev.Kind == "text" {
			texts = append(texts, ev.Text)
		}
	}
	verdicts := parseEvalVerdicts(strings.Join(texts, ""))
	if len(verdicts) == 0 {
		return fmt.Errorf("收官评估应答未解析(未按契约收尾)")
	}
	applied := 0
	byID := map[string]*ParkingEntry{}
	for _, p := range pending {
		byID[p.ID] = p
	}
	for _, v := range verdicts {
		p := byID[v.ID]
		if p == nil || (v.Verdict != VerdictDeploy && v.Verdict != VerdictDismiss) {
			continue // 模型编造 id/档位:如实跳过,不写入
		}
		reason := v.Reason
		if utf8.RuneCountInString(reason) > 200 {
			reason = string([]rune(reason)[:200])
		}
		if err := e.deps.Store.SetParkingVerdict(ctx, p.ID, v.Verdict, reason); err != nil {
			return fmt.Errorf("评估建议落库失败: %w", err)
		}
		applied++
	}
	_, _, _ = e.deps.Audit.AppendAudit(ctx, goal.CaseID, "engine", "intent.chapter_eval",
		goal.ID, map[string]any{"goal": goal.Text, "entries": len(pending),
			"applied": applied, "session": sessID})
	text := fmt.Sprintf("章节收官评估:章「%s」%d 条停车场线索已给出处置建议(%d 条落账;"+
		"AI 只建议,展开/丢弃仍走人批)", cutRunes(goal.Text, 30), len(pending), applied)
	if logf != nil {
		logf("park", text)
	} else {
		e.emitFeedEvent(goal.CaseID, goal.ID, "park", text)
	}
	return nil
}

// parseEvalVerdicts 解析收官评估应答(最后一个 ```json 围栏块或裸数组)。
func parseEvalVerdicts(text string) []evalVerdict {
	candidates := []string{}
	rest := text
	for {
		i := strings.LastIndex(rest, "```json")
		if i < 0 {
			break
		}
		tail := rest[i+7:]
		j := strings.Index(tail, "```")
		if j < 0 {
			break
		}
		candidates = append(candidates, tail[:j])
		rest = rest[:i]
	}
	if idx := strings.LastIndex(text, "["); idx >= 0 {
		if end := strings.LastIndex(text, "]"); end > idx {
			candidates = append(candidates, text[idx:end+1])
		}
	}
	for _, c := range candidates {
		var out []evalVerdict
		if err := json.Unmarshal([]byte(strings.TrimSpace(c)), &out); err == nil && len(out) > 0 {
			return out
		}
	}
	return nil
}
