// 案件黑板(0.28.0-blackboard,读侧):每案一块板,从现有意图图/停车场
// 派生(不建新表),分四段——
//
//   - 已确认事实:proves 边确认的 fact 节点(文本+锚点),上限 30 条;
//   - 存疑发现:doubt 意图的收尾摘要,上限 15 条;
//   - 在查/已查意图清单:非 parked 意图标题级一行(标状态;在查优先),
//     上限 60 条;
//   - 停车场线索:parked 条目一行一条,上限 10 条。
//
// 两个消费面共用同一份派生逻辑(buildBlackboard),不两处实现:
//   - worker systemExtra 注入(RenderBlackboard,总预算 4000 中文字宽,
//     逐段截断如实标「其余 N 条未注入」;查询失败如实标注不杀 worker,
//     同启发式参考口径——它不是「不得触碰」类红线);
//   - 前端黑板 tab(GET /api/cases/{id}/blackboard):人也能一眼看到
//     「AI 现在知道什么」。
//
// 设计依据(HEARSAY-II 经典黑板 + ARTEX 实现):任务域绑定(每案一块板,
// 不跨案)、部分解(知识源只读写板,互不可见)、文本预算+截断如实。
package intent

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"
)

// 黑板四段条目上限与注入总预算(rune,中文字宽口径)。
const (
	bbMaxFacts    = 30
	bbMaxDoubts   = 15
	bbMaxIntents  = 60
	bbMaxParking  = 10
	bbBudgetRunes = 4000
)

// BlackboardFact 已确认事实一条(proves 边确认的 fact;锚点可回溯)。
type BlackboardFact struct {
	NodeID  string   `json:"node_id"`
	Text    string   `json:"text"`
	Anchors []Anchor `json:"anchors"`
}

// BlackboardDoubt 存疑发现一条(doubt 意图:标题+收尾摘要)。
type BlackboardDoubt struct {
	NodeID  string `json:"node_id"`
	Intent  string `json:"intent"`
	Summary string `json:"summary"`
}

// BlackboardIntent 在查/已查意图一行(标题级+状态)。
type BlackboardIntent struct {
	NodeID string `json:"node_id"`
	Text   string `json:"text"`
	Status string `json:"status"`
}

// Blackboard 案件黑板(API 返回形;XxxTotal=全集条数,切片=已注入/已呈现
// 条数,差值=被上限截掉的条数,如实)。
type Blackboard struct {
	CaseID       string             `json:"case_id"`
	Facts        []BlackboardFact   `json:"facts"`
	FactsTotal   int                `json:"facts_total"`
	Doubts       []BlackboardDoubt  `json:"doubts"`
	DoubtsTotal  int                `json:"doubts_total"`
	Intents      []BlackboardIntent `json:"intents"`
	IntentsTotal int                `json:"intents_total"`
	Parking      []*ParkingEntry    `json:"parking"`
	ParkingTotal int                `json:"parking_total"`
}

// Blackboard 案件黑板(web 层 GET /api/cases/{id}/blackboard 用)。
func (e *Engine) Blackboard(ctx context.Context, caseID string) (*Blackboard, error) {
	nodes, err := e.deps.Store.ListNodes(ctx, caseID)
	if err != nil {
		return nil, err
	}
	return e.blackboardFrom(ctx, caseID, nodes)
}

// blackboardFrom 已知节点快照下的黑板派生(worker systemExtra 复用
// hint 段已取的节点清单,不重复查;边/停车场两条查询失败如实上抛,
// 调用方按「不杀 worker」口径降级标注)。
func (e *Engine) blackboardFrom(ctx context.Context, caseID string, nodes []*Node) (*Blackboard, error) {
	edges, err := e.deps.Store.ListEdges(ctx, caseID)
	if err != nil {
		return nil, fmt.Errorf("黑板边清单查询失败: %w", err)
	}
	parking, err := e.deps.Store.ListParking(ctx, caseID)
	if err != nil {
		return nil, fmt.Errorf("黑板停车场清单查询失败: %w", err)
	}
	return buildBlackboard(caseID, nodes, edges, parking), nil
}

// buildBlackboard 黑板派生纯逻辑(单一实现:worker 注入与 API 同一份)。
func buildBlackboard(caseID string, nodes []*Node, edges []*Edge, parking []*ParkingEntry) *Blackboard {
	bb := &Blackboard{CaseID: caseID,
		Facts: []BlackboardFact{}, Doubts: []BlackboardDoubt{},
		Intents: []BlackboardIntent{}, Parking: []*ParkingEntry{}}

	// 已确认事实 = 有 proves 出边的 fact 节点(系统按证据结构确认,
	// supported 写回时才落 proves,见 worker.writeBack)
	proven := map[string]bool{}
	for _, ed := range edges {
		if ed.Kind == EdgeProves {
			proven[ed.FromID] = true
		}
	}
	for _, n := range nodes {
		switch {
		case n.Kind == KindFact && proven[n.ID]:
			bb.FactsTotal++
			if len(bb.Facts) < bbMaxFacts {
				bb.Facts = append(bb.Facts, BlackboardFact{NodeID: n.ID, Text: n.Text, Anchors: n.Evidence})
			}
		case n.Kind == KindIntent && n.Status == StatusDoubt:
			bb.DoubtsTotal++
			if len(bb.Doubts) < bbMaxDoubts {
				bb.Doubts = append(bb.Doubts, BlackboardDoubt{
					NodeID: n.ID, Intent: n.Text, Summary: n.ResultText})
			}
		}
	}

	// 在查/已查意图:非 parked 的 intent;在查(open/running/awaiting)排前,
	// 已查终态随后,各自保持创建序(在查的一眼可见,不被历史淹没)
	var active, done []*Node
	for _, n := range nodes {
		if n.Kind != KindIntent || n.Status == StatusParked {
			continue
		}
		switch n.Status {
		case StatusOpen, StatusRunning, StatusAwaitingApproval:
			active = append(active, n)
		default:
			done = append(done, n)
		}
	}
	for _, n := range append(active, done...) {
		bb.IntentsTotal++
		if len(bb.Intents) < bbMaxIntents {
			bb.Intents = append(bb.Intents, BlackboardIntent{NodeID: n.ID, Text: n.Text, Status: n.Status})
		}
	}

	for _, p := range parking {
		if p.Status != ParkingParked {
			continue // 已处置的是历史账(停车场 tab 看),不占黑板
		}
		bb.ParkingTotal++
		if len(bb.Parking) < bbMaxParking {
			bb.Parking = append(bb.Parking, p)
		}
	}
	return bb
}

// RenderBlackboard 黑板 → worker systemExtra 注入段(总预算 bbBudgetRunes
// rune 记条目与段头,逐行记账,行写不进即截断,如实标「其余 N 条未注入」;
// 预算耗尽后后续段整段不注入,同样如实标。截断标注本身是控制元信息,
// 不占预算,固定短小)。空段如实写「暂无」,不藏。
func RenderBlackboard(bb *Blackboard) string {
	var b strings.Builder
	intro := "\n\n## 案件黑板(本案实时状态:兄弟分支在查什么/已确认什么/什么存疑)\n\n" +
		"优先级低于操作约束与人工线索,与启发式参考平级——但这是本案实时状态:" +
		"派生新意图前先对照「在查/已查意图清单」,已在查/已查过的方向不要重复派" +
		"(系统有去重闸,重复/高度相似的派生会被拦进停车场);引用黑板上的结论仍需自己核锚点。\n"
	b.WriteString(intro)

	rem := bbBudgetRunes - utf8.RuneCountInString(intro)
	if rem < 0 {
		rem = 0
	}
	exhausted := false // 总预算耗尽:后续段整段未注入(如实标)
	emit := func(s string) bool {
		if exhausted {
			return false
		}
		n := utf8.RuneCountInString(s)
		if n > rem {
			exhausted = true
			return false
		}
		rem -= n
		b.WriteString(s)
		return true
	}
	note := func(s string) { b.WriteString(s) } // 截断标注:控制元信息,不占预算

	// section 一段:head=段头(含条数),lines=条目行,total=全集条数。
	// 返回后调用方无需再管;预算语义全收口在这。
	section := func(head string, lines []string, total int) {
		if exhausted {
			note("\n### " + head + "\n\n(总预算耗尽,本段未注入,详见案件页黑板 tab,如实)\n")
			return
		}
		emit("\n### " + head + "\n\n")
		if total == 0 {
			emit("(暂无)\n")
			return
		}
		shown := 0
		for _, ln := range lines {
			if !emit(ln) {
				break
			}
			shown++
		}
		if rest := total - shown; rest > 0 {
			if exhausted {
				note(fmt.Sprintf("(总预算耗尽,其余 %d 条未注入,详见案件页黑板 tab,如实)\n", rest))
			} else {
				note(fmt.Sprintf("(其余 %d 条未注入,详见案件页黑板 tab,如实)\n", rest))
			}
		}
	}

	factLines := make([]string, 0, len(bb.Facts))
	for _, f := range bb.Facts {
		factLines = append(factLines, "- "+f.Text+bbAnchorSuffix(f.Anchors)+"\n")
	}
	section(fmt.Sprintf("已确认事实(系统按证据结构确认,锚点可回溯;共 %d 条)", bb.FactsTotal),
		factLines, bb.FactsTotal)

	doubtLines := make([]string, 0, len(bb.Doubts))
	for _, d := range bb.Doubts {
		ln := "- " + d.Intent
		if d.Summary != "" {
			ln += " → " + cutRunes(d.Summary, 80)
		}
		doubtLines = append(doubtLines, ln+"\n")
	}
	section(fmt.Sprintf("存疑发现(证据不足/数据未覆盖,如实存疑;共 %d 条)", bb.DoubtsTotal),
		doubtLines, bb.DoubtsTotal)

	intentLines := make([]string, 0, len(bb.Intents))
	for _, it := range bb.Intents {
		intentLines = append(intentLines, "- ["+it.Status+"] "+it.Text+"\n")
	}
	section(fmt.Sprintf("在查/已查意图清单(共 %d 条;派生前先对照,勿重复)", bb.IntentsTotal),
		intentLines, bb.IntentsTotal)

	parkLines := make([]string, 0, len(bb.Parking))
	for _, p := range bb.Parking {
		parkLines = append(parkLines, "- "+p.Text+"\n")
	}
	section(fmt.Sprintf("停车场线索(未展开,人批才开;共 %d 条)", bb.ParkingTotal),
		parkLines, bb.ParkingTotal)
	return b.String()
}

// bbAnchorSuffix 事实锚点尾巴(最多 3 个,source_id:line;零锚点如实标——
// proves 确认的事实按理有锚点,缺了不藏)。
func bbAnchorSuffix(anchors []Anchor) string {
	if len(anchors) == 0 {
		return "(锚点缺失,见节点详情,如实)"
	}
	parts := []string{}
	for i, a := range anchors {
		if i >= 3 {
			parts = append(parts, fmt.Sprintf("等 %d 个", len(anchors)))
			break
		}
		if a.LineNo > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", a.SourceID, a.LineNo))
		} else {
			parts = append(parts, a.SourceID)
		}
	}
	return "(锚: " + strings.Join(parts, ", ") + ")"
}
