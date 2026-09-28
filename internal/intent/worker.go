// worker:领一条意图 → 单意图单 norma 会话(六个只读工具)→ 执行留痕 →
// 系统按证据结构评估(§6.2:模型只给材料,档位系统算)→ 写回 fact →
// 派生子意图(模板子 + AI 子,深度 ≤5)。
package intent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// eventTextCap 单条过程流事件文本上限(rune)。
const eventTextCap = 800

// maxAIChildren 单次写回最多派生的 AI 子意图数(防烂模型刷图)。
const maxAIChildren = 5

// parkLead AI 主动登记的章外线索(0.24.0 停车场;只登记不展开,人批才开)。
type parkLead struct {
	Text    string `json:"text"`    // 线索摘要(一句话)
	Suggest string `json:"suggest"` // 归属建议(哪章/新开章;人读标签)
}

// verdict 机器解析的收尾契约(worker systemExtra 里写死结构)。
type verdict struct {
	Verdict   string     `json:"verdict"`
	Summary   string     `json:"summary"`
	Anchors   []Anchor   `json:"anchors"`
	Children  []string   `json:"children"`
	ParkLeads []parkLead `json:"park_leads"` // 0.24.0:章外线索登记(停车场)
}

// systemExtra 意图上下文(附加在 agentloop 铁律 SystemPrompt 之后的第二段)。
// 含:意图正文/规则来源/模板排查要点/主机范围 + 案件级操作约束(人定,最高
// 优先——查不到约束宁可不跑,fail-closed)+ 人工线索(hint,下轮可见的
// 兑现处)。返回 error = 约束/线索清单查询失败(调用方如实 fail,不裸奔)。
func (e *Engine) systemExtra(ctx context.Context, node *Node) (string, error) {
	var b strings.Builder
	b.WriteString("# 意图链任务\n\n你正在意图链引擎中执行一条排查意图" +
		"(单意图单会话;只读纪律/锚点纪律/疑似措辞铁律全部不变)。\n\n## 当前意图\n\n")
	b.WriteString(node.Text)
	if node.RuleID != "" {
		b.WriteString("\n\n该意图由规则/算子 " + node.RuleID + " 的扫描候选派生;" +
			"先用 list_hits(status=pending) 看该规则候选,再逐条核实锚点。")
	}
	if tpl := e.deps.Templates[node.TemplateID]; tpl != nil && node.TemplateKey != "" {
		baseKey := node.TemplateKey // per-host 展开节点带 @主机后缀,要点按裸 key 查
		if i := strings.LastIndex(baseKey, "@"); i > 0 {
			baseKey = baseKey[:i]
		}
		if ti := tpl.Find(baseKey); ti != nil && ti.Ask != "" {
			b.WriteString("\n\n## 排查要点\n\n")
			b.WriteString(ti.Ask)
		}
	}
	if node.HostScope != "" {
		b.WriteString("\n\n## 主机范围\n\n本意图限定在主机 " + node.HostScope +
			" 上排查:你的工具已被系统限定在该主机的源集合(list_sources 只列该主机," +
			"检索/算子/回查只覆盖该主机),不要尝试查其他主机的源。")
	}
	// 操作约束(设计 §3 set_constraints 应急映射;人定,最高优先)
	cs, err := e.deps.Store.ListConstraints(ctx, node.CaseID)
	if err != nil {
		return "", fmt.Errorf("操作约束清单查询失败: %w", err)
	}
	if len(cs) > 0 {
		b.WriteString("\n\n## 操作约束(操作员设定,最高优先,与约束冲突的方向宁可不查)\n\n")
		for _, c := range cs {
			b.WriteString("- " + c.Text + "\n")
		}
	}
	// 人工线索(设计 §3 add_hint:hint 节点挂图,worker 下轮可见)
	nodes, err := e.deps.Store.ListNodes(ctx, node.CaseID)
	if err != nil {
		return "", fmt.Errorf("人工线索清单查询失败: %w", err)
	}
	hints := []string{}
	for _, n := range nodes {
		if n.Kind == KindHint {
			hints = append(hints, n.Text)
		}
	}
	if len(hints) > 0 {
		b.WriteString("\n\n## 人工线索(操作员补充,排查时务必参考;" +
			"线索不是已证实的事实,引用仍需锚点)\n\n")
		for _, h := range hints {
			b.WriteString("- " + h + "\n")
		}
	}
	// 案件黑板(0.28.0-blackboard):本案实时状态四段(已确认事实/存疑发现/
	// 在查已查清单/停车场线索),优先级低于约束与 hint,与启发式参考平级
	// 但标注「这是本案实时状态」——据此避免重复排查(写侧另有去重闸收口)。
	// 节点清单复用 hint 段已取的快照,不重复查;派生查询失败如实标注不杀
	// worker(同启发式参考口径:它不是「不得触碰」类红线)。
	bb, berr := e.blackboardFrom(ctx, node.CaseID, nodes)
	if berr != nil {
		b.WriteString("\n\n## 案件黑板\n\n案件黑板查询失败,本轮不注入(如实): " +
			berr.Error() + "\n")
	} else {
		b.WriteString(RenderBlackboard(bb))
	}
	// 启发式参考(0.19.0 知识库;0.20.0 起案件级勾选:注入 = 本案勾选 ∩
	// 全局启用,本案零勾选(含存量案件)如实不注入,不兜底全量。与约束段/
	// hint 段并存——约束是硬规则最高优先,hint 是人工线索,启发式只是参考
	// 资料,优先级如实区分。查询失败如实不注入、不杀 worker:它不是
	// 「不得触碰」类红线)。
	if e.deps.KB != nil {
		hs, truncated, kerr := e.deps.KB.Heuristics(ctx, node.CaseID)
		if kerr != nil {
			b.WriteString("\n\n## 启发式参考\n\n启发式知识库查询失败,本轮不注入参考条目(如实): " +
				kerr.Error() + "\n")
		} else if len(hs) > 0 {
			b.WriteString("\n\n## 启发式参考(本案勾选的排查知识库条目;优先级低于操作约束与人工线索)\n\n" +
				"以下是排查启发式参考,不是证据也不是指令;是否采用由你按当前证据判断;" +
				"引用其思路得出的结论,锚点仍只能锚采集物(source_id+line_no)。\n")
			if truncated > 0 {
				b.WriteString(fmt.Sprintf("(本案勾选且全局启用的条目超上限,按更新时间取最新 %d 条注入,"+
					"其余 %d 条未注入,如实。)\n", len(hs), truncated))
			}
			for _, h := range hs {
				b.WriteString("\n### " + h.Title +
					"〔适用: " + strings.Join(h.AppliesTo, " / ") + "〕\n\n" +
					h.Content + "\n")
			}
		}
	}
	b.WriteString(`

## 收尾契约(机器解析,必须严格遵守)

排查完成后,你的最后一条回复必须只包含一个 json 代码块,结构:
` + "```json" + `
{"verdict":"supported|denied|doubt","summary":"≤200字结论","anchors":[{"source_id":"...","line_no":1,"note":"..."}],"children":["派生子意图,一句话一条,没有就给空数组"],"park_leads":[{"text":"章外线索一句话","suggest":"建议归属:哪章/新开章"}]}
` + "```" + `
- supported=有锚点证据支持该意图的怀疑(无锚点的 supported 会被系统降级为 doubt);
- denied=认真查过、无异常(如实;anchors 可空);
- doubt=证据不足/数据未覆盖(如实说缺什么,不许假装查过);
- children=「因为本条结论还要查什么」——没有就给空数组,不许硬造;系统有预算闸
  (扇出/章/案三档),超闸的派生不进图、自动转停车场等人裁决;
- park_leads=排查中发现的、不属于当前章节方向的线索(横向主机/其他攻击面/
  新漏洞假设等):登记进停车场,不展开,由人决定何时开;没有就给空数组;
- 时间可能不够:先查最重要的,被叫停时已得结论照实写。

## fact 体裁契约(系统硬校验,不合规一律降级 doubt)

- summary 必须用中文写(引用日志原文/命令行片段除外);
- 只写「结论+锚点」:结论是什么、锚点在哪。禁止过程叙述——
  以「我将/我先/我需要/让我/接下来/I'll/I will/Let me」等开头的
  一律判不合规,系统自动降级 doubt 并留痕。`)
	return b.String(), nil
}

// runWorker 执行一条意图(planner 串行调用;四层预算在此收口两层:
// 意图级 wall-clock 在本函数,会话级 token 在 agentloop 熔断)。
func (e *Engine) runWorker(ctx context.Context, node *Node) {
	now := e.deps.Now
	logf := func(kind, text string) {
		if utf8.RuneCountInString(text) > eventTextCap {
			text = string([]rune(text)[:eventTextCap]) + "…"
		}
		_ = e.deps.Store.AppendEvent(context.Background(), node.CaseID, node.ID, kind, text)
		e.emitFeedEvent(node.CaseID, node.ID, kind, text) // 播报·中间发现档
	}
	fail := func(msg string) {
		logf("error", msg)
		_ = e.deps.Store.FinishNode(context.Background(), node.ID, StatusClosed,
			"", "执行失败(引擎侧,如实): "+msg, nil, now().UTC())
		e.emitNodeUpdated(context.Background(), node.ID)
		e.emitFeedFinish(node.CaseID, node.ID, StatusClosed, "", "执行失败(引擎侧,如实): "+msg)
	}

	// 会话级:单意图单 norma 会话(token 预算=会话级层;主机范围随会话绑定)
	sessID, err := e.deps.AI.CreateSessionBudget(ctx, node.CaseID,
		"worker:"+node.CreatedBy, e.deps.TokenBudget, node.HostScope)
	if err != nil {
		fail("AI 会话开账失败: " + err.Error())
		return
	}
	ok, err := e.deps.Store.MarkRunning(ctx, node.ID, sessID, now().UTC())
	if err != nil || !ok {
		return // 认领失败=已被领走/状态已变,如实不跑
	}
	e.emitNodeUpdated(ctx, node.ID) // open→running:图上看脉冲
	logf("plan", fmt.Sprintf("认领意图,开工(会话 %s,wall-clock 预算 %ds,token 预算 %d)",
		sessID, node.BudgetSeconds, e.deps.TokenBudget))
	_, _, _ = e.deps.Audit.AppendAudit(context.Background(), node.CaseID,
		"worker", "intent.start", node.ID, map[string]any{
			"session": sessID, "text": node.Text, "budget_seconds": node.BudgetSeconds,
		})

	h := &runHandle{caseID: node.CaseID, sessionID: sessID}
	e.mu.Lock()
	e.running[node.ID] = h
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		delete(e.running, node.ID)
		e.mu.Unlock()
	}()

	// 意图级 wall-clock:耗尽 → 停查(Abort)→ 写回已得 → closed_exhausted
	budget := node.BudgetSeconds
	if budget <= 0 {
		budget = e.deps.BudgetSeconds
	}
	timer := newBudgetTimer(budget, h, func() {
		_ = e.deps.AI.Abort(context.Background(), sessID, "intent-budget")
	})
	defer timer.Stop()

	sysExtra, err := e.systemExtra(ctx, node)
	if err != nil {
		// 约束/线索清单查不到宁可不跑(fail-closed:约束是最高优先,
		// 裸奔可能违反「不得触碰」类约束)
		fail("意图上下文装配失败(未执行,如实): " + err.Error())
		return
	}

	// 纠偏循环(交互改造切片三 steer):一轮跑完若队列里有人工纠偏,
	// 同一 AI 会话续跑(transcript 延续),纠偏文本作为新 user 消息;
	// wall-clock 计时器跨轮不重置。texts 跨轮累计——extractVerdict 取
	// 最后一个 json 块,终轮收尾契约天然胜出。
	prompt := "执行意图链中的当前意图,并按 system 里的收尾契约收尾。"
	var texts []string
	var finalReason string
	explored := map[string]bool{}
	for {
		ch, err := e.deps.AI.RunWithSystem(ctx, sessID, prompt, sysExtra)
		if err != nil {
			fail("AI 会话启动失败: " + err.Error())
			return
		}

		// 消费事件流 → 过程流落账;摸过的源(explored)随手记。
		// text 事件是流式碎片:连续碎片合并成一条过程流事件(可回放性),
		// 非 text 事件到达时冲刷。
		finalReason = ""
		roundTexts := 0 // 本轮流式碎片计数(零碎片时 result 全文兜底)
		var textBuf strings.Builder
		flushText := func() {
			if textBuf.Len() > 0 {
				logf("text", textBuf.String())
				textBuf.Reset()
			}
		}
		for ev := range ch {
			switch ev.Kind {
			case "text":
				texts = append(texts, ev.Text)
				roundTexts++
				textBuf.WriteString(ev.Text)
			case "thinking":
				flushText()
				logf("thinking", ev.Text)
			case "tool_use":
				flushText()
				logf("tool_use", ev.ToolName+" "+ev.ToolInput)
				if sid := extractSourceID(ev.ToolInput); sid != "" {
					explored[sid] = true
				}
			case "tool_result":
				flushText()
				logf("tool_result", ev.ToolOutput)
			case "usage":
				// token 账在 ai_sessions,过程流不逐笔刷(噪声)
			case "budget_exceeded":
				flushText()
				finalReason = "budget_exceeded"
				logf("budget", ev.ErrText)
			case "result":
				flushText()
				finalReason = ev.Reason
				if ev.Text != "" && roundTexts == 0 {
					texts = append(texts, ev.Text) // 无流式碎片时终态全文兜底
				}
				if ev.ErrText != "" {
					logf("error", "模型侧: "+ev.ErrText)
				}
			case "error":
				flushText()
				logf("error", ev.ErrText)
			}
		}
		flushText()

		steer, redirect := h.takeSteerOrSeal()
		if !redirect {
			break
		}
		logf("steer", "人工纠偏(本轮被中断,同一会话按纠偏方向续跑): "+steer)
		prompt = "【人工纠偏】操作员对本次排查的调整指令(优先级高于你当前的" +
			"探索方向):\n" + steer + "\n\n按纠偏后的方向继续排查;收尾契约不变。"
	}
	// 流式碎片直接拼接(不插 \n:碎片边界落在 JSON 字符串里会拼出
	// 非法控制字符,收尾契约解析必挂——台架实测踩过)
	full := strings.Join(texts, "")
	e.writeBack(node, h, full, finalReason, explored)
	e.Wake(node.CaseID) // 写回即图变更:唤醒 planner 续派(子意图/下一条)
}

// writeBack 评估 + 写回(终态/fact/锚点/子意图)。系统按证据结构算档:
// 无锚点的 supported 降级 doubt(§6.2,模型自评不作数)。
func (e *Engine) writeBack(node *Node, h *runHandle, full, finalReason string,
	explored map[string]bool) {

	ctx := context.Background()
	now := e.deps.Now().UTC()
	logf := func(kind, text string) {
		if utf8.RuneCountInString(text) > eventTextCap {
			text = string([]rune(text)[:eventTextCap]) + "…"
		}
		_ = e.deps.Store.AppendEvent(ctx, node.CaseID, node.ID, kind, text)
		e.emitFeedEvent(node.CaseID, node.ID, kind, text) // 播报·中间发现档
	}

	// 摸过的源上证据图(explored;源覆盖图的「查没查过」)
	var exp []Anchor
	for sid := range explored {
		exp = append(exp, Anchor{SourceID: sid})
	}
	if len(exp) > 0 {
		_ = e.deps.Store.AddAnchors(ctx, node.CaseID, node.ID, "explored", exp)
	}

	// 终态判定:中断理由优先(预算/人工),其次模型收尾契约
	var status, summary, closeNote string
	var anchors []Anchor
	var children []string
	var parkLeads []parkLead
	switch h.getReason() {
	case "budget":
		status = StatusClosedExhausted
		v := extractVerdict(full)
		summary = v.Summary
		anchors = filterAnchors(v.Anchors)
		closeNote = fmt.Sprintf("时间耗尽(wall-clock %ds),已停查并写回已得;"+
			"覆盖可能不全(如实标,非失败)", node.BudgetSeconds)
		logf("budget", closeNote)
	case "user":
		status = StatusClosed
		v := extractVerdict(full)
		summary = v.Summary
		anchors = filterAnchors(v.Anchors)
		closeNote = "人工停止,已写回已得"
		logf("stop", closeNote)
	default:
		v := extractVerdict(full)
		status, summary = v.Verdict, v.Summary
		anchors = filterAnchors(v.Anchors)
		children = v.Children
		parkLeads = v.ParkLeads
		switch status {
		case StatusSupported:
			if len(anchors) == 0 {
				status = StatusDoubt
				closeNote = "模型报 supported 但零锚点,系统按证据结构降级 doubt(§6.2)"
			}
		case StatusDenied, StatusDoubt:
		default:
			status = StatusDoubt
			closeNote = "收尾契约未解析(模型未按格式收尾),如实记 doubt"
		}
		if finalReason == "budget_exceeded" {
			closeNote = strings.TrimSpace(closeNote + " 会话 token 预算熔断(agentloop)")
		}
		logf("eval", fmt.Sprintf("评估: %s(%s)", status, closeNote))
	}
	if summary == "" && full != "" {
		summary = full
		if utf8.RuneCountInString(summary) > 400 {
			summary = string([]rune(summary)[:400]) + "…"
		}
	}

	// fact 体裁契约(M3):中文 + 只写结论+锚点;不合规降级 doubt 如实记
	// (与「无锚点 supported 降级」同档,genre.go)。
	if gv := factGenreViolation(summary); gv != "" {
		gnote := "fact 体裁不合规(" + gv + "),系统按契约降级 doubt 如实记录"
		if status == StatusSupported || status == StatusDenied {
			status = StatusDoubt
		}
		closeNote = strings.TrimSpace(closeNote + " " + gnote)
		logf("eval", "体裁闸: "+gv)
	}

	if err := e.deps.Store.FinishNode(ctx, node.ID, status, summary,
		closeNote, anchors, now); err != nil {
		logf("error", "写回失败: "+err.Error())
		return
	}
	e.emitNodeUpdated(ctx, node.ID) // 终态写回:图上看变色(绿/灰/琥珀)
	e.emitFeedFinish(node.CaseID, node.ID, status, summary, closeNote) // 播报·终结档
	if len(anchors) > 0 {
		_ = e.deps.Store.AddAnchors(ctx, node.CaseID, node.ID, "evidence", anchors)
	}
	_, _, _ = e.deps.Audit.AppendAudit(ctx, node.CaseID, "worker",
		"intent.finish", node.ID, map[string]any{
			"status": status, "anchors": len(anchors), "close_note": closeNote,
		})

	// fact 写回(有实质结论才落;边:意图 yields fact,supported 时 fact proves 意图)
	if summary != "" {
		fact := &Node{CaseID: node.CaseID, Kind: KindFact, Text: summary,
			Status: StatusClosed, CreatedBy: ByAI, Scope: node.Scope,
			HostScope: node.HostScope,
			ParentID: node.ID, Depth: node.Depth, Evidence: anchors,
			BudgetSeconds: node.BudgetSeconds}
		if err := ValidateNode(fact); err == nil {
			if err := e.deps.Store.CreateNode(ctx, fact); err == nil {
				e.emitNodeAdded(fact)
				yEd := &Edge{CaseID: node.CaseID, FromID: node.ID, ToID: fact.ID, Kind: EdgeYields}
				if err := e.deps.Store.CreateEdge(ctx, yEd); err == nil {
					e.emitEdgeAdded(yEd)
				}
				if status == StatusSupported {
					pEd := &Edge{CaseID: node.CaseID, FromID: fact.ID, ToID: node.ID, Kind: EdgeProves}
					if err := e.deps.Store.CreateEdge(ctx, pEd); err == nil {
						e.emitEdgeAdded(pEd)
					}
				}
				if len(anchors) > 0 {
					_ = e.deps.Store.AddAnchors(ctx, node.CaseID, fact.ID, "evidence", anchors)
				}
			}
		}
	}

	// 派生子意图(模板子 + AI 子;深度闸 ≤MaxDepth;0.24.0 预算三闸在此收口,
	// 超闸转停车场不进图)
	if node.Depth+1 <= MaxDepth && (status == StatusSupported ||
		status == StatusDenied || status == StatusDoubt) {
		e.spawnChildren(ctx, node, children, logf)
		// AI 章外线索申请(park_leads):登记停车场,不展开,人批才开
		for i, pl := range parkLeads {
			if i >= maxParkLeads {
				logf("park", fmt.Sprintf("停车场申请超上限(≤%d 条/次),其余如实丢弃",
					maxParkLeads))
				break
			}
			if err := e.ParkLead(ctx, node, pl.Text, pl.Suggest, logf); err != nil {
				logf("error", "停车场申请落库失败: "+err.Error())
			}
		}
	}
	// 章节收官评估(0.24.0):本条写回后章内意图全终态 且 该章停车场有待评估
	// 条目 → 一次 LLM 调用给建议(只建议,展开走人);否则如实零调用
	e.maybeEvalChapter(ctx, node, logf)
	// goal 收官重估(0.29.1):章内意图全终态 → goal 置机器评估终态
	// (幂等;失败如实记过程流,不挡写回)
	e.reevalGoalsQuiet(ctx, node.CaseID, logf)
}

// spawnChildren 模板子意图(after 链)+ AI 提议子意图(审批门按 GateStatus)。
// 0.24.0 预算三闸(L1)在此收口:每条派生前过闸(扇出→章→案),超闸不进
// open 队列,转停车场(parked 节点+parking 条目+过程流/播报/审计留痕);
// 只闸自动派生,人工手写意图不过闸(判断权归人)。
func (e *Engine) spawnChildren(ctx context.Context, node *Node, aiChildren []string,
	logf func(string, string)) {

	lim := e.limits()
	// 闸计数与模板判重共用一份节点快照;库读不出=闸失效,如实不派生
	// (预算闸是防爆炸保险丝,不裸奔)——与 systemExtra 约束 fail-closed 同纪律
	nodes, nerr := e.deps.Store.ListNodes(ctx, node.CaseID)
	if nerr != nil {
		logf("error", "节点清单查询失败(预算闸/判重不可用,本轮不派生,如实): "+nerr.Error())
		return
	}
	spawned := 0 // 本轮已派生(进图+parked)数;maxAIChildren 硬顶用
	noteSpawned := func(n *Node) { nodes = append(nodes, n) } // 快照续上,闸计数连续
	gate := func() *spawnGate { return e.checkSpawnGates(lim, node, nodes) }
	// 去重闸的归属建议章:父节点祖先链不变(快照追加的只是子孙),算一次即可
	chapterIdx := map[string]*Node{}
	for _, n := range nodes {
		chapterIdx[n.ID] = n
	}
	chapterGoal := chapterOf(chapterIdx, node)

	if tpl := e.deps.Templates[node.TemplateID]; tpl != nil && node.TemplateKey != "" {
		// 幂等:同案同模板同 key 已存在则跳过(worker 重跑不重复长;
		// parked 节点带 template_key,同样占判重——展开走 deploy,不重派)
		existing := map[string]bool{}
		for _, n := range nodes {
			if n.TemplateID == node.TemplateID {
				existing[n.TemplateKey] = true
			}
		}
		// per-host 展开的节点 template_key 带 @主机后缀;父子派生按裸 key 查,
		// 主机范围沿父节点继承(单主机排查链不串台;host_scope=all 显式跨机)
		baseKey := node.TemplateKey
		if i := strings.LastIndex(baseKey, "@"); i > 0 {
			baseKey = baseKey[:i]
		}
		for _, ti := range tpl.ChildrenOf(baseKey) {
			cp := *ti
			if node.HostScope != "" && (cp.HostScope == "" || cp.HostScope == "each") {
				cp.HostScope = node.HostScope
			}
			// each(父节点无主机范围):按已建模主机逐台判重展开
			if cp.HostScope == "each" {
				hosts, herr := e.deps.Store.ListHosts(ctx, node.CaseID)
				if herr != nil {
					logf("error", "主机清单查询失败(each 展开): "+herr.Error())
					continue
				}
				for _, h := range hosts {
					hostCP := cp
					hostCP.HostScope = h
					hostCP.Key = cp.Key + "@" + h
					if existing[hostCP.Key] {
						continue
					}
					if g := gate(); g != nil {
						if pn := e.parkTemplateChild(ctx, node, tpl, &hostCP, g, logf); pn != nil {
							existing[hostCP.Key] = true
							noteSpawned(pn)
							spawned++ // parked 也占扇出账(与 checkSpawnGates 口径一致)
						}
						continue
					}
					if _, err := e.spawnTemplateIntent(ctx, node, tpl, &hostCP, node.Depth+1); err != nil {
						logf("error", "模板子意图派生失败: "+err.Error())
						continue
					}
					existing[hostCP.Key] = true
					spawned++
					logf("spawn", "模板派生子意图("+h+"): "+ti.Text)
				}
				continue
			}
			spawnKey := cp.Key
			if cp.HostScope != "" && cp.HostScope != "all" {
				spawnKey = cp.Key + "@" + cp.HostScope
			}
			if existing[spawnKey] {
				continue
			}
			cp.Key = spawnKey
			if g := gate(); g != nil {
				if pn := e.parkTemplateChild(ctx, node, tpl, &cp, g, logf); pn != nil {
					existing[spawnKey] = true
					noteSpawned(pn)
					spawned++
				}
				continue
			}
			n, err := e.spawnTemplateIntent(ctx, node, tpl, &cp, node.Depth+1)
			if err != nil {
				logf("error", "模板子意图派生失败: "+err.Error())
				continue
			}
			existing[spawnKey] = true
			noteSpawned(n)
			spawned++
			logf("spawn", "模板派生子意图: "+ti.Text)
		}
	}
	for _, c := range aiChildren {
		c = strings.TrimSpace(c)
		if c == "" || spawned >= maxAIChildren {
			continue
		}
		if utf8.RuneCountInString(c) > 300 {
			c = string([]rune(c)[:300])
		}
		child := &Node{CaseID: node.CaseID, Kind: KindIntent, Text: c,
			CreatedBy: ByAI, Scope: node.Scope, HostScope: node.HostScope,
			ParentID: node.ID, Depth: node.Depth + 1, BudgetSeconds: node.BudgetSeconds}
		// 派生去重闸(0.28.0 黑板写侧,dedup.go):AI 派生 vs 本案现存意图
		// (非 parked)——完全重复直接拦,高度相似转停车场人裁;只闸 AI 派生,
		// 人工手写/模板播种不过闸(判断权归人;模板另有 key 幂等判重)。
		// 误拦代价低(停车场人可捞),放行代价是烧 token 重复排查,保守优先。
		if dv, score, hit := CheckIntentDup(c, nodes); dv != DupNone {
			g := &spawnGate{reason: ParkReasonDupExact, goal: chapterGoal,
				detail: "与现存意图完全重复: 「" + cutRunes(hit.Text, 40) + "」"}
			if dv == DupSimilar {
				g.reason = ParkReasonDupSimilar
				g.detail = fmt.Sprintf("与现存意图「%s」关键词 Jaccard %.2f ≥ %.2f",
					cutRunes(hit.Text, 40), score, DupJaccardThreshold)
			}
			if err := e.park(ctx, node, child, g, logf); err != nil {
				logf("error", "重复意图转停车场失败: "+err.Error())
				continue
			}
			noteSpawned(child)
			spawned++
			continue
		}
		if g := gate(); g != nil {
			if err := e.park(ctx, node, child, g, logf); err != nil {
				logf("error", "AI 子意图转停车场失败: "+err.Error())
				continue
			}
			noteSpawned(child)
			spawned++
			continue
		}
		child.Status = GateStatus(child.CreatedBy, child.Scope)
		if err := ValidateNode(child); err != nil {
			continue
		}
		if err := e.deps.Store.CreateNode(ctx, child); err != nil {
			logf("error", "AI 子意图派生失败: "+err.Error())
			continue
		}
		e.emitNodeAdded(child)
		cEd := &Edge{CaseID: node.CaseID, FromID: node.ID, ToID: child.ID, Kind: EdgeSpawns}
		if err := e.deps.Store.CreateEdge(ctx, cEd); err == nil {
			e.emitEdgeAdded(cEd)
		}
		noteSpawned(child)
		spawned++
		logf("spawn", "AI 派生子意图: "+c)
	}
}

// parkTemplateChild 模板子意图超闸 → 停车场(parked 节点带 template_id/key,
// 判重占住 key——人点 deploy 展开即按模板上下文跑,不重派不缺位)。
// 返回落库成功的 parked 节点(失败 nil,调用方不占扇出账)。
func (e *Engine) parkTemplateChild(ctx context.Context, parent *Node, tpl *Template,
	ti *TemplateIntent, gate *spawnGate, logf func(string, string)) *Node {

	budget := ti.BudgetSeconds
	if budget <= 0 {
		budget = e.deps.BudgetSeconds
	}
	scope := ti.Scope
	if scope == "" {
		scope = ScopeCase
	}
	hostScope := ti.HostScope
	if hostScope == "all" {
		hostScope = "" // all ≡ 全案件(NULL 语义,与 spawnTemplateIntent 同口径)
	}
	child := &Node{CaseID: parent.CaseID, Kind: KindIntent, Text: ti.Text,
		CreatedBy: ByRule, TemplateID: tpl.ID, TemplateKey: ti.Key,
		Scope: scope, HostScope: hostScope, ParentID: parent.ID,
		Depth: parent.Depth + 1, BudgetSeconds: budget}
	if err := e.park(ctx, parent, child, gate, logf); err != nil {
		logf("error", "模板子意图转停车场失败: "+err.Error())
		return nil
	}
	return child
}

// extractVerdict 从模型全文解析收尾契约:优先最后一个 ```json 围栏块,
// 兜底最后一个含 "verdict" 的 JSON 对象;解析失败给零值(doubt 由调用方定)。
func extractVerdict(text string) verdict {
	var v verdict
	candidates := []string{}
	// 围栏块(从后往前)
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
	// 裸 JSON 兜底:最后一个含 "verdict" 的 {...}
	if idx := strings.LastIndex(text, `"verdict"`); idx >= 0 {
		start := strings.LastIndex(text[:idx], "{")
		end := strings.Index(text[idx:], "}")
		if start >= 0 && end >= 0 {
			candidates = append(candidates, text[start:idx+end+1])
		}
	}
	for _, c := range candidates {
		var got verdict
		if err := json.Unmarshal([]byte(strings.TrimSpace(c)), &got); err == nil && got.Verdict != "" {
			return got
		}
	}
	return v
}

// filterAnchors 锚点清洗(无 source_id 的锚点不是锚点,§6.2 纪律)。
func filterAnchors(in []Anchor) []Anchor {
	var out []Anchor
	for _, a := range in {
		if a.SourceID == "" {
			continue
		}
		out = append(out, a)
	}
	return out
}

// extractSourceID 从工具入参 JSON 抠 source_id(explored 覆盖记账)。
func extractSourceID(input string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(input), &m); err != nil {
		return ""
	}
	if v, ok := m["source_id"].(string); ok {
		return v
	}
	return ""
}
