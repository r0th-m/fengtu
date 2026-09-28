// 研判报告(形态二,0.31.0-narrative-report):LLM 生成,opt-in 烧 token。
//
// 与形态一(模板化结构化报告,GET /report,不动)的关系:同一份
// loadReportData 组装出的事实账是 grounding 的唯一输入——防幻觉的命:
//   - 输入只给本案数据:goal 章收官态、supported/closed 带锚点事实、doubt
//     方向、人工 accepted 候选、攻击时间线、覆盖统计;
//   - prompt 写死:所有结论必须带锚点引用(`源路径:行号`,锚点只能来自
//     grounding 里出现过的);没锚点的判断必须用「推断」「疑似」并标注;
//     禁止编造数据里不存在的证据/IP/时间/文件名;多假设带置信度;
//   - 报告头读侧动态拼「AI 生成初稿,定论归人」(库里的 content 是 LLM
//     产出原文,不加工——证据链如实)。
//
// 生成走 agentloop 会话(CreateSessionBudget + Run):LLM 录制/费率闸/
// 外发同意闸与聊天/意图 worker 同纪律;单次固定 token 预算(默认 30000,
// 请求体 budget_tokens 可调,钳 1000~200000),超了 agentloop 熔断,
// 已产出部分如实落库并标 truncated。
// 归档案 409 同纪律(只读可看历史版本,不新生成)。
// 审计:report.generate(含版本/token 消耗/截断标)。
package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/ye-mengwen/fengtu/internal/ingest/store"
	"github.com/ye-mengwen/fengtu/internal/intent"
)

// 研判报告生成预算(单次会话 token;可调,钳制区间防手滑)。
const (
	narrativeKind          = "narrative"
	narrativeDefaultBudget = int64(30000)
	narrativeMinBudget     = int64(1000)
	narrativeMaxBudget     = int64(200000)
)

// grounding 呈现预算帽(控制 prompt 体积;超帽截断如实标,与报告同纪律)。
const (
	groundingFactsPerChapterCap = 30
	groundingDoubtsCap          = 30
	groundingFindingsCap        = 60
)

// narrativePromptPreamble 研判报告 prompt 纪律段(写死,不随案件变)。
const narrativePromptPreamble = `你是应急响应研判分析师。基于下方【案件数据】为本案写一份「研判报告」初稿(markdown 正文)。

铁律(一条不许破):
1. 只允许使用下方【案件数据】里的信息;数据之外的任何东西不许写——禁止编造证据、行号、IP、账户、时间、文件名、哈希。
2. 每条结论必须带锚点引用,格式 ` + "`主机 · 源路径:行号`" + `(数据里锚点即此格式);引用只能来自数据里出现过的锚点。
3. 没有锚点支撑的判断必须用「推断」「疑似」措辞,并在该句末尾标「(无锚点,推断)」。
4. 多种解释都成立的地方给多假设,各自标置信度(高/中/低)与各自依据,不硬拍单一结论。
5. 数据里事件时间为 UTC;报告时间线统一换算为北京时间(UTC+8)并注明口径。
6. 数据里标「机器评估」的一律转述为机器评估(收官定论归人);「已确认发现」=人工裁决 accepted,可直述为已确认。
7. 数据撑不起的章节(如无勒索家族鉴定数据)如实写「本案数据不足以支撑本节结论」,不硬凑。

报告结构(按数据实际内容取舍,章节可增删):
一、结论摘要(编号列表,每条带置信度)
二、攻击时间线(表格:北京时间|事件|证据引用)
三、攻击路径分析(多假设带置信度)
四、分章排查结论(沿目的章)
五、IOC 清单(仅从数据中提取)
六、处置建议(每条对应证据)
七、证据覆盖与局限(覆盖缺口/存疑方向如实)

只输出报告 markdown 正文,不要任何寒暄、说明或自我引用。

【案件数据】
`

// narrativeDoubt 存疑方向一条(意图/结论 doubt 态;grounding 用)。
type narrativeDoubt struct {
	Kind       string             `json:"kind"` // intent|fact
	Text       string             `json:"text"`
	ResultText string             `json:"result_text,omitempty"`
	Evidence   []reportFactAnchor `json:"evidence"`
}

// collectDoubts 抽取 doubt 态节点(意图/结论;锚点解析到源,缺失如实)。
func collectDoubts(nodes []*intent.Node,
	srcByID map[string]*store.Source) []narrativeDoubt {

	out := []narrativeDoubt{}
	for _, n := range nodes {
		if n.Status != intent.StatusDoubt ||
			(n.Kind != intent.KindIntent && n.Kind != intent.KindFact) {
			continue
		}
		d := narrativeDoubt{Kind: n.Kind, Text: n.Text,
			ResultText: n.ResultText, Evidence: []reportFactAnchor{}}
		for _, a := range n.Evidence {
			fa := reportFactAnchor{SourceID: a.SourceID, LineNo: a.LineNo,
				HitID: a.HitID, Note: a.Note}
			if src := srcByID[a.SourceID]; src != nil {
				fa.Host, fa.SourcePath, fa.SourceSHA256 = src.Host, src.Path, src.SHA256
			} else if a.SourceID != "" {
				fa.Note = strings.TrimSpace(fa.Note + " 源记录缺失(如实)")
			}
			d.Evidence = append(d.Evidence, fa)
		}
		out = append(out, d)
	}
	return out
}

// anchorText 锚点一行(grounding 内统一格式:主机 · 源路径:行号)。
func anchorText(a reportFactAnchor) string {
	switch {
	case a.SourceID != "":
		return fmt.Sprintf("主机 `%s` · 源 `%s:%d`", a.Host, a.SourcePath, a.LineNo)
	case a.HitID != "":
		return fmt.Sprintf("待审区候选 `%s`", a.HitID)
	default:
		return a.Note
	}
}

// narrativeGrounding 组装研判报告 grounding 文本(纯函数,零 IO 可测;
// 内容全部来自已组装的事实账,无锚点的结论以 doubt/缺口形态如实呈现)。
func narrativeGrounding(d *reportData, doubts []narrativeDoubt) string {
	var b strings.Builder
	typeLabel := d.IncidentType
	if v, ok := incidentTypeLabel[d.IncidentType]; ok {
		typeLabel = v
	}
	fmt.Fprintf(&b, "## 案件概况\n- 案件名:%s\n- 应急类型:%s\n", d.CaseName, typeLabel)
	if d.Background != "" {
		fmt.Fprintf(&b, "- 应急背景:%s\n", strings.ReplaceAll(d.Background, "\n", " "))
	}
	if len(d.Hosts) > 0 {
		fmt.Fprintf(&b, "- 已建模主机:`%s`\n", strings.Join(d.Hosts, "`、`"))
	} else {
		b.WriteString("- 主机未建模(散件源,如实)\n")
	}
	fmt.Fprintf(&b, "- 证据源 %d 份(已被排查触及 %d,覆盖缺口 %d)\n",
		d.SourcesTotal, d.SourcesExplored, d.SourcesTotal-d.SourcesExplored)
	fmt.Fprintf(&b, "- 候选裁决:待裁决 %d · 已确认 %d · 已排除 %d\n",
		d.HitsPending, d.HitsAccepted, d.HitsRejected)
	if d.WindowFrom != nil && d.WindowTo != nil {
		fmt.Fprintf(&b, "- 事件时间窗(UTC):%s ~ %s\n",
			d.WindowFrom.Format("2006-01-02 15:04:05"),
			d.WindowTo.Format("2006-01-02 15:04:05"))
	}

	// ---- 目的章收官态(机器评估)----
	b.WriteString("\n## 目的章收官态(机器评估,收官定论归人)\n")
	if !d.IntentReady {
		b.WriteString("(意图引擎未装配,本章缺失,如实)\n")
	} else if len(d.Chapters) == 0 {
		b.WriteString("(未播种子目标,如实)\n")
	}
	for i := range d.Chapters {
		ch := &d.Chapters[i]
		fmt.Fprintf(&b, "- 章「%s」:%s\n", ch.GoalText, chapterVerdict(ch))
	}

	// ---- 证据支持的结论(supported/closed,带锚点)----
	b.WriteString("\n## 证据支持的结论(机器评估 supported/closed,均带锚点)\n")
	writeFacts := func(facts []reportFact) {
		for _, f := range facts {
			fmt.Fprintf(&b, "- %s\n", f.Text)
			for _, a := range f.Evidence {
				fmt.Fprintf(&b, "  - 锚点:%s\n", anchorText(a))
			}
		}
	}
	truncNote := false
	for i := range d.Chapters {
		ch := &d.Chapters[i]
		if len(ch.Facts) == 0 {
			continue
		}
		fmt.Fprintf(&b, "### 章「%s」\n", ch.GoalText)
		facts := ch.Facts
		if len(facts) > groundingFactsPerChapterCap {
			facts = facts[:groundingFactsPerChapterCap]
			truncNote = true
		}
		writeFacts(facts)
	}
	if len(d.OrphanFacts) > 0 {
		b.WriteString("### 未挂章节的结论(如实单列)\n")
		writeFacts(d.OrphanFacts)
	}
	if truncNote {
		fmt.Fprintf(&b, "\n(单章结论超 %d 条,grounding 截断,如实)\n",
			groundingFactsPerChapterCap)
	}

	// ---- 存疑方向(doubt)----
	fmt.Fprintf(&b, "\n## 存疑方向(doubt · %d 条)\n", len(doubts))
	if len(doubts) == 0 {
		b.WriteString("(无存疑方向,如实)\n")
	}
	dd := doubts
	if len(dd) > groundingDoubtsCap {
		dd = dd[:groundingDoubtsCap]
		fmt.Fprintf(&b, "(存疑方向超 %d 条,grounding 截断,如实)\n", groundingDoubtsCap)
	}
	for _, dbt := range dd {
		fmt.Fprintf(&b, "- [%s] %s\n", dbt.Kind, dbt.Text)
		if dbt.ResultText != "" {
			fmt.Fprintf(&b, "  - 结果摘要:%s\n", cutRunes(dbt.ResultText, 200))
		}
		for _, a := range dbt.Evidence {
			fmt.Fprintf(&b, "  - 锚点:%s\n", anchorText(a))
		}
	}

	// ---- 已确认发现(人工裁决 accepted)----
	fmt.Fprintf(&b, "\n## 已确认发现(人工裁决 accepted · %d 条,严重度降序)\n",
		d.HitsAccepted)
	finds := d.Findings
	if len(finds) > groundingFindingsCap {
		finds = finds[:groundingFindingsCap]
		fmt.Fprintf(&b, "(已确认发现超 %d 条,grounding 只取严重度前 %d,如实)\n",
			groundingFindingsCap, groundingFindingsCap)
	}
	if len(finds) == 0 {
		b.WriteString("(无已确认发现;待裁决候选不进 grounding,如实)\n")
	}
	for _, f := range finds {
		ts := "事件时间缺失"
		if f.TsUTC != nil {
			ts = "事件时间(UTC) " + f.TsUTC.UTC().Format("2006-01-02 15:04:05")
		}
		fmt.Fprintf(&b, "- [%s] %s(证据强度 %s;%s):%s\n  - 锚点:主机 `%s` · 源 `%s:%d`\n",
			strings.ToUpper(f.Severity), f.RuleID, f.Grade, ts,
			cutRunes(f.Snippet, 120), f.Host, f.SourcePath, f.LineNo)
	}

	// ---- 攻击时间线(UTC)----
	fmt.Fprintf(&b, "\n## 攻击时间线(UTC 升序 · 共 %d 条)\n", d.TimelineTotal)
	if len(d.Timeline) == 0 {
		b.WriteString("(无从锚点解析出事件时间的条目,如实为空)\n")
	}
	for _, it := range d.Timeline {
		fmt.Fprintf(&b, "- %s | %s | 锚点:主机 `%s` · 源 `%s:%d`\n",
			it.TsUTC.Format("2006-01-02 15:04:05"), it.Text, it.Host,
			it.SourcePath, it.LineNo)
	}
	if d.TimelineTruncated {
		fmt.Fprintf(&b, "(时间线超 %d 条,此处截断,如实)\n", reportTimelineCap)
	}
	return b.String()
}

// narrativeComposed 读侧成稿:报告头(「AI 生成初稿,定论归人」+ 版本/
// 时间/token/截断标)动态拼 + 库内 LLM 原文;截断稿尾部再补标注。
func narrativeComposed(r *store.CaseReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "> ⚠️ 本报告为 **AI 生成初稿,定论归人**。版本 v%d · 生成时间 %s · "+
		"生成人 %s · token 消耗 in %d / out %d",
		r.Version, r.CreatedAt.UTC().Format("2006-01-02 15:04:05"),
		r.CreatedBy, r.TokensIn, r.TokensOut)
	if r.Truncated {
		b.WriteString(" · ⚠️ **token 预算熔断截断,内容不完整(如实)**")
	}
	b.WriteString("\n> 结论均须锚点可回查;「推断/疑似」措辞为人复核前的候选判断,不许直接采信。\n\n---\n\n")
	b.WriteString(r.Content)
	if r.Truncated {
		b.WriteString("\n\n---\n> (本次生成因 token 预算熔断被截断,内容不完整,如实标注)")
	}
	return b.String()
}

// narrativeList 版本清单(content 不随行,看内容走详情端点)。
func (s *Server) narrativeList(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	c, err := s.deps.Meta.GetCase(r.Context(), caseID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if c == nil {
		writeErr(w, http.StatusNotFound, "无此案件: "+caseID)
		return
	}
	reps, err := s.deps.Meta.ListCaseReports(r.Context(), caseID, narrativeKind)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"reports": reps,
		"note": "研判报告=AI 生成初稿(定论归人);同案多次生成版本递增保留历史;" +
			"归档案只读可看,新生成 409",
	})
}

// narrativeGet 版本详情(content=报告头+LLM 原文,前端直接渲染/下载 md)。
func (s *Server) narrativeGet(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	version, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || version <= 0 {
		writeErr(w, http.StatusBadRequest, "版本号须为正整数: "+r.PathValue("version"))
		return
	}
	rep, err := s.deps.Meta.GetCaseReport(r.Context(), caseID, narrativeKind, version)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rep == nil {
		writeErr(w, http.StatusNotFound,
			fmt.Sprintf("无此研判报告版本: 案件 %s v%d", caseID, version))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"report":  rep,
		"content": narrativeComposed(rep),
	})
}

// narrativeGenerate 生成一版研判报告(opt-in;同步等 LLM 跑完,前端转圈)。
// 闸序:AI 未装配 503 → 无此案 404 → 归档 409 → 外发关/未配置(经 agentloop
// 建会话/跑消息如实冒泡)→ LLM 零产出 502(不落库,如实)。
func (s *Server) narrativeGenerate(w http.ResponseWriter, r *http.Request) {
	if !s.aiReady(w) {
		return
	}
	caseID := r.PathValue("id")
	ctx := r.Context()

	var body struct {
		BudgetTokens int64 `json:"budget_tokens"` // 空=默认 30000;钳 1000~200000
	}
	if r.Body != nil && r.ContentLength != 0 {
		if !decodeJSON(w, r, &body) {
			return
		}
	}
	budget := body.BudgetTokens
	if budget <= 0 {
		budget = narrativeDefaultBudget
	}
	if budget < narrativeMinBudget || budget > narrativeMaxBudget {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(
			"token 预算须在 %d~%d 之间: %d", narrativeMinBudget, narrativeMaxBudget, budget))
		return
	}

	c, d, nodes, srcByID, err := s.loadReportData(ctx, caseID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if c == nil {
		writeErr(w, http.StatusNotFound, "无此案件: "+caseID)
		return
	}
	if caseArchivedGuard(c) {
		writeErr(w, http.StatusConflict,
			"案件已归档(只读可看历史版本,不生成新研判报告);解归档后恢复: POST /api/cases/{id}/unarchive")
		return
	}

	u := userFrom(ctx)
	actor := "system"
	if u != nil {
		actor = u.Username
	}

	// grounding:只给本案数据(事实账 + doubt 方向),prompt 纪律段写死
	grounding := narrativeGrounding(d, collectDoubts(nodes, srcByID))
	prompt := narrativePromptPreamble + grounding

	// 走 agentloop:会话预算=本次生成预算(熔断/录制/外发闸同纪律)
	sess, err := s.deps.AI.CreateSessionBudget(ctx, caseID, actor, budget, "")
	if err != nil {
		aiErr(w, err)
		return
	}
	events, err := s.deps.AI.Run(ctx, sess.ID, prompt)
	if err != nil {
		aiErr(w, err)
		return
	}

	var streamed strings.Builder
	finalText, reason, runErr := "", "interrupted", ""
	var tokIn, tokOut int64
	truncated := false
	for ev := range events {
		switch ev.Kind {
		case "text":
			streamed.WriteString(ev.Text)
		case "result":
			finalText, reason = ev.Text, ev.Reason
			tokIn, tokOut = ev.TokensIn, ev.TokensOut
			if ev.ErrText != "" {
				runErr = ev.ErrText
			}
		case "budget_exceeded":
			truncated = true
			reason = "budget_exceeded"
			tokIn, tokOut = ev.TokensIn, ev.TokensOut
		case "error":
			runErr = ev.ErrText
		}
	}
	// 正文拼装:流式 text 事件拼接优先(s37 实战实锤——max_tokens 触顶后
	// norma 自动续写,result 终态事件只带最后一段续写文本,优先它会丢开头)。
	// result.Text 仅在零流式(罕见:一次性终态)时兜底。
	content := strings.TrimSpace(streamed.String())
	if content == "" {
		content = strings.TrimSpace(finalText)
	}
	if content == "" {
		// 零产出:不落库(库里不留空报告),如实 502
		detail := reason
		if runErr != "" {
			detail += ": " + runErr
		}
		writeErr(w, http.StatusBadGateway, "LLM 未产出报告文本("+detail+
			");本次不落库,token 消耗已记 LLM 录制/会话账")
		return
	}

	rep := &store.CaseReport{
		CaseID: caseID, Kind: narrativeKind, Content: content,
		TokensIn: tokIn, TokensOut: tokOut, Truncated: truncated,
		CreatedBy: actor,
	}
	if err := s.deps.Meta.InsertCaseReport(ctx, rep); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _, _ = s.deps.Audit.AppendAudit(ctx, caseID, actor, "report.generate", rep.ID,
		map[string]any{
			"kind": narrativeKind, "version": rep.Version, "session_id": sess.ID,
			"tokens_in": tokIn, "tokens_out": tokOut, "truncated": truncated,
			"budget": budget, "reason": reason,
		})
	writeJSON(w, http.StatusCreated, map[string]any{
		"report":  rep,
		"content": narrativeComposed(rep),
		"note": "AI 生成初稿,定论归人;结论锚点回查源原文后再采信;" +
			"同案可多次生成,版本递增保留历史",
	})
}
