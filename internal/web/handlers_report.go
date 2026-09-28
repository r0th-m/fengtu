// 报告端点(交互改造切片三落地;0.30.0-report-ux 可读性重构):
// 模板化骨架,不走 LLM——数据源=已确认发现(hits accepted,人裁决过的)
// + 已证明 goal/事实(意图图)+ 覆盖账;每条证据锚点可回溯到
// 「主机+源+行+SHA256」(铁律,ARTEX 没有对应物)。
// 「已确认/已证明」全部是系统按既有账如实汇总:发现的确认是人点的
// (hit.verdict),意图状态是系统按证据结构算的——报告不新下任何结论。
//
// 0.30.0 结构(应急报告读法,结论先行;旧版是数据倾倒:目的达成=状态列表、
// 结论=大流水账):
//   一、结论先行:案子是什么(类型/主机/源规模)+ 时间窗一句话(从结论/发现
//     锚点的事件时间聚合,最早~最晚)+ 核心判断清单(每章一行:章名+机器
//     评估结论+章内 supported 数);
//   二、攻击时间线:带 ts 的事实/发现锚点抽事件按时间升序(上限 50 截断如实);
//   三、分章排查结论:结论按 goal 章分组(沿 parent 链归属),不再是大流水;
//   四、已确认发现(人工裁决 accepted);
//   五、候选与裁决概况 / 六、证据覆盖 / 七、处置建议(模板建议,需人核);
//   八、证据附录:锚点去重清单(主机+源+行+SHA256)放最后。
// 每节空态如实标;markdown 与结构化 JSON 同一份数据渲染,两口径一致。
package web

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ye-mengwen/fengtu/internal/ingest/store"
	"github.com/ye-mengwen/fengtu/internal/intent"
	"github.com/ye-mengwen/fengtu/internal/review"
)

// 报告呈现预算帽(超帽截断如实标,不装全量)。
const (
	reportFindingsCap = 500 // 已确认发现
	reportTimelineCap = 50  // 攻击时间线条目
	reportEvidenceCap = 200 // 证据附录锚点(去重后)
)

// reportFinding 报告「已确认发现」一条(锚点四件:主机+源+行+哈希)。
type reportFinding struct {
	ID           string     `json:"id"`
	RuleID       string     `json:"rule_id"`
	Severity     string     `json:"severity"`
	Grade        string     `json:"evidence_grade"`
	Snippet      string     `json:"snippet"`
	TsUTC        *time.Time `json:"ts_utc"`
	ReviewedBy   string     `json:"reviewed_by"`
	ReviewedAt   *time.Time `json:"reviewed_at,omitempty"`
	SourceID     string     `json:"source_id"`
	LineNo       int        `json:"line_no"`
	Host         string     `json:"host"` // 空=未建模散件(如实)
	SourcePath   string     `json:"source_path"`
	SourceSHA256 string     `json:"source_sha256"`
}

// reportFactAnchor 事实锚点(解析到源路径/主机/哈希;源缺失如实标)。
type reportFactAnchor struct {
	SourceID     string `json:"source_id,omitempty"`
	LineNo       int    `json:"line_no,omitempty"`
	HitID        string `json:"hit_id,omitempty"`
	Note         string `json:"note,omitempty"`
	Host         string `json:"host,omitempty"`
	SourcePath   string `json:"source_path,omitempty"`
	SourceSHA256 string `json:"source_sha256,omitempty"`
}

// reportFact 证据支持的排查结论(fact 节点;supported 或 closed 且带锚点)。
type reportFact struct {
	ID       string             `json:"id"` // 血缘子图锚(前端按 id 回溯)
	Text     string             `json:"text"`
	Evidence []reportFactAnchor `json:"evidence"`
}

// reportChapter 分章结论(0.30.0):goal 章 + 机器评估 + 章内意图 supported 账
// + 归属本章的结论清单(沿 parent 链归属;归属不上的进 orphan_facts 如实)。
type reportChapter struct {
	GoalID           string        `json:"goal_id"`
	GoalText         string        `json:"goal_text"`
	Status           string        `json:"status"` // goal 机器评估态(原样)
	IntentsTotal     int           `json:"intents_total"`
	IntentsSupported int           `json:"intents_supported"`
	Facts            []reportFact  `json:"facts"`
}

// reportTimelineItem 攻击时间线一条(0.30.0):仅收锚点可解析出事件时间的
// 发现(accepted hit.ts_utc)/结论(fact 锚点 hit_id 解析出 ts)。
type reportTimelineItem struct {
	TsUTC        time.Time `json:"ts_utc"`
	Kind         string    `json:"kind"` // finding|fact
	Text         string    `json:"text"` // 一句话(发现=规则+摘要;结论=fact 文本,截断)
	FactID       string    `json:"fact_id,omitempty"` // kind=fact 时的血缘回溯锚
	Host         string    `json:"host"`
	SourceID     string    `json:"source_id"`
	SourcePath   string    `json:"source_path"`
	LineNo       int       `json:"line_no"`
	SourceSHA256 string    `json:"source_sha256"`
}

// reportEvidenceItem 证据附录一行(锚点去重:源+行;refs=被引次数)。
type reportEvidenceItem struct {
	Host         string `json:"host"`
	SourceID     string `json:"source_id"`
	SourcePath   string `json:"source_path"`
	LineNo       int    `json:"line_no"`
	SourceSHA256 string `json:"source_sha256"`
	Refs         int    `json:"refs"`
}

// reportData 报告结构化数据(markdown 由同一份数据模板渲染,两口径一致)。
type reportData struct {
	CaseID       string    `json:"case_id"`
	CaseName     string    `json:"case_name"`
	IncidentType string    `json:"incident_type"` // 空=旧案件未填(如实)
	Background   string    `json:"background"`
	GeneratedAt  time.Time `json:"generated_at"`

	Hosts []string `json:"hosts"` // 已建模主机键清单(空=未建模散件,如实)
	// 时间窗(结论先行一句话的原料):时间线条目最早~最晚;nil=无从锚点
	// 解析出事件时间(如实)。
	WindowFrom *time.Time `json:"window_from"`
	WindowTo   *time.Time `json:"window_to"`

	Chapters    []reportChapter `json:"chapters"`     // goal 章(结论分组+机器评估账)
	OrphanFacts []reportFact    `json:"orphan_facts"` // 归属不上任何章的结论(如实单列)

	Findings []reportFinding `json:"findings"` // 人裁决 accepted,严重度降序

	Timeline          []reportTimelineItem `json:"timeline"`
	TimelineTotal     int                  `json:"timeline_total"`
	TimelineTruncated bool                 `json:"timeline_truncated"` // 超 50 条截断(如实)

	Evidence          []reportEvidenceItem `json:"evidence"` // 附录:锚点去重清单
	EvidenceTruncated bool                 `json:"evidence_truncated"`

	HitsPending  int `json:"hits_pending"`
	HitsAccepted int `json:"hits_accepted"`
	HitsRejected int `json:"hits_rejected"`
	// FindingsTruncated:accepted 超过 500 条截断(如实;预算帽语义)。
	FindingsTruncated bool `json:"findings_truncated"`

	SourcesTotal    int  `json:"sources_total"`
	SourcesExplored int  `json:"sources_explored"`
	IntentReady     bool `json:"intent_ready"` // false=意图引擎未装配,章节/覆盖区段缺失(如实)

	Advice []string `json:"advice"` // 处置建议(模板建议,需人核)
}

// incidentTypeLabel 应急类型中文标(与前端 taskWizard.INCIDENT_TYPES 同表;
// 后端白名单见 handlers.go createCase)。
var incidentTypeLabel = map[string]string{
	"ransomware": "勒索响应", "webshell": "WebShell 排查", "intrusion": "入侵排查",
	"data-leak": "数据泄露", "other": "其他",
}

// reportAdvice 处置建议模板(数据不是代码;通用骨架,报告内焊死
// 「模板建议,需人核」——不装针对性)。
var reportAdvice = map[string][]string{
	"ransomware": {
		"隔离已确认受影响主机(断网不关机,保内存证据)",
		"按报告证据清单固定勒索信/加密样本/时间窗原文",
		"全量重置受影响域账户与凭据,排查报告所列驻留点",
		"从离线备份恢复前,先核对加密定位结论覆盖的主机范围",
	},
	"webshell": {
		"下线报告所列疑似 WebShell 文件(保留原件哈希再清理)",
		"按锚点回溯 WebShell 首见时间,向前扩查上传通道",
		"轮换站点凭据/数据库口令,复查计划任务与启动项",
	},
	"intrusion": {
		"按报告登录面结论封禁异常来源,重置被滥用账户",
		"清除报告所列驻留点(服务/计划任务/启动项),逐项对锚点",
		"横向波及主机逐台复查,缺口源补采后再扫",
	},
	"data-leak": {
		"按报告外联/泄露面锚点定位外发通道并封堵",
		"清点泄露数据范围(库表/目录),评估通报义务",
		"轮换可能被拖库的凭据,审计访问日志补证",
	},
	"other": {
		"按证据清单逐条复核人裁结论,缺口源补采",
		"处置动作逐条对锚点留痕,不凭记忆操作",
	},
}

// severityRank 严重度降序排(reporting 呈现序;未知档排尾如实)。
func severityRank(s string) int {
	switch s {
	case "high":
		return 0
	case "medium":
		return 1
	case "low":
		return 2
	case "info":
		return 3
	}
	return 4
}

// cutRunes 截断到 n 字(报告一句话摘要用;超长按 rune 截断加省略号)。
func cutRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

// chapterOf 沿 parent 链找节点归属的 goal 章(与 intent.inChapter 同口径;
// 找不到/断链如实空串)。index 为节点 id → 节点。
func chapterOf(index map[string]*intent.Node, n *intent.Node,
	goalIDs map[string]bool) string {

	cur := n
	for i := 0; i < 100; i++ {
		if goalIDs[cur.ID] {
			return cur.ID
		}
		if cur.ParentID == "" {
			return ""
		}
		p := index[cur.ParentID]
		if p == nil {
			return ""
		}
		cur = p
	}
	return ""
}

// buildReport 汇总报告数据(纯组装;来源全在入参,零 IO 可测)。
// hitsByID:三态候选 id→hit(fact 锚点 hit_id 解析事件时间/源用;未解析
// 出的锚点如实不进时间线)。
func buildReport(c *store.Case, nodes []*intent.Node, hits []review.Hit,
	hitCounts map[string]int, srcByID map[string]*store.Source,
	hitsByID map[string]*review.Hit, covTotal, covExplored int,
	intentReady bool, now time.Time) *reportData {

	d := &reportData{
		CaseID: c.ID, CaseName: c.Name, IncidentType: c.IncidentType,
		Background: c.Background, GeneratedAt: now.UTC(),
		Hosts: []string{}, Chapters: []reportChapter{}, OrphanFacts: []reportFact{},
		Findings: []reportFinding{}, Timeline: []reportTimelineItem{},
		Evidence: []reportEvidenceItem{},
		HitsPending: hitCounts["pending"], HitsAccepted: hitCounts["accepted"],
		HitsRejected: hitCounts["rejected"],
		SourcesTotal: covTotal, SourcesExplored: covExplored, IntentReady: intentReady,
	}

	// 已建模主机清单(空 host=未建模散件,不进清单如实)
	hostSeen := map[string]bool{}
	for _, src := range srcByID {
		if src.Host != "" && !hostSeen[src.Host] {
			hostSeen[src.Host] = true
			d.Hosts = append(d.Hosts, src.Host)
		}
	}
	sort.Strings(d.Hosts)

	// ---- 意图图:goal 章 + fact 结论分组 ----
	index := map[string]*intent.Node{}
	goalIDs := map[string]bool{}
	for _, n := range nodes {
		index[n.ID] = n
		if n.Kind == intent.KindGoal {
			goalIDs[n.ID] = true
		}
	}
	chapterByID := map[string]*reportChapter{}
	for _, n := range nodes {
		if n.Kind != intent.KindGoal {
			continue
		}
		ch := reportChapter{GoalID: n.ID, GoalText: n.Text, Status: n.Status,
			Facts: []reportFact{}}
		d.Chapters = append(d.Chapters, ch)
	}
	sort.Slice(d.Chapters, func(i, j int) bool { return d.Chapters[i].GoalID < d.Chapters[j].GoalID })
	for i := range d.Chapters {
		chapterByID[d.Chapters[i].GoalID] = &d.Chapters[i]
	}
	// 章内意图 supported 账(与 goal 收官同口径:parked 未展开不计)
	for _, n := range nodes {
		if n.Kind != intent.KindIntent || n.Status == intent.StatusParked {
			continue
		}
		gid := chapterOf(index, n, goalIDs)
		if gid == "" {
			continue
		}
		ch := chapterByID[gid]
		ch.IntentsTotal++
		if n.Status == intent.StatusSupported {
			ch.IntentsSupported++
		}
	}
	// fact 结论(supported 或 closed 且带锚点,0.29.1 口径)按章分组
	for _, n := range nodes {
		if n.Kind != intent.KindFact || len(n.Evidence) == 0 ||
			(n.Status != intent.StatusSupported && n.Status != intent.StatusClosed) {
			continue
		}
		f := reportFact{ID: n.ID, Text: n.Text, Evidence: []reportFactAnchor{}}
		for _, a := range n.Evidence {
			fa := reportFactAnchor{SourceID: a.SourceID, LineNo: a.LineNo,
				HitID: a.HitID, Note: a.Note}
			if src := srcByID[a.SourceID]; src != nil {
				fa.Host, fa.SourcePath, fa.SourceSHA256 = src.Host, src.Path, src.SHA256
			} else if a.SourceID != "" {
				fa.Note = strings.TrimSpace(fa.Note + " 源记录缺失(如实)")
			}
			f.Evidence = append(f.Evidence, fa)
		}
		if gid := chapterOf(index, n, goalIDs); gid != "" {
			ch := chapterByID[gid]
			ch.Facts = append(ch.Facts, f)
		} else {
			d.OrphanFacts = append(d.OrphanFacts, f)
		}
	}

	// ---- 已确认发现(人裁决 accepted,严重度降序)----
	for i := range hits {
		h := &hits[i]
		f := reportFinding{
			ID: h.ID, RuleID: h.RuleID, Severity: h.Severity, Grade: h.EvidenceGrade,
			Snippet: h.Snippet, TsUTC: h.TsUTC, ReviewedBy: h.ReviewedBy,
			ReviewedAt: h.ReviewedAt, SourceID: h.SourceID, LineNo: h.LineNo,
		}
		if src := srcByID[h.SourceID]; src != nil {
			f.Host, f.SourcePath, f.SourceSHA256 = src.Host, src.Path, src.SHA256
		}
		d.Findings = append(d.Findings, f)
	}
	sort.SliceStable(d.Findings, func(i, j int) bool {
		return severityRank(d.Findings[i].Severity) < severityRank(d.Findings[j].Severity)
	})
	if len(d.Findings) > reportFindingsCap { // 预算帽:截断如实标
		d.Findings = d.Findings[:reportFindingsCap]
		d.FindingsTruncated = true
	}

	// ---- 攻击时间线(0.30.0):发现 ts + fact 锚点 hit 解析 ts,升序 ----
	type tlKey struct {
		ts   int64
		kind string
		text string
		sid  string
		line int
	}
	tlSeen := map[tlKey]bool{}
	tlAdd := func(ts time.Time, kind, text, factID, host, sid, spath string,
		line int, sha string) {
		k := tlKey{ts.Unix(), kind, text, sid, line}
		if tlSeen[k] {
			return
		}
		tlSeen[k] = true
		d.Timeline = append(d.Timeline, reportTimelineItem{
			TsUTC: ts.UTC(), Kind: kind, Text: text, FactID: factID, Host: host,
			SourceID: sid, SourcePath: spath, LineNo: line, SourceSHA256: sha})
	}
	for _, f := range d.Findings {
		if f.TsUTC == nil {
			continue
		}
		text := "[" + strings.ToUpper(f.Severity) + "] " + f.RuleID
		if f.Snippet != "" {
			text += ":" + cutRunes(f.Snippet, 80)
		}
		tlAdd(*f.TsUTC, "finding", text, "", f.Host, f.SourceID, f.SourcePath,
			f.LineNo, f.SourceSHA256)
	}
	allFacts := make([]reportFact, 0, 8)
	for i := range d.Chapters {
		allFacts = append(allFacts, d.Chapters[i].Facts...)
	}
	allFacts = append(allFacts, d.OrphanFacts...)
	for _, f := range allFacts {
		for _, a := range f.Evidence {
			if a.HitID == "" {
				continue // 源+行锚点无事件时间可解析,如实不进时间线
			}
			h := hitsByID[a.HitID]
			if h == nil || h.TsUTC == nil {
				continue
			}
			host, spath, sha := "", "", ""
			sid, line := h.SourceID, h.LineNo
			if src := srcByID[h.SourceID]; src != nil {
				host, spath, sha = src.Host, src.Path, src.SHA256
			}
			tlAdd(*h.TsUTC, "fact", cutRunes(f.Text, 120), f.ID, host, sid, spath,
				line, sha)
		}
	}
	sort.SliceStable(d.Timeline, func(i, j int) bool {
		return d.Timeline[i].TsUTC.Before(d.Timeline[j].TsUTC)
	})
	d.TimelineTotal = len(d.Timeline)
	if d.TimelineTotal > 0 {
		// 时间窗取全量(截断前)首末——截断只影响呈现,不影响窗口口径
		from := d.Timeline[0].TsUTC
		to := d.Timeline[len(d.Timeline)-1].TsUTC
		d.WindowFrom = &from
		d.WindowTo = &to
	}
	if len(d.Timeline) > reportTimelineCap {
		d.Timeline = d.Timeline[:reportTimelineCap]
		d.TimelineTruncated = true
	}

	// ---- 证据附录(锚点去重:源+行;refs=被引次数)----
	evIdx := map[string]int{}
	evAdd := func(host, sid, spath string, line int, sha string) {
		if sid == "" {
			return // hit_id 死引用/纯 note 锚点无源可附,如实不进附录
		}
		k := sid + "|" + fmt.Sprint(line)
		if i, ok := evIdx[k]; ok {
			d.Evidence[i].Refs++
			return
		}
		evIdx[k] = len(d.Evidence)
		d.Evidence = append(d.Evidence, reportEvidenceItem{
			Host: host, SourceID: sid, SourcePath: spath, LineNo: line,
			SourceSHA256: sha, Refs: 1})
	}
	for _, f := range d.Findings {
		evAdd(f.Host, f.SourceID, f.SourcePath, f.LineNo, f.SourceSHA256)
	}
	for _, f := range allFacts {
		for _, a := range f.Evidence {
			host, spath, sha, sid, line := a.Host, a.SourcePath, a.SourceSHA256,
				a.SourceID, a.LineNo
			if sid == "" && a.HitID != "" {
				if h := hitsByID[a.HitID]; h != nil {
					sid, line = h.SourceID, h.LineNo
					if src := srcByID[h.SourceID]; src != nil {
						host, spath, sha = src.Host, src.Path, src.SHA256
					}
				}
			}
			evAdd(host, sid, spath, line, sha)
		}
	}
	sort.Slice(d.Evidence, func(i, j int) bool {
		a, b := d.Evidence[i], d.Evidence[j]
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.SourcePath != b.SourcePath {
			return a.SourcePath < b.SourcePath
		}
		return a.LineNo < b.LineNo
	})
	if len(d.Evidence) > reportEvidenceCap {
		d.Evidence = d.Evidence[:reportEvidenceCap]
		d.EvidenceTruncated = true
	}

	adviceKey := c.IncidentType
	if _, ok := reportAdvice[adviceKey]; !ok {
		adviceKey = "other"
	}
	d.Advice = reportAdvice[adviceKey]
	return d
}

// goalStatusLabel 报告内 goal 状态中文标(机器评估口径,如实;章内 supported
// 账与「收官定论归人」由 chapterVerdict 统一拼,标签自身不带括号尾巴)。
var goalStatusLabel = map[string]string{
	intent.StatusOpen: "排查中", intent.StatusRunning: "排查中",
	intent.StatusSupported: "机器评估达成",
	intent.StatusDenied: "机器评估排除", intent.StatusDoubt: "存疑",
	intent.StatusClosedExhausted: "时间耗尽(覆盖可能不全)",
	intent.StatusClosed: "已关闭", intent.StatusAwaitingApproval: "待审批",
	// 0.29.1 goal 收官机器评估态
	intent.StatusClosedGoalMet:     "机器评估达成",
	intent.StatusClosedGoalPartial: "机器评估部分达成",
	intent.StatusClosedGoalUnmet:   "机器评估未达成",
}

func goalLabel(s string) string {
	if v, ok := goalStatusLabel[s]; ok {
		return v
	}
	return s
}

// chapterVerdict 核心判断清单一行:机器评估结论+章内 supported 账
// (措辞焊死「机器评估,收官定论归人」;零意图=还没开查,如实)。
func chapterVerdict(ch *reportChapter) string {
	if ch.IntentsTotal == 0 {
		return goalLabel(ch.Status) + "(未派发意图,如实)"
	}
	return fmt.Sprintf("%s(章内意图 supported %d/%d;机器评估,收官定论归人)",
		goalLabel(ch.Status), ch.IntentsSupported, ch.IntentsTotal)
}

// markdown 报告骨架渲染(纯模板,不走 LLM;与结构化数据同一份来源)。
// 0.30.0 结构:结论先行 → 攻击时间线 → 分章排查结论 → 已确认发现 →
// 裁决概况 → 证据覆盖 → 处置建议 → 证据附录;每节空态如实标。
func (d *reportData) markdown() string {
	var b strings.Builder
	typeLabel := d.IncidentType
	if v, ok := incidentTypeLabel[d.IncidentType]; ok {
		typeLabel = v
	}
	fmt.Fprintf(&b, "# 应急响应报告:%s\n\n", d.CaseName)
	fmt.Fprintf(&b, "- 生成时间:%s(UTC)\n- 应急类型:%s\n",
		d.GeneratedAt.Format("2006-01-02 15:04:05"), typeLabel)
	if d.Background != "" {
		fmt.Fprintf(&b, "- 应急背景:%s\n", strings.ReplaceAll(d.Background, "\n", " "))
	}
	b.WriteString("\n> 本报告由平台按既有账模板化生成:发现以人工裁决为准," +
		"目标/结论状态为系统按证据结构的机器评估,最终定论与收官归人。\n")

	// ---- 一、结论先行 ----
	b.WriteString("\n## 一、结论先行\n\n")
	hostPart := "主机未建模(散件源,如实)"
	if len(d.Hosts) > 0 {
		hostPart = fmt.Sprintf("主机 %d 台(`%s`)", len(d.Hosts),
			strings.Join(d.Hosts, "`、`"))
	}
	fmt.Fprintf(&b, "**案子是什么**:%s;%s;证据源 %d 份(已被排查触及 %d);"+
		"已确认发现 %d 条(人工裁决),待裁决候选 %d 条。\n\n",
		typeLabel, hostPart, d.SourcesTotal, d.SourcesExplored,
		d.HitsAccepted, d.HitsPending)
	if d.WindowFrom != nil && d.WindowTo != nil {
		fmt.Fprintf(&b, "**时间窗**:`%s` ~ `%s`(UTC;从结论/发现锚点的"+
			"事件时间聚合,最早~最晚)。\n\n",
			d.WindowFrom.Format("2006-01-02 15:04:05"),
			d.WindowTo.Format("2006-01-02 15:04:05"))
	} else {
		b.WriteString("**时间窗**:从锚点可解析出事件时间的条目为零," +
			"时间窗缺失(如实;发现/结论锚点不带 ts 时即如此)。\n\n")
	}
	b.WriteString("**核心判断**(机器评估,收官定论归人):\n\n")
	if !d.IntentReady {
		b.WriteString("(意图引擎未装配,目标/结论账缺失,如实)\n")
	} else if len(d.Chapters) == 0 {
		b.WriteString("(未播种子目标,无章节可归纳,如实)\n")
	}
	for i := range d.Chapters {
		ch := &d.Chapters[i]
		fmt.Fprintf(&b, "- **%s** —— %s\n", ch.GoalText, chapterVerdict(ch))
	}

	// ---- 二、攻击时间线 ----
	fmt.Fprintf(&b, "\n## 二、攻击时间线\n\n(按事件时间升序;仅收锚点可解析出"+
		"事件时间的发现/结论,共 %d 条)\n\n", d.TimelineTotal)
	if len(d.Timeline) == 0 {
		b.WriteString("(无从锚点解析出事件时间的条目——时间线如实为空)\n")
	}
	for _, it := range d.Timeline {
		fmt.Fprintf(&b, "- `%s` %s —— 主机 `%s` · 源 `%s` · 行 %d\n",
			it.TsUTC.Format("2006-01-02 15:04:05"), it.Text, it.Host,
			it.SourcePath, it.LineNo)
	}
	if d.TimelineTruncated {
		fmt.Fprintf(&b, "\n> 时间线条目超 %d 条,本报告截断(如实;"+
			"完整事件回待审区/检索页按时间过滤)。\n", reportTimelineCap)
	}

	// ---- 三、分章排查结论 ----
	b.WriteString("\n## 三、分章排查结论(证据支持的事实,按目的章节分组;机器评估)\n\n")
	if !d.IntentReady {
		b.WriteString("(意图引擎未装配,本节缺失,如实)\n")
	} else if len(d.Chapters) == 0 && len(d.OrphanFacts) == 0 {
		b.WriteString("(无 goal 章节且无结论,如实)\n")
	}
	for i := range d.Chapters {
		ch := &d.Chapters[i]
		fmt.Fprintf(&b, "### 3.%d %s —— %s\n\n", i+1, ch.GoalText, chapterVerdict(ch))
		if len(ch.Facts) == 0 {
			b.WriteString("(本章无证据支持的结论,如实)\n\n")
			continue
		}
		for _, f := range ch.Facts {
			fmt.Fprintf(&b, "- %s\n", f.Text)
			for _, a := range f.Evidence {
				switch {
				case a.SourceID != "":
					fmt.Fprintf(&b, "  - 锚点:主机 `%s` · 源 `%s` · 行 %d · SHA256 `%s`\n",
						a.Host, a.SourcePath, a.LineNo, a.SourceSHA256)
				case a.HitID != "":
					fmt.Fprintf(&b, "  - 锚点:待审区候选 `%s`\n", a.HitID)
				default:
					fmt.Fprintf(&b, "  - %s\n", a.Note)
				}
			}
		}
		b.WriteString("\n")
	}
	if len(d.OrphanFacts) > 0 {
		b.WriteString("### 未挂章节的结论(归属不上任何 goal,如实单列)\n\n")
		for _, f := range d.OrphanFacts {
			fmt.Fprintf(&b, "- %s\n", f.Text)
			for _, a := range f.Evidence {
				switch {
				case a.SourceID != "":
					fmt.Fprintf(&b, "  - 锚点:主机 `%s` · 源 `%s` · 行 %d · SHA256 `%s`\n",
						a.Host, a.SourcePath, a.LineNo, a.SourceSHA256)
				case a.HitID != "":
					fmt.Fprintf(&b, "  - 锚点:待审区候选 `%s`\n", a.HitID)
				default:
					fmt.Fprintf(&b, "  - %s\n", a.Note)
				}
			}
		}
	}

	// ---- 四、已确认发现 ----
	fmt.Fprintf(&b, "\n## 四、已确认发现(人工裁决 accepted · %d 条)\n\n", d.HitsAccepted)
	if len(d.Findings) == 0 {
		b.WriteString("(无已确认发现;待裁决候选不进报告,如实)\n")
	}
	for i, f := range d.Findings {
		fmt.Fprintf(&b, "### %d. [%s] %s\n\n", i+1, strings.ToUpper(f.Severity), f.RuleID)
		if f.TsUTC != nil {
			fmt.Fprintf(&b, "- 事件时间:%s(UTC)\n", f.TsUTC.UTC().Format("2006-01-02 15:04:05"))
		}
		fmt.Fprintf(&b, "- 证据强度:%s;裁决人:%s\n", f.Grade, f.ReviewedBy)
		if f.Snippet != "" {
			fmt.Fprintf(&b, "- 摘要:`%s`\n", f.Snippet)
		}
		fmt.Fprintf(&b, "- 证据锚点:主机 `%s` · 源 `%s` · 行 %d · SHA256 `%s`\n\n",
			f.Host, f.SourcePath, f.LineNo, f.SourceSHA256)
	}
	if d.FindingsTruncated {
		fmt.Fprintf(&b, "> 已确认发现超 %d 条,本报告截断(完整清单见候选发现页,如实)。\n",
			reportFindingsCap)
	}

	// ---- 五~七:概况/覆盖/处置建议 ----
	fmt.Fprintf(&b, "\n## 五、候选与裁决概况\n\n- 待裁决:%d · 已确认:%d · 已排除:%d\n",
		d.HitsPending, d.HitsAccepted, d.HitsRejected)
	if d.IntentReady {
		fmt.Fprintf(&b, "\n## 六、证据覆盖\n\n- 源总数:%d · 已被排查触及:%d · 覆盖缺口:%d(如实)\n",
			d.SourcesTotal, d.SourcesExplored, d.SourcesTotal-d.SourcesExplored)
	} else {
		b.WriteString("\n## 六、证据覆盖\n\n(意图引擎未装配,覆盖账缺失,如实)\n")
	}
	b.WriteString("\n## 七、处置建议(模板建议,需人核)\n\n")
	for _, a := range d.Advice {
		fmt.Fprintf(&b, "- %s\n", a)
	}

	// ---- 八、证据附录 ----
	fmt.Fprintf(&b, "\n## 八、证据附录(锚点去重清单 · %d 条)\n\n", len(d.Evidence))
	if len(d.Evidence) == 0 {
		b.WriteString("(无源锚点可附,如实)\n")
	}
	for _, e := range d.Evidence {
		fmt.Fprintf(&b, "- 主机 `%s` · 源 `%s` · 行 %d · SHA256 `%s`(被引 %d 次)\n",
			e.Host, e.SourcePath, e.LineNo, e.SourceSHA256, e.Refs)
	}
	if d.EvidenceTruncated {
		fmt.Fprintf(&b, "\n> 附录锚点超 %d 条,截断(如实)。\n", reportEvidenceCap)
	}
	return b.String()
}

// loadReportData 报告数据组装(结构化报告与研判报告 grounding 同源,0.31.0
// 抽出共用)。c=nil 且 err=nil = 无此案件;调用方写 404。
func (s *Server) loadReportData(ctx context.Context, caseID string) (
	c *store.Case, d *reportData, nodes []*intent.Node,
	srcByID map[string]*store.Source, err error) {

	c, err = s.deps.Meta.GetCase(ctx, caseID)
	if err != nil || c == nil {
		return c, nil, nil, nil, err
	}
	sources, err := s.deps.Meta.ListSources(ctx, caseID)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	srcByID = map[string]*store.Source{}
	for i := range sources {
		srcByID[sources[i].ID] = &sources[i]
	}
	// 已确认发现(全量,报告内预算帽 500)+ 三态计数;三态清单同时建
	// hitsByID(fact 锚点 hit_id 解析事件时间/源用;未解析出的如实不进时间线)
	hitCounts := map[string]int{}
	hitsByID := map[string]*review.Hit{}
	var accepted []review.Hit
	for _, st := range []string{"accepted", "pending", "rejected"} {
		hs, herr := s.deps.Review.Hits(ctx, caseID, review.HitFilter{Status: st})
		if herr != nil {
			return nil, nil, nil, nil, fmt.Errorf("候选汇总失败: %w", herr)
		}
		hitCounts[st] = len(hs)
		for i := range hs {
			hitsByID[hs[i].ID] = &hs[i]
		}
		if st == "accepted" {
			accepted = hs
		}
	}
	// 意图图(goal/fact)+ 覆盖账(引擎未装配则区段缺失,如实)
	covTotal, covExplored := 0, 0
	intentReady := s.deps.Intent != nil
	if intentReady {
		// goal 收官重估(0.29.1):报告生成时实时评估=旧 goal 的一次性重估
		// 路径(与 worker 写回触发点同函数,幂等);失败如实不挡报告。
		_, _ = s.deps.Intent.ReevalGoals(ctx, caseID)
		nodes, _, err = s.deps.Intent.Graph(ctx, caseID)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("意图图汇总失败: %w", err)
		}
		cov, cerr := s.deps.Intent.Coverage(ctx, caseID)
		if cerr != nil {
			return nil, nil, nil, nil, fmt.Errorf("覆盖账汇总失败: %w", cerr)
		}
		covTotal = len(cov)
		for _, sc := range cov {
			if sc.Explored {
				covExplored++
			}
		}
	}
	d = buildReport(c, nodes, accepted, hitCounts, srcByID, hitsByID,
		covTotal, covExplored, intentReady, time.Now())
	return c, d, nodes, srcByID, nil
}

// report 报告端点:模板化骨架(结构化 JSON + markdown 双口径同源)。
func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	c, d, _, _, err := s.loadReportData(r.Context(), caseID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if c == nil {
		writeErr(w, http.StatusNotFound, "无此案件: "+caseID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"report":   d,
		"markdown": d.markdown(),
		"note": "模板化骨架,不走 LLM;0.30.0 起结论先行(案子/时间窗/核心判断)" +
			"→攻击时间线→分章结论→发现→概况/覆盖→建议→证据附录;发现=人工裁决 " +
			"accepted,目标/结论=机器评估(收官定论归人);锚点四件=主机+源+行+SHA256",
	})
}
