// 一键分析主链路(DESIGN §6.3):POST /api/cases/{id}/analyze 一条任务流
// 跑完「指纹 → 解析 → 全量规则+算子扫描」,SSE 分阶段进度。
//
// 语义(§6.2/§6.3 拍板):
//   - 幂等:已解析过的源(最新任务账 done 且非 raw 登记账)跳过;
//   - 指纹前验 ≥0.9 自动按判定格式解析,判定与置信度在源信息里可见
//     可改(POST /api/sources/{id}/detect);<0.9 挂「待确认」,不阻塞
//     其他源,汇总如实报「N 源自动,M 源待确认」;
//   - 后验绊线:全量解析失败率 bad/(event+bad) >5% → 判定降级「存疑」,
//     结果里如实标出;
//   - 扫描沿轮次语义(全量 = 签名规则 + 适用域算子),命中进待审;
//   - raw 源(二进制/未识别)不参与指纹,如实记 skipped_raw。
package web

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ye-mengwen/fengtu/internal/fingerprint"
	"github.com/ye-mengwen/fengtu/internal/ingest"
	"github.com/ye-mengwen/fengtu/internal/ingest/store"
	"github.com/ye-mengwen/fengtu/internal/intent"
	"github.com/ye-mengwen/fengtu/internal/review"
)

// analyzeOpts 一键分析可选参数(切片六:意图链播种开关 + playbook 模板 +
// 案件级 deadline)。
type analyzeOpts struct {
	Playbook    string // 意图模板 id(空=不实例化;仅播种规则意图)
	SeedIntents bool   // 一键分析完成后自动播种意图图并起 planner
	DeadlineAt  *time.Time
}

// startAnalyze 开一键分析任务(202 + task_id;SSE 走既有任务流)。
// 可选 JSON 体(切片六):{"playbook":"ransomware-triage","seed_intents":true,
// "deadline_at":"RFC3339"}——seed_intents 默认 true;playbook 空=只播种规则意图。
func (s *Server) startAnalyze(w http.ResponseWriter, r *http.Request) {
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
	if caseArchivedGuard(c) {
		writeErr(w, http.StatusConflict,
			"案件已归档(只读可看,不起新分析);解归档后恢复: POST /api/cases/{id}/unarchive")
		return
	}
	opts := analyzeOpts{SeedIntents: true}
	var body struct {
		Playbook    *string `json:"playbook"`
		SeedIntents *bool   `json:"seed_intents"`
		DeadlineAt  *string `json:"deadline_at"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		if !decodeJSON(w, r, &body) {
			return
		}
		if body.Playbook != nil {
			opts.Playbook = strings.TrimSpace(*body.Playbook)
		}
		if body.SeedIntents != nil {
			opts.SeedIntents = *body.SeedIntents
		}
		if body.DeadlineAt != nil && *body.DeadlineAt != "" {
			t, perr := time.Parse(time.RFC3339, *body.DeadlineAt)
			if perr != nil {
				writeErr(w, http.StatusBadRequest,
					"deadline_at 须为 RFC3339: "+*body.DeadlineAt)
				return
			}
			opts.DeadlineAt = &t
		}
	}
	if opts.Playbook != "" {
		if s.deps.Intent == nil {
			writeErr(w, http.StatusServiceUnavailable,
				"意图链引擎未启用,playbook 无法实例化(见启动日志)")
			return
		}
		found := false
		for _, t := range s.deps.Intent.Templates() {
			if t.ID == opts.Playbook {
				found = true
				break
			}
		}
		if !found {
			writeErr(w, http.StatusBadRequest,
				"未知 playbook 模板: "+opts.Playbook+"(可选见 GET /api/playbooks)")
			return
		}
	}
	u := userFrom(r.Context())
	actor := "system"
	if u != nil {
		actor = u.Username
	}
	task := s.tasks.New("analyze", caseID)
	go s.runAnalyze(task.ID, caseID, c.Name, actor, opts)
	writeJSON(w, http.StatusAccepted, map[string]any{"task_id": task.ID})
}

// parseOutcome 单源解析动作的结果(汇总账用)。
type parseOutcome struct {
	Path       string   `json:"path"`
	SourceID   string   `json:"source_id"`
	Action     string   `json:"action"` // parsed_auto|parsed_override|parsed_evtx|skip_parsed|skip_raw|pending_confirm|failed
	Format     string   `json:"format,omitempty"`
	Confidence *float64 `json:"confidence,omitempty"`
	Events     int64    `json:"events,omitempty"`
	Bad        int64    `json:"bad,omitempty"`
	BadRate    *float64 `json:"bad_rate,omitempty"`
	Suspect    bool     `json:"suspect,omitempty"` // 后验绊线:判定降级存疑
	Note       string   `json:"note,omitempty"`
}

func (s *Server) runAnalyze(taskID, caseID, caseName, actor string, opts analyzeOpts) {
	ctx := context.Background() // 异步任务不随请求生命周期
	rep := map[string]any{"case_id": caseID}

	sources, err := s.deps.Meta.ListSources(ctx, caseID)
	if err != nil {
		s.tasks.Finish(taskID, "failed", "源清单查询失败: "+err.Error(), rep)
		return
	}

	// ---- 阶段 1/2:指纹判定 + 解析(幂等:已解析源跳过) ----
	var outcomes []parseOutcome
	counts := map[string]int{}
	for i, src := range sources {
		s.tasks.Progress(taskID, fmt.Sprintf("阶段1/2 指纹与解析(%d/%d): %s",
			i+1, len(sources), src.Path))
		oc := s.analyzeOne(ctx, caseID, caseName, &src)
		outcomes = append(outcomes, oc)
		counts[oc.Action]++
		if oc.Suspect {
			counts["suspect"]++
		}
	}
	rep["sources"] = outcomes
	rep["fingerprint"] = map[string]any{
		"parsed_auto":     counts["parsed_auto"] + counts["parsed_evtx"],
		"parsed_override": counts["parsed_override"],
		"pending_confirm": counts["pending_confirm"],
		"suspect":         counts["suspect"],
		"skip_parsed":     counts["skip_parsed"],
		"skip_raw":        counts["skip_raw"],
		"failed":          counts["failed"],
		"note": "指纹前验≥0.9 自动解析(判定与置信度源信息可见可改);" +
			"<0.9 挂待确认不阻塞其他源;后验失败率>5% 判定降级存疑",
	}

	// ---- 阶段 2/2:全量规则 + 适用域算子扫描(轮次语义) ----
	s.tasks.Progress(taskID, "阶段2/2 全量规则+算子扫描中")
	sum, serr := s.deps.Review.Scan(ctx, caseID, actor, nil)
	if sum != nil {
		rep["scan"] = sum
	}
	_, _, _ = s.deps.Audit.AppendAudit(ctx, caseID, actor,
		"analyze.run", caseID, map[string]any{
			"fingerprint": rep["fingerprint"], "scan_ok": serr == nil,
		})
	if serr != nil {
		s.tasks.Finish(taskID, "failed", "扫描失败: "+serr.Error(), rep)
		return
	}

	// ---- 阶段 3/3(切片六):意图链播种(模板实例化 + 规则候选派生)+ 起 planner ----
	if opts.SeedIntents && s.deps.Intent != nil {
		s.tasks.Progress(taskID, "阶段3/3 意图链播种中")
		seedRep := map[string]any{}
		if opts.DeadlineAt != nil {
			if derr := s.deps.Intent.SetCaseDeadline(ctx, caseID, opts.DeadlineAt); derr != nil {
				seedRep["deadline_error"] = derr.Error() // 如实,不杀主链路
			} else {
				seedRep["deadline_at"] = opts.DeadlineAt.UTC().Format(time.RFC3339)
			}
		}
		if opts.Playbook != "" {
			goal, roots, gerr := s.deps.Intent.SeedTemplate(ctx, caseID,
				opts.Playbook, actor)
			if gerr != nil {
				seedRep["template_error"] = gerr.Error() // 如实,不杀主链路
			} else {
				seedRep["playbook"] = opts.Playbook
				seedRep["goal_id"] = goal.ID
				seedRep["root_intents"] = roots // 0=幂等(已实例化过)
			}
		}
		seeded, rerr := s.deps.Intent.SeedRules(ctx, caseID, actor,
			s.ruleSeeds(sum))
		if rerr != nil {
			seedRep["rules_error"] = rerr.Error() // 如实,不杀主链路
		} else {
			seedRep["rule_intents"] = seeded
		}
		seedRep["note"] = "意图链已播种,planner 事件驱动续跑(没有未覆盖方向则静默);" +
			"批量执行意图(scope=all)挂审批门待人批"
		rep["intents"] = seedRep
	}
	s.tasks.Finish(taskID, "done", "", rep)
}

// ruleSeeds 扫描总账 → 规则意图种子(只取有新增候选的规则/算子)。
func (s *Server) ruleSeeds(sum *review.ScanSummary) []intent.RuleSeed {
	if sum == nil {
		return nil
	}
	titles := map[string]string{}
	for _, r := range s.deps.Review.Rules() {
		titles[r.ID] = r.Title
	}
	if s.deps.Operators != nil {
		for _, sp := range s.deps.Operators.Specs() {
			titles[sp.ID] = sp.Title
		}
	}
	var out []intent.RuleSeed
	for _, rs := range sum.Rules {
		if rs.HitsNew > 0 {
			out = append(out, intent.RuleSeed{
				RuleID: rs.RuleID, Title: titles[rs.RuleID], HitsNew: rs.HitsNew})
		}
	}
	for _, os := range sum.Operators {
		if os.HitsNew > 0 {
			out = append(out, intent.RuleSeed{
				RuleID: os.OpID, Title: titles[os.OpID], HitsNew: os.HitsNew})
		}
	}
	return out
}

// analyzeOne 单源的指纹/解析动作(主链路阶段 1 的单元)。
func (s *Server) analyzeOne(ctx context.Context, caseID, caseName string,
	src *store.Source) parseOutcome {

	oc := parseOutcome{Path: src.Path, SourceID: src.ID}

	// 幂等先行(原生解析源 kind=native 同样已解析过,M3):最新任务账
	// done 且非 raw 登记账 = 已解析,跳过(原来在 kind 门之后,native
	// 源会被误报 skip_raw)
	job, err := s.deps.Meta.LatestJob(ctx, src.ID)
	if err != nil {
		oc.Action = "failed"
		oc.Note = "任务账查询失败: " + err.Error()
		return oc
	}
	if job != nil && job.Status == "done" && job.Parser != "raw" {
		oc.Action = "skip_parsed" // 幂等:已解析过的源跳过
		oc.Format = src.DetectFormat
		oc.Note = "已解析(任务账 done),跳过"
		return oc
	}

	// M3 原生解析源:包摄入时即解析;走到这里 = 未解析(如实标,不走指纹)
	if src.Kind == "native" {
		oc.Action = "skip_raw"
		oc.Note = "原生解析源(native)未解析:指纹是文本面判定,对二进制不适用;" +
			"解析在包摄入通路完成(重摄入该包即可),不参与指纹"
		return oc
	}

	// 路由看「源是否可判」而非登记 kind:上传未绑格式的文本如实登记为
	// raw(registered_unparsed),主链路的指纹正是为它们而来;
	// 采集包里 route=raw 的 .log/.txt 同理可判。其余二进制不参与指纹。
	textLike := src.Kind == "text" ||
		(src.Kind == "raw" && ingest.DetectKind(src.Path) == ingest.KindText)
	if src.Kind != "evtx" && !textLike {
		oc.Action = "skip_raw"
		oc.Note = "二进制/未识别源不参与指纹,原文已在金库"
		return oc
	}

	if src.Kind == "evtx" {
		return s.parseSource(ctx, caseID, caseName, src, "evtx_native:velocidex",
			"parsed_evtx", nil, oc)
	}

	// text 源:人改判优先,其次指纹判定
	if src.DetectStatus == "overridden" && src.DetectFormat != "" {
		cand := fingerprint.FindCandidate(s.deps.Candidates, src.DetectFormat)
		if cand == nil {
			oc.Action = "failed"
			oc.Note = "改判格式已不在候选集: " + src.DetectFormat
			return oc
		}
		return s.parseSource(ctx, caseID, caseName, src, src.DetectFormat,
			"parsed_override", cand, oc)
	}

	sample, err := s.deps.Vault.Lines(src.SHA256, 1, fingerprint.SampleLines)
	if err != nil {
		oc.Action = "failed"
		oc.Note = "金库抽样失败: " + err.Error()
		return oc
	}
	res := fingerprint.Detect(sample, s.deps.Candidates)
	if res == nil || res.Confidence < fingerprint.AutoThreshold {
		oc.Action = "pending_confirm"
		conf := 0.0
		format := ""
		if res != nil {
			conf, format = res.Confidence, res.FormatID
			oc.Format, oc.Confidence = res.FormatID, &res.Confidence
		}
		oc.Note = "指纹前验 <0.9,挂待确认(不阻塞其他源);" +
			"确认/改判: POST /api/sources/{id}/detect"
		_ = s.deps.Meta.SetDetection(ctx, src.ID, store.Detection{
			Format: format, Confidence: &conf, Status: "pending_confirm",
		})
		return oc
	}
	cand := fingerprint.FindCandidate(s.deps.Candidates, res.FormatID)
	if cand == nil {
		oc.Action = "failed"
		oc.Note = "判定格式不在候选集: " + res.FormatID
		return oc
	}
	oc.Confidence = &res.Confidence
	if err := s.deps.Meta.SetDetection(ctx, src.ID, store.Detection{
		Format: res.FormatID, Confidence: &res.Confidence,
		Status: "auto", LogType: res.LogType,
	}); err != nil {
		oc.Action = "failed"
		oc.Note = "判定落库失败: " + err.Error()
		return oc
	}
	// 本地副本同步,后验绊线降级时置信度/品类不留陈值
	src.DetectConfidence, src.LogType = &res.Confidence, res.LogType
	return s.parseSource(ctx, caseID, caseName, src, res.FormatID,
		"parsed_auto", cand, oc)
}

// parseSource 执行解析 + 后验绊线(失败率 >5% → 判定降级存疑,如实标)。
// cand 非 nil = 文本路径(desc/builtin);nil = evtx 原生路径。
func (s *Server) parseSource(ctx context.Context, caseID, caseName string,
	src *store.Source, format, action string, cand *fingerprint.Candidate,
	oc parseOutcome) parseOutcome {

	spec := ingest.Spec{
		CaseName: caseName, Path: s.deps.Vault.Path(src.SHA256),
		DisplayPath: src.Path, ParserLabel: format,
	}
	var st *ingest.Stats
	var err error
	if cand != nil {
		st, err = ingest.IngestTextParsed(ctx, s.deps.Meta, s.deps.Events,
			caseID, src.ID, spec, cand.Encoding,
			ingest.ParseFunc(cand.Parse), cand.IsBlockStart)
	} else {
		spec.Kind = ingest.KindEVTX
		st, err = ingest.IngestEVTXParsed(ctx, s.deps.Meta, s.deps.Events,
			caseID, src.ID, spec, ingest.VelocidexParser{})
	}
	oc.Format = format
	if err != nil {
		oc.Action = "failed"
		oc.Note = "解析失败: " + err.Error()
		return oc
	}
	oc.Action = action
	oc.Events, oc.Bad = st.Events, st.Bad
	if cand != nil && src.Kind == "raw" {
		// registered_unparsed 源解析成功:kind 提升 text(回查/路由以它为准)
		_ = s.deps.Meta.MarkParsedText(ctx, src.ID)
	}

	// 后验绊线(§6.2 第一面):全量失败率 >5% → 判定降级存疑
	if total := st.Events + st.Bad; total > 0 {
		rate := float64(st.Bad) / float64(total)
		oc.BadRate = &rate
		if rate > fingerprint.PosteriorBadRate {
			oc.Suspect = true
			oc.Note = fmt.Sprintf("后验绊线:全量解析失败率 %.1f%% >5%%,判定降级存疑",
				rate*100)
			_ = s.deps.Meta.SetDetection(ctx, src.ID, store.Detection{
				Format: format, Confidence: src.DetectConfidence,
				Status: "suspect", LogType: src.LogType,
			})
		}
	}
	return oc
}

// overrideDetect 改判端点:人确认/改判源格式(判定可见可改的「改」)。
// 立即异步解析该源。幂等纪律(切片七):
//   - 已解析源 + reparse=false → 200 如实提示(不重复解析,重复会产出重复事件);
//   - 已解析源 + reparse=true → 重解析通路:先删该源全部旧事件(CH 同步
//     mutation)再按新格式重插——删失败即拒(不留下双份);全程审计留痕。
func (s *Server) overrideDetect(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	src, err := s.deps.Meta.GetSource(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if src == nil {
		writeErr(w, http.StatusNotFound, "无此源: "+id)
		return
	}
	var body struct {
		Format  string `json:"format"`
		Reparse bool   `json:"reparse"` // 已解析源的重解析开关(默认关,防误触)
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if src.Kind != "text" &&
		!(src.Kind == "raw" && ingest.DetectKind(src.Path) == ingest.KindText) {
		writeErr(w, http.StatusUnprocessableEntity,
			"改判仅适用行式文本源(含未绑格式登记的文本);该源类别为 "+
				src.Kind+" ("+src.Path+")")
		return
	}
	cand := fingerprint.FindCandidate(s.deps.Candidates, body.Format)
	if cand == nil {
		var avail []string
		for _, c := range s.deps.Candidates {
			avail = append(avail, c.FormatID)
		}
		writeErr(w, http.StatusBadRequest,
			fmt.Sprintf("格式不在候选集: %q(可选: %s)", body.Format,
				strings.Join(avail, ", ")))
		return
	}
	u := userFrom(r.Context())
	actor := "system"
	if u != nil {
		actor = u.Username
	}
	if err := s.deps.Meta.SetDetection(r.Context(), id, store.Detection{
		Format: body.Format, Confidence: src.DetectConfidence, // 前验原值留痕
		Status: "overridden", LogType: cand.LogType,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "判定落库失败: "+err.Error())
		return
	}
	_, _, _ = s.deps.Audit.AppendAudit(r.Context(), src.CaseID, actor,
		"source.detect", id, map[string]any{
			"path": src.Path, "format": body.Format,
			"prev_format": src.DetectFormat, "prev_status": src.DetectStatus,
		})

	// 改判后立即异步解析(已解析源:默认不重复解析;reparse=true 走
	// 重解析通路——先删旧事件再重插,幂等,审计留痕)
	job, err := s.deps.Meta.LatestJob(r.Context(), id)
	if err == nil && job != nil && job.Status == "done" && job.Parser != "raw" {
		if !body.Reparse {
			writeJSON(w, http.StatusOK, map[string]any{
				"source_id": id, "detect_status": "overridden",
				"format": body.Format,
				"note": "判定已改;该源已解析过,未重复解析(重复解析会产出重复事件)。" +
					"如需按新判定重解析:再发一次带 reparse=true——旧事件先删后插," +
					"幂等,审计留痕",
			})
			return
		}
		if s.deps.EventsAdmin == nil {
			writeErr(w, http.StatusServiceUnavailable,
				"重解析通路未装配(server 未接事件库管理面;见启动日志)")
			return
		}
		// 先删(同步落地);删失败即拒,不留下双份事件
		if err := s.deps.EventsAdmin.DeleteEventsForSource(
			r.Context(), src.CaseID, id); err != nil {
			_, _, _ = s.deps.Audit.AppendAudit(r.Context(), src.CaseID, actor,
				"source.reparse_failed", id, map[string]any{
					"path": src.Path, "format": body.Format, "stage": "delete",
					"reason": err.Error(),
				})
			writeErr(w, http.StatusInternalServerError,
				"重解析前置删除旧事件失败,未重解析(旧数据未动): "+err.Error())
			return
		}
		_, _, _ = s.deps.Audit.AppendAudit(r.Context(), src.CaseID, actor,
			"source.reparse", id, map[string]any{
				"path": src.Path, "format": body.Format,
				"note": "旧事件已删,按新判定重解析(先删后插,幂等)",
			})
	}
	task := s.tasks.New("parse", src.CaseID)
	c, _ := s.deps.Meta.GetCase(r.Context(), src.CaseID)
	caseName := ""
	if c != nil {
		caseName = c.Name
	}
	go func() {
		ctx := context.Background()
		s.tasks.Progress(task.ID, "改判解析中: "+src.Path)
		oc := s.parseSource(ctx, src.CaseID, caseName, src, body.Format,
			"parsed_override", cand, parseOutcome{Path: src.Path, SourceID: src.ID})
		if oc.Action == "failed" {
			s.tasks.Finish(task.ID, "failed", oc.Note, oc)
			return
		}
		s.tasks.Finish(task.ID, "done", "", oc)
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{
		"source_id": id, "detect_status": "overridden",
		"format": body.Format, "task_id": task.ID,
	})
}

// ---- 采集项内容树(§6.3 结果页后端) ----

// treeNode 内容树节点(目录聚合源;叶子=源,带行数/状态/类别)。
type treeNode struct {
	Name     string      `json:"name"`
	Path     string      `json:"path"`
	Type     string      `json:"type"` // dir | source
	Children []*treeNode `json:"children,omitempty"`
	// 叶子(源)字段
	SourceID   string   `json:"source_id,omitempty"`
	Kind       string   `json:"kind,omitempty"`
	Artifact   string   `json:"artifact_type,omitempty"`
	LogType    string   `json:"log_type,omitempty"`
	SizeBytes  int64    `json:"size_bytes,omitempty"`
	Lines      int64    `json:"lines,omitempty"`  // 摄入行数(任务账 rows_total)
	Status     string   `json:"status,omitempty"` // 已解析/已登记/待确认/存疑/解析失败/未摄入
	DetectFmt  string   `json:"detect_format,omitempty"`
	DetectConf *float64 `json:"detect_confidence,omitempty"`
}

func sourceStatus(st store.SourceState) string {
	switch st.DetectStatus {
	case "pending_confirm":
		return "待确认"
	case "suspect":
		return "存疑"
	}
	if st.Job == nil {
		return "未摄入"
	}
	switch st.Job.Status {
	case "failed":
		return "解析失败"
	case "running":
		return "解析中"
	}
	if st.Job.Parser == "raw" {
		return "已登记(未解析)"
	}
	return "已解析"
}

func (s *Server) artifactTree(w http.ResponseWriter, r *http.Request) {
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
	states, err := s.deps.Meta.ListSourcesWithJobs(r.Context(), caseID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	root := &treeNode{Name: "/", Path: "", Type: "dir"}
	dirs := map[string]*treeNode{"": root}
	for _, st := range states {
		p := strings.ReplaceAll(st.Path, "\\", "/")
		segs := strings.Split(p, "/")
		// 逐级建目录节点
		cur := ""
		for i := 0; i < len(segs)-1; i++ {
			parent := cur
			if cur == "" {
				cur = segs[i]
			} else {
				cur += "/" + segs[i]
			}
			if _, ok := dirs[cur]; !ok {
				n := &treeNode{Name: segs[i], Path: cur, Type: "dir"}
				dirs[cur] = n
				dirs[parent].Children = append(dirs[parent].Children, n)
			}
		}
		leaf := &treeNode{
			Name: segs[len(segs)-1], Path: p, Type: "source",
			SourceID: st.ID, Kind: st.Kind, Artifact: st.ArtifactType,
			LogType: st.LogType, SizeBytes: st.SizeBytes,
			Status: sourceStatus(st), DetectFmt: st.DetectFormat,
			DetectConf: st.DetectConfidence,
		}
		if st.Job != nil {
			leaf.Lines = st.Job.RowsTotal
		}
		dirs[cur].Children = append(dirs[cur].Children, leaf)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tree": root.Children, "sources_total": len(states),
		"note": "目录按采集包结构聚合;叶子行数=摄入任务账 rows_total;" +
			"内容查看: GET /api/sources/{id}/lines(支持 page/size 翻页)",
	})
}

// ---- 规则裁决统计(§6.2 第四面:长期校准) ----

func (s *Server) ruleStats(w http.ResponseWriter, r *http.Request) {
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
	since := time.Now().UTC().Add(-90 * 24 * time.Hour)
	stats, err := s.deps.Review.RuleStats(r.Context(), caseID, since)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if stats == nil {
		stats = []review.RuleStat{} // 零统计返回 [],不返回 null
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"window_days": 90, "since": since.Format(time.RFC3339), "stats": stats,
		"note": "接受率=accepted/(accepted+rejected)(无裁决为 null);" +
			"needs_review=裁决样本≥10 且接受率为 0(待复审退役闸,§6.2)",
	})
}

// listOperators 算子注册清单(含未实现,如实标)。
func (s *Server) listOperators(w http.ResponseWriter, _ *http.Request) {
	if s.deps.Operators == nil {
		writeJSON(w, http.StatusOK, map[string]any{"operators": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"operators": s.deps.Operators.Specs(),
		"note":      "implemented=false 只注册不实例化,清单如实标(§6.1)",
	})
}
