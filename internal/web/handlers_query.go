// 检索/原文回查/规则/扫描/待审/审计端点。
package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ye-mengwen/fengtu/internal/audit"
	"github.com/ye-mengwen/fengtu/internal/ingest"
	"github.com/ye-mengwen/fengtu/internal/query"
	"github.com/ye-mengwen/fengtu/internal/review"
)

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// ---- 检索(单一检索层,只读) ----

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	caseID := q.Get("case_id")
	if caseID == "" {
		writeErr(w, http.StatusBadRequest, "case_id 必填")
		return
	}
	c, err := s.deps.Meta.GetCase(r.Context(), caseID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if c == nil {
		writeErr(w, http.StatusNotFound, "无此案件: "+caseID)
		return
	}
	p := query.Params{CaseID: caseID, Q: q.Get("q")}
	// source_id 重复参数=源多选(切片 8b 检索界面;单值维持单源语义)
	if ids := q["source_id"]; len(ids) > 1 {
		p.SourceIDs = ids
	} else {
		p.SourceID = q.Get("source_id")
	}
	// cond 形如 field:op:value(value 可含冒号,SplitN 三段)
	for _, raw := range q["cond"] {
		parts := strings.SplitN(raw, ":", 3)
		if len(parts) != 3 {
			writeErr(w, http.StatusBadRequest,
				"cond 形如 field:op:value(op=eq|contains): "+raw)
			return
		}
		p.Conds = append(p.Conds, query.FieldCond{
			Field: parts[0], Op: query.CondOp(parts[1]), Values: []string{parts[2]},
		})
	}
	if v := q.Get("ts_from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "ts_from 须为 RFC3339: "+v)
			return
		}
		p.TSFrom = &t
	}
	if v := q.Get("ts_to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "ts_to 须为 RFC3339: "+v)
			return
		}
		p.TSTo = &t
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "limit 须为整数")
			return
		}
		p.Limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "offset 须为整数")
			return
		}
		p.Offset = n
	}
	events, err := s.deps.Query.Search(r.Context(), p)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if events == nil {
		events = []query.Event{} // 零命中返回 [],不返回 null
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"count":  len(events),
		"note": "结果按源+行号主键序返回(未按 ts 排序);" +
			"无时区源 ts 为 null,不参与时间窗过滤(如实);行号锚点可回查原文",
	})
}

// ---- 时间线(切片 8b:全源 ts 小时桶密度 + 无时区源单列) ----

// timeline 时间线数据(buckets=小时桶密度升序;notz=无时区源清单,如实单列)。
// 点条跳锚点由前端组合:桶窗 → GET /api/query(ts_from/ts_to)取首条命中。
func (s *Server) timeline(w http.ResponseWriter, r *http.Request) {
	if s.deps.Stats == nil {
		writeErr(w, http.StatusServiceUnavailable,
			"时间线聚合面未装配(server 未接事件库统计面;见启动日志)")
		return
	}
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
	sql, args, err := query.BuildTimelineSQL(caseID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	buckets, err := s.deps.Stats.QueryStats(r.Context(), sql, args...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "时间线聚合失败: "+err.Error())
		return
	}
	if buckets == nil {
		buckets = []query.StatRow{}
	}
	nsql, nargs, _ := query.BuildNoTZSQL(caseID)
	notz, err := s.deps.Stats.QueryStats(r.Context(), nsql, nargs...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "无时区源聚合失败: "+err.Error())
		return
	}
	if notz == nil {
		notz = []query.StatRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"buckets": buckets, "notz_sources": notz,
		"bucket": "hour", "bucket_epoch_seconds": true,
		"note": "buckets.key=小时桶起 Unix 秒(UTC),只含有时区源;" +
			"notz_sources=无时区源(不参与时间线/时间窗,如实单列不静默);" +
			"桶上限 4100,超出截断(如实)",
	})
}

// ---- 行号锚点回查(金库按 sha256 定位) ----
func (s *Server) sourceLines(w http.ResponseWriter, r *http.Request) {
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
	if src.Kind != "text" {
		// raw 兜底源内容嗅探:后缀生僻的文本允许行式回查;二进制如实拒绝
		if len(src.SHA256) != 64 {
			writeErr(w, http.StatusUnprocessableEntity,
				"行号回查仅适用行式文本源;该源类别为 "+src.Kind+"(哈希登记异常,不可嗅探)")
			return
		}
		ok, serr := ingest.SniffText(s.deps.Vault.Path(src.SHA256))
		if serr != nil {
			writeErr(w, http.StatusInternalServerError, "金库嗅探失败: "+serr.Error())
			return
		}
		if !ok {
			writeErr(w, http.StatusUnprocessableEntity,
				"行号回查仅适用行式文本源;该源类别为 "+src.Kind+
					"(内容嗅探=二进制;evtx/二进制源的事件原文在 CH raw 列,随检索结果返回)")
			return
		}
	}
	from, _ := strconv.Atoi(r.URL.Query().Get("from"))
	to, _ := strconv.Atoi(r.URL.Query().Get("to"))
	// 按源翻页浏览(结果页内容树):page(1 起)+size(≤1000)映射行号区间
	if v := r.URL.Query().Get("page"); v != "" {
		page, err := strconv.Atoi(v)
		if err != nil || page < 1 {
			writeErr(w, http.StatusBadRequest, "page 须为 ≥1 整数")
			return
		}
		size := 100
		if sv := r.URL.Query().Get("size"); sv != "" {
			size, err = strconv.Atoi(sv)
			if err != nil || size < 1 || size > 1000 {
				writeErr(w, http.StatusBadRequest, "size 须为 1..1000 整数")
				return
			}
		}
		from = (page-1)*size + 1
		to = from + size - 1
	}
	if from < 1 || to < from || to-from > 1000 {
		writeErr(w, http.StatusBadRequest,
			"行号区间非法: 1≤from≤to 且跨度 ≤1000(或 page/size 翻页)")
		return
	}
	lines, err := s.deps.Vault.Lines(src.SHA256, from, to)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	out := make([]map[string]any, len(lines))
	replaced := false
	for i, line := range lines {
		valid := strings.ToValidUTF8(line, "�")
		if valid != line {
			replaced = true
		}
		out[i] = map[string]any{"no": from + i, "text": valid}
	}
	resp := map[string]any{
		"source_id": src.ID, "sha256": src.SHA256,
		"from": from, "to": to, "lines": out,
	}
	if replaced {
		resp["note"] = "原文含非 UTF-8 字节(如 GBK 源),回查按 UTF-8 呈现," +
			"不可解码字节已替换为 �;编码还原展示是后续切片(如实)"
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- 规则/扫描/待审 ----

func (s *Server) listRules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"rules": s.deps.Review.Rules()})
}

func (s *Server) startScan(w http.ResponseWriter, r *http.Request) {
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
			"案件已归档(只读可看,不起新扫描);解归档后恢复: POST /api/cases/{id}/unarchive")
		return
	}
	var body struct {
		RuleIDs []string `json:"rule_ids"`
	}
	if r.ContentLength > 0 && !decodeJSON(w, r, &body) {
		return
	}
	u := userFrom(r.Context())
	actor := "system"
	if u != nil {
		actor = u.Username
	}
	task := s.tasks.New("scan", caseID)
	go s.runScan(task.ID, caseID, actor, body.RuleIDs)
	writeJSON(w, http.StatusAccepted, map[string]any{"task_id": task.ID})
}

func (s *Server) runScan(taskID, caseID, actor string, ruleIDs []string) {
	ctx := context.Background() // 异步任务不随请求生命周期
	s.tasks.Progress(taskID, "扫描中")
	sum, err := s.deps.Review.Scan(ctx, caseID, actor, ruleIDs)
	if err != nil {
		s.tasks.Finish(taskID, "failed", err.Error(), sum)
		_, _, _ = s.deps.Audit.AppendAudit(ctx, caseID, actor,
			"scan.run", caseID, map[string]any{
				"round": sumRound(sum), "ok": false, "error": err.Error(),
			})
		return
	}
	s.tasks.Finish(taskID, "done", "", sum)
	_, _, _ = s.deps.Audit.AppendAudit(ctx, caseID, actor,
		"scan.run", caseID, map[string]any{"round": sum.RoundNo, "ok": true, "summary": sum})
}

func sumRound(sum *review.ScanSummary) int {
	if sum == nil {
		return 0
	}
	return sum.RoundNo
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	runs, err := s.deps.Review.ScanRuns(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scan_runs": runs})
}

func (s *Server) listHits(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := review.HitFilter{Status: q.Get("status")}
	if v := q.Get("round"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "round 须为整数")
			return
		}
		f.Round = n
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "limit 须为整数")
			return
		}
		f.Limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "offset 须为整数")
			return
		}
		f.Offset = n
	}
	hits, err := s.deps.Review.Hits(r.Context(), r.PathValue("id"), f)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"hits": hits,
		"note": "命中≠结论:机器候选,判断权归人;裁决 POST /api/hits/{id}/verdict",
	})
}

// maxBatchIDs 批量端点单次受理上限(防误点全库;本页全选 500 封顶同口径)。
const maxBatchIDs = 500

// batchItemResult 批量操作逐条结果(不装全成:每条如实标 ok/失败原因)。
type batchItemResult struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"` // 失败原因原文(已被裁决/无此候选/…)
}

// dedupIDs 去重保序(同一 id 重复传不重复裁决——第二次 CAS 必然 409,
// 去重让计数口径干净)。
func dedupIDs(ids []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// batchVerdict 批量裁决(0.29.0-batch-ops):逐条走与单条同一 CAS 语义
// (仅 pending 可落,已被他人裁决该条如实标失败,不影响其余);审计逐条落,
// 与单条 hit.verdict 同构。判断权归人:批量也是人逐批拍板,无自动裁决。
func (s *Server) batchVerdict(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs     []string `json:"ids"`
		Status  string   `json:"status"`  // accepted|rejected(与单条 verdict 端点同字段)
		Verdict string   `json:"verdict"` // 兼容别名;status 优先
		Note    string   `json:"note"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	status := body.Status
	if status == "" {
		status = body.Verdict
	}
	if status != "accepted" && status != "rejected" {
		writeErr(w, http.StatusBadRequest,
			fmt.Sprintf("裁决状态须为 accepted|rejected: %q", status))
		return
	}
	ids := dedupIDs(body.IDs)
	if len(ids) == 0 {
		writeErr(w, http.StatusBadRequest, "ids 为空:批量裁决至少一条")
		return
	}
	if len(ids) > maxBatchIDs {
		writeErr(w, http.StatusBadRequest,
			fmt.Sprintf("单次批量上限 %d 条(实传 %d)", maxBatchIDs, len(ids)))
		return
	}
	u := userFrom(r.Context())
	actor := "system"
	if u != nil {
		actor = u.Username
	}
	results := make([]batchItemResult, 0, len(ids))
	done := 0
	for _, id := range ids {
		h, err := s.deps.Review.Verdict(r.Context(), id, actor, status, body.Note)
		if err != nil {
			results = append(results, batchItemResult{ID: id, Error: err.Error()})
			continue
		}
		done++
		results = append(results, batchItemResult{ID: id, OK: true})
		_, _, _ = s.deps.Audit.AppendAudit(r.Context(), h.CaseID, actor,
			"hit.verdict", id, map[string]any{
				"status": status, "note": body.Note, "batch": true,
				"rule_id": h.RuleID, "source_id": h.SourceID, "line_no": h.LineNo,
			})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"results": results,
		"total":   len(ids), "done": done, "skipped": len(ids) - done,
		"note": "逐条同单条 CAS 语义(仅 pending 可落);skipped=已被裁决/不存在的条数," +
			"原因逐条在 results[].error,不装全成",
	})
}

func (s *Server) verdict(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	u := userFrom(r.Context())
	actor := "system"
	if u != nil {
		actor = u.Username
	}
	h, err := s.deps.Review.Verdict(r.Context(), id, actor, body.Status, body.Note)
	if err != nil {
		if errors.Is(err, review.ErrVerdictConflict) {
			writeErr(w, http.StatusConflict, err.Error())
		} else if strings.Contains(err.Error(), "无此候选") {
			writeErr(w, http.StatusNotFound, err.Error())
		} else if strings.Contains(err.Error(), "裁决状态") {
			writeErr(w, http.StatusBadRequest, err.Error())
		} else {
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	_, _, _ = s.deps.Audit.AppendAudit(r.Context(), h.CaseID, actor,
		"hit.verdict", id, map[string]any{
			"status": body.Status, "note": body.Note,
			"rule_id": h.RuleID, "source_id": h.SourceID, "line_no": h.LineNo,
		})
	writeJSON(w, http.StatusOK, map[string]any{"hit": h})
}

// ---- 审计链 ----

func (s *Server) auditChain(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := s.deps.Audit.ListAudit(r.Context(),
		r.URL.Query().Get("case_id"), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

func (s *Server) auditVerify(w http.ResponseWriter, r *http.Request) {
	entries, err := s.deps.Audit.AllAudit(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := audit.VerifyChain(entries); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": false, "checked": len(entries), "detail": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "checked": len(entries), "detail": "审计哈希链完整",
	})
}
