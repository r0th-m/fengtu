// 平台页端点(切片十,ARTEX dashboard/llm-records/logs/approvals 的应急
// 映射;全部只读聚合,判断权归人铁律不变——这里没有裁决/写入通路,裁决
// 仍在既有端点。工作空间页切片十一起独立成文件管理器,见
// handlers_workspace.go,不再走本文件)。
package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// ---- 仪表盘(GET /api/stats/overview) ----

// caseStatusBuckets 案件状态分布(口径与工作台/前端 caseStatus 一致,
// 三处不许多叉:改一处必须三处同改)。
type caseStatusBuckets struct {
	Pending  int64 `json:"pending"`  // 有待裁决候选
	Reviewed int64 `json:"reviewed"` // 全部候选已裁决
	Ingested int64 `json:"ingested"` // 有源无候选
	Empty    int64 `json:"empty"`    // 无源
}

func (s *Server) statsOverview(w http.ResponseWriter, r *http.Request) {
	stats, err := s.deps.Meta.GlobalStats(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cases, err := s.deps.Meta.ListCases(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// 归档口径(0.18.0):仪表盘默认不含已归档案件(活跃口径;
	// 归档案数 stats.archived_cases 单列)
	var buckets caseStatusBuckets
	for _, c := range cases {
		if c.ArchivedAt != nil {
			continue
		}
		switch {
		case c.PendingCandidates > 0:
			buckets.Pending++
		case c.Candidates > 0:
			buckets.Reviewed++
		case c.Sources > 0:
			buckets.Ingested++
		default:
			buckets.Empty++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"stats":              stats,
		"case_status":        buckets,
		"activity_note":      "活动=审计链日条数(UTC 日界),近 7 天",
		"candidates_note":    "命中≠结论:机器候选,判断权归人",
		"archive_note":       "统计默认不含已归档案件(archived_cases 单列);归档=停派新意图/禁起新分析,只读可看",
	})
}

// ---- LLM 录制(GET /api/llm/records[/{id}]) ----

func (s *Server) llmRecordsList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	rows, total, err := s.deps.Meta.ListLLMRecords(r.Context(),
		q.Get("case_id"), limit, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"records": rows,
		"total":   total,
		"note": "档位见系统配置 record_mode:off=不录,metadata(默认)=只记元数据," +
			"full=opt-in 录 prompt/response 全文;录制是台账不是证据",
	})
}

func (s *Server) llmRecordGet(w http.ResponseWriter, r *http.Request) {
	rec, err := s.deps.Meta.GetLLMRecord(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rec == nil {
		writeErr(w, http.StatusNotFound, "无此录制记录")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"record": rec,
		"note":   "prompt/response 仅 record_mode=full 期间录制;NULL=元数据档(如实)",
	})
}

// ---- 平台日志(GET /api/logs) ----

func (s *Server) logsTail(w http.ResponseWriter, r *http.Request) {
	if s.deps.Logs == nil {
		writeErr(w, http.StatusServiceUnavailable,
			"日志环形账未装配(server 未传 Logs;持久日志看 systemd journal)")
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	entries := s.deps.Logs.Tail(limit, before)
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": entries,
		"note": "进程内环形账(容量 2000 行,重启清零,如实);" +
			"翻页:before=<本页最小 seq>;持久日志在 systemd journal",
	})
}

// ---- 全局审批记录(GET /api/approvals) ----

// approvalActions 审批历史的审计动作白名单(与 ApprovalsTab ACTION_LABEL
// 同口径:批准/拒绝/人工停止)。
var approvalActions = map[string]bool{
	"intent.approve": true,
	"intent.reject":  true,
	"intent.stop":    true,
}

// approvalHistoryEntry 审批历史投影(审计链只读;案件名由 cases 表补)。
type approvalHistoryEntry struct {
	Seq      int64     `json:"seq"`
	TS       time.Time `json:"ts"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	CaseID   string    `json:"case_id"`
	CaseName string    `json:"case_name"`
	Text     string    `json:"text"` // detail.text(意图原文;取不到如实留空)
}

func (s *Server) approvalsGlobal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pending, err := s.deps.Meta.ListAwaitingIntents(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	entries, err := s.deps.Audit.ListAudit(ctx, "", 1000)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cases, err := s.deps.Meta.ListCases(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	caseName := map[string]string{}
	for _, c := range cases {
		caseName[c.ID] = c.Name
	}

	history := []approvalHistoryEntry{}
	for _, e := range entries {
		if !approvalActions[e.Action] {
			continue
		}
		text := ""
		if e.DetailJSON != "" {
			// detail 形态 {text: ...}(ApprovalsTab 同口径);非预期形态留空
			var d struct {
				Text string `json:"text"`
			}
			if err := json.Unmarshal([]byte(e.DetailJSON), &d); err == nil {
				text = d.Text
			}
		}
		history = append(history, approvalHistoryEntry{
			Seq: e.Seq, TS: e.TS, Actor: e.Actor, Action: e.Action,
			CaseID: e.CaseID, CaseName: caseName[e.CaseID], Text: text,
		})
	}
	// 历史倒序(最新在前;审计链本身是升序)
	for i, j := 0, len(history)-1; i < j; i, j = i+1, j-1 {
		history[i], history[j] = history[j], history[i]
	}

	type pendingItem struct {
		ID        string    `json:"id"`
		CaseID    string    `json:"case_id"`
		CaseName  string    `json:"case_name"`
		Text      string    `json:"text"`
		CreatedBy string    `json:"created_by"`
		Scope     string    `json:"scope"`
		HostScope string    `json:"host_scope,omitempty"`
		CreatedAt time.Time `json:"created_at"`
	}
	pendingOut := []pendingItem{}
	for _, n := range pending {
		pendingOut = append(pendingOut, pendingItem{
			ID: n.ID, CaseID: n.CaseID, CaseName: caseName[n.CaseID],
			Text: n.Text, CreatedBy: n.CreatedBy, Scope: n.Scope,
			HostScope: n.HostScope, CreatedAt: n.CreatedAt,
		})
	}
	// 停车场待处置计数(0.24.0-convergence):与待批同属「等人拍板」入口,
	// 侧边栏徽标合并计数(pending+parked),构成如实进 note。
	parked, err := s.deps.Meta.CountPendingParking(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pending": pendingOut,
		"history": history,
		"parked":  parked, // 停车场待处置条数(处置入口在案件页「停车场」tab)
		"note": "待批=意图图 awaiting_approval 节点(批准/拒绝走 " +
			"POST /api/intents/{id}/approve);历史=审计哈希链只读投影;" +
			"parked=停车场待处置线索(0.24.0;GET /api/cases/{id}/parking)",
	})
}
