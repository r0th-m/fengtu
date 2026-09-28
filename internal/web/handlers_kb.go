// 启发式知识库端点(0.19.0-heuristic-kb 起;0.20.0-case-kb 案件级勾选;
// 0.27.1-kb-simplify 启停下线):内置(configs/kb/*.yaml)+ 用户(PG
// kb_entries)合一视图;写操作全进审计哈希链(kb.create/kb.update/kb.delete/
// kb.case_update;kb.toggle 随启停下线退役,不再产生)。内置条目内容不可改
// (可另建用户条目)。0.27.1 起「全局启用」概念退役:知识库页纯管条目内容,
// 案件实际生效 = 本案勾选(建案/案内勾选为准,零勾选如实不注入);存量
// kb_entries.enabled 列 / kb_builtin_state 表数据原样保留,不再参与任何判断。
package web

import (
	"context"
	"net/http"
	"strings"

	"github.com/ye-mengwen/fengtu/internal/intent"
	"github.com/ye-mengwen/fengtu/internal/kb"
)

// KBProviderAdapter kb.Service → intent.KBProvider(意图包不 import kb,
// 防层间耦合;与 AIRunnerAdapter 同手法)。0.27.1:注入 = 本案勾选
// (kb.Service.HeuristicsForCase),不再交集全局启用。
type KBProviderAdapter struct {
	KB interface {
		HeuristicsForCase(ctx context.Context, caseID string) ([]*kb.Entry, int, error)
	}
}

func (a KBProviderAdapter) Heuristics(ctx context.Context, caseID string) ([]intent.KBHeuristic, int, error) {
	entries, truncated, err := a.KB.HeuristicsForCase(ctx, caseID)
	if err != nil {
		return nil, 0, err
	}
	out := make([]intent.KBHeuristic, 0, len(entries))
	for _, e := range entries {
		out = append(out, intent.KBHeuristic{
			Title: e.Title, Content: e.Content, AppliesTo: e.AppliesTo,
		})
	}
	return out, truncated, nil
}

// KBFace web 层需要的知识库面(kb.Service 实现;nil = 未装配,端点 503 如实)。
type KBFace interface {
	List(ctx context.Context) ([]*kb.Entry, error)
	Builtin(id string) *kb.Entry
	CreateUser(ctx context.Context, actor, title, content string,
		appliesTo []string) (*kb.Entry, error)
	UpdateUser(ctx context.Context, id, title, content string,
		appliesTo []string) (*kb.Entry, bool, error)
	DeleteUser(ctx context.Context, id string) (bool, error)
	// 案件级勾选(0.20.0):本案勾选集查询/整体覆写(差集回传审计记账)。
	CaseEntries(ctx context.Context, caseID string) ([]string, error)
	SetCaseEntries(ctx context.Context, caseID, actor string, ids []string) (added, removed []string, err error)
}

func (s *Server) kbReady(w http.ResponseWriter) bool {	if s.deps.KB == nil {
		writeErr(w, http.StatusServiceUnavailable,
			"启发式知识库未启用(server 未装配 kb;见启动日志)")
		return false
	}
	return true
}

// listKB 合一清单(builtin+user,标 source;0.27.1 起不再输出 enabled——
// 启停概念退役,生效以案件勾选为准)。
func (s *Server) listKB(w http.ResponseWriter, r *http.Request) {
	if !s.kbReady(w) {
		return
	}
	entries, err := s.deps.KB.List(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []*kb.Entry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": entries,
		"note": "启发式知识库=排查方法论沉淀(「怎么找」不是「找什么关键词」);" +
			"本接口只管条目内容(0.27.1 起启停下线);条目生效以新建任务/案件页勾选为准," +
			"worker 注入 = 本案勾选(上限 20 条按更新时间截断)," +
			"本案零勾选如实不注入;内置条目内容不可改,可另建用户条目",
	})
}

// createKB 新建用户条目(审计 kb.create)。
func (s *Server) createKB(w http.ResponseWriter, r *http.Request) {
	if !s.kbReady(w) {
		return
	}
	var body struct {
		Title     string   `json:"title"`
		Content   string   `json:"content"`
		AppliesTo []string `json:"applies_to"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	e, err := s.deps.KB.CreateUser(r.Context(), s.actorOf(r),
		body.Title, body.Content, body.AppliesTo)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_, _, _ = s.deps.Audit.AppendAudit(r.Context(), "", s.actorOf(r),
		"kb.create", e.ID, map[string]any{
			"title": e.Title, "applies_to": e.AppliesTo,
		})
	writeJSON(w, http.StatusCreated, map[string]any{"entry": e})
}

// updateKB 改条目:builtin 一律 400(内容是数据,在 YAML 里;启停 0.27.1
// 下线);user 条目按非空字段覆盖(审计 kb.update)。带 enabled 字段 400 如实
// ——启停语义已下线,生效以案件勾选为准(0.27.1)。
func (s *Server) updateKB(w http.ResponseWriter, r *http.Request) {
	if !s.kbReady(w) {
		return
	}
	id := r.PathValue("id")
	var body struct {
		Title     *string   `json:"title"`
		Content   *string   `json:"content"`
		AppliesTo *[]string `json:"applies_to"`
		Enabled   *bool     `json:"enabled"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	actor := s.actorOf(r)

	// 内置条目:内容不可改,启停亦下线(0.27.1;生效以案件勾选为准)
	if b := s.deps.KB.Builtin(id); b != nil {
		writeErr(w, http.StatusBadRequest,
			"内置条目不可改,可另建用户条目;条目启停已下线(0.27.1),生效以案件勾选为准")
		return
	}

	// 启停语义下线(0.27.1):带 enabled 字段一律 400 如实(前端已不发;
	// 存量调用方拿到明确口径,不静默吞掉)
	if body.Enabled != nil {
		writeErr(w, http.StatusBadRequest,
			"条目启停已下线(0.27.1):enabled 字段不再受理,条目生效以案件勾选为准")
		return
	}

	// 用户条目:非空字段覆盖(取现值兜底)
	entries, err := s.deps.KB.List(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var cur *kb.Entry
	for _, e := range entries {
		if e.ID == id && e.Source == kb.SourceUser {
			cur = e
			break
		}
	}
	if cur == nil {
		writeErr(w, http.StatusNotFound, "无此条目: "+id)
		return
	}
	title, content, appliesTo := cur.Title, cur.Content, cur.AppliesTo
	if body.Title != nil {
		title = *body.Title
	}
	if body.Content != nil {
		content = *body.Content
	}
	if body.AppliesTo != nil {
		appliesTo = *body.AppliesTo
	}
	e, ok, err := s.deps.KB.UpdateUser(r.Context(), id, title, content, appliesTo)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "无此条目: "+id)
		return
	}
	_, _, _ = s.deps.Audit.AppendAudit(r.Context(), "", actor,
		"kb.update", id, map[string]any{
			"title": e.Title, "applies_to": e.AppliesTo,
		})
	writeJSON(w, http.StatusOK, map[string]any{"entry": e})
}

// deleteKB 删用户条目(builtin 400;审计 kb.delete)。
func (s *Server) deleteKB(w http.ResponseWriter, r *http.Request) {
	if !s.kbReady(w) {
		return
	}
	id := r.PathValue("id")
	if b := s.deps.KB.Builtin(id); b != nil {
		writeErr(w, http.StatusBadRequest,
			"内置条目不可删除(内容在 configs/kb YAML)")
		return
	}
	ok, err := s.deps.KB.DeleteUser(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "无此条目: "+id)
		return
	}
	_, _, _ = s.deps.Audit.AppendAudit(r.Context(), "", s.actorOf(r),
		"kb.delete", id, map[string]any{"note": "硬删;历史在本条审计链"})
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// precheckKB 建案预勾选(0.30.0-report-ux,GET /api/kb/precheck?incident_type=x):
// 映射表单一数据源在 kb.PrecheckTags——前端新建向导与 API/脚本建案
// (createCase 不传 kb_entries 时)共用同一张表,前端不再自持映射。
// 未知类型 400 如实(与 createCase 白名单同口径;预勾选只对合法类型有意义)。
func (s *Server) precheckKB(w http.ResponseWriter, r *http.Request) {
	if !s.kbReady(w) {
		return
	}
	typ := r.URL.Query().Get("incident_type")
	if !incidentTypeOK(typ) {
		writeErr(w, http.StatusBadRequest, "应急类型非法: "+typ+
			"(可选: "+strings.Join(incidentTypes, ", ")+")")
		return
	}
	entries, err := s.deps.KB.List(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"incident_type": typ,
		"selected":      kb.Preselect(typ, entries),
		"note": "按应急类型的建案预勾选(映射表在后端 kb.PrecheckTags,双端单一" +
			"数据源);只是默认值,人可增删,判断权归人;显式零勾选=本案不注入",
	})
}

// ---- 案件级 KB 勾选(0.20.0-case-kb;0.27.1 起勾选即生效,不再交集全局启用) ----

// getCaseKB 本案勾选视图:全部条目池 + 本案勾选 id 集。0.27.1 语义如实:
// worker 注入 = 本案勾选(全局启停概念已下线);本案零勾选(含存量案件)=
// 不注入,前端据 selected 空集提示去勾选。
func (s *Server) getCaseKB(w http.ResponseWriter, r *http.Request) {
	if !s.kbReady(w) {
		return
	}
	caseID := r.PathValue("id")
	entries, err := s.deps.KB.List(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	selected, err := s.deps.KB.CaseEntries(r.Context(), caseID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []*kb.Entry{}
	}
	if selected == nil {
		selected = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": entries, "selected": selected,
		"note": "本案生效 = 本案勾选(0.27.1 起不再有全局启停,知识库页只管条目内容);" +
			"本案零勾选如实不注入启发式参考段,不兜底全量;" +
			"勾选改即生效,对之后派发的 worker 生效,在跑的不追回(与并发上限同口径)",
	})
}

// putCaseKB 本案勾选集整体覆写(PUT,body {"selected":[entry_id...]})。
// 未知条目 id 400 如实;勾选差集落审计 kb.case_update(增/删两列)。
func (s *Server) putCaseKB(w http.ResponseWriter, r *http.Request) {
	if !s.kbReady(w) {
		return
	}
	caseID := r.PathValue("id")
	var body struct {
		Selected []string `json:"selected"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	actor := s.actorOf(r)
	added, removed, err := s.deps.KB.SetCaseEntries(r.Context(), caseID, actor, body.Selected)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_, _, _ = s.deps.Audit.AppendAudit(r.Context(), caseID, actor,
		"kb.case_update", caseID, map[string]any{
			"added": added, "removed": removed,
			"note": "案件 KB 勾选覆写;对之后派发的 worker 生效,在跑的不追回",
		})
	writeJSON(w, http.StatusOK, map[string]any{
		"selected": body.Selected, "added": added, "removed": removed,
		"note": "勾选已生效:对之后派发的 worker 生效,在跑的不追回(如实)",
	})
}
