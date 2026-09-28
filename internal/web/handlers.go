// 认证/案件/任务端点。
package web

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ye-mengwen/fengtu/internal/auth"
	"github.com/ye-mengwen/fengtu/internal/ingest/store"
	"github.com/ye-mengwen/fengtu/internal/kb"
)

// ---- 认证 ----

func (s *Server) authSetup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	needs, err := s.deps.Auth.NeedsSetup(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "首启判定失败: "+err.Error())
		return
	}
	if !needs {
		writeErr(w, http.StatusForbidden, "系统已初始化,首启引导关闭")
		return
	}
	if err := s.deps.Auth.Setup(r.Context(), body.Username, body.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_, _, _ = s.deps.Audit.AppendAudit(r.Context(), "", body.Username,
		"auth.setup", body.Username, map[string]any{"via": "setup", "first_user": true})
	writeJSON(w, http.StatusCreated, map[string]any{
		"user": map[string]string{"username": body.Username, "role": "admin"},
	})
}

func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	token, user, err := s.deps.Auth.Login(r.Context(), body.Username, body.Password)
	if err != nil {
		// 失败也进审计(只记用户名,永不记口令);锁定与凭据不符分 reason,
		// 状态码同为 401(锁定不引入新码,文案如实区分)。
		reason := "bad_credentials"
		msg := "凭据不符"
		if errors.Is(err, auth.ErrAccountLocked) {
			reason = "locked"
			msg = err.Error()
		}
		_, _, _ = s.deps.Audit.AppendAudit(r.Context(), "", body.Username,
			"auth.login", body.Username, map[string]any{"ok": false, "reason": reason})
		writeErr(w, http.StatusUnauthorized, msg)
		return
	}
	_, _, _ = s.deps.Audit.AppendAudit(r.Context(), "", body.Username,
		"auth.login", body.Username, map[string]any{"ok": true})
	s.setSessionCookie(w, token, int((12 * time.Hour).Seconds()))
	writeJSON(w, http.StatusOK, map[string]any{
		"user": map[string]string{
			"id": user.ID, "username": user.Username, "role": user.Role,
		},
	})
}

func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookie)
	if err == nil {
		_ = s.deps.Auth.Logout(r.Context(), cookie.Value)
	}
	u := userFrom(r.Context())
	if u != nil {
		_, _, _ = s.deps.Audit.AppendAudit(r.Context(), "", u.Username,
			"auth.logout", u.Username, nil)
	}
	s.setSessionCookie(w, "", -1)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) authMe(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"user": u})
}

// ---- 案件 ----

// incidentTypes 应急类型固定枚举(交互改造·新建任务向导,设计依据
// fengtu-interaction-design.md §1:ARTEX 的自由分类改成固定应急类型枚举;
// 类型驱动前端目的预设推荐。枚举是结构常量,前后端同表,契约测试焊死)。
var incidentTypes = []string{"ransomware", "webshell", "intrusion", "data-leak", "other"}

// 向导字段上限(防呆不是防攻:同源已登录用户;上限与前端 taskWizard 同值)。
const (
	caseNameMaxRunes  = 128
	backgroundMaxRunes = 4000
	goalsMaxCount     = 12
	goalTextMaxRunes  = 300
)

func incidentTypeOK(t string) bool {
	for _, x := range incidentTypes {
		if x == t {
			return true
		}
	}
	return false
}

// createCase 新建应急任务(交互改造·新建任务向导,设计 §1):
// 应急类型/背景/目的预设落案件元数据,目的预设同步播种为意图图 goal 节点
// (goal 先行;goal 不可派发,播种零 AI 消耗)。0.20.0 起随案落 KB 勾选
// (kb_entries 字段;未提交不动勾选)。同名案件复用既有
// (EnsureCase 语义),元数据按本次提交覆盖——采集包上传链
// (POST /api/uploads,case_name=任务名)与本端点共享同一案件。
func (s *Server) createCase(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name         string   `json:"name"`
		IncidentType string   `json:"incident_type"`
		Background   string   `json:"background"`
		Goals        []string `json:"goals"`
		// KBEntries 本案勾选的 KB 条目 id(0.20.0-case-kb:向导按应急类型
		// 预勾选、人可增删;空数组=显式零勾选不注入,判断权归人)。
		// 0.30.0 起:nil(未提交)=按应急类型套预勾选映射(与前端向导同一张表,
		// 单一数据源在 kb.PrecheckTags,经 GET /api/kb/precheck 暴露)——
		// 修验收缺口:脚本/API 建案不传 kb_entries 过去=零勾选=KB 不注入,
		// worker 拿不到启发式参考(如 WER 加密器定位)。
		KBEntries *[]string `json:"kb_entries"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		writeErr(w, http.StatusBadRequest, "任务名称必填")
		return
	}
	if utf8.RuneCountInString(name) > caseNameMaxRunes {
		writeErr(w, http.StatusBadRequest,
			fmt.Sprintf("任务名称过长(≤%d 字)", caseNameMaxRunes))
		return
	}
	if !incidentTypeOK(body.IncidentType) {
		writeErr(w, http.StatusBadRequest, "应急类型非法: "+body.IncidentType+
			"(可选: "+strings.Join(incidentTypes, ", ")+")")
		return
	}
	if utf8.RuneCountInString(body.Background) > backgroundMaxRunes {
		writeErr(w, http.StatusBadRequest,
			fmt.Sprintf("应急背景过长(≤%d 字)", backgroundMaxRunes))
		return
	}
	if len(body.Goals) > goalsMaxCount {
		writeErr(w, http.StatusBadRequest,
			fmt.Sprintf("应急目的条数超上限(≤%d 条)", goalsMaxCount))
		return
	}
	goals := make([]string, 0, len(body.Goals))
	for _, g := range body.Goals {
		g = strings.TrimSpace(g)
		if g == "" {
			continue // 空白条目如实跳过,不算数
		}
		if utf8.RuneCountInString(g) > goalTextMaxRunes {
			writeErr(w, http.StatusBadRequest,
				fmt.Sprintf("应急目的单条过长(≤%d 字): %q", goalTextMaxRunes, g))
			return
		}
		goals = append(goals, g)
	}

	ctx := r.Context()
	caseID, err := s.deps.Meta.EnsureCase(ctx, name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "案件登记失败: "+err.Error())
		return
	}
	if err := s.deps.Meta.SetCaseProfile(ctx, caseID, store.CaseProfile{
		IncidentType: body.IncidentType, Background: body.Background,
		GoalPresets: goals,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "案件元数据写入失败: "+err.Error())
		return
	}
	actor := s.actorOf(r)

	// 案件级 KB 勾选(0.20.0):随案件落库(判断权归人——人勾的才算;
	// KB 未装配如实标注;未知条目 id 400)。
	// 0.30.0 起 nil(未提交 kb_entries)按应急类型套默认预勾选
	// (kb.PrecheckTags,与前端向导同表);显式空数组仍=零勾选不注入。
	kbSelected := -1 // -1=未落勾选(KB 未装配)
	kbPreselected := false
	if body.KBEntries != nil {
		if s.deps.KB == nil {
			writeErr(w, http.StatusServiceUnavailable,
				"启发式知识库未启用,勾选未落库(server 未装配 kb;见启动日志)")
			return
		}
		if _, _, err := s.deps.KB.SetCaseEntries(ctx, caseID, actor, *body.KBEntries); err != nil {
			writeErr(w, http.StatusBadRequest, "KB 勾选落库失败: "+err.Error())
			return
		}
		kbSelected = len(*body.KBEntries)
	} else if s.deps.KB != nil {
		// 未提交 kb_entries:套默认预勾选(脚本/API 建案不再零勾选裸奔)。
		// 预勾选集来自合一清单自身,未知 id 不可能,失败即 500 如实。
		entries, err := s.deps.KB.List(ctx)
		if err != nil {
			writeErr(w, http.StatusInternalServerError,
				"KB 清单查询失败,预勾选未落库: "+err.Error())
			return
		}
		sel := kb.Preselect(body.IncidentType, entries)
		if _, _, err := s.deps.KB.SetCaseEntries(ctx, caseID, actor, sel); err != nil {
			writeErr(w, http.StatusInternalServerError,
				"KB 预勾选落库失败: "+err.Error())
			return
		}
		kbSelected = len(sel)
		kbPreselected = true
	}
	_, _, _ = s.deps.Audit.AppendAudit(ctx, caseID, actor, "case.create", name,
		map[string]any{"incident_type": body.IncidentType, "goals": len(goals),
			"kb_selected": kbSelected, "kb_preselected": kbPreselected})

	// goal 先行(设计 §1「第 0 轮目标拆解先行」的应急化:预设落库即 goal
	// 节点;引擎未装配时如实标注,元数据账不受影响)
	goalsSeeded := 0
	note := ""
	if len(goals) > 0 {
		if s.deps.Intent == nil {
			note = "意图链引擎未启用,目的预设已落任务元数据,未播种 goal 节点(见启动日志)"
		} else {
			n, serr := s.deps.Intent.SeedGoals(ctx, caseID, actor, goals)
			if serr != nil {
				note = "目的预设播种 goal 节点失败(元数据已落库,如实): " + serr.Error()
			}
			goalsSeeded = n
		}
	}
	c, err := s.deps.Meta.GetCase(ctx, caseID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := map[string]any{"case": c, "goals_seeded": goalsSeeded,
		"kb_preselected": kbPreselected} // 0.30.0:响应/审计如实标是否套的默认预勾选
	if kbSelected >= 0 {
		resp["kb_selected"] = kbSelected
	}
	if note != "" {
		resp["note"] = note
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) listCases(w http.ResponseWriter, r *http.Request) {
	cases, err := s.deps.Meta.ListCases(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cases": cases})
}

func (s *Server) getCase(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := s.deps.Meta.GetCase(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if c == nil {
		writeErr(w, http.StatusNotFound, "无此案件: "+id)
		return
	}
	sources, err := s.deps.Meta.ListSources(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"case": c, "sources": sources})
}

// ---- 任务 ----

func (s *Server) listTasks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"tasks": s.tasks.List()})
}

func (s *Server) getTask(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tasks.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "无此任务")
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// taskEvents SSE 任务进度流(快照式;终态帧后服务端关闭)。
func (s *Server) taskEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	snap, ok := s.tasks.Get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "无此任务")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "响应不支持流式")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	send := func(t *Task) bool {
		b, err := jsonMarshal(t)
		if err != nil {
			return false
		}
		if _, err := w.Write(append([]byte("data: "), append(b, '\n', '\n')...)); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	// 先发当前快照;已终态即收
	if !send(snap) || snap.terminal() {
		return
	}
	ch, cancel, ok := s.tasks.Subscribe(id)
	if !ok {
		return
	}
	defer cancel()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case t, open := <-ch:
			if !open {
				return
			}
			if !send(t) || t.terminal() {
				return
			}
		case <-heartbeat.C:
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
