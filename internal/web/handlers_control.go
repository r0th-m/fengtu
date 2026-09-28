// 运行中操控端点(交互改造切片三,设计依据 fengtu-interaction-design.md §3):
//   - steer 纠偏:对在跑意图发人工消息(中断当前轮,同一 AI 会话续跑);
//   - add_hint 补充线索:hint 节点挂图,worker 下轮可见(注入 system);
//   - 操作约束 CRUD:案件级,人增人删,注入 worker system 最高优先。
// 治理语义在 intent.Engine 收口,本层只做结果映射。
package web

import (
	"net/http"

	"github.com/ye-mengwen/fengtu/internal/intent"
)

// steerIntent 人工纠偏(设计 §3 steer_work 照抄:任务页图上对在跑意图
// 「纠偏」,人在环路的低成本入口)。
func (s *Server) steerIntent(w http.ResponseWriter, r *http.Request) {
	if !s.intentReady(w) {
		return
	}
	var body struct {
		Text string `json:"text"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := s.deps.Intent.Steer(r.Context(), r.PathValue("id"),
		s.actorOf(r), body.Text); err != nil {
		intentErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"steered": r.PathValue("id"),
		"note":    "纠偏已入队:当前轮被中断,同一 AI 会话按纠偏方向续跑(transcript 延续);wall-clock 预算不延长",
	})
}

// addHint 补充线索(设计 §3 add_hint 照抄:hint 节点挂图,worker 下轮可见;
// 比直接改意图更温和的人在环路)。
func (s *Server) addHint(w http.ResponseWriter, r *http.Request) {
	if !s.intentReady(w) {
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
	var body struct {
		Text     string `json:"text"`
		ParentID string `json:"parent_id"` // 可选;缺省锚首 goal,无 goal 则孤儿
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	n, err := s.deps.Intent.AddHint(r.Context(), caseID, s.actorOf(r),
		body.Text, body.ParentID)
	if err != nil {
		intentErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"node": n,
		"note": "线索已挂图;不派发执行,worker 下轮起在 system 里可见(人工线索段)",
	})
}

// listConstraints 案件操作约束清单。
func (s *Server) listConstraints(w http.ResponseWriter, r *http.Request) {
	if !s.intentReady(w) {
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
	cs, err := s.deps.Intent.Constraints(r.Context(), caseID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cs == nil {
		cs = []*intent.Constraint{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"constraints": cs,
		"note": "操作约束=人定的排查红线(如「不得触碰的生产系统/只读/时间窗」);" +
			"注入 worker system 最高优先,对之后认领的意图生效;增删进审计哈希链",
	})
}

// addConstraint 新增操作约束(人定;同案同文本幂等)。
func (s *Server) addConstraint(w http.ResponseWriter, r *http.Request) {
	if !s.intentReady(w) {
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
	var body struct {
		Text string `json:"text"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	cc, err := s.deps.Intent.AddConstraint(r.Context(), caseID, s.actorOf(r), body.Text)
	if err != nil {
		intentErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"constraint": cc})
}

// deleteConstraint 删除操作约束(硬删;历史在审计链)。
func (s *Server) deleteConstraint(w http.ResponseWriter, r *http.Request) {
	if !s.intentReady(w) {
		return
	}
	if err := s.deps.Intent.RemoveConstraint(r.Context(), r.PathValue("id"),
		r.PathValue("cid"), s.actorOf(r)); err != nil {
		intentErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": r.PathValue("cid")})
}
