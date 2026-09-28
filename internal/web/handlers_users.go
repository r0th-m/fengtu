// 用户管理端点(0.26.0-m4-multiuser,DESIGN §9 延伸):
//
//   - /api/users* 全部挂 requireAdmin 角色闸(装配在 server.go),
//     业务闸(自残/最后 admin)焊死在 auth.Service,本层只做映射;
//   - 一切变更落全局审计(caseID 空,同 auth.login 惯例);actor=操作者
//     用户名,detail 带目标用户名;口令永不进审计/日志/响应;
//   - 错误映射:无此用户 404,业务闸/校验 400,与 intentErr 同风格。
package web

import (
	"net/http"
	"strings"
)

// userErr 用户管理错误 → HTTP 状态(无此用户 404;余 400 业务闸/校验)。
func userErr(w http.ResponseWriter, err error) {
	msg := err.Error()
	if strings.Contains(msg, "无此用户") {
		writeErr(w, http.StatusNotFound, msg)
		return
	}
	writeErr(w, http.StatusBadRequest, msg)
}

// userByID 按 id 取用户账(响应回填用;量小,ListUsers 过滤)。
func (s *Server) userByID(r *http.Request, id string) (map[string]any, bool) {
	users, err := s.deps.Auth.ListUsers(r.Context())
	if err != nil {
		return nil, false
	}
	for _, u := range users {
		if u.ID == id {
			return map[string]any{
				"id": u.ID, "username": u.Username, "role": u.Role,
				"disabled": u.Disabled, "failed_attempts": u.FailedAttempts,
				"locked_until": u.LockedUntil, "created_at": u.CreatedAt,
			}, true
		}
	}
	return nil, false
}

// listUsers GET /api/users(admin):全量用户账。
func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.deps.Auth.ListUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "用户清单查询失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

// createUser POST /api/users(admin){username,password,role} → 201 {user}。
func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	u, err := s.deps.Auth.CreateUserAs(r.Context(), body.Username, body.Password, body.Role)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_, _, _ = s.deps.Audit.AppendAudit(r.Context(), "", s.actorOf(r),
		"user.create", u.Username, map[string]any{
			"target": u.Username, "role": u.Role,
		})
	writeJSON(w, http.StatusCreated, map[string]any{"user": u})
}

// patchUser PATCH /api/users/{id}(admin){role?, disabled?} → {user}。
// 两字段指针解码(未提交=不动);先角色后禁用,各落一条审计。
func (s *Server) patchUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Role == nil && body.Disabled == nil {
		writeErr(w, http.StatusBadRequest, "无可更新字段(role/disabled 至少其一)")
		return
	}
	actor := s.actorOf(r)
	actorID := ""
	if u := userFrom(r.Context()); u != nil {
		actorID = u.ID
	}
	if body.Role != nil {
		if err := s.deps.Auth.SetRole(r.Context(), actorID, id, *body.Role); err != nil {
			userErr(w, err)
			return
		}
	}
	if body.Disabled != nil {
		if err := s.deps.Auth.SetDisabled(r.Context(), actorID, id, *body.Disabled); err != nil {
			userErr(w, err)
			return
		}
	}
	u, ok := s.userByID(r, id)
	if !ok {
		writeErr(w, http.StatusNotFound, "无此用户: "+id)
		return
	}
	if body.Role != nil {
		_, _, _ = s.deps.Audit.AppendAudit(r.Context(), "", actor,
			"user.update_role", u["username"].(string), map[string]any{
				"target": u["username"].(string), "role": *body.Role,
			})
	}
	if body.Disabled != nil {
		action := "user.enable"
		if *body.Disabled {
			action = "user.disable"
		}
		_, _, _ = s.deps.Audit.AppendAudit(r.Context(), "", actor,
			action, u["username"].(string), map[string]any{
				"target": u["username"].(string), "disabled": *body.Disabled,
			})
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": u})
}

// resetUserPassword POST /api/users/{id}/password(admin){password} → 204。
// 重置即焚目标全部会话(旧令牌立失效,auth.Service 内闭环)。
func (s *Server) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	u, ok := s.userByID(r, id)
	if !ok {
		writeErr(w, http.StatusNotFound, "无此用户: "+id)
		return
	}
	if err := s.deps.Auth.ResetPassword(r.Context(), id, body.Password); err != nil {
		userErr(w, err)
		return
	}
	_, _, _ = s.deps.Audit.AppendAudit(r.Context(), "", s.actorOf(r),
		"user.reset_password", u["username"].(string), map[string]any{
			"target": u["username"].(string), "sessions_revoked": true,
		})
	w.WriteHeader(http.StatusNoContent)
}

// deleteUser DELETE /api/users/{id}(admin)→ 204(会话同事务焚)。
func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	actorID := ""
	if u := userFrom(r.Context()); u != nil {
		actorID = u.ID
	}
	u, ok := s.userByID(r, id)
	if !ok {
		writeErr(w, http.StatusNotFound, "无此用户: "+id)
		return
	}
	if err := s.deps.Auth.DeleteUserAs(r.Context(), actorID, id); err != nil {
		userErr(w, err)
		return
	}
	_, _, _ = s.deps.Audit.AppendAudit(r.Context(), "", s.actorOf(r),
		"user.delete", u["username"].(string), map[string]any{
			"target": u["username"].(string),
		})
	w.WriteHeader(http.StatusNoContent)
}

// changeMyPassword POST /api/auth/password(任何登录用户)
// {old_password,new_password} → 200。验旧口令(错即 400「凭据不符」)。
func (s *Server) changeMyPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	u := userFrom(r.Context())
	if u == nil {
		writeErr(w, http.StatusUnauthorized, "未登录")
		return
	}
	if err := s.deps.Auth.ChangePassword(r.Context(), u.ID,
		body.OldPassword, body.NewPassword); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_, _, _ = s.deps.Audit.AppendAudit(r.Context(), "", u.Username,
		"user.password_change", u.Username, map[string]any{
			"target": u.Username, "self": true,
		})
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}
