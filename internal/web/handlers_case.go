// 案件生命周期端点(0.18.0-case-lifecycle):改名 / 归档·解归档 / 删除。
//
// 纪律锚点:
//   - 判断权归人:删除不可逆——前端逐字输名确认 + 本层复核名匹配
//     (不符 400),双闸都是人的显式动作,机器不替人下决心;
//   - 证据链不可断:删案先落 case.delete 审计(案件名/源数/事件数快照),
//     审计链本身一条不动(全局哈希链,011 迁移已解除其案件外键,
//     被删案件的历史审计条目原样保留,链校验零影响);
//   - 在跑闸:有关联摄入任务/意图在跑 → 409 如实列出,先停再删;
//   - 级联范围:PG 该案全部元数据 → CH fengtu.events 该案事件(同步
//     mutation)→ 磁盘 workspace/<case_id> 与 vault 原件(同哈希仍被
//     其他案件引用的原件如实保留)。
package web

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/ye-mengwen/fengtu/internal/ingest/store"
)

// caseArchivedGuard 归档案写操作闸:已归档 → 409 如实。
// 归档案页面照常只读可看,但不许起新分析/扫描/手写意图(解归档即恢复)。
func caseArchivedGuard(c *store.Case) bool {
	return c != nil && c.ArchivedAt != nil
}

// renameCase 案件改名(PATCH /api/cases/{id},body {"name"})。
// 口径与创建一致:去空白、非空、≤caseNameMaxRunes 字;重名 409 如实。
func (s *Server) renameCase(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Name string `json:"name"`
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
	ctx := r.Context()
	c, err := s.deps.Meta.GetCase(ctx, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if c == nil {
		writeErr(w, http.StatusNotFound, "无此案件: "+id)
		return
	}
	ok, err := s.deps.Meta.RenameCase(ctx, id, name)
	if err != nil {
		if strings.Contains(err.Error(), "已被占用") {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "无此案件: "+id)
		return
	}
	_, _, _ = s.deps.Audit.AppendAudit(ctx, id, s.actorOf(r), "case.rename", id,
		map[string]any{"old_name": c.Name, "new_name": name})
	c.Name = name
	writeJSON(w, http.StatusOK, map[string]any{"case": c})
}

// archiveCase 归档(POST /api/cases/{id}/archive):列表默认隐藏、停派
// 新意图、禁起新分析;案件页照常只读可看。审计落 case.archive。
func (s *Server) archiveCase(w http.ResponseWriter, r *http.Request) {
	s.setArchived(w, r, true)
}

// unarchiveCase 解归档(POST /api/cases/{id}/unarchive):全量恢复。
func (s *Server) unarchiveCase(w http.ResponseWriter, r *http.Request) {
	s.setArchived(w, r, false)
}

func (s *Server) setArchived(w http.ResponseWriter, r *http.Request, archived bool) {
	id := r.PathValue("id")
	ctx := r.Context()
	c, err := s.deps.Meta.GetCase(ctx, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if c == nil {
		writeErr(w, http.StatusNotFound, "无此案件: "+id)
		return
	}
	ok, err := s.deps.Meta.SetCaseArchived(ctx, id, archived)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "无此案件: "+id)
		return
	}
	action := "case.archive"
	note := "已归档:列表默认隐藏,意图引擎停派新意图(在跑的如实跑完)," +
		"分析/扫描/手写意图 409;案件页只读可看,解归档即恢复"
	if !archived {
		action = "case.unarchive"
		note = "已解归档:恢复派发与分析通路"
	}
	_, _, _ = s.deps.Audit.AppendAudit(ctx, id, s.actorOf(r), action, id,
		map[string]any{"name": c.Name, "note": note})
	fresh, err := s.deps.Meta.GetCase(ctx, id)
	if err != nil || fresh == nil {
		writeErr(w, http.StatusInternalServerError, "归档状态回读失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"case": fresh, "note": note})
}

// deleteCase 案件删除(DELETE /api/cases/{id},body {"name"} 逐字匹配)。
// 不可逆——判断权归人,人输名确认才删(前端对话框逐字输入 + 本层复核,
// 名不符 400)。级联范围见文件头;各阶段失败如实分项报,不装全成。
func (s *Server) deleteCase(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	ctx := r.Context()
	c, err := s.deps.Meta.GetCase(ctx, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if c == nil {
		writeErr(w, http.StatusNotFound, "无此案件: "+id)
		return
	}
	// 双确认后端闸:名逐字匹配(去首尾空白后比对;前端已逐字闸,
	// 这里是服务端复核——判断权归人,两头都要人点头)
	if strings.TrimSpace(body.Name) != c.Name {
		writeErr(w, http.StatusBadRequest,
			"案件名不匹配,拒绝删除(逐字输入案件名确认;删除不可逆)")
		return
	}
	// 在跑闸:关联摄入/扫描任务或意图在跑 → 409 如实列出,先停再删
	jobs, intents, err := s.deps.Meta.CaseInFlight(ctx, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	running := s.tasks.RunningForCase(id)
	if jobs > 0 || intents > 0 || len(running) > 0 {
		tasks := make([]map[string]string, 0, len(running))
		for _, t := range running {
			tasks = append(tasks, map[string]string{
				"id": t.ID, "kind": t.Kind, "progress": t.Progress})
		}
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": fmt.Sprintf("案件有在跑工作(摄入任务 %d / 在跑意图 %d / "+
				"本进程任务 %d),先停再删", jobs, intents, len(running)),
			"running_jobs": jobs, "running_intents": intents, "running_tasks": tasks,
		})
		return
	}
	if s.deps.EventsAdmin == nil {
		writeErr(w, http.StatusServiceUnavailable,
			"事件库管理面未装配,无法级联清该案事件,拒绝删除(见启动日志)")
		return
	}

	// 快照:源清单(sha256 集,删后清 vault 用)+ CH 事件数(审计账)
	sources, err := s.deps.Meta.ListSources(ctx, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "源清单查询失败: "+err.Error())
		return
	}
	hashes := make([]string, 0, len(sources))
	seen := map[string]bool{}
	for _, src := range sources {
		if !seen[src.SHA256] {
			seen[src.SHA256] = true
			hashes = append(hashes, src.SHA256)
		}
	}
	eventCount, err := s.deps.EventsAdmin.CountEventsForCase(ctx, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError,
			"事件计数失败,未动任何数据: "+err.Error())
		return
	}
	actor := s.actorOf(r)

	// 先落审计(删除动作本身的账;案件名/源数/事件数快照——案件删后
	// 这条与该案历史审计条目一起留在全局链上,case_id 成悬空文本,
	// 取舍见 migrations/011 注释)
	_, _, _ = s.deps.Audit.AppendAudit(ctx, id, actor, "case.delete", id,
		map[string]any{
			"name": c.Name, "case_id": id,
			"sources": len(sources), "events": eventCount,
			"note": "判断权归人:人逐字输名确认才删;审计链全局保留不动," +
				"该案历史审计条目原样留在链上(证据链不可断)",
		})

	// 级联一:PG 该案全部元数据(单事务,外键依赖序)
	rep, err := s.deps.Meta.DeleteCase(ctx, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError,
			"元数据级联删除失败,未动事件与磁盘: "+err.Error())
		return
	}

	// 级联二:CH 该案事件(同步 mutation,删完才算)
	stageErrs := map[string]string{}
	if err := s.deps.EventsAdmin.DeleteEventsForCase(ctx, id); err != nil {
		stageErrs["events"] = err.Error()
	}

	// 级联三:磁盘——workspace/<case_id> 工作区 + vault 原件
	// (同哈希仍被其他案件引用的如实保留,证据链不断)
	workspaceRemoved := false
	if s.deps.DataDir != "" {
		wsDir := filepath.Join(s.deps.DataDir, "workspace", id)
		if err := os.RemoveAll(wsDir); err != nil {
			stageErrs["workspace"] = err.Error()
		} else {
			workspaceRemoved = true
		}
	}
	vaultRemoved, vaultKept := 0, 0
	if s.deps.Vault != nil {
		for _, h := range hashes {
			n, cerr := s.deps.Meta.CountSourcesByHash(ctx, h)
			if cerr != nil {
				stageErrs["vault:"+h[:12]] = cerr.Error()
				continue
			}
			if n > 0 {
				vaultKept++ // 其他案件还指着这份证据,如实留着
				continue
			}
			if rerr := s.deps.Vault.Remove(h); rerr != nil {
				stageErrs["vault:"+h[:12]] = rerr.Error()
				continue
			}
			vaultRemoved++
		}
	}

	resp := map[string]any{
		"deleted": true, "case_id": id, "name": c.Name,
		"report": rep, "events_deleted": eventCount,
		"workspace_removed": workspaceRemoved,
		"vault_removed": vaultRemoved, "vault_kept": vaultKept,
		"note": "案件已删(不可逆);该案历史审计条目留在全局审计链" +
			"(GET /api/audit/chain 按 case_id 仍可回查,链校验零影响)",
	}
	if len(stageErrs) > 0 {
		resp["stage_errors"] = stageErrs // 如实分项:PG 已删,后续阶段有未成
		writeJSON(w, http.StatusInternalServerError, resp)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
