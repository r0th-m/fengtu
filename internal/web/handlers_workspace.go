// 工作空间文件管理器端点(ARTEX function/workspace 复刻;切片十一落地,
// 切片十三按案件隔离):
// 根 = FENGTU_DATA_DIR/workspace;案件工作区 = 根下 <case_id>/ 一级目录,
// 路由 /api/cases/{id}/workspace/*(案件存在性核验,无此案 404);旧全局
// 端点 /api/workspace/* 保留为「未分配」遗留区(兼容旧数据,不丢用户文件),
// 但隔离焊死:清单滤掉案件目录、首段命中案件 id 的路径一律 400(案件工作区
// 只能从案件路由进出,A 案通路物理上看不到 B 案)。
// 与案件原件金库 vault/ 物理隔离——证据链不可断:vault 原件永不进可写通路。
//
// 安全焊死(负样本测试 handlers_workspace_test.go):
//   - 路径净化+符号链接逃逸检查与 agentloop 工作区工具共用
//     internal/workspace.Resolve(唯一真源,两处不得各写一份);
//   - 案件 id 本身也过 Resolve 单段净化(注入 ../、反斜杠一律 400);
//   - 全部端点在登录闸内(server.go requireAuth);写操作(mkdir/upload/
//     write/delete)进审计哈希链(workspace.* 动作,案件作用域记案件 id);
//   - 文本判定按内容嗅探(workspace.LooksBinary),不按扩展名猜;
//     预览/编辑限 8MB 内文本,超出如实标 too_large 只给下载。
package web

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ye-mengwen/fengtu/internal/workspace"
)

// wsMaxTextBytes 预览/编辑文本上限(8MB;超出如实 too_large 只给下载)。
const wsMaxTextBytes = 8 << 20

// wsEntry 目录清单条目(与前端 WorkspaceEntry 对齐;mtime=Unix 毫秒)。
type wsEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"` // 相对根的 slash 路径(面包屑/下级导航用)
	Dir   bool   `json:"dir"`
	Size  int64  `json:"size"`
	Mtime int64  `json:"mtime"`
}

// wsBase 工作区总根(懒创建;DataDir 未装配 → 错误,端点 503 如实,
// 与 logsTail 同纪律)。
func (s *Server) wsBase() (string, error) {
	if s.deps.DataDir == "" {
		return "", errors.New("数据根未装配(server 未传 DataDir)")
	}
	root := filepath.Join(s.deps.DataDir, "workspace")
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", err
	}
	return root, nil
}

// wsScope 请求级作用域解析:案件路由(PathValue id 非空)→ 校验案件 id
// 单段净化 + 案件存在性,根=workspace/<case_id>(写操作懒创建,读操作
// 不建——不存在即如实空);全局路由(未分配区)→ 根=workspace,叠隔离闸:
// rel 首段命中现存案件 id 一律 400(案件工作区只能从案件路由进出)。
// 返回根与案件 id(全局="";审计记账用)。
func (s *Server) wsScope(w http.ResponseWriter, r *http.Request,
	rel string, forWrite bool) (string, string, bool) {

	base, err := s.wsBase()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return "", "", false
	}
	caseID := r.PathValue("id")
	if caseID == "" {
		// 未分配区隔离闸:首段不得是现存案件 id
		first := rel
		if i := strings.Index(first, "/"); i >= 0 {
			first = first[:i]
		}
		if first != "" && !strings.Contains(first, "..") {
			c, err := s.deps.Meta.GetCase(r.Context(), first)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, "案件核验失败: "+err.Error())
				return "", "", false
			}
			if c != nil {
				writeErr(w, http.StatusBadRequest,
					"该路径属案件工作区(隔离):请从对应案件的工作区入口操作")
				return "", "", false
			}
		}
		return base, "", true
	}
	// 案件作用域:id 单段净化(注 ../、反斜杠一律 400)+ 案件存在性核验
	if _, err := workspace.Resolve(base, caseID); err != nil {
		writeErr(w, http.StatusBadRequest, "案件 id 非法: "+err.Error())
		return "", "", false
	}
	// 案件 id 是 UUID(schema 001_init):非 UUID 形态不可能存在,如实 404,
	// 不落到 PG 报 500(VM 实测:非 UUID 直查 PG 报 SQLSTATE 22P02)
	if !looksUUID(caseID) {
		writeErr(w, http.StatusNotFound, "无此案件: "+caseID)
		return "", "", false
	}
	c, err := s.deps.Meta.GetCase(r.Context(), caseID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "案件核验失败: "+err.Error())
		return "", "", false
	}
	if c == nil {
		writeErr(w, http.StatusNotFound, "无此案件: "+caseID)
		return "", "", false
	}
	root := filepath.Join(base, caseID)
	if forWrite {
		if err := os.MkdirAll(root, 0o755); err != nil {
			writeErr(w, http.StatusInternalServerError, "案件工作区创建失败: "+err.Error())
			return "", "", false
		}
	}
	return root, caseID, true
}

// looksUUID 案件 id 形态闸(UUID v4 形态 8-4-4-4-12 十六进制;只管形态,
// 存在性仍查库)。cases.id 是 UUID 主键(deploy/schema/pg/001_init.sql),
// 非 UUID 形态必不存在——提前 404,防 PG 类型错误变 500。
func looksUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}

// wsResolve 请求级路径解析:作用域根(wsScope)+ 相对路径净化;失败写错误
// 并返回 false。wantDir 语义由调用方自己 stat 判定。
func (s *Server) wsResolve(w http.ResponseWriter, r *http.Request, rel string,
	forWrite bool) (string, string, string, bool) {

	root, caseID, ok := s.wsScope(w, r, rel, forWrite)
	if !ok {
		return "", "", "", false
	}
	fp, err := workspace.Resolve(root, rel)
	if err != nil {
		if errors.Is(err, workspace.ErrBadPath) ||
			strings.Contains(err.Error(), "符号链接") {
			writeErr(w, http.StatusBadRequest, err.Error())
		} else {
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return "", "", "", false
	}
	return root, caseID, fp, true
}

// ---- GET list?path=(案件路由:/api/cases/{id}/workspace/list) ----

func (s *Server) wsList(w http.ResponseWriter, r *http.Request) {
	rel := r.URL.Query().Get("path")
	_, caseID, fp, ok := s.wsResolve(w, r, rel, false)
	if !ok {
		return
	}
	des, err := os.ReadDir(fp)
	if err != nil {
		if os.IsNotExist(err) {
			if caseID != "" && rel == "" {
				// 案件工作区尚未建(无补充材料):如实空清单,不 404
				writeJSON(w, http.StatusOK, map[string]any{
					"path": "", "entries": []wsEntry{}, "case_id": caseID,
					"note": "案件工作区为空:用户上传的补充材料会落在该案专属目录;" +
						"AI 会话只读可见(参考材料不是证据,锚点仍只能锚采集物)",
				})
				return
			}
			writeErr(w, http.StatusNotFound, "无此目录: "+rel)
			return
		}
		writeErr(w, http.StatusInternalServerError, "目录读取失败: "+err.Error())
		return
	}
	// 未分配区:滤掉案件目录(隔离——案件工作区只能从案件路由进出)
	var caseDirs map[string]bool
	if caseID == "" {
		caseDirs = map[string]bool{}
		if cases, err := s.deps.Meta.ListCases(r.Context()); err != nil {
			writeErr(w, http.StatusInternalServerError, "案件清单核验失败: "+err.Error())
			return
		} else {
			for _, c := range cases {
				caseDirs[c.ID] = true
			}
		}
	}
	entries := []wsEntry{}
	for _, de := range des {
		info, err := de.Info()
		if err != nil {
			continue // 竞态删除:跳过(刷新即一致)
		}
		if caseID == "" && de.IsDir() && caseDirs[de.Name()] {
			continue // 案件目录不进未分配区清单
		}
		ep := de.Name()
		if rel != "" {
			ep = rel + "/" + de.Name()
		}
		entries = append(entries, wsEntry{
			Name: de.Name(), Path: ep, Dir: de.IsDir(),
			Size: info.Size(), Mtime: info.ModTime().UnixMilli(),
		})
	}
	// 目录在前,各自按名排序(与 ARTEX 一致)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Dir != entries[j].Dir {
			return entries[i].Dir
		}
		return entries[i].Name < entries[j].Name
	})
	note := "未分配区(旧全局工作区遗留,不属任何案件);案件工作区在 /function/workspace 选案件进入"
	if caseID != "" {
		note = "案件工作区(workspace/" + caseID + "):用户上传的补充材料,AI 会话只读可见;" +
			"参考材料不是证据,锚点仍只能锚采集物"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path": rel, "entries": entries, "case_id": caseID, "note": note,
	})
}

// ---- GET file?path=(读文本;二进制/超大如实标记) ----

func (s *Server) wsFile(w http.ResponseWriter, r *http.Request) {
	rel := r.URL.Query().Get("path")
	if rel == "" {
		writeErr(w, http.StatusBadRequest, "缺 path")
		return
	}
	_, _, fp, ok := s.wsResolve(w, r, rel, false)
	if !ok {
		return
	}
	info, err := os.Stat(fp)
	if err != nil {
		if os.IsNotExist(err) {
			writeErr(w, http.StatusNotFound, "无此文件: "+rel)
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if info.IsDir() {
		writeErr(w, http.StatusBadRequest, "目录不能按文件读: "+rel)
		return
	}
	out := map[string]any{
		"name": info.Name(), "path": rel, "size": info.Size(),
		"mtime": info.ModTime().UnixMilli(),
		"binary": false, "too_large": false,
	}
	if info.Size() > wsMaxTextBytes {
		out["too_large"] = true // 如实:超 8MB 只给下载,不回内容
		writeJSON(w, http.StatusOK, out)
		return
	}
	data, err := os.ReadFile(fp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取失败: "+err.Error())
		return
	}
	if workspace.LooksBinary(data) {
		out["binary"] = true // 如实:二进制不回内容
	} else {
		out["content"] = string(data)
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- GET download?path= ----

func (s *Server) wsDownload(w http.ResponseWriter, r *http.Request) {
	rel := r.URL.Query().Get("path")
	if rel == "" {
		writeErr(w, http.StatusBadRequest, "缺 path")
		return
	}
	_, _, fp, ok := s.wsResolve(w, r, rel, false)
	if !ok {
		return
	}
	f, err := os.Open(fp)
	if err != nil {
		if os.IsNotExist(err) {
			writeErr(w, http.StatusNotFound, "无此文件: "+rel)
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if info.IsDir() {
		writeErr(w, http.StatusBadRequest, "目录不提供下载: "+rel)
		return
	}
	// RFC 5987 文件名(中文名不落 latin-1 报错)
	w.Header().Set("Content-Disposition",
		"attachment; filename*=UTF-8''"+url.PathEscape(info.Name()))
	http.ServeContent(w, r, info.Name(), info.ModTime(), f)
}

// ---- POST upload(multipart:path 字段=目标目录,files 多文件) ----

func (s *Server) wsUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 512<<20) // 请求总量封顶 512MB
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "multipart 解析失败: "+err.Error())
		return
	}
	rel := r.FormValue("path")
	_, caseID, dir, ok := s.wsResolve(w, r, rel, true)
	if !ok {
		return
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		writeErr(w, http.StatusBadRequest, "目标目录不存在: "+rel)
		return
	}
	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		writeErr(w, http.StatusBadRequest, "无文件(files 字段为空)")
		return
	}
	names := []string{}
	for _, fh := range files {
		// 文件名只取 base(客户端路径信息剥掉),非法名拒收
		name := filepath.Base(strings.ReplaceAll(fh.Filename, "\\", "/"))
		if name == "" || name == "." || name == ".." ||
			strings.ContainsRune(name, 0) {
			writeErr(w, http.StatusBadRequest, "文件名非法: "+fh.Filename)
			return
		}
		src, err := fh.Open()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "上传件打开失败: "+err.Error())
			return
		}
		dst, err := os.OpenFile(filepath.Join(dir, name),
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			src.Close()
			writeErr(w, http.StatusInternalServerError, "写入失败: "+err.Error())
			return
		}
		_, cpyErr := io.Copy(dst, src)
		closeErr := dst.Close()
		src.Close()
		if cpyErr != nil || closeErr != nil {
			writeErr(w, http.StatusInternalServerError, "写入失败")
			return
		}
		names = append(names, name)
	}
	ep := rel
	if ep == "" {
		ep = "/"
	}
	_, _, _ = s.deps.Audit.AppendAudit(r.Context(), caseID, s.actorOf(r),
		"workspace.upload", ep, map[string]any{
			"files": names, "count": len(names)})
	writeJSON(w, http.StatusOK, map[string]any{"uploaded": len(names)})
}

// ---- POST mkdir{path} ----

func (s *Server) wsMkdir(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path string `json:"path"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Path == "" {
		writeErr(w, http.StatusBadRequest, "缺 path")
		return
	}
	_, caseID, fp, ok := s.wsResolve(w, r, body.Path, true)
	if !ok {
		return
	}
	if err := os.MkdirAll(fp, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "目录创建失败: "+err.Error())
		return
	}
	_, _, _ = s.deps.Audit.AppendAudit(r.Context(), caseID, s.actorOf(r),
		"workspace.mkdir", body.Path, nil)
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "path": body.Path})
}

// ---- PUT file{path,content}(保存文本) ----

func (s *Server) wsWrite(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	// 文本上限 8MB(与预览同口径);JSON 包装留 1MB 余量
	r.Body = http.MaxBytesReader(w, r.Body, wsMaxTextBytes+(1<<20))
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体 JSON 解析失败: "+err.Error())
		return
	}
	if body.Path == "" {
		writeErr(w, http.StatusBadRequest, "缺 path")
		return
	}
	if len(body.Content) > wsMaxTextBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, "文本超 8MB 上限,拒写")
		return
	}
	_, caseID, fp, ok := s.wsResolve(w, r, body.Path, true)
	if !ok {
		return
	}
	if info, err := os.Stat(fp); err == nil && info.IsDir() {
		writeErr(w, http.StatusBadRequest, "目录不能按文件写: "+body.Path)
		return
	}
	if err := os.WriteFile(fp, []byte(body.Content), 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, "写入失败: "+err.Error())
		return
	}
	_, _, _ = s.deps.Audit.AppendAudit(r.Context(), caseID, s.actorOf(r),
		"workspace.write", body.Path, map[string]any{"size": len(body.Content)})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- DELETE entry?path=(目录递归删;根不许删) ----

func (s *Server) wsDelete(w http.ResponseWriter, r *http.Request) {
	rel := r.URL.Query().Get("path")
	if rel == "" {
		writeErr(w, http.StatusBadRequest, "缺 path(工作区根不许删)")
		return
	}
	_, caseID, fp, ok := s.wsResolve(w, r, rel, false)
	if !ok {
		return
	}
	info, err := os.Stat(fp)
	if err != nil {
		if os.IsNotExist(err) {
			writeErr(w, http.StatusNotFound, "无此条目: "+rel)
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := os.RemoveAll(fp); err != nil {
		writeErr(w, http.StatusInternalServerError, "删除失败: "+err.Error())
		return
	}
	_, _, _ = s.deps.Audit.AppendAudit(r.Context(), caseID, s.actorOf(r),
		"workspace.delete", rel, map[string]any{
			"dir": info.IsDir(), "size": info.Size(),
			"mtime": info.ModTime().UTC().Format(time.RFC3339)})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
