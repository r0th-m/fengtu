// 上传接入端点与摄入派发:分块上传 → 金库(写前校验)→ 登记 → 异步摄入
// (切片二管线)→ SSE 进度。zip:单层展开登记多源(语义同索图);
// WinInfoSC 包 zip:整树展开 + 清单对账(契约失配拒收)+ 包摄入。
package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/ye-mengwen/fengtu/internal/fingerprint"
	"github.com/ye-mengwen/fengtu/internal/ingest"
	"github.com/ye-mengwen/fengtu/internal/ingress"
)

// uploadInit 开上传会话(返回 upload_id 与分块大小,客户端按块上传)。
func (s *Server) uploadInit(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CaseName string `json:"case_name"`
		Filename string `json:"filename"`
		Size     int64  `json:"size"`
		SHA256   string `json:"sha256"`
		Format   string `json:"format"`
		Desc     string `json:"desc"`
		TZ       string `json:"tz"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	u := userFrom(r.Context())
	actor := "system"
	if u != nil {
		actor = u.Username
	}
	meta, err := s.deps.Ingress.Init(body.CaseName, body.Filename, body.Size,
		body.SHA256, body.Format, body.Desc, body.TZ, actor)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"upload_id":  meta.ID,
		"chunk_size": s.deps.Ingress.ChunkSize(),
		"received":   []int{},
	})
}

// uploadStatus 续传账(已收分块清单)。
func (s *Server) uploadStatus(w http.ResponseWriter, r *http.Request) {
	meta, got, err := s.deps.Ingress.Status(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"upload": meta, "received": got,
		"chunk_size": s.deps.Ingress.ChunkSize(),
	})
}

// uploadChunk 收一个分块(可选 X-Chunk-SHA256 逐块校验)。
func (s *Server) uploadChunk(w http.ResponseWriter, r *http.Request) {
	index, err := strconv.Atoi(r.PathValue("index"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "分块序号须为整数")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.deps.Ingress.ChunkSize()+1<<20)
	if err := s.deps.Ingress.PutChunk(r.PathValue("id"), index, r.Body,
		r.Header.Get("X-Chunk-SHA256")); err != nil {
		if strings.Contains(err.Error(), "无此上传会话") {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"received": index})
}

// uploadComplete 齐块对账 → 金库 → 登记 → 异步摄入(202 + task_id)。
func (s *Server) uploadComplete(w http.ResponseWriter, r *http.Request) {
	meta, rc, cleanup, err := s.deps.Ingress.Complete(r.PathValue("id"))
	if err != nil {
		if strings.Contains(err.Error(), "无此上传会话") {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeErr(w, http.StatusConflict, err.Error()) // 分块不全 = 状态未就绪
		return
	}
	u := userFrom(r.Context())
	actor := meta.Actor
	if u != nil {
		actor = u.Username
	}

	// 金库写前校验:全文件 SHA256 对账不过 = 拒收(审计留痕,不登记不摄入)
	if _, err := s.deps.Vault.Put(meta.SHA256, rc); err != nil {
		cleanup()
		_, _, _ = s.deps.Audit.AppendAudit(r.Context(), "", actor,
			"upload.rejected", meta.Filename, map[string]any{
				"case_name": meta.CaseName, "sha256": meta.SHA256,
				"reason": err.Error(),
			})
		writeErr(w, http.StatusUnprocessableEntity,
			"全文件 SHA256 对账不过,拒收入库: "+err.Error())
		return
	}
	vaultPath := s.deps.Vault.Path(meta.SHA256)
	_, _, _ = s.deps.Audit.AppendAudit(r.Context(), "", actor,
		"upload.completed", meta.Filename, map[string]any{
			"case_name": meta.CaseName, "filename": meta.Filename,
			"sha256": meta.SHA256, "size": meta.Size,
			"format": meta.Format, "desc": meta.Desc,
		})

	// 先落案件账再开任务(摄入 goroutine 内 EnsureCase 同键幂等)——
	// 任务带案件锚,删案前置闸(TaskManager.RunningForCase)才能拦到
	// 「上传刚完成、摄入在跑」的窗口期。
	caseID, err := s.deps.Meta.EnsureCase(r.Context(), meta.CaseName)
	if err != nil {
		cleanup()
		writeErr(w, http.StatusInternalServerError, "案件登记失败: "+err.Error())
		return
	}
	task := s.tasks.New("ingest", caseID)
	go s.runIngest(task.ID, meta, vaultPath, actor, cleanup)
	writeJSON(w, http.StatusAccepted, map[string]any{"task_id": task.ID})
}

// runIngest 异步摄入派发(单文件 / zip 文件模式 / WinInfoSC 包模式)。
func (s *Server) runIngest(taskID string, meta *ingress.UploadMeta,
	vaultPath, actor string, cleanup func()) {
	ctx := context.Background() // 异步任务不随请求生命周期
	defer cleanup()
	s.tasks.Progress(taskID, "摄入中: "+meta.Filename)

	if isZipFile(vaultPath) {
		s.runIngestZip(ctx, taskID, meta, vaultPath, actor)
		return
	}
	rep, err := s.ingestOne(ctx, meta.CaseName, vaultPath, meta.Filename,
		meta.Format, meta.Desc, meta.TZ)
	if err != nil {
		s.tasks.Finish(taskID, "failed", err.Error(), rep)
		return
	}
	s.tasks.Finish(taskID, "done", "", rep)
}

// strIn 字符串成员判定(包登记根名 #N 后缀去重用)。
func strIn(s string, ss []string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// isZipFile PK 魔数嗅探。
func isZipFile(path string) bool {	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var head [4]byte
	if _, err := io.ReadFull(f, head[:]); err != nil {
		return false
	}
	return head[0] == 'P' && head[1] == 'K' && head[2] == 3 && head[3] == 4
}

// runIngestZip zip 通道:包模式(整树展开+清单对账+包摄入)或
// 文件模式(单层逐文件登记多源,语义同索图)。
func (s *Server) runIngestZip(ctx context.Context, taskID string,
	meta *ingress.UploadMeta, vaultPath, actor string) {

	staging := filepath.Join(s.deps.StagingDir, "zip-"+taskID)
	defer os.RemoveAll(staging)

	exp, err := ingress.ExpandZip(vaultPath, staging, s.deps.ArtifactMap.IsPackageRoot)
	if err != nil {
		s.tasks.Finish(taskID, "failed", "zip 展开失败: "+err.Error(), nil)
		return
	}

	if exp.Mode == "package" {
		// 清单契约:失配 = 证据完整性存疑 = 拒收(原件已在金库,派生不建)
		if exp.Manifest != nil && !exp.Manifest.Pass() {
			detail := map[string]any{
				"case_name": meta.CaseName, "zip": meta.Filename,
				"sha256": meta.SHA256, "manifest": exp.Manifest,
			}
			_, _, _ = s.deps.Audit.AppendAudit(ctx, "", actor,
				"upload.rejected", meta.Filename, map[string]any{
					"case_name": meta.CaseName, "sha256": meta.SHA256,
					"reason": "哈希清单契约失配", "manifest": exp.Manifest,
				})
			s.tasks.Finish(taskID, "failed",
				fmt.Sprintf("哈希清单契约失配(missing=%d mismatch=%d),拒收——"+
					"原件已留金库,派生数据未建", len(exp.Manifest.Missing),
					len(exp.Manifest.Mismatch)), detail)
			return
		}
		s.runIngestPackage(ctx, taskID, meta, exp, actor)
		return
	}

	// 文件模式:逐文件金库 + 登记 + 摄入(text 源套用上传绑定;
	// 无绑定如实登记不解析,指纹建议是后续切片)
	var results []map[string]any
	var failures []map[string]string
	for i, ef := range exp.Files {
		s.tasks.Progress(taskID, fmt.Sprintf("摄入中(%d/%d): %s",
			i+1, len(exp.Files), ef.Name))
		if err := s.vaultFile(ef); err != nil {
			failures = append(failures, map[string]string{
				"file": ef.Name, "err": err.Error()})
			continue
		}
		rep, ierr := s.ingestOne(ctx, meta.CaseName, s.deps.Vault.Path(ef.SHA256),
			ef.Name, meta.Format, meta.Desc, meta.TZ)
		if ierr != nil {
			failures = append(failures, map[string]string{
				"file": ef.Name, "err": ierr.Error()})
			continue
		}
		results = append(results, rep)
	}
	status := "done"
	errText := ""
	if len(failures) > 0 {
		status = "failed"
		errText = fmt.Sprintf("%d 个文件摄入失败(详见 detail.failures)", len(failures))
	}
	s.tasks.Finish(taskID, status, errText, map[string]any{
		"mode": "files", "sources": results, "skipped": exp.Skipped,
		"failures": failures,
	})
}

// vaultFile 展开文件进金库(写前校验复用解出时已算的哈希)。
func (s *Server) vaultFile(ef ingress.ExpandedFile) error {
	f, err := os.Open(ef.Path)
	if err != nil {
		return fmt.Errorf("展开文件打开失败: %w", err)
	}
	defer f.Close()
	if _, err := s.deps.Vault.Put(ef.SHA256, f); err != nil {
		return err
	}
	return nil
}

// pkgRegLocks 同案包登记的进程内互斥(caseID → *sync.Mutex;M4 并发安全):
// 「ListPackages 查重 + 算 #N 后缀 + IngestPackage 登记」不在事务里,
// 两并发同包名上传会算出同一后缀撞 UNIQUE(case_id,path) → 23505 任务失败。
// 取舍:单二进制部署进程内锁足够;若日后多实例部署,须换 PG advisory
// lock(参照 store.scanLockKey 的范式),此处如实标注。
var pkgRegLocks sync.Map

func pkgRegLock(caseID string) *sync.Mutex {
	v, _ := pkgRegLocks.LoadOrStore(caseID, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// runIngestPackage WinInfoSC 包摄入:逐文件进金库 → 切片二包管线。
func (s *Server) runIngestPackage(ctx context.Context, taskID string,
	meta *ingress.UploadMeta, exp *ingress.Expanded, actor string) {

	// 逐文件进金库(证据链:sources.sha256 → 金库可回查)
	for i, ef := range exp.Files {
		s.tasks.Progress(taskID, fmt.Sprintf("金库登记中(%d/%d)",
			i+1, len(exp.Files)))
		if err := s.vaultFile(ef); err != nil {
			s.tasks.Finish(taskID, "failed",
				fmt.Sprintf("文件 %s 金库入库失败: %v", ef.Name, err), nil)
			return
		}
	}

	s.tasks.Progress(taskID, "包摄入中")
	// 一案多包(§3 修正稿):同一主机二次采包时,登记根名加 #N 后缀
	// (sources (case_id,path) 唯一约束不撞车;主机键从真实包名提取,
	// 两包归并同一主机——归并靠 host 列,不靠路径)。
	displayRoot := exp.PackageName
	caseID, err := s.deps.Meta.EnsureCase(ctx, meta.CaseName)
	if err != nil {
		s.tasks.Finish(taskID, "failed", "案件登记失败: "+err.Error(), nil)
		return
	}
	// 同案串行化:查重→#N 后缀→登记 须原子(见 pkgRegLocks 注释);
	// 锁覆盖整个包摄入——登记动作在 IngestPackage 内部,只锁查重段
	// 挡不住「后缀算完、登记未落」的窗口。
	mu := pkgRegLock(caseID)
	mu.Lock()
	defer mu.Unlock()
	existing, err := s.deps.Meta.ListPackages(ctx, caseID)
	if err != nil {
		s.tasks.Finish(taskID, "failed", "包清单查询失败: "+err.Error(), nil)
		return
	}
	if strIn(exp.PackageName, existing) {
		for n := 2; ; n++ {
			cand := fmt.Sprintf("%s#%d", exp.PackageName, n)
			if !strIn(cand, existing) {
				displayRoot = cand
				break
			}
		}
	}
	rep, err := ingest.IngestPackage(ctx, s.deps.Meta, s.deps.Events,
		ingest.PackageSpec{
			CaseName: meta.CaseName,
			Root:     exp.PackageRoot,
			Map:      s.deps.ArtifactMap,
			Evtx:     ingest.VelocidexParser{},
			DescDir:  s.deps.DescDir,
			Spec:     ingest.Spec{TZDeclared: meta.TZ},
			DisplayRoot: displayRoot,
			OnFile: func(done, total int, rel string) {
				s.tasks.Progress(taskID, fmt.Sprintf("包摄入中(%d/%d): %s",
					done, total, rel))
			},
		})
	detail := map[string]any{
		"mode": "package", "package": exp.PackageName, "manifest": exp.Manifest,
		"report": rep,
	}
	if err != nil {
		s.tasks.Finish(taskID, "failed", err.Error(), detail)
		return
	}
	s.tasks.Finish(taskID, "done", "", detail)
}

// ingestOne 单文件登记 + 摄入(返回对账摘要;text 无格式绑定如实登记
// 不解析——解析配置须有人确认,不静默猜,索图 confirm 语义)。
func (s *Server) ingestOne(ctx context.Context, caseName, fsPath, displayPath,
	format, descName, tz string) (map[string]any, error) {

	spec := ingest.Spec{
		CaseName: caseName, Path: fsPath, DisplayPath: displayPath,
		TZDeclared: tz,
	}
	rep := func(route string, extra map[string]any) map[string]any {
		m := map[string]any{"file": displayPath, "route": route}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	switch ingest.DetectKind(displayPath) {
	case ingest.KindEVTX:
		spec.Kind = ingest.KindEVTX
		spec.ParserLabel = "evtx_native:velocidex"
		spec.LogType = "windows_event_log" // evtx 原生路由品类(结构常量)
		st, err := ingest.IngestEVTXFile(ctx, s.deps.Meta, s.deps.Events, spec,
			ingest.VelocidexParser{})
		if err != nil {
			return nil, fmt.Errorf("evtx 摄入失败: %w", err)
		}
		return rep("evtx_native", map[string]any{"events": st.Events,
			"bad": st.Bad, "skip": st.Skip}), nil
	case ingest.KindText:
		if format == "" && descName == "" {
			// 无格式绑定:如实登记不解析(解析配置要人确认——一键分析
			// 主链路的指纹判定 + 改判端点接这条路,切片四起)
			spec.Kind = ingest.KindRaw
			if err := ingest.RegisterRawFile(ctx, s.deps.Meta, spec); err != nil {
				return nil, fmt.Errorf("登记失败: %w", err)
			}
			return rep("registered_unparsed", map[string]any{
				"note": "行式文本无格式绑定,已登记未解析(解析配置需人确认;" +
					"一键分析 POST /api/cases/{id}/analyze 会自动指纹判定)"}), nil
		}
		spec.Kind = ingest.KindText
		var parse ingest.ParseFunc
		var encoding string
		var isBlockStart func(string) bool
		var err error
		if format != "" {
			parse, err = ingest.BuiltinParse(format)
			encoding = "utf-8"
			isBlockStart = ingest.AlwaysBlockStart
			spec.ParserLabel = "builtin:" + format
		} else {
			parse, encoding, isBlockStart, err = ingest.LoadDescParse(
				filepath.Join(s.deps.DescDir, descName+".yaml"))
			spec.ParserLabel = "desc:" + descName
		}
		if err != nil {
			return nil, fmt.Errorf("格式绑定装载失败: %w", err)
		}
		// 显式绑定 = 品类已知(适用域路由键;候选集声明,空=无品类)
		if cand := fingerprint.FindCandidate(s.deps.Candidates, spec.ParserLabel); cand != nil {
			spec.LogType = cand.LogType
		}
		st, err := ingest.IngestTextFile(ctx, s.deps.Meta, s.deps.Events, spec,
			encoding, parse, isBlockStart)
		if err != nil {
			return nil, fmt.Errorf("文本摄入失败: %w", err)
		}
		return rep(spec.ParserLabel, map[string]any{"events": st.Events,
			"bad": st.Bad, "skip": st.Skip}), nil
	default:
		spec.Kind = ingest.KindRaw
		if err := ingest.RegisterRawFile(ctx, s.deps.Meta, spec); err != nil {
			return nil, fmt.Errorf("登记失败: %w", err)
		}
		return rep("raw", nil), nil
	}
}
