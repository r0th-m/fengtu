// 0.27.0 案件封存/迁移(M4):导出单 zip(跨实例迁移/移交)+ 导入校验重建。
//
// 纪律(与 DESIGN §1/§5 同源):
//   - 证据链不可断:导入先对账(SHA256SUMS 逐文件 + vault/<sha256> 内容实算
//     必须等于寻址文件名),对不上 422 拒收——不落源、不建案、不入库;
//   - 审计段是全局哈希链切片:导出做快照随包走(audit_snapshot.json),
//     导入绝不回插 audit_chain(序号为源实例全局序,回插必断链)——快照
//     作为文件落新案工作区 seal/ 留档,导入动作本身落全局审计;
//   - 判断权归人:导入永远建新案(名撞加「(导入)」后缀),不并案不覆盖;
//     hits/裁决不随包(规格未列)——导入后人工重扫描重裁决;
//   - 迁移不续跑:在跑(running)/待批(awaiting_approval)意图导入一律落
//     stopped(017 迁移;终态,人看过证据后重新派发);open 意图保持 open
//     (未派发语义,目标实例引擎按正常派发接手)。
//   - 导出整包内存拼装(bytes.Buffer;案件导出量级内网可接受,如实标注),
//     算完哈希再写响应;导出不许动 vault(只读)。
package web

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ye-mengwen/fengtu/internal/fingerprint"
	"github.com/ye-mengwen/fengtu/internal/ingest"
	"github.com/ye-mengwen/fengtu/internal/ingest/store"
	"github.com/ye-mengwen/fengtu/internal/intent"
)

// 封存包格式契约(manifest.json;format_version 不符 = 422 拒收,不猜不兼容)。
const (
	sealFormat        = "fengtu-case-seal"
	sealFormatVersion = 1
	// sealMaxBytes 导入包上限(4GB;内网移交量级,防内存/磁盘被撑爆)。
	sealMaxBytes = 4 << 30
	// sealJSONMax 包内单个 JSON 段读取上限(256MB;元数据段正常 KB~MB 级)。
	sealJSONMax = 256 << 20
)

// sealManifest manifest.json(清单 + 计数账 + 导出侧在跑快照)。
type sealManifest struct {
	Format        string       `json:"format"` // 恒 fengtu-case-seal
	FormatVersion int          `json:"format_version"`
	AppVersion    string       `json:"app_version"`
	Case          store.Case   `json:"case"` // 案件元数据快照(含应急元数据三字段)
	ExportedAt    time.Time    `json:"exported_at"`
	ExportedBy    string       `json:"exported_by"`
	Counts        sealCounts   `json:"counts"`
	InFlight      sealInFlight `json:"in_flight"`
}

type sealCounts struct {
	Sources      int `json:"sources"`
	Anchors      int `json:"anchors"`
	IntentNodes  int `json:"intent_nodes"`
	IntentEdges  int `json:"intent_edges"`
	AuditEntries int `json:"audit_entries"`
	VaultFiles   int `json:"vault_files"` // 唯一 sha256 数(同哈希多源只带一份)
}

// sealInFlight 导出当下在跑账(快照不拒导,如实标;导入侧 running 一律 stopped)。
type sealInFlight struct {
	Jobs    int64 `json:"jobs"`
	Intents int64 `json:"intents"`
}

// sealSource sources.json 行:源全字段 + 任务账解析器实证(上传绑定格式的
// 解析配置只活在 ingest_jobs.parser 列——sources 表无此列,不随包带走的话
// 这类源导入后无法按原格式重派生,只能退化 raw;如实补上)。
type sealSource struct {
	store.Source
	ParserLabel string `json:"parser_label,omitempty"`
}

// sealIntent intent.json(意图图:节点 + 血缘边)。
type sealIntent struct {
	Nodes []*intent.Node `json:"nodes"`
	Edges []*intent.Edge `json:"edges"`
}

// ---- 导出 ----

// exportCase GET /api/cases/{id}/export → 200 application/zip。
// 整包内存拼装(注释见文件头);全角色,登录即可。
func (s *Server) exportCase(w http.ResponseWriter, r *http.Request) {
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
	sources, err := s.deps.Meta.ListSources(ctx, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "源清单查询失败: "+err.Error())
		return
	}
	anchors, err := s.deps.Meta.ListSealAnchors(ctx, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "锚点查询失败: "+err.Error())
		return
	}
	nodes, err := s.deps.Meta.ListNodes(ctx, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "意图节点查询失败: "+err.Error())
		return
	}
	edges, err := s.deps.Meta.ListEdges(ctx, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "意图边查询失败: "+err.Error())
		return
	}
	// 案件审计段快照(ListAudit 既有口径:PG 面单次上限 1000 条——超出部分
	// 不随包,如实标注;全局链本体不动)。
	entries, err := s.deps.Audit.ListAudit(ctx, id, 0)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "审计段查询失败: "+err.Error())
		return
	}
	jobs, intents, err := s.deps.Meta.CaseInFlight(ctx, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "在跑账查询失败: "+err.Error())
		return
	}

	// 源行补任务账解析器实证(sealSource.ParserLabel 的由来,见类型注释)
	packed := make([]sealSource, 0, len(sources))
	for _, src := range sources {
		ps := sealSource{Source: src}
		if job, jerr := s.deps.Meta.LatestJob(ctx, src.ID); jerr == nil &&
			job != nil && job.Status == "done" {
			ps.ParserLabel = job.Parser
		}
		packed = append(packed, ps)
	}

	// vault 原件清单先定(唯一 sha256,排序定序)——manifest.counts 要先算后写
	hashes := []string{}
	seen := map[string]bool{}
	for _, src := range sources {
		if !seen[src.SHA256] {
			seen[src.SHA256] = true
			hashes = append(hashes, src.SHA256)
		}
	}
	sort.Strings(hashes)

	man := sealManifest{
		Format: sealFormat, FormatVersion: sealFormatVersion,
		AppVersion: s.deps.Version, Case: *c,
		ExportedAt: time.Now().UTC(), ExportedBy: s.actorOf(r),
		Counts: sealCounts{
			Sources: len(sources), Anchors: len(anchors), IntentNodes: len(nodes),
			IntentEdges: len(edges), AuditEntries: len(entries), VaultFiles: len(hashes),
		},
		InFlight: sealInFlight{Jobs: jobs, Intents: intents},
	}

	// 整包内存拼装:逐文件边写边算 sha256,SHA256SUMS 覆盖除自身外全部文件
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	sums := []string{}
	add := func(name string, r io.Reader) error {
		entry, err := zw.Create(name)
		if err != nil {
			return err
		}
		h := sha256.New()
		if _, err := io.Copy(io.MultiWriter(entry, h), r); err != nil {
			return err
		}
		sums = append(sums, hex.EncodeToString(h.Sum(nil))+"  "+name)
		return nil
	}
	addJSON := func(name string, v any) error {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			return err
		}
		return add(name, &b)
	}

	if err := addJSON("manifest.json", &man); err == nil {
		err = addJSON("case.json", c)
	}
	if err == nil {
		err = addJSON("sources.json", packed)
	}
	if err == nil {
		err = addJSON("anchors.json", anchors)
	}
	if err == nil {
		err = addJSON("intent.json", sealIntent{Nodes: nodes, Edges: edges})
	}
	if err == nil {
		err = addJSON("audit_snapshot.json", entries)
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "封存包元数据段拼装失败: "+err.Error())
		return
	}

	// vault 原件(只读,不动金库)
	for _, sum := range hashes {
		f, err := s.deps.Vault.OpenFile(sum) // 读前校验在 vault 内
		if err != nil {
			writeErr(w, http.StatusInternalServerError,
				fmt.Sprintf("金库原文读取失败(%s…),导出中止(证据链不可断,不出残包): %v",
					sum[:12], err))
			return
		}
		err = add("vault/"+sum, f)
		f.Close()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "金库原件打包失败: "+err.Error())
			return
		}
	}

	// SHA256SUMS 收尾(覆盖除自身外全部文件;清单自身不哈希自身)
	entry, err := zw.Create("SHA256SUMS")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "封存包收尾失败: "+err.Error())
		return
	}
	if _, err := io.WriteString(entry, strings.Join(sums, "\n")+"\n"); err != nil {
		writeErr(w, http.StatusInternalServerError, "封存包清单写入失败: "+err.Error())
		return
	}
	if err := zw.Close(); err != nil {
		writeErr(w, http.StatusInternalServerError, "封存包收尾失败: "+err.Error())
		return
	}

	zipSum := sha256.Sum256(buf.Bytes())
	filename := fmt.Sprintf("fengtu-case-%s-%s.zip", c.Name,
		man.ExportedAt.Format("20060102-150405"))
	_, _, _ = s.deps.Audit.AppendAudit(ctx, id, s.actorOf(r), "case.export", id,
		map[string]any{
			"name": c.Name, "zip_sha256": hex.EncodeToString(zipSum[:]),
			"filename": filename, "counts": man.Counts,
			"in_flight": man.InFlight,
			"note": "整包内存拼装(内网移交量级);含 vault 原件;" +
				"hits/裁决不随包;审计段为快照,导入侧不回插全局链",
		})

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", sealContentDisposition(filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", buf.Len()))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// sealContentDisposition RFC 5987 filename*(中文案件名百分号编码;
// 附 ASCII 兜底文件名给不认 filename* 的旧客户端)。
func sealContentDisposition(filename string) string {
	var b strings.Builder
	for i := 0; i < len(filename); i++ {
		c := filename[i]
		if c < 0x80 && strings.ContainsRune(
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$&+-.^_`|~",
			rune(c)) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return `attachment; filename="fengtu-case.zip"; filename*=UTF-8''` + b.String()
}

// ---- 导入 ----

// sealImportJob 异步摄入/重建的载荷(同步校验段已全过,zip 已不需再读)。
type sealImportJob struct {
	caseID, caseName string
	actor            string
	sourceCase       string // 源案名(审计 detail 留痕)
	sources          []sealSource
	anchors          []store.SealAnchor
	graph            sealIntent
	sealFiles        map[string][]byte // manifest.json/audit_snapshot.json 原文(落 seal/ 留档)
	manifestSHA256   string
}

// importCase POST /api/cases/import(multipart 字段 file;全角色,登录即可)。
// 同步段:收包 → 格式验 → SHA256SUMS 逐文件对账 → vault 原件内容=寻址名
// 对账并入库(幂等)→ 各 JSON 段解析 → 建新案恢复 profile;任一失败
// 如实报错 + 审计 case.import{ok:false},不落源不入库。重建段异步(任务流)。
func (s *Server) importCase(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actor := s.actorOf(r)
	fail := func(status int, stage, msg string) {
		_, _, _ = s.deps.Audit.AppendAudit(ctx, "", actor, "case.import", "",
			map[string]any{"ok": false, "stage": stage, "reason": msg})
		writeErr(w, status, msg)
	}

	// seal/ 留档依赖工作区根;未装配则导入无从留档,前置如实拒(落审计)
	if s.deps.DataDir == "" {
		fail(http.StatusServiceUnavailable, "seal_dir",
			"数据目录未装配(DataDir 空),审计快照无处留档,拒绝导入(见启动日志)")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, sealMaxBytes)
	// multipart 大文件由 net/http 自落临时文件(请求结束自清),内存只留
	// 32MB 表单窗口;zip 需 seek,直接用 multipart.File 的 ReaderAt 即可
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		fail(http.StatusBadRequest, "receive",
			"表单解析失败(超 4GB 上限或表单损坏): "+err.Error())
		return
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		fail(http.StatusBadRequest, "receive", "缺少 multipart 字段 file: "+err.Error())
		return
	}
	defer f.Close()
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		fail(http.StatusBadRequest, "receive", "包读取失败: "+err.Error())
		return
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		fail(http.StatusBadRequest, "receive", "包读取失败: "+err.Error())
		return
	}
	zr, err := zip.NewReader(f, size)
	if err != nil {
		fail(http.StatusBadRequest, "format", "非 zip 包: "+err.Error())
		return
	}

	// 1. manifest 格式验(先于哈希对账:格式不对的包没有资格谈清单)
	manifestRaw, err := readSealFile(zr, "manifest.json", sealJSONMax)
	if err != nil {
		fail(http.StatusBadRequest, "format",
			"非丰图案件封存包(缺 manifest.json): "+err.Error())
		return
	}
	var man sealManifest
	if err := json.Unmarshal(manifestRaw, &man); err != nil {
		fail(http.StatusBadRequest, "format", "manifest.json 解析失败: "+err.Error())
		return
	}
	if man.Format != sealFormat {
		fail(http.StatusBadRequest, "format",
			fmt.Sprintf("非丰图案件封存包(format=%q)", man.Format))
		return
	}
	if man.FormatVersion != sealFormatVersion {
		fail(http.StatusUnprocessableEntity, "format",
			fmt.Sprintf("封存包格式版本不支持(format_version=%d,本实例支持 %d)",
				man.FormatVersion, sealFormatVersion))
		return
	}

	// 2. SHA256SUMS 逐文件对账(双向:包内每个文件必在清单且哈希符,
	//    清单每条必在包内;清单自身除外)
	sumsRaw, err := readSealFile(zr, "SHA256SUMS", sealJSONMax)
	if err != nil {
		fail(http.StatusUnprocessableEntity, "checksum",
			"缺 SHA256SUMS,完整性无法对账,拒收: "+err.Error())
		return
	}
	sums, err := parseSealSums(string(sumsRaw))
	if err != nil {
		fail(http.StatusUnprocessableEntity, "checksum", "SHA256SUMS 解析失败: "+err.Error())
		return
	}
	contentHash := map[string]string{}
	for _, zf := range zr.File {
		if zf.Name == "SHA256SUMS" {
			continue
		}
		want, ok := sums[zf.Name]
		if !ok {
			fail(http.StatusUnprocessableEntity, "checksum",
				"清单外文件(完整性存疑,拒收): "+zf.Name)
			return
		}
		rc, err := zf.Open()
		if err != nil {
			fail(http.StatusUnprocessableEntity, "checksum",
				"包内文件读取失败: "+zf.Name+": "+err.Error())
			return
		}
		h := sha256.New()
		_, cpErr := io.Copy(h, rc)
		rc.Close()
		if cpErr != nil {
			fail(http.StatusUnprocessableEntity, "checksum",
				"包内文件读取失败: "+zf.Name+": "+cpErr.Error())
			return
		}
		got := hex.EncodeToString(h.Sum(nil))
		if got != want {
			fail(http.StatusUnprocessableEntity, "checksum",
				fmt.Sprintf("SHA256SUMS 对账不过(证据链不可断,拒收): %s 期望 %s,实算 %s",
					zf.Name, want[:12]+"…", got[:12]+"…"))
			return
		}
		contentHash[zf.Name] = got
	}
	for name := range sums {
		if _, ok := contentHash[name]; !ok {
			fail(http.StatusUnprocessableEntity, "checksum",
				"清单有而包内缺(完整性存疑,拒收): "+name)
			return
		}
	}

	// 3. vault 原件:内容实算必须等于寻址文件名(证据链寻址键),过 →
	//    入库(Vault.Put 自带写前校验,同哈希已在库幂等)
	vaultFiles := []string{}
	for name, got := range contentHash {
		if !strings.HasPrefix(name, "vault/") {
			continue
		}
		base := strings.TrimPrefix(name, "vault/")
		if base != got {
			fail(http.StatusUnprocessableEntity, "vault",
				fmt.Sprintf("金库原件内容与寻址哈希不符(%s,实算 %s…),拒收",
					name, got[:12]))
			return
		}
		vaultFiles = append(vaultFiles, name)
	}
	sort.Strings(vaultFiles)
	for _, name := range vaultFiles {
		base := strings.TrimPrefix(name, "vault/")
		zf := findSealFile(zr, name)
		rc, err := zf.Open()
		if err != nil {
			fail(http.StatusUnprocessableEntity, "vault",
				"金库原件读取失败: "+name+": "+err.Error())
			return
		}
		// 并发导入同一证据串行化(put exists→write→rename 窗口会撞)
		sealVaultMu.Lock()
		_, putErr := s.deps.Vault.Put(base, rc)
		sealVaultMu.Unlock()
		rc.Close()
		if putErr != nil {
			fail(http.StatusUnprocessableEntity, "vault",
				"金库入库失败(写前校验不过/IO),拒收: "+putErr.Error())
			return
		}
	}

	// 4. 各 JSON 段解析(此时未建案未落源;解析不过 422 全拒)
	caseRaw, err := readSealFile(zr, "case.json", sealJSONMax)
	if err != nil {
		fail(http.StatusUnprocessableEntity, "payload", "缺 case.json: "+err.Error())
		return
	}
	var caseMeta store.Case
	if err := json.Unmarshal(caseRaw, &caseMeta); err != nil {
		fail(http.StatusUnprocessableEntity, "payload", "case.json 解析失败: "+err.Error())
		return
	}
	if strings.TrimSpace(caseMeta.Name) == "" {
		fail(http.StatusUnprocessableEntity, "payload", "case.json 案件名为空,拒收")
		return
	}
	sourcesRaw, err := readSealFile(zr, "sources.json", sealJSONMax)
	if err != nil {
		fail(http.StatusUnprocessableEntity, "payload", "缺 sources.json: "+err.Error())
		return
	}
	sources := []sealSource{}
	if err := json.Unmarshal(sourcesRaw, &sources); err != nil {
		fail(http.StatusUnprocessableEntity, "payload", "sources.json 解析失败: "+err.Error())
		return
	}
	anchorsRaw, err := readSealFile(zr, "anchors.json", sealJSONMax)
	if err != nil {
		fail(http.StatusUnprocessableEntity, "payload", "缺 anchors.json: "+err.Error())
		return
	}
	anchors := []store.SealAnchor{}
	if err := json.Unmarshal(anchorsRaw, &anchors); err != nil {
		fail(http.StatusUnprocessableEntity, "payload", "anchors.json 解析失败: "+err.Error())
		return
	}
	intentRaw, err := readSealFile(zr, "intent.json", sealJSONMax)
	if err != nil {
		fail(http.StatusUnprocessableEntity, "payload", "缺 intent.json: "+err.Error())
		return
	}
	graph := sealIntent{Nodes: []*intent.Node{}, Edges: []*intent.Edge{}}
	if err := json.Unmarshal(intentRaw, &graph); err != nil {
		fail(http.StatusUnprocessableEntity, "payload", "intent.json 解析失败: "+err.Error())
		return
	}
	auditRaw, err := readSealFile(zr, "audit_snapshot.json", sealJSONMax)
	if err != nil {
		fail(http.StatusUnprocessableEntity, "payload",
			"缺 audit_snapshot.json: "+err.Error())
		return
	}

	// 5. 建新案(永远新案;名撞加「(导入)」后缀,并发安全在存储面)+ 恢复 profile
	caseID, finalName, err := s.deps.Meta.EnsureNewCase(ctx, caseMeta.Name)
	if err != nil {
		fail(http.StatusInternalServerError, "case", "案件登记失败: "+err.Error())
		return
	}
	if err := s.deps.Meta.SetCaseProfile(ctx, caseID, store.CaseProfile{
		IncidentType: caseMeta.IncidentType, Background: caseMeta.Background,
		GoalPresets: caseMeta.GoalPresets,
	}); err != nil {
		fail(http.StatusInternalServerError, "case", "案件元数据恢复失败: "+err.Error())
		return
	}

	// 6. 重建段异步(逐源摄入 → 锚点/意图重映射 → seal 留档 → 审计)
	manifestSum := sha256.Sum256(manifestRaw)
	job := sealImportJob{
		caseID: caseID, caseName: finalName, actor: actor,
		sourceCase: man.Case.Name, sources: sources, anchors: anchors, graph: graph,
		sealFiles: map[string][]byte{
			"manifest.json":       manifestRaw,
			"audit_snapshot.json": auditRaw,
		},
		manifestSHA256: hex.EncodeToString(manifestSum[:]),
	}
	task := s.tasks.New("import", caseID)
	go s.runSealImport(task.ID, job)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"case":    map[string]string{"id": caseID, "name": finalName},
		"sources": len(sources), "task_id": task.ID,
		"note": "逐源从 vault 原件重派生事件(解析器对 spec 写,重跑确定);" +
			"hits/裁决不随包,导入后请人工重扫描重裁决;" +
			"源案审计段不回插全局链,快照在本案工作区 seal/ 留档",
	})
}

// sealVaultMu 导入侧金库写入串行化(并发导入同一证据时 vault.Put 的
// exists→write→rename 窗口在 Windows 上会撞 rename;同一证据写一次即可)。
var sealVaultMu sync.Mutex

// runSealImport 重建段(异步任务):逐源摄入 → 判定账恢复 → 意图图/锚点
// 重映射 → seal/ 留档 → 审计 case.import。逐源失败不杀全案(如实分项,
// 与上传 zip 文件模式同口径);有失败则任务 failed + 审计 ok:false。
func (s *Server) runSealImport(taskID string, job sealImportJob) {
	ctx := context.Background() // 异步任务不随请求生命周期
	detail := map[string]any{"case_id": job.caseID, "source_case": job.sourceCase}

	// ---- 逐源摄入(vault 原件重派生) ----
	type sourceOutcome struct {
		Path  string `json:"path"`
		SHA256 string `json:"sha256"`
		Route string `json:"route"`           // evtx_native|<formatID>|raw
		Note  string `json:"note,omitempty"`  // 降级/如实说明
	}
	outcomes := []sourceOutcome{}
	failures := []map[string]string{}
	for i, src := range job.sources {
		s.tasks.Progress(taskID, fmt.Sprintf("源重派生中(%d/%d): %s",
			i+1, len(job.sources), src.Path))
		route, note, err := s.sealIngestOne(ctx, job.caseName, src)
		if err != nil {
			failures = append(failures, map[string]string{
				"path": src.Path, "sha256": src.SHA256, "err": err.Error()})
			continue
		}
		outcomes = append(outcomes, sourceOutcome{
			Path: src.Path, SHA256: src.SHA256, Route: route, Note: note})
	}
	detail["sources"] = outcomes
	detail["sources_failed"] = failures

	// ---- 源重映射键:旧 source_id →(sha256,path)→ 新 source_id ----
	newSources, err := s.deps.Meta.ListSources(ctx, job.caseID)
	if err != nil {
		s.sealImportFailed(ctx, taskID, job, detail, "源清单回读失败: "+err.Error())
		return
	}
	byKey := map[string]string{}   // sha256\x00path → 新 id
	bySHA := map[string][]string{} // sha256 → 新 id 集(唯一时兜底)
	for _, ns := range newSources {
		byKey[ns.SHA256+"\x00"+ns.Path] = ns.ID
		bySHA[ns.SHA256] = append(bySHA[ns.SHA256], ns.ID)
	}
	oldByID := map[string]sealSource{}
	for _, src := range job.sources {
		oldByID[src.ID] = src
	}
	resolveSource := func(oldID string) string {
		row, ok := oldByID[oldID]
		if !ok {
			return ""
		}
		if id, ok := byKey[row.SHA256+"\x00"+row.Path]; ok {
			return id
		}
		if ids := bySHA[row.SHA256]; len(ids) == 1 {
			return ids[0]
		}
		return ""
	}

	// ---- 判定账恢复(按原格式重解析成功的源,判定随案走) ----
	for _, oc := range outcomes {
		if oc.Route == "raw" || oc.Route == "evtx_native" {
			continue
		}
		var orig *sealSource
		for i := range job.sources {
			if job.sources[i].SHA256 == oc.SHA256 && job.sources[i].Path == oc.Path {
				orig = &job.sources[i]
				break
			}
		}
		if orig == nil || orig.DetectFormat == "" || orig.DetectFormat != oc.Route ||
			orig.DetectStatus == "" || orig.DetectStatus == "none" {
			continue // 上传绑定重派生的源与上传链同口径:不动判定账
		}
		newID := resolveSource(orig.ID)
		if newID == "" {
			continue
		}
		_ = s.deps.Meta.SetDetection(ctx, newID, store.Detection{
			Format: orig.DetectFormat, Confidence: orig.DetectConfidence,
			Status: orig.DetectStatus, LogType: orig.LogType,
		})
	}

	// ---- 意图图重建:新 UUID、case_id 换新、in-flight 一律 stopped、
	//      parent/边端点重映射;节点 evidence 锚点同步重映射(hit_id 置空) ----
	idMap := map[string]string{} // 旧节点 id → 新 id
	stoppedN, orphanN, evDropped := 0, 0, 0
	for _, n := range job.graph.Nodes {
		cp := *n
		cp.ID = ""
		cp.CaseID = job.caseID
		cp.SessionID = "" // AI 会话不随包
		if cp.Status == intent.StatusRunning ||
			cp.Status == intent.StatusAwaitingApproval {
			// 迁移不续跑:人看过证据后重新派发
			mig := "迁移封存:导出时状态 " + cp.Status + ",迁移不续跑,需人工重新派发"
			if cp.CloseNote == "" {
				cp.CloseNote = mig
			} else {
				cp.CloseNote += ";" + mig
			}
			cp.Status = intent.StatusStopped
			stoppedN++
		}
		if cp.ParentID != "" {
			if np, ok := idMap[cp.ParentID]; ok {
				cp.ParentID = np
			} else {
				cp.ParentID = "" // 父节点缺失(包内不全),如实断挂并计数
				orphanN++
			}
		}
		if len(cp.Evidence) > 0 {
			kept := make([]intent.Anchor, 0, len(cp.Evidence))
			for _, a := range cp.Evidence {
				a.HitID = "" // hits 不随包,锚点 hit 引用一律置空
				if a.SourceID != "" {
					ns := resolveSource(a.SourceID)
					if ns == "" {
						evDropped++ // 源未随包/摄入失败,锚点跳过
						continue
					}
					a.SourceID = ns
				}
				kept = append(kept, a)
			}
			cp.Evidence = kept
		}
		oldID := n.ID
		if err := s.deps.Meta.SealInsertNode(ctx, &cp); err != nil {
			s.sealImportFailed(ctx, taskID, job, detail,
				fmt.Sprintf("意图节点落库失败(旧 id %s): %v", oldID, err))
			return
		}
		idMap[oldID] = cp.ID
	}
	edgeOK, edgeSkip := 0, 0
	for _, e := range job.graph.Edges {
		from, ok1 := idMap[e.FromID]
		to, ok2 := idMap[e.ToID]
		if !ok1 || !ok2 {
			edgeSkip++ // 端点缺失,跳过计数
			continue
		}
		ne := &intent.Edge{CaseID: job.caseID, FromID: from, ToID: to, Kind: e.Kind}
		if err := s.deps.Meta.CreateEdge(ctx, ne); err != nil {
			s.sealImportFailed(ctx, taskID, job, detail,
				"意图边落库失败: "+err.Error())
			return
		}
		edgeOK++
	}

	// ---- 证据锚点重映射(源找不到跳过并计数;hit_id 一律置空) ----
	anchorOK, anchorSkip := 0, 0
	for _, a := range job.anchors {
		nodeID, ok := idMap[a.NodeID]
		if !ok {
			anchorSkip++
			continue
		}
		newSrc := ""
		if a.SourceID != "" {
			newSrc = resolveSource(a.SourceID)
			if newSrc == "" {
				anchorSkip++
				continue
			}
		}
		if err := s.deps.Meta.AddAnchors(ctx, job.caseID, nodeID, a.Kind,
			[]intent.Anchor{{SourceID: newSrc, LineNo: a.LineNo, Note: a.Note}}); err != nil {
			s.sealImportFailed(ctx, taskID, job, detail,
				"证据锚点落库失败: "+err.Error())
			return
		}
		anchorOK++
	}
	detail["intent_nodes"] = len(idMap)
	detail["intent_edges"] = edgeOK
	detail["intent_edges_skipped"] = edgeSkip
	detail["intent_stopped"] = stoppedN
	detail["intent_parent_orphaned"] = orphanN
	detail["node_evidence_dropped"] = evDropped
	detail["anchors"] = anchorOK
	detail["anchors_skipped"] = anchorSkip

	// ---- seal/ 留档(审计段快照 + manifest;不回插全局链) ----
	sealDir := filepath.Join(s.deps.DataDir, "workspace", job.caseID, "seal")
	if err := os.MkdirAll(sealDir, 0o755); err != nil {
		s.sealImportFailed(ctx, taskID, job, detail, "seal 留档目录创建失败: "+err.Error())
		return
	}
	for name, raw := range job.sealFiles {
		if err := os.WriteFile(filepath.Join(sealDir, name), raw, 0o644); err != nil {
			s.sealImportFailed(ctx, taskID, job, detail,
				"seal 留档写入失败("+name+"): "+err.Error())
			return
		}
	}
	detail["seal_dir"] = sealDir

	// ---- 审计(源哈希清单前 8 + manifest 哈希) ----
	shaList := make([]string, 0, len(outcomes))
	for _, oc := range outcomes {
		shaList = append(shaList, oc.SHA256)
	}
	if len(shaList) > 8 {
		shaList = shaList[:8]
	}
	ok := len(failures) == 0
	_, _, _ = s.deps.Audit.AppendAudit(ctx, job.caseID, job.actor, "case.import",
		job.caseID, map[string]any{
			"ok": ok, "source_case": job.sourceCase, "case_name": job.caseName,
			"sources": len(outcomes), "sources_failed": len(failures),
			"anchors": anchorOK, "anchors_skipped": anchorSkip,
			"intent_nodes": len(idMap), "intent_edges": edgeOK,
			"intent_stopped": stoppedN,
			"source_sha256_head": shaList, "manifest_sha256": job.manifestSHA256,
			"note": "审计段快照不回插全局哈希链(源实例全局序,回插必断链)," +
				"原件在本案工作区 seal/;hits/裁决不随包,需人工重扫描重裁决;" +
				"in-flight 意图已落 stopped(迁移不续跑)",
		})
	if !ok {
		s.tasks.Finish(taskID, "failed",
			fmt.Sprintf("%d 个源重派生失败(详见 detail.sources_failed)", len(failures)),
			detail)
		return
	}
	s.tasks.Finish(taskID, "done", "", detail)
}

// sealImportFailed 重建段致命失败:审计 ok:false + 任务 failed
// (已落库部分不装没发生,detail 如实分项)。
func (s *Server) sealImportFailed(ctx context.Context, taskID string,
	job sealImportJob, detail map[string]any, msg string) {

	_, _, _ = s.deps.Audit.AppendAudit(ctx, job.caseID, job.actor, "case.import",
		job.caseID, map[string]any{
			"ok": false, "source_case": job.sourceCase, "case_name": job.caseName,
			"reason": msg, "manifest_sha256": job.manifestSHA256,
			"note": "部分数据可能已落库(源/节点按序写入,无回滚),detail 如实分项",
		})
	s.tasks.Finish(taskID, "failed", msg, detail)
}

// sealIngestOne 单源重派生(复用摄入链文件级入口 ingest.IngestEVTXFile/
// IngestTextFile/RegisterRawFile——与上传链 ingestOne 同一条链,区别只在
// 路由依据:上传链按扩展名嗅探+上传绑定,本函数按导出实据,不重新指纹猜)。
// 路由:
//  1. kind=evtx → 原生解析(解析器对 spec 写,重跑结果确定);
//  2. detect_format(或任务账 parser_label 实证)解析出候选格式且源可判
//     → 按该格式重解析;
//  3. 其余(native 包解析源/无绑定文本/二进制)→ 如实登记 raw 不解析。
//
// 如实标注:源声明时区不在 sources 表(随上传请求存在),不随包——重派生
// 以空声明进行,与一键分析重解析通路同口径。
func (s *Server) sealIngestOne(ctx context.Context, caseName string,
	src sealSource) (route, note string, err error) {

	spec := ingest.Spec{
		CaseName: caseName, Path: s.deps.Vault.Path(src.SHA256),
		DisplayPath: src.Path, ArtifactType: src.ArtifactType,
		Host: src.Host, Package: src.Package,
	}

	if src.Kind == string(ingest.KindEVTX) {
		spec.Kind = ingest.KindEVTX
		spec.ParserLabel = "evtx_native:velocidex"
		spec.LogType = src.LogType // evtx 原生路由品类(空则由库内默认)
		if _, err := ingest.IngestEVTXFile(ctx, s.deps.Meta, s.deps.Events,
			spec, ingest.VelocidexParser{}); err != nil {
			return "", "", fmt.Errorf("evtx 重派生失败: %w", err)
		}
		return "evtx_native", "", nil
	}

	// 文本可判源:detect_format 优先,任务账 parser_label 实证兜底
	textLike := src.Kind == string(ingest.KindText) ||
		(src.Kind == string(ingest.KindRaw) &&
			ingest.DetectKind(src.Path) == ingest.KindText)
	formatID := src.DetectFormat
	if formatID == "" {
		formatID = src.ParserLabel
	}
	if textLike && formatID != "" && formatID != "raw" {
		if cand := fingerprint.FindCandidate(s.deps.Candidates, formatID); cand != nil {
			spec.Kind = ingest.KindText
			spec.ParserLabel = cand.FormatID
			spec.LogType = cand.LogType
			if _, err := ingest.IngestTextFile(ctx, s.deps.Meta, s.deps.Events,
				spec, cand.Encoding, ingest.ParseFunc(cand.Parse),
				cand.IsBlockStart); err != nil {
				return "", "", fmt.Errorf("按导出格式 %s 重派生失败: %w", formatID, err)
			}
			return cand.FormatID, "", nil
		}
		// 格式绑定在目标实例不可用:不静默猜,退化登记,人重分析
		spec.Kind = ingest.KindRaw
		spec.LogType = src.LogType
		if err := ingest.RegisterRawFile(ctx, s.deps.Meta, spec); err != nil {
			return "", "", fmt.Errorf("登记失败: %w", err)
		}
		return "raw", fmt.Sprintf(
			"导出格式绑定 %q 在本实例候选集不可用,已登记未解析(请人工重新分析)",
			formatID), nil
	}

	spec.Kind = ingest.KindRaw
	spec.LogType = src.LogType
	if err := ingest.RegisterRawFile(ctx, s.deps.Meta, spec); err != nil {
		return "", "", fmt.Errorf("登记失败: %w", err)
	}
	if src.Kind == string(ingest.KindNative) {
		return "raw", "原生包解析源(native)按文件无法重派生,已登记未解析" +
			"(请人工重新分析;原事件由采集包管线产出,不随包迁移)", nil
	}
	return "raw", "", nil
}

// ---- zip 读取小件 ----

// findSealFile 按名找 zip 成员(找不到 nil,调用方判)。
func findSealFile(zr *zip.Reader, name string) *zip.File {
	for _, zf := range zr.File {
		if zf.Name == name {
			return zf
		}
	}
	return nil
}

// readSealFile 读 zip 成员全文(限大小;找不到如实报错)。
func readSealFile(zr *zip.Reader, name string, max int64) ([]byte, error) {
	zf := findSealFile(zr, name)
	if zf == nil {
		return nil, fmt.Errorf("包内无此文件: %s", name)
	}
	rc, err := zf.Open()
	if err != nil {
		return nil, fmt.Errorf("包内文件打开失败(%s): %w", name, err)
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, max+1))
	if err != nil {
		return nil, fmt.Errorf("包内文件读取失败(%s): %w", name, err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("包内文件超上限(%s > %d 字节)", name, max)
	}
	return b, nil
}

// parseSealSums SHA256SUMS 解析("<64hex>  <path>" 每行一条;
// 哈希小写十六进制校验,路径去 sha256sum 文本/二进制模式标记)。
func parseSealSums(body string) (map[string]string, error) {
	out := map[string]string{}
	for ln, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		if len(line) < 66 || line[64] != ' ' {
			return nil, fmt.Errorf("第 %d 行形态非法(应 `<sha256>  <path>`)", ln+1)
		}
		sum := line[:64]
		if _, err := hex.DecodeString(sum); err != nil {
			return nil, fmt.Errorf("第 %d 行哈希非十六进制", ln+1)
		}
		path := strings.TrimLeft(line[65:], " *")
		if path == "" {
			return nil, fmt.Errorf("第 %d 行路径为空", ln+1)
		}
		if _, dup := out[path]; dup {
			return nil, fmt.Errorf("第 %d 行路径重复: %s", ln+1, path)
		}
		out[path] = sum
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("清单为空")
	}
	return out, nil
}
