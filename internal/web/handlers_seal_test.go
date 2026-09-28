// 案件封存/迁移(0.27.0,M4)契约测试:导出→导入往返 + 负样本(篡改拒收)
// + 名撞后缀 + 并发两导入互不串。全 fake/httptest,不碰真库不碰真 AI。
//
// 焊死的纪律:
//   - 证据链不可断:SHA256SUMS 逐文件对账 + vault 内容=寻址名,篡改一律
//     422 且不落源不建案;
//   - 审计段不回插:源案审计条目绝不出现在目标实例 audit_chain;
//   - 迁移不续跑:running/awaiting_approval 意图导入落 stopped;
//   - hits 不随包:锚点 hit_id 导入一律置空。
package web

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ye-mengwen/fengtu/internal/ingest/store"
	"github.com/ye-mengwen/fengtu/internal/intent"
)

// exportSeal 导出案件,返回 zip 字节与响应头(200 是前置断言)。
func (e *testEnv) exportSeal(t *testing.T, caseID string) ([]byte, http.Header) {
	t.Helper()
	req, err := http.NewRequest("GET", e.ts.URL+"/api/cases/"+caseID+"/export", nil)
	if err != nil {
		t.Fatalf("请求构造失败: %v", err)
	}
	req.Header.Set("Cookie", sessionCookie+"="+e.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("导出请求失败: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("导出响应读取失败: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("导出应 200: %d %s", resp.StatusCode, body)
	}
	return body, resp.Header
}

// importSeal 导入封存包(multipart file 字段),返回状态码与 JSON 应答。
func (e *testEnv) importSeal(t *testing.T, zipBytes []byte) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "fengtu-case.zip")
	if err != nil {
		t.Fatalf("表单构造失败: %v", err)
	}
	if _, err := fw.Write(zipBytes); err != nil {
		t.Fatalf("表单写入失败: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("表单收尾失败: %v", err)
	}
	req, err := http.NewRequest("POST", e.ts.URL+"/api/cases/import", &buf)
	if err != nil {
		t.Fatalf("请求构造失败: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Cookie", sessionCookie+"="+e.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("导入请求失败: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("导入应答解析失败(%d): %v", resp.StatusCode, err)
	}
	return resp.StatusCode, out
}

// rezip 解开重打包(mutate 增改文件内容;顺序保持,SHA256SUMS 不重算——
// 篡改负样本正靠这点)。
func rezip(t *testing.T, zipBytes []byte,
	mutate func(files map[string][]byte)) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("zip 解开失败: %v", err)
	}
	files := map[string][]byte{}
	order := []string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("zip 成员打开失败: %v", err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("zip 成员读取失败: %v", err)
		}
		files[f.Name] = b
		order = append(order, f.Name)
	}
	mutate(files)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	written := map[string]bool{}
	for _, name := range order {
		w, _ := zw.Create(name)
		w.Write(files[name])
		written[name] = true
	}
	for name, b := range files { // mutate 新增的成员
		if written[name] {
			continue
		}
		w, _ := zw.Create(name)
		w.Write(b)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip 重打包失败: %v", err)
	}
	return buf.Bytes()
}

// verifySealZip 包内对账:SHA256SUMS 逐文件符 + vault 内容=寻址名。
func verifySealZip(t *testing.T, zipBytes []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("zip 解开失败: %v", err)
	}
	sumsRaw := map[string][]byte{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		sumsRaw[f.Name] = b
	}
	sums, err := parseSealSums(string(sumsRaw["SHA256SUMS"]))
	if err != nil {
		t.Fatalf("SHA256SUMS 解析失败: %v", err)
	}
	for name, b := range sumsRaw {
		if name == "SHA256SUMS" {
			continue
		}
		sum := sha256.Sum256(b)
		got := hex.EncodeToString(sum[:])
		if sums[name] != got {
			t.Fatalf("包内对账不过: %s", name)
		}
		if strings.HasPrefix(name, "vault/") &&
			strings.TrimPrefix(name, "vault/") != got {
			t.Fatalf("vault 寻址名≠内容哈希: %s", name)
		}
		delete(sums, name)
	}
	if len(sums) != 0 {
		t.Fatalf("清单有而包内缺: %v", sums)
	}
	out := map[string]string{}
	for name, b := range sumsRaw {
		sum := sha256.Sum256(b)
		out[name] = hex.EncodeToString(sum[:])
	}
	return out
}

// sealCaseID 按名找案件 id(fake 直查)。
func sealCaseID(t *testing.T, m *fakeMeta, name string) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.cases[name]
	if !ok {
		t.Fatalf("无此案件: %s(实有 %v)", name, m.cases)
	}
	return id
}

// sealSourceCaseFixture 造一个待导出案件:nginx 解析源 + 二进制 raw 源 +
// 应急元数据 + 意图图(goal/intent running/intent awaiting/fact)+ 锚点 +
// 案件审计段一条。返回案件 id 与两源内容哈希。
func sealSourceCaseFixture(t *testing.T, e *testEnv) (caseID, logSHA, binSHA string) {
	t.Helper()
	ctx := context.Background()

	taskID := e.uploadFileTZ(t, "case-seal", "access.log",
		[]byte(nginxContent), "nginx_combined", "+0000")
	if task := e.waitTask(t, taskID); task["status"] != "done" {
		t.Fatalf("日志摄入应 done: %v", task)
	}
	binContent := []byte("BINARY\x00\x01\x02 证据杂件")
	taskID = e.uploadFile(t, "case-seal", "evidence.bin", binContent, "")
	if task := e.waitTask(t, taskID); task["status"] != "done" {
		t.Fatalf("杂件摄入应 done: %v", task)
	}
	caseID = sealCaseID(t, e.meta, "case-seal")
	logSHA = shaOf([]byte(nginxContent))
	binSHA = shaOf(binContent)

	// 应急元数据(随 case.json 恢复面)
	if err := e.meta.SetCaseProfile(ctx, caseID, store.CaseProfile{
		IncidentType: "intrusion", Background: "封存往返测试背景",
		GoalPresets: []string{"查清入侵路径"},
	}); err != nil {
		t.Fatalf("案件元数据写入失败: %v", err)
	}

	// 意图图:goal(open) → n1(running,在跑) → fact(supported,带证据);
	//        goal → n2(awaiting_approval,待批)
	sources, err := e.meta.ListSources(ctx, caseID)
	if err != nil || len(sources) != 2 {
		t.Fatalf("源清单不符: %v %v", sources, err)
	}
	var logSrcID string
	for _, s := range sources {
		if s.SHA256 == logSHA {
			logSrcID = s.ID
		}
	}
	if logSrcID == "" {
		t.Fatal("日志源未登记")
	}
	goal := &intent.Node{CaseID: caseID, Kind: intent.KindGoal,
		Text: "查清入侵路径", Status: intent.StatusOpen, CreatedBy: intent.ByHuman,
		Scope: intent.ScopeCase}
	if err := e.meta.SealInsertNode(ctx, goal); err != nil {
		t.Fatal(err)
	}
	n1 := &intent.Node{CaseID: caseID, Kind: intent.KindIntent,
		Text: "盘点 Web 访问异常", Status: intent.StatusRunning,
		CreatedBy: intent.ByHuman, Scope: intent.ScopeCase,
		ParentID: goal.ID, Depth: 1}
	if err := e.meta.SealInsertNode(ctx, n1); err != nil {
		t.Fatal(err)
	}
	n2 := &intent.Node{CaseID: caseID, Kind: intent.KindIntent,
		Text: "全源批扫webshell", Status: intent.StatusAwaitingApproval,
		CreatedBy: intent.ByAI, Scope: intent.ScopeAll,
		ParentID: goal.ID, Depth: 1}
	if err := e.meta.SealInsertNode(ctx, n2); err != nil {
		t.Fatal(err)
	}
	fact := &intent.Node{CaseID: caseID, Kind: intent.KindFact,
		Text: "发现 sqlmap 扫描特征", Status: intent.StatusSupported,
		CreatedBy: intent.ByAI, Scope: intent.ScopeCase,
		ParentID: n1.ID, Depth: 2,
		Evidence: []intent.Anchor{{SourceID: logSrcID, LineNo: 2,
			HitID: "hit-old-1", Note: "ua 含 sqlmap"}}}
	if err := e.meta.SealInsertNode(ctx, fact); err != nil {
		t.Fatal(err)
	}
	for _, e2 := range [][3]string{
		{goal.ID, n1.ID, intent.EdgeSpawns},
		{goal.ID, n2.ID, intent.EdgeSpawns},
		{n1.ID, fact.ID, intent.EdgeYields},
	} {
		if err := e.meta.CreateEdge(ctx, &intent.Edge{
			CaseID: caseID, FromID: e2[0], ToID: e2[1], Kind: e2[2]}); err != nil {
			t.Fatal(err)
		}
	}
	// 证据锚点(带 hit 引用——导入应置空)
	if err := e.meta.AddAnchors(ctx, caseID, n1.ID, "evidence",
		[]intent.Anchor{{SourceID: logSrcID, LineNo: 2, HitID: "hit-old-1",
			Note: "回查锚"}}); err != nil {
		t.Fatal(err)
	}
	// 案件审计段一条(快照随包走;导入侧绝不应在链上见到它)
	if _, _, err := e.audit.AppendAudit(ctx, caseID, "admin", "case.note",
		caseID, map[string]any{"text": "源实例专属审计条目"}); err != nil {
		t.Fatal(err)
	}
	return caseID, logSHA, binSHA
}

// TestSealRoundTrip 导出→导入往返(跨实例:两个独立 fake 环境)。
func TestSealRoundTrip(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	ctx := context.Background()
	caseID, logSHA, binSHA := sealSourceCaseFixture(t, e)

	// ---- 导出 ----
	zipBytes, hdr := e.exportSeal(t, caseID)
	if ct := hdr.Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("Content-Type 不符: %s", ct)
	}
	if cd := hdr.Get("Content-Disposition"); !strings.Contains(cd,
		"filename*=UTF-8''") {
		t.Fatalf("Content-Disposition 缺 filename*: %s", cd)
	}
	hashes := verifySealZip(t, zipBytes)
	for _, name := range []string{"manifest.json", "case.json", "sources.json",
		"anchors.json", "intent.json", "audit_snapshot.json",
		"vault/" + logSHA, "vault/" + binSHA} {
		if hashes[name] == "" {
			t.Fatalf("封存包缺文件: %s", name)
		}
	}
	// manifest 计数账
	zr, _ := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	manRaw, _ := readSealFile(zr, "manifest.json", sealJSONMax)
	var man sealManifest
	if err := json.Unmarshal(manRaw, &man); err != nil {
		t.Fatalf("manifest 解析失败: %v", err)
	}
	if man.Format != sealFormat || man.FormatVersion != sealFormatVersion {
		t.Fatalf("manifest 格式头不符: %+v", man)
	}
	if man.Counts.Sources != 2 || man.Counts.Anchors != 1 ||
		man.Counts.IntentNodes != 4 || man.Counts.IntentEdges != 3 ||
		man.Counts.AuditEntries != 1 || man.Counts.VaultFiles != 2 {
		t.Fatalf("manifest 计数不符: %+v", man.Counts)
	}
	if man.ExportedBy != "admin" {
		t.Fatalf("导出人应锚 admin: %+v", man.ExportedBy)
	}
	// 导出审计:case.export 带整包 sha256
	zipSum := sha256.Sum256(zipBytes)
	exportAudited := false
	for _, en := range e.audit.entries {
		if en.Action != "case.export" || en.CaseID != caseID {
			continue
		}
		var d map[string]any
		_ = json.Unmarshal([]byte(en.DetailJSON), &d)
		if d["zip_sha256"] == hex.EncodeToString(zipSum[:]) {
			exportAudited = true
		}
	}
	if !exportAudited {
		t.Fatal("审计缺 case.export(或 zip 哈希不符)")
	}

	// ---- 导入(新实例;DataDir 装配,否则 seal 留档无处落) ----
	e2 := newTestEnv(t)
	e2.login(t)
	e2.srv.deps.DataDir = t.TempDir()
	code, out := e2.importSeal(t, zipBytes)
	if code != http.StatusAccepted {
		t.Fatalf("导入应 202: %d %v", code, out)
	}
	newCase := out["case"].(map[string]any)
	newCaseID := newCase["id"].(string)
	if newCase["name"] != "case-seal" {
		t.Fatalf("空库导入不应加后缀: %v", newCase)
	}
	if int(out["sources"].(float64)) != 2 {
		t.Fatalf("导入源数不符: %v", out)
	}
	task := e2.waitTask(t, out["task_id"].(string))
	if task["status"] != "done" {
		t.Fatalf("导入任务应 done: %v", task)
	}

	// 源:计数一致、sha256 一致、vault 可取、事件从原件重派生
	sources2, err := e2.meta.ListSources(ctx, newCaseID)
	if err != nil || len(sources2) != 2 {
		t.Fatalf("导入源清单不符: %v %v", sources2, err)
	}
	var newLogSrc store.Source
	shaSet := map[string]bool{}
	for _, s := range sources2 {
		shaSet[s.SHA256] = true
		if s.SHA256 == logSHA {
			newLogSrc = s
		}
	}
	if !shaSet[logSHA] || !shaSet[binSHA] {
		t.Fatalf("导入源 sha256 集不符: %v", shaSet)
	}
	if newLogSrc.Kind != "text" {
		t.Fatalf("日志源应按导出绑定重解析为 text: %+v", newLogSrc)
	}
	vf, err := e2.srv.deps.Vault.OpenFile(logSHA)
	if err != nil {
		t.Fatalf("导入侧金库取原文失败: %v", err)
	}
	got, _ := io.ReadAll(vf)
	vf.Close()
	if string(got) != nginxContent {
		t.Fatal("金库原文内容不符")
	}
	// 事件重派生(3 行 nginx;fakeCH 按 source_id 归账)
	evN := 0
	e2.ch.mu.Lock()
	for _, r := range e2.ch.rows {
		if r.SourceID == newLogSrc.ID {
			evN++
		}
	}
	e2.ch.mu.Unlock()
	if evN != 3 {
		t.Fatalf("日志源应重派生 3 条事件: %d", evN)
	}
	// 案件 profile 恢复
	nc, _ := e2.meta.GetCase(ctx, newCaseID)
	if nc.IncidentType != "intrusion" || nc.Background != "封存往返测试背景" ||
		len(nc.GoalPresets) != 1 || nc.GoalPresets[0] != "查清入侵路径" {
		t.Fatalf("案件元数据未恢复: %+v", nc)
	}

	// 意图图:计数一致;in-flight 两节点 stopped;parent/边端点已重映射
	nodes2, _ := e2.meta.ListNodes(ctx, newCaseID)
	if len(nodes2) != 4 {
		t.Fatalf("意图节点计数不符: %d", len(nodes2))
	}
	byKind2 := map[string]*intent.Node{}
	stoppedN := 0
	newIDs := map[string]bool{}
	for _, n := range nodes2 {
		newIDs[n.ID] = true
		byKind2[n.Kind+":"+n.Text] = n
		if n.Status == intent.StatusStopped {
			stoppedN++
			if !strings.Contains(n.CloseNote, "迁移不续跑") {
				t.Fatalf("stopped 节点缺迁移说明: %+v", n)
			}
		}
	}
	if stoppedN != 2 {
		t.Fatalf("running/awaiting_approval 应落 2 条 stopped: %d", stoppedN)
	}
	goal2 := byKind2[intent.KindGoal+":查清入侵路径"]
	fact2 := byKind2[intent.KindFact+":发现 sqlmap 扫描特征"]
	if goal2 == nil || fact2 == nil {
		t.Fatalf("意图节点缺失: %v", byKind2)
	}
	if goal2.Status != intent.StatusOpen || fact2.Status != intent.StatusSupported {
		t.Fatalf("非在跑节点状态应原样: goal=%s fact=%s",
			goal2.Status, fact2.Status)
	}
	if fact2.ParentID == "" || !newIDs[fact2.ParentID] {
		t.Fatalf("parent 未重映射到新 id 域: %+v", fact2)
	}
	if len(fact2.Evidence) != 1 ||
		fact2.Evidence[0].SourceID != newLogSrc.ID ||
		fact2.Evidence[0].HitID != "" {
		t.Fatalf("节点 evidence 锚点重映射不符(hit_id 应置空): %+v", fact2.Evidence)
	}
	edges2, _ := e2.meta.ListEdges(ctx, newCaseID)
	if len(edges2) != 3 {
		t.Fatalf("意图边计数不符: %d", len(edges2))
	}
	for _, ed := range edges2 {
		if !newIDs[ed.FromID] || !newIDs[ed.ToID] {
			t.Fatalf("边端点未重映射: %+v", ed)
		}
	}

	// 锚点:重映射到新源,hit_id 置空
	anchors2, _ := e2.meta.ListSealAnchors(ctx, newCaseID)
	if len(anchors2) != 1 {
		t.Fatalf("锚点计数不符: %v", anchors2)
	}
	a0 := anchors2[0]
	if a0.SourceID != newLogSrc.ID || a0.HitID != "" || a0.LineNo != 2 ||
		a0.Kind != "evidence" {
		t.Fatalf("锚点重映射不符: %+v", a0)
	}

	// 审计:新增 case.import{ok:true};源案审计段绝未回插
	importAudited := false
	for _, en := range e2.audit.entries {
		if en.Action == "case.note" {
			t.Fatal("源案审计段被回插进目标链(证据链纪律破坏)")
		}
		if en.Action == "case.import" && en.CaseID == newCaseID {
			var d map[string]any
			_ = json.Unmarshal([]byte(en.DetailJSON), &d)
			if d["ok"] == true {
				importAudited = true
			}
		}
	}
	if !importAudited {
		t.Fatal("审计缺 case.import{ok:true}")
	}
	// 审计链完整(导入后全局链重算应过)
	code, out = e2.do(t, "GET", "/api/audit/verify", nil)
	if code != http.StatusOK || out["ok"] != true {
		t.Fatalf("导入后审计链应完整: %d %v", code, out)
	}

	// seal 留档:manifest + 审计快照原文落工作区(不回插,但可查)
	sealDir := filepath.Join(e2.srv.deps.DataDir, "workspace", newCaseID, "seal")
	for _, name := range []string{"manifest.json", "audit_snapshot.json"} {
		if _, err := os.Stat(filepath.Join(sealDir, name)); err != nil {
			t.Fatalf("seal 留档缺文件 %s: %v", name, err)
		}
	}
	snap, _ := os.ReadFile(filepath.Join(sealDir, "audit_snapshot.json"))
	if !strings.Contains(string(snap), "case.note") {
		t.Fatal("审计快照应含源案审计段原文")
	}
}

// TestSealImportTamperedVaultFile 篡改 vault 原件一字节 → 422 拒收,
// 不落源不建案(证据链纪律),拒收进审计。
func TestSealImportTamperedVaultFile(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	caseID, logSHA, _ := sealSourceCaseFixture(t, e)
	zipBytes, _ := e.exportSeal(t, caseID)

	bad := rezip(t, zipBytes, func(files map[string][]byte) {
		b := files["vault/"+logSHA]
		b[0] ^= 0xFF // 翻一字节,清单不动
		files["vault/"+logSHA] = b
	})

	e2 := newTestEnv(t)
	e2.login(t)
	e2.srv.deps.DataDir = t.TempDir()
	code, out := e2.importSeal(t, bad)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("篡改应 422: %d %v", code, out)
	}
	assertImportRejected(t, e2)
}

// TestSealImportTamperedSums 篡改 SHA256SUMS → 422 拒收。
func TestSealImportTamperedSums(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	caseID, logSHA, _ := sealSourceCaseFixture(t, e)
	zipBytes, _ := e.exportSeal(t, caseID)

	bad := rezip(t, zipBytes, func(files map[string][]byte) {
		body := string(files["SHA256SUMS"])
		// 把日志源条目的哈希首位换掉(清单失配;换成的字符保证与原不同)
		i := strings.Index(body, logSHA[:8])
		if i < 0 {
			t.Fatal("清单缺日志源条目")
		}
		repl := byte('f')
		if body[i] == 'f' {
			repl = '0'
		}
		files["SHA256SUMS"] = []byte(body[:i] + string(repl) + body[i+1:])
	})

	e2 := newTestEnv(t)
	e2.login(t)
	e2.srv.deps.DataDir = t.TempDir()
	code, out := e2.importSeal(t, bad)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("清单篡改应 422: %d %v", code, out)
	}
	assertImportRejected(t, e2)
}

// TestSealImportNotSeal 非封存 zip(无 manifest)→ 400。
func TestSealImportNotSeal(t *testing.T) {
	e2 := newTestEnv(t)
	e2.login(t)
	e2.srv.deps.DataDir = t.TempDir()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("hello.txt")
	w.Write([]byte("not a seal"))
	zw.Close()
	code, _ := e2.importSeal(t, buf.Bytes())
	if code != http.StatusBadRequest {
		t.Fatalf("非封存包应 400: %d", code)
	}
	assertImportRejected(t, e2)
}

// TestSealImportBadVersion format_version 不符 → 422。
func TestSealImportBadVersion(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	caseID, _, _ := sealSourceCaseFixture(t, e)
	zipBytes, _ := e.exportSeal(t, caseID)

	bad := rezip(t, zipBytes, func(files map[string][]byte) {
		files["manifest.json"] = bytes.Replace(files["manifest.json"],
			[]byte(`"format_version": 1`), []byte(`"format_version": 99`), 1)
	})

	e2 := newTestEnv(t)
	e2.login(t)
	e2.srv.deps.DataDir = t.TempDir()
	code, out := e2.importSeal(t, bad)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("版本不符应 422: %d %v", code, out)
	}
	assertImportRejected(t, e2)
}

// TestSealImportNoDataDir DataDir 未装配 → 503 如实拒(不留档不导入)。
func TestSealImportNoDataDir(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	caseID, _, _ := sealSourceCaseFixture(t, e)
	zipBytes, _ := e.exportSeal(t, caseID)

	e2 := newTestEnv(t) // newTestEnv 不装配 DataDir
	e2.login(t)
	code, _ := e2.importSeal(t, zipBytes)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("DataDir 未装配应 503: %d", code)
	}
	assertImportRejected(t, e2)
}

// assertImportRejected 拒收公共断言:零案件零源 + case.import{ok:false} 落审计。
func assertImportRejected(t *testing.T, e2 *testEnv) {
	t.Helper()
	cases, _ := e2.meta.ListCases(context.Background())
	if len(cases) != 0 {
		t.Fatalf("拒收后不得建案: %v", cases)
	}
	if len(e2.meta.sources) != 0 {
		t.Fatalf("拒收后不得落源: %v", e2.meta.sources)
	}
	found := false
	for _, en := range e2.audit.entries {
		if en.Action != "case.import" {
			continue
		}
		var d map[string]any
		_ = json.Unmarshal([]byte(en.DetailJSON), &d)
		if d["ok"] == false {
			found = true
		}
	}
	if !found {
		t.Fatal("拒收应进审计(case.import{ok:false})")
	}
}

// TestSealImportNameCollision 名撞后缀:同名包连导三次 →
// 「case-seal」「case-seal(导入)」「case-seal(导入2)」,各案源独立。
func TestSealImportNameCollision(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	caseID, _, _ := sealSourceCaseFixture(t, e)
	zipBytes, _ := e.exportSeal(t, caseID)

	e2 := newTestEnv(t)
	e2.login(t)
	e2.srv.deps.DataDir = t.TempDir()
	wantNames := []string{"case-seal", "case-seal(导入)", "case-seal(导入2)"}
	for i, want := range wantNames {
		code, out := e2.importSeal(t, zipBytes)
		if code != http.StatusAccepted {
			t.Fatalf("第 %d 次导入应 202: %d %v", i+1, code, out)
		}
		got := out["case"].(map[string]any)["name"].(string)
		if got != want {
			t.Fatalf("第 %d 次导入案件名应 %q: %q", i+1, want, got)
		}
		task := e2.waitTask(t, out["task_id"].(string))
		if task["status"] != "done" {
			t.Fatalf("第 %d 次导入任务应 done: %v", i+1, task)
		}
		sources, _ := e2.meta.ListSources(context.Background(),
			out["case"].(map[string]any)["id"].(string))
		if len(sources) != 2 {
			t.Fatalf("第 %d 次导入案源应独立成 2: %v", i+1, sources)
		}
	}
}

// TestSealImportConcurrent 并发两导入互不串:两个不同案件、源各自归账、
// vault 同哈希幂等不撞。
func TestSealImportConcurrent(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	caseID, _, _ := sealSourceCaseFixture(t, e)
	zipBytes, _ := e.exportSeal(t, caseID)

	e2 := newTestEnv(t)
	e2.login(t)
	e2.srv.deps.DataDir = t.TempDir()

	type result struct {
		code int
		out  map[string]any
	}
	res := make([]result, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			code, out := e2.importSeal(t, zipBytes)
			res[i] = result{code, out}
		}(i)
	}
	wg.Wait()
	ids := map[string]bool{}
	names := map[string]bool{}
	for i, r := range res {
		if r.code != http.StatusAccepted {
			t.Fatalf("并发导入 %d 应 202: %d %v", i, r.code, r.out)
		}
		c := r.out["case"].(map[string]any)
		ids[c["id"].(string)] = true
		names[c["name"].(string)] = true
		task := e2.waitTask(t, r.out["task_id"].(string))
		if task["status"] != "done" {
			t.Fatalf("并发导入 %d 任务应 done: %v", i, task)
		}
		sources, _ := e2.meta.ListSources(context.Background(), c["id"].(string))
		if len(sources) != 2 {
			t.Fatalf("并发导入 %d 案源串账: %v", i, sources)
		}
	}
	if len(ids) != 2 || len(names) != 2 {
		t.Fatalf("并发导入应落两个不同案件: ids=%v names=%v", ids, names)
	}
}
