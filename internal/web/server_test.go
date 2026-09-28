// API 契约测试:用户最小可用闭环全链(httptest)。
package web

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ye-mengwen/fengtu/internal/auth"
	"github.com/ye-mengwen/fengtu/internal/fingerprint"
	"github.com/ye-mengwen/fengtu/internal/ingest"
	"github.com/ye-mengwen/fengtu/internal/ingress"
	"github.com/ye-mengwen/fengtu/internal/kb"
	"github.com/ye-mengwen/fengtu/internal/operator"
	"github.com/ye-mengwen/fengtu/internal/query"
	"github.com/ye-mengwen/fengtu/internal/review"
	"github.com/ye-mengwen/fengtu/internal/vault"
)

const nginxContent = `10.0.0.1 - - [01/Aug/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 612 "-" "Mozilla/5.0"
10.0.0.2 - - [01/Aug/2026:10:00:02 +0000] "GET /admin.php?id=1 HTTP/1.1" 200 123 "-" "sqlmap/1.7.8"
10.0.0.3 - - [01/Aug/2026:10:00:03 +0000] "POST /login HTTP/1.1" 403 55 "-" "Nikto/2.1.6"
`

const scannerUARule = `
id: scanner-ua
title: 扫描器 User-Agent 特征
severity: medium
target: any
match:
  ua: ["sqlmap", "nikto"]
note: 公开工具指纹,命中≠结论
`

type testEnv struct {
	srv    *Server
	ts     *httptest.Server
	meta   *fakeMeta
	ch     *fakeCH
	audit  *fakeAudit
	review *fakeReviewStore
	cookie string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	tmp := t.TempDir()
	v, err := vault.Open(filepath.Join(tmp, "vault"))
	if err != nil {
		t.Fatalf("金库打开失败: %v", err)
	}
	up, err := ingress.OpenManager(filepath.Join(tmp, "uploads"), 8) // 8 字节块,逼出多块路径
	if err != nil {
		t.Fatalf("上传管理器打开失败: %v", err)
	}
	ch := newFakeCH()
	meta := newFakeMeta()
	au := &fakeAudit{}
	rs := newFakeReviewStore()
	rs.meta = meta
	rule, err := review.CompileRule("scanner-ua.yaml", scannerUARule)
	if err != nil {
		t.Fatalf("规则编译失败: %v", err)
	}
	engine, err := review.NewEngine([]*review.Rule{rule},
		query.NewService(ch), rs)
	if err != nil {
		t.Fatalf("引擎构造失败: %v", err)
	}
	// 指纹候选(内置 nginx)+ 算子注册表(低阈爆破链,合成样本可触发)
	descDir := filepath.Join(tmp, "desc")
	if err := os.MkdirAll(descDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cands, err := fingerprint.LoadCandidates(descDir)
	if err != nil {
		t.Fatalf("指纹候选装载失败: %v", err)
	}
	opsDir := filepath.Join(tmp, "operators")
	if err := os.MkdirAll(opsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	opYAML := `
id: web-bruteforce-chain
title: Web 爆破链(失败×N → 窗口内成功)
family: web
severity: high
applicable_to:
  log_types: [web_access]
params:
  fail_threshold: 2
  window_seconds: 600
  window_lines: 50
  fail_status: ["401", "403"]
  success_status: ["200"]
implemented: true
note: 测试算子
max_hits: 500
`
	if err := os.WriteFile(filepath.Join(opsDir, "web-bruteforce-chain.yaml"),
		[]byte(opYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	ops, err := operator.LoadDir(opsDir)
	if err != nil {
		t.Fatalf("算子注册表装载失败: %v", err)
	}
	engine.SetOperators(ops)
	mapYAML := `
name: test-map
package_root_regex: '^Forensic_\d+\.\d+\.\d+\.\d+_.+$'
rules:
  - match: "\\.evtx$"
    artifact: evtx
    route: evtx_native
`
	am, err := ingest.LoadArtifactMap(mapYAML)
	if err != nil {
		t.Fatalf("映射表装载失败: %v", err)
	}
	// 启发式知识库(0.19.0):两条内置夹具 + 内存用户条目账(真实 kb.Service
	// 合并逻辑进契约,不另起 fake 面)。
	kbDir := filepath.Join(tmp, "kb")
	if err := os.MkdirAll(kbDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"t-one.yaml": "id: t-one\ntitle: 测试内置一\napplies_to: [execution]\ncontent: 找一\n",
		"t-two.yaml": "id: t-two\ntitle: 测试内置二\napplies_to: [timeline]\ncontent: 找二\n",
	} {
		if err := os.WriteFile(filepath.Join(kbDir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	kbBuiltin, err := kb.LoadBuiltinDir(kbDir)
	if err != nil {
		t.Fatalf("知识库内置夹具装载失败: %v", err)
	}
	kbSvc := kb.NewService(kbBuiltin, newFakeKBStore())
	srv := NewServer(Deps{
		Auth:        auth.NewService(newFakeAuthStore(), 0),
		Meta:        meta,
		Audit:       au,
		Vault:       v,
		Ingress:     up,
		Query:       query.NewService(ch),
		Stats:       ch, // 时间线聚合面(fakeCH 同实现)
		Review:      engine,
		Events:      ch,
		EventsAdmin: ch, // 重解析通路(fakeCH 同实现)
		ArtifactMap: am,
		DescDir:     descDir,
		StagingDir:  filepath.Join(tmp, "staging"),
		Candidates:  cands,
		Operators:   ops,
		KB:          kbSvc,
		Version:     "test",
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &testEnv{srv: srv, ts: ts, meta: meta, ch: ch, audit: au, review: rs}
}

// do 发请求(自动带会话 cookie)。
func (e *testEnv) do(t *testing.T, method, path string, body any,
	headers ...string) (int, map[string]any) {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, e.ts.URL+path, rdr)
	if err != nil {
		t.Fatalf("请求构造失败: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if e.cookie != "" {
		req.Header.Set("Cookie", sessionCookie+"="+e.cookie)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("响应 JSON 解析失败(%d %s %s): %v",
				resp.StatusCode, method, path, err)
		}
	}
	if method == "POST" && path == "/api/auth/login" && resp.StatusCode == 200 {
		for _, c := range resp.Cookies() {
			if c.Name == sessionCookie {
				e.cookie = c.Value
			}
		}
	}
	return resp.StatusCode, out
}

func (e *testEnv) login(t *testing.T) {
	t.Helper()
	code, out := e.do(t, "POST", "/api/auth/setup",
		map[string]string{"username": "admin", "password": "password123"})
	if code != http.StatusCreated {
		t.Fatalf("首启失败: %d %v", code, out)
	}
	code, out = e.do(t, "POST", "/api/auth/login",
		map[string]string{"username": "admin", "password": "password123"})
	if code != http.StatusOK {
		t.Fatalf("登录失败: %d %v", code, out)
	}
	if e.cookie == "" {
		t.Fatal("登录未发会话 cookie")
	}
}

// uploadFile 分块上传(乱序 + 逐块校验)并完成。
func (e *testEnv) uploadFile(t *testing.T, caseName, filename string,
	content []byte, format string) string {
	t.Helper()
	return e.uploadFileTZ(t, caseName, filename, content, format, "")
}

func (e *testEnv) uploadFileTZ(t *testing.T, caseName, filename string,
	content []byte, format, tz string) string {
	t.Helper()
	sum := sha256.Sum256(content)
	sha := hex.EncodeToString(sum[:])
	code, out := e.do(t, "POST", "/api/uploads", map[string]any{
		"case_name": caseName, "filename": filename,
		"size": len(content), "sha256": sha, "format": format, "tz": tz,
	})
	if code != http.StatusCreated {
		t.Fatalf("上传 init 失败: %d %v", code, out)
	}
	uploadID := out["upload_id"].(string)
	chunkSize := int(out["chunk_size"].(float64))
	if chunkSize != 8 {
		t.Fatalf("分块大小应为 8(测试注入): %d", chunkSize)
	}
	total := (len(content) + chunkSize - 1) / chunkSize
	// 乱序传块(倒序),首块带逐块校验
	for i := total - 1; i >= 0; i-- {
		end := (i + 1) * chunkSize
		if end > len(content) {
			end = len(content)
		}
		chunk := content[i*chunkSize : end]
		var hdrs []string
		if i == 0 {
			cs := sha256.Sum256(chunk)
			hdrs = []string{"X-Chunk-SHA256", hex.EncodeToString(cs[:])}
		}
		req, _ := http.NewRequest("PUT",
			fmt.Sprintf("%s/api/uploads/%s/chunks/%d", e.ts.URL, uploadID, i),
			bytes.NewReader(chunk))
		req.Header.Set("Cookie", sessionCookie+"="+e.cookie)
		for j := 0; j+1 < len(hdrs); j += 2 {
			req.Header.Set(hdrs[j], hdrs[j+1])
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("分块上传失败: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("分块 %d 被拒: %d", i, resp.StatusCode)
		}
	}
	// 续传账
	code, out = e.do(t, "GET", "/api/uploads/"+uploadID, nil)
	if code != http.StatusOK {
		t.Fatalf("续传账查询失败: %d %v", code, out)
	}
	if len(out["received"].([]any)) != total {
		t.Fatalf("续传账已收不符: %v", out["received"])
	}
	// 完成
	code, out = e.do(t, "POST", "/api/uploads/"+uploadID+"/complete", nil)
	if code != http.StatusAccepted {
		t.Fatalf("上传完成被拒: %d %v", code, out)
	}
	return out["task_id"].(string)
}

// waitTask 轮询任务到终态。
func (e *testEnv) waitTask(t *testing.T, id string) map[string]any {
	t.Helper()
	for i := 0; i < 200; i++ {
		code, out := e.do(t, "GET", "/api/tasks/"+id, nil)
		if code != http.StatusOK {
			t.Fatalf("任务查询失败: %d %v", code, out)
		}
		if out["status"] != "running" {
			return out
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("任务超时未终态")
	return nil
}

func shaOf(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// TestClosedLoop 用户最小可用闭环:
// 首启 → 登录 → 上传(分块/乱序/逐块校验) → 摄入 → 检索 → 回查 →
// 扫描 → 待审 → 裁决 → 审计链。
func TestClosedLoop(t *testing.T) {
	e := newTestEnv(t)

	// 0. 登录闸:健康检查公开,业务端点未登录 401
	if code, _ := e.do(t, "GET", "/api/health", nil); code != http.StatusOK {
		t.Fatalf("健康检查应公开: %d", code)
	}
	if code, _ := e.do(t, "GET", "/api/cases", nil); code != http.StatusUnauthorized {
		t.Fatalf("未登录应 401: %d", code)
	}

	// 1. 首启 + 登录
	e.login(t)
	// auth/me 契约:user 字段名小写(前端 App.tsx 取 d.user.username;
	// 大写序列化曾致登录态全站白屏,焊死防回归)
	code, meOut := e.do(t, "GET", "/api/auth/me", nil)
	if code != http.StatusOK {
		t.Fatalf("auth/me 应 200: %d", code)
	}
	meUser, ok := meOut["user"].(map[string]any)
	if !ok || meUser["username"] != "admin" {
		t.Fatalf("auth/me user.username 契约破坏: %v", meOut)
	}
	if _, has := meUser["Username"]; has {
		t.Fatalf("auth/me 出现大写字段(序列化契约破坏): %v", meOut)
	}
	// 二次首启 403
	if code, _ := e.do(t, "POST", "/api/auth/setup",
		map[string]string{"username": "bob", "password": "password123"}); code != http.StatusForbidden {
		t.Fatalf("二次首启应 403: %d", code)
	}

	// 2. 上传 nginx 日志(3 行,含 sqlmap/Nikto UA;声明源时区 +0000 →
	//    ts 归一参与时间窗;不声明则 ts 如实为 null 不参与,见包注释)
	content := []byte(nginxContent)
	taskID := e.uploadFileTZ(t, "case-web", "access.log", content,
		"nginx_combined", "+0000")
	task := e.waitTask(t, taskID)
	if task["status"] != "done" {
		t.Fatalf("摄入任务应 done: %v", task)
	}

	// 3. 案件/源登记 + 证据链锚点
	code, out := e.do(t, "GET", "/api/cases", nil)
	if code != http.StatusOK || len(out["cases"].([]any)) != 1 {
		t.Fatalf("案件清单不符: %d %v", code, out)
	}
	caseID := out["cases"].([]any)[0].(map[string]any)["id"].(string)
	code, out = e.do(t, "GET", "/api/cases/"+caseID, nil)
	if code != http.StatusOK {
		t.Fatalf("案件详情失败: %d %v", code, out)
	}
	sources := out["sources"].([]any)
	if len(sources) != 1 {
		t.Fatalf("应登记 1 个源: %v", sources)
	}
	src := sources[0].(map[string]any)
	if src["sha256"] != shaOf(content) {
		t.Fatalf("源 sha256 锚点不符: %v", src["sha256"])
	}
	if src["path"] != "access.log" {
		t.Fatalf("源登记路径应留客户端原文件名: %v", src["path"])
	}
	sourceID := src["id"].(string)

	// 4. 检索:全文词
	code, out = e.do(t, "GET", "/api/query?case_id="+caseID+"&q=sqlmap", nil)
	if code != http.StatusOK {
		t.Fatalf("检索失败: %d %v", code, out)
	}
	events := out["events"].([]any)
	if len(events) != 1 {
		t.Fatalf("全文检索应命中 1 行: %v", events)
	}
	ev := events[0].(map[string]any)
	if ev["source_id"] != sourceID || int(ev["line_no"].(float64)) != 2 {
		t.Fatalf("行号锚点不符: %v", ev)
	}
	// 字段条件(contains)
	code, out = e.do(t, "GET",
		"/api/query?case_id="+caseID+"&cond=ua:contains:nikto", nil)
	if code != http.StatusOK || len(out["events"].([]any)) != 1 {
		t.Fatalf("字段条件检索应命中 1 行: %d %v", code, out)
	}
	// 字段条件(eq,不命中)
	code, out = e.do(t, "GET",
		"/api/query?case_id="+caseID+"&cond=status:eq:500", nil)
	if code != http.StatusOK || len(out["events"].([]any)) != 0 {
		t.Fatalf("status=500 应零命中: %d %v", code, out)
	}
	// 时间窗(覆盖事件时刻 → 命中;窗口外 → 零命中;无时区源不参与)
	code, out = e.do(t, "GET", "/api/query?case_id="+caseID+
		"&ts_from=2026-08-01T00:00:00Z&ts_to=2026-08-02T00:00:00Z", nil)
	if code != http.StatusOK || len(out["events"].([]any)) != 3 {
		t.Fatalf("时间窗内应 3 行: %d %v", code, out)
	}
	code, out = e.do(t, "GET", "/api/query?case_id="+caseID+
		"&ts_from=2026-08-02T00:00:00Z&ts_to=2026-08-03T00:00:00Z", nil)
	if code != http.StatusOK || len(out["events"].([]any)) != 0 {
		t.Fatalf("时间窗外应零命中: %d %v", code, out)
	}

	// 5. 行号锚点回查(金库按 sha256 定位)
	code, out = e.do(t, "GET",
		fmt.Sprintf("/api/sources/%s/lines?from=2&to=3", sourceID), nil)
	if code != http.StatusOK {
		t.Fatalf("原文回查失败: %d %v", code, out)
	}
	lines := out["lines"].([]any)
	if len(lines) != 2 ||
		!strings.Contains(lines[0].(map[string]any)["text"].(string), "sqlmap") {
		t.Fatalf("回查原文不符: %v", lines)
	}

	// 6. 规则 + 扫描(轮次 1)
	code, out = e.do(t, "GET", "/api/rules", nil)
	if code != http.StatusOK || len(out["rules"].([]any)) != 1 {
		t.Fatalf("规则清单不符: %d %v", code, out)
	}
	code, out = e.do(t, "POST", "/api/cases/"+caseID+"/scans",
		map[string]any{})
	if code != http.StatusAccepted {
		t.Fatalf("扫描启动失败: %d %v", code, out)
	}
	scanTask := e.waitTask(t, out["task_id"].(string))
	if scanTask["status"] != "done" {
		t.Fatalf("扫描任务应 done: %v", scanTask)
	}
	detail := scanTask["detail"].(map[string]any)
	if int(detail["round_no"].(float64)) != 1 {
		t.Fatalf("首轮应为 1: %v", detail)
	}
	rules := detail["rules"].([]any)
	hitsNew := int(rules[0].(map[string]any)["hits_new"].(float64))
	if hitsNew != 2 {
		t.Fatalf("应命中 2 条候选(sqlmap+Nikto): %v", rules[0])
	}

	// 7. 待审区:全 pending,文案「命中≠结论」
	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/hits?status=pending", nil)
	if code != http.StatusOK {
		t.Fatalf("待审查询失败: %d %v", code, out)
	}
	hits := out["hits"].([]any)
	if len(hits) != 2 {
		t.Fatalf("待审区应 2 条 pending: %v", hits)
	}
	hit := hits[0].(map[string]any)
	if !strings.Contains(hit["detail_json"].(string), "命中≠结论") {
		t.Fatalf("候选 detail 缺判断权文案: %v", hit)
	}
	if hit["matched_field"] != "ua" || hit["source_id"] != sourceID {
		t.Fatalf("候选锚点不符: %v", hit)
	}
	hitID := hit["id"].(string)

	// 8. 裁决(留审计)
	code, out = e.do(t, "POST", "/api/hits/"+hitID+"/verdict",
		map[string]string{"status": "accepted", "note": "实锤扫描"})
	if code != http.StatusOK {
		t.Fatalf("裁决失败: %d %v", code, out)
	}
	v := out["hit"].(map[string]any)
	if v["status"] != "accepted" || v["reviewed_by"] != "admin" {
		t.Fatalf("裁决账不符: %v", v)
	}
	// 非法裁决
	if code, _ := e.do(t, "POST", "/api/hits/"+hitID+"/verdict",
		map[string]string{"status": "pending"}); code != http.StatusBadRequest {
		t.Fatalf("裁决回 pending 应 400: %d", code)
	}
	if code, _ := e.do(t, "POST", "/api/hits/no-such/verdict",
		map[string]string{"status": "accepted"}); code != http.StatusNotFound {
		t.Fatalf("无此候选应 404: %d", code)
	}

	// 9. 审计链:动作齐 + 哈希链完整
	code, out = e.do(t, "GET", "/api/audit/chain", nil)
	if code != http.StatusOK {
		t.Fatalf("审计查询失败: %d %v", code, out)
	}
	entries := out["entries"].([]any)
	actions := map[string]bool{}
	for _, en := range entries {
		actions[en.(map[string]any)["Action"].(string)] = true
	}
	for _, want := range []string{"auth.setup", "auth.login", "upload.completed",
		"scan.run", "hit.verdict"} {
		if !actions[want] {
			t.Fatalf("审计缺动作 %s: 实有 %v", want, actions)
		}
	}
	code, out = e.do(t, "GET", "/api/audit/verify", nil)
	if code != http.StatusOK || out["ok"] != true {
		t.Fatalf("审计链应完整: %d %v", code, out)
	}

	// 10. SSE:终态任务立即给终态帧
	req, _ := http.NewRequest("GET", e.ts.URL+"/api/tasks/"+taskID+"/events", nil)
	req.Header.Set("Cookie", sessionCookie+"="+e.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("SSE 连接失败: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	frame := string(buf[:n])
	if !strings.HasPrefix(frame, "data: ") || !strings.Contains(frame, `"done"`) {
		t.Fatalf("SSE 首帧应为终态快照: %q", frame)
	}
}

// TestUploadSHA256MismatchRejected 客户端申报 sha256 与内容不符 → 拒收。
func TestUploadSHA256MismatchRejected(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	content := []byte("real content here")
	code, out := e.do(t, "POST", "/api/uploads", map[string]any{
		"case_name": "case-x", "filename": "a.log",
		"size": len(content), "sha256": strings.Repeat("ab", 32), // 假申报
		"format": "nginx_combined",
	})
	if code != http.StatusCreated {
		t.Fatalf("init 失败: %d %v", code, out)
	}
	uploadID := out["upload_id"].(string)
	total := (len(content) + 7) / 8
	for i := 0; i < total; i++ {
		end := (i + 1) * 8
		if end > len(content) {
			end = len(content)
		}
		req, _ := http.NewRequest("PUT",
			fmt.Sprintf("%s/api/uploads/%s/chunks/%d", e.ts.URL, uploadID, i),
			bytes.NewReader(content[i*8:end]))
		req.Header.Set("Cookie", sessionCookie+"="+e.cookie)
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
	}
	code, out = e.do(t, "POST", "/api/uploads/"+uploadID+"/complete", nil)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("哈希对账不过应 422: %d %v", code, out)
	}
	// 拒收进审计
	found := false
	for _, en := range e.audit.entries {
		if en.Action == "upload.rejected" {
			found = true
		}
	}
	if !found {
		t.Fatal("拒收应进审计(upload.rejected)")
	}
	// 无登记
	cases, _ := e.meta.ListCases(context.Background())
	if len(cases) != 0 {
		t.Fatal("拒收后不得有案件登记")
	}
}

// TestZipUploadMultiSource zip 单层展开登记多源(语义同索图)。
func TestZipUploadMultiSource(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w1, _ := zw.Create("access.log")
	w1.Write([]byte(nginxContent))
	w2, _ := zw.Create("extra.log")
	w2.Write([]byte(nginxContent))
	w3, _ := zw.Create("nested.zip")
	w3.Write([]byte("PK fake"))
	zw.Close()
	zipBytes := buf.Bytes()

	taskID := e.uploadFile(t, "case-zip", "logs.zip", zipBytes, "nginx_combined")
	task := e.waitTask(t, taskID)
	if task["status"] != "done" {
		t.Fatalf("zip 摄入应 done: %v", task)
	}
	detail := task["detail"].(map[string]any)
	if len(detail["sources"].([]any)) != 2 {
		t.Fatalf("应展 2 个源: %v", detail["sources"])
	}
	if len(detail["skipped"].([]any)) != 1 {
		t.Fatalf("嵌套 zip 应跳过如实记: %v", detail["skipped"])
	}
	// 两源都登记,路径留 zip 内名
	var caseID string
	for name, id := range e.meta.cases {
		if name == "case-zip" {
			caseID = id
		}
	}
	sources, _ := e.meta.ListSources(context.Background(), caseID)
	if len(sources) != 2 {
		t.Fatalf("应登记 2 源: %v", sources)
	}
	// 检索跨源命中(sqlmap 在两个成员里各一次)
	e.do(t, "POST", "/api/auth/login",
		map[string]string{"username": "admin", "password": "password123"})
	code, out := e.do(t, "GET", "/api/query?case_id="+caseID+"&q=sqlmap", nil)
	if code != http.StatusOK || len(out["events"].([]any)) != 2 {
		t.Fatalf("zip 多源检索应命中 2 行: %d %v", code, out)
	}
}

// TestChunkSHA256Mismatch 逐块校验不过拒收。
func TestChunkSHA256Mismatch(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	content := []byte("0123456789abcdef")
	code, out := e.do(t, "POST", "/api/uploads", map[string]any{
		"case_name": "c", "filename": "a.log", "size": len(content),
		"sha256": shaOf(content), "format": "nginx_combined",
	})
	if code != http.StatusCreated {
		t.Fatalf("init 失败: %d %v", code, out)
	}
	uploadID := out["upload_id"].(string)
	req, _ := http.NewRequest("PUT",
		e.ts.URL+"/api/uploads/"+uploadID+"/chunks/0",
		bytes.NewReader(content[:8]))
	req.Header.Set("Cookie", sessionCookie+"="+e.cookie)
	req.Header.Set("X-Chunk-SHA256", strings.Repeat("cd", 32))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("逐块校验不过应 400: %d", resp.StatusCode)
	}
}

// TestPackageUploadManifest 包模式清单对账:失配拒收,匹配则走包摄入。
// (合成包:不写真案件数据,结构特征即可)
func TestPackageManifestContract(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	root := "Forensic_10.9.9.9_SYNTH"

	buildPkg := func(tamper bool) []byte {
		fileA := []byte("a-content")
		manifest := fmt.Sprintf(
			"WinInfoSC Forensic Collection - SHA256 Manifest\n"+
				"Host=SYNTH IP=10.9.9.9 Generated=2026/01/01 00:00:00\n"+
				"================================================\n"+
				"%s  C:\\c\\%s\\a.txt\n",
			shaOf(fileA), root)
		if tamper {
			manifest += fmt.Sprintf("%s  C:\\c\\%s\\ghost.txt\n", shaOf([]byte("x")), root)
		}
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		w, _ := zw.Create(root + "/_HASH_MANIFEST.txt")
		w.Write([]byte(manifest))
		w2, _ := zw.Create(root + "/a.txt")
		w2.Write(fileA)
		zw.Close()
		return buf.Bytes()
	}

	// 失配 → 拒收(manifest missing)
	bad := buildPkg(true)
	taskID := e.uploadFile(t, "case-pkg-bad", "pkg.zip", bad, "")
	task := e.waitTask(t, taskID)
	if task["status"] != "failed" {
		t.Fatalf("清单失配应拒收(failed): %v", task)
	}
	if !strings.Contains(task["err"].(string), "清单契约失配") &&
		!strings.Contains(task["err"].(string), "契约失配") {
		t.Fatalf("拒收原因不符: %v", task["err"])
	}
	// 匹配 → done(无 evtx/无映射命中,a.txt 走 raw 兜底)
	good := buildPkg(false)
	taskID = e.uploadFile(t, "case-pkg-good", "pkg.zip", good, "")
	task = e.waitTask(t, taskID)
	if task["status"] != "done" {
		t.Fatalf("清单匹配应摄入成功: %v", task)
	}
	detail := task["detail"].(map[string]any)
	if detail["mode"] != "package" {
		t.Fatalf("应为包模式: %v", detail)
	}
	manifest := detail["manifest"].(map[string]any)
	if manifest["present"] != true {
		t.Fatalf("应有清单对账: %v", manifest)
	}
}

// TestIngestViaTempDir 临时目录清理(防测试残留影响其他用例)。
func TestIngestViaTempDir(t *testing.T) {
	_ = os.MkdirTemp
}
