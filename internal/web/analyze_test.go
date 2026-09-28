// 一键分析主链路 API 契约测试(httptest 全链):
// 上传(不绑格式) → analyze(指纹自动解析+扫描,SSE 任务流) → 判定可见
// 可改(改判端点+后验绊线) → 幂等重跑 → 内容树/翻页/规则统计/算子清单。
package web

import (
	"archive/zip"
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// 爆破链样本(测试算子 fail_threshold=2):同 IP 401×2 → 200;另带 sqlmap
// UA 命中签名规则。全部文档段 IP,无案件值。
const analyzeNginx = `203.0.113.10 - - [01/Aug/2026:10:00:01 +0000] "GET /login HTTP/1.1" 401 55 "-" "Mozilla/5.0"
203.0.113.10 - - [01/Aug/2026:10:00:02 +0000] "POST /login HTTP/1.1" 401 55 "-" "Mozilla/5.0"
203.0.113.10 - - [01/Aug/2026:10:00:03 +0000] "GET /admin HTTP/1.1" 200 612 "-" "Mozilla/5.0"
198.51.100.2 - - [01/Aug/2026:10:00:04 +0000] "GET /x?id=1 HTTP/1.1" 200 123 "-" "sqlmap/1.7.8"
`

func analyzeCase(t *testing.T, e *testEnv, caseID string) map[string]any {
	t.Helper()
	code, out := e.do(t, "POST", "/api/cases/"+caseID+"/analyze", nil)
	if code != http.StatusAccepted {
		t.Fatalf("analyze 应 202: %d %v", code, out)
	}
	task := e.waitTask(t, out["task_id"].(string))
	if task["status"] != "done" {
		t.Fatalf("analyze 任务应 done: %v err=%v", task["status"], task["err"])
	}
	return task["detail"].(map[string]any)
}

// num JSON 数字取值(omitempty 下 0 值键缺省 = 0)。
func num(m map[string]any, key string) float64 {
	v, _ := m[key].(float64)
	return v
}

func TestAnalyzeMainChain(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)

	// 上传文本日志不绑格式(registered_unparsed:如实登记不解析)
	tid := e.uploadFile(t, "analyze-case", "access.log", []byte(analyzeNginx), "")
	task := e.waitTask(t, tid)
	if task["status"] != "done" {
		t.Fatalf("上传摄入任务失败: %v", task["err"])
	}

	// 找案件 id
	code, out := e.do(t, "GET", "/api/cases", nil)
	if code != http.StatusOK || len(out["cases"].([]any)) != 1 {
		t.Fatalf("案件清单: %d %v", code, out)
	}
	caseID := out["cases"].([]any)[0].(map[string]any)["id"].(string)

	// ---- 一键分析:指纹 → 自动解析 → 全量扫描 ----
	detail := analyzeCase(t, e, caseID)
	fp := detail["fingerprint"].(map[string]any)
	if num(fp, "parsed_auto") != 1 {
		t.Fatalf("1 源应自动解析: %v", fp)
	}
	src0 := detail["sources"].([]any)[0].(map[string]any)
	if src0["action"] != "parsed_auto" {
		t.Fatalf("源动作: %v", src0)
	}
	if src0["confidence"].(float64) < 0.9 {
		t.Fatalf("前验置信度: %v", src0["confidence"])
	}
	if num(src0, "events") != 4 || num(src0, "bad") != 0 {
		t.Fatalf("解析账: %v", src0)
	}
	if _, ok := detail["scan"].(map[string]any); !ok {
		t.Fatalf("扫描账缺失: %v", detail)
	}

	// 判定与置信度在源信息里可见
	code, out = e.do(t, "GET", "/api/cases/"+caseID, nil)
	if code != http.StatusOK {
		t.Fatalf("案件查询: %d", code)
	}
	src := out["sources"].([]any)[0].(map[string]any)
	if src["detect_status"] != "auto" ||
		src["detect_format"] != "builtin:nginx_combined" ||
		src["log_type"] != "web_access" {
		t.Fatalf("判定可见: %+v", src)
	}
	if src["detect_confidence"].(float64) < 0.9 {
		t.Fatalf("置信度可见: %+v", src["detect_confidence"])
	}
	srcID := src["id"].(string)

	// 命中进待审:签名规则(疑似)+ 爆破链算子(强疑似,适用域路由)
	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/hits", nil)
	if code != http.StatusOK {
		t.Fatalf("待审查询: %d", code)
	}
	grades := map[string]string{}
	anchors := map[string]float64{}
	for _, h := range out["hits"].([]any) {
		hm := h.(map[string]any)
		grades[hm["rule_id"].(string)] = hm["evidence_grade"].(string)
		anchors[hm["rule_id"].(string)] = num(hm, "line_no")
	}
	if grades["scanner-ua"] != "suspect" {
		t.Fatalf("签名族默认疑似档: %v", grades)
	}
	if grades["web-bruteforce-chain"] != "strong" || anchors["web-bruteforce-chain"] != 3 {
		t.Fatalf("爆破链应强疑似锚 L3: %v %v", grades, anchors)
	}

	// ---- 幂等:二次 analyze 已解析源跳过,重扫 hits_new=0 ----
	detail2 := analyzeCase(t, e, caseID)
	src2 := detail2["sources"].([]any)[0].(map[string]any)
	if src2["action"] != "skip_parsed" {
		t.Fatalf("已解析源应跳过(幂等): %v", src2)
	}
	scan2 := detail2["scan"].(map[string]any)
	if num(scan2, "round_no") != 2 {
		t.Fatalf("轮次应递增到 2: %v", scan2["round_no"])
	}
	for _, rs := range scan2["rules"].([]any) {
		if num(rs.(map[string]any), "hits_new") != 0 {
			t.Fatalf("重扫去重幂等: %v", rs)
		}
	}

	// ---- 内容树 + 按源翻页浏览 ----
	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/artifact-tree", nil)
	if code != http.StatusOK {
		t.Fatalf("内容树: %d", code)
	}
	tree := out["tree"].([]any)
	if len(tree) != 1 {
		t.Fatalf("树应 1 叶子: %v", tree)
	}
	leaf := tree[0].(map[string]any)
	if leaf["type"] != "source" || leaf["status"] != "已解析" ||
		num(leaf, "lines") != 4 || leaf["log_type"] != "web_access" {
		t.Fatalf("叶子账: %+v", leaf)
	}
	code, out = e.do(t, "GET",
		fmt.Sprintf("/api/sources/%s/lines?page=1&size=3", srcID), nil)
	if code != http.StatusOK || len(out["lines"].([]any)) != 3 {
		t.Fatalf("翻页 P1: %d %v", code, out)
	}
	code, out = e.do(t, "GET",
		fmt.Sprintf("/api/sources/%s/lines?page=2&size=3", srcID), nil)
	if code != http.StatusOK || len(out["lines"].([]any)) != 1 {
		t.Fatalf("翻页 P2 应剩 1 行: %d %v", code, out)
	}

	// ---- 规则统计:裁决后接受率落地 ----
	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/hits?status=pending", nil)
	if code != http.StatusOK {
		t.Fatal(code)
	}
	var hitID string
	for _, h := range out["hits"].([]any) {
		hm := h.(map[string]any)
		if hm["rule_id"] == "scanner-ua" {
			hitID = hm["id"].(string)
		}
	}
	code, _ = e.do(t, "POST", "/api/hits/"+hitID+"/verdict",
		map[string]string{"status": "accepted", "note": "实锤扫描"})
	if code != http.StatusOK {
		t.Fatalf("裁决: %d", code)
	}
	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/rules/stats", nil)
	if code != http.StatusOK || num(out, "window_days") != 90 {
		t.Fatalf("规则统计: %d %v", code, out)
	}
	stats := map[string]map[string]any{}
	for _, st := range out["stats"].([]any) {
		sm := st.(map[string]any)
		stats[sm["rule_id"].(string)] = sm
	}
	sua := stats["scanner-ua"]
	if sua == nil || num(sua, "candidates") != 1 ||
		num(sua, "accepted") != 1 || num(sua, "acceptance_rate") != 1 {
		t.Fatalf("scanner-ua 统计: %+v", sua)
	}
	if _, ok := stats["web-bruteforce-chain"]; !ok {
		t.Fatal("算子也应在统计清单")
	}

	// ---- 算子清单(含未实现如实标) ----
	code, out = e.do(t, "GET", "/api/operators", nil)
	if code != http.StatusOK || len(out["operators"].([]any)) == 0 {
		t.Fatalf("算子清单: %d %v", code, out)
	}
}

// TestAnalyzePendingConfirmAndOverride 低置信挂待确认(不阻塞)→ 改判端点
// → 改判解析 → 后验绊线(全量失败率 >5%)→ 判定降级存疑。
func TestAnalyzePendingConfirmAndOverride(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)

	garbage := strings.Repeat("这不是任何已知日志格式的一行\n", 30)
	tid := e.uploadFile(t, "pending-case", "mystery.log", []byte(garbage), "")
	e.waitTask(t, tid)

	code, out := e.do(t, "GET", "/api/cases", nil)
	if code != http.StatusOK {
		t.Fatal(code)
	}
	caseID := out["cases"].([]any)[0].(map[string]any)["id"].(string)

	// 垃圾文本指纹 <0.9 → 待确认,不阻塞(任务照样 done)
	detail := analyzeCase(t, e, caseID)
	fp := detail["fingerprint"].(map[string]any)
	if num(fp, "pending_confirm") != 1 {
		t.Fatalf("应 1 源待确认: %v", fp)
	}
	code, out = e.do(t, "GET", "/api/cases/"+caseID, nil)
	if code != http.StatusOK {
		t.Fatal(code)
	}
	src := out["sources"].([]any)[0].(map[string]any)
	if src["detect_status"] != "pending_confirm" {
		t.Fatalf("待确认状态: %+v", src)
	}
	srcID := src["id"].(string)

	// 改判端点:非法格式 400(带可选清单)
	code, out = e.do(t, "POST", "/api/sources/"+srcID+"/detect",
		map[string]string{"format": "desc:not-exist"})
	if code != http.StatusBadRequest ||
		!strings.Contains(out["error"].(string), "builtin:nginx_combined") {
		t.Fatalf("非法格式应 400 带候选清单: %d %v", code, out)
	}

	// 改判为 nginx → 立即异步解析 → 全量皆坏行,后验绊线触发存疑
	code, out = e.do(t, "POST", "/api/sources/"+srcID+"/detect",
		map[string]string{"format": "builtin:nginx_combined"})
	if code != http.StatusAccepted {
		t.Fatalf("改判应 202: %d %v", code, out)
	}
	ptask := e.waitTask(t, out["task_id"].(string))
	if ptask["status"] != "done" {
		t.Fatalf("改判解析任务: %v err=%v", ptask["status"], ptask["err"])
	}
	pd := ptask["detail"].(map[string]any)
	if pd["suspect"] != true || num(pd, "bad_rate") <= 0.05 {
		t.Fatalf("后验绊线应触发(全量坏行): %+v", pd)
	}
	code, out = e.do(t, "GET", "/api/cases/"+caseID, nil)
	if code != http.StatusOK {
		t.Fatal(code)
	}
	src = out["sources"].([]any)[0].(map[string]any)
	if src["detect_status"] != "suspect" {
		t.Fatalf("判定应降级存疑: %+v", src)
	}
}

// TestArtifactTreeDirs zip 多源(含子目录)内容树按目录聚合。
func TestArtifactTreeDirs(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range map[string]string{
		"site/logs/a.log": analyzeNginx,
		"site/logs/b.log": analyzeNginx,
		"site/readme.txt": "说明文件\n",
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	tid := e.uploadFile(t, "tree-case", "bundle.zip", buf.Bytes(), "")
	task := e.waitTask(t, tid)
	if task["status"] != "done" {
		t.Fatalf("zip 摄入失败: %v", task["err"])
	}

	code, out := e.do(t, "GET", "/api/cases", nil)
	if code != http.StatusOK {
		t.Fatal(code)
	}
	caseID := out["cases"].([]any)[0].(map[string]any)["id"].(string)
	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/artifact-tree", nil)
	if code != http.StatusOK {
		t.Fatalf("内容树: %d", code)
	}
	tree := out["tree"].([]any)
	if len(tree) != 1 || tree[0].(map[string]any)["name"] != "site" {
		t.Fatalf("根应为 site 目录: %v", tree)
	}
	site := tree[0].(map[string]any)
	var logsDir map[string]any
	leaves := 0
	for _, c := range site["children"].([]any) {
		cm := c.(map[string]any)
		if cm["type"] == "dir" && cm["name"] == "logs" {
			logsDir = cm
		}
		if cm["type"] == "source" {
			leaves++
		}
	}
	if logsDir == nil || len(logsDir["children"].([]any)) != 2 || leaves != 1 {
		t.Fatalf("目录聚合形态: %v", site)
	}
}

// TestReparsePathway 切片七重解析通路:已解析源改判 reparse=true →
// 旧事件先删后插(幂等:行数不变),审计留痕;reparse=false 不重复解析。
func TestReparsePathway(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)

	tid := e.uploadFile(t, "reparse-case", "access.log", []byte(analyzeNginx), "")
	if task := e.waitTask(t, tid); task["status"] != "done" {
		t.Fatalf("上传摄入任务失败: %v", task["err"])
	}
	code, out := e.do(t, "GET", "/api/cases", nil)
	if code != http.StatusOK {
		t.Fatal(code)
	}
	caseID := out["cases"].([]any)[0].(map[string]any)["id"].(string)
	analyzeCase(t, e, caseID)

	code, out = e.do(t, "GET", "/api/cases/"+caseID, nil)
	if code != http.StatusOK {
		t.Fatal(code)
	}
	srcID := out["sources"].([]any)[0].(map[string]any)["id"].(string)
	eventsBefore := len(e.ch.rows)
	if eventsBefore != 4 {
		t.Fatalf("解析后应 4 事件: %d", eventsBefore)
	}

	// 不带 reparse:判定照改但不重复解析(200 如实提示)
	code, out = e.do(t, "POST", "/api/sources/"+srcID+"/detect",
		map[string]any{"format": "builtin:nginx_combined"})
	if code != http.StatusOK || !strings.Contains(out["note"].(string), "reparse=true") {
		t.Fatalf("无 reparse 应 200 提示重解析开关: %d %v", code, out)
	}
	if len(e.ch.rows) != eventsBefore || e.ch.deletedRows != 0 {
		t.Fatalf("无 reparse 不应动事件: rows=%d deleted=%d",
			len(e.ch.rows), e.ch.deletedRows)
	}

	// reparse=true:删旧插新,幂等(行数不变),审计留痕
	code, out = e.do(t, "POST", "/api/sources/"+srcID+"/detect",
		map[string]any{"format": "builtin:nginx_combined", "reparse": true})
	if code != http.StatusAccepted {
		t.Fatalf("重解析应 202: %d %v", code, out)
	}
	ptask := e.waitTask(t, out["task_id"].(string))
	if ptask["status"] != "done" {
		t.Fatalf("重解析任务: %v err=%v", ptask["status"], ptask["err"])
	}
	if e.ch.deletedRows != eventsBefore {
		t.Fatalf("旧事件应全删: deleted=%d want=%d", e.ch.deletedRows, eventsBefore)
	}
	if len(e.ch.rows) != eventsBefore {
		t.Fatalf("重解析应幂等(行数不变): got=%d want=%d",
			len(e.ch.rows), eventsBefore)
	}
	found := false
	for _, en := range e.audit.entries {
		if en.Action == "source.reparse" {
			found = true
		}
	}
	if !found {
		t.Fatal("重解析应进审计(source.reparse)")
	}
}
