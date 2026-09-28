// M4 并发安全焊死(httptest + fake,全链路真 HTTP):
//   - 两用户(admin+operator)同案并发上传两文件:都 202,任务各自独立,
//     源登记互不串,审计锚各自真人;
//   - 裁决 CAS 的 web 映射:并发/二次裁决 → 409(审计只落成功那次);
//   - 同案同包名两 zip 并发:pkgRegLocks 串行化,一个裸名一个 #2,
//     零任务因登记冲突(fake 复现 PG 23505)失败。
package web

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// doRaw 发请求(显式 cookie,不动 e.cookie——并发测试里 e.do 的共享
// cookie 会串会话;goroutine 内禁用 t.Fatal,错误经返回值上报)。
func doRaw(baseURL, cookie, method, path string, body any) (int, map[string]any, error) {
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, baseURL+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.Header.Set("Cookie", sessionCookie+"="+cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return resp.StatusCode, nil,
				fmt.Errorf("响应 JSON 解析失败(%d %s %s): %w",
					resp.StatusCode, method, path, err)
		}
	}
	return resp.StatusCode, out, nil
}

// loginAs 登录取会话 cookie(不污染 e.cookie)。
func loginAs(baseURL, username, password string) (string, error) {
	b, _ := json.Marshal(map[string]string{
		"username": username, "password": password})
	resp, err := http.Post(baseURL+"/api/auth/login", "application/json",
		bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("登录 %s 被拒: %d", username, resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			return c.Value, nil
		}
	}
	return "", fmt.Errorf("登录 %s 未发会话 cookie", username)
}

// uploadAs 完整分块上传(顺序传块;init→chunks→complete),返回 task_id。
func uploadAs(baseURL, cookie, caseName, filename string, content []byte,
	format string) (string, error) {

	code, out, err := doRaw(baseURL, cookie, "POST", "/api/uploads", map[string]any{
		"case_name": caseName, "filename": filename,
		"size": len(content), "sha256": shaOf(content), "format": format,
	})
	if err != nil {
		return "", err
	}
	if code != http.StatusCreated {
		return "", fmt.Errorf("init 被拒: %d %v", code, out)
	}
	uploadID := out["upload_id"].(string)
	chunkSize := int(out["chunk_size"].(float64))
	total := (len(content) + chunkSize - 1) / chunkSize
	for i := 0; i < total; i++ {
		end := (i + 1) * chunkSize
		if end > len(content) {
			end = len(content)
		}
		req, err := http.NewRequest("PUT",
			fmt.Sprintf("%s/api/uploads/%s/chunks/%d", baseURL, uploadID, i),
			bytes.NewReader(content[i*chunkSize:end]))
		if err != nil {
			return "", err
		}
		req.Header.Set("Cookie", sessionCookie+"="+cookie)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("块 %d 被拒: %d", i, resp.StatusCode)
		}
	}
	code, out, err = doRaw(baseURL, cookie, "POST",
		"/api/uploads/"+uploadID+"/complete", nil)
	if err != nil {
		return "", err
	}
	if code != http.StatusAccepted {
		return "", fmt.Errorf("complete 被拒: %d %v", code, out)
	}
	return out["task_id"].(string), nil
}

// TestUploadConcurrentTwoUsers 两用户(admin+operator)同案并发上传:
// 都 202,任务各自独立 done,源/审计互不串。
func TestUploadConcurrentTwoUsers(t *testing.T) {
	e := newTestEnv(t)
	e.login(t) // admin
	// admin 建 operator(用户管理面 0.26.0)
	code, out := e.do(t, "POST", "/api/users",
		map[string]string{"username": "op1", "password": "password123",
			"role": "operator"})
	if code != http.StatusCreated {
		t.Fatalf("建 operator 失败: %d %v", code, out)
	}
	opCookie, err := loginAs(e.ts.URL, "op1", "password123")
	if err != nil {
		t.Fatalf("operator 登录失败: %v", err)
	}

	contentAdmin := []byte(nginxContent)
	contentOp := []byte(nginxContent + nginxContent) // 不同内容不同 sha256

	type res struct {
		taskID string
		err    error
	}
	results := make([]res, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		id, err := uploadAs(e.ts.URL, e.cookie, "case-race", "admin.log",
			contentAdmin, "nginx_combined")
		results[0] = res{id, err}
	}()
	go func() {
		defer wg.Done()
		id, err := uploadAs(e.ts.URL, opCookie, "case-race", "op.log",
			contentOp, "nginx_combined")
		results[1] = res{id, err}
	}()
	wg.Wait()
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("并发上传 %d 失败: %v", i, r.err)
		}
	}
	if results[0].taskID == results[1].taskID {
		t.Fatal("两上传应各自独立任务")
	}
	for i, r := range results {
		if task := e.waitTask(t, r.taskID); task["status"] != "done" {
			t.Fatalf("任务 %d 应 done: %v", i, task)
		}
	}
	// 源登记互不串:同案 2 源,路径各归各
	var caseID string
	for name, id := range e.meta.cases {
		if name == "case-race" {
			caseID = id
		}
	}
	if caseID == "" {
		t.Fatal("案件未登记")
	}
	sources, _ := e.meta.ListSources(context.Background(), caseID)
	if len(sources) != 2 {
		t.Fatalf("应登记 2 源: %v", sources)
	}
	paths := map[string]string{} // path → sha256
	for _, s := range sources {
		paths[s.Path] = s.SHA256
	}
	if paths["admin.log"] != shaOf(contentAdmin) ||
		paths["op.log"] != shaOf(contentOp) {
		t.Fatalf("源登记串味: %v", paths)
	}
	// 审计锚各自真人:两条 upload.completed,actor 一 admin 一 op1
	actors := map[string]bool{}
	n := 0
	for _, en := range e.audit.entries {
		if en.Action == "upload.completed" {
			n++
			actors[en.Actor] = true
		}
	}
	if n != 2 || !actors["admin"] || !actors["op1"] {
		t.Fatalf("审计上传账不符: n=%d actors=%v", n, actors)
	}
}

// TestVerdictConflict409 裁决 CAS 的 web 映射:同一候选并发裁决,
// 恰好一 200 余者 409;审计只落成功那次(失败不落账)。
func TestVerdictConflict409(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	opCookie := func() string { // 第二把「人」:并发另一裁决者
		code, _ := e.do(t, "POST", "/api/users",
			map[string]string{"username": "op9", "password": "password123",
				"role": "operator"})
		if code != http.StatusCreated {
			t.Fatalf("建 operator 失败: %d", code)
		}
		c, err := loginAs(e.ts.URL, "op9", "password123")
		if err != nil {
			t.Fatalf("operator 登录失败: %v", err)
		}
		return c
	}()

	// 上传 + 扫描出一条候选(上传是异步任务,先等摄入落库再扫)
	upTask := e.uploadFile(t, "case-v409", "access.log", []byte(nginxContent), "nginx_combined")
	if task := e.waitTask(t, upTask); task["status"] != "done" {
		t.Fatalf("摄入任务应 done: %v", task)
	}
	code, out := e.do(t, "GET", "/api/cases", nil)
	if code != http.StatusOK {
		t.Fatalf("案件清单失败: %d", code)
	}
	caseID := out["cases"].([]any)[0].(map[string]any)["id"].(string)
	e.waitTask(t, func() string {
		code, out := e.do(t, "POST", "/api/cases/"+caseID+"/scans", map[string]any{})
		if code != http.StatusAccepted {
			t.Fatalf("扫描启动失败: %d", code)
		}
		return out["task_id"].(string)
	}())
	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/hits?status=pending", nil)
	if code != http.StatusOK || len(out["hits"].([]any)) == 0 {
		t.Fatalf("待审区应有候选: %d %v", code, out)
	}
	hitID := out["hits"].([]any)[0].(map[string]any)["id"].(string)

	// 两人并发裁决同一候选
	codes := make([]int, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		c, _, err := doRaw(e.ts.URL, e.cookie, "POST",
			"/api/hits/"+hitID+"/verdict",
			map[string]string{"status": "accepted", "note": "admin 裁"})
		if err != nil {
			codes[0] = -1
			return
		}
		codes[0] = c
	}()
	go func() {
		defer wg.Done()
		c, _, err := doRaw(e.ts.URL, opCookie, "POST",
			"/api/hits/"+hitID+"/verdict",
			map[string]string{"status": "rejected", "note": "op 裁"})
		if err != nil {
			codes[1] = -1
			return
		}
		codes[1] = c
	}()
	wg.Wait()
	got := map[int]int{codes[0]: 1, codes[1]: 1}
	if codes[0] == codes[1] || !(got[http.StatusOK] == 1 && got[http.StatusConflict] == 1) {
		t.Fatalf("并发裁决应恰好一 200 一 409: %v", codes)
	}
	// 二次裁决(顺序)也 409——改判语义焊死为拒绝
	code, out = e.do(t, "POST", "/api/hits/"+hitID+"/verdict",
		map[string]string{"status": "rejected"})
	if code != http.StatusConflict {
		t.Fatalf("改判应 409: %d %v", code, out)
	}
	if !strings.Contains(fmt.Sprint(out["error"]), "已被他人裁决") {
		t.Fatalf("409 文案不符: %v", out)
	}
	// 审计:hit.verdict 只落成功那一次
	n := 0
	for _, en := range e.audit.entries {
		if en.Action == "hit.verdict" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("裁决审计应恰 1 条(失败不落账): %d", n)
	}
}

// TestConcurrentSameNamePackage 同案同包名两 zip 并发:pkgRegLocks 把
// 「查重 + #N 后缀 + 登记」串行化——一个裸名一个 #2,零任务因登记冲突
// 失败(fake RegisterSource 拒绝同案同路径,复现 PG 23505 场景)。
func TestConcurrentSameNamePackage(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	root := "Forensic_10.9.9.8_RACE"

	buildPkg := func(fileContent string) []byte {
		fileA := []byte(fileContent)
		manifest := fmt.Sprintf(
			"WinInfoSC Forensic Collection - SHA256 Manifest\n"+
				"Host=RACE IP=10.9.9.8 Generated=2026/01/01 00:00:00\n"+
				"================================================\n"+
				"%s  C:\\c\\%s\\a.txt\n",
			shaOf(fileA), root)
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		w, _ := zw.Create(root + "/_HASH_MANIFEST.txt")
		w.Write([]byte(manifest))
		w2, _ := zw.Create(root + "/a.txt")
		w2.Write(fileA)
		zw.Close()
		return buf.Bytes()
	}
	pkgA := buildPkg("race-A-content")
	pkgB := buildPkg("race-B-content-different")
	if shaOf(pkgA) == shaOf(pkgB) {
		t.Fatal("两包内容须不同(sha256 不同)")
	}
	// 拉宽「查重→登记」窗口:无 pkgRegLocks 时两并发必然都算出裸名、
	// 后登记方撞 fake 的同案同路径拒绝(复现 PG 23505)→ 任务 failed。
	// 有锁时第二人进锁后查重看到首包 → #2。锁存废由此测试判决。
	e.meta.listPackagesDelay = 80 * time.Millisecond

	type res struct {
		taskID string
		err    error
	}
	results := make([]res, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		id, err := uploadAs(e.ts.URL, e.cookie, "case-pkg-race", "pkg1.zip", pkgA, "")
		results[0] = res{id, err}
	}()
	go func() {
		defer wg.Done()
		id, err := uploadAs(e.ts.URL, e.cookie, "case-pkg-race", "pkg2.zip", pkgB, "")
		results[1] = res{id, err}
	}()
	wg.Wait()
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("并发包上传 %d 失败: %v", i, r.err)
		}
	}
	for i, r := range results {
		task := e.waitTask(t, r.taskID)
		if task["status"] != "done" {
			t.Fatalf("同包名并发任务 %d 不应失败(登记冲突=锁缺失): %v",
				i, task)
		}
	}
	// 包根名:一个裸名一个 #2(先后不定,集合断言)
	var caseID string
	for name, id := range e.meta.cases {
		if name == "case-pkg-race" {
			caseID = id
		}
	}
	pkgs, err := e.meta.ListPackages(context.Background(), caseID)
	if err != nil {
		t.Fatalf("包清单查询失败: %v", err)
	}
	got := map[string]bool{}
	for _, p := range pkgs {
		got[p] = true
	}
	if len(pkgs) != 2 || !got[root] || !got[root+"#2"] {
		t.Fatalf("并发同包名应登记为 {%s, %s#2}: %v", root, root, pkgs)
	}
}
