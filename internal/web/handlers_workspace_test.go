// 工作空间文件管理器契约测试(切片十一,ARTEX workspace 复刻):
// 闭环(mkdir → upload → list → read → write → download → delete)+
// 登录闸 + 路径逃逸负样本(../、绝对路径、盘符、反斜杠、NUL、符号链接
// 全 400)+ 二进制/超大如实标记 + DataDir 未装配 503。合成临时目录,
// 不碰真数据,零 AI 调用。
package web

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newWSEnv 工作空间测试台:testEnv + DataDir 指向独立临时目录。
func newWSEnv(t *testing.T) *testEnv {
	t.Helper()
	e := newTestEnv(t)
	e.srv.deps.DataDir = t.TempDir()
	return e
}

// wsUpload  multipart 上传(files 字段,path 表单字段)。
func (e *testEnv) wsUpload(t *testing.T, dir string,
	files map[string][]byte) (int, map[string]any) {

	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("path", dir); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		fw, err := mw.CreateFormFile("files", name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", e.ts.URL+"/api/workspace/upload", &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Cookie", sessionCookie+"="+e.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("上传响应 JSON 解析失败(%d): %v", resp.StatusCode, err)
	}
	return resp.StatusCode, out
}

// TestWorkspaceClosedLoop 工作空间闭环:建目录 → 上传 → 列目录 → 读文件 →
// 改文本保存 → 下载逐字节一致 → 删除;写动作全进审计链。
func TestWorkspaceClosedLoop(t *testing.T) {
	e := newWSEnv(t)

	// 登录闸:未登录一律 401
	if code, _ := e.do(t, "GET", "/api/workspace/list", nil); code != http.StatusUnauthorized {
		t.Fatalf("未登录应 401: %d", code)
	}
	e.login(t)

	// 1. 空根清单
	code, out := e.do(t, "GET", "/api/workspace/list", nil)
	if code != http.StatusOK {
		t.Fatalf("根清单状态码: %d %v", code, out)
	}
	if len(out["entries"].([]any)) != 0 {
		t.Fatalf("空根应零条目: %v", out)
	}

	// 2. mkdir(含嵌套)
	code, out = e.do(t, "POST", "/api/workspace/mkdir",
		map[string]string{"path": "notes/host-a"})
	if code != http.StatusCreated {
		t.Fatalf("mkdir 状态码: %d %v", code, out)
	}

	// 3. 上传两个文件到嵌套目录
	code, out = e.wsUpload(t, "notes/host-a", map[string][]byte{
		"timeline.md": []byte("# 时间线\n10:00 爆破开始\n"),
		"iocs.txt":    []byte("1.2.3.4\nevil.example\n"),
	})
	if code != http.StatusOK || int(out["uploaded"].(float64)) != 2 {
		t.Fatalf("上传不符: %d %v", code, out)
	}

	// 4. list:目录在前,文件按名排
	code, out = e.do(t, "GET", "/api/workspace/list?path=notes/host-a", nil)
	if code != http.StatusOK {
		t.Fatalf("子目录清单状态码: %d %v", code, out)
	}
	entries := out["entries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("应 2 条目: %v", entries)
	}
	first := entries[0].(map[string]any)
	if first["name"] != "iocs.txt" || first["dir"] != false ||
		first["path"] != "notes/host-a/iocs.txt" {
		t.Fatalf("条目形态不符: %v", first)
	}
	code, out = e.do(t, "GET", "/api/workspace/list?path=notes", nil)
	if code != http.StatusOK {
		t.Fatalf("notes 清单状态码: %d", code)
	}
	dirent := out["entries"].([]any)[0].(map[string]any)
	if dirent["dir"] != true || dirent["name"] != "host-a" {
		t.Fatalf("目录条目不符: %v", dirent)
	}

	// 5. 读文件(文本回内容)
	code, out = e.do(t, "GET", "/api/workspace/file?path=notes/host-a/timeline.md", nil)
	if code != http.StatusOK {
		t.Fatalf("读文件状态码: %d %v", code, out)
	}
	if out["binary"] != false || out["too_large"] != false ||
		!strings.Contains(out["content"].(string), "爆破开始") {
		t.Fatalf("文件内容不符: %v", out)
	}

	// 6. 保存文本(PUT)→ 重读校验
	code, out = e.do(t, "PUT", "/api/workspace/file", map[string]string{
		"path": "notes/host-a/timeline.md", "content": "# 时间线 v2\n改写\n"})
	if code != http.StatusOK {
		t.Fatalf("保存状态码: %d %v", code, out)
	}
	code, out = e.do(t, "GET", "/api/workspace/file?path=notes/host-a/timeline.md", nil)
	if code != http.StatusOK || !strings.Contains(out["content"].(string), "v2") {
		t.Fatalf("保存后重读不符: %d %v", code, out)
	}

	// 7. 下载逐字节一致
	req, _ := http.NewRequest("GET",
		e.ts.URL+"/api/workspace/download?path=notes/host-a/iocs.txt", nil)
	req.Header.Set("Cookie", sessionCookie+"="+e.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	dl, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK ||
		string(dl) != "1.2.3.4\nevil.example\n" {
		t.Fatalf("下载内容不符: %d %q", resp.StatusCode, dl)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Fatalf("下载应为 attachment: %q", cd)
	}

	// 8. 删除(文件 + 递归目录)
	if code, out = e.do(t, "DELETE",
		"/api/workspace/entry?path=notes/host-a/iocs.txt", nil); code != http.StatusOK {
		t.Fatalf("删文件状态码: %d %v", code, out)
	}
	if code, _ = e.do(t, "DELETE", "/api/workspace/entry?path=notes", nil); code != http.StatusOK {
		t.Fatalf("递归删目录状态码: %d", code)
	}
	code, _ = e.do(t, "GET", "/api/workspace/file?path=notes/host-a/timeline.md", nil)
	if code != http.StatusNotFound {
		t.Fatalf("删后读应 404: %d", code)
	}

	// 9. 写动作全进审计
	actions := map[string]bool{}
	for _, en := range e.audit.entries {
		actions[en.Action] = true
	}
	for _, want := range []string{"workspace.mkdir", "workspace.upload",
		"workspace.write", "workspace.delete"} {
		if !actions[want] {
			t.Fatalf("审计缺动作 %s: 实有 %v", want, actions)
		}
	}
}

// TestWorkspacePathEscapeRejected 逃逸负样本:全端点全形态 400,
// 且不得产生任何副作用(目录/文件不出现)。
func TestWorkspacePathEscapeRejected(t *testing.T) {
	e := newWSEnv(t)
	e.login(t)

	bad := []string{
		"../vault", "..", "a/../../b", "/etc/passwd", "C:/Windows/system32",
		"c:\\windows", "a\\..\\b", "a//b", "a/./b",
	}
	check := func(name string, code int, out map[string]any) {
		t.Helper()
		if code != http.StatusBadRequest {
			t.Fatalf("%s 应 400: %d %v", name, code, out)
		}
	}
	for _, p := range bad {
		enc := urlQueryEscape(p)
		code, out := e.do(t, "GET", "/api/workspace/list?path="+enc, nil)
		check("list "+p, code, out)
		code, out = e.do(t, "GET", "/api/workspace/file?path="+enc, nil)
		check("file "+p, code, out)
		code, out = e.do(t, "GET", "/api/workspace/download?path="+enc, nil)
		check("download "+p, code, out)
		code, out = e.do(t, "POST", "/api/workspace/mkdir", map[string]string{"path": p})
		check("mkdir "+p, code, out)
		code, out = e.do(t, "PUT", "/api/workspace/file",
			map[string]string{"path": p, "content": "x"})
		check("write "+p, code, out)
		code, out = e.do(t, "DELETE", "/api/workspace/entry?path="+enc, nil)
		check("delete "+p, code, out)
		code, out = e.wsUpload(t, p, map[string][]byte{"x.txt": []byte("x")})
		check("upload "+p, code, out)
	}
	// NUL
	code, out := e.do(t, "GET", "/api/workspace/list?path=a%00b", nil)
	check("list NUL", code, out)
	code, out = e.do(t, "POST", "/api/workspace/mkdir", map[string]string{"path": "a\x00b"})
	check("mkdir NUL", code, out)

	// 副作用断言:根仍为空,data 根下不得长出 vault 目录
	code, out = e.do(t, "GET", "/api/workspace/list", nil)
	if code != http.StatusOK || len(out["entries"].([]any)) != 0 {
		t.Fatalf("逃逸尝试后根应仍为空: %d %v", code, out)
	}
	if _, err := os.Stat(filepath.Join(e.srv.deps.DataDir, "vault")); !os.IsNotExist(err) {
		t.Fatal("逃逸尝试不得在工作区外造出 vault 目录")
	}
}

// TestWorkspaceSymlinkEscapeRejected 符号链接逃逸:工作区内 symlink 指外,
// 任何操作 400(平台不支持建 symlink 则跳过,如实)。
func TestWorkspaceSymlinkEscapeRejected(t *testing.T) {
	e := newWSEnv(t)
	e.login(t)
	root := filepath.Join(e.srv.deps.DataDir, "workspace")
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"),
		[]byte("不得读出"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("平台不支持建符号链接(Windows 需开发者模式/管理员): %v", err)
	}
	for _, tc := range [][2]string{
		{"GET", "/api/workspace/list?path=link"},
		{"GET", "/api/workspace/file?path=link/secret.txt"},
		{"GET", "/api/workspace/download?path=link/secret.txt"},
		{"DELETE", "/api/workspace/entry?path=link"},
	} {
		code, out := e.do(t, tc[0], tc[1], nil)
		if code != http.StatusBadRequest {
			t.Fatalf("%s %s 应 400: %d %v", tc[0], tc[1], code, out)
		}
	}
	code, out := e.do(t, "PUT", "/api/workspace/file",
		map[string]string{"path": "link/evil.txt", "content": "x"})
	if code != http.StatusBadRequest {
		t.Fatalf("symlink 内写应 400: %d %v", code, out)
	}
}

// TestWorkspaceBinaryAndTooLarge 内容嗅探:NUL 字节/高控制字符比例 →
// binary 如实不回内容;超 8MB → too_large 如实只给下载。
func TestWorkspaceBinaryAndTooLarge(t *testing.T) {
	e := newWSEnv(t)
	e.login(t)
	root := filepath.Join(e.srv.deps.DataDir, "workspace")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}

	// NUL 二进制
	if err := os.WriteFile(filepath.Join(root, "a.bin"),
		[]byte{'P', 'K', 0, 1, 2}, 0o644); err != nil {
		t.Fatal(err)
	}
	// 控制字符比例 >30%(无 NUL)
	ctrl := bytes.Repeat([]byte{0x01, 0x02, 0x03}, 100) // 100% 控制字符
	if err := os.WriteFile(filepath.Join(root, "ctrl.dat"), ctrl, 0o644); err != nil {
		t.Fatal(err)
	}
	// GBK 中文(非 UTF-8 但无 NUL/低控制字符)→ 应判文本(不按扩展名/编码猜)
	if err := os.WriteFile(filepath.Join(root, "gbk.txt"),
		[]byte{0xC4, 0xE3, 0xBA, 0xC3, '\n'}, 0o644); err != nil {
		t.Fatal(err)
	}
	// 8MB+1 超大文本
	big := bytes.Repeat([]byte("a"), wsMaxTextBytes+1)
	if err := os.WriteFile(filepath.Join(root, "big.log"), big, 0o644); err != nil {
		t.Fatal(err)
	}

	code, out := e.do(t, "GET", "/api/workspace/file?path=a.bin", nil)
	if code != http.StatusOK || out["binary"] != true {
		t.Fatalf("NUL 文件应 binary: %d %v", code, out)
	}
	if _, has := out["content"]; has {
		t.Fatalf("binary 不得回内容: %v", out)
	}
	code, out = e.do(t, "GET", "/api/workspace/file?path=ctrl.dat", nil)
	if code != http.StatusOK || out["binary"] != true {
		t.Fatalf("高控制字符应 binary: %d %v", code, out)
	}
	code, out = e.do(t, "GET", "/api/workspace/file?path=gbk.txt", nil)
	if code != http.StatusOK || out["binary"] != false {
		t.Fatalf("GBK 文本不该误判 binary: %d %v", code, out)
	}
	code, out = e.do(t, "GET", "/api/workspace/file?path=big.log", nil)
	if code != http.StatusOK || out["too_large"] != true {
		t.Fatalf("超 8MB 应 too_large: %d %v", code, out)
	}
	if _, has := out["content"]; has {
		t.Fatalf("too_large 不得回内容: %v", out)
	}
	// 超大文件下载仍可用
	req, _ := http.NewRequest("GET", e.ts.URL+"/api/workspace/download?path=big.log", nil)
	req.Header.Set("Cookie", sessionCookie+"="+e.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("超大文件下载应 200: %d", resp.StatusCode)
	}
}

// TestWorkspaceEdgeCases 边界:写超 8MB 拒、目录按文件读/写/下载 400、
// 删根拒、无此条目 404、上传文件名净化(剥客户端路径)、DataDir 空 503。
func TestWorkspaceEdgeCases(t *testing.T) {
	e := newWSEnv(t)
	e.login(t)

	// DataDir 未装配 → 503 如实
	savedDir := e.srv.deps.DataDir
	e.srv.deps.DataDir = ""
	if code, _ := e.do(t, "GET", "/api/workspace/list", nil); code != http.StatusServiceUnavailable {
		t.Fatalf("DataDir 空应 503: %d", code)
	}
	e.srv.deps.DataDir = savedDir

	// 写超 8MB 拒(413)
	code, out := e.do(t, "PUT", "/api/workspace/file", map[string]string{
		"path": "huge.txt", "content": strings.Repeat("a", wsMaxTextBytes+1)})
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超 8MB 写应 413: %d %v", code, out)
	}

	// 建目录后按文件读/写/下载 → 400
	e.do(t, "POST", "/api/workspace/mkdir", map[string]string{"path": "d1"})
	for _, tc := range [][2]string{
		{"GET", "/api/workspace/file?path=d1"},
		{"GET", "/api/workspace/download?path=d1"},
	} {
		code, out = e.do(t, tc[0], tc[1], nil)
		if code != http.StatusBadRequest {
			t.Fatalf("%s 目录应 400: %d %v", tc[1], code, out)
		}
	}
	code, out = e.do(t, "PUT", "/api/workspace/file",
		map[string]string{"path": "d1", "content": "x"})
	if code != http.StatusBadRequest {
		t.Fatalf("目录按文件写应 400: %d %v", code, out)
	}

	// 删根/无此条目
	if code, _ = e.do(t, "DELETE", "/api/workspace/entry", nil); code != http.StatusBadRequest {
		t.Fatalf("删根应 400: %d", code)
	}
	if code, _ = e.do(t, "DELETE", "/api/workspace/entry?path=nope", nil); code != http.StatusNotFound {
		t.Fatalf("删无此条目应 404: %d", code)
	}
	if code, _ = e.do(t, "GET", "/api/workspace/list?path=nope", nil); code != http.StatusNotFound {
		t.Fatalf("列无此目录应 404: %d", code)
	}

	// 上传文件名剥客户端路径(../../etc/passwd 名义只取 passwd)
	code, out = e.wsUpload(t, "", map[string][]byte{"../../etc/passwd": []byte("x")})
	if code != http.StatusOK {
		t.Fatalf("上传应 200: %d %v", code, out)
	}
	code, out = e.do(t, "GET", "/api/workspace/list", nil)
	entries := out["entries"].([]any)
	foundPasswd := false
	for _, en := range entries {
		m := en.(map[string]any)
		if strings.Contains(m["path"].(string), "..") || strings.Contains(m["path"].(string), "/") {
			t.Fatalf("上传后条目路径应无逃逸: %v", m)
		}
		if m["name"] == "passwd" {
			foundPasswd = true
		}
	}
	if !foundPasswd {
		t.Fatalf("剥路径后应落在根下 passwd: %v", entries)
	}
	// 上传空 files → 400
	code, out = e.wsUpload(t, "", nil)
	if code != http.StatusBadRequest {
		t.Fatalf("空上传应 400: %d %v", code, out)
	}
	// 上传到不存在的目录 → 400
	code, out = e.wsUpload(t, "no-such-dir", map[string][]byte{"a.txt": []byte("x")})
	if code != http.StatusBadRequest {
		t.Fatalf("目标目录不存在应 400: %d %v", code, out)
	}
}

func urlQueryEscape(s string) string {
	r := strings.NewReplacer(
		"%", "%25", "&", "%26", "=", "%3D", "#", "%23", "+", "%2B",
		"?", "%3F", " ", "%20")
	return r.Replace(s)
}

// ---- 切片十二:案件工作区隔离 ----

// mkCase 建案返回 id(工作区隔离测试用)。
func mkCase(t *testing.T, e *testEnv, name string) string {
	t.Helper()
	code, out := e.do(t, "POST", "/api/cases", map[string]any{"name": name, "incident_type": "other"})
	if code != http.StatusCreated {
		t.Fatalf("建案应 201: %d %v", code, out)
	}
	return out["case"].(map[string]any)["id"].(string)
}

// wsUploadCase 案件作用域 multipart 上传。
func (e *testEnv) wsUploadCase(t *testing.T, caseID, dir string,
	files map[string][]byte) (int, map[string]any) {

	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("path", dir); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		fw, err := mw.CreateFormFile("files", name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST",
		e.ts.URL+"/api/cases/"+caseID+"/workspace/upload", &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Cookie", sessionCookie+"="+e.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("上传响应 JSON 解析失败(%d): %v", resp.StatusCode, err)
	}
	return resp.StatusCode, out
}

// TestWorkspaceCaseIsolation 案件隔离闭环:A 案建文件,B 案通路全维度不可见
// (list 空/file 404/download 404/overwrite 写不穿),全局「未分配」区
// 清单滤掉案件目录、首段命中案件 id 的路径一律 400。
func TestWorkspaceCaseIsolation(t *testing.T) {
	e := newWSEnv(t)
	e.login(t)
	caseA := mkCase(t, e, "案件A")
	caseB := mkCase(t, e, "案件B")

	// A 案:mkdir + 上传 + 写文本(案件作用域写操作落审计且记案件 id)
	code, out := e.do(t, "POST", "/api/cases/"+caseA+"/workspace/mkdir",
		map[string]string{"path": "notes"})
	if code != http.StatusCreated {
		t.Fatalf("A 案 mkdir 状态码: %d %v", code, out)
	}
	code, out = e.wsUploadCase(t, caseA, "notes",
		map[string][]byte{"supp.md": []byte("A 案补充材料\n")})
	if code != http.StatusOK {
		t.Fatalf("A 案上传状态码: %d %v", code, out)
	}

	// A 案自见
	code, out = e.do(t, "GET", "/api/cases/"+caseA+"/workspace/list?path=notes", nil)
	if code != http.StatusOK || len(out["entries"].([]any)) != 1 {
		t.Fatalf("A 案清单应 1 条目: %d %v", code, out)
	}
	if out["case_id"] != caseA {
		t.Fatalf("清单应带 case_id: %v", out)
	}
	code, out = e.do(t, "GET",
		"/api/cases/"+caseA+"/workspace/file?path=notes/supp.md", nil)
	if code != http.StatusOK ||
		!strings.Contains(out["content"].(string), "A 案补充材料") {
		t.Fatalf("A 案读文件不符: %d %v", code, out)
	}

	// B 案看不到 A 案文件:list 空 200(如实空)、file/download 404
	code, out = e.do(t, "GET", "/api/cases/"+caseB+"/workspace/list", nil)
	if code != http.StatusOK || len(out["entries"].([]any)) != 0 {
		t.Fatalf("B 案清单应空: %d %v", code, out)
	}
	if code, _ = e.do(t, "GET",
		"/api/cases/"+caseB+"/workspace/file?path=notes/supp.md", nil); code != http.StatusNotFound {
		t.Fatalf("B 案读 A 案文件应 404: %d", code)
	}
	if code, _ = e.do(t, "GET",
		"/api/cases/"+caseB+"/workspace/download?path=notes/supp.md", nil); code != http.StatusNotFound {
		t.Fatalf("B 案下载 A 案文件应 404: %d", code)
	}
	// B 案同路径写:落在 B 案自己根,写不穿 A 案
	e.do(t, "POST", "/api/cases/"+caseB+"/workspace/mkdir",
		map[string]string{"path": "notes"})
	code, _ = e.do(t, "PUT", "/api/cases/"+caseB+"/workspace/file",
		map[string]string{"path": "notes/supp.md", "content": "B 案版本\n"})
	if code != http.StatusOK {
		t.Fatalf("B 案写自己工作区应 200: %d", code)
	}
	code, out = e.do(t, "GET",
		"/api/cases/"+caseA+"/workspace/file?path=notes/supp.md", nil)
	if !strings.Contains(out["content"].(string), "A 案补充材料") {
		t.Fatalf("A 案文件被 B 案写穿: %v", out)
	}

	// 未分配区:案件目录不进清单,首段命中案件 id 一律 400(隔离闸)
	code, out = e.do(t, "GET", "/api/workspace/list", nil)
	if code != http.StatusOK {
		t.Fatalf("未分配区清单状态码: %d %v", code, out)
	}
	for _, en := range out["entries"].([]any) {
		m := en.(map[string]any)
		if m["name"] == caseA || m["name"] == caseB {
			t.Fatalf("案件目录不得进未分配区清单: %v", m)
		}
	}
	for _, tc := range [][2]string{
		{"GET", "/api/workspace/list?path=" + caseA},
		{"GET", "/api/workspace/file?path=" + caseA + "/notes/supp.md"},
		{"GET", "/api/workspace/download?path=" + caseA + "/notes/supp.md"},
		{"DELETE", "/api/workspace/entry?path=" + caseA + "/notes/supp.md"},
	} {
		code, out = e.do(t, tc[0], tc[1], nil)
		if code != http.StatusBadRequest {
			t.Fatalf("未分配区越权 %s 应 400: %d %v", tc[1], code, out)
		}
	}
	code, out = e.do(t, "PUT", "/api/workspace/file",
		map[string]string{"path": caseA + "/evil.txt", "content": "x"})
	if code != http.StatusBadRequest {
		t.Fatalf("未分配区写案件目录应 400: %d %v", code, out)
	}

	// 案件作用域写操作审计记案件 id
	found := false
	for _, en := range e.audit.entries {
		if en.Action == "workspace.upload" && en.CaseID == caseA {
			found = true
		}
	}
	if !found {
		t.Fatalf("案件工作区写操作审计缺 case_id=%s", caseA)
	}
}

// TestWorkspaceCaseIDRejected 案件 id 闸:注入形态 400、无此案 404;
// 且不得产生任何副作用(工作区根下不长垃圾目录)。
func TestWorkspaceCaseIDRejected(t *testing.T) {
	e := newWSEnv(t)
	e.login(t)

	// 反斜杠/盘符注入(Go mux 对 .. 段会先 301 重定向,到不了 handler,
	// 故逃逸负样本走能落到 handler 的形态)
	for _, id := range []string{"a%5Cb", "c%3Ad", "a%00b"} {
		code, out := e.do(t, "GET", "/api/cases/"+id+"/workspace/list", nil)
		if code != http.StatusBadRequest {
			t.Fatalf("案件 id %s 应 400: %d %v", id, code, out)
		}
	}
	// 无此案:404(不给垃圾 id 建目录)
	code, out := e.do(t, "GET", "/api/cases/case-nonexistent/workspace/list", nil)
	if code != http.StatusNotFound {
		t.Fatalf("无此案应 404: %d %v", code, out)
	}
	code, out = e.do(t, "POST", "/api/cases/case-nonexistent/workspace/mkdir",
		map[string]string{"path": "x"})
	if code != http.StatusNotFound {
		t.Fatalf("无此案写应 404: %d %v", code, out)
	}
	// 副作用断言:根下不得长出垃圾目录
	code, out = e.do(t, "GET", "/api/workspace/list", nil)
	if code != http.StatusOK || len(out["entries"].([]any)) != 0 {
		t.Fatalf("逃逸尝试后根应仍为空: %d %v", code, out)
	}
}

// TestWorkspaceUnassignedCompat 未分配区兼容:旧全局根下文件照常可见可管
// (不丢用户文件),与案件工作区并存互不串。
func TestWorkspaceUnassignedCompat(t *testing.T) {
	e := newWSEnv(t)
	e.login(t)
	caseA := mkCase(t, e, "案件A")

	// 旧全局根遗留文件(模拟切片十一时代的全局工作区数据)
	code, out := e.wsUpload(t, "", map[string][]byte{"legacy.txt": []byte("旧全局文件\n")})
	if code != http.StatusOK {
		t.Fatalf("未分配区上传应 200: %d %v", code, out)
	}
	// 案件工作区造文件后,未分配区仍只见自己的文件(案件目录被滤)
	if code, out = e.do(t, "PUT", "/api/cases/"+caseA+"/workspace/file",
		map[string]string{"path": "a.txt", "content": "x"}); code != http.StatusOK {
		t.Fatalf("案件写应 200: %d", code)
	}
	code, out = e.do(t, "GET", "/api/workspace/list", nil)
	entries := out["entries"].([]any)
	if len(entries) != 1 || entries[0].(map[string]any)["name"] != "legacy.txt" {
		t.Fatalf("未分配区应只见遗留文件: %v", entries)
	}
	code, out = e.do(t, "GET", "/api/workspace/file?path=legacy.txt", nil)
	if code != http.StatusOK || out["content"] != "旧全局文件\n" {
		t.Fatalf("遗留文件读不符: %d %v", code, out)
	}
}
