// 案件工作区只读工具契约测试(切片十三;合成临时目录,零 AI 调用):
// 挂载条件(WorkspaceDir 配置即挂/空不挂)、案件绑定(B 案会话够不到
// A 案文件)、逃逸负样本全 400 语义软错、二进制拒读、256KB 截断如实、
// 空目录/未建如实空清单。
package agentloop

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ye-mengwen/fengtu/internal/ingest/store"
)

// newWSSvc 装配带工作区根的 Service,返回根目录取便造文件。
func newWSSvc(t *testing.T) (*Service, string) {
	t.Helper()
	svc, _, _, _, _ := testService(t, &mockProvider{})
	root := t.TempDir()
	svc.deps.WorkspaceDir = root
	return svc, root
}

// TestWorkspaceToolsMount 挂载条件:WorkspaceDir 配置即挂两个只读工具;
// 空配置不挂(测试台默认,advertised 六工具断言不受影响)。
func TestWorkspaceToolsMount(t *testing.T) {
	svc, _ := newWSSvc(t)
	sess := newSess(t, svc)
	tools := svc.buildTools(sess, ResolvedConfig{})
	findTool(t, tools, "workspace_list")
	findTool(t, tools, "workspace_read")

	svc2, _, _, _, _ := testService(t, &mockProvider{})
	sess2 := newSess(t, svc2)
	for _, tl := range svc2.buildTools(sess2, ResolvedConfig{}) {
		if strings.HasPrefix(tl.Name(), "workspace_") {
			t.Fatalf("WorkspaceDir 空不应挂工作区工具: %s", tl.Name())
		}
	}
}

// TestWorkspaceListReadTool 闭环:造材料 → list 得见 → read 得内容;
// 未建目录如实空清单;口径文案(参考不是证据/锚点纪律)在场。
func TestWorkspaceListReadTool(t *testing.T) {
	svc, root := newWSSvc(t)
	sess := newSess(t, svc) // case-1
	caseDir := filepath.Join(root, "case-1")
	if err := os.MkdirAll(filepath.Join(caseDir, "notes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "notes", "supp.md"),
		[]byte("用户补充:10:00 发现异常外联\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	list := findTool(t, svc.buildTools(sess, ResolvedConfig{}), "workspace_list")
	read := findTool(t, svc.buildTools(sess, ResolvedConfig{}), "workspace_read")

	// 未建子目录:如实空,不报错
	res := callTool(t, list, `{"path":"nope"}`)
	if res.IsError || !strings.Contains(res.Flatten(), `"entries":[]`) {
		t.Fatalf("未建目录应如实空: %s", res.Flatten())
	}
	// 根清单:notes 目录在,口径文案在
	res = callTool(t, list, `{}`)
	if res.IsError || !strings.Contains(res.Flatten(), "notes") {
		t.Fatalf("根清单缺 notes: %s", res.Flatten())
	}
	if !strings.Contains(res.Flatten(), "不是采集证据") ||
		!strings.Contains(res.Flatten(), "锚点") {
		t.Fatalf("口径文案缺位: %s", res.Flatten())
	}
	// 读文件:内容 + 口径
	res = callTool(t, read, `{"path":"notes/supp.md"}`)
	if res.IsError || !strings.Contains(res.Flatten(), "异常外联") {
		t.Fatalf("读取不符: %s", res.Flatten())
	}
	// 读目录/无此文件:软错如实
	if res = callTool(t, read, `{"path":"notes"}`); !res.IsError {
		t.Fatal("读目录应报错")
	}
	if res = callTool(t, read, `{"path":"notes/nope.txt"}`); !res.IsError {
		t.Fatal("无此文件应报错")
	}
}

// TestWorkspaceToolCaseBinding 案件绑定:case-2 会话的工作区工具够不到
// case-1 的文件(作用域=会话案件子目录,模型给不出别的案件)。
func TestWorkspaceToolCaseBinding(t *testing.T) {
	svc, root := newWSSvc(t)
	if err := os.MkdirAll(filepath.Join(root, "case-1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "case-1", "secret.txt"),
		[]byte("A 案材料\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// case-2 会话直接构造(buildTools 只读 sess.CaseID;fake 元数据只播种 case-1)
	sessB := &store.AISession{ID: "sess-b", CaseID: "case-2"}
	tools := svc.buildTools(sessB, ResolvedConfig{})
	list := findTool(t, tools, "workspace_list")
	read := findTool(t, tools, "workspace_read")

	res := callTool(t, list, `{}`)
	if res.IsError || strings.Contains(res.Flatten(), "secret.txt") {
		t.Fatalf("B 案不应见 A 案文件: %s", res.Flatten())
	}
	res = callTool(t, read, `{"path":"secret.txt"}`)
	if !res.IsError || !strings.Contains(res.Flatten(), "无此文件") {
		t.Fatalf("B 案读 A 案文件应无此文件: %s", res.Flatten())
	}
}

// TestWorkspaceToolEscapeRejected 逃逸负样本:../、绝对路径、盘符、
// 反斜杠、NUL 全部软错拒(与 web 端点同一套 workspace.Resolve)。
func TestWorkspaceToolEscapeRejected(t *testing.T) {
	svc, root := newWSSvc(t)
	sess := newSess(t, svc)
	if err := os.WriteFile(filepath.Join(root, "outside.txt"),
		[]byte("根下别的案件的邻居文件\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tools := svc.buildTools(sess, ResolvedConfig{})
	list := findTool(t, tools, "workspace_list")
	read := findTool(t, tools, "workspace_read")

	bad := []string{
		"../outside.txt", "..", "a/../../outside.txt", "/etc/passwd",
		"C:/Windows/system32", "a\\..\\b", "a//b", "a\x00b",
	}
	for _, p := range bad {
		enc := strings.ReplaceAll(strings.ReplaceAll(p, `\`, `\\`), `"`, `\"`)
		if res := callTool(t, list, `{"path":"`+enc+`"}`); !res.IsError {
			t.Fatalf("list 逃逸 %q 应报错", p)
		}
		if res := callTool(t, read, `{"path":"`+enc+`"}`); !res.IsError {
			t.Fatalf("read 逃逸 %q 应报错", p)
		}
	}
	// ../outside.txt 尝试不得读出邻居文件内容
	res := callTool(t, read, `{"path":"../outside.txt"}`)
	if strings.Contains(res.Flatten(), "邻居文件") {
		t.Fatalf("逃逸读到了根下邻居文件: %s", res.Flatten())
	}
}

// TestWorkspaceToolBinaryAndTruncation 二进制如实拒读;超 256KB 截断
// 如实标 truncated,内容不超闸。
func TestWorkspaceToolBinaryAndTruncation(t *testing.T) {
	svc, root := newWSSvc(t)
	sess := newSess(t, svc)
	caseDir := filepath.Join(root, "case-1")
	if err := os.MkdirAll(caseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "blob.bin"),
		[]byte{'P', 'K', 0, 1, 2}, 0o644); err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("a", wsToolReadMaxBytes+100)
	if err := os.WriteFile(filepath.Join(caseDir, "big.log"),
		[]byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	read := findTool(t, svc.buildTools(sess, ResolvedConfig{}), "workspace_read")

	res := callTool(t, read, `{"path":"blob.bin"}`)
	if !res.IsError || !strings.Contains(res.Flatten(), "二进制") {
		t.Fatalf("二进制应拒读: %s", res.Flatten())
	}
	res = callTool(t, read, `{"path":"big.log"}`)
	if res.IsError {
		t.Fatalf("超大应截断而非报错: %s", res.Flatten())
	}
	flat := res.Flatten()
	if !strings.Contains(flat, `"truncated":true`) {
		t.Fatalf("超大应如实标 truncated: %.200s", flat)
	}
	if len(flat) > wsToolReadMaxBytes+2048 { // JSON 包装+note 余量
		t.Fatalf("截断后结果仍超闸: %d", len(flat))
	}
}
