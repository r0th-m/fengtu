// 启发式知识库契约测试:YAML 装载(默认值/负样本/id 冲突)、合一清单
// (builtin+user 标 source)、注入集(0.27.1:本案勾选 ∩ 已知条目,enabled
// 退役不过滤;MaxInject 上限按更新时间截断如实)。
package kb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLoadRealBuiltinDir 真实内置目录焊死:configs/kb 下 32 条
// (0.21.0 及以前 11 条 + 树庭侧族级 11 条 + 0.25.0 数据源解锁族级 3 条
// + 0.32.0 LinuxSC 族级 3 条 + 0.32.1 案件蒸馏 4 条,wer-crash-report
// 为扩写不加数)
// 全量装载,结构与防过拟合闸(零具体案件值)。
func TestLoadRealBuiltinDir(t *testing.T) {
	got, err := LoadBuiltinDir(filepath.Join("..", "..", "configs", "kb"))
	if err != nil {
		t.Fatalf("真实 KB 目录装载失败: %v", err)
	}
	wantIDs := []string{
		// 存量(0.19.0~0.21.0)
		"entry-point-timeline-anchoring", "persistence-surface-crosscheck",
		"ransomware-encryption-window", "web-key-divergence-triage",
		"web-probe-and-rce-signatures", "web-sequence-chain-triage",
		"web-size-outlier-triage", "web-sqli-signatures", "web-xss-signatures",
		"wer-crash-report", "xhost-entity-triage",
		// 树庭侧族级(0.22.0)
		"win-exfil-staging-and-channel", "win-lateral-foothold-triage",
		"ransomware-precursor-shadow", "persistence-writable-dir-signal",
		"remote-access-tool-triage", "miner-multi-view-crosscheck",
		"linux-authlog-bruteforce-review", "linux-persistence-surface",
		"linux-ransomware-triage", "linux-webshell-chain-triage",
		"linux-exfil-staging",
		// 0.25.0-datasource-unlock(数据源解锁族级)
		"command-history-snapshot-triage", "net-connection-snapshot-triage",
		"entity-canonical-layer-triage",
		// 0.32.0-linuxsc(LinuxSC 数据源族级)
		"linux-fileless-memory-triage", "linux-sshd-backdoor-review",
		"linux-rootkit-surface-review",
		// 0.32.1-case-distilled(勒索案排查路径蒸馏;wer-crash-report
		// 为扩写不加数)
		"session-logonid-attribution", "bruteforce-success-validation",
		"pre-auth-system-channel", "historical-compromise-layering",
	}
	if len(got) != len(wantIDs) {
		t.Fatalf("KB 条目数应为 %d(实得 %d)", len(wantIDs), len(got))
	}
	for _, id := range wantIDs {
		e := got[id]
		if e == nil {
			t.Fatalf("KB 条目缺失: %s", id)
		}
		if !e.Enabled {
			t.Fatalf("内置条目 %s 不应出厂即关", id)
		}
	}
	// 防过拟合:零具体案件值
	for id, e := range got {
		for _, bad := range []string{"CASEHOST99", "192.168.", "FAMALPHA", "FAMBETA", "10.99."} {
			if strings.Contains(e.Title+e.Content, bad) {
				t.Fatalf("KB 条目 %s 夹带具体案件值 %q(防过拟合)", id, bad)
			}
		}
	}
}

type fakeStore struct {
	users   []*Entry
	states  map[string]bool
	caseSel map[string][]string // case_id → 勾选条目 id 集(0.20.0)
	nextID  int
}

func newFakeStore() *fakeStore {
	return &fakeStore{states: map[string]bool{}, caseSel: map[string][]string{}}
}

func (f *fakeStore) ListUserKB(_ context.Context) ([]*Entry, error) {
	out := make([]*Entry, len(f.users))
	copy(out, f.users)
	return out, nil
}

func (f *fakeStore) CreateKB(_ context.Context, e *Entry) error {
	f.nextID++
	e.ID = fmt.Sprintf("user-%d", f.nextID)
	e.CreatedAt = time.Now().UTC()
	e.UpdatedAt = e.CreatedAt
	f.users = append(f.users, e)
	return nil
}

func (f *fakeStore) UpdateKB(_ context.Context, e *Entry) (bool, error) {
	for i, u := range f.users {
		if u.ID == e.ID {
			e.CreatedAt = u.CreatedAt
			e.UpdatedAt = time.Now().UTC()
			f.users[i] = e
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeStore) DeleteKB(_ context.Context, id string) (bool, error) {
	for i, u := range f.users {
		if u.ID == id {
			f.users = append(f.users[:i], f.users[i+1:]...)
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeStore) SetBuiltinKBState(_ context.Context, id string, enabled bool) (time.Time, error) {
	f.states[id] = enabled
	return time.Now().UTC(), nil
}

func (f *fakeStore) ListBuiltinKBStates(_ context.Context) (map[string]bool, error) {
	out := map[string]bool{}
	for k, v := range f.states {
		out[k] = v
	}
	return out, nil
}

func (f *fakeStore) ListCaseKB(_ context.Context, caseID string) ([]string, error) {
	return append([]string(nil), f.caseSel[caseID]...), nil
}

func (f *fakeStore) SetCaseKB(_ context.Context, caseID, _ string, ids []string) (added, removed []string, err error) {
	old := map[string]bool{}
	for _, id := range f.caseSel[caseID] {
		old[id] = true
	}
	newSet := map[string]bool{}
	for _, id := range ids {
		newSet[id] = true
		if !old[id] {
			added = append(added, id)
		}
	}
	for id := range old {
		if !newSet[id] {
			removed = append(removed, id)
		}
	}
	f.caseSel[caseID] = append([]string(nil), ids...)
	return added, removed, nil
}

// writeKB 落一个内置条目 YAML(测试夹具)。
func writeKB(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadBuiltinDir(t *testing.T) {
	dir := t.TempDir()
	writeKB(t, dir, "a.yaml", `
id: alpha
title: 甲条目
applies_to: [execution]
content: 怎么找甲。
`)
	writeKB(t, dir, "b.yaml", `
id: beta
title: 乙条目
applies_to: [timeline, persistence]
enabled: false
content: 怎么找乙。
`)
	got, err := LoadBuiltinDir(dir)
	if err != nil {
		t.Fatalf("装载失败: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("条目数: %d", len(got))
	}
	if !got["alpha"].Enabled {
		t.Fatal("enabled 缺省应为开")
	}
	if got["beta"].Enabled {
		t.Fatal("显式 enabled:false 应出厂即关")
	}
	if got["alpha"].Source != SourceBuiltin {
		t.Fatalf("source 应标 builtin: %q", got["alpha"].Source)
	}
	if got["beta"].UpdatedAt.IsZero() {
		t.Fatal("内置条目更新时间应取 YAML 文件 mtime(如实)")
	}
}

func TestLoadBuiltinDirNegative(t *testing.T) {
	cases := map[string]string{
		"缺 title":      "id: x\napplies_to: [execution]\ncontent: 有正文\n",
		"缺 content":    "id: x\ntitle: 有标题\napplies_to: [execution]\n",
		"缺 applies_to": "id: x\ntitle: 有标题\ncontent: 有正文\n",
		"空标签":          "id: x\ntitle: 有标题\napplies_to: [' ']\ncontent: 有正文\n",
	}
	for name, body := range cases {
		dir := t.TempDir()
		writeKB(t, dir, "bad.yaml", body)
		if _, err := LoadBuiltinDir(dir); err == nil {
			t.Fatalf("负样本应拒装: %s", name)
		}
	}
	// id 冲突
	dir := t.TempDir()
	writeKB(t, dir, "a.yaml", "id: dup\ntitle: 一\napplies_to: [execution]\ncontent: 一\n")
	writeKB(t, dir, "b.yaml", "id: dup\ntitle: 二\napplies_to: [timeline]\ncontent: 二\n")
	if _, err := LoadBuiltinDir(dir); err == nil ||
		!strings.Contains(err.Error(), "id 冲突") {
		t.Fatalf("id 冲突应拒装: %v", err)
	}
}

func TestServiceListMergeAndCRUD(t *testing.T) {
	dir := t.TempDir()
	writeKB(t, dir, "a.yaml", "id: alpha\ntitle: 甲\napplies_to: [execution]\ncontent: 找甲\n")
	builtin, err := LoadBuiltinDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := newFakeStore()
	svc := NewService(builtin, st)
	ctx := context.Background()

	// 合一清单:builtin+user 标 source(0.27.1:不再叠 kb_builtin_state 覆写,
	// enabled 语义退役不读不改)
	entries, err := svc.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Source != SourceBuiltin {
		t.Fatalf("合一清单不符: %+v", entries)
	}

	// 用户条目 CRUD
	u, err := svc.CreateUser(ctx, "tester", "我的沉淀", "怎么找丙", []string{"timeline"})
	if err != nil {
		t.Fatal(err)
	}
	if u.ID == "" || u.Source != SourceUser || u.CreatedBy != "tester" {
		t.Fatalf("用户条目回写不符: %+v", u)
	}
	entries, _ = svc.List(ctx)
	if len(entries) != 2 || entries[1].Source != SourceUser {
		t.Fatalf("合一清单应含用户条目: %+v", entries)
	}
	if _, ok, err := svc.UpdateUser(ctx, u.ID, "改后", "改后正文", []string{"execution"}); err != nil || !ok {
		t.Fatalf("用户条目更新失败: %v %v", ok, err)
	}
	entries, _ = svc.List(ctx)
	if entries[1].Title != "改后" {
		t.Fatalf("更新未生效: %+v", entries[1])
	}
	if ok, err := svc.DeleteUser(ctx, u.ID); err != nil || !ok {
		t.Fatalf("用户条目删除失败: %v %v", ok, err)
	}
	if ok, _ := svc.DeleteUser(ctx, u.ID); ok {
		t.Fatal("幽灵删除应 ok=false")
	}
	// 负样本:空标题/空标签
	if _, err := svc.CreateUser(ctx, "tester", " ", "正文", []string{"timeline"}); err == nil {
		t.Fatal("空标题应拒")
	}
	if _, err := svc.CreateUser(ctx, "tester", "标题", "正文", nil); err == nil {
		t.Fatal("空 applies_to 应拒")
	}
}

// TestHeuristicsPoolSorted 全部条目池(0.27.1:enabled 退役,不再过滤),
// 按更新时间新→旧,不截断(截断在 HeuristicsForCase 交集后做)。
func TestHeuristicsPoolSorted(t *testing.T) {
	st := newFakeStore()
	svc := NewService(map[string]*Entry{}, st)
	ctx := context.Background()
	base := time.Now().UTC()
	for i := 0; i < MaxInject+5; i++ {
		e := &Entry{
			ID: fmt.Sprintf("u-%02d", i), Title: fmt.Sprintf("条目 %02d", i),
			Content: "正文", AppliesTo: []string{"execution"}, Source: SourceUser,
			CreatedAt: base.Add(time.Duration(i) * time.Minute),
			UpdatedAt: base.Add(time.Duration(i) * time.Minute),
		}
		st.users = append(st.users, e)
	}
	got, err := svc.Heuristics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != MaxInject+5 { // 全集不截断、不过滤
		t.Fatalf("条目池应为全集 %d 条: %d", MaxInject+5, len(got))
	}
	// 最新在前
	if got[0].ID != fmt.Sprintf("u-%02d", MaxInject+4) {
		t.Fatalf("应按更新时间新→旧: %s", got[0].ID)
	}
}

// TestHeuristicsForCase 案件级勾选注入(0.27.1-kb-simplify):
// 注入 = 本案勾选 ∩ 已知条目(enabled 概念退役,不再交集全局启用——历史
// 禁用条目勾选即注入);本案零勾选(含存量案件零记录)如实空集不注入,
// 不兜底全量;交集超上限按更新时间截断。
func TestHeuristicsForCase(t *testing.T) {
	st := newFakeStore()
	svc := NewService(map[string]*Entry{}, st)
	ctx := context.Background()
	base := time.Now().UTC()
	mk := func(id string, min int) *Entry {
		return &Entry{ID: id, Title: "条目 " + id, Content: "正文",
			AppliesTo: []string{"execution"}, Source: SourceUser, Enabled: true,
			CreatedAt: base.Add(time.Duration(min) * time.Minute),
			UpdatedAt: base.Add(time.Duration(min) * time.Minute)}
	}
	// c 的存量 enabled=false(历史禁用)——0.27.1 起不再影响注入
	st.users = []*Entry{mk("a", 1), mk("b", 2), mk("c", 3)}
	st.users[2].Enabled = false

	// 存量案件(零勾选记录):如实空集,不兜底全量
	got, truncated, err := svc.HeuristicsForCase(ctx, "legacy-case")
	if err != nil || len(got) != 0 || truncated != 0 {
		t.Fatalf("零勾选应如实空集: %v %d %v", len(got), truncated, err)
	}

	// 勾选落库 + 交集注入:勾 a/b/c 全注入(存量 enabled=false 不再过滤)
	if _, _, err := svc.SetCaseEntries(ctx, "case-1", "tester",
		[]string{"a", "b", "c"}); err != nil {
		t.Fatal(err)
	}
	got, truncated, err = svc.HeuristicsForCase(ctx, "case-1")
	if err != nil || truncated != 0 {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].ID != "c" || got[1].ID != "b" || got[2].ID != "a" { // 新→旧
		t.Fatalf("交集注入应为 c,b,a(勾选即注入): %+v", got)
	}
	// 勾选未知条目 400 语义(service 层拒)
	if _, _, err := svc.SetCaseEntries(ctx, "case-1", "tester", []string{"ghost"}); err == nil {
		t.Fatal("未知条目勾选应拒")
	}
	// 勾选差集如实(审计记账用):去掉 a 加上 b 已有 → removed=[a]
	sel, err := svc.CaseEntries(ctx, "case-1")
	if err != nil || len(sel) != 3 {
		t.Fatalf("勾选回读: %v %v", sel, err)
	}
	added, removed, err := svc.SetCaseEntries(ctx, "case-1", "tester", []string{"b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 0 || len(removed) != 2 { // a、c 出局(去重后)
		t.Fatalf("差集如实: added=%v removed=%v", added, removed)
	}
	// 显式零勾选(空数组)= 不注入
	got, _, _ = svc.HeuristicsForCase(ctx, "case-1")
	if len(got) != 1 || got[0].ID != "b" {
		t.Fatalf("勾选覆写未生效: %+v", got)
	}

	// 交集超上限截断:勾 MaxInject+2 条 → 截到 MaxInject,truncated 如实
	st2 := newFakeStore()
	svc2 := NewService(map[string]*Entry{}, st2)
	var ids []string
	for i := 0; i < MaxInject+2; i++ {
		id := fmt.Sprintf("x-%02d", i)
		st2.users = append(st2.users, mk(id, i))
		ids = append(ids, id)
	}
	if _, _, err := svc2.SetCaseEntries(ctx, "case-big", "tester", ids); err != nil {
		t.Fatal(err)
	}
	got, truncated, err = svc2.HeuristicsForCase(ctx, "case-big")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != MaxInject || truncated != 2 {
		t.Fatalf("交集超上限截断: %d 条 truncated=%d", len(got), truncated)
	}
}
