// 建案 KB 预勾选映射测试(0.30.0):五类类型齐全、映射语义(交集即勾/全勾/
// 未知类型空集)、保序。本表是双端单一数据源,缺类/漂移在这里焊死。
package kb

import "testing"

func TestPreselectTableCoversAllTypes(t *testing.T) {
	for _, typ := range []string{"ransomware", "webshell", "intrusion", "data-leak", "other"} {
		if _, ok := PrecheckTags[typ]; !ok {
			t.Fatalf("类型 %s 缺预勾选映射", typ)
		}
	}
}

func TestPreselect(t *testing.T) {
	pool := []*Entry{
		{ID: "e1", AppliesTo: []string{"execution", "sample-recovery"}},
		{ID: "e2", AppliesTo: []string{"timeline"}},
		{ID: "e3", AppliesTo: []string{"persistence"}},
		{ID: "e4", AppliesTo: []string{"entry-point"}},
	}
	eq := func(got []string, want ...string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("预勾选=%v,应=%v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("预勾选=%v,应=%v", got, want)
			}
		}
	}
	// 勒索:五标签全命中(保池序)
	eq(Preselect("ransomware", pool), "e1", "e2", "e3", "e4")
	// WebShell:execution/persistence(applies_to 相交即勾)
	eq(Preselect("webshell", pool), "e1", "e3")
	// 入侵排查/其他:全勾哨兵
	eq(Preselect("intrusion", pool), "e1", "e2", "e3", "e4")
	eq(Preselect("other", pool), "e1", "e2", "e3", "e4")
	// 数据泄露:persistence/timeline
	eq(Preselect("data-leak", pool), "e2", "e3")
	// 未知类型如实空集(不兜底全勾,判断权归人)
	eq(Preselect("no-such-type", pool))
	// 空池任何类型都空
	eq(Preselect("intrusion", nil))
}
