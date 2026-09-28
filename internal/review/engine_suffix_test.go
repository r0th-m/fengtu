// match 后缀语义焊死(0.22.0-treecourt-port):
//   - splitFieldKey 后缀解析(_contains/_prefix/_eq/裸键);
//   - 编译期:去后缀字段校验、同字段多后缀条件共存、重复键拒载;
//   - matchRule:eq/prefix/contains 正负样本、同字段多条件 OR、跨字段 AND、
//     嵌套 data 对象串化匹配、bool 值;
//   - 对拍用例集(testdata/match_parity_cases.json):期望值由树庭
//     backend/app/rules.py _match_fields 跑出(金标准,见 .verify/match_parity.py,
//     20/20 PASS),Go 侧焊死同一结果防漂移;
//   - matchConds:同字段值并集、contains 宽筛下推(eq/prefix ⊆ contains,
//     严判在 Go 复判)。
package review

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSplitFieldKey(t *testing.T) {
	cases := []struct{ key, field, op string }{
		{"ua", "ua", MatchOpContains},
		{"event_id", "event_id", MatchOpContains},
		{"data_contains", "data", MatchOpContains},
		{"key_path_prefix", "key_path", MatchOpPrefix},
		{"event_id_eq", "event_id", MatchOpEq},
		{"exe_name_eq", "exe_name", MatchOpEq},
	}
	for _, c := range cases {
		f, op := splitFieldKey(c.key)
		if f != c.field || op != c.op {
			t.Fatalf("splitFieldKey(%q) = %q,%q;期望 %q,%q", c.key, f, op, c.field, c.op)
		}
	}
}

func TestCompileRuleSuffixes(t *testing.T) {
	r, err := CompileRule("t.yaml", `
id: host-sig
title: t
severity: high
target: any
match:
  event_id_eq: ["7045"]
  channel_eq: [System]
  data_contains: ['\appdata\', '\temp\']
  key_path_prefix: ['software\microsoft']
`)
	if err != nil {
		t.Fatalf("后缀规则编译失败: %v", err)
	}
	if len(r.Match) != 4 {
		t.Fatalf("match 条件数不符: %+v", r.Match)
	}
	if r.Match[0].Field != "event_id" || r.Match[0].Op != MatchOpEq ||
		r.Match[1].Op != MatchOpEq || r.Match[1].Subs[0] != "system" ||
		r.Match[2].Op != MatchOpContains || r.Match[3].Op != MatchOpPrefix {
		t.Fatalf("后缀编译不符(字段/算子/预转小写): %+v", r.Match)
	}

	// 负样本:后缀后字段仍未知 → 拒载
	if _, err := CompileRule("bad.yaml", `
id: bad
title: t
severity: low
target: any
match:
  evil_field_contains: [x]
`); err == nil {
		t.Fatal("未知字段带后缀应拒载")
	}
	// 负样本:同一键重复(YAML 映射重复键,编译期捕获)
	if _, err := CompileRule("bad2.yaml", `
id: bad2
title: t
severity: low
target: any
match:
  event_id_eq: ["1"]
  event_id_eq: ["2"]
`); err == nil {
		t.Fatal("重复键应拒载")
	}
}

// parityCase 对拍用例(与 .verify/match_parity.py 共用一份 JSON)。
type parityCase struct {
	Name   string              `json:"name"`
	Match  map[string][]string `json:"match"`
	Fields map[string]any      `json:"fields"`
	Raw    string              `json:"raw"`
	Expect bool                `json:"expect"`
}

func TestMatchRuleParityWithTreecourt(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "match_parity_cases.json"))
	if err != nil {
		t.Fatalf("对拍用例读取失败: %v", err)
	}
	var doc struct {
		Cases []parityCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("对拍用例解析失败: %v", err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("对拍用例为空")
	}
	for _, c := range doc.Cases {
		// 直接构造编译态 Rule(对拍目标是匹配语义,不是白名单;
		// 用例含 canonical_key/is_ioc 等非白名单字段是有意的——语义对拍
		// 覆盖树庭附录 A 全形态,白名单是另一层闸门)。
		rule := &Rule{ID: "parity", Match: nil}
		for key, vals := range c.Match {
			field, op := splitFieldKey(key)
			subs := make([]string, 0, len(vals))
			for _, v := range vals {
				subs = append(subs, lowerASCII(v))
			}
			rule.Match = append(rule.Match, FieldMatch{Field: field, Op: op, Subs: subs})
		}
		fieldsJSON, _ := json.Marshal(c.Fields)
		_, _, ok := matchRule(rule, string(fieldsJSON), c.Raw)
		if ok != c.Expect {
			t.Fatalf("对拍用例 %q:Go=%v 期望(树庭金标准)=%v", c.Name, ok, c.Expect)
		}
	}
}

// lowerASCII 与编译期 strings.ToLower 同语义(测试内联防循环依赖 import)。
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func TestMatchRuleSuffixSemantics(t *testing.T) {
	// 嵌套 data 串化匹配:HTML 字符不转义(SetEscapeHTML(false) 与 CH 对齐)
	r, err := CompileRule("t.yaml", `
id: nested
title: t
severity: low
target: any
match:
  data_contains: ["a<b"]
`)
	if err != nil {
		t.Fatalf("规则编译失败: %v", err)
	}
	if _, _, ok := matchRule(r, `{"data":{"cmd":"x a<b y"}}`, ""); !ok {
		t.Fatal("嵌套 data 含 HTML 字符应命中(串化不转义)")
	}

	// 同字段多条件 OR:_eq 与 _prefix 任一成立即字段成立
	r2, err := CompileRule("t2.yaml", `
id: samefield
title: t
severity: low
target: any
match:
  exe_name_eq: ["xmrig.exe"]
  exe_name_prefix: ["xmr"]
`)
	if err != nil {
		t.Fatalf("同字段多条件编译失败: %v", err)
	}
	if _, _, ok := matchRule(r2, `{"exe_name":"XMRIG.EXE"}`, ""); !ok {
		t.Fatal("同字段多条件:eq 命中应成立")
	}
	if _, _, ok := matchRule(r2, `{"exe_name":"xmr-miner.exe"}`, ""); !ok {
		t.Fatal("同字段多条件:prefix 命中应成立")
	}
	if _, _, ok := matchRule(r2, `{"exe_name":"notxmrig.exe"}`, ""); ok {
		t.Fatal("同字段多条件:皆不命中应不成立(prefix 不吃中段)")
	}

	// 声明序:首个命中字段记 matched_field
	r3, err := CompileRule("t3.yaml", `
id: order
title: t
severity: low
target: any
match:
  event_id_eq: ["7045"]
  data_contains: ['\appdata\']
`)
	if err != nil {
		t.Fatalf("规则编译失败: %v", err)
	}
	f, _, ok := matchRule(r3, `{"event_id":7045,"data":{"ImagePath":"C:\\X\\AppData\\a.exe"}}`, "")
	if !ok || f != "event_id" {
		t.Fatalf("声明序首个命中字段应为 event_id: %q %v", f, ok)
	}
}

func TestMatchCondsPushdown(t *testing.T) {
	r, err := CompileRule("t.yaml", `
id: push
title: t
severity: low
target: any
match:
  event_id_eq: ["7045"]
  exe_name_eq: ["a.exe"]
  exe_name_prefix: ["b"]
`)
	if err != nil {
		t.Fatalf("规则编译失败: %v", err)
	}
	conds := matchConds(r)
	// 同字段并集合并为一条宽筛;两字段各一条
	if len(conds) != 2 {
		t.Fatalf("下推条件数不符: %+v", conds)
	}
	for _, c := range conds {
		if c.Op != "contains" {
			t.Fatalf("下推统一 contains 宽筛: %+v", c)
		}
	}
	if conds[0].Field != "event_id" || len(conds[0].Values) != 1 ||
		conds[1].Field != "exe_name" || len(conds[1].Values) != 2 {
		t.Fatalf("下推并集不符: %+v", conds)
	}
}
