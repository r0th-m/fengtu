// golden 金标准对照测试:同一输入,Go 引擎输出必须与索图 Python 引擎输出
// 逐条相等(行号/字段/ts_utc/kind/raw/续行计数全等;对照按 JSON 语义,
// 不依赖键序)。golden 由 golden/gen_golden.py 生成并入库。
//
// 已知豁免(如实标注):kind=bad 且原因为「行内 JSON 解析失败: ...」时,
// Python 的报错文本(json.JSONDecodeError.msg)与 Go 的报错文本
// (encoding/json)措辞不同——两边引擎不同,错误文案无法逐字对齐;
// 对照只要求两边 reason 同前缀(即同一失败类别),其余字段全等。
package descform_test

import (
	"encoding/json"
	"iter"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ye-mengwen/fengtu/internal/descform"
	"github.com/ye-mengwen/fengtu/internal/model"
)

var repoRoot = func() string {
	// internal/descform → 仓根
	wd, _ := os.Getwd()
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}()

type goldenCase struct {
	name     string // 用例名(golden 文件同名)
	format   string // 内置格式(与 desc 二选一)
	descFile string // 描述文件(testdata 相对路径)
	input    string // 输入文件(testdata 相对路径)
	tz       string // 源声明时区
}

var goldenCases = []goldenCase{
	{"nginx", "nginx_combined", "", "testdata/nginx/demo-access.log", "Asia/Shanghai"},
	{"nginx-extra", "nginx_combined", "", "testdata/nginx/nginx-extra.log", "Asia/Shanghai"},
	{"oa-audit", "", "testdata/desc/oa-audit-demo.yaml", "testdata/desc/oa-audit.log", "Asia/Shanghai"},
	{"log4j-multiline", "", "testdata/desc/app-log4j.yaml", "testdata/desc/app.log4j", "UTC+8"},
	{"log4j-tight", "", "testdata/desc/app-log4j-tight.yaml", "testdata/desc/app.log4j-tight", "UTC+8"},
	{"json-lines", "", "testdata/desc/app-json.yaml", "testdata/desc/app.jsonlog", "Asia/Shanghai"},
	{"csv-lines", "", "testdata/desc/app-csv.yaml", "testdata/desc/app.csv", "Asia/Shanghai"},
	{"gbk-declared", "", "testdata/desc/app-gbk.yaml", "testdata/desc/app-gbk.log", "Asia/Shanghai"},
	{"gbk-as-utf8", "", "testdata/desc/app-utf8.yaml", "testdata/desc/app-gbk.log", "Asia/Shanghai"},
}

// runCase 跑 Go 引擎,产出 JSON 语义对象序列(与 golden 同构)。
func runCase(t *testing.T, tc goldenCase) []any {
	t.Helper()
	var parse func(lines []string) iter.Seq[model.Record]
	encoding := "utf-8"
	if tc.format != "" {
		if tc.format != descform.NginxCombinedFormatID {
			t.Fatalf("未知内置格式 %s", tc.format)
		}
		parse = descform.ParseNginxCombined
	} else {
		text, err := os.ReadFile(filepath.Join(repoRoot, tc.descFile))
		if err != nil {
			t.Fatalf("desc 读取失败: %v", err)
		}
		d, err := descform.CompileText(string(text))
		if err != nil {
			t.Fatalf("desc 编译失败: %v", err)
		}
		encoding = d.Encoding
		parse = d.Parse
	}
	lines, err := descform.DecodeFile(filepath.Join(repoRoot, tc.input), encoding)
	if err != nil {
		t.Fatalf("输入解码失败: %v", err)
	}
	var out []any
	for rec := range parse(lines) {
		rec.TsUTC = descform.ResolveTsUTC(rec.DTLocal, tc.tz, rec.TsUTCDirect)
		b, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("记录编码失败: %v", err)
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("记录回读失败: %v", err)
		}
		out = append(out, v)
	}
	return out
}

// loadGolden 读 golden JSONL → JSON 语义对象序列。
func loadGolden(t *testing.T, name string) []any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, "golden", name+".golden.jsonl"))
	if err != nil {
		t.Fatalf("golden 读取失败(先用 golden/gen_golden.py 生成): %v", err)
	}
	var out []any
	for i, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		var v any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatalf("golden 第 %d 行 JSON 坏: %v", i+1, err)
		}
		out = append(out, v)
	}
	return out
}

const jsonFailPrefix = "行内 JSON 解析失败: "

// equalRecords 逐条对照;返回首个差异的描述(空串=全等)。
func equalRecords(golden, got []any) string {
	if len(golden) != len(got) {
		return "记录数不等"
	}
	for i := range golden {
		g := golden[i].(map[string]any)
		o := got[i].(map[string]any)
		// JSON 解析失败文案豁免:同前缀即可,其余字段全等
		gr, _ := g["reason"].(string)
		or, _ := o["reason"].(string)
		if strings.HasPrefix(gr, jsonFailPrefix) {
			if !strings.HasPrefix(or, jsonFailPrefix) {
				return "JSON 解析失败类别不一致"
			}
			g["reason"] = jsonFailPrefix
			o["reason"] = jsonFailPrefix
		}
		gb, _ := json.Marshal(g)
		ob, _ := json.Marshal(o)
		if string(gb) != string(ob) {
			return "记录不等:\ngolden: " + string(gb) + "\ngo   : " + string(ob)
		}
	}
	return ""
}

func TestGolden(t *testing.T) {
	for _, tc := range goldenCases {
		t.Run(tc.name, func(t *testing.T) {
			golden := loadGolden(t, tc.name)
			got := runCase(t, tc)
			if diff := equalRecords(golden, got); diff != "" {
				t.Fatalf("golden 对照失败(%s):\n%s", tc.name, diff)
			}
			// 防呆:golden 非空且至少一条 event(nginx 系)
			if len(golden) == 0 {
				t.Fatalf("golden 为空(%s)", tc.name)
			}
		})
	}
}

// TestGoldenStrictFields 显式锚定关键字段语义(防「两边一起错」):
// 行号、kind、ts_utc 规范形、多行 raw 合并、XFF。
func caseByName(t *testing.T, name string) goldenCase {
	t.Helper()
	for _, tc := range goldenCases {
		if tc.name == name {
			return tc
		}
	}
	t.Fatalf("无用例 %s", name)
	return goldenCase{}
}

func TestGoldenStrictFields(t *testing.T) {
	got := runCase(t, caseByName(t, "nginx")) // nginx demo
	first := got[0].(map[string]any)
	if first["line_no"].(float64) != 1 || first["kind"] != "event" {
		t.Fatalf("首记录行号/kind 错: %v", first)
	}
	if first["ts_utc"] != "2026-08-14T02:00:15Z" {
		t.Fatalf("ts_utc 规范形错: %v", first["ts_utc"])
	}

	extra := runCase(t, caseByName(t, "nginx-extra"))
	ev1 := extra[0].(map[string]any)
	if ev1["norm"].(map[string]any)["xff"] != "1.2.3.4, 5.6.7.8" {
		t.Fatalf("XFF 提取错: %v", ev1["norm"])
	}

	ml := runCase(t, caseByName(t, "log4j-tight"))
	ev := ml[0].(map[string]any)
	if ev["continuation_lines"].(float64) != 3 {
		t.Fatalf("截断块续行计数错: %v", ev)
	}
	extras := ev["norm"].(map[string]any)["extras"].(map[string]any)
	if extras["multiline_truncated"] != true {
		t.Fatalf("截断标记缺失: %v", extras)
	}
}
