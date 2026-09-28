// 单元/负样本测试:schema 校验、strptime、时区归一、解码、
// 多行截断/孤儿、CSV/JSON 边界——golden 照不到的引擎内面。
package descform

import (
	"strings"
	"testing"
	"time"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// ------------------------------------------------------------ schema 校验

const validDesc = `
name: t-ok
kind: regex
line_regex: '^(?P<ts>\S+) (?P<msg>.*)$'
field_map: {ts: ts_raw, msg: message}
ts_field: ts
ts_formats: ['%Y-%m-%d']
status: draft
`

func TestValidateDescOK(t *testing.T) {
	if _, err := LoadDescText(validDesc); err != nil {
		t.Fatalf("合法 desc 被拒: %v", err)
	}
}

func TestValidateDescProblems(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string // 问题文本须含此子串
	}{
		{"未知键", validDesc + "bogus_key: 1\n", "未知键"},
		{"坏name", strings.Replace(validDesc, "name: t-ok", "name: Bad_Name", 1), "name 缺失或非法"},
		{"缺ts_field", strings.Replace(validDesc, "ts_field: ts\n", "", 1), "ts_field 缺失或不在 field_map 中"},
		{"双时间字段", strings.Replace(validDesc, "msg: message", "msg: ts_raw", 1), "时间字段唯一"},
		{"坏正则", strings.Replace(validDesc, "(?P<ts>", "(?P<ts>(", 1), "line_regex 编译失败"},
		{"无命名分组", strings.Replace(validDesc, "(?P<ts>\\S+)", "(\\S+)", 1) /* 仍剩 msg 分组 */, "field_map 引用了 line_regex 不存在的分组"},
		{"未知归一字段", strings.Replace(validDesc, "msg: message", "msg: nope", 1), "field_map 含未知归一字段"},
		{"空ts_formats", strings.Replace(validDesc, "['%Y-%m-%d']", "[]", 1), "ts_formats 须为非空字符串列表"},
		{"未知编码", validDesc + "encoding: klingon\n", "encoding 未知编码"},
		{"坏status", strings.Replace(validDesc, "status: draft", "status: live", 1), "status 未知"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadDescText(tc.yaml)
			if err == nil {
				t.Fatalf("应拒绝却放行")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("问题文本 %q 不含 %q", err.Error(), tc.want)
			}
		})
	}
}

func TestValidateCSVAndMultiline(t *testing.T) {
	// csv.header 非 true 拒
	badCSV := `
name: t-csv
kind: csv
csv: {delimiter: ',', header: false}
field_map: {ts: ts_raw}
ts_field: ts
ts_formats: ['%Y']
`
	if _, err := LoadDescText(badCSV); err == nil ||
		!strings.Contains(err.Error(), "csv.header 本期仅支持 true") {
		t.Fatalf("csv.header=false 应拒: %v", err)
	}
	// multiline 上限越界拒
	badML := validDesc + `
multiline: {start_regex: '^x', max_continuation_lines: 0}
`
	if _, err := LoadDescText(badML); err == nil ||
		!strings.Contains(err.Error(), "max_continuation_lines 须为 1..100000") {
		t.Fatalf("multiline 上限越界应拒: %v", err)
	}
	// YAML 非映射拒
	if _, err := LoadDescText("- just\n- a\n- list\n"); err == nil {
		t.Fatalf("非映射 YAML 应拒")
	}
}

// ------------------------------------------------------------ strptime

func TestStrptimeBasics(t *testing.T) {
	f, err := compileTSFormat("%Y-%m-%d %H:%M:%S")
	if err != nil {
		t.Fatal(err)
	}
	tm, err := f.parse("2024-05-01 08:00:01")
	if err != nil {
		t.Fatal(err)
	}
	if tm.Year() != 2024 || tm.Month() != 5 || tm.Day() != 1 ||
		tm.Hour() != 8 || tm.Minute() != 0 || tm.Second() != 1 {
		t.Fatalf("解析错: %v", tm)
	}
	// 越界值拒(99-99 与 Python strptime 同款 ValueError)
	if _, err := f.parse("99-99 99:99:99"); err == nil {
		t.Fatalf("越界时间应解析失败")
	}
	// 无年份格式 → 默认 1900(Python strptime 同款)
	f2, _ := compileTSFormat("%m-%d %H:%M:%S")
	tm2, err := f2.parse("04-27 16:26:48")
	if err != nil {
		t.Fatal(err)
	}
	if tm2.Year() != 1900 {
		t.Fatalf("无年份格式默认年应 1900,得 %d", tm2.Year())
	}
}

func TestStrptimeFraction(t *testing.T) {
	f, err := compileTSFormat("%d-%b-%Y %H:%M:%S.%f")
	if err != nil {
		t.Fatal(err)
	}
	tm, err := f.parse("27-Apr-2024 16:26:48.123456")
	if err != nil {
		t.Fatal(err)
	}
	if tm.Nanosecond() != 123456000 {
		t.Fatalf("微秒错: %d", tm.Nanosecond())
	}
	// Python %f 必填:缺小数应失败(Go .999999 本可选,预校验补齐)
	if _, err := f.parse("27-Apr-2024 16:26:48"); err == nil {
		t.Fatalf("缺小数秒应失败(Python %%f 必填)")
	}
	// 1 位小数也合法(Python %f 收 1~6 位)
	if _, err := f.parse("27-Apr-2024 16:26:48.5"); err != nil {
		t.Fatalf("1 位小数应可解析: %v", err)
	}
	// 7 位小数超界
	if _, err := f.parse("27-Apr-2024 16:26:48.1234567"); err == nil {
		t.Fatalf("7 位小数应失败(Python %%f 最多 6 位)")
	}
}

// ------------------------------------------------------------ 时区归一

func TestTZResolve(t *testing.T) {
	// IANA(Go zoneinfo.zip;1992 年后与 Python 兜底表结果一致)
	loc := TZOffset("Asia/Shanghai")
	if loc == nil {
		t.Fatalf("Asia/Shanghai 应可解析")
	}
	// 兜底表(Python 无 tzdata 时同值):2024 年 +08:00
	dl := time.Date(2024, 5, 1, 8, 0, 0, 0, time.UTC)
	ts := ToUTC(&dl, "Asia/Shanghai")
	if ts == nil || ts.Format("2006-01-02T15:04:05Z07:00") != "2024-05-01T00:00:00Z" {
		t.Fatalf("归一错: %v", ts)
	}
	// UTC±x 字面量
	ts2 := ToUTC(&dl, "UTC+8")
	if ts2 == nil || *ts2 != *ts {
		t.Fatalf("UTC+8 字面量应与 Asia/Shanghai(2024)同值: %v", ts2)
	}
	ts3 := ToUTC(&dl, "GMT-5:30")
	if ts3 == nil || ts3.Format("15:04") != "13:30" {
		t.Fatalf("GMT-5:30 归一错: %v", ts3)
	}
	// 未知时区 → nil 如实(不硬归一)
	if ToUTC(&dl, "Mars/Olympus") != nil {
		t.Fatalf("未知时区应 nil")
	}
	if ToUTC(&dl, "") != nil {
		t.Fatalf("空时区声明应 nil")
	}
}

// ------------------------------------------------------------ 解码/切行

func TestSplitLines(t *testing.T) {
	got := SplitLines("a\nb\r\nc\rd\n")
	want := []string{"a", "b", "c", "d"}
	if len(got) != len(want) {
		t.Fatalf("通用换行切分错: %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 行: got %q want %q", i, got[i], want[i])
		}
	}
	if SplitLines("") != nil {
		t.Fatalf("空文本应 0 行")
	}
}

func TestSanitizeUTF8(t *testing.T) {
	// CPython: b"\xe4\xb8".decode("utf-8","replace") == "�"(一个 U+FFFD)
	if got := sanitizeUTF8([]byte("\xe4\xb8")); got != "�" {
		t.Fatalf("截断序列应换一个 U+FFFD: %q", got)
	}
	// b"\xb7A" → "�A"(孤立延续字节 + ASCII)
	if got := sanitizeUTF8([]byte("\xb7A")); got != "�A" {
		t.Fatalf("孤立字节: %q", got)
	}
	// 合法串原样
	if got := sanitizeUTF8([]byte("中文 ok")); got != "中文 ok" {
		t.Fatalf("合法串被改: %q", got)
	}
	// E4 后接 ASCII:极大子串=E4 一个,换 1 个 U+FFFD
	if got := sanitizeUTF8([]byte("\xe4A")); got != "�A" {
		t.Fatalf("半序列+ASCII: %q", got)
	}
}

// ------------------------------------------------------------ 引擎负样本

func compileOrDie(t *testing.T, yaml string) *CompiledDesc {
	t.Helper()
	d, err := CompileText(yaml)
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	return d
}

func collect(d *CompiledDesc, lines []string) []model.Record {
	var out []model.Record
	for r := range d.Parse(lines) {
		out = append(out, r)
	}
	return out
}

func TestEngineBadLineNoSilent(t *testing.T) {
	d := compileOrDie(t, validDesc)
	recs := collect(d, []string{"2024-05-01 hello", "garbage", "", "1900-13-40 x"})
	if len(recs) != 4 {
		t.Fatalf("记录数: %d", len(recs))
	}
	if recs[0].Kind != model.KindEvent {
		t.Fatalf("首行应成事件: %+v", recs[0])
	}
	if recs[1].Kind != model.KindBad || recs[1].Reason == nil {
		t.Fatalf("坏行零静默: %+v", recs[1])
	}
	if recs[2].Kind != model.KindSkip {
		t.Fatalf("空行 skip: %+v", recs[2])
	}
	// 有 ts 但时间解析失败 → bad 且 ts_raw 留证
	if recs[3].Kind != model.KindBad || recs[3].TsRaw == nil {
		t.Fatalf("时间解析失败行: %+v", recs[3])
	}
	// 未映射字段进 extras
	ev := recs[0]
	if ev.Norm["message"] != "hello" {
		t.Fatalf("字段映射错: %v", ev.Norm)
	}
}

func TestMultilineTruncationAndOrphan(t *testing.T) {
	yaml := `
name: t-ml
kind: regex
line_regex: '^(?P<ts>\d{4}-\d{2}-\d{2}) (?P<msg>.*)$'
field_map: {ts: ts_raw, msg: message}
ts_field: ts
ts_formats: ['%Y-%m-%d']
multiline:
  start_regex: '^\d{4}-\d{2}-\d{2} '
  max_continuation_lines: 2
  max_block_bytes: 1024
`
	d := compileOrDie(t, yaml)
	recs := collect(d, []string{
		"orphan line first",       // 无宿主续行 → bad
		"2024-05-01 start",        // block
		"cont one",
		"cont two",
		"cont three",              // 超上限 → 截断封块 + 孤儿块新起
		"2024-05-02 second",
	})
	if len(recs) != 4 {
		t.Fatalf("记录数: %d(%+v)", len(recs), recs)
	}
	if recs[0].Kind != model.KindBad ||
		!strings.Contains(*recs[0].Reason, "续行无宿主事件") {
		t.Fatalf("孤儿续行: %+v", recs[0])
	}
	trunc := recs[1]
	if trunc.Kind != model.KindEvent || trunc.ContinuationLines != 2 {
		t.Fatalf("截断块: %+v", trunc)
	}
	extras, _ := trunc.Norm["extras"].(map[string]any)
	if extras["multiline_truncated"] != true {
		t.Fatalf("截断标记: %v", extras)
	}
	if !strings.Contains(trunc.Raw, "cont two") {
		t.Fatalf("raw 应含续行全文: %q", trunc.Raw)
	}
	orphan := recs[2]
	if orphan.Kind != model.KindBad || !strings.Contains(*orphan.Reason, "孤儿续行块") {
		t.Fatalf("孤儿块: %+v", orphan)
	}
	if recs[3].Kind != model.KindEvent || recs[3].ContinuationLines != 0 {
		t.Fatalf("第二事件: %+v", recs[3])
	}
}

func TestPyStr(t *testing.T) {
	if pyStr("x") != "x" || pyStr(nil) != "None" || pyStr(true) != "True" {
		t.Fatalf("pyStr 基础错")
	}
	if pyNumStr("200") != "200" || pyNumStr("1.5") != "1.5" || pyNumStr("2.0") != "2.0" {
		t.Fatalf("pyNumStr: %q %q %q", pyNumStr("200"), pyNumStr("1.5"), pyNumStr("2.0"))
	}
}

func TestModelJSON(t *testing.T) {
	tm := time.Date(2024, 5, 1, 0, 0, 1, 123456000, time.UTC)
	if model.FormatUTC(tm) != "2024-05-01T00:00:01.123456Z" {
		t.Fatalf("微秒格式: %s", model.FormatUTC(tm))
	}
	if model.FormatUTC(tm.Truncate(time.Second)) != "2024-05-01T00:00:01Z" {
		t.Fatalf("整秒格式: %s", model.FormatUTC(tm.Truncate(time.Second)))
	}
}
