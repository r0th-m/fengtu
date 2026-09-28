// 描述文件编译产物与解析状态机(语义照索图 descriptor.CompiledDesc)。
//
// 与索图同款契约:输入物理行(已按声明编码解码、通用换行切分),
// 产出归一记录流(event/bad/skip,零静默);多行合并只在起始行解析 ts,
// raw 合并续行全文,截断/孤儿如实标注。
package descform

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// CompiledDesc 描述文件编译产物。
type CompiledDesc struct {
	Name      string
	FormatID  string // "desc:<name>"
	Title     string
	Kind      string // regex | json | csv
	FieldMap  map[string]string
	TsField   string
	Encoding  string // 源文件编码(描述文件声明,缺省 utf-8)
	LogType   string // 源品类(可选声明,空 = 无品类,适用域算子按域跳过)
	tsFormats []*parsedTSFormat
	lineRe    *regexp.Regexp
	delimiter rune
	startRe   *regexp.Regexp
	maxCont   int
	maxBytes  int // 代码点计数(对齐 Python len(str) 语义)
}

// Compile 校验过的 spec → 驱动对象。spec 须已过 ValidateDesc
// (LoadDescText 一条龙;对未校验 spec 编译是调用方契约违规)。
func Compile(spec Spec) (*CompiledDesc, error) {
	name, _ := spec["name"].(string)
	title, _ := spec["title"].(string)
	if title == "" {
		title = name
	}
	kind, _ := spec["kind"].(string)
	d := &CompiledDesc{
		Name:     name,
		FormatID: "desc:" + name,
		Title:    title,
		Kind:     kind,
		FieldMap: map[string]string{},
		maxCont:  2000,
		maxBytes: 1000000,
		Encoding: "utf-8",
	}
	for k, v := range spec["field_map"].(map[string]any) {
		d.FieldMap[k], _ = v.(string)
	}
	d.TsField, _ = spec["ts_field"].(string)
	if formats, _ := spec["ts_formats"].([]any); formats != nil {
		for _, f := range formats {
			pf, err := compileTSFormat(f.(string))
			if err != nil {
				return nil, &DescError{Msg: fmt.Sprintf("ts_formats 编译失败: %v", err)}
			}
			d.tsFormats = append(d.tsFormats, pf)
		}
	} // nil(ts_optional raw 源):tsFormats 为空,全部行 ts=nil 如实
	if kind == "regex" {
		re, err := regexp.Compile(spec["line_regex"].(string))
		if err != nil {
			return nil, &DescError{Msg: fmt.Sprintf("line_regex 编译失败: %v", err)}
		}
		d.lineRe = re
	}
	if csvSpec, ok := spec["csv"].(map[string]any); ok {
		delim, _ := csvSpec["delimiter"].(string)
		if delim == "" {
			delim = ","
		}
		// Python csv 要求单字符分隔符(多字符在解析期崩);
		// Go 取首字符,差异如实标注于移植文档
		d.delimiter = []rune(delim)[0]
	}
	if ml, ok := spec["multiline"].(map[string]any); ok {
		if start, _ := ml["start_regex"].(string); start != "" {
			re, err := regexp.Compile(start)
			if err != nil {
				return nil, &DescError{Msg: fmt.Sprintf("multiline.start_regex 编译失败: %v", err)}
			}
			d.startRe = re
		}
		if v, ok := asInt(ml["max_continuation_lines"]); ok {
			d.maxCont = v
		}
		if v, ok := asInt(ml["max_block_bytes"]); ok {
			d.maxBytes = v
		}
	}
	if enc, ok := spec["encoding"].(string); ok && strings.TrimSpace(enc) != "" {
		d.Encoding, _ = LookupEncoding(enc)
	}
	d.LogType, _ = spec["log_type"].(string)
	return d, nil
}

// CompileText YAML 全文 → 校验 + 编译一条龙(解析入口)。
func CompileText(yamlText string) (*CompiledDesc, error) {
	spec, err := LoadDescText(yamlText)
	if err != nil {
		return nil, err
	}
	return Compile(spec)
}

// matchAt 模拟 Python re.match:只在串首锚定匹配(不锚尾)。
func matchAt(re *regexp.Regexp, s string) []int {
	loc := re.FindStringSubmatchIndex(s)
	if loc == nil || loc[0] != 0 {
		return nil
	}
	return loc
}

// ---- 三种 kind 的「行 → 源字段 dict」 ----

// fieldsOf 只派发 regex/json;csv 需要表头列序(columns),由 Parse 状态机
// 单独派发(见 Parse 内的 parseSingle 闭包)。
func (d *CompiledDesc) fieldsOf(raw string) (map[string]any, string) {
	if d.Kind == "json" {
		return d.fieldsJSON(raw)
	}
	return d.fieldsRegex(raw)
}

func (d *CompiledDesc) fieldsRegex(raw string) (map[string]any, string) {
	loc := matchAt(d.lineRe, raw)
	if loc == nil {
		return nil, "不匹配 line_regex 行式"
	}
	fields := map[string]any{}
	names := d.lineRe.SubexpNames()
	for i := 1; i < len(names); i++ {
		if names[i] == "" || loc[2*i] < 0 {
			continue // 未参与匹配的分组(None)不进 fields,与 groupdict 过滤同款
		}
		fields[names[i]] = raw[loc[2*i]:loc[2*i+1]]
	}
	return fields, ""
}

func (d *CompiledDesc) fieldsJSON(raw string) (map[string]any, string) {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var obj any
	if err := dec.Decode(&obj); err != nil {
		return nil, fmt.Sprintf("行内 JSON 解析失败: %v", err)
	}
	if err := ensureEOF(dec); err != nil {
		return nil, fmt.Sprintf("行内 JSON 解析失败: %v", err)
	}
	m, ok := obj.(map[string]any)
	if !ok {
		return nil, "行内 JSON 非对象(每行须为一个 JSON 对象)"
	}
	return m, ""
}

func ensureEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("额外数据(一行须恰好一个 JSON 值)")
		}
		return err
	}
	return nil
}

func (d *CompiledDesc) fieldsCSV(raw string, columns []string) (map[string]any, string) {
	cells, err := parseCSVLine(raw, d.delimiter)
	if err != nil {
		return nil, fmt.Sprintf("行内 CSV 解析失败: %v", err)
	}
	if columns == nil {
		return nil, "缺表头(header 未读到,不猜列序)"
	}
	if len(cells) != len(columns) {
		return nil, fmt.Sprintf("字段数 %d 与表头 %d 不一致(截断/多列)",
			len(cells), len(columns))
	}
	fields := map[string]any{}
	for i, c := range cells {
		fields[columns[i]] = c
	}
	return fields, ""
}

// parseCSVLine 单行 CSV 解析;LazyQuotes 对齐 Python csv 非 strict 的宽容。
func parseCSVLine(raw string, delimiter rune) ([]string, error) {
	r := csv.NewReader(strings.NewReader(raw))
	r.Comma = delimiter
	r.LazyQuotes = true
	r.FieldsPerRecord = -1
	rec, err := r.Read()
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// pyStr 模拟 Python str():JSON 值 → 文本(供 ts_raw)。
func pyStr(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case string:
		return t
	case bool:
		if t {
			return "True"
		}
		return "False"
	case json.Number:
		return pyNumStr(t.String())
	default:
		return fmt.Sprintf("%v", t)
	}
}

// pyNumStr 模拟 Python str(int)/str(float) 的常见形态:
// 整数字面量原样;浮点最短表示,整值浮点补 ".0"(Python str(1.0)="1.0")。
// 已知边界:1e16~1e21 区间 Python 用科学计数而 Go 'g' 不用,如实标注。
func pyNumStr(lit string) string {
	if !strings.ContainsAny(lit, ".eE") {
		return lit
	}
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		return lit
	}
	s := strconv.FormatFloat(f, 'g', -1, 64)
	if !strings.ContainsAny(s, ".eE") && !strings.ContainsAny(s, "inf") {
		s += ".0"
	}
	return s
}

// ---- 源字段 dict → Record(field_map 落归一/extras + 时间解析) ----

func (d *CompiledDesc) build(lineNo int, raw string, fields map[string]any) model.Record {
	norm := map[string]any{}
	extras := map[string]any{}
	for key, value := range fields {
		target, mapped := d.FieldMap[key]
		switch {
		case !mapped:
			extras[key] = value // 未映射字段进 extras,不丢数据
		case target == TsNorm:
			// 行内时间:进 ts_raw/dt_local,不进 norm
		default:
			norm[target] = value
		}
	}
	if len(extras) > 0 {
		norm["extras"] = extras
	}
	// ts_optional(raw 兜底):无 ts_formats 时不做时间解析,ts=nil 如实,恒为事件
	if len(d.tsFormats) == 0 {
		return model.Record{LineNo: lineNo, Raw: raw, Kind: model.KindEvent, Norm: norm}
	}
	tsVal, ok := fields[d.TsField]
	if !ok {
		reason := fmt.Sprintf("缺时间字段 '%s'", d.TsField)
		return model.Record{LineNo: lineNo, Raw: raw, Kind: model.KindBad, Reason: &reason}
	}
	var tsText *string
	if tsVal != nil {
		s := pyStr(tsVal)
		tsText = &s
	}
	text := ""
	if tsText != nil {
		text = *tsText
	}
	dtLocal, ok := parseTimeAny(text, d.tsFormats)
	if !ok {
		reason := fmt.Sprintf("时间解析失败(字段 '%s',ts_formats 全部不匹配)", d.TsField)
		return model.Record{LineNo: lineNo, Raw: raw, Kind: model.KindBad,
			TsRaw: tsText, Reason: &reason}
	}
	return model.Record{LineNo: lineNo, Raw: raw, Kind: model.KindEvent,
		TsRaw: tsText, DTLocal: &dtLocal, Norm: norm}
}

func (d *CompiledDesc) parseSingle(lineNo int, raw string) model.Record {
	fields, errText := d.fieldsOf(raw)
	if fields == nil {
		return model.Record{LineNo: lineNo, Raw: raw, Kind: model.KindBad, Reason: &errText}
	}
	return d.build(lineNo, raw, fields)
}

// finishBlock 多行块收尾:只在起始行解析,raw 合并续行全文,计数如实。
// truncated=合并超上限被截;orphan=截断后无宿主的孤儿续行块(同样如实)。
// parseSingle 由 Parse 注入(csv 需要带表头列序的派发)。
func (d *CompiledDesc) finishBlock(startLine int, parts []string,
	truncated bool, orphan bool,
	parseSingle func(lineNo int, raw string) model.Record) model.Record {
	o := parseSingle(startLine, parts[0])
	o.Raw = strings.Join(parts, "\n") // 坏行也保留整块原文留证
	if o.Kind == model.KindEvent {
		o.ContinuationLines = len(parts) - 1
		extras, _ := o.Norm["extras"].(map[string]any)
		if extras == nil {
			extras = map[string]any{}
		}
		if truncated {
			extras["multiline_truncated"] = true
		}
		if orphan {
			extras["continuation_orphan"] = true
		}
		if len(extras) > 0 {
			o.Norm["extras"] = extras
		}
	} else {
		var marks []string
		if truncated {
			marks = append(marks, "合并超上限被截")
		}
		if orphan {
			marks = append(marks, "孤儿续行块(截断后无宿主)")
		}
		if len(marks) > 0 {
			reason := ""
			if o.Reason != nil {
				reason = *o.Reason
			}
			reason += ";" + strings.Join(marks, ";")
			o.Reason = &reason
		}
	}
	return o
}

// Parse 与索图 CompiledDesc.parse 同契约的解析驱动。
// lines: 物理行(已解码、通用换行切分、不含行尾换行符)。
func (d *CompiledDesc) Parse(lines []string) iter.Seq[model.Record] {
	return func(yield func(model.Record) bool) {
		lineNo := 0
		next := func() (int, string, bool) {
			if lineNo >= len(lines) {
				return 0, "", false
			}
			lineNo++
			return lineNo, lines[lineNo-1], true
		}

		// csv:首条非空行是表头(skip 计数),列序以表头为准不猜
		var columns []string
		if d.Kind == "csv" {
			for {
				no, raw, ok := next()
				if !ok {
					return
				}
				if strings.TrimSpace(raw) == "" {
					if !yield(model.Record{LineNo: no, Raw: raw, Kind: model.KindSkip,
						Reason: strPtr("空行")}) {
						return
					}
					continue
				}
				cells, err := parseCSVLine(raw, d.delimiter)
				if err != nil {
					// 表头都解析不出:如实坏行(索图此处会异常上抛,
					// Go 落 bad 行零静默,差异如实标注)
					if !yield(model.Record{LineNo: no, Raw: raw, Kind: model.KindBad,
						Reason: strPtr(fmt.Sprintf("CSV 表头解析失败: %v", err))}) {
						return
					}
					continue
				}
				columns = cells
				if !yield(model.Record{LineNo: no, Raw: raw, Kind: model.KindSkip,
					Reason: strPtr("CSV 表头(列序依据)")}) {
					return
				}
				break
			}
		}

		// 统一的单行解析派发(csv 带表头列序;regex/json 直接派)
		parseSingle := func(no int, raw string) model.Record {
			if d.Kind == "csv" {
				fields, errText := d.fieldsCSV(raw, columns)
				if fields == nil {
					return model.Record{LineNo: no, Raw: raw, Kind: model.KindBad,
						Reason: &errText}
				}
				return d.build(no, raw, fields)
			}
			return d.parseSingle(no, raw)
		}

		// block = [起始行号, 行原文..., 已合并代码点数, orphan 标记]
		var blockStart int
		var blockParts []string
		var blockChars int
		var blockOrphan bool
		hasBlock := false

		flush := func(truncated bool) bool {
			rec := d.finishBlock(blockStart, blockParts, truncated, blockOrphan, parseSingle)
			hasBlock = false
			return yield(rec)
		}

		for {
			no, raw, ok := next()
			if !ok {
				break
			}
			if strings.TrimSpace(raw) == "" {
				// 空行恒 skip:不打断也不并入多行块
				if !yield(model.Record{LineNo: no, Raw: raw, Kind: model.KindSkip,
					Reason: strPtr("空行")}) {
					return
				}
				continue
			}
			if d.startRe == nil {
				if !yield(parseSingle(no, raw)) {
					return
				}
				continue
			}
			if matchAt(d.startRe, raw) != nil {
				if hasBlock {
					if !flush(false) {
						return
					}
				}
				blockStart, blockParts, blockChars, blockOrphan = no, []string{raw}, runeLen(raw), false
				hasBlock = true
			} else if hasBlock {
				// 合并上限:超界即截断封块(truncated 如实),当前行作孤儿块新起
				if len(blockParts)-1 >= d.maxCont || blockChars+runeLen(raw) > d.maxBytes {
					if !flush(true) {
						return
					}
					blockStart, blockParts, blockChars, blockOrphan = no, []string{raw}, runeLen(raw), true
					hasBlock = true
				} else {
					blockParts = append(blockParts, raw)
					blockChars += runeLen(raw)
				}
			} else {
				if !yield(model.Record{LineNo: no, Raw: raw, Kind: model.KindBad,
					Reason: strPtr("续行无宿主事件(起始正则未匹配,前面没有可并入的事件)")}) {
					return
				}
			}
		}
		if hasBlock {
			flush(false)
		}
	}
}

// runeLen 代码点数(对齐 Python len(str) 的合并字节计数语义)。
func runeLen(s string) int { return utf8.RuneCountInString(s) }

func strPtr(s string) *string { return &s }
