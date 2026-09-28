// Package descform 是描述文件(desc)解析引擎的 Go 移植,语义源为索图 M4
// (backend/app/formats/descriptor.py + base.py + normalize.py)。
//
// 描述文件是数据不是代码:YAML 声明 kind(regex|json|csv)/line_regex/
// field_map/ts_field/ts_formats/multiline/encoding,「加载即校验」
// (schema 不过一律 DescError,零静默),编译成驱动对象 CompiledDesc。
//
// 纪律(与索图同款):
//   - 归一字段词表固定(mini-ECS,见 NormVocab);保留映射值 "ts_raw" 表示
//     该源字段是行内时间——解析进 ts_raw/dt_local,不进 norm;
//   - field_map 未覆盖的源字段进 extras,不丢数据;
//   - 多行合并:ts 只在起始行解析;续行计数如实记 continuation_lines;
//     起始正则未匹配且前面无宿主事件 → 坏行(不静默吞);
//     空行恒 skip(不打断也不并入多行块);
//   - 坏行零静默;行内时区偏移(如 nginx time_local 的 +0800)如实抽进
//     extras 留证,归一只按源声明时区走,不替源裁决。
package descform

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// NormVocab 归一字段词表(mini-ECS):web 族 + 审计族 + 通用族。
var NormVocab = map[string]bool{
	// web 族
	"src_ip": true, "method": true, "path": true, "query": true,
	"status": true, "bytes": true, "ua": true, "referer": true,
	// 审计族
	"actor": true, "action": true, "object": true, "result": true, "detail": true,
	// 通用族(中间件/杂项)
	"level": true, "logger": true, "message": true, "exception": true,
	// 主机族(0.25.0-datasource-unlock:PSHistory 命令历史;与 review
	// 引擎 MatchFields 主机统一面对齐——command 是树庭附录 A 锚字段,
	// cmdline 是丰图主机统一面字段,两者同值双写,规则两侧都能锚)
	"command": true, "cmdline": true,
}

// TsNorm 保留映射值:行内时间字段(进 ts_raw/dt_local,不进 norm)。
const TsNorm = "ts_raw"

// LogTypes 源品类词表(DESIGN §6.1 适用域路由键;desc 可选声明,
// 不声明 = 无品类)。新增品类是数据工作,先加词表再被算子引用。
var LogTypes = map[string]bool{
	"web_access":        true, // Web 访问日志(nginx/apache/iis 族)
	"app_log":           true, // 应用/中间件运行日志
	"audit_log":         true, // 审计日志
	"windows_event_log": true, // Windows 事件日志(evtx 原生路由自带,不经 desc)
	"usn_journal":       true, // USN 变更日志(fsutil /csv;native 路由自带,M3)
	"generic":           true, // 通用行式日志(无族属)
	// 0.25.0-datasource-unlock(树庭附录 A 同名 event_type 对齐)
	"command_history": true, // PowerShell 命令历史(ConsoleHost_history.txt)
	"net_connection":  true, // 网络连接快照(netstat;native 路由自带)
}

var (
	topKeys = map[string]bool{
		"name": true, "title": true, "kind": true, "line_regex": true,
		"json": true, "csv": true, "field_map": true, "ts_field": true,
		"ts_formats": true, "multiline": true, "status": true, "note": true,
		"encoding": true, "log_type": true, "ts_optional": true,
	}
	csvKeys       = map[string]bool{"delimiter": true, "header": true}
	multilineKeys = map[string]bool{
		"start_regex": true, "max_continuation_lines": true, "max_block_bytes": true,
	}
	kinds    = map[string]bool{"regex": true, "json": true, "csv": true}
	statuses = map[string]bool{"draft": true, "review": true, "enable": true}
	nameRe   = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
)

// DescError 描述文件 schema / 加载失败的明确原因
// (缺字段/未知键/坏正则等,问题全部列出,一次说清)。
type DescError struct{ Msg string }

func (e *DescError) Error() string { return e.Msg }

// Spec 是校验通过的描述文件(原样保留的 YAML 映射)。
type Spec map[string]any

// LoadDescText YAML 全文 → 校验过的 spec(YAML 坏/schema 坏 → DescError)。
func LoadDescText(yamlText string) (Spec, error) {
	var data any
	if err := yaml.Unmarshal([]byte(yamlText), &data); err != nil {
		return nil, &DescError{Msg: fmt.Sprintf("YAML 解析失败: %v", err)}
	}
	m, ok := data.(map[string]any)
	if !ok {
		return nil, &DescError{Msg: "描述文件须为 YAML 映射(顶层是键值对)"}
	}
	if err := ValidateDesc(m); err != nil {
		return nil, err
	}
	return m, nil
}

// ValidateDesc 加载即校验:任何一项不过 → DescError(问题全部列出)。
// 通过则返回 nil。纯函数,不碰盘。
func ValidateDesc(data map[string]any) error {
	var problems []string

	var unknown []string
	for k := range data {
		if !topKeys[k] {
			unknown = append(unknown, k)
		}
	}
	if unknown != nil {
		sort.Strings(unknown)
		problems = append(problems,
			fmt.Sprintf("未知键 %v(允许: %v)", unknown, sortedKeys(topKeys)))
	}

	name, _ := data["name"].(string)
	if name == "" || !nameRe.MatchString(name) {
		problems = append(problems, "name 缺失或非法(须小写连字符,如 oa-audit-demo)")
	}

	kind, _ := data["kind"].(string)
	if !kinds[kind] {
		problems = append(problems,
			fmt.Sprintf("kind 缺失或未知: %v(允许: [csv json regex])", data["kind"]))
	}

	if v, ok := data["title"]; ok {
		if _, isStr := v.(string); !isStr {
			problems = append(problems, "title 须为字符串")
		}
	}
	if v, ok := data["note"]; ok {
		if _, isStr := v.(string); !isStr {
			problems = append(problems, "note 须为字符串")
		}
	}
	if v, ok := data["json"]; ok {
		if _, isBool := v.(bool); !isBool {
			problems = append(problems, "json 键只接受布尔值(kind=json 的声明位)")
		}
	}

	// log_type:源品类声明(可选;适用域路由键,DESIGN §6.1——算子按
	// log_type 路由,不声明 = 无品类,适用域算子按域跳过,如实记)
	if v, ok := data["log_type"]; ok {
		s, isStr := v.(string)
		if !isStr || !LogTypes[s] {
			problems = append(problems,
				fmt.Sprintf("log_type 未知: %v(允许: %v)", v, sortedKeys(LogTypes)))
		}
	}

	// encoding:声明源文件编码(缺省 utf-8;GBK 业务日志是常态)
	if enc, ok := data["encoding"]; ok {
		s, isStr := enc.(string)
		if !isStr || strings.TrimSpace(s) == "" {
			problems = append(problems, "encoding 须为非空字符串(如 gbk/utf-8)")
		} else if _, ok := LookupEncoding(s); !ok {
			problems = append(problems,
				fmt.Sprintf("encoding 未知编码: %v", enc))
		}
	}

	status := "draft"
	if v, ok := data["status"]; ok {
		status, _ = v.(string)
	}
	if !statuses[status] {
		problems = append(problems,
			fmt.Sprintf("status 未知: %v(允许: [draft enable review])", data["status"]))
	}

	// kind 专属键
	var lineRe *regexp.Regexp
	if kind == "regex" {
		rawRe, isStr := data["line_regex"].(string)
		if !isStr || rawRe == "" {
			problems = append(problems, "kind=regex 缺 line_regex")
		} else {
			re, err := regexp.Compile(rawRe)
			if err != nil {
				problems = append(problems,
					fmt.Sprintf("line_regex 编译失败: %v", err))
			} else {
				lineRe = re
				if len(re.SubexpNames()) <= 1 {
					problems = append(problems,
						"line_regex 无命名分组(须 (?P<名>...) 覆盖每行结构)")
				}
			}
		}
	}
	if kind == "csv" {
		csvSpec, isMap := data["csv"].(map[string]any)
		if !isMap {
			problems = append(problems, "kind=csv 缺 csv 配置({delimiter, header})")
		} else {
			var bad []string
			for k := range csvSpec {
				if !csvKeys[k] {
					bad = append(bad, k)
				}
			}
			if bad != nil {
				sort.Strings(bad)
				problems = append(problems,
					fmt.Sprintf("csv 含未知键 %v(允许: [delimiter header])", bad))
			}
			delim, isStr := csvSpec["delimiter"].(string)
			if csvSpec["delimiter"] != nil && (!isStr || delim == "") {
				problems = append(problems, "csv.delimiter 须为非空字符串")
			}
			if h, _ := csvSpec["header"].(bool); !h {
				problems = append(problems,
					"csv.header 本期仅支持 true(带表头;无表头则列名无依据,不猜列序)")
			}
		}
	}

	// field_map / ts_field / ts_formats
	// ts_optional: raw 兜底类描述(无时戳行),显式声明后豁免时间字段校验,
	// 全部行 ts=nil 如实,不猜时间。
	tsOptional, _ := data["ts_optional"].(bool)
	fieldMap, _ := data["field_map"].(map[string]any)
	tsField, tsFieldIsStr := data["ts_field"].(string)
	if len(fieldMap) == 0 {
		problems = append(problems, "field_map 缺失或为空({源字段: 归一字段})")
	} else {
		var badNorm []string
		for _, v := range fieldMap {
			if s, ok := v.(string); !ok || (!NormVocab[s] && s != TsNorm) {
				badNorm = append(badNorm, fmt.Sprintf("%v", v))
			}
		}
		if badNorm != nil {
			sort.Strings(badNorm)
			problems = append(problems,
				fmt.Sprintf("field_map 含未知归一字段 %v(允许: %v + 保留值 %s)",
					badNorm, sortedKeys(NormVocab), TsNorm))
		}
		var tsKeys []string
		for k, v := range fieldMap {
			if v == TsNorm {
				tsKeys = append(tsKeys, k)
			}
		}
		if !tsOptional {
			if len(tsKeys) == 0 {
				problems = append(problems,
					"field_map 缺时间字段(须有且仅有一个源字段映射到 ts_raw;无时戳源请显式 ts_optional: true)")
			} else if len(tsKeys) > 1 {
				sort.Strings(tsKeys)
				problems = append(problems,
					fmt.Sprintf("field_map 多个源字段映射到 ts_raw: %v(时间字段唯一)", tsKeys))
			}
			if !tsFieldIsStr {
				problems = append(problems,
					"ts_field 缺失或不在 field_map 中(须指向映射到 ts_raw 的那个源字段)")
			} else if target, ok := fieldMap[tsField]; !ok {
				problems = append(problems,
					"ts_field 缺失或不在 field_map 中(须指向映射到 ts_raw 的那个源字段)")
			} else if target != TsNorm {
				problems = append(problems,
					fmt.Sprintf("ts_field 指向的 %q 未映射到 ts_raw", tsField))
			}
		}
		if kind == "regex" && lineRe != nil {
			groups := map[string]bool{}
			for _, g := range lineRe.SubexpNames()[1:] {
				groups[g] = true
			}
			var bad []string
			for k := range fieldMap {
				if !groups[k] {
					bad = append(bad, k)
				}
			}
			if bad != nil {
				sort.Strings(bad)
				problems = append(problems,
					fmt.Sprintf("field_map 引用了 line_regex 不存在的分组 %v", bad))
			}
		}
	}

	tsFormats, _ := data["ts_formats"].([]any)
	okFormats := len(tsFormats) > 0
	if okFormats {
		for _, f := range tsFormats {
			if s, isStr := f.(string); !isStr || s == "" {
				okFormats = false
				break
			}
		}
	}
	if !okFormats && !tsOptional {
		problems = append(problems,
			"ts_formats 须为非空字符串列表(strptime 格式;无时戳源请显式 ts_optional: true)")
	}

	if ml, ok := data["multiline"]; ok {
		mlMap, isMap := ml.(map[string]any)
		if !isMap {
			problems = append(problems, "multiline 须为映射({start_regex})")
		} else {
			var bad []string
			for k := range mlMap {
				if !multilineKeys[k] {
					bad = append(bad, k)
				}
			}
			if bad != nil {
				sort.Strings(bad)
				problems = append(problems,
					fmt.Sprintf("multiline 含未知键 %v(允许: [max_block_bytes max_continuation_lines start_regex])", bad))
			}
			start, isStr := mlMap["start_regex"].(string)
			if !isStr || start == "" {
				problems = append(problems, "multiline 缺 start_regex")
			} else if _, err := regexp.Compile(start); err != nil {
				problems = append(problems,
					fmt.Sprintf("multiline.start_regex 编译失败: %v", err))
			}
			// 合并上限(无界合并会出 MB 级单事件;必须有界)
			for _, b := range []struct {
				key    string
				lo, hi int
			}{{"max_continuation_lines", 1, 100000}, {"max_block_bytes", 1024, 1900000}} {
				v, exists := mlMap[b.key]
				if !exists {
					continue
				}
				n, isInt := asInt(v)
				if !isInt || n < b.lo || n > b.hi {
					problems = append(problems,
						fmt.Sprintf("multiline.%s 须为 %d..%d 的整数", b.key, b.lo, b.hi))
				}
			}
		}
	}

	if len(problems) > 0 {
		return &DescError{Msg: "描述文件校验未过: " + strings.Join(problems, "; ")}
	}
	return nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// asInt 取整数值;YAML 的 bool 不算整数(与 Python isinstance 判别同款)。
func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case uint64:
		return int(n), true
	case float64:
		if n == float64(int(n)) {
			return int(n), true
		}
	}
	return 0, false
}
