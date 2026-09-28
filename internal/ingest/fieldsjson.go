// fields JSON 快速编码器(管线热路径)。
//
// 为什么不使 encoding/json 的 mapEncoder:它对 map 键排序 + 反射遍历,
// 在 50 万行/分钟/核的预算里是实测热点(pprof: mapEncoder+sort+反射
// 合计 ~15%,叠加 GC 压力)。CH 侧按名抽取(JSONExtract*),键序无语义;
// 转义语义保持 Python json.dumps(ensure_ascii=False) 等价——
// 非 ASCII 原样(UTF-8),只转义引号/反斜杠/控制字符——与引擎
// AppendJSONL 的约定一致(golden 对照按语义比较,不依赖键序)。
package ingest

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// appendFieldsJSON 把归一字段 map 追加编码为 JSON 对象(键序不定)。
// 值类型契约:descform/evtx 转换器产出的 string/bool/json.Number/
// int(64)/float64/nil/map[string]any/[]any;其余类型兜底 json.Marshal
// (如实,不带病静默)。
func appendFieldsJSON(dst []byte, m map[string]any) []byte {
	dst = append(dst, '{')
	first := true
	for k, v := range m {
		if !first {
			dst = append(dst, ',')
		}
		first = false
		dst = appendJSONString(dst, k)
		dst = append(dst, ':')
		dst = appendJSONValue(dst, v)
	}
	return append(dst, '}')
}

func appendJSONValue(dst []byte, v any) []byte {
	switch t := v.(type) {
	case nil:
		return append(dst, "null"...)
	case string:
		return appendJSONString(dst, t)
	case bool:
		return strconv.AppendBool(dst, t)
	case json.Number:
		return append(dst, t.String()...)
	case int:
		return strconv.AppendInt(dst, int64(t), 10)
	case int64:
		return strconv.AppendInt(dst, t, 10)
	case float64:
		return strconv.AppendFloat(dst, t, 'g', -1, 64)
	case map[string]any:
		return appendFieldsJSON(dst, t)
	case []any:
		dst = append(dst, '[')
		for i, e := range t {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendJSONValue(dst, e)
		}
		return append(dst, ']')
	case []string:
		dst = append(dst, '[')
		for i, e := range t {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendJSONString(dst, e)
		}
		return append(dst, ']')
	default:
		// 契约外类型:兜底标准库(保留可见错误而非静默丢字段)
		b, err := json.Marshal(t)
		if err != nil {
			return append(dst, fmt.Sprintf("%q", fmt.Sprintf("<编码失败: %v>", err))...)
		}
		return append(dst, b...)
	}
}

// appendJSONString JSON 字符串转义(Python ensure_ascii=False 等价:
// 非 ASCII 原样;" \ 与控制字符按 JSON 规则转义;HTML 字符不转义)。
func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' {
			continue
		}
		dst = append(dst, s[start:i]...)
		switch c {
		case '"':
			dst = append(dst, `\"`...)
		case '\\':
			dst = append(dst, `\\`...)
		case '\n':
			dst = append(dst, `\n`...)
		case '\r':
			dst = append(dst, `\r`...)
		case '\t':
			dst = append(dst, `\t`...)
		default:
			dst = append(dst, fmt.Sprintf(`\u%04x`, c)...)
		}
		start = i + 1
	}
	dst = append(dst, s[start:]...)
	return append(dst, '"')
}
