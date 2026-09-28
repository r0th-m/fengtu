// 算子公共助手:字段取值(fields JSON 顶层 / evtx data 子对象)、
// params 取值(全部走 YAML spec,缺省值在代码里声明一次)。
package operator

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// fieldsOf 解析事件 fields JSON(坏 JSON → 空 map,不炸流)。
func fieldsOf(fieldsJSON string) map[string]any {
	if fieldsJSON == "" {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(fieldsJSON), &m); err != nil {
		return map[string]any{}
	}
	return m
}

func asStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	default:
		return ""
	}
}

// fieldStr 顶层字段文本值(缺失/类型不符 → 空)。
func fieldStr(fields map[string]any, key string) string { return asStr(fields[key]) }

// dataStr evtx data 子对象字段文本值(顶层没有再看 data,一层兜底)。
func dataStr(fields map[string]any, key string) string {
	if v := asStr(fields[key]); v != "" {
		return v
	}
	if sub, ok := fields["data"].(map[string]any); ok {
		return asStr(sub[key])
	}
	return ""
}

// eventIDOf evtx event_id 字段。
func eventIDOf(fields map[string]any) (int64, bool) {
	switch v := fields["event_id"].(type) {
	case float64:
		return int64(v), true
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		return n, err == nil
	}
	return 0, false
}

// ---- params 取值(spec 是数据;类型不符即拒,不静默降级) ----

func intParam(spec *Spec, key string, def int) (int, error) {
	v, ok := spec.Params[key]
	if !ok {
		return def, nil
	}
	switch n := v.(type) {
	case int:
		return n, nil
	case float64:
		if n == float64(int(n)) {
			return int(n), nil
		}
	}
	return 0, fmt.Errorf("算子 %s 参数 %s 须为整数", spec.ID, key)
}

// strParam 字符串参数(键名类:field/dimension 等)。
func strParam(spec *Spec, key string, def string) (string, error) {
	v, ok := spec.Params[key]
	if !ok {
		return def, nil
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("算子 %s 参数 %s 须为非空字符串", spec.ID, key)
	}
	return s, nil
}

func floatParam(spec *Spec, key string, def float64) (float64, error) {	v, ok := spec.Params[key]
	if !ok {
		return def, nil
	}
	switch n := v.(type) {
	case float64:
		return n, nil
	case int:
		return float64(n), nil
	}
	return 0, fmt.Errorf("算子 %s 参数 %s 须为数值", spec.ID, key)
}

func strListParam(spec *Spec, key string, def []string) ([]string, error) {
	v, ok := spec.Params[key]
	if !ok {
		return def, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("算子 %s 参数 %s 须为字符串列表", spec.ID, key)
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("算子 %s 参数 %s 须为字符串列表", spec.ID, key)
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("算子 %s 参数 %s 空列表", spec.ID, key)
	}
	return out, nil
}

func strSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

// secondsBetween 两时刻差(秒,绝对值)。
func secondsBetween(a, b time.Time) float64 {
	d := b.Sub(a)
	if d < 0 {
		d = -d
	}
	return d.Seconds()
}
