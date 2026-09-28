// Web 日志族算子·切片七补齐(DESIGN §6.1 六族余量:同键异值分化 /
// 异键同值聚簇 / 尺寸离群)。键名/阈值/排除模式全走 YAML params。
//
// 0.21.0-operator-port 对齐索图 STAT runner(backend/app/rules.py)语义:
//   - size_outlier:复合键(key_fields,如 path+method+status)、真中位数
//     (偶数样本取两中值均值,对齐 DuckDB MEDIAN)、严格偏离(>median*r
//     或 <median/r)、max_outliers 按 |值-中位数| 降序拎少数派;
//   - same_key_divergence:复合键 + diverge_field 分桶 + metric 均值
//     max/min 比超阈(min 桶均值为 0 而 max>0 记 ∞ 如实命中);
//   - cross_key_same_value:exclude_value_patterns 正则之外,并行支持
//     exclude_kb 排除清单引用(值小写化后子串包含,对齐索图 load_kb;
//     排除只缩小聚簇,不产生命中——宁漏勿冤)。
//
// 旧配置兼容:单 key_field 配置照常工作(负样本测试焊死)。
//
// 判定要点(§6.1 第三层,随命中 detail 返回):
//   - 同键异值:单一终端高分化是自动化工具迹象,但代理出口/爬虫池亦然;
//   - 异键同值:稀有 UA 跨 IP 是同一工具换址,主流浏览器系结构性排除
//     (排除模式是 spec 数据);
//   - 尺寸离群:同键字节偏离中位数 N 倍——大文件接口/下载页天然离群,
//     先确认该 path 的语义。
package operator

import (
	"sort"
	"strconv"
	"strings"

	"github.com/ye-mengwen/fengtu/internal/query"
)

// keyFieldsOf 取复合键字段列表:key_fields(列表)优先,缺省回落单
// key_field(旧配置兼容);两者都缺用传入缺省字段。
func keyFieldsOf(spec *Spec, def string) ([]string, error) {
	if _, ok := spec.Params["key_fields"]; ok {
		return strListParam(spec, "key_fields", nil)
	}
	single, err := strParam(spec, "key_field", def)
	if err != nil {
		return nil, err
	}
	return []string{single}, nil
}

// keyOf 事件 → 复合键(任一字段缺失/占位 "-" 即不参与,对齐索图
// 「缺任一键字段的事件如实不计,不拿 NULL 凑组」)。
func keyOf(f map[string]any, fields []string) (string, []string, bool) {
	vals := make([]string, len(fields))
	for i, k := range fields {
		v := fieldStr(f, k)
		if v == "" || v == "-" {
			return "", nil, false
		}
		vals[i] = v
	}
	return strings.Join(vals, "\x1f"), vals, true
}

// keyStr 复合键 → 人读串(path=/a method=GET;对齐索图 _key_str)。
func keyStr(fields, vals []string) string {
	parts := make([]string, len(fields))
	for i := range fields {
		parts[i] = fields[i] + "=" + vals[i]
	}
	return strings.Join(parts, " ")
}

// matchedValueOf 命中值:单字段键保持旧形态(裸值),复合键给人读串。
func matchedValueOf(fields, vals []string) string {
	if len(fields) == 1 {
		return vals[0]
	}
	return keyStr(fields, vals)
}

// medianOf 真中位数(偶数样本取两中值均值,对齐 DuckDB MEDIAN)。
func medianOf(sorted []float64) float64 {
	n := len(sorted)
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

// ---- 同键异值分化 ----
//
// 双模式(配置驱动,0.21.0):
//   - 均值比模式(对齐索图 same_key_divergence):声明 diverge_field 即启用——
//     复合键组内按分化字段分桶,metric 均值 max/min ≥ diverge_ratio 且
//     组事件总数 ≥ min_group_events → 一条命中;
//   - distinct 计数模式(旧配置兼容):同键在维度上取值数 ≥ min_distinct。
type keyDivergence struct{}

func (keyDivergence) Run(spec *Spec, srcs []Source, stream StreamFunc) ([]Finding, error) {
	if _, ok := spec.Params["diverge_field"]; ok {
		return divergenceMeanRatio(spec, srcs, stream)
	}
	return divergenceDistinct(spec, srcs, stream)
}

// divergenceMeanRatio 均值比模式(索图 _run_divergence 语义逐条对拍:
// 缺键/缺分化字段的事件不计;metric 非数值不计入均值但计入桶计数;
// min 桶均值为 0 而 max>0 → 无限分化如实命中;锚点=组内最小行号)。
func divergenceMeanRatio(spec *Spec, srcs []Source, stream StreamFunc) ([]Finding, error) {
	keyFields, err := keyFieldsOf(spec, "src_ip")
	if err != nil {
		return nil, err
	}
	divergeField, err := strParam(spec, "diverge_field", "method")
	if err != nil {
		return nil, err
	}
	metric, err := strParam(spec, "metric", "bytes")
	if err != nil {
		return nil, err
	}
	if metric != "bytes" && metric != "status" {
		return nil, errParam(spec, "metric 须为 bytes|status 之一")
	}
	minGroup, err := intParam(spec, "min_group_events", 10)
	if err != nil {
		return nil, err
	}
	if minGroup < 2 {
		minGroup = 2
	}
	ratio, err := floatParam(spec, "diverge_ratio", 3.0)
	if err != nil {
		return nil, err
	}
	if ratio <= 1.0 {
		return nil, errParam(spec, "diverge_ratio 须 > 1.0")
	}

	type bucket struct {
		count     int     // 桶内事件数(含 metric 非数值行,对齐索图 COUNT(*))
		sum       float64 // metric 数值行合计
		numeric   int     // metric 数值行数(AVG 分母,TRY_CAST 非 NULL)
		firstLine int
	}
	var out []Finding
	for _, src := range srcs {
		groups := map[string]map[string]*bucket{}
		firstLines := map[string]int{}
		serr := stream(src.ID, func(ev query.Event) error {
			f := fieldsOf(ev.Fields)
			gk, _, ok := keyOf(f, keyFields)
			if !ok {
				return nil
			}
			dv := fieldStr(f, divergeField)
			if dv == "" || dv == "-" {
				return nil // 无分化字段如实不计(不拿 NULL 凑桶)
			}
			buckets := groups[gk]
			if buckets == nil {
				buckets = map[string]*bucket{}
				groups[gk] = buckets
			}
			b := buckets[dv]
			if b == nil {
				b = &bucket{firstLine: ev.LineNo}
				buckets[dv] = b
			}
			b.count++
			if ev.LineNo < b.firstLine {
				b.firstLine = ev.LineNo
			}
			if raw := fieldStr(f, metric); raw != "" && raw != "-" {
				if v, perr := strconv.ParseFloat(raw, 64); perr == nil {
					b.sum += v
					b.numeric++
				}
			}
			if firstLines[gk] == 0 || ev.LineNo < firstLines[gk] {
				firstLines[gk] = ev.LineNo
			}
			return nil
		})
		if serr != nil {
			return out, serr
		}
		for gk, buckets := range groups {
			total := 0
			for _, b := range buckets {
				total += b.count
			}
			if total < minGroup {
				continue // 小样本噪声闸
			}
			type bucketStat struct {
				value string
				count int
				avg   float64
			}
			var vals []bucketStat
			for dv, b := range buckets {
				if b.numeric == 0 {
					continue // 无 metric 均值的桶不参与分化比较(AVG 自然忽略)
				}
				vals = append(vals, bucketStat{dv, b.count, b.sum / float64(b.numeric)})
			}
			if len(vals) < 2 {
				continue // 不足两个有 metric 的桶,无从分化
			}
			sort.Slice(vals, func(i, j int) bool { return vals[i].value < vals[j].value })
			lo, hi := vals[0].avg, vals[0].avg
			for _, v := range vals[1:] {
				if v.avg < lo {
					lo = v.avg
				}
				if v.avg > hi {
					hi = v.avg
				}
			}
			ratioActual := 0.0
			inf := false
			if lo <= 0 {
				if hi <= 0 {
					continue
				}
				inf = true // 一桶为零一桶非零:无限分化,如实命中
			} else {
				ratioActual = hi / lo
				if ratioActual < ratio {
					continue
				}
			}
			keyVals := strings.Split(gk, "\x1f")
			rep := 0
			for _, b := range buckets {
				if rep == 0 || b.firstLine < rep {
					rep = b.firstLine
				}
			}
			ratioText := "×" + strconv.FormatFloat(ratioActual, 'f', 1, 64)
			var ratioDetail any = ratioActual
			if inf {
				ratioText = "∞"
				ratioDetail = nil
			}
			var bucketList []map[string]any
			for _, v := range vals {
				bucketList = append(bucketList, map[string]any{
					"value": v.value, "count": v.count, "avg": v.avg,
				})
			}
			out = append(out, Finding{
				SourceID: src.ID, LineNo: rep,
				MatchedField: divergeField, MatchedValue: ratioText,
				Detail: map[string]any{
					"kind": "divergence", "key_fields": keyFields,
					"group":         keyStr(keyFields, keyVals),
					"diverge_field": divergeField, "metric": metric,
					"ratio": ratioDetail, "diverge_ratio": ratio,
					"total_events": total, "buckets": bucketList,
					"rep_line_no": rep,
					"judgement_hint": "分化≠异常:正常业务 GET/POST 返回体天然不同;" +
						"同键(路径+IP+UA)跨方法均值比超阈才进待审,交人复核",
				},
				Evidence: Evidence{StatisticalOnly: true, Exclusions: []string{
					"排除业务天然分化(GET 取页面/POST 提表单的返回体差异)",
					"排除错误簇(4xx/5xx 小 body 与 200 大 body 的结构性差异)",
				}},
			})
		}
	}
	return out, nil
}

// divergenceDistinct distinct 计数模式(旧配置兼容:单 key_field +
// dimension + min_distinct;复合 key_fields 亦可用)。
func divergenceDistinct(spec *Spec, srcs []Source, stream StreamFunc) ([]Finding, error) {
	keyFields, err := keyFieldsOf(spec, "src_ip")
	if err != nil {
		return nil, err
	}
	dim, err := strParam(spec, "dimension", "ua")
	if err != nil {
		return nil, err
	}
	minDistinct, err := intParam(spec, "min_distinct", 50)
	if err != nil {
		return nil, err
	}
	if minDistinct < 2 {
		minDistinct = 2
	}
	const sampleCap = 10 // detail 里维度样例上限(全量可检索,不刷屏)
	var out []Finding
	for _, src := range srcs {
		type agg struct {
			values   map[string]int
			vals     []string
			total    int
			lastLine int
		}
		aggs := map[string]*agg{}
		serr := stream(src.ID, func(ev query.Event) error {
			f := fieldsOf(ev.Fields)
			gk, vals, ok := keyOf(f, keyFields)
			if !ok {
				return nil
			}
			val := fieldStr(f, dim)
			if val == "" || val == "-" {
				return nil
			}
			a := aggs[gk]
			if a == nil {
				a = &agg{values: map[string]int{}, vals: vals}
				aggs[gk] = a
			}
			a.values[val]++
			a.total++
			a.lastLine = ev.LineNo
			return nil
		})
		if serr != nil {
			return out, serr
		}
		for _, a := range aggs {
			if len(a.values) < minDistinct {
				continue
			}
			var samples []string
			for v := range a.values {
				if len(samples) >= sampleCap {
					break
				}
				samples = append(samples, v)
			}
			sort.Strings(samples)
			out = append(out, Finding{
				SourceID: src.ID, LineNo: a.lastLine,
				MatchedField: strings.Join(keyFields, ","),
				MatchedValue: matchedValueOf(keyFields, a.vals),
				Detail: map[string]any{
					"key_fields": keyFields, "key": matchedValueOf(keyFields, a.vals),
					"dimension":       dim,
					"distinct_values": len(a.values), "total_events": a.total,
					"min_distinct": minDistinct, "value_samples": samples,
					"judgement_hint": "单一终端高分化=自动化工具迹象(换 UA/扫路径);" +
						"先排除代理出口/爬虫池(多用户共享出口天然高分化)",
				},
				Evidence: Evidence{StatisticalOnly: true, Exclusions: []string{
					"排除代理/NAT 出口(多用户共享,分化是聚合假象)",
					"排除搜索引擎爬虫池与监控探针的多变指纹",
				}},
			})
		}
	}
	return out, nil
}

// ---- 异键同值聚簇(稀有 UA 跨 IP;主流浏览器系前置结构性排除) ----

type crossKeySameValue struct{}

func (crossKeySameValue) Run(spec *Spec, srcs []Source, stream StreamFunc) ([]Finding, error) {
	valueField, err := strParam(spec, "value_field", "ua")
	if err != nil {
		return nil, err
	}
	keyField, err := strParam(spec, "key_field", "src_ip")
	if err != nil {
		return nil, err
	}
	minKeys, err := intParam(spec, "min_keys", 3)
	if err != nil {
		return nil, err
	}
	maxDF, err := intParam(spec, "max_df", 5)
	if err != nil {
		return nil, err
	}
	if minKeys < 2 {
		minKeys = 2
	}
	// 主流浏览器 UA 系结构性排除(品类是结构,不是案件值;spec 可配)
	exclude, err := compilePatterns(spec, "exclude_value_patterns",
		[]string{`(?i)^mozilla/4\.`, `(?i)^mozilla/5\.0.*(chrome|safari|firefox|edge)`})
	if err != nil {
		return nil, err
	}
	// exclude_kb 排除清单(0.21.0,对齐索图 cross_key_same_value:值小写化
	// 后子串包含;与正则并行,任一命中即排除——排除只缩小聚簇,宁漏勿冤)
	kbTokens := spec.ExcludeKBTokens

	type valAgg struct {
		keys      map[string]bool
		df        int
		firstLine int
		firstSrc  string
	}
	var out []Finding
	aggs := map[string]*valAgg{}
	for _, src := range srcs {
		serr := stream(src.ID, func(ev query.Event) error {
			f := fieldsOf(ev.Fields)
			val := fieldStr(f, valueField)
			key := fieldStr(f, keyField)
			if val == "" || val == "-" || key == "" {
				return nil
			}
			for _, re := range exclude {
				if re.MatchString(val) {
					return nil // 主流浏览器系:跨 IP 复现是互联网常态
				}
			}
			valLower := strings.ToLower(val)
			for _, tk := range kbTokens {
				if strings.Contains(valLower, tk) {
					return nil // 排除清单命中(已知爬虫/库默认值)
				}
			}
			a := aggs[val]
			if a == nil {
				a = &valAgg{keys: map[string]bool{}, firstLine: ev.LineNo, firstSrc: src.ID}
				aggs[val] = a
			}
			a.keys[key] = true
			a.df++
			return nil
		})
		if serr != nil {
			return out, serr
		}
	}
	for val, a := range aggs {
		if len(a.keys) < minKeys || a.df > maxDF {
			continue
		}
		var keys []string
		for k := range a.keys {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out = append(out, Finding{
			SourceID: a.firstSrc, LineNo: a.firstLine,
			MatchedField: valueField, MatchedValue: val,
			Detail: map[string]any{
				"value_field": valueField, "value": val,
				"key_field": keyField, "key_count": len(a.keys), "keys": keys,
				"df": a.df, "max_df": maxDF, "min_keys": minKeys,
				"exclude_kb_tokens": len(kbTokens),
				"judgement_hint": "稀有值跨多键=同一工具换址迹象;" +
					"先查该值是什么(框架默认 UA/扫描器指纹),别见到少见就当敌意",
			},
			Evidence: Evidence{IndependentPoints: len(a.keys), ChainLinked: true},
		})
	}
	return out, nil
}

// ---- 尺寸离群(同键字节偏离中位数 N 倍;0.21.0 对齐索图 size_outlier) ----

type sizeOutlier struct{}

// Run 索图 agg_size_outliers/_run_size_outlier 语义逐条对拍:
//   - 复合键(key_fields,如 path+method+status);缺键/metric 非数值不计;
//   - 组内样本 ≥ min_samples 才判;真中位数(偶数取两中值均值);
//     中位数 ≤0 的组不判比率(防除零,如实跳过);
//   - 严格偏离:值 > 中位数×ratio 或 < 中位数÷ratio(双向,偏大偏小都算);
//   - 离群行按 |值-中位数| 降序,每组最多拎 max_outliers 条(少数派);
//   - 锚点=偏离最大的离群行(直指那次异常响应本身)。
//
// 旧配置兼容:单 key_field 配置照常工作(负样本测试焊死)。
func (sizeOutlier) Run(spec *Spec, srcs []Source, stream StreamFunc) ([]Finding, error) {
	keyFields, err := keyFieldsOf(spec, "path")
	if err != nil {
		return nil, err
	}
	bytesField, err := strParam(spec, "bytes_field", "bytes")
	if err != nil {
		return nil, err
	}
	if m, ok := spec.Params["metric"]; ok { // 索图参数名并容(同一字段)
		if s, ok := m.(string); ok && s != "" {
			bytesField = s
		}
	}
	ratio, err := floatParam(spec, "ratio", 3.0)
	if err != nil {
		return nil, err
	}
	if _, ok := spec.Params["deviate_ratio"]; ok { // 索图参数名并容
		ratio, err = floatParam(spec, "deviate_ratio", 3.0)
		if err != nil {
			return nil, err
		}
	}
	minSamples, err := intParam(spec, "min_samples", 10)
	if err != nil {
		return nil, err
	}
	if _, ok := spec.Params["min_group_events"]; ok { // 索图参数名并容
		minSamples, err = intParam(spec, "min_group_events", 10)
		if err != nil {
			return nil, err
		}
	}
	maxOutliers, err := intParam(spec, "max_outliers", 3)
	if err != nil {
		return nil, err
	}
	if ratio < 1.5 {
		ratio = 1.5
	}
	if minSamples < 3 {
		minSamples = 3
	}
	if maxOutliers < 1 {
		maxOutliers = 1
	}
	var out []Finding
	for _, src := range srcs {
		type sample struct {
			bytes float64
			line  int
		}
		type agg struct {
			vals    []string
			samples []sample
		}
		aggs := map[string]*agg{}
		serr := stream(src.ID, func(ev query.Event) error {
			f := fieldsOf(ev.Fields)
			gk, vals, ok := keyOf(f, keyFields)
			if !ok {
				return nil
			}
			rawB := fieldStr(f, bytesField)
			if rawB == "" || rawB == "-" {
				return nil
			}
			b, perr := strconv.ParseFloat(rawB, 64)
			if perr != nil {
				return nil // 字节字段非数值:如实不计
			}
			a := aggs[gk]
			if a == nil {
				a = &agg{vals: vals}
				aggs[gk] = a
			}
			a.samples = append(a.samples, sample{b, ev.LineNo})
			return nil
		})
		if serr != nil {
			return out, serr
		}
		for _, a := range aggs {
			if len(a.samples) < minSamples {
				continue
			}
			sorted := make([]float64, len(a.samples))
			for i, sm := range a.samples {
				sorted[i] = sm.bytes
			}
			sort.Float64s(sorted)
			med := medianOf(sorted)
			if med <= 0 {
				continue // 中位数为零的键不判比率(除零无意义,如实跳过)
			}
			type outlierRow struct {
				line  int
				bytes float64
				dev   float64 // |值-中位数|(索图 ORDER BY ABS(v-median) DESC)
			}
			var flagged []outlierRow
			hi, lo := med*ratio, med/ratio
			for _, sm := range a.samples {
				if sm.bytes > hi || sm.bytes < lo {
					dev := sm.bytes - med
					if dev < 0 {
						dev = -dev
					}
					flagged = append(flagged, outlierRow{sm.line, sm.bytes, dev})
				}
			}
			if len(flagged) == 0 {
				continue
			}
			// 每组拎 |值-中位数| 最大的前 max_outliers 条(少数派,防刷屏)
			sort.Slice(flagged, func(i, j int) bool {
				if flagged[i].dev != flagged[j].dev {
					return flagged[i].dev > flagged[j].dev
				}
				return flagged[i].line < flagged[j].line
			})
			reported := len(flagged)
			if len(flagged) > maxOutliers {
				flagged = flagged[:maxOutliers]
			}
			var outliers []map[string]any
			for _, o := range flagged {
				direction := "偏大"
				if o.bytes < med {
					direction = "偏小"
				}
				outliers = append(outliers, map[string]any{
					"line_no": o.line, "bytes": o.bytes,
					"ratio": o.bytes / med, "direction": direction,
				})
			}
			out = append(out, Finding{
				SourceID: src.ID, LineNo: flagged[0].line,
				MatchedField: strings.Join(keyFields, ","),
				MatchedValue: matchedValueOf(keyFields, a.vals),
				Detail: map[string]any{
					"key_fields": keyFields, "key": matchedValueOf(keyFields, a.vals),
					"bytes_field":  bytesField,
					"median_bytes": med, "samples": len(a.samples),
					"ratio_threshold": ratio, "outlier_count": reported,
					"max_outliers": maxOutliers, "outliers": outliers,
					"judgement_hint": "同键尺寸离群=异常负载(webshell 回显/数据外发/" +
						"探测);先确认该 path 的语义——大文件接口/下载页天然离群",
				},
				Evidence: Evidence{StatisticalOnly: true, Exclusions: []string{
					"排除大文件下载/上传接口(尺寸大是业务属性)",
					"排除错误页/重定向等小尺寸常态簇(向下离群多看语义)",
				}},
			})
		}
	}
	return out, nil
}
