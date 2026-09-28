// 通用 sequence 链式引擎(0.21.0-operator-port,对照表中档;索图 STAT
// runner _run_sequence 语义逐条对拍):
//
//	同复合键组内按 (ts, line_no) 排序:step1 命中 ≥ min_first_step_count 次
//	(防偶然闸)且最后一次 step1 之后,每步在上一步命中后 window_seconds 内
//	依次出现(滚动窗口,超窗即断链)→ 一条命中,锚点行 = 末步命中行。
//
// 与 web-bruteforce-chain 的分工:爆破链是特化版(失败计数达阈才开窗、
// 一段爆破一次账、ts 缺失降级行距窗),继续服役不动;本引擎是通用版——
// 任意 2~3 步 {field, in} 链全走 YAML params 驱动(扫描→打点→利用等
// 新案型改配置即得,不写 Go)。ts 缺失的事件不参与(对齐索图「时间未知
// 不硬算」),计数如实进 detail。
package operator

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ye-mengwen/fengtu/internal/query"
)

type sequenceChain struct{}

type seqStep struct {
	field string
	set   map[string]bool
	in    []string // 归一化后的值集(排序,人读/留证用)
}

func (sequenceChain) params(spec *Spec) ([]string, []seqStep, int, int, error) {
	keyFields, err := keyFieldsOf(spec, "src_ip")
	if err != nil {
		return nil, nil, 0, 0, err
	}
	window, err := intParam(spec, "window_seconds", 0)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	if window <= 0 {
		return nil, nil, 0, 0, errParam(spec, "window_seconds 必填且须 > 0")
	}
	minFirst, err := intParam(spec, "min_first_step_count", 3)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	if minFirst < 1 {
		minFirst = 1
	}
	raw, ok := spec.Params["steps"]
	if !ok {
		return nil, nil, 0, 0, errParam(spec, "steps 必填(2~3 步,每步 {field, in})")
	}
	list, ok := raw.([]any)
	if !ok || len(list) < 2 || len(list) > 3 {
		return nil, nil, 0, 0, errParam(spec, "steps 须为 2~3 步的列表(每步 {field, in})")
	}
	var steps []seqStep
	for i, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, nil, 0, 0, errParam(spec, fmt.Sprintf("steps[%d] 须为 {field, in} 映射", i))
		}
		field, _ := m["field"].(string)
		if field == "" {
			return nil, nil, 0, 0, errParam(spec, fmt.Sprintf("steps[%d].field 须为非空字段名", i))
		}
		vals, ok := m["in"].([]any)
		if !ok || len(vals) == 0 {
			return nil, nil, 0, 0, errParam(spec, fmt.Sprintf("steps[%d].in 须为非空常量列表", i))
		}
		st := seqStep{field: field, set: map[string]bool{}}
		for _, v := range vals {
			switch t := v.(type) {
			case string:
				if t == "" {
					return nil, nil, 0, 0, errParam(spec, fmt.Sprintf("steps[%d].in 含空值", i))
				}
				st.set[strings.ToLower(t)] = true
			case int:
				st.set[fmt.Sprintf("%d", t)] = true
			case float64:
				if t != float64(int64(t)) {
					return nil, nil, 0, 0, errParam(spec, fmt.Sprintf("steps[%d].in 值须为字符串/整数", i))
				}
				st.set[fmt.Sprintf("%d", int64(t))] = true
			default:
				return nil, nil, 0, 0, errParam(spec, fmt.Sprintf("steps[%d].in 值须为字符串/整数", i))
			}
		}
		for v := range st.set {
			st.in = append(st.in, v)
		}
		sort.Strings(st.in)
		steps = append(steps, st)
	}
	return keyFields, steps, window, minFirst, nil
}

type seqEvent struct {
	ts   float64
	line int
	vals map[string]string // step 字段值(小写化前原文,匹配时转小写)
}

func (sequenceChain) Run(spec *Spec, srcs []Source, stream StreamFunc) ([]Finding, error) {
	keyFields, steps, window, minFirst, err := sequenceChain{}.params(spec)
	if err != nil {
		return nil, err
	}
	stepFields := map[string]bool{}
	for _, s := range steps {
		stepFields[s.field] = true
	}

	var out []Finding
	for _, src := range srcs {
		groups := map[string][]seqEvent{}
		groupVals := map[string][]string{}
		noTS := 0
		serr := stream(src.ID, func(ev query.Event) error {
			if ev.TS == nil {
				noTS++
				return nil // ts 缺失不参与时序链(时间未知不硬算)
			}
			f := fieldsOf(ev.Fields)
			gk, vals, ok := keyOf(f, keyFields)
			if !ok {
				return nil
			}
			se := seqEvent{ts: float64(ev.TS.Unix()), line: ev.LineNo,
				vals: map[string]string{}}
			for sf := range stepFields {
				se.vals[sf] = fieldStr(f, sf)
			}
			if _, ok := groups[gk]; !ok {
				groupVals[gk] = vals
			}
			groups[gk] = append(groups[gk], se)
			return nil
		})
		if serr != nil {
			return out, serr
		}
		for gk, evs := range groups {
			// 组内按 (ts, line_no) 排序(对齐索图 agg_event_series)
			sort.Slice(evs, func(i, j int) bool {
				if evs[i].ts != evs[j].ts {
					return evs[i].ts < evs[j].ts
				}
				return evs[i].line < evs[j].line
			})
			match := func(step seqStep, ev seqEvent) bool {
				v, ok := ev.vals[step.field]
				return ok && v != "" && step.set[strings.ToLower(v)]
			}
			var firstIdx []int
			for i, ev := range evs {
				if match(steps[0], ev) {
					firstIdx = append(firstIdx, i)
				}
			}
			if len(firstIdx) < minFirst {
				continue // 第一步次数闸(防偶然)
			}
			// 链式推进:末次 step1 之后,每步在上一步命中后 window 内找
			// 首个匹配(窗口从上一命中步起算,超窗即断链)
			chain := []int{firstIdx[len(firstIdx)-1]}
			for _, step := range steps[1:] {
				prevTS := evs[chain[len(chain)-1]].ts
				nxt := -1
				for j := chain[len(chain)-1] + 1; j < len(evs); j++ {
					if evs[j].ts-prevTS > float64(window) {
						break // 超窗,链断
					}
					if match(step, evs[j]) {
						nxt = j
						break
					}
				}
				if nxt < 0 {
					break
				}
				chain = append(chain, nxt)
			}
			if len(chain) != len(steps) {
				continue // 链不完整,不命中
			}
			anchor := evs[chain[len(chain)-1]]
			anchorTS := time.Unix(int64(anchor.ts), 0).UTC()
			firstLastTS := time.Unix(int64(evs[firstIdx[len(firstIdx)-1]].ts), 0).UTC()
			var chainLines []int
			for _, j := range chain {
				chainLines = append(chainLines, evs[j].line)
			}
			var stepDesc []string
			for _, s := range steps {
				stepDesc = append(stepDesc,
					fmt.Sprintf("%s in [%s]", s.field, strings.Join(s.in, ",")))
			}
			vals := groupVals[gk]
			out = append(out, Finding{
				SourceID: src.ID, LineNo: anchor.line, TS: &anchorTS,
				MatchedField: strings.Join(keyFields, ","),
				MatchedValue: matchedValueOf(keyFields, vals),
				Detail: map[string]any{
					"kind": "sequence", "key_fields": keyFields,
					"group":              keyStr(keyFields, vals),
					"chain":              strings.Join(stepDesc, " → "),
					"first_step_count":   len(firstIdx),
					"window_seconds":     window,
					"first_step_last_ts": firstLastTS.Format(time.RFC3339),
					"final_ts":           anchorTS.Format(time.RFC3339),
					"chain_line_nos":     chainLines,
					"rep_line_no":        anchor.line,
					"events_without_ts":  noTS,
					"judgement_hint": "链式命中≠成功入侵:正常用户试错后成功同样符合;" +
						"先确认末步的成功语义(哪些值算「成了」是应用属性,params 可配)",
				},
				Evidence: Evidence{IndependentPoints: len(steps), ChainLinked: true},
			})
		}
	}
	return out, nil
}
