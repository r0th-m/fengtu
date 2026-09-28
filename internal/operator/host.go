// 主机取证族算子(evtx;键=事件ID/账户/计算机;事件号/阈值/模式清单全走
// YAML params)。
//
// 判定要点(§6.1 第三层,随命中 detail 返回):
//   - 认证链 4625→4624:先确认账户语义(机器账户$/服务账户的批量失败
//     多为配置问题);成功类型(LogonType)在 detail 里直给;
//   - 驻留链 4698/4702:名实不符只是置疑不是结论——先查任务创建人
//     (SubjectUserName)与软件分发通道(SCCM/域管推送也会建任务)。
package operator

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ye-mengwen/fengtu/internal/query"
)

// ---- 认证链 4625×N → 窗口内 4624(同计算机+同账户) ----

type authChain struct{}

type authKey struct{ computer, account string }

type authState struct {
	fails       int
	anchorLine  int
	anchorTS    *time.Time
	anchorFirst int
	// 窗口锚必须跟最近一次失败走:锚死在「第 N 次失败」上,长周期爆破
	// (第 N 次失败与成功相隔数日,但成功前几秒仍有失败)会永不成链——
	// 2026-09-22 真实勒索案件实战挖出(188 万条 4625 零命中实锤)。
	lastLine int
	lastTS   *time.Time
}

func (authChain) Run(spec *Spec, srcs []Source, stream StreamFunc) ([]Finding, error) {
	thr, err := intParam(spec, "fail_threshold", 10)
	if err != nil {
		return nil, err
	}
	winSec, err := intParam(spec, "window_seconds", 600)
	if err != nil {
		return nil, err
	}
	failEv, err := intParam(spec, "fail_event", 4625)
	if err != nil {
		return nil, err
	}
	successEv, err := intParam(spec, "success_event", 4624)
	if err != nil {
		return nil, err
	}
	if thr < 2 {
		thr = 2
	}
	var out []Finding
	for _, src := range srcs {
		states := map[authKey]*authState{}
		serr := stream(src.ID, func(ev query.Event) error {
			f := fieldsOf(ev.Fields)
			eid, ok := eventIDOf(f)
			if !ok {
				return nil
			}
			if eid != int64(failEv) && eid != int64(successEv) {
				return nil
			}
			account := dataStr(f, "TargetUserName")
			// 结构性排除:空/占位账户与机器账户($ 后缀是协议结构,
			// 不是案件值);服务账户的噪音归人裁决,不替人滤
			if account == "" || account == "-" || strings.HasSuffix(account, "$") {
				return nil
			}
			key := authKey{computer: fieldStr(f, "computer"), account: account}
			st := states[key]
			if st == nil {
				st = &authState{}
				states[key] = st
			}
			switch eid {
			case int64(failEv):
				st.fails++
				if st.fails == 1 {
					st.anchorFirst = ev.LineNo
				}
				if st.fails == thr {
					st.anchorLine, st.anchorTS = ev.LineNo, ev.TS
				}
				st.lastLine, st.lastTS = ev.LineNo, ev.TS
			case int64(successEv):
				if st.fails >= thr && st.lastLine > 0 && ev.LineNo > st.lastLine &&
					(ev.TS == nil || st.lastTS == nil ||
						secondsBetween(*ev.TS, *st.lastTS) <= float64(winSec)) {
					win := -1.0
					if ev.TS != nil && st.lastTS != nil {
						win = secondsBetween(*ev.TS, *st.lastTS)
					}
					out = append(out, Finding{
						SourceID: src.ID, LineNo: ev.LineNo, TS: ev.TS,
						MatchedField: "event_id", MatchedValue: account,
						Snippet: ev.Raw,
						Detail: map[string]any{
							"computer": key.computer, "account": account,
							"logon_type": dataStr(f, "LogonType"),
							"src_ip":     dataStr(f, "IpAddress"),
							"fail_event": failEv, "success_event": successEv,
							"fail_count":      st.fails,
							"fail_first_line": st.anchorFirst,
							"fail_nth_line":   st.anchorLine,
							"fail_last_line":  st.lastLine,
							"success_line":    ev.LineNo,
							"window_seconds":  win,
							"judgement_hint": "先确认账户语义——服务账户/配置错误的批量失败是常态噪音;" +
								"成功事件的 LogonType 与来源 IP 是下一步",
						},
						Evidence: Evidence{IndependentPoints: 2, ChainLinked: true},
					})
					delete(states, key) // 一段爆破一次账,防刷屏
				}
			}
			return nil
		})
		if serr != nil {
			return out, serr
		}
	}
	return out, nil
}

// ---- 驻留链 4698/4702(任务名 vs 动作路径名实不符→置疑) ----

type persistenceTask struct{}

var (
	commandRe   = regexp.MustCompile(`<Command>\s*([^<]+?)\s*</Command>`)
	argumentsRe = regexp.MustCompile(`<Arguments>\s*([^<]*?)\s*</Arguments>`)
)

func compilePatterns(spec *Spec, key string, def []string) ([]*regexp.Regexp, error) {
	list, err := strListParam(spec, key, def)
	if err != nil {
		return nil, err
	}
	out := make([]*regexp.Regexp, 0, len(list))
	for _, p := range list {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("算子 %s 参数 %s 含非法正则 %q: %w",
				spec.ID, key, p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

func (persistenceTask) Run(spec *Spec, srcs []Source, stream StreamFunc) ([]Finding, error) {
	eventIDs, err := strListParam(spec, "events", []string{"4698", "4702"})
	if err != nil {
		return nil, err
	}
	evSet := strSet(eventIDs)
	// 名实不符的两翼都是 spec 数据(默认模式是结构性类目,不是案件值):
	// 「名」像系统/厂商维护任务,「实」却落在临时目录或脚本解释器。
	benignName, err := compilePatterns(spec, "benign_name_patterns",
		[]string{`(?i)(microsoft|windows|google|adobe|intel|nvidia)`})
	if err != nil {
		return nil, err
	}
	suspiciousExec, err := compilePatterns(spec, "suspicious_exec_patterns",
		[]string{
			`(?i)\\(temp|tmp)\\`,
			`(?i)\\users\\public\\`,
			`(?i)\\appdata\\(local|roaming)\\temp\\`,
			`(?i)\b(powershell(\.exe)?|cmd\.exe|wscript\.exe|cscript\.exe|mshta\.exe|rundll32\.exe|regsvr32\.exe)\b`,
		})
	if err != nil {
		return nil, err
	}
	var out []Finding
	for _, src := range srcs {
		serr := stream(src.ID, func(ev query.Event) error {
			f := fieldsOf(ev.Fields)
			eid, ok := eventIDOf(f)
			if !ok {
				return nil
			}
			if !evSet[strconv.FormatInt(eid, 10)] {
				return nil
			}
			content := dataStr(f, "TaskContent")
			if content == "" {
				content = dataStr(f, "Content")
			}
			cmd := ""
			if m := commandRe.FindStringSubmatch(content); m != nil {
				cmd = m[1]
			}
			if cmd == "" {
				return nil // 取不出动作路径则不判,不猜(如实不计)
			}
			args := ""
			if m := argumentsRe.FindStringSubmatch(content); m != nil {
				args = m[1]
			}
			execText := cmd + " " + args
			taskName := dataStr(f, "TaskName")
			nameHit := ""
			for _, re := range benignName {
				if re.MatchString(taskName) {
					nameHit = re.String()
					break
				}
			}
			if nameHit == "" {
				return nil
			}
			execHit := ""
			for _, re := range suspiciousExec {
				if re.MatchString(execText) {
					execHit = re.String()
					break
				}
			}
			if execHit == "" {
				return nil
			}
			out = append(out, Finding{
				SourceID: src.ID, LineNo: ev.LineNo, TS: ev.TS,
				MatchedField: "event_id", MatchedValue: taskName,
				Snippet: ev.Raw,
				Detail: map[string]any{
					"event_id": eid, "task_name": taskName,
					"command": cmd, "arguments": args,
					"computer":             fieldStr(f, "computer"),
					"subject_user":         dataStr(f, "SubjectUserName"),
					"matched_name_pattern": nameHit,
					"matched_exec_pattern": execHit,
					"judgement_hint": "名实不符只是置疑不是结论——先查任务创建人(SubjectUserName)" +
						"与软件分发通道(SCCM/域管推送也会建任务)",
				},
				Evidence: Evidence{IndependentPoints: 1},
			})
			return nil
		})
		if serr != nil {
			return out, serr
		}
	}
	return out, nil
}
