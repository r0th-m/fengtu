// 主机取证族算子·切片七补齐(DESIGN §6.1:7045 新服务 / 进程树异常 /
// 时间簇 / 凭据面)。全部对 spec 写:事件号/路径白名单/模式清单/阈值
// 全走 YAML params,任何案件值进代码判负。
//
// 金标准对照(v1 树庭 Python 语义,backend/rules/builtin/ 与
// backend/app/efu_anomaly.py):
//   - 7045 新服务:v1 lateral-service-installed(7045 全量 medium)+
//     lateral-service-writable-dir(映像在可写目录 high)两规则合并为
//     一个算子两翼——路径命中可写目录模式 → 两点咬合(强疑似),否则单点
//     (疑似);创建账户/启动类型 detail 直给;
//   - 进程树异常(相似名×异常位置):名似系统进程(精确同名或编辑距离 1
//     的形近)且路径不在系统目录白名单——白名单是 spec 数据(KB 语义,
//     不写死);4688 的 NewProcessName 是全路径,目录判定按前缀;
//   - 时间簇(窗口内海量写/改名):v1 efu_anomaly 滑窗语义移植到 USN
//     变更事件流——按原因位(写/改名/建/删,params 可配)过滤,双指针
//     找最密窗,窗内事件数达阈即簇;每源只报最密一簇(防刷屏);
//   - 凭据面(SAM 访问/4648):4648 显式凭据登录(localhost/占位目标
//     结构性排除)+ SAM/SECURITY hive 对象访问(进程白名单是 spec 数据,
//     lsass/winlogon 等系统进程访问是常态)。
package operator

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ye-mengwen/fengtu/internal/query"
)

// ---- 7045 新服务(v1 lateral-service-* 两规则合并两翼) ----

type serviceInstall struct{}

func (serviceInstall) Run(spec *Spec, srcs []Source, stream StreamFunc) ([]Finding, error) {
	eventIDs, err := strListParam(spec, "events", []string{"7045"})
	if err != nil {
		return nil, err
	}
	evSet := strSet(eventIDs)
	// 可写目录模式(v1 lateral-service-writable-dir 同款语义,spec 数据)
	writable, err := compilePatterns(spec, "writable_dir_patterns",
		[]string{`(?i)\\appdata\\`, `(?i)\\temp\\`, `(?i)\\tmp\\`,
			`(?i)\\programdata\\`, `(?i)\\users\\public\\`,
			`(?i)\\windows\\(temp|debug)\\`,
			`(?i)\b(powershell(\.exe)?|cmd\.exe|mshta\.exe|rundll32\.exe)\b.*-(e|en|enc)\b`})
	if err != nil {
		return nil, err
	}
	var out []Finding
	for _, src := range srcs {
		serr := stream(src.ID, func(ev query.Event) error {
			f := fieldsOf(ev.Fields)
			eid, ok := eventIDOf(f)
			if !ok || !evSet[strconv.FormatInt(eid, 10)] {
				return nil
			}
			imagePath := dataStr(f, "ImagePath")
			serviceName := dataStr(f, "ServiceName")
			if imagePath == "" && serviceName == "" {
				return nil // 取不出语义字段不判(如实不计)
			}
			pathHit := ""
			for _, re := range writable {
				if re.MatchString(imagePath) {
					pathHit = re.String()
					break
				}
			}
			evd := Evidence{IndependentPoints: 1}
			if pathHit != "" {
				// 两翼咬合:新服务安装 + 映像落可写目录(v1 high 语义)
				evd = Evidence{IndependentPoints: 2, ChainLinked: true}
			}
			out = append(out, Finding{
				SourceID: src.ID, LineNo: ev.LineNo, TS: ev.TS,
				MatchedField: "event_id", MatchedValue: serviceName,
				Snippet: ev.Raw,
				Detail: map[string]any{
					"event_id": eid, "service_name": serviceName,
					"image_path": imagePath,
					"start_type": dataStr(f, "StartType"),
					"account":    dataStr(f, "ServiceStartAccount"),
					"computer":   fieldStr(f, "computer"),
					"writable_dir_hit": pathHit,
					"judgement_hint": "7045 合法部署也触发——先看映像路径与创建账户;" +
						"落可写目录是横向移动/木马服务强信号(v1 两级语义)",
				},
				Evidence: evd,
			})
			return nil
		})
		if serr != nil {
			return out, serr
		}
	}
	return out, nil
}

// ---- 进程树异常(相似名 × 异常位置) ----

type processTreeAnomaly struct{}

// lev1 编辑距离 ≤1 判定(早退;只对长度差 ≤1 的串算)。
func lev1(a, b string) bool {
	if a == b {
		return false // 精确同名不算「形近」,调用方分列
	}
	la, lb := len(a), len(b)
	if la-lb > 1 || lb-la > 1 {
		return false
	}
	// 单趟对齐计数(允许替换/插删各一)
	i, j, edits := 0, 0, 0
	for i < la && j < lb {
		if a[i] == b[j] {
			i++
			j++
			continue
		}
		edits++
		if edits > 1 {
			return false
		}
		switch {
		case la == lb:
			i++
			j++
		case la < lb:
			j++
		default:
			i++
		}
	}
	if i < la || j < lb {
		edits++
	}
	return edits <= 1
}

// normPath 路径归一(正斜杠→反斜杠,小写,去引号/首尾空白)。
func normPath(p string) string {
	p = strings.Trim(strings.TrimSpace(p), `"'`)
	p = strings.ReplaceAll(p, "/", "\\")
	return strings.ToLower(p)
}

// baseName 路径基名(去扩展名由调用方做)。
func baseName(p string) string {
	if i := strings.LastIndexAny(p, "\\/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func (processTreeAnomaly) Run(spec *Spec, srcs []Source, stream StreamFunc) ([]Finding, error) {
	eventIDs, err := strListParam(spec, "events", []string{"4688"})
	if err != nil {
		return nil, err
	}
	evSet := strSet(eventIDs)
	targets, err := strListParam(spec, "lookalike_targets",
		[]string{"svchost", "lsass", "csrss", "explorer", "rundll32", "services",
			"winlogon", "taskhost", "sihost", "runtimebroker"})
	if err != nil {
		return nil, err
	}
	// 系统目录白名单(KB 语义,spec 数据不写死):精确同名的系统进程落在
	// 这些前缀下 = 正常,不判
	sysDirs, err := strListParam(spec, "system_dirs",
		[]string{`c:\windows\system32\`, `c:\windows\syswow64\`,
			`c:\windows\winsxs\`, `c:\windows\servicing\`,
			`c:\program files\`, `c:\program files (x86)\`})
	if err != nil {
		return nil, err
	}
	sysNorm := make([]string, 0, len(sysDirs))
	for _, d := range sysDirs {
		sysNorm = append(sysNorm, normPath(d))
	}

	var out []Finding
	for _, src := range srcs {
		serr := stream(src.ID, func(ev query.Event) error {
			f := fieldsOf(ev.Fields)
			eid, ok := eventIDOf(f)
			if !ok || !evSet[strconv.FormatInt(eid, 10)] {
				return nil
			}
			procPath := dataStr(f, "NewProcessName")
			if procPath == "" {
				procPath = dataStr(f, "ProcessName")
			}
			if procPath == "" || !strings.Contains(procPath, `\`) {
				return nil // 无路径(内核进程等)不判,不猜
			}
			norm := normPath(procPath)
			base := baseName(norm)
			baseNoExt := strings.TrimSuffix(base, ".exe")
			target, simType := "", ""
			for _, tg := range targets {
				if baseNoExt == tg {
					target, simType = tg, "exact"
					break
				}
				if lev1(baseNoExt, tg) {
					target, simType = tg, "edit1"
					break
				}
			}
			if target == "" {
				return nil
			}
			whitelisted := false
			for _, d := range sysNorm {
				if strings.HasPrefix(norm, d) {
					whitelisted = true
					break
				}
			}
			if whitelisted && simType == "exact" {
				return nil // 真系统进程在系统目录:正常
			}
			// 形近名(edit1)落在哪都可疑(系统目录里出现形近名仍是强信号——
			// 白名单护的是真名);精确同名要求位置异常才判
			evd := Evidence{IndependentPoints: 1}
			if simType == "exact" {
				// 两翼咬合:自称系统进程 + 位置反驳
				evd = Evidence{IndependentPoints: 2, ChainLinked: true}
			}
			out = append(out, Finding{
				SourceID: src.ID, LineNo: ev.LineNo, TS: ev.TS,
				MatchedField: "process", MatchedValue: base,
				Snippet: ev.Raw,
				Detail: map[string]any{
					"event_id": eid, "process_path": procPath,
					"lookalike_target": target, "similarity": simType,
					"whitelisted_path":   whitelisted,
					"command_line":       dataStr(f, "CommandLine"),
					"parent_process":     dataStr(f, "ParentProcessName"),
					"subject_user":       dataStr(f, "SubjectUserName"),
					"computer":           fieldStr(f, "computer"),
					"judgement_hint": "形近名/错位进程是仿冒经典手法——核实父进程与" +
						"命令行;软件自更新/便携版也会落在用户目录,别一见就定性",
				},
				Evidence: evd,
			})
			return nil
		})
		if serr != nil {
			return out, serr
		}
	}
	return out, nil
}

// ---- 时间簇(窗口内海量写/改名;USN 变更事件流,v1 efu_anomaly 滑窗语义) ----

type timeCluster struct{}

// extraStr 归一 extras 子对象取值(desc 未映射字段的留证位)。
func extraStr(fields map[string]any, key string) string {
	if sub, ok := fields["extras"].(map[string]any); ok {
		return asStr(sub[key])
	}
	return ""
}

func (timeCluster) Run(spec *Spec, srcs []Source, stream StreamFunc) ([]Finding, error) {
	winSec, err := intParam(spec, "window_seconds", 300)
	if err != nil {
		return nil, err
	}
	minEvents, err := intParam(spec, "min_events", 100)
	if err != nil {
		return nil, err
	}
	if minEvents < 2 {
		minEvents = 2
	}
	// 写/改名原因位(USN_REASON_* winnt.h 结构常量,spec 数据可配):
	// DATA_OVERWRITE 0x1 | DATA_EXTEND 0x2 | DATA_TRUNCATION 0x4 |
	// FILE_CREATE 0x100 | FILE_DELETE 0x200 | RENAME_OLD 0x1000 | RENAME_NEW 0x2000
	reasonBits, err := intParam(spec, "reason_bits", 0x2307)
	if err != nil {
		return nil, err
	}
	// 底噪后缀排除(v1 EXT_EXCLUDE_DEFAULT 同款语义,spec 数据)
	extExclude, err := strListParam(spec, "ext_exclude",
		[]string{"exe", "dll", "sys", "log", "ini", "tmp", "lnk", "pf", "etl",
			"evtx", "mui", "cat", "man", "xml", "dat", "pdb", "cache", "db"})
	if err != nil {
		return nil, err
	}
	extExSet := strSet(extExclude)

	var out []Finding
	for _, src := range srcs {
		// 先收集该源(路径, ts)序列(过滤原因位+底噪后缀后)
		type chEv struct {
			ts   *time.Time
			line int
			path string
		}
		var seq []chEv
		noTS := 0
		serr := stream(src.ID, func(ev query.Event) error {
			f := fieldsOf(ev.Fields)
			// 原因编号:desc 契约进 extras.reason_hex(0x????????);
			// 无原因字段的源(非 USN)不参与,如实
			rh := extraStr(f, "reason_hex")
			if rh == "" {
				rh = fieldStr(f, "reason_hex")
			}
			if rh == "" {
				return nil
			}
			bits, perr := strconv.ParseUint(strings.TrimPrefix(rh, "0x"), 16, 64)
			if perr != nil {
				return nil
			}
			if int(bits)&reasonBits == 0 {
				return nil // 非写/改名类变更
			}
			path := fieldStr(f, "path")
			if path == "" {
				path = extraStr(f, "path")
			}
			ext := ""
			if i := strings.LastIndex(path, "."); i >= 0 {
				ext = strings.ToLower(path[i+1:])
			}
			if extExSet[ext] {
				return nil // 底噪后缀(系统/程序自身活动常态)
			}
			if ev.TS == nil {
				noTS++
				return nil // 无 ts 不参与滑窗(不猜时区是硬纪律)
			}
			seq = append(seq, chEv{ts: ev.TS, line: ev.LineNo, path: path})
			return nil
		})
		if serr != nil {
			return out, serr
		}
		if len(seq) < minEvents {
			continue
		}
		// 流按行号序,滑窗按 ts——先按 ts 排序(行序≈时序是常态但不保证)
		sort.Slice(seq, func(i, j int) bool { return seq[i].ts.Before(*seq[j].ts) })
		// 双指针最密窗(v1 efu_anomaly 同款:窗内计数达阈即簇,每源只报最密一簇)
		bestLo, bestHi, bestN := -1, -1, 0
		hi := 0
		for lo := 0; lo < len(seq); lo++ {
			if hi < lo {
				hi = lo
			}
			for hi < len(seq) && seq[hi].ts.Sub(*seq[lo].ts).Seconds() <= float64(winSec) {
				hi++
			}
			if n := hi - lo; n > bestN {
				bestN, bestLo, bestHi = n, lo, hi-1
			}
		}
		if bestN < minEvents {
			continue
		}
		// 簇内后缀分布(detail 直给原始统计量)
		extCount := map[string]int{}
		for i := bestLo; i <= bestHi; i++ {
			ext := "(无后缀)"
			if j := strings.LastIndex(seq[i].path, "."); j >= 0 {
				ext = strings.ToLower(seq[i].path[j+1:])
			}
			extCount[ext]++
		}
		out = append(out, Finding{
			SourceID: src.ID, LineNo: seq[bestLo].line, TS: seq[bestLo].ts,
			MatchedField: "time_cluster", MatchedValue: fmt.Sprintf("%d events", bestN),
			Detail: map[string]any{
				"window_seconds": winSec,
				"window_start":   seq[bestLo].ts.UTC().Format("2006-01-02T15:04:05Z"),
				"window_end":     seq[bestHi].ts.UTC().Format("2006-01-02T15:04:05Z"),
				"events_in_window": bestN, "min_events": minEvents,
				"reason_bits": fmt.Sprintf("0x%08x", reasonBits),
				"ext_breakdown": extCount,
				"first_line":    seq[bestLo].line, "last_line": seq[bestHi].line,
				"events_without_ts": noTS,
				"judgement_hint": "海量写/改名=加密行为候选,但编译产出/同步盘/备份" +
					"同样可命中(v1 诚实边界)——对照后缀分布与进程上下文再定性",
			},
			Evidence: Evidence{StatisticalOnly: true, Exclusions: []string{
				"排除编译产出/同步盘/备份窗口等合法批量写(对照后缀分布)",
				"排除系统更新/索引重建等周期性大批量变更",
			}},
		})
	}
	return out, nil
}

// ---- 凭据面(SAM 访问 / 4648 显式凭据登录) ----

type credentialFace struct{}

func (credentialFace) Run(spec *Spec, srcs []Source, stream StreamFunc) ([]Finding, error) {
	explicitEvs, err := strListParam(spec, "explicit_events", []string{"4648"})
	if err != nil {
		return nil, err
	}
	samEvs, err := strListParam(spec, "sam_events", []string{"4656", "4663"})
	if err != nil {
		return nil, err
	}
	explicitSet, samSet := strSet(explicitEvs), strSet(samEvs)
	// SAM/SECURITY hive 对象模式(注册表配置单元路径是结构,不是案件值)
	samObj, err := compilePatterns(spec, "sam_object_patterns",
		[]string{`(?i)\\REGISTRY\\MACHINE\\(SAM|SECURITY)`,
			`(?i)HKLM\\(SAM|SECURITY)`, `(?i)\bSAM\.dll`})
	if err != nil {
		return nil, err
	}
	// 系统进程访问 SAM 是常态(白名单是 spec 数据)
	samProcAllow, err := compilePatterns(spec, "sam_process_allowlist",
		[]string{`(?i)\\(lsass|winlogon|csrss|smss|services|svchost)\.exe$`,
			`(?i)^(system|registry)$`})
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
			switch {
			case explicitSet[strconv.FormatInt(eid, 10)]:
				// 4648 显式凭据登录:localhost/占位目标结构性排除
				target := dataStr(f, "TargetServerName")
				if target == "" || target == "-" ||
					strings.EqualFold(target, "localhost") || target == "127.0.0.1" ||
					target == "::1" {
					return nil
				}
				out = append(out, Finding{
					SourceID: src.ID, LineNo: ev.LineNo, TS: ev.TS,
					MatchedField: "event_id", MatchedValue: dataStr(f, "TargetUserName"),
					Snippet: ev.Raw,
					Detail: map[string]any{
						"event_id": eid, "wing": "explicit_credential",
						"subject_user":  dataStr(f, "SubjectUserName"),
						"target_user":   dataStr(f, "TargetUserName"),
						"target_server": target,
						"process":       dataStr(f, "ProcessName"),
						"computer":      fieldStr(f, "computer"),
						"judgement_hint": "显式凭据登录(runas/psexec 类)——先问" +
							"「谁对谁用了谁的凭据」,管理员的正常运维也是 4648",
					},
					Evidence: Evidence{IndependentPoints: 1},
				})
			case samSet[strconv.FormatInt(eid, 10)]:
				obj := dataStr(f, "ObjectName")
				objHit := ""
				for _, re := range samObj {
					if re.MatchString(obj) {
						objHit = re.String()
						break
					}
				}
				if objHit == "" {
					return nil
				}
				proc := dataStr(f, "ProcessName")
				for _, re := range samProcAllow {
					if re.MatchString(proc) {
						return nil // 系统进程访问 SAM 是常态(白名单)
					}
				}
				out = append(out, Finding{
					SourceID: src.ID, LineNo: ev.LineNo, TS: ev.TS,
					MatchedField: "event_id", MatchedValue: obj,
					Snippet: ev.Raw,
					Detail: map[string]any{
						"event_id": eid, "wing": "sam_access",
						"object": obj, "process": proc,
						"subject_user":   dataStr(f, "SubjectUserName"),
						"access_mask":    dataStr(f, "AccessMask"),
						"computer":       fieldStr(f, "computer"),
						"matched_object_pattern": objHit,
						"judgement_hint": "非系统进程碰 SAM/SECURITY 配置单元=凭据抓取" +
							"强信号;先确认进程身份与访问掩码(读 vs 写)",
					},
					// 两翼咬合:SAM 对象 + 非系统进程
					Evidence: Evidence{IndependentPoints: 2, ChainLinked: true},
				})
			}
			return nil
		})
		if serr != nil {
			return out, serr
		}
	}
	return out, nil
}
