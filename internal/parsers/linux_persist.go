// LinuxSC 采集包持久化面解析器(0.32.0-linuxsc):crontab(全用户/系统/
// spool)/ anacrontab / systemd unit 与 drop-in / udev rules / pam.d /
// shell 配置,共 9 个 parser。
//
// 语义基准 = 树庭 backend/app/parsers/linux_persist.py + linux_persist2.py
// (逐文件对照移植);格式契约 = LINUXSC_SPEC.md + LinuxSC.sh 采集端输出
// (对 spec 写,不对值写)。全部快照型:行内无时间戳,ts 一律不设。
//
// 与树庭的刻意差异(如实标注):
//   - 规则锚定字段一律字符串(has_exec/is_pam_exec 存 "true"/"false";
//     exec_start/exports/aliases 等列表存 "\n" join 字符串)——宽筛走
//     CH JSONExtractString 只认字符串;树庭是原生 list/bool。非锚定列表
//     (sections 等)可存 []string。
//   - 丰图零静默:每行都有账(event/skip/bad);树庭对注释/空行/不中行
//     是静默 continue,此处如实 skip 留账(Reason 注明)。
//   - cron spool:树庭坏行计数+末尾 summary 事件;丰图逐行 bad 记录
//     (零静默),不加 summary。
//   - source 字段:树庭记 rel_path;丰图记恒定源标(规则分流锚点,
//     cron_sys 的具体文件名另记 file 字段,不丢数据)。
//   - systemd drop-in:树庭 unit 取 /systemd/ 之后的相对段;丰图记文件
//     基名;树庭 directives 存嵌套 dict,丰图存 "节.键=值" 逐行 "\n" join
//     字符串(directives_text,便于检索)。
package parsers

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// ---- 共享正则(与树庭 linux_persist.py/linux_persist2.py 逐字对应) ----

var (
	// crontab_all_users.txt 分节行:`===== <user> =====`。
	lpSectionUserRe = regexp.MustCompile(`^=====\s*(.+?)\s*=====$`)
	// 采集端声明的「无 crontab」(大小写不敏感)。
	lpNoCronRe = regexp.MustCompile(`(?i)^no crontab for\b`)
	// 环境变量行(cron/anacrontab 通用)。
	lpEnvRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	// 用户 crontab 条目:@keyword 或五段时间 + 命令。
	lpCronLineRe = regexp.MustCompile(
		`^(@\w+|\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(.+)$`)
	// 系统 crontab 条目:五段时间 + 执行用户 + 命令。
	lpSysCronRe = regexp.MustCompile(
		`^(@\w+|\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(\S+)\s+(.+)$`)
	// anacrontab:周期 延迟 作业名 命令。
	lpAnacronRe = regexp.MustCompile(`^(@\w+|\d+)\s+(\d+)\s+(\S+)\s+(.+)$`)
	// INI 节 / 键值(systemd unit、drop-in 共用)。
	lpIniSectionRe = regexp.MustCompile(`^\[(.+)\]\s*$`)
	lpIniKVRe      = regexp.MustCompile(`^([^=;#\s][^=]*)=(.*)$`)
	// udev 执行面三类赋值。
	lpUdevRunRe     = regexp.MustCompile(`RUN(?:\{program\})?[+:]?="([^"]*)"`)
	lpUdevImportRe  = regexp.MustCompile(`IMPORT\{program\}="([^"]*)"`)
	lpUdevProgramRe = regexp.MustCompile(`PROGRAM[+:]?="([^"]*)"`)
	// pam:@include 指令;type control module [args](control 可为 [k=v ...] 括号组)。
	lpPamIncludeRe = regexp.MustCompile(`^@include\s+(\S+)`)
	lpPamRe        = regexp.MustCompile(`^([a-z]+)\s+(\[[^\]]*\]|\S+)\s+(\S+)\s*(.*)$`)
	// shell 配置:alias 优先于 export(alias 行也含 =,顺序即契约)。
	lpAliasRe  = regexp.MustCompile(`^alias\s+([^=]+)=(.*)$`)
	lpExportRe = regexp.MustCompile(`^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)
)

// lpSkip 一行 skip 记录(零静默:空行/注释/结构行/不中行都留账)。
func lpSkip(no int, raw, reason string) model.Record {
	return model.Record{LineNo: no, Kind: model.KindSkip,
		Raw: raw, Reason: strPtrP(reason)}
}

// lpBool 规则锚定布尔 → 字符串(CH JSONExtractString 宽筛只认字符串)。
func lpBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// lpTrunc 按字符截断(留证用上限;中文等多字节按 rune 计,不截碎)。
func lpTrunc(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// lpBase 文件基名(source/unit/file/rule_file 锚定用)。
func lpBase(path string) string { return filepath.Base(path) }

// ---- 1. linux_cron_all:Persistence/crontab_all_users.txt ----

// LinuxCronAllParser 全用户 crontab 汇总(采集端 `crontab -l -u` 循环输出)。
type LinuxCronAllParser struct{}

// Records 解析 crontab_all_users.txt:分节行定当前 user;no crontab 如实
// 记 section_empty;节前条目行属主未知 skip(不猜)。
func (LinuxCronAllParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	var recs []model.Record
	user := ""
	for i, line := range lines {
		no := i + 1
		s := strings.TrimSpace(line)
		if m := lpSectionUserRe.FindStringSubmatch(s); m != nil {
			user = m[1]
			recs = append(recs, lpSkip(no, line, "分节行(当前用户="+user+")"))
			continue
		}
		if s == "" {
			recs = append(recs, lpSkip(no, line, "空行"))
			continue
		}
		if strings.HasPrefix(s, "#") {
			recs = append(recs, lpSkip(no, line, "注释行"))
			continue
		}
		if lpEnvRe.MatchString(s) {
			recs = append(recs, lpSkip(no, line, "环境变量行"))
			continue
		}
		if lpNoCronRe.MatchString(s) {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
				Raw: line, Norm: map[string]any{
					"source":        "crontab_all_users",
					"user":          user,
					"section_empty": "true", // 锚定字段:字符串
				}})
			continue
		}
		if m := lpCronLineRe.FindStringSubmatch(s); m != nil {
			if user == "" {
				recs = append(recs, lpSkip(no, line, "分节外条目行,属主未知"))
				continue
			}
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
				Raw: line, Norm: map[string]any{
					"source":   "crontab_all_users",
					"user":     user,
					"schedule": m[1],
					"command":  m[2],
				}})
			continue
		}
		recs = append(recs, lpSkip(no, line, "非 cron 条目行"))
	}
	return &sliceStream{recs: recs}, nil
}

// ---- 2. linux_cron_sys:Persistence/etc/crontab 与 etc/cron.d/* ----

// LinuxCronSysParser 系统 crontab(条目带执行用户列)。
type LinuxCronSysParser struct{}

// Records 解析系统 crontab;不中条目正则的行如实 skip(不硬解)。
func (LinuxCronSysParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	src := lpBase(path)
	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		s := strings.TrimSpace(line)
		if s == "" {
			recs = append(recs, lpSkip(no, line, "空行"))
			continue
		}
		if strings.HasPrefix(s, "#") {
			recs = append(recs, lpSkip(no, line, "注释行"))
			continue
		}
		if lpEnvRe.MatchString(s) {
			recs = append(recs, lpSkip(no, line, "环境变量行"))
			continue
		}
		m := lpSysCronRe.FindStringSubmatch(s)
		if m == nil {
			recs = append(recs, lpSkip(no, line, "非 cron 条目行"))
			continue
		}
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
			Raw: line, Norm: map[string]any{
				"source":   "cron_sys", // 恒定源标(规则分流锚点;树庭记 rel_path)
				"file":     src,        // 具体文件名(cron.d 下多文件)
				"schedule": m[1],
				"user":     m[2],
				"command":  m[3],
			}})
	}
	return &sliceStream{recs: recs}, nil
}

// ---- 3. linux_anacrontab:Persistence/etc/anacrontab ----

// LinuxAnacrontabParser anacrontab(周期 延迟 作业名 命令 四段,无 user 列)。
type LinuxAnacrontabParser struct{}

// Records 解析 anacrontab;delay_minutes 存字符串(锚定字段)。
func (LinuxAnacrontabParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		s := strings.TrimSpace(line)
		if s == "" {
			recs = append(recs, lpSkip(no, line, "空行"))
			continue
		}
		if strings.HasPrefix(s, "#") {
			recs = append(recs, lpSkip(no, line, "注释行"))
			continue
		}
		if lpEnvRe.MatchString(s) {
			recs = append(recs, lpSkip(no, line, "环境变量行"))
			continue
		}
		m := lpAnacronRe.FindStringSubmatch(s)
		if m == nil {
			recs = append(recs, lpSkip(no, line, "非 anacrontab 条目行"))
			continue
		}
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
			Raw: line, Norm: map[string]any{
				"source":        "anacrontab",
				"schedule":      m[1],
				"delay_minutes": m[2], // 字符串,不转 int(锚定字段口径统一)
				"job_id":        m[3],
				"command":       m[4],
			}})
	}
	return &sliceStream{recs: recs}, nil
}

// ---- 4. linux_cron_spool:Persistence/var/spool/cron/** ----

// LinuxCronSpoolParser 用户 crontab spool(文件名即用户)。
type LinuxCronSpoolParser struct{}

// Records 解析 cron spool;非条目行逐行 bad(丰图零静默,树庭是末尾
// summary)。var/spool/cron/atjobs 下的文件也路由到这里——不区分,同契约
// 解析(atjobs 是二进制+文本混合,坏行会如实 bad,这正是要的效果)。
func (LinuxCronSpoolParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	user := lpBase(path)
	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		s := strings.TrimSpace(line)
		if s == "" {
			recs = append(recs, lpSkip(no, line, "空行"))
			continue
		}
		if strings.HasPrefix(s, "#") {
			recs = append(recs, lpSkip(no, line, "注释行"))
			continue
		}
		if lpEnvRe.MatchString(s) {
			recs = append(recs, lpSkip(no, line, "环境变量行"))
			continue
		}
		m := lpCronLineRe.FindStringSubmatch(s)
		if m == nil {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindBad,
				Raw: line, Reason: strPtrP("cron spool 坏行")})
			continue
		}
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
			Raw: line, Norm: map[string]any{
				"source":   "cron_spool",
				"user":     user,
				"schedule": m[1],
				"command":  m[2],
			}})
	}
	return &sliceStream{recs: recs}, nil
}

// ---- systemd INI 共享解析(unit 与 drop-in 同一套契约) ----

// lpIni 解析 systemd 风格 INI:节 → 键 → 值列表(同名键多行保序,键名
// 大小写敏感——systemd 契约)。continuation=true 时行尾 `\` 续行拼接
// (pending+raw.strip(),拼接点不加空格——树庭契约;unit 文件用);
// drop-in 不做续行处理。directives 按遇到顺序记 "节.键=值"(drop-in 的
// directives_text 用)。
func lpIni(lines []string, continuation bool) (data map[string]map[string][]string,
	directives []string) {
	data = map[string]map[string][]string{}
	section := ""
	pending := ""
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if continuation {
			line = pending + line
			if strings.HasSuffix(line, `\`) {
				pending = line[:len(line)-1] // 去反斜杠续接下一行
				continue
			}
			pending = ""
		}
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") {
			continue
		}
		if m := lpIniSectionRe.FindStringSubmatch(s); m != nil {
			section = m[1]
			continue
		}
		m := lpIniKVRe.FindStringSubmatch(s)
		if m == nil || section == "" {
			continue // 节外键值/非键值行:不硬解(文件级事件已留全文 Raw)
		}
		key, val := strings.TrimSpace(m[1]), strings.TrimSpace(m[2])
		if data[section] == nil {
			data[section] = map[string][]string{}
		}
		data[section][key] = append(data[section][key], val)
		directives = append(directives, section+"."+key+"="+val)
	}
	return data, directives
}

// lpSections 节名排序(非锚定列表,存 []string)。
func lpSections(data map[string]map[string][]string) []string {
	out := make([]string, 0, len(data))
	for k := range data {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// lpFirst 取键值列表首项;无 → ""。
func lpFirst(data map[string]map[string][]string, section, key string) (string, bool) {
	if sec, ok := data[section]; ok {
		if vals, ok := sec[key]; ok && len(vals) > 0 {
			return vals[0], true
		}
	}
	return "", false
}

// lpJoined 取键值全列表 "\n" join;无 → 不写(锚定字段:字符串,
// 与树庭 list 的差异见文件头)。
func lpJoined(data map[string]map[string][]string, section, key string) (string, bool) {
	if sec, ok := data[section]; ok {
		if vals, ok := sec[key]; ok && len(vals) > 0 {
			return strings.Join(vals, "\n"), true
		}
	}
	return "", false
}

// lpJoinInto norm[key] = 键值全列表 "\n" join(有才写)。
func lpJoinInto(norm map[string]any, field string,
	data map[string]map[string][]string, section, key string) {
	if s, ok := lpJoined(data, section, key); ok {
		norm[field] = s
	}
}

// lpFullText 物理行回拼全文(行尾归一为 \n),截前 2000 字符留证。
func lpFullText(lines []string) string {
	return lpTrunc(strings.Join(lines, "\n"), 2000)
}

// ---- 5. linux_systemd:Persistence 下 *.service/*.timer 等单元文件 ----

// LinuxSystemdUnitParser systemd 单元文件(INI,行尾 `\` 续行拼接)。
type LinuxSystemdUnitParser struct{}

// Records 一文件产一条事件(LineNo=1,Raw=全文前 2000 字符截断留证);
// specifier(%i 等)原样保留不求值(树庭取舍照抄)。
func (LinuxSystemdUnitParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	unit := lpBase(path)
	data, _ := lpIni(lines, true)
	norm := map[string]any{
		"source":   unit,
		"unit":     unit,
		"sections": lpSections(data),
	}
	if v, ok := lpFirst(data, "Unit", "Description"); ok {
		norm["description"] = v
	}
	if v, ok := lpFirst(data, "Service", "Type"); ok {
		norm["type"] = v
	}
	lpJoinInto(norm, "exec_start", data, "Service", "ExecStart")
	lpJoinInto(norm, "exec_start_pre", data, "Service", "ExecStartPre")
	lpJoinInto(norm, "exec_start_post", data, "Service", "ExecStartPost")
	if v, ok := lpFirst(data, "Service", "User"); ok {
		norm["user"] = v
	}
	lpJoinInto(norm, "on_calendar", data, "Timer", "OnCalendar")
	lpJoinInto(norm, "wanted_by", data, "Install", "WantedBy")
	lpJoinInto(norm, "required_by", data, "Install", "RequiredBy")
	return &sliceStream{recs: []model.Record{
		{LineNo: 1, Kind: model.KindEvent, Raw: lpFullText(lines), Norm: norm},
	}}, nil
}

// ---- 6. linux_systemd_dropin:Persistence 下 *.d/*.conf drop-in ----

// LinuxSystemdDropinParser systemd drop-in 覆盖片段(INI,无续行处理)。
type LinuxSystemdDropinParser struct{}

// Records 一文件一条事件;drop-in 里的 ExecStart 覆盖同样是持久化抓手
// (有才写);directives_text 留存全文键值便于检索。
func (LinuxSystemdDropinParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	unit := lpBase(path)
	data, directives := lpIni(lines, false)
	norm := map[string]any{
		"source":          unit,
		"unit":            unit,
		"drop_in":         "true", // 锚定字段:字符串
		"sections":        lpSections(data),
		"directives_text": strings.Join(directives, "\n"),
	}
	lpJoinInto(norm, "exec_start", data, "Service", "ExecStart")
	return &sliceStream{recs: []model.Record{
		{LineNo: 1, Kind: model.KindEvent, Raw: lpFullText(lines), Norm: norm},
	}}, nil
}

// ---- 7. linux_udev:Persistence 下 udev rules.d/*.rules ----

// LinuxUdevParser udev rules(RUN/IMPORT{program}/PROGRAM 执行面提取)。
type LinuxUdevParser struct{}

// lpFindAll 正则全匹配取组 1(findall 语义)。
func lpFindAll(re *regexp.Regexp, s string) []string {
	var out []string
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// Records 每条非注释非空行都产事件(无可执行赋值也产,has_exec="false"
// ——规则本体即证据);run/import_program/program 空格 join(有才写,
// 锚定字段为字符串)。
func (LinuxUdevParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	base := lpBase(path)
	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		s := strings.TrimSpace(line)
		if s == "" {
			recs = append(recs, lpSkip(no, line, "空行"))
			continue
		}
		if strings.HasPrefix(s, "#") {
			recs = append(recs, lpSkip(no, line, "注释行"))
			continue
		}
		runs := lpFindAll(lpUdevRunRe, s)
		imports := lpFindAll(lpUdevImportRe, s)
		progs := lpFindAll(lpUdevProgramRe, s)
		norm := map[string]any{
			"source":    base,
			"rule_file": base,
			"raw":       s,
			"has_exec":  lpBool(len(runs) > 0 || len(imports) > 0 || len(progs) > 0),
		}
		if len(runs) > 0 {
			norm["run"] = strings.Join(runs, " ")
		}
		if len(imports) > 0 {
			norm["import_program"] = strings.Join(imports, " ")
		}
		if len(progs) > 0 {
			norm["program"] = strings.Join(progs, " ")
		}
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
			Raw: line, Norm: norm})
	}
	return &sliceStream{recs: recs}, nil
}

// ---- 8. linux_pam:Persistence/etc/pam.d/* ----

// LinuxPamParser pam.d 配置(type control module [args] / @include)。
type LinuxPamParser struct{}

// Records 逐行解析;is_pam_exec 锚定字段存 "true"/"false"(module 含
// 子串 "pam_exec"——pam_exec 是任意命令执行面,规则宽筛锚点)。
func (LinuxPamParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	service := lpBase(path)
	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		s := strings.TrimSpace(line)
		if s == "" {
			recs = append(recs, lpSkip(no, line, "空行"))
			continue
		}
		if strings.HasPrefix(s, "#") {
			recs = append(recs, lpSkip(no, line, "注释行"))
			continue
		}
		if m := lpPamIncludeRe.FindStringSubmatch(s); m != nil {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
				Raw: line, Norm: map[string]any{
					"source":    "pam_d",
					"service":   service,
					"directive": "@include",
					"target":    m[1],
				}})
			continue
		}
		m := lpPamRe.FindStringSubmatch(s)
		if m == nil {
			recs = append(recs, lpSkip(no, line, "非 PAM 指令行"))
			continue
		}
		norm := map[string]any{
			"source":      "pam_d",
			"service":     service,
			"type":        m[1],
			"control":     m[2],
			"module":      m[3],
			"is_pam_exec": lpBool(strings.Contains(m[3], "pam_exec")),
		}
		if args := strings.TrimSpace(m[4]); args != "" {
			norm["args"] = args
		}
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
			Raw: line, Norm: norm})
	}
	return &sliceStream{recs: recs}, nil
}

// ---- 9. linux_shellcfg:profile/bashrc/zshrc/用户 rc 等 shell 配置 ----

// LinuxShellConfigParser shell 启动配置(export/alias 限量提取,行数留证)。
type LinuxShellConfigParser struct{}

// lpShellOwner 从绝对路径推属主:…/Persistence/home/<u>/… → <u>;
// …/Persistence/root/… → "root";etc/ 下等系统级 → 空(不写)。
// 依据:parser 只拿到绝对路径,树庭按 rel_path 组件取属主,丰图按
// "/Persistence/" 锚段对齐同一语义(映射表只路由 Persistence 下文件)。
func lpShellOwner(path string) string {
	segs := strings.Split(filepath.ToSlash(path), "/")
	for i := 0; i+2 < len(segs); i++ {
		if segs[i] != "Persistence" {
			continue
		}
		switch segs[i+1] {
		case "home":
			return segs[i+2]
		case "root":
			return "root"
		}
	}
	return ""
}

// Records 一文件一条事件(LineNo=1,Raw=全文前 2000 字符);alias 上限
// 20 条、export 上限 50 条,如实截断(exports_truncated);exports/aliases
// 为规则锚定字段,存 "\n" join 字符串(与树庭 list 的差异见文件头)。
func (LinuxShellConfigParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	base := lpBase(path)
	var exports, aliases []string
	nonComment := 0
	for _, line := range lines {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue // 空行/注释不计 non_comment(文件级事件,行账在 line_count)
		}
		nonComment++
		if lpAliasRe.MatchString(s) {
			if len(aliases) < 20 {
				aliases = append(aliases, s) // 收整行(树庭契约)
			}
			continue
		}
		if lpExportRe.MatchString(s) && strings.Contains(s, "=") {
			if len(exports) < 50 {
				exports = append(exports, s)
			}
		}
	}
	norm := map[string]any{
		"source":            base,
		"file":              base,
		"line_count":        len(lines),
		"non_comment_lines": nonComment,
	}
	if owner := lpShellOwner(path); owner != "" {
		norm["owner"] = owner
	}
	if len(exports) > 0 {
		norm["exports"] = strings.Join(exports, "\n")
	}
	if len(aliases) > 0 {
		norm["aliases"] = strings.Join(aliases, "\n")
	}
	if nonComment > 0 && len(exports) == 50 {
		norm["exports_truncated"] = "true"
	}
	return &sliceStream{recs: []model.Record{
		{LineNo: 1, Kind: model.KindEvent, Raw: lpFullText(lines), Norm: norm},
	}}, nil
}
