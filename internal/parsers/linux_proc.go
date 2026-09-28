// LinuxSC ProcInfo 进程面解析器(0.32.0-linuxsc):ps 快照 / cmdline-comm-exe
// 三方比对 / shm+tmp 清单 / lsof deleted 句柄 / exe 已删 / memfd 句柄 /
// maps 可疑执行段。
//
// 语义基准 = 树庭 backend/app/parsers/linux_proc.py(逐行对照移植,照抄
// 契约不自作主张加过滤)。全部为快照型:行内无时间戳,ts 一律不设
// (采集时刻语义由采集元信息承载)。
//
// 与树庭的如实差异:
//   - 规则锚定字段一律落字符串(nlink "0"、size、pid 等),布尔也统一落
//     "true"/"false" 字符串(树庭是 JSON bool)——丰图宽筛走 ClickHouse
//     JSONExtractString,只认字符串。
//   - 树庭 ps/lsof 旁路 emit_account 产账户实体;丰图不落实体表,ps 事件
//     双写 account=user 统一面字段承载同一语义(lsof 按契约不加)。
//   - 树庭对不中的行静默 continue;丰图每行留账(不中 = skip + 原因),
//     与 netstat 等解析器同款零静默纪律。
package parsers

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// fieldsN 等价 Python s.split(None, n-1):前 n-1 列按空白取 token,
// 第 n 段 = 剩余原文(前导空白剥除,内部空白原样保留)。ps 的 COMMAND
// 段靠它保留原始内部空白——strings.Fields 会把多空格压成单空格,
// 语义不等价,故自实现(树庭 split(None,10) 同款契约)。
func fieldsN(s string, n int) []string {
	var out []string
	i := 0
	for len(out) < n-1 {
		for i < len(s) && isProcSpace(s[i]) {
			i++
		}
		if i >= len(s) {
			return out
		}
		j := i
		for j < len(s) && !isProcSpace(s[j]) {
			j++
		}
		out = append(out, s[i:j])
		i = j
	}
	rest := strings.TrimLeftFunc(s[i:], unicode.IsSpace)
	if rest != "" {
		out = append(out, rest)
	}
	return out
}

func isProcSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '\v' || b == '\f'
}

// procBool 布尔 → "true"/"false" 字符串(CH JSONExtractString 宽筛契约,
// 与树庭 JSON bool 的如实差异,见文件头)。
func procBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// procSkip 追加一行 skip 账(空行/表头/结构行/不中的行,零静默)。
func procSkip(recs []model.Record, no int, raw, reason string) []model.Record {
	return append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
		Raw: raw, Reason: strPtrP(reason)})
}

// ---------------- 1. ps_auxwwf.txt(`ps auxwwf` 进程快照) ----------------

// LinuxPSParser ProcInfo/ps_auxwwf.txt 解析器。
type LinuxPSParser struct{}

// psCols 前 10 列定界字段(第 11 段 = COMMAND 整体,含森林前缀 `\_`
// 原样保留不剥;START 列可本地化如 `6月30`,快照型不解析)。
var psCols = [10]string{"user", "pid", "cpu", "mem", "vsz", "rss", "tty",
	"stat", "start", "time"}

func (LinuxPSParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		s := strings.TrimRightFunc(line, unicode.IsSpace)
		if strings.TrimSpace(s) == "" {
			recs = procSkip(recs, no, line, "空行")
			continue
		}
		// 表头:lstrip 后大写以 "USER" 开头即跳(中部重复表头同待)。
		if strings.HasPrefix(strings.ToUpper(
			strings.TrimLeftFunc(s, unicode.IsSpace)), "USER") {
			recs = procSkip(recs, no, line, "表头行")
			continue
		}
		parts := fieldsN(s, 11)
		if len(parts) < 11 {
			recs = procSkip(recs, no, line, "列数不足 11,不硬解")
			continue
		}
		command := strings.TrimSpace(parts[10])
		norm := map[string]any{"source": "ps_auxwwf"}
		for k, col := range psCols {
			norm[col] = parts[k]
		}
		norm["command"] = command
		// command 是树庭附录 A 锚字段;cmdline 是丰图主机统一面字段——
		// 同值双写,存量 cmdline 规则因此自动覆盖 Linux 进程面。
		norm["cmdline"] = command
		norm["account"] = parts[0] // 双写统一面(树庭 emit_account 语义)
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
			Raw: line, Norm: norm})
	}
	return &sliceStream{recs: recs}, nil
}

// ---------------- 2. proc_cmdline_comm_exe_compare.txt(TSV) ----------------

// LinuxProcIdentityParser ProcInfo/proc_cmdline_comm_exe_compare.txt 解析器。
type LinuxProcIdentityParser struct{}

func (LinuxProcIdentityParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		if strings.TrimSpace(line) == "" {
			recs = procSkip(recs, no, line, "空行")
			continue
		}
		// 表头仅认第 1 行(树庭契约;内核线程行 comm 可为任意词,
		// 不做中部表头扩展)。
		if no == 1 && strings.HasPrefix(strings.ToUpper(
			strings.TrimLeftFunc(line, unicode.IsSpace)), "PID") {
			recs = procSkip(recs, no, line, "表头行")
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 4 {
			recs = procSkip(recs, no, line, "TSV 列数不足 4,不硬解")
			continue
		}
		pid := strings.TrimSpace(parts[0])
		comm := strings.TrimSpace(parts[1])
		cmdline := strings.TrimSpace(parts[2])
		exe := strings.TrimSpace(parts[3])
		exeBase := ""
		if exe != "" {
			exeBase = exe[strings.LastIndex(exe, "/")+1:]
		}
		mismatch := exeBase != "" && comm != exeBase
		norm := map[string]any{
			"source": "proc_cmdline_comm_exe_compare",
			"pid":    pid,
			"comm":   comm,
			// exe 空 = 内核线程/异常;mismatch 是伪装检测素材。
			"exe_missing":       procBool(exe == ""),
			"comm_exe_mismatch": procBool(mismatch),
		}
		if cmdline != "" {
			norm["cmdline"] = cmdline
		}
		if exe != "" {
			norm["exe"] = exe
		}
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
			Raw: line, Norm: norm})
	}
	return &sliceStream{recs: recs}, nil
}

// ---------------- 3. shm_tmp_listing.txt(ls -la /dev/shm /run/shm /tmp /var/tmp) ----------------

// LinuxShmTmpParser ProcInfo/shm_tmp_listing.txt 解析器。
type LinuxShmTmpParser struct{}

func (LinuxShmTmpParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	var recs []model.Record
	section := ""
	for i, line := range lines {
		no := i + 1
		s := strings.TrimSpace(line)
		if s == "" {
			recs = procSkip(recs, no, line, "空行")
			continue
		}
		// 分节行「== /dev/shm ==」:两端按字符集剥 "=" 和空格。
		if strings.HasPrefix(s, "==") && strings.HasSuffix(s, "==") {
			section = strings.Trim(s, "= ")
			recs = procSkip(recs, no, line, "分节行")
			continue
		}
		if strings.HasPrefix(s, "total") || strings.HasPrefix(s, "总用量") {
			recs = procSkip(recs, no, line, "total/总用量 行")
			continue
		}
		parts := strings.Fields(s)
		if len(parts) < 9 {
			recs = procSkip(recs, no, line, "列数不足 9,不硬解")
			continue
		}
		if last := parts[len(parts)-1]; last == "." || last == ".." {
			recs = procSkip(recs, no, line, "点行(./..)")
			continue
		}
		if idx := strings.LastIndex(s, " -> "); idx >= 0 {
			// 符号链接行:用最后一个 " -> " 切(目标含 " -> " 不碎);
			// 左半最后一词 = 链接名(契约取舍:名字含空格只拿最后一词,
			// 树庭照抄);链接行无 size/is_dir 字段(树庭契约)。
			left := s[:idx]
			names := strings.Fields(left)
			norm := map[string]any{
				"source":      "shm_tmp_listing",
				"name":        names[len(names)-1],
				"mode":        parts[0],
				"owner":       parts[2],
				"link_target": strings.TrimSpace(s[idx+4:]),
				"is_symlink":  "true",
			}
			if section != "" {
				norm["dir"] = section
			}
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
				Raw: line, Norm: norm})
			continue
		}
		// 普通行:name = 最后一词(文件名含空格时只拿最后一词,契约
		// 取舍,树庭照抄,不硬解全名)。
		norm := map[string]any{
			"source":     "shm_tmp_listing",
			"name":       parts[len(parts)-1],
			"mode":       parts[0],
			"owner":      parts[2],
			"size":       parts[4], // 字符串(规则锚定契约)
			"is_dir":     procBool(parts[0][0] == 'd'),
			"is_symlink": "false",
		}
		if section != "" {
			norm["dir"] = section
		}
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
			Raw: line, Norm: norm})
	}
	return &sliceStream{recs: recs}, nil
}

// ---------------- 4. lsof_deleted_open.txt(`lsof +L1`) ----------------

// LinuxLsofDeletedParser ProcInfo/lsof_deleted_open.txt 解析器。
// 解析层零过滤:fd=txt/mem 也原样入库,可疑性判断在规则层(树庭契约)。
type LinuxLsofDeletedParser struct{}

func (LinuxLsofDeletedParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		s := strings.TrimRightFunc(line, unicode.IsSpace)
		if strings.TrimSpace(s) == "" {
			recs = procSkip(recs, no, line, "空行")
			continue
		}
		// 表头:lstrip 后以 "COMMAND" 开头(树庭大小写敏感,照抄)。
		if strings.HasPrefix(strings.TrimLeftFunc(s, unicode.IsSpace), "COMMAND") {
			recs = procSkip(recs, no, line, "表头行")
			continue
		}
		// 最多 10 段(第 10 段 = name 剩余整体,可含 " (deleted)" 尾缀);
		// 阈值是 9 不是 10:9 段时 name 取第 9 段兜底。
		parts := fieldsN(s, 10)
		if len(parts) < 9 {
			recs = procSkip(recs, no, line, "列数不足 9,不硬解")
			continue
		}
		name := parts[8]
		if len(parts) > 9 {
			name = parts[9]
		}
		norm := map[string]any{
			"source":  "lsof_deleted_open",
			"command": parts[0],
			"pid":     parts[1],
			"user":    parts[2],
			"fd":      parts[3],
			"type":    parts[4],
			// parts[5] = DEVICE 列,跳过不锚(树庭契约)。
			"size_off": parts[6],
			"nlink":    parts[7], // 字符串("0" 是 deleted 锚,规则层判)
			"name":     strings.TrimSpace(name),
		}
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
			Raw: line, Norm: norm})
	}
	return &sliceStream{recs: recs}, nil
}

// ---------------- 5~7. deleted/memfd/maps 内存马检测链(正则契约) ----------------

var (
	// `/proc/PID/exe -> 路径 (deleted)`(行内 search,允许 ls 前段)。
	procExeDeletedRe = regexp.MustCompile(
		`/proc/(\d+)/exe\s+->\s+(.+?)\s+\(deleted\)\s*$`)
	// `/proc/PID/fd/N -> /memfd:NAME (deleted)`。
	procFdMemfdRe = regexp.MustCompile(
		`/proc/(\d+)/fd/(\d+)\s+->\s+/memfd:(\S+)\s+\(deleted\)\s*$`)
	// `/proc/PID/maps:区间 权限 ... 路径 [(deleted)]`(整行锚定,
	// 路径非贪婪," (deleted)" 尾缀被可选组吃掉不进 path)。
	procMapsRe = regexp.MustCompile(
		`^/proc/(\d+)/maps:([0-9a-f]+-[0-9a-f]+)\s+(\S+)\s+\S+\s+\S+\s+\S+\s+` +
			`(.+?)\s*(?:\(deleted\))?\s*$`)
)

// LinuxProcExeDeletedParser ProcInfo/proc_exe_deleted.txt 解析器。
type LinuxProcExeDeletedParser struct{}

func (LinuxProcExeDeletedParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		if strings.TrimSpace(line) == "" {
			recs = procSkip(recs, no, line, "空行")
			continue
		}
		m := procExeDeletedRe.FindStringSubmatch(line)
		if m == nil {
			recs = procSkip(recs, no, line, "非 /proc/PID/exe deleted 行")
			continue
		}
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
			Raw: line, Norm: map[string]any{
				"source": "proc_exe_deleted",
				"pid":    m[1],
				"exe":    m[2], // 非贪婪,"(deleted)" 不进 exe
			}})
	}
	return &sliceStream{recs: recs}, nil
}

// LinuxProcFdMemfdParser ProcInfo/proc_fd_memfd.txt 解析器。
type LinuxProcFdMemfdParser struct{}

func (LinuxProcFdMemfdParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		if strings.TrimSpace(line) == "" {
			recs = procSkip(recs, no, line, "空行")
			continue
		}
		m := procFdMemfdRe.FindStringSubmatch(line)
		if m == nil {
			recs = procSkip(recs, no, line, "非 memfd deleted 行")
			continue
		}
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
			Raw: line, Norm: map[string]any{
				"source":     "proc_fd_memfd",
				"pid":        m[1],
				"fd":         m[2],
				"memfd_name": m[3],
			}})
	}
	return &sliceStream{recs: recs}, nil
}

// LinuxProcMapsParser ProcInfo/proc_maps_suspicious_exec.txt 解析器。
type LinuxProcMapsParser struct{}

func (LinuxProcMapsParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		s := strings.TrimSpace(line)
		if s == "" {
			recs = procSkip(recs, no, line, "空行")
			continue
		}
		m := procMapsRe.FindStringSubmatch(s)
		if m == nil {
			recs = procSkip(recs, no, line, "非 maps 可疑执行段行")
			continue
		}
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
			Raw: line, Norm: map[string]any{
				"source":  "proc_maps_suspicious_exec",
				"pid":     m[1],
				"range":   m[2],
				"perms":   m[3],
				"path":    m[4],
				"deleted": procBool(strings.Contains(s, "(deleted)")),
			}})
	}
	return &sliceStream{recs: recs}, nil
}
