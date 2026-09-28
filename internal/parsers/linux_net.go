// LinuxSC 采集包网络面解析器(0.32.0-linuxsc):ss_tuanp / netstat_tuanp /
// conntrack_L 三个快照解析器。
//
// 语义基准 = 树庭 backend/app/parsers/linux_net.py 的 parse_ss /
// parse_netstat / parse_conntrack(逐字段对照移植;格式契约对 `ss -tuanp`、
// `netstat -tuanp`、`conntrack -L` 的公开输出 spec 写,不对具体案件值写)。
//
// 与树庭的刻意差异(如实标注):
//   - 树庭行级跳过是静默 continue;丰图零静默——空行/表头/残缺行一律产
//     skip 记录带原因留账。
//   - conntrack flags 树庭是 list;丰图规则宽筛走 JSONExtractString 只认
//     字符串,落空格 join 的字符串("ASSURED" / "UNREPLIED" 等)。
//   - conntrack 双写(丰图适配):dst/dport 同时写 remote_addr/remote_port
//     ——conntrack 首现五元组是发起方向,dst 即远端;让存量 net_connection
//     面规则(如 linux-lateral-internal-ssh-conn 的 remote_port_eq 22)
//     自动覆盖 conntrack 面。
//   - conntrack 树庭另有五元组会话聚合(conntrack_session);丰图不实现
//     (无规则锚定,查询层可按五元组现算),保留逐行 cap + summary 契约。
//   - 快照型:三个文件行内均无时间戳,ts 一律不设(TsRaw/DTLocal/TsUTC
//     全 nil,绝不伪造)。
//   - 规则锚定字段一律字符串(proto/state/local_port/remote_port/pid/
//     dport/flags/timeout 等);仅 conntrack summary 的计数字段用 int
//     (不被规则锚定),capped 用字符串 "true"/"false"。
package parsers

import (
	"regexp"
	"strings"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// conntrackCap 逐行事件产出上限(树庭 _CONNTRACK_CAP=20000 照抄;
// 防淹没,全量行照常计数进 summary)。
const conntrackCap = 20000

// ssUsersRe users:(("dnsmasq",pid=2063,fd=5),...) → 取首个进程归属
// (树庭 _USERS_RE 同契约)。
var ssUsersRe = regexp.MustCompile(`users:\(\("([^"]+)",pid=(\d+)`)

// netstatStates Linux netstat -tuanp 的 State 列词表(树庭 parse_netstat
// 同契约;udp 行无此列,靠词表判 parts[5] 是 state 还是 owner)。
var netstatStates = map[string]bool{
	"ESTABLISHED": true, "LISTEN": true, "TIME_WAIT": true,
	"CLOSE_WAIT": true, "SYN_SENT": true, "SYN_RECV": true,
	"FIN_WAIT1": true, "FIN_WAIT2": true, "CLOSING": true,
	"LAST_ACK": true, "UNKNOWN": true,
}

// ---- linux_ss:Network/ss_tuanp.txt(`ss -tuanp` 输出) ----

// LinuxSSParser ss -tuanp 连接快照解析器。
type LinuxSSParser struct{}

// Records 打开并解析 ss_tuanp 快照(打开期失败 = 文件级 fatal)。
func (LinuxSSParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		s := strings.TrimSpace(line)
		if s == "" {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("空行")})
			continue
		}
		if strings.HasPrefix(strings.ToLower(s), "netid") {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("表头(Netid 列名行)")})
			continue
		}
		parts := strings.Fields(s)
		if len(parts) < 6 {
			// 非数据行(截断/噪声),不硬解(树庭静默跳过,丰图 skip 留账)
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("列数不足(<6 段,非数据行)")})
			continue
		}
		// netid state recvq sendq local peer [users:...];recvq/sendq 丢弃
		localAddr, localPort := splitLAddr(parts[4])
		remoteAddr, remotePort := splitLAddr(parts[5])
		norm := map[string]any{
			"source": "ss_tuanp",
			"proto":  parts[0], // netid 原样(ss 输出即小写 tcp/udp)
			"state":  parts[1],
		}
		if localAddr != "" {
			norm["local_addr"] = localAddr
		}
		if localPort != "" {
			norm["local_port"] = localPort
		}
		if remoteAddr != "" {
			norm["remote_addr"] = remoteAddr
		}
		if remotePort != "" {
			norm["remote_port"] = remotePort
		}
		if m := ssUsersRe.FindStringSubmatch(s); m != nil {
			norm["process_name"] = m[1]
			norm["pid"] = m[2] // 规则锚定字段,字符串留存
		}
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
			Raw: line, Norm: norm})
	}
	return &sliceStream{recs: recs}, nil
}

// ---- linux_netstat:Network/netstat_tuanp.txt(Linux `netstat -tuanp`) ----

// LinuxNetstatParser Linux netstat -tuanp 连接快照解析器。
type LinuxNetstatParser struct{}

// Records 打开并解析 netstat_tuanp 快照(打开期失败 = 文件级 fatal)。
func (LinuxNetstatParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		s := strings.TrimSpace(line)
		if s == "" {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("空行")})
			continue
		}
		if strings.HasPrefix(s, "Active") || strings.HasPrefix(s, "Proto") {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("表头/标题(Active/Proto 行)")})
			continue
		}
		parts := strings.Fields(s)
		if len(parts) < 6 {
			// 非数据行(udp 无 State 列则恰好 6 段),不硬解
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("列数不足(<6 段,非数据行)")})
			continue
		}
		// proto rq sq local foreign [state] [pid/prog];
		// udp 行无 State 列:parts[5] 在状态词表(大写比较)则是 state,
		// 否则是 owner(pid/prog)
		var state, owner string
		if netstatStates[parts[5]] {
			state = parts[5]
			if len(parts) > 6 {
				owner = parts[6]
			}
		} else {
			owner = parts[5]
		}
		var pid, prog string
		if i := strings.Index(owner, "/"); i >= 0 {
			pid, prog = owner[:i], owner[i+1:] // 按第一个 "/" 拆
		}
		localAddr, localPort := splitLAddr(parts[3])
		remoteAddr, remotePort := splitLAddr(parts[4])
		norm := map[string]any{
			"source": "netstat_tuanp",
			"proto":  strings.ToLower(parts[0]),
		}
		if state != "" {
			norm["state"] = state
		}
		if localAddr != "" {
			norm["local_addr"] = localAddr
		}
		if localPort != "" {
			norm["local_port"] = localPort
		}
		if remoteAddr != "" {
			norm["remote_addr"] = remoteAddr
		}
		if remotePort != "" {
			norm["remote_port"] = remotePort
		}
		if pid != "" {
			norm["pid"] = pid
		}
		if prog != "" {
			norm["process_name"] = prog
		}
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
			Raw: line, Norm: norm})
	}
	return &sliceStream{recs: recs}, nil
}

// ---- linux_conntrack:Network/conntrack_L.txt(`conntrack -L`) ----

// LinuxConntrackParser conntrack -L 连接跟踪表快照解析器。
type LinuxConntrackParser struct{}

// Records 打开并解析 conntrack_L 快照(打开期失败 = 文件级 fatal)。
// 逐行事件只在前 conntrackCap 行产出(树庭量控契约照抄),全部行照常
// 计数;文件结束追加一条 summary 事件。
func (LinuxConntrackParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	var recs []model.Record
	total, malformed, emitted := 0, 0, 0
	for i, line := range lines {
		no := i + 1
		s := strings.TrimSpace(line)
		if s == "" {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("空行")})
			continue
		}
		total++ // 计数口径照树庭:只计非空行
		parts := strings.Fields(s)
		if len(parts) < 4 {
			malformed++
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("列数不足(<4 段,malformed)")})
			continue
		}
		if total > conntrackCap {
			// 超上限:行照常计数,不再产逐行事件(防淹没;零静默→skip 留账)
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("超逐行事件上限 20000(已计入 summary)")})
			continue
		}
		// kv:原向/回向同键重复 → 同键取首现(原始五元组在前,reply 在后)
		kv := map[string]string{}
		for _, p := range parts {
			if j := strings.Index(p, "="); j >= 0 {
				if _, has := kv[p[:j]]; !has {
					kv[p[:j]] = p[j+1:]
				}
			}
		}
		// flags:[ASSURED]/[UNREPLIED] 等剥括号后空格 join(树庭是 list;
		// 丰图规则宽筛只认字符串,差异见文件头)
		var flags []string
		for _, p := range parts {
			if strings.HasPrefix(p, "[") && strings.HasSuffix(p, "]") {
				flags = append(flags, p[1:len(p)-1])
			}
		}
		// parts[3] 以 src= 或 [ 开头 = icmp/无状态协议变体 → state 不写
		state := parts[3]
		if strings.HasPrefix(state, "src=") || strings.HasPrefix(state, "[") {
			state = ""
		}
		norm := map[string]any{
			"source":  "conntrack",
			"proto":   parts[0],
			"timeout": parts[2], // 原始字符串留存(非数字不猜,规则锚定)
		}
		if state != "" {
			norm["state"] = state
		}
		if v := kv["src"]; v != "" {
			norm["src"] = v
		}
		if v := kv["dst"]; v != "" {
			norm["dst"] = v
			// 双写(丰图适配):conntrack 首现五元组是发起方向,dst 即
			// 远端 → remote_addr/remote_port,让存量 net_connection 面
			// 规则自动覆盖 conntrack 面
			norm["remote_addr"] = v
		}
		if v := kv["sport"]; v != "" {
			norm["sport"] = v
		}
		if v := kv["dport"]; v != "" {
			norm["dport"] = v
			norm["remote_port"] = v
		}
		if len(flags) > 0 {
			norm["flags"] = strings.Join(flags, " ")
		}
		if v := kv["mark"]; v != "" {
			norm["mark"] = v
		}
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
			Raw: line, Norm: norm})
		emitted++
	}
	// summary 事件(一条;计数字段用 int——不被规则锚定;capped 用字符串)
	truncated := total - malformed - conntrackCap
	if truncated < 0 {
		truncated = 0
	}
	capped := "false"
	if total-malformed > conntrackCap {
		capped = "true"
	}
	recs = append(recs, model.Record{LineNo: 1, Kind: model.KindEvent, Raw: "",
		Norm: map[string]any{
			"source":            "conntrack",
			"kind_note":         "conntrack_summary",
			"total_lines":       total,
			"malformed_lines":   malformed,
			"emitted_entries":   emitted,
			"truncated_entries": truncated,
			"capped":            capped,
		}})
	return &sliceStream{recs: recs}, nil
}
