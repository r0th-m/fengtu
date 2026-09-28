// netstat.txt / netstat_established.txt → 网络连接快照事件(net_connection)。
//
// 语义基准 = 树庭 backend/app/parsers/netstat.py(逐行对照移植);格式契约
// (netstat -ano[b] 输出,对 spec 写不对值写):
//   - 连接行:协议(TCP/UDP) 本地地址 外部地址 [状态(TCP)] PID,空白分隔;
//     识别只看行首协议词,不依赖表头语言(中文「活动连接」/英文
//     "Active Connections" 同样跳过——结构行不是事件,如实 skip 留账);
//   - 连接行后可跟 0~2 行归属信息(-b 输出):「[进程.exe]」回填上一条
//     事件的 process_name;其他文本作 service;占位文案「无法获取所有权
//     信息 / can not obtain ownership information」丢弃(不是进程名);
//   - UDP 无状态列,远端常为 *:*(通配 → addr/port 均空,如实);
//   - 地址拆分:IPv6 带括号 [::1]:135 处理;多冒号无括号形式整体当地址
//     (判不准不硬拆);
//   - 快照型:行内无时间戳,ts 一律 nil,绝不伪造时间。
//
// 与树庭的一处刻意偏差(如实记):TCP 无 -o 时行态为 4 段(协议 本地
// 外部 状态)——树庭把第 4 段记进 pid 且 state 留空(把状态当 PID 是
// 字段错位);丰图按格式 spec 记 state=parts[3]、pid 空。WinInfoSC 采集
// 恒带 -ano(5 段),此分支只影响第三方手工投喂的 netstat 文本。
//
// 编码:中文 Windows 的 netstat 输出是 ANSI(GBK),英文为 ASCII(⊂GBK);
// 判定口径与 usn_csv 一致——合法 UTF-8 按 UTF-8,否则按 GBK 解码
// (errors=replace 语义由解码器保证,选择入文件账)。
package parsers

import (
	"os"
	"strings"
	"unicode/utf8"

	"github.com/ye-mengwen/fengtu/internal/descform"
	"github.com/ye-mengwen/fengtu/internal/model"
)

// NetstatParser netstat -ano[b] 文本快照解析器。
type NetstatParser struct{}

// 归属信息里「拿不到进程名」的占位文案(中英),不是进程名,不记。
var netstatNoOwner = map[string]bool{
	"无法获取所有权信息":                        true,
	"can not obtain ownership information": true,
}

// netstatSplitAddr 拆 地址:端口;[v6]:port 也处理;通配(*)与判不准
// 返回空(如实,不硬拆)。
func netstatSplitAddr(token string) (addr, port string) {
	token = strings.TrimSpace(token)
	if token == "" || strings.HasPrefix(token, "*") {
		return "", ""
	}
	if strings.HasPrefix(token, "[") {
		if i := strings.Index(token, "]:"); i >= 0 {
			return token[1:i], token[i+2:]
		}
		return token, "" // 括号无端口形态:整体当地址
	}
	i := strings.LastIndex(token, ":")
	if i < 0 {
		return token, ""
	}
	if strings.Contains(token[:i], ":") {
		return token, "" // 多冒号且非括号形式 → 无端口 IPv6,整体当地址
	}
	return token[:i], token[i+1:]
}

// netstatStream 预解析全量记录后逐条流出(文件 KB 级;-b 归属回填需要
// 回看上一事件,流内缓冲一条即可,全量切片实现最简单)。
type netstatStream struct {
	recs []model.Record
	pos  int
}

func (s *netstatStream) Next() (model.Record, bool) {
	if s.pos >= len(s.recs) {
		return model.Record{}, false
	}
	r := s.recs[s.pos]
	s.pos++
	return r, true
}

func (s *netstatStream) Err() error   { return nil }
func (s *netstatStream) Close() error { return nil }

// Records 打开并解析 netstat 快照(打开期失败 = 文件级 fatal,如实 failed)。
func (NetstatParser) Records(path string) (Stream, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// 编码判定:合法 UTF-8 按 UTF-8,否则 GBK(中文 Windows ANSI)。
	enc := "utf-8"
	if !utf8.Valid(raw) {
		enc = "gbk"
	}
	text, err := descform.DecodeBytes(raw, enc)
	if err != nil {
		return nil, err
	}
	lines := descform.SplitLines(text)

	var recs []model.Record
	lastEvent := -1 // 归属信息回填目标(recs 下标)
	for i, line := range lines {
		no := i + 1
		s := strings.TrimSpace(line)
		if s == "" {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("空行")})
			continue
		}
		parts := strings.Fields(s)
		proto := strings.ToUpper(parts[0])
		isConn := (proto == "TCP" || proto == "UDP") && len(parts) >= 3
		if !isConn {
			if lastEvent < 0 {
				// 表头/标题等结构行(语言无关:协议词之外一律当结构)
				recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
					Raw: line, Reason: strPtrP("结构行(表头/标题,非连接行)")})
				continue
			}
			// 归属信息行:回填上一条连接事件
			if netstatNoOwner[strings.ToLower(s)] {
				recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
					Raw: line, Reason: strPtrP("归属占位文案(非进程名,丢弃)")})
				continue
			}
			ev := &recs[lastEvent]
			if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
				ev.Norm["process_name"] = s[1 : len(s)-1]
			} else if _, has := ev.Norm["service"]; !has {
				ev.Norm["service"] = s
			}
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("归属信息行(已回填上一条连接)")})
			continue
		}

		localAddr, localPort := netstatSplitAddr(parts[1])
		remoteAddr, remotePort := netstatSplitAddr(parts[2])
		var state, pid string
		if proto == "TCP" {
			if len(parts) >= 4 {
				state = parts[3] // 见文件头:与树庭 4 段分支的刻意偏差
			}
			if len(parts) >= 5 {
				pid = parts[4]
			}
		} else { // UDP:协议 本地 远端 [PID](无状态列)
			if len(parts) >= 4 {
				pid = parts[3]
			}
		}
		norm := map[string]any{"proto": proto}
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
		if state != "" {
			norm["state"] = state
		}
		if pid != "" {
			norm["pid"] = pid
		}
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
			Raw: line, Norm: norm})
		lastEvent = len(recs) - 1
	}
	return &netstatStream{recs: recs}, nil
}

func strPtrP(s string) *string { return &s }
