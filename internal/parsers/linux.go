// LinuxSC 采集包解析器共享基础(0.32.0-linuxsc)。
//
// 语义基准 = 树庭 backend/app/parsers/linux_*.py(逐文件对照移植;
// 精确语义逐文件对照提取)。采集格式契约 =
// LINUXSC_SPEC.md + LinuxSC.sh 采集端输出(对 spec 写,不对值写)。
//
// 与树庭的刻意差异(如实标注):
//   - 树庭 journal/syslog 做「优先事件全量 + 其余按 unit 聚合」的量控
//     取舍(PG 存储压力);丰图事件面是 ClickHouse,无此约束——
//     逐行全量入库(更利于检索/时间线),聚合统计由查询层现算。
//   - 树庭 conntrack 逐行事件限前 20000 行 + 五元组会话聚合;丰图保留
//     逐行 cap(防炸)与 summary 事件,不实现会话聚合(无规则锚定,
//     查询层可按五元组现算)。
//   - 树庭 ts_raw 归一走「UTC→本地字符串→三层归一」绕圈;丰图管线原生
//     支持 TsUTCDirect 直通 + DTLocal+声明时区,语义等价(见 evtx 先例)。
package parsers

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ye-mengwen/fengtu/internal/descform"
	"github.com/ye-mengwen/fengtu/internal/model"
)

// sliceStream 预解析全量记录后逐条流出(LinuxSC 产物均为 KB~MB 级文本,
// 与 netstatStream 同款取舍;行号=事件序在解析时已编好)。
type sliceStream struct {
	recs []model.Record
	pos  int
}

func (s *sliceStream) Next() (model.Record, bool) {
	if s.pos >= len(s.recs) {
		return model.Record{}, false
	}
	r := s.recs[s.pos]
	s.pos++
	return r, true
}

func (s *sliceStream) Err() error   { return nil }
func (s *sliceStream) Close() error { return nil }

// readLinuxLines 读 LinuxSC 文本产物 → 物理行(不含行尾换行)。
// 编码判别与 netstat 同款:合法 UTF-8 按 UTF-8,否则 GBK 兜底(LinuxSC
// 产物理论 UTF-8,GBK 兜底是中文 locale 实测踩坑来的防线)。
func readLinuxLines(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	enc := "utf-8"
	if !utf8.Valid(raw) {
		enc = "gbk"
	}
	text, err := descform.DecodeBytes(raw, enc)
	if err != nil {
		return nil, err
	}
	return descform.SplitLines(text), nil
}

// linuxMonths 英文三月名(小写)→ 月号;非英文月份不猜(syslog 契约)。
var linuxMonths = map[string]int{
	"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
	"jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

// ---- 采集元信息(_COLLECTION_TIME.txt):syslog 无年份时间戳的年份推断依据 ----

// collectionStartedRe 「LinuxSC Collection Started: 2026/07/28 星期二 17:25:28」
// (星期词随 locale 变,只锚日期;WinInfoSC 同款首行,格式契约一致)。
var collectionStartedRe = regexp.MustCompile(
	`Started:\s*(\d{4})/(\d{2})/(\d{2})\s+\S+\s+(\d{2}):(\d{2}):(\d{2})`)

// collectionTZRe LinuxSC 写的「Timezone=Asia/Beijing」行(timedatectl/
// date 兜底多路,键名恒定)。
var collectionTZRe = regexp.MustCompile(`(?m)^Timezone=(\S+)\s*$`)

// collectionMeta 采集包元信息(从源文件路径向上找 _COLLECTION_TIME.txt,
// 最多上溯 5 层;找不到/解析失败 → ok=false,年份不可推如实)。
type collectionMeta struct {
	year, month, day int
	tz               string
}

func findCollectionMeta(path string) (collectionMeta, bool) {
	dir := filepath.Dir(path)
	for range 5 {
		cand := filepath.Join(dir, "_COLLECTION_TIME.txt")
		if raw, err := os.ReadFile(cand); err == nil {
			text := string(raw)
			if !utf8.Valid(raw) {
				if t, derr := descform.DecodeBytes(raw, "gbk"); derr == nil {
					text = t
				}
			}
			m := collectionStartedRe.FindStringSubmatch(text)
			if m == nil {
				return collectionMeta{}, false
			}
			y, _ := strconv.Atoi(m[1])
			mo, _ := strconv.Atoi(m[2])
			d, _ := strconv.Atoi(m[3])
			tz := ""
			if tm := collectionTZRe.FindStringSubmatch(text); tm != nil {
				tz = tm[1]
			}
			return collectionMeta{year: y, month: mo, day: d, tz: tz}, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return collectionMeta{}, false
}

// inferYear syslog 无年份时间戳的年份推断(树庭 _infer_year 同契约):
// 日志月日在采集月日「之后」(元组字典序) = 跨年(典型 12 月日志 1 月
// 采集)→ 年份 = 采集年-1;否则 = 采集年。rollover 如实标注。
func inferYear(mon, day int, cm collectionMeta) (year int, rollover bool) {
	if mon > cm.month || (mon == cm.month && day > cm.day) {
		return cm.year - 1, true
	}
	return cm.year, false
}

// ---- sshd 认证消息语法抽取(authlog 与 journal 共用,树庭 _action_fields) ----

var (
	// 锚定行首;invalid user 前缀吸收;方法词捕获后丢弃(照树庭)。
	sshdAcceptedRe = regexp.MustCompile(
		`(?i)^Accepted\s+\S+\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)`)
	sshdFailedRe = regexp.MustCompile(
		`(?i)^Failed\s+\S+\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)`)
	sshdInvalidRe = regexp.MustCompile(
		`(?i)^Invalid user\s+(\S+)\s+from\s+(\S+)`)
	// pam_unix session:authlog 锚定行首,journal 用 search(树庭差异照抄)。
	pamSessionRe = regexp.MustCompile(
		`(?i)pam_unix\(\S+\):\s*session\s+(opened|closed)\s+for\s+user\s+(\S+)`)
	pamSessionAnchorRe = regexp.MustCompile(
		`(?i)^pam_unix\(\S+\):\s*session\s+(opened|closed)\s+for\s+user\s+(\S+)`)
)

// sshdAction 从 syslog 消息抽 (action, user, src_ip)。
// 只认 4 类(Disconnected/Connection closed/reverse mapping 等一律不猜,
// 字段留空);sessionAnchored=true 时 session 模式锚定行首(authlog
// 契约),false 时任意位置(journal 契约)。
func sshdAction(msg string, sessionAnchored bool) (action, user, srcIP string) {
	if m := sshdAcceptedRe.FindStringSubmatch(msg); m != nil {
		return "accepted", m[1], m[2]
	}
	if m := sshdFailedRe.FindStringSubmatch(msg); m != nil {
		return "failed", m[1], m[2]
	}
	if m := sshdInvalidRe.FindStringSubmatch(msg); m != nil {
		return "invalid_user", m[1], m[2]
	}
	re := pamSessionRe
	if sessionAnchored {
		re = pamSessionAnchorRe
	}
	if m := re.FindStringSubmatch(msg); m != nil {
		return "session_" + strings.ToLower(m[1]), m[2], ""
	}
	return "", "", ""
}

// ---- ss/netstat 地址拆分(树庭 _split_laddr 同契约) ----

var laddrIfaceRe = regexp.MustCompile(`%[^:\]]*`)

// splitLAddr 拆 地址:端口;%ifname 后缀剥除;[v6]:port 处理;
// 裸 IPv6 无端口不硬猜(整体当地址,port 空);通配/判不准 port 为空(如实)。
func splitLAddr(token string) (addr, port string) {
	token = strings.TrimSpace(laddrIfaceRe.ReplaceAllString(strings.TrimSpace(token), ""))
	if token == "" {
		return "", ""
	}
	if strings.HasPrefix(token, "[") {
		if i := strings.Index(token, "]:"); i >= 0 {
			return token[1:i], token[i+2:]
		}
		if strings.HasSuffix(token, "]") {
			return token, "" // 括号无端口形态:整体当地址
		}
	}
	i := strings.LastIndex(token, ":")
	if i < 0 {
		return token, ""
	}
	host, p := token[:i], token[i+1:]
	if strings.Contains(host, ":") {
		// 含冒号地址:仅 :: 或 ::ffff: 前缀且端口纯数字/* 可拆,否则不硬猜
		low := strings.ToLower(host)
		numericPort := p != "" && isAllDigits(p)
		if (host == "::" || strings.HasPrefix(low, "::ffff:")) && (numericPort || p == "*") {
			if p == "*" {
				p = ""
			}
			return host, p
		}
		return token, ""
	}
	if p == "*" {
		p = ""
	}
	return host, p
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}
