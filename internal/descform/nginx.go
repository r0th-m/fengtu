// 内置 nginx combined 格式解析器(对 spec 写,语义照索图 nginx_combined.py)。
//
// spec 依据:nginx 默认 LogFormat combined——
//
//	$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
//	"$http_referer" "$http_user_agent"
//
//	time_local 形如 10/Oct/2000:13:55:36 +0300。
//
// 实现说明(2026-09-21 性能轮):初版用一组正则切行,台架 pprof 实测
// 正则引擎占 worker CPU ~22%(doOnePass+MatchRune);本版热路径手写
// 字节切分,语义与原正则版逐点等价(状态码必须 3 位、引号定界、trailing
// 处理、坏行判定),等价性由 golden/nginx*.golden.jsonl 金标准焊死。
// XFF 判定是冷路径(仅 trailing 非空时),保留正则。
//
// 诚实边界(与索图同款):
//   - 行内时区段(+0300)如实抽进 extras.time_offset 留证,归一不猜用——
//     归一只按源声明时区 tz_declared 走;
//   - $request 拆不出「方法 路径 协议」三段时(如 "-"),不判坏行:
//     原文进 extras.request,method/path 留 NULL;
//   - status 非三位数字、time_local 解析失败 → 坏行计数,零静默;
//   - combined 之后的追加字段进 extras.trailing;若恰好是单个引号段且内容
//     形如 IP 列表(常见 $http_x_forwarded_for 追加法),抽为 norm.xff
//     留真实客户端源——首列 src_ip 可能是 WAF/代理回源节点;多跳原样保留。
package descform

import (
	"iter"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// NginxCombinedFormatID 内置格式标识(与索图注册表一致)。
const NginxCombinedFormatID = "nginx_combined"

var (
	// trailing 里的 XFF 形态:单个引号段 + IP 列表(多跳逗号分隔)——冷路径
	nginxXFFTrailingRe = regexp.MustCompile(`^"(?P<xff>[^"]*)"$`)
	nginxIPListRe      = regexp.MustCompile(
		`^\d{1,3}(?:\.\d{1,3}){3}(?:\s*,\s*\d{1,3}(?:\.\d{1,3}){3})*$`)
)

// nginxMonths 小写三字母月份 → 月序(Go time.Parse 月份名大小写不敏感,
// 手工等价:折叠为小写查表)。
var nginxMonths = map[string]time.Month{
	"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
	"jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

// tokenAt 取到下一空格为止的非空 token(\S+ 语义);
// 返回内容与 token 结束位(即空格位置或串尾);失败 ok=false。
// 约定:不消费尾随空格,调用方按行式自行处置定界符。
func tokenAt(s string, i int) (string, int, bool) {
	if i >= len(s) || s[i] == ' ' {
		return "", i, false
	}
	j := strings.IndexByte(s[i:], ' ')
	if j < 0 {
		return s[i:], len(s), true
	}
	return s[i : i+j], i + j, true
}

// nextQuoted 期望 ` "` 并取到下一引号为止的内容(引号定界语义);
// 返回内容与 closing quote 后一位。
func nextQuoted(s string, i int) (string, int, bool) {
	if i+1 >= len(s) || s[i] != ' ' || s[i+1] != '"' {
		return "", i, false
	}
	rest := s[i+2:]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return "", i, false
	}
	return rest[:j], i + 2 + j + 1, true
}

// digits2/digits4 定长数字段(定长是 spec:dd/yyyy/HH/MM/SS)。
func digits2(s string, i int) (int, bool) {
	if i+2 > len(s) {
		return 0, false
	}
	a, b := s[i], s[i+1]
	if a < '0' || a > '9' || b < '0' || b > '9' {
		return 0, false
	}
	return int(a-'0')*10 + int(b-'0'), true
}

func digits4(s string, i int) (int, bool) {
	if i+4 > len(s) {
		return 0, false
	}
	n := 0
	for k := 0; k < 4; k++ {
		c := s[i+k]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

// parseTimeLocal time_local → (naive 本地时间, 行内时区段);失败 ok=false。
// 形如 04/Aug/2026:00:00:01 +0800;月份名大小写不敏感(同 Go time.Parse);
// 各字段值域校验与 time.Parse 一致(日 1..31,时 0..23,分秒 0..59,
// 越界判失败;合法但不存在的日期如 2/30 与 Go 同款由 time.Date 归一)。
func parseTimeLocal(text string) (local time.Time, offset string, ok bool) {
	s := strings.TrimSpace(text)
	// 定长布局:dd/Mon/yyyy:HH:MM:SS +zzzz(最少 24+1+5 字节)
	day, ok1 := digits2(s, 0)
	if !ok1 || len(s) < 25 || s[2] != '/' || s[6] != '/' || s[11] != ':' ||
		s[14] != ':' || s[17] != ':' || s[20] != ' ' {
		return time.Time{}, "", false
	}
	mon, mok := nginxMonths[strings.ToLower(s[3:6])]
	year, yok := digits4(s, 7)
	hh, hok := digits2(s, 12)
	mm, mmok := digits2(s, 15)
	ss, sok := digits2(s, 18)
	if !mok || !yok || !hok || !mmok || !sok ||
		day < 1 || day > 31 || hh > 23 || mm > 59 || ss > 59 {
		return time.Time{}, "", false
	}
	off := s[21:]
	if len(off) != 5 || (off[0] != '+' && off[0] != '-') {
		return time.Time{}, "", false
	}
	if _, ok4 := digits4(off, 1); !ok4 {
		return time.Time{}, "", false
	}
	// 剥离为 naive 墙钟(UTC location 承载),偏移段只留证
	return time.Date(year, mon, day, hh, mm, ss, 0, time.UTC), off, true
}

// splitRequest $request → method/path(+query)/protocol;
// 拆不出 → 原文进 extras.request(与索图同款不判坏行)。
// 等价原正则 ^(?P<method>\S+) (?P<target>\S+)(?: (?P<protocol>\S+))?$。
func splitRequest(request string, norm map[string]any) {
	sp1 := strings.IndexByte(request, ' ')
	if sp1 <= 0 || sp1+1 >= len(request) {
		if request != "" {
			normSetExtras(norm)["request"] = request
		}
		return
	}
	method := request[:sp1]
	rest := request[sp1+1:]
	var target, protocol string
	if sp2 := strings.IndexByte(rest, ' '); sp2 < 0 {
		target = rest
	} else {
		if sp2 == 0 || sp2+1 >= len(rest) ||
			strings.IndexByte(rest[sp2+1:], ' ') >= 0 {
			// target 空 / protocol 空 / protocol 含空格:整式不匹配
			normSetExtras(norm)["request"] = request
			return
		}
		target, protocol = rest[:sp2], rest[sp2+1:]
	}
	norm["method"] = method
	if i := strings.IndexByte(target, '?'); i >= 0 {
		norm["path"] = target[:i]
		norm["query"] = target[i+1:]
	} else {
		norm["path"] = target
	}
	if protocol != "" {
		normSetExtras(norm)["protocol"] = protocol
	}
}

func normSetExtras(norm map[string]any) map[string]any {
	extras, _ := norm["extras"].(map[string]any)
	if extras == nil {
		extras = map[string]any{}
		norm["extras"] = extras
	}
	return extras
}

// nginxFields 一行 combined 的切分结果(定长结构,热路径零 map)。
type nginxFields struct {
	srcIP, user, time, request, status, bytes, referer, ua, trailing string
}

// parseNginxLine 切一行 combined;失败 ok=false(调用方判坏行)。
// 定界与原正则逐点等价:token 间恰好一个空格,引号段 ` "..."`,
// status 为 ` \d{3} `,ua 后的一切原样进 trailing。
func parseNginxLine(raw string, m *nginxFields) bool {
	i := 0
	var f string
	var ok bool
	if f, i, ok = tokenAt(raw, i); !ok || i >= len(raw) {
		return false
	}
	m.srcIP = f
	i++
	if _, i, ok = tokenAt(raw, i); !ok || i >= len(raw) { // identd 段(须存在,语义不取)
		return false
	}
	i++
	if f, i, ok = tokenAt(raw, i); !ok || i >= len(raw) {
		return false
	}
	m.user = f
	i++
	// "[time]"
	if i >= len(raw) || raw[i] != '[' {
		return false
	}
	j := strings.IndexByte(raw[i:], ']')
	if j < 0 {
		return false
	}
	m.time = raw[i+1 : i+j]
	i += j + 1
	// ` "request" status bytes "referer" "ua"trailing`
	if f, i, ok = nextQuoted(raw, i); !ok {
		return false
	}
	m.request = f
	// status:空格 + 恰好 3 位数字 + 空格(spec ` \d{3} `)
	if i+5 > len(raw) || raw[i] != ' ' {
		return false
	}
	for k := 1; k <= 3; k++ {
		if raw[i+k] < '0' || raw[i+k] > '9' {
			return false
		}
	}
	if raw[i+4] != ' ' {
		return false
	}
	m.status = raw[i+1 : i+4]
	// bytes:token,尾随空格留给 nextQuoted 的 ` "` 定界
	if f, i, ok = tokenAt(raw, i+5); !ok {
		return false
	}
	m.bytes = f
	if f, i, ok = nextQuoted(raw, i); !ok {
		return false
	}
	m.referer = f
	if f, i, ok = nextQuoted(raw, i); !ok {
		return false
	}
	m.ua = f
	m.trailing = raw[i:]
	return true
}

// ParseNginxCombined 内置 nginx combined 解析驱动(逐行无状态)。
// lines: 物理行(utf-8,已通用换行切分、不含行尾换行符)。
func ParseNginxCombined(lines []string) iter.Seq[model.Record] {
	return func(yield func(model.Record) bool) {
		var m nginxFields
		for lineNo, raw := range lines {
			lineNo++
			if strings.TrimSpace(raw) == "" {
				if !yield(model.Record{LineNo: lineNo, Raw: raw, Kind: model.KindSkip,
					Reason: strPtr("空行")}) {
					return
				}
				continue
			}
			if !parseNginxLine(raw, &m) {
				if !yield(model.Record{LineNo: lineNo, Raw: raw, Kind: model.KindBad,
					Reason: strPtr("不匹配 combined 行式")}) {
					return
				}
				continue
			}
			dtLocal, tzSeg, ok := parseTimeLocal(m.time)
			tsRaw := m.time
			if !ok {
				if !yield(model.Record{LineNo: lineNo, Raw: raw, Kind: model.KindBad,
					TsRaw: &tsRaw, Reason: strPtr("time_local 解析失败")}) {
					return
				}
				continue
			}
			norm := make(map[string]any, 12)
			norm["src_ip"] = m.srcIP
			if user := m.user; user != "" && user != "-" {
				norm["user"] = user
			}
			splitRequest(m.request, norm)
			if status, err := strconv.Atoi(m.status); err == nil {
				norm["status"] = status
			}
			if b := m.bytes; b != "-" {
				if n, err := strconv.Atoi(b); err == nil {
					norm["bytes"] = n
				}
			}
			if ref := m.referer; ref != "" && ref != "-" {
				norm["referer"] = ref
			}
			if ua := m.ua; ua != "" && ua != "-" {
				norm["ua"] = ua
			}
			extras := normSetExtras(norm)
			extras["time_offset"] = tzSeg // 行内时区如实留证,不猜用
			if trailing := strings.TrimSpace(m.trailing); trailing != "" {
				if xl := matchAt(nginxXFFTrailingRe, trailing); xl != nil &&
					nginxIPListRe.MatchString(
						strings.TrimSpace(trailing[xl[2]:xl[3]])) {
					norm["xff"] = strings.TrimSpace(trailing[xl[2]:xl[3]])
				} else {
					extras["trailing"] = trailing
				}
			}
			if len(extras) == 0 {
				delete(norm, "extras")
			}
			rec := model.Record{LineNo: lineNo, Raw: raw, Kind: model.KindEvent,
				TsRaw: &tsRaw, DTLocal: &dtLocal, Norm: norm}
			if !yield(rec) {
				return
			}
		}
	}
}
