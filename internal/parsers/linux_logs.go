// LinuxSC 采集包日志面解析器(authlog/syslog/journal×2/last/lastlog/yumlog)。
//
// 语义基准 = 树庭 backend/app/parsers/ 的 linux_authlog.py / linux_syslog.py /
// linux_journal.py / linux_last.py / linux_lastlog.py(逐文件对照移植,
// 行式正则与分支照抄,不自作主张增删);linux_yumlog 树庭无对应 parser,
// 为丰图新增,对 yum.log(RHEL 系包管理日志)公开格式 spec 写。
// 采集格式契约 = LINUXSC_SPEC.md + LinuxSC.sh 采集端输出(对 spec 写,
// 不对值写);共享件(readLinuxLines/linuxMonths/findCollectionMeta/
// inferYear/sshdAction)见 linux.go。
//
// 格式契约要点(与树庭逐条对齐):
//   - authlog/secure、messages/syslog/cron:先试 ISO 变体(YYYY-MM-DD[ T]
//     HH:MM:SS,UOS 实测),再试传统 syslog 变体(Mon dd HH:MM:SS,日可空格
//     补齐);都不中 → skip(续行/噪声)。syslog 变体无年份:有采集元信息
//     按 inferYear 推断(跨年 rollover 如实标注),无元信息 → TsRaw 留原文、
//     DTLocal 不设(不归一,如实)。
//   - journalctl_full_shortiso:行内自带 UTC offset → TsUTCDirect 直通
//     (树庭 utc_to_local 回转的等价语义,见 evtx 先例);`--` 头注 skip。
//   - journalctl_sshd_unit / journalctl_xe:本地化短格式,中文月(7月)与
//     英文三月名并存;月份不识 → 事件照产、ts 不设(树庭 ts_raw=None 语义);
//     年份推断契约同 syslog。
//   - last/lastb:last -F 输出,行内自带年份,不推断;wtmp/btmp begins
//     尾注 skip;from_host 原样留存(:0/内核版本号不清洗)。
//   - lastlog:表头 skip;**Never logged in** 与数据行两面;offset 直通。
//   - yum.log:Mon dd HH:MM:SS + 消息(无 host/tag 列),年份推断同 syslog。
//
// 与树庭的已知差异(如实标注):
//   - 树庭不匹配行式计入 skipped 计数(不入库);丰图以 skip 记录留账
//     (零静默),事件数不含它们——语义等价,留账更显式。
//   - 树庭 ts_raw 归一走 UTC→本地字符串绕圈;丰图 TsUTCDirect 直通 /
//     DTLocal naive 墙钟 + 声明时区由管线归一,语义等价。
package parsers

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// skipLogLine 造一条 skip 记录(零静默:每行都有账)。
func skipLogLine(no int, raw, reason string) model.Record {
	return model.Record{LineNo: no, Kind: model.KindSkip, Raw: raw, Reason: strPtrP(reason)}
}

// naiveLocal 拼 naive 墙钟(UTC location 承载,管线按源声明时区归一)。
func naiveLocal(y, mon, d int, hms string) (time.Time, bool) {
	t, err := time.Parse("15:04:05", hms)
	if err != nil {
		return time.Time{}, false
	}
	return time.Date(y, time.Month(mon), d, t.Hour(), t.Minute(), t.Second(), 0, time.UTC), true
}

// ---- authlog / syslog 共用行式(先试 ISO 再试 syslog 变体,树庭同序) ----

var (
	// isoLogLineRe ISO 变体:2026-07-01 00:17:01 host TAG[pid]: msg
	// (UOS 实测;日期与时间分隔允许 T 或空格)。
	// 0.32.0 追加:rsyslog 高精度格式(RSYSLOG_FileFormat,带小数秒+
	// 显式偏移,如 2026-09-21T02:04:51.698311+00:00)——同正则兼容,
	// 有偏移走 TsUTCDirect 直通,无偏移走 DTLocal(如实分流)。
	isoLogLineRe = regexp.MustCompile(
		`^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(\.\d+)?([+-]\d{2}:?\d{2}|Z)?\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$`)
	// syslogLogLineRe 传统 syslog 变体:Mar 12 16:46:24 host TAG[pid]: msg
	// (日可空格补齐两位,如 "Jul  5")。
	syslogLogLineRe = regexp.MustCompile(
		`^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$`)
)

// parseSyslogStyle authlog/syslog/cron/yum 共用的「ISO+syslog 双变体 +
// 年份推断」骨架。unitFromTag=true 时 Norm 加 unit=tag(journal 面契约);
// anchorSession=true 时 sshd session 锚定行首(authlog 契约)。
func parseSyslogStyle(path, source string, unitFromTag, anchorSession bool) ([]model.Record, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	cm, cmOK := findCollectionMeta(path)

	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		if strings.TrimSpace(line) == "" {
			recs = append(recs, skipLogLine(no, line, "空行"))
			continue
		}

		var (
			tsText              string // TsRaw 文本(推断后归一形或原文)
			dt                  time.Time
			hasDT               bool
			host, tag, pid, msg string
			inferred, rollover  bool // 年份推断标注(仅推断时写 Norm)
			matched             bool
		)

		var tsUTC *time.Time // 高精度 ISO 变体带显式偏移 → UTC 直通
		if m := isoLogLineRe.FindStringSubmatch(line); m != nil {
			// ISO 变体:自带年份,不需推断
			matched = true
			tsText = m[1] + " " + m[2]
			host, tag, pid, msg = m[5], m[6], m[7], m[8]
			if m[4] != "" {
				// 带显式偏移(±HHMM/±HH:MM/Z):直通 UTC,不依赖声明时区
				iso := m[1] + "T" + m[2] + m[3] + m[4]
				layouts := []string{"2006-01-02T15:04:05.999999999Z07:00",
					"2006-01-02T15:04:05.999999999Z0700"}
				for _, layout := range layouts {
					if t, perr := time.Parse(layout, iso); perr == nil {
						u := t.UTC()
						tsUTC = &u
						tsText = iso
						break
					}
				}
				if tsUTC == nil {
					matched = false // 有偏移却解析失败:不猜,按不匹配行式留账
				}
			} else if t, perr := time.Parse("2006-01-02 15:04:05", tsText); perr == nil {
				dt, hasDT = t, true
			}
		} else if m := syslogLogLineRe.FindStringSubmatch(line); m != nil {
			mon, ok := linuxMonths[strings.ToLower(m[1])]
			if !ok {
				// 月份不识:authlog 契约 skip 不猜;syslog 契约照产事件、
				// ts 不设(树庭 linux_journal.py:parse_syslog_file 同款,
				// 如实标注 month_unrecognized)。
				if anchorSession {
					recs = append(recs, skipLogLine(no, line, "月份不可识(不猜)"))
					continue
				}
				matched = true
				host, tag, pid, msg = m[4], m[5], m[6], m[7]
				norm := map[string]any{"source": source, "message": msg,
					"month_unrecognized": "true"}
				if host != "" {
					norm["host"] = host
				}
				if tag != "" {
					norm["tag"] = tag
				}
				if unitFromTag && tag != "" {
					norm["unit"] = tag
				}
				if pid != "" {
					norm["pid"] = pid
				}
				recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
					Raw: line, Norm: norm})
				continue
			}
			matched = true
			day, _ := strconv.Atoi(m[2])
			hms := m[3]
			host, tag, pid, msg = m[4], m[5], m[6], m[7]
			if cmOK {
				// syslog 变体无年份:按采集时刻推断(跨年 rollover 如实)
				year, ro := inferYear(mon, day, cm)
				inferred, rollover = true, ro
				tsText = fmt.Sprintf("%04d-%02d-%02d %s", year, mon, day, hms)
				if t, ok2 := naiveLocal(year, mon, day, hms); ok2 {
					dt, hasDT = t, true
				}
			} else {
				// 无采集元信息:TsRaw 留原文,不归一(如实)
				tsText = fmt.Sprintf("%s %d %s", m[1], day, hms)
			}
		}
		if !matched {
			recs = append(recs, skipLogLine(no, line, "不匹配行式(续行/噪声)"))
			continue
		}

		norm := map[string]any{"source": source, "message": msg}
		if host != "" {
			norm["host"] = host
		}
		if tag != "" {
			norm["tag"] = tag
		}
		if unitFromTag && tag != "" {
			// 树庭 syslog 事件挂在 journal_event 面、unit=tag;丰图复刻,
			// journal 类规则(unit=sshd)因此覆盖 messages/syslog 里的
			// sshd 行,与树庭语义一致。
			norm["unit"] = tag
		}
		if pid != "" {
			norm["pid"] = pid // 规则锚定字段恒字符串
		}
		if action, user, srcIP := sshdAction(msg, anchorSession); action != "" {
			norm["action"] = action
			norm["user"] = user
			if srcIP != "" {
				norm["src_ip"] = srcIP
			}
		}
		if inferred {
			norm["year_inferred"] = true
			norm["year_rollover"] = rollover
		}

		rec := model.Record{LineNo: no, Kind: model.KindEvent, Raw: line,
			TsRaw: strPtrP(tsText), Norm: norm}
		if tsUTC != nil {
			rec.TsUTCDirect = tsUTC // 行内显式偏移直通(优先于声明时区)
		} else if hasDT {
			rec.DTLocal = &dt
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

// LinuxAuthlogParser Logs/var/log/{auth.log,secure} 解析器
// (session 锚定行首 = authlog 契约)。
type LinuxAuthlogParser struct{}

// Records 解析 auth.log / secure。
func (LinuxAuthlogParser) Records(path string) (Stream, error) {
	recs, err := parseSyslogStyle(path, "auth_log", false, true)
	if err != nil {
		return nil, err
	}
	return &sliceStream{recs: recs}, nil
}

// LinuxSyslogParser Logs/var/log/{messages,syslog,cron} 解析器
// (session search 模式 + unit=tag = journal 面契约)。
type LinuxSyslogParser struct{}

// Records 解析 messages / syslog / cron(source = 文件基名)。
func (LinuxSyslogParser) Records(path string) (Stream, error) {
	base := filepath.Base(path)
	source := strings.TrimSuffix(base, filepath.Ext(base))
	recs, err := parseSyslogStyle(path, source, true, false)
	if err != nil {
		return nil, err
	}
	return &sliceStream{recs: recs}, nil
}

// ---- journalctl_full_shortiso(行内自带 UTC offset,直通) ----

// journalFullLineRe 2026-07-28T17:06:30+0800 host unit[pid]: msg
var journalFullLineRe = regexp.MustCompile(
	`^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})([+-]\d{4})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$`)

// LinuxJournalFullParser Logs/journalctl_full_shortiso.txt 解析器。
type LinuxJournalFullParser struct{}

// Records 解析 journalctl -o short-iso 全量导出。
func (LinuxJournalFullParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		if strings.TrimSpace(line) == "" {
			recs = append(recs, skipLogLine(no, line, "空行"))
			continue
		}
		if strings.HasPrefix(line, "--") {
			recs = append(recs, skipLogLine(no, line, "journalctl 头注"))
			continue
		}
		m := journalFullLineRe.FindStringSubmatch(line)
		if m == nil {
			recs = append(recs, skipLogLine(no, line, "不匹配行式(续行/噪声)"))
			continue
		}
		tsText := m[1] + "T" + m[2] + m[3]
		norm := map[string]any{
			"source":    "journalctl_full_shortiso",
			"host":      m[4],
			"unit":      m[5],
			"message":   m[7],
			"ts_offset": m[3],
		}
		if m[6] != "" {
			norm["pid"] = m[6]
		}
		if action, user, srcIP := sshdAction(m[7], false); action != "" {
			norm["action"] = action
			norm["user"] = user
			if srcIP != "" {
				norm["src_ip"] = srcIP
			}
		}
		rec := model.Record{LineNo: no, Kind: model.KindEvent, Raw: line,
			TsRaw: strPtrP(tsText), Norm: norm}
		if t, perr := time.Parse("2006-01-02T15:04:05-0700", tsText); perr == nil {
			utc := t.UTC()
			rec.TsUTCDirect = &utc // UTC 直通(树庭回转本地的等价语义)
		}
		// 解析失败 → 不设 ts(如实;offset 原文仍留 ts_offset)
		recs = append(recs, rec)
	}
	return &sliceStream{recs: recs}, nil
}

// ---- journalctl 本地化短格式(sshd_unit / xe;中文月与英文三月名并存) ----

// journalShortLineRe 「7月 28 17:17:44 host unit[pid]: msg」或
// 「Mar 12 16:46:24 host unit[pid]: msg」。
var journalShortLineRe = regexp.MustCompile(
	`^(?:(\d{1,2})月|([A-Za-z]{3}))\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$`)

// LinuxJournalShortParser Logs/journalctl_{sshd_unit,xe}.txt 解析器。
type LinuxJournalShortParser struct{}

// Records 解析 journalctl 本地化短格式导出。
func (LinuxJournalShortParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	// source 按文件基名:sshd_unit 专属导出 vs journalctl -xe 兜底
	base := filepath.Base(path)
	source := "journalctl_xe"
	if strings.Contains(base, "sshd_unit") {
		source = "journalctl_sshd_unit"
	}
	cm, cmOK := findCollectionMeta(path)

	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		if strings.TrimSpace(line) == "" {
			recs = append(recs, skipLogLine(no, line, "空行"))
			continue
		}
		if strings.HasPrefix(line, "--") {
			recs = append(recs, skipLogLine(no, line, "journalctl 头注"))
			continue
		}
		m := journalShortLineRe.FindStringSubmatch(line)
		if m == nil {
			recs = append(recs, skipLogLine(no, line, "不匹配行式(续行/噪声)"))
			continue
		}
		// 组:1=中文月数字 2=英文月名 3=day 4=hms 5=host 6=unit 7=pid 8=msg
		host, unit, pid, msg := m[5], m[6], m[7], m[8]
		norm := map[string]any{"source": source, "host": host, "unit": unit, "message": msg}
		if pid != "" {
			norm["pid"] = pid
		}
		if action, user, srcIP := sshdAction(msg, false); action != "" {
			norm["action"] = action
			norm["user"] = user
			if srcIP != "" {
				norm["src_ip"] = srcIP
			}
		}
		rec := model.Record{LineNo: no, Kind: model.KindEvent, Raw: line, Norm: norm}

		// 月份:中文组直取数字,英文组查三月名表;都不识 → 事件照产、
		// ts 不设(树庭 ts_raw=None 语义,照抄)
		mon := 0
		rawMon := m[1] + "月"
		if m[1] != "" {
			mon, _ = strconv.Atoi(m[1])
		} else {
			rawMon = m[2]
			if v, ok := linuxMonths[strings.ToLower(m[2])]; ok {
				mon = v
			}
		}
		if mon > 0 {
			day, _ := strconv.Atoi(m[3])
			hms := m[4]
			if cmOK {
				year, rollover := inferYear(mon, day, cm)
				tsText := fmt.Sprintf("%04d-%02d-%02d %s", year, mon, day, hms)
				rec.TsRaw = strPtrP(tsText)
				if t, ok2 := naiveLocal(year, mon, day, hms); ok2 {
					rec.DTLocal = &t
				}
				norm["year_inferred"] = true
				norm["year_rollover"] = rollover
			} else {
				// 无采集元信息:TsRaw 留原文,不归一(如实)
				rec.TsRaw = strPtrP(fmt.Sprintf("%s %d %s", rawMon, day, hms))
			}
		}
		recs = append(recs, rec)
	}
	return &sliceStream{recs: recs}, nil
}

// ---- last / lastb(last -F 输出,行内自带年份) ----

// lastLineRe 树庭契约行式:user tty from_host(非贪婪) 起(Mon dd hms year)
// [ - 止] status尾段。
var lastLineRe = regexp.MustCompile(
	`^(\S+)\s+(\S+)\s+(.+?)\s+(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})(?:\s+-\s+(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+)?([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4}))?\s*(.*)$`)

// lastBeginsRe wtmp/btmp 起始尾注(结构行,非登录事件)。
var lastBeginsRe = regexp.MustCompile(`(?i)^(wtmp|btmp)\s+begins\b`)

// LinuxLastParser Logs/{last,lastb}.txt 解析器。
type LinuxLastParser struct{}

// Records 解析 last -F / lastb -F 输出。
func (LinuxLastParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	source := "last"
	if filepath.Base(path) == "lastb.txt" {
		source = "lastb"
	}

	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		if strings.TrimSpace(line) == "" {
			recs = append(recs, skipLogLine(no, line, "空行"))
			continue
		}
		if lastBeginsRe.MatchString(line) {
			recs = append(recs, skipLogLine(no, line, "wtmp/btmp 起始注记(结构行)"))
			continue
		}
		m := lastLineRe.FindStringSubmatch(line)
		if m == nil {
			recs = append(recs, skipLogLine(no, line, "不匹配行式(续行/噪声)"))
			continue
		}
		norm := map[string]any{
			"source":    source,
			"user":      m[1],
			"tty":       m[2],
			"from_host": strings.TrimSpace(m[3]), // :0/内核版本号原样留存,不清洗
		}
		rec := model.Record{LineNo: no, Kind: model.KindEvent, Raw: line, Norm: norm}

		// 起始时间:行内自带年份,不推断;月份不识 → 不设 ts(不猜)
		if mon, ok := linuxMonths[strings.ToLower(m[4])]; ok {
			day, _ := strconv.Atoi(m[5])
			year, _ := strconv.Atoi(m[7])
			tsText := fmt.Sprintf("%04d-%02d-%02d %s", year, mon, day, m[6])
			rec.TsRaw = strPtrP(tsText)
			norm["start"] = tsText
			if t, ok2 := naiveLocal(year, mon, day, m[6]); ok2 {
				rec.DTLocal = &t
			}
		}
		// 结束时间(可选):同理格式串存 Norm["end"],仅留存不参与 ts
		if m[8] != "" {
			if mon, ok := linuxMonths[strings.ToLower(m[8])]; ok {
				day, _ := strconv.Atoi(m[9])
				year, _ := strconv.Atoi(m[11])
				norm["end"] = fmt.Sprintf("%04d-%02d-%02d %s", year, mon, day, m[10])
			}
		}
		if status := strings.TrimSpace(m[12]); status != "" {
			norm["status"] = status
		}
		recs = append(recs, rec)
	}
	return &sliceStream{recs: recs}, nil
}

// ---- lastlog(表头 / Never logged in / 数据行三面) ----

// lastlogLineRe 数据行:user [port from_host] 星期词 中/英月 day hms offset year
// (port/from_host 可缺一并对缺——树庭契约照抄,部分缺列的行不中即 skip)。
var lastlogLineRe = regexp.MustCompile(
	`^(\S+)(?:\s+(\S+)\s+(\S+))?\s+\S+\s+(?:(\d{1,2})月|([A-Za-z]{3}))\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+([+-]\d{4})\s+(\d{4})\s*$`)

// lastlogNeverMark 从未登录标记(中英文 locale 均为英文文案,lastlog 契约)。
const lastlogNeverMark = "**Never logged in**"

// LinuxLastlogParser Logs/lastlog.txt 解析器。
type LinuxLastlogParser struct{}

// Records 解析 lastlog 输出。
func (LinuxLastlogParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		if strings.TrimSpace(line) == "" {
			recs = append(recs, skipLogLine(no, line, "空行"))
			continue
		}
		if strings.HasPrefix(strings.TrimLeft(line, " \t"), "Username") {
			recs = append(recs, skipLogLine(no, line, "表头"))
			continue
		}
		if strings.Contains(line, lastlogNeverMark) {
			user := strings.Fields(line)[0]
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent, Raw: line,
				Norm: map[string]any{"source": "lastlog", "user": user, "never": "true"}})
			continue
		}
		m := lastlogLineRe.FindStringSubmatch(line)
		if m == nil {
			recs = append(recs, skipLogLine(no, line, "不匹配行式(续行/噪声)"))
			continue
		}
		norm := map[string]any{"source": "lastlog", "user": m[1], "never": "false"}
		if m[2] != "" {
			norm["port"] = m[2]
		}
		if m[3] != "" {
			norm["from_host"] = m[3]
		}
		rec := model.Record{LineNo: no, Kind: model.KindEvent, Raw: line, Norm: norm}

		// 月份:中文直取 / 英文查表;不识 → 不设 ts(不猜)
		mon := 0
		if m[4] != "" {
			mon, _ = strconv.Atoi(m[4])
		} else if v, ok := linuxMonths[strings.ToLower(m[5])]; ok {
			mon = v
		}
		if mon > 0 {
			day, _ := strconv.Atoi(m[6])
			year, _ := strconv.Atoi(m[9])
			offset := m[8]
			tsText := fmt.Sprintf("%04d-%02d-%02d %s%s", year, mon, day, m[7], offset)
			rec.TsRaw = strPtrP(tsText)
			norm["ts_offset"] = offset
			if t, perr := time.Parse("2006-01-02 15:04:05-0700", tsText); perr == nil {
				utc := t.UTC()
				rec.TsUTCDirect = &utc // UTC 直通
			}
		}
		recs = append(recs, rec)
	}
	return &sliceStream{recs: recs}, nil
}

// ---- yum.log(树庭无此 parser;丰图新增,对 yum.log 格式 spec 写) ----

// yumLogLineRe 「Mar 12 16:46:24 Installed: passwd-0.80-1.x86_64」
// (无 host/tag 列)。
var yumLogLineRe = regexp.MustCompile(
	`^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(.*)$`)

// LinuxYumlogParser Logs/var/log/yum.log 解析器。
type LinuxYumlogParser struct{}

// Records 解析 yum.log(年份推断契约同 syslog)。
func (LinuxYumlogParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	cm, cmOK := findCollectionMeta(path)

	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		if strings.TrimSpace(line) == "" {
			recs = append(recs, skipLogLine(no, line, "空行"))
			continue
		}
		m := yumLogLineRe.FindStringSubmatch(line)
		if m == nil {
			recs = append(recs, skipLogLine(no, line, "不匹配行式(续行/噪声)"))
			continue
		}
		mon, ok := linuxMonths[strings.ToLower(m[1])]
		if !ok {
			recs = append(recs, skipLogLine(no, line, "月份不可识(不猜)"))
			continue
		}
		day, _ := strconv.Atoi(m[2])
		hms, msg := m[3], m[4]
		norm := map[string]any{"source": "yum_log", "message": msg}
		rec := model.Record{LineNo: no, Kind: model.KindEvent, Raw: line, Norm: norm}
		if cmOK {
			year, rollover := inferYear(mon, day, cm)
			tsText := fmt.Sprintf("%04d-%02d-%02d %s", year, mon, day, hms)
			rec.TsRaw = strPtrP(tsText)
			if t, ok2 := naiveLocal(year, mon, day, hms); ok2 {
				rec.DTLocal = &t
			}
			norm["year_inferred"] = true
			norm["year_rollover"] = rollover
		} else {
			// 无采集元信息:TsRaw 留原文,不归一(如实)
			rec.TsRaw = strPtrP(fmt.Sprintf("%s %d %s", m[1], day, hms))
		}
		recs = append(recs, rec)
	}
	return &sliceStream{recs: recs}, nil
}
