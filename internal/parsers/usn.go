// USN Journal CSV(fsutil usn readjournal /csv)流式解析(M3,切片七遗留
// 落地):逐行 usn_change 事件 + 收尾 usn_journal_summary;语义逐字段移植
// 树庭 backend/app/parsers/usn.py(金标准基准)。
//
// 格式契约(fsutil /csv,对公开 spec 写):
//   - 前置元数据块(本地化键名,键随系统语言变,值契约不变)→ 原行进
//     summary 留证,Journal ID 按 `ID: 0x<hex>` 提取(语言无关);
//     空行后是 CSV 表头,首列恒为 "Usn"(语言无关锚点,大小写不敏感);
//   - 数据列位置固定(本地化只改表头名与「原因/文件属性」文本,不改列序):
//     0 Usn / 1 文件名 / 2 文件名长度 / 3 原因编号(0x????????)/ 4 原因 /
//     5 时间戳(本地文本) / 6 文件属性编号 / 7 文件属性 / 8 文件 ID /
//     9 父文件 ID / 12 安全 ID / 13 主要版本 / 14 次要版本 / 15 记录长度
//     (尾部盘区列恒为空可缺,前 16 列必备);
//   - 结构锚点:Usn 纯数字 + 原因编号 0x+8hex;两锚不符 = 未知列布局变体
//     → bad_row 计数;全文件零有效行 → 文件级如实 failed,不猜布局;
//   - 变更原因从原因编号 hex 位解码(USN_REASON_* winnt.h 常量,语言无关),
//     本地化原因文本原样留证不参与判定(对 spec 写不对值写);
//   - 时间戳是主机本地文本 → dt_local 交管线三层归一(tz 声明/NULL 如实);
//     编码:无 BOM 且前 4KB 合法 UTF-8 → utf-8,否则 GBK(中文 Windows
//     fsutil 默认 ANSI),选择入 summary 留证;
//   - 父文件 ID 是 FRN 引用,CSV 不携带父路径:不伪造路径,parent_file_id
//     留证(路径关联留给 MFT 记录)。
//
// 算子契约:host-time-cluster 读 fields.path(=文件名)与 fields.reason_hex,
// 本解析器同名产出(见 configs/operators/host-time-cluster.yaml)。
package parsers

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"

	"github.com/ye-mengwen/fengtu/internal/model"
)

var (
	usnHex8Re      = regexp.MustCompile(`^0x[0-9a-f]{8}$`) // 原因编号结构锚点
	usnJournalIDRe = regexp.MustCompile(`ID\s*:\s*(0x[0-9A-Fa-f]+)`)
)

const (
	usnPreambleCap   = 20 // 前置元数据行留证上限
	usnBadExampleCap = 5  // 坏行样例留证上限
	usnMinCols       = 16 // 前 16 列必备(尾部盘区列恒空可缺)
	usnDetectBytes   = 4096
)

// USN_REASON_*(winnt.h,语言无关 spec 常量):从原因编号 hex 位解码。
var usnReasonFlags = []struct {
	bit  uint64
	name string
}{
	{0x00000001, "DATA_OVERWRITE"}, {0x00000002, "DATA_EXTEND"},
	{0x00000004, "DATA_TRUNCATION"}, {0x00000010, "NAMED_DATA_OVERWRITE"},
	{0x00000020, "NAMED_DATA_EXTEND"}, {0x00000040, "NAMED_DATA_TRUNCATION"},
	{0x00000100, "FILE_CREATE"}, {0x00000200, "FILE_DELETE"},
	{0x00000400, "EA_CHANGE"}, {0x00000800, "SECURITY_CHANGE"},
	{0x00001000, "RENAME_OLD_NAME"}, {0x00002000, "RENAME_NEW_NAME"},
	{0x00004000, "INDEXABLE_CHANGE"}, {0x00008000, "BASIC_INFO_CHANGE"},
	{0x00010000, "HARD_LINK_CHANGE"}, {0x00020000, "COMPRESSION_CHANGE"},
	{0x00040000, "ENCRYPTION_CHANGE"}, {0x00080000, "OBJECT_ID_CHANGE"},
	{0x00100000, "REPARSE_POINT_CHANGE"}, {0x00200000, "STREAM_CHANGE"},
	{0x80000000, "CLOSE"},
}

// usnReasonNames 原因位掩码 → 标志名列表;未知位如实 UNKNOWN_0x…… 列出。
func usnReasonNames(code uint64) []string {
	var names []string
	var known uint64
	for _, rf := range usnReasonFlags {
		known |= rf.bit
		if code&rf.bit != 0 {
			names = append(names, rf.name)
		}
	}
	if unknown := code &^ known; unknown != 0 {
		names = append(names, fmt.Sprintf("UNKNOWN_0x%08X", unknown))
	}
	return names
}

// usnTSLayouts 时间戳本地文本布局(实测:中文 fsutil "2026/7/9 15:15:46";
// 区域变体归一失败 → ts 留 nil,TsRaw 留证,不猜)。
var usnTSLayouts = []string{
	"2006/1/2 15:04:05", "2006/01/02 15:04:05",
	"2006-1-2 15:04:05", "2006-01-02 15:04:05",
}

// UsnCSVParser USN CSV 解析器。
type UsnCSVParser struct{}

// usnStream 流式行解析(csv.Reader 惰性推进,summary 在 EOF 后放出)。
type usnStream struct {
	f      *os.File
	r      *csv.Reader
	enc    string
	lineNo int // 物理行号(FieldPos)

	headerSeen bool
	journalID  string
	preamble   []string

	valid, bad  int64
	badExamples []string
	noTS        int64
	firstUSN    uint64
	lastUSN     uint64
	reasonHist  map[string]int64
	topFiles    map[string]int64

	summary   *model.Record
	exhausted bool // EOF 终止标记(防 summary 无限重放,2026-09-22 事故修复)
	err       error
}

// Records 打开 USN CSV(编码探测在此;文件打不开 → 文件级失败)。
func (UsnCSVParser) Records(path string) (Stream, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("USN CSV 打开失败: %w", err)
	}
	// 编码探测:前 4KB;BOM→UTF-8;合法 UTF-8→utf-8;否则 GBK(中文
	// Windows fsutil 默认 ANSI;纯 ASCII 两码同解,选择如实留证)
	br := bufio.NewReader(f)
	sample, _ := br.Peek(usnDetectBytes)
	enc := "gbk"
	if len(sample) >= 3 && sample[0] == 0xEF && sample[1] == 0xBB && sample[2] == 0xBF {
		enc = "utf-8-sig"
	} else if utf8.Valid(sample) {
		enc = "utf-8"
	}
	var rd io.Reader = br
	if enc == "gbk" {
		rd = transform.NewReader(br, simplifiedchinese.GBK.NewDecoder())
	}
	cr := csv.NewReader(rd)
	cr.FieldsPerRecord = -1 // 列数不齐不拦,结构锚点自定夺
	cr.LazyQuotes = false
	return &usnStream{f: f, r: cr, enc: enc,
		reasonHist: map[string]int64{}, topFiles: map[string]int64{}}, nil
}

// Next 逐行产出 usn_change;表头未现 → 前置块留证;EOF → summary 收尾(仅一次,
// exhausted 后恒 false——2026-09-22 事故根因:EOF 后无终止标记,finish()
// 被无限重放,summary 无限产出,调用方 drain 内存爆炸)。
func (s *usnStream) Next() (model.Record, bool) {
	if s.err != nil || s.exhausted {
		return model.Record{}, false
	}
	for {
		cells, err := s.r.Read()
		if err == io.EOF {
			s.finish()
			s.exhausted = true // 终止标记:此后恒 false,绝不重放
			if s.err != nil {
				return model.Record{}, false
			}
			if s.summary != nil {
				rec := *s.summary
				s.summary = nil
				return rec, true
			}
			return model.Record{}, false
		}
		if err != nil {
			s.err = fmt.Errorf("CSV 读取失败(行 %d 附近): %w", s.lineNo, err)
			return model.Record{}, false
		}
		pos, _ := s.r.FieldPos(0)
		s.lineNo = pos
		if emptyCells(cells) {
			continue // 空行(前置块与表头之间/文件尾)
		}
		if !s.headerSeen {
			if strings.EqualFold(strings.TrimSpace(cells[0]), "usn") {
				s.headerSeen = true // 语言无关锚点:首列恒为 Usn
				continue
			}
			line := strings.Join(cells, " | ")
			if len(s.preamble) < usnPreambleCap {
				s.preamble = append(s.preamble, line)
			}
			if s.journalID == "" {
				if m := usnJournalIDRe.FindStringSubmatch(line); m != nil {
					s.journalID = m[1]
				}
			}
			continue
		}
		rec, isBad := s.parseRow(cells)
		if isBad {
			s.bad++
			if len(s.badExamples) < usnBadExampleCap {
				s.badExamples = append(s.badExamples, fmt.Sprintf(
					"line %d: %s", s.lineNo, truncRunes(strings.Join(cells, " | "), 200)))
			}
			return rec, true // 坏行产出 bad 记录(零静默)
		}
		return rec, true
	}
}

// parseRow 一行 → usn_change 事件;结构锚点不符 → bad 记录(第二返回值 true
// 且 KindBad;列数不足等无事件价值的行也走 bad 如实计)。
func (s *usnStream) parseRow(cells []string) (model.Record, bool) {
	raw := truncRunes(strings.Join(cells, " | "), 500)
	bad := func(why string) (model.Record, bool) {
		return model.Record{LineNo: s.lineNo, Kind: model.KindBad,
			Reason: &why, Raw: raw}, true
	}
	if len(cells) < usnMinCols {
		return bad(fmt.Sprintf("列数 %d 不足 %d(结构锚点不符,未知列布局不猜)",
			len(cells), usnMinCols))
	}
	usnStr := strings.TrimSpace(cells[0])
	usn, err := strconv.ParseUint(usnStr, 10, 64)
	if err != nil {
		return bad("Usn 列非纯数字(结构锚点不符)")
	}
	reasonHex := strings.ToLower(strings.TrimSpace(cells[3]))
	if !usnHex8Re.MatchString(reasonHex) {
		return bad("原因编号非 0x+8hex(结构锚点不符)")
	}
	filename := cells[1]
	if filename == "" {
		return bad("无文件名(无事件价值,如实计)")
	}
	code, _ := strconv.ParseUint(reasonHex[2:], 16, 64)

	norm := map[string]any{
		"event_type":     "usn_change",
		"usn":            usn,
		"path":           filename, // 算子契约字段(host-time-cluster)
		"filename":       filename,
		"reason_hex":     reasonHex, // 算子契约字段
		"reason_flags":   usnReasonNames(code),
		"reason_text":    cells[4], // 本地化原文留证,不参与判定
		"file_id":        strings.TrimSpace(cells[8]),
		"parent_file_id": strings.TrimSpace(cells[9]),
	}
	if v, ok := usnIntOrNone(cells[2]); ok {
		norm["filename_length"] = v
	}
	norm["file_attributes_hex"] = strings.TrimSpace(cells[6])
	norm["file_attributes_text"] = cells[7]
	if v, ok := usnIntOrNone(cells[12]); ok {
		norm["security_id"] = v
	}
	if v, ok := usnIntOrNone(cells[13]); ok {
		norm["major_version"] = v
	}
	if v, ok := usnIntOrNone(cells[14]); ok {
		norm["minor_version"] = v
	}
	if v, ok := usnIntOrNone(cells[15]); ok {
		norm["record_length"] = v
	}

	rec := model.Record{LineNo: s.lineNo, Kind: model.KindEvent,
		Norm: norm, Raw: raw}
	tsRaw := strings.TrimSpace(cells[5])
	if tsRaw != "" {
		rec.TsRaw = &tsRaw
		if t, ok := parseUSNLocal(tsRaw); ok {
			rec.DTLocal = &t // 本地墙钟,管线按时区声明三层归一
		} else {
			s.noTS++ // 区域变体归一失败:ts 留 nil,TsRaw 留证,不猜
		}
	}

	s.valid++
	if s.valid == 1 {
		s.firstUSN = usn
	}
	s.lastUSN = usn
	for _, fl := range norm["reason_flags"].([]string) {
		s.reasonHist[fl]++
	}
	s.topFiles[filename]++
	return rec, false
}

// finish EOF 收尾:表头未现/零有效行 → err(文件级如实 failed);否则 summary。
func (s *usnStream) finish() {
	if !s.headerSeen {
		head := "<空文件>"
		if len(s.preamble) > 0 {
			head = truncRunes(strings.Join(s.preamble[:min(3, len(s.preamble))], " ; "), 200)
		}
		s.err = fmt.Errorf("未找到 USN CSV 表头(首列 'Usn');文件开头: %s", head)
		return
	}
	if s.valid == 0 {
		s.err = fmt.Errorf("表头存在但无有效数据行(共扫 %d 行全不符结构锚点:"+
			"Usn 纯数字 + 原因编号 0x+8hex;未知列布局变体,不猜)", s.bad)
		return
	}
	norm := map[string]any{
		"event_type":         "usn_journal_summary",
		"journal_id":         s.journalID,
		"preamble_lines":     s.preamble,
		"encoding":           s.enc,
		"total_rows":         s.valid + s.bad,
		"valid_rows":         s.valid,
		"bad_rows":           s.bad,
		"bad_row_examples":   s.badExamples,
		"first_usn":          s.firstUSN,
		"last_usn":           s.lastUSN,
		"file_creates":       s.reasonHist["FILE_CREATE"],
		"file_deletes":       s.reasonHist["FILE_DELETE"],
		"rename_old":         s.reasonHist["RENAME_OLD_NAME"],
		"rename_new":         s.reasonHist["RENAME_NEW_NAME"],
		"reason_histogram":   usnTopPairs(s.reasonHist, 25, "reason"),
		"top_changed_files":  usnTopPairs(s.topFiles, 10, "file"),
		"rows_ts_unresolved": s.noTS,
		"note": "逐行 usn_change 事件入 events(ts_raw=本地时间文本,管线三层归一," +
			"时区未声明则 ts 留 nil 不猜);原因位从原因编号 hex 解码(语言无关)," +
			"本地化原因文本原样留证;父文件 ID 为 FRN 引用,CSV 不携带父路径," +
			"路径关联走 MFT 记录",
	}
	s.summary = &model.Record{LineNo: s.lineNo + 1, Kind: model.KindEvent,
		Norm: norm, Raw: "<usn_journal_summary>"}
}

// parseUSNLocal 本地文本时间 → naive 墙钟(UTC location 承载,模型约定)。
func parseUSNLocal(s string) (time.Time, bool) {
	for _, layout := range usnTSLayouts {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func usnIntOrNone(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false // 非数字 → 不落(不猜)
	}
	return v, true
}

func emptyCells(cells []string) bool {
	for _, c := range cells {
		if strings.TrimSpace(c) != "" {
			return false
		}
	}
	return true
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// usnTopPairs 计数 map → 前 n 名 [{key,count}](字典序定同分,输出确定)。
func usnTopPairs(m map[string]int64, n int, keyName string) []map[string]any {
	type kv struct {
		k string
		v int64
	}
	pairs := make([]kv, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].v != pairs[j].v {
			return pairs[i].v > pairs[j].v
		}
		return pairs[i].k < pairs[j].k
	})
	if len(pairs) > n {
		pairs = pairs[:n]
	}
	out := make([]map[string]any, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, map[string]any{keyName: p.k, "count": p.v})
	}
	return out
}

func (s *usnStream) Err() error { return s.err }

func (s *usnStream) Close() error { return s.f.Close() }
