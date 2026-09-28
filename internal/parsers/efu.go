// Everything 文件清单(EFU)原生解析:UTF-8 CSV → 行级文件清单事件流 +
// 收尾统计。语义基准 = 树庭 backend/app/parsers/efu.py(金标准)。
//
// 格式契约(Everything EFU,对 spec 写):
//   - UTF-8(可带 BOM)CSV,表头 Filename,Size,Date Modified,Date Created,
//     Attributes;列按表头名定位(缺列 → 该字段一律 nil,诚实不猜);
//   - Date Modified/Created 是 FILETIME 整数(原生 UTC,与主机时区无关)
//     → TsUTCDirect 直通 + *_utc 留证;非法/0 → 字段 nil 不猜;
//   - Size 空(目录)→ size_bytes nil,不填 0;
//   - 字段数与表头不符 → bad_rows 计数,行内有路径仍照出不丢(树庭同款);
//   - 无路径的行无落库价值,跳过(坏行已计数,零静默)。
//
// 与树庭的口径差(如实):
//   - 树庭行级数据入独立 efu_files 表不进事件流;丰图无此表,行级产出
//     file_listing_entry 事件(Stream 流式,内存与行数无关)——对拍口径 =
//     行数/bad 数/逐字段值,不走事件条数;
//   - top_extensions/drives 计数器设去重键上限(防恶意海量伪造扩展名灌爆
//     内存,超上限入溢出桶如实计数;树庭 Counter 无上限)。
//
// 流式纪律:csv.Reader 逐行读,单条事件即产即放,内存恒定
// (340MB 真实清单实测,内存恒定)。
package parsers

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// EFU 计数与呈现上限(防过拟合:均为结构上限,不是案件值)。
const (
	efuTopN            = 50      // top_extensions 呈现条数(树庭 _TOP=50)
	efuMaxDistinctKeys = 1 << 16 // 扩展名/盘符去重键上限,超限入溢出桶
)

// EfuParser everything.efu 解析器。
type EfuParser struct{}

type efuStream struct {
	f                        *os.File
	r                        *csv.Reader
	header                   []string       // 小写表头
	idx                      map[string]int // 列名 → 下标(只含存在的列)
	lineNo                   int            // 当前物理行号(表头=1;EFU 路径不含裸换行,逐行对齐)
	total, bad               int64
	extCounts                map[string]int64
	drvCounts                map[string]int64
	extOverflow, drvOverflow int64
	done                     bool
	err                      error
}

// Records 打开 EFU:表头校验在打开期完成(无表头/无 filename 列 →
// 文件级如实 failed)。
func (EfuParser) Records(path string) (Stream, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("efu 打开失败: %w", err)
	}
	br := bufio.NewReaderSize(f, 1<<20)
	// UTF-8 BOM 剥离(Everything 写出带 BOM)
	if b, err := br.Peek(3); err == nil &&
		b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		if _, err := br.Discard(3); err != nil {
			f.Close()
			return nil, fmt.Errorf("efu BOM 剥离失败: %w", err)
		}
	}
	r := csv.NewReader(br)
	r.FieldsPerRecord = -1 // 字段数不齐的行不拒,自计数 bad(树庭同款)
	r.LazyQuotes = true    // 路径里裸引号容忍(Python csv 同款宽松)
	s := &efuStream{f: f, r: r, idx: map[string]int{},
		extCounts: map[string]int64{}, drvCounts: map[string]int64{}}
	for {
		cells, err := r.Read()
		if err == io.EOF {
			f.Close()
			return nil, fmt.Errorf("空文件或无表头(efu 表头契约不符)")
		}
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("efu 表头行解析失败: %w", err)
		}
		s.lineNo++
		empty := true
		for _, c := range cells {
			if strings.TrimSpace(c) != "" {
				empty = false
				break
			}
		}
		if empty {
			continue // 表头前空行跳过(树庭同款)
		}
		for i, c := range cells {
			cells[i] = strings.ToLower(strings.TrimSpace(c))
		}
		s.header = cells
		for _, name := range []string{
			"filename", "size", "date modified", "date created", "attributes"} {
			for i, c := range cells {
				if c == name {
					s.idx[name] = i
					break
				}
			}
		}
		if _, ok := s.idx["filename"]; !ok {
			f.Close()
			return nil, fmt.Errorf("无法识别 EFU 表头(无 filename 列): %v",
				cells[:min(len(cells), 5)])
		}
		return s, nil
	}
}

// efuCell 按列名取单元格;缺列/越界/空白 → ""(调用方判空,不猜)。
func (s *efuStream) efuCell(cells []string, col string) string {
	i, ok := s.idx[col]
	if !ok || i >= len(cells) {
		return ""
	}
	return strings.TrimSpace(cells[i])
}

// efuSplitPath 完整路径 → (末段文件名, 小写扩展名或 "")(树庭 _split_path 同语义)。
func efuSplitPath(full string) (base, ext string) {
	if i := strings.LastIndexAny(full, "\\/"); i >= 0 {
		base = full[i+1:]
	} else {
		base = full
	}
	if j := strings.LastIndexByte(base, '.'); j >= 0 && j+1 < len(base) {
		return base, strings.ToLower(base[j+1:])
	}
	return base, ""
}

// efuCount 计数器落键(去重键超上限入溢出桶,如实计数,内存有界)。
func efuCount(m map[string]int64, key string, overflow *int64) {
	if _, ok := m[key]; ok || len(m) < efuMaxDistinctKeys {
		m[key]++
		return
	}
	*overflow++
}

// Next 逐行产 file_listing_entry;EOF 收尾产 file_listing_summary。
func (s *efuStream) Next() (model.Record, bool) {
	for !s.done {
		cells, err := s.r.Read()
		if err == io.EOF {
			s.done = true
			return s.summaryRecord(), true
		}
		if err != nil {
			// 行级解析错(半行引号等):计 bad 继续,零静默
			s.total++
			s.bad++
			s.lineNo++
			continue
		}
		s.lineNo++
		if len(cells) == 0 {
			continue
		}
		s.total++
		if len(cells) != len(s.header) {
			s.bad++
		}
		name := s.efuCell(cells, "filename")
		if name == "" {
			continue // 无路径行无落库价值(坏行已计数)
		}
		rec := s.entryRecord(cells, name)
		return rec, true
	}
	return model.Record{}, false
}

// entryRecord 一行 → file_listing_entry 事件。
func (s *efuStream) entryRecord(cells []string, name string) model.Record {
	norm := map[string]any{
		"event_type": "file_listing_entry",
		"path":       name,
	}
	base, ext := efuSplitPath(name)
	if base == "" {
		// 卷根行(C:\)末段为空:以全名兜底(树庭同款,不静默丢行)
		base, ext = name, ""
	}
	norm["filename"] = base
	if ext != "" {
		norm["extension"] = ext
	}
	if v := s.efuCell(cells, "size"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			norm["size_bytes"] = n
		} // 非数字:size_bytes 缺省不猜(树庭同款)
	}
	if v := s.efuCell(cells, "attributes"); v != "" {
		norm["attributes"] = v
	}
	var modUTC *time.Time
	if v := s.efuCell(cells, "date modified"); v != "" {
		if ft, err := strconv.ParseUint(v, 10, 64); err == nil {
			if t, ok := FiletimeToUTC(ft); ok {
				norm["date_modified_utc"] = t.Format("2006-01-02T15:04:05Z")
				modUTC = &t
			}
		}
	}
	if v := s.efuCell(cells, "date created"); v != "" {
		if ft, err := strconv.ParseUint(v, 10, 64); err == nil {
			if t, ok := FiletimeToUTC(ft); ok {
				norm["date_created_utc"] = t.Format("2006-01-02T15:04:05Z")
			}
		}
	}
	// 统计(与树庭同口径:盘符按 name[:3] 含冒号判定)
	drive := "<无盘符>"
	if len(name) >= 3 && strings.Contains(name[:3], ":") {
		drive = strings.ToUpper(strings.SplitN(name, ":", 2)[0])
	}
	efuCount(s.drvCounts, drive, &s.drvOverflow)
	if ext != "" {
		efuCount(s.extCounts, ext, &s.extOverflow)
	} else {
		efuCount(s.extCounts, "<无扩展名>", &s.extOverflow)
	}
	return model.Record{LineNo: s.lineNo, Kind: model.KindEvent, Norm: norm,
		Raw: name, TsUTCDirect: modUTC}
}

// summaryRecord 收尾统计事件(top-N 降序,溢出如实标)。
func (s *efuStream) summaryRecord() model.Record {
	top := topNCounts(s.extCounts, efuTopN)
	drives := topNCounts(s.drvCounts, 0) // 盘符少,全列
	summary := map[string]any{
		"total_rows": s.total, "bad_rows": s.bad,
		"top_extensions": top, "drives": drives,
		"distinct_extensions": int64(len(s.extCounts)),
	}
	if s.extOverflow > 0 {
		summary["extension_overflow_rows"] = s.extOverflow
	}
	if s.drvOverflow > 0 {
		summary["drive_overflow_rows"] = s.drvOverflow
	}
	summary["note"] = "行级=file_listing_entry 事件流(树庭入 efu_files 独立表," +
		"丰图进统一事件流);FILETIME 原生 UTC 直通;文件路径非跨主机实体;" +
		"勒索信/加密后缀检索直接查本事件流"
	return model.Record{LineNo: s.lineNo + 1, Kind: model.KindEvent,
		Norm: map[string]any{"event_type": "file_listing_summary",
			"summary": summary},
		Raw: "<file_listing_summary>"}
}

// topNCounts 计数 map → [{key,count}...] 降序(n=0 全列;并列按 key 定序,
// 输出确定性)。
func topNCounts(m map[string]int64, n int) []map[string]any {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if n > 0 && len(keys) > n {
		keys = keys[:n]
	}
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]any{"key": k, "count": m[k]})
	}
	return out
}

func (s *efuStream) Err() error   { return s.err }
func (s *efuStream) Close() error { return s.f.Close() }
