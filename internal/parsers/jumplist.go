// WinInfoSC JumpList 跳转列表原生解析(M4.5b):*.automaticDestinations-ms
// (CFB/OLE2 复合文档)+ *.customDestinations-ms(LNK 序列)→ 文件访问事件
// 流 + 收尾统计。语义基准 = 树庭 backend/app/parsers/jumplist.py(金标准)。
//
// 格式契约(对公开 spec 写):
//   - automaticDestinations-ms = CFB(OLE2,MS-CFB)容器,用 vendored
//     github.com/richardlehane/mscfb 迭代流;DestList 流:32 字节头
//     (version@0 u32,条目数@4 u32),条目 = 0x84 字节定长头(条目号 u32@+0x58、
//     访问 FILETIME u64@+0x64、路径长 u16@+0x80)+ UTF-16LE 路径 + 变长属性尾
//     (u32 尺寸@路径结束后,跳过该尺寸+4);已知版本 {3,4,6},未知版本同布局
//     尝试并在 destlist_status 如实注明;条目边界不齐 → 降级产出已解析部分
//   - status 如实注明(树庭 _parse_destlist 同款语义,状态文案逐字对齐);
//   - 数字名流(如 "21")= 完整 LNK blob,交本包 parseLNK(MS-SHLLINK);
//   - customDestinations-ms:头 4 字节 u32 必须 == 2 否则文件级如实 failed;
//     按 LNK 签名(lnkMagic)全文扫描定位每个 LNK blob,下一条目前 20 字节
//     截断为上一条边界,逐条 parseLNK;
//   - 时间:FILETIME 原生 UTC → TsUTCDirect 直通 + *_utc ISO 留证;非法时间
//     字段不置,不猜;
//   - 容器打不开/非 CFB/头部契约不符 → Records 返回 error(文件级如实
//     failed);条目级失败计数进 jumplist_summary(零静默)。
//
// 与树庭的口径差(如实):
//   - 树庭用 olefile,丰图用 mscfb(纯 Go);目录迭代顺序不同,但产出按
//     「DestList 条目在前、LNK 流在后」重排,与树庭 emit 顺序对齐;
//   - 内存纪律上限(树庭无):customDestinations 整读上限 4MB(实测真机最大
//     约 20KB,超限文件级如实 failed);单流读取上限 8MB、单文件条目上限
//     64K(超限如实计数/标注,不静默);
//   - 树庭 ts 走 utc_to_local_ts_raw 回转本地;丰图 UTC 直通(同 efu 等
//     原生解析器口径,语义等价)。
//
// 流式纪律:CFB 流逐条读取即解析即弃(单流 ≤8MB),custom 整读 ≤4MB,
// 记录即产即放,堆增量与输入大小无关(内存回归测试见 _test)。
package parsers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/richardlehane/mscfb"
	"github.com/ye-mengwen/fengtu/internal/model"
)

// JumpList 计数与读取上限(防过拟合:均为结构上限,不是案件值)。
const (
	jlMaxCustomBytes = 4 << 20 // customDestinations 整读上限(真机实测约 20KB)
	jlMaxStreamBytes = 8 << 20 // CFB 单流读取上限(真机 DestList/LNK 均 KB 级)
	jlMaxEntries     = 1 << 16 // 单文件产出条目上限,超限截断并如实标注
)

// jlDestListKnownVersions DestList 已知版本(树庭 _DESTLIST_VERSIONS_KNOWN;
// 6 = Win10/11 实测,3/4 同布局尝试)。
var jlDestListKnownVersions = map[uint32]bool{3: true, 4: true, 6: true}

// JumpListParser *.automaticDestinations-ms / *.customDestinations-ms 解析器。
type JumpListParser struct{}

// jlDestEntry DestList 单条目(树庭 _parse_destlist 条目同字段)。
type jlDestEntry struct {
	entryNo    uint32
	target     string
	accessedFT uint64
}

// jlStream 重放打开期已解析好的记录(jumplist 容器均为 KB 级,记录即产
// 即入切片;上限见 jlMaxEntries,内存有界)。
type jlStream struct {
	recs []model.Record
	i    int
}

// Records 打开跳转列表容器:按文件名后缀分流(契约);容器级结构不符
// → 文件级如实 failed。
func (JumpListParser) Records(path string) (Stream, error) {
	base := strings.ToLower(filepath.Base(path))
	appID := strings.SplitN(base, ".", 2)[0] // 树庭 split(".")[0] 同语义
	s := &jlStream{}
	var err error
	switch {
	case strings.HasSuffix(base, ".automaticdestinations-ms"):
		err = s.parseAutomatic(path, appID)
	case strings.HasSuffix(base, ".customdestinations-ms"):
		err = s.parseCustom(path, appID)
	default:
		err = fmt.Errorf("非 JumpList 文件名后缀: %s", base)
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

// parseDestList DestList 流字节 → (条目, 状态)。树庭 _parse_destlist 逐字
// 同语义(含状态文案);边界不齐降级产出已解析部分,零静默。
func parseDestList(d []byte) ([]jlDestEntry, string) {
	if len(d) < 0x20 {
		return nil, "DestList 头不足 32 字节"
	}
	version := binary.LittleEndian.Uint32(d[0:])
	n := binary.LittleEndian.Uint32(d[4:])
	if version == 0 || n == 0 {
		return nil, "空 DestList(version=0 或无条目)"
	}
	var entries []jlDestEntry
	off := 0x20
	for i := uint32(0); i < n; i++ {
		if off+0x84 > len(d) {
			return entries, fmt.Sprintf("条目 %d/%d 处截断,已产出前 %d 条",
				i, n, len(entries))
		}
		entryNo := binary.LittleEndian.Uint32(d[off+0x58:])
		ft := binary.LittleEndian.Uint64(d[off+0x64:])
		sl := int(binary.LittleEndian.Uint16(d[off+0x80:]))
		sEnd := off + 0x82 + sl*2
		if sEnd+4 > len(d) {
			return entries, fmt.Sprintf("条目 %d/%d 路径越界,已产出前 %d 条",
				i, n, len(entries))
		}
		entries = append(entries, jlDestEntry{
			entryNo:    entryNo,
			target:     utf16le(d[off+0x82 : sEnd]),
			accessedFT: ft,
		})
		trailer := int(binary.LittleEndian.Uint32(d[sEnd:]))
		off = sEnd + trailer + 4
	}
	if off != len(d) {
		return entries, fmt.Sprintf("尾部残留 %d 字节,条目已全产出版本存疑",
			len(d)-off)
	}
	if !jlDestListKnownVersions[version] {
		return entries, fmt.Sprintf("ok(版本 %d 未在已知表内,同布局解析成功)",
			version)
	}
	return entries, "ok"
}

// jlIsDigits 纯 ASCII 数字判定(树庭 str.isdigit 同语义;空串 false)。
func jlIsDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// jlEntryRecord 一条目 → jumplist_entry 事件;lineNo 由调用方编。
// entryNo < 0 表示该源无条目号(custom_lnk,树庭同款不产)。
func jlEntryRecord(lineNo int, appID, source string, entryNo int,
	locator, target, arguments string, createdFT, modifiedFT, accessedFT,
	tsFT uint64) model.Record {
	norm := map[string]any{
		"event_type": "jumplist_entry",
		"app_id":     appID,
		"source":     source,
	}
	if entryNo >= 0 {
		norm["entry_no"] = entryNo
	}
	if target != "" {
		norm["target_path"] = target
	}
	if arguments != "" {
		norm["arguments"] = arguments
	}
	if s := FiletimeISO(accessedFT); s != "" {
		norm["accessed_utc"] = s
	}
	if s := FiletimeISO(createdFT); s != "" {
		norm["created_utc"] = s
	}
	if s := FiletimeISO(modifiedFT); s != "" {
		norm["modified_utc"] = s
	}
	raw := locator
	if target != "" {
		raw += " -> " + target
	}
	rec := model.Record{LineNo: lineNo, Kind: model.KindEvent,
		Norm: norm, Raw: raw}
	if t, ok := FiletimeToUTC(tsFT); ok {
		rec.TsUTCDirect = &t
	}
	return rec
}

// jlSummary 收尾汇总状态(树庭 summary dict 同字段)。
type jlSummary struct {
	entries     int64
	entryErrors int64
	notes       []string
	destStatus  string // automatic 且有 DestList 流时置
	pinnedTail  bool   // custom 固定尾注
}

// summaryRecord 收尾产 jumplist_summary。
func (s *jlStream) summaryRecord(lineNo int, appID string, sum *jlSummary) {
	norm := map[string]any{
		"event_type":   "jumplist_summary",
		"app_id":       appID,
		"entries":      sum.entries,
		"entry_errors": sum.entryErrors,
		"notes":        sum.notes,
	}
	if sum.destStatus != "" {
		norm["destlist_status"] = sum.destStatus
	}
	if sum.pinnedTail {
		norm["pinned_tail_note"] = "固定项字符串尾(u32 计数于 0x0C)未逐条解析," +
			"条目以 LNK 为准(取舍,非静默)"
	}
	s.recs = append(s.recs, model.Record{LineNo: lineNo, Kind: model.KindEvent,
		Norm: norm, Raw: "<jumplist_summary>"})
}

// parseAutomatic *.automaticDestinations-ms(CFB 容器)。
func (s *jlStream) parseAutomatic(path, appID string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("jumplist 打开失败: %w", err)
	}
	defer f.Close()
	r, err := mscfb.New(f)
	if err != nil {
		return fmt.Errorf("非 CFB 容器或损坏: %w", err)
	}
	sum := &jlSummary{notes: []string{}}
	var destData []byte
	hasDest := false
	type lnkBlob struct {
		leaf string
		data []byte
	}
	var lnks []lnkBlob
	// 目录迭代(mscfb.Next 跳过根项,只产存储/流项);读流即弃,内存有界
	for {
		file, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("CFB 目录迭代失败: %w", err)
		}
		if file.FileInfo().IsDir() {
			continue // 存储项不是流,跳过
		}
		leaf := file.Name
		isDest := leaf == "DestList"
		if !isDest && !jlIsDigits(leaf) {
			continue // 非 DestList 非数字流(如属性集),树庭 isdigit 同款忽略
		}
		if file.Size > jlMaxStreamBytes {
			sum.entryErrors++
			sum.notes = append(sum.notes,
				fmt.Sprintf("流 %s: 尺寸 %d 超上限,跳过", leaf, file.Size))
			continue
		}
		data, err := io.ReadAll(file)
		if err != nil {
			sum.entryErrors++
			sum.notes = append(sum.notes, fmt.Sprintf("流 %s: 读取失败: %v", leaf, err))
			continue
		}
		if isDest {
			hasDest = true
			destData = data
		} else {
			lnks = append(lnks, lnkBlob{leaf: leaf, data: data})
		}
	}
	line := 0
	// DestList 条目在前(与树庭 emit 顺序对齐)
	if hasDest {
		entries, status := parseDestList(destData)
		sum.destStatus = status
		for _, e := range entries {
			if line >= jlMaxEntries {
				sum.notes = append(sum.notes,
					fmt.Sprintf("条目数超上限 %d,截断", jlMaxEntries))
				break
			}
			line++
			s.recs = append(s.recs, jlEntryRecord(line, appID, "destlist",
				int(e.entryNo), fmt.Sprintf("DestList:%d", e.entryNo),
				e.target, "", 0, 0, e.accessedFT, e.accessedFT))
			sum.entries++
		}
	} else {
		sum.notes = append(sum.notes, "无 DestList 流")
	}
	// 数字名流 = 完整 LNK(树庭同款)
	for _, lb := range lnks {
		if line >= jlMaxEntries {
			sum.notes = append(sum.notes,
				fmt.Sprintf("条目数超上限 %d,截断", jlMaxEntries))
			break
		}
		no, _ := strconv.Atoi(lb.leaf)
		lf, err := parseLNK(lb.data)
		if err != nil {
			sum.entryErrors++
			sum.notes = append(sum.notes, fmt.Sprintf("流 %s: %v", lb.leaf, err))
			continue
		}
		line++
		s.recs = append(s.recs, jlEntryRecord(line, appID, "lnk_stream", no,
			"lnk:"+lb.leaf, lf.target, lf.arguments,
			lf.createdFT, lf.modifiedFT, lf.accessedFT, lf.modifiedFT))
		sum.entries++
	}
	s.summaryRecord(line+1, appID, sum)
	return nil
}

// parseCustom *.customDestinations-ms(u32 version==2 头 + LNK 序列,
// 按 LNK 签名扫描定位;树庭 parse customDestinations 分支同语义)。
func (s *jlStream) parseCustom(path, appID string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("jumplist 打开失败: %w", err)
	}
	if fi.Size() > jlMaxCustomBytes {
		return fmt.Errorf("customDestinations 尺寸 %d 超上限 %d(真机约 20KB),"+
			"如实 failed", fi.Size(), jlMaxCustomBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("jumplist 读取失败: %w", err)
	}
	if len(data) < 4 || binary.LittleEndian.Uint32(data) != 2 {
		head := data
		if len(head) > 8 {
			head = head[:8]
		}
		return fmt.Errorf("非 CustomDestinations v2 结构(头 %x)", head)
	}
	// LNK 签名全文扫描;下一条目前 20 字节为上一条边界(树庭同款)
	var offs []int
	for i := 0; ; {
		j := bytes.Index(data[i:], lnkMagic)
		if j < 0 {
			break
		}
		offs = append(offs, i+j)
		i += j + 1
	}
	sum := &jlSummary{notes: []string{}, pinnedTail: true}
	line := 0
	for idx, off := range offs {
		if line >= jlMaxEntries {
			sum.notes = append(sum.notes,
				fmt.Sprintf("条目数超上限 %d,截断", jlMaxEntries))
			break
		}
		end := len(data)
		if idx+1 < len(offs) {
			end = offs[idx+1] - 20
		}
		if end < off {
			end = off // 重叠病态输入:边界钳位,交 parseLNK 如实报错
		}
		lf, err := parseLNK(data[off:end])
		if err != nil {
			sum.entryErrors++
			sum.notes = append(sum.notes, fmt.Sprintf("条目 @%d: %v", off, err))
			continue
		}
		line++
		s.recs = append(s.recs, jlEntryRecord(line, appID, "custom_lnk", -1,
			fmt.Sprintf("lnk:@%d", off), lf.target, lf.arguments,
			lf.createdFT, lf.modifiedFT, lf.accessedFT, lf.modifiedFT))
		sum.entries++
	}
	if len(offs) == 0 {
		sum.notes = append(sum.notes,
			"空容器或仅头部(无 LNK 条目,真机存在 12 字节空壳),如实标注")
	}
	s.summaryRecord(line+1, appID, sum)
	return nil
}

func (s *jlStream) Next() (model.Record, bool) {
	if s.i >= len(s.recs) {
		return model.Record{}, false
	}
	rec := s.recs[s.i]
	s.i++
	return rec, true
}

func (s *jlStream) Err() error   { return nil }
func (s *jlStream) Close() error { return nil }
