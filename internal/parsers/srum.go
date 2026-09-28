// SRUDB.dat(SRUM 系统资源用量监视库)原生解析:ESE 数据库 → 三类用量
// 事件流 + 收尾统计。语义基准 = 树庭 backend/app/parsers/srum.py(金标准)。
//
// 选型:go-ese(vendor www.velocidex.com/golang/go-ese,纯 Go ESE 只读
// 解析,Velociraptor 生产同款)提供页层原语(ESEContext/Catalog/
// WalkPages);行解码(tagToRecord)不用库自带实现,本文件自带边界安全
// 重写版(srumDecodeRow),原因如实:
//   - go-ese v0.2.0 在真实 SRUDB 上踩三个坑:GetPageValues 把整个
//     itagState 当 tag 数(高 4 位是保留数,47 活行放大成 19 万
//     value,1.5MB 真实样本实锤)、LastFixedType(int8)为负时被
//     uint32 转换爆炸成 0xFFFFFFFF(整行错位、IdBlob 静默丢失)、
//     ParseTaggedValues 切片无界直接 panic——故页枚举/行解码均为本
//     文件自带的边界安全实现(srumPageNodes/srumWalkPages/
//     srumDecodeRow),行级结构损坏计 row_errors 跳过,不崩不猜;
//   - go-ese 把 DateTime 列就地截断成秒级 time.Time(丢亚秒、无合理
//     性窗),无法对齐树庭「int64 位模式 = OA double」语义;本解码器
//     DateTime 一律返回原始 8 字节位模式(uint64),OA/FILETIME 由
//     调用方按树庭口径解码;
//   - go-ese 的 Binary/Long Binary 给 hex 串,本解码器直接给原始字节。
//
// 格式契约(ESE/SRUM,对公开 spec 写):
//   - SruDbIdMapTable:IdIndex→名称映射(IdType 0/1 = UTF-16LE 串去尾
//     NUL;3 = 二进制 SID → S-1-...,布局 rev(1)+子机构数(1)+颁发机构
//     (6,BE)+子机构×4(LE);结构不合法 → 不映射,不猜);
//   - {973F5D5C-1D90-4944-BE8E-24B94231A174} → srum_network_usage
//     (AppId/UserId 经 id_map 解名/BytesSent/BytesRecvd/InterfaceLuid
//   - TimeStamp);
//   - {DD6636C4-8929-4683-974E-22C046A43763} → srum_network_connectivity
//     (ConnectedTime 秒 + ConnectStartTime FILETIME);
//   - {D10CA2FE-6FCF-4F6D-848E-B2E99266FA89} → srum_app_resource_usage
//     (前台/后台 CPU 周期、FaceTime、读写字节=前台+后台求和);
//   - 时间怪癖(树庭真机实测,照抄):三表 TimeStamp 列是 int64,其位模式
//     是 OLE Automation 日期 double(1899-12-30 起算天数,合理窗
//     [36526,73050]≈2000~2100,越窗不猜);ConnectStartTime 是 FILETIME。
//     均原生 UTC → TsUTCDirect 直通 + Norm 里 *_utc ISO 留证;非法不置;
//   - 未映射 ID 计 unmapped_ids;表缺失记 missing_tables;行级异常(行
//     结构损坏/解码 panic)计 row_errors;ESE 头校验失败 → 文件级如实
//     failed。零静默。
//
// 与树庭的口径差(如实):
//   - 树庭 dissect.esedb 自动解析 long-value 溢出页;go-ese(及本解码
//     器)不解析 tagged 长值引用——SRUM 四表未见该形态,两份真实样本
//     全量对拍无差异;
//   - 树庭 id_map 加载是表级 try(任一行异常 → 整表放弃);丰图行级
//     容错(坏行跳过计 row_errors,好行照常映射),更韧且零静默;
//   - 树庭行迭代中途损坏会让整个任务 failed;丰图按「记录级损坏」处理:
//     产 bad 记录 + row_errors 计数,继续余下表,不拖垮整文件;
//   - 树庭 utc_to_local_ts_raw 回转本地再归一;丰图 UTC 原生直通
//     (parsers.go 统一契约),无 parse_note 分支。
//
// 流式纪律:WalkPages 逐页 ReadAt(无页缓存),行解码即产即放;单泵
// goroutine + 有界 channel(64),Close 即发即停。id_map 全量驻内存
// (SRUM 实测千级条目,ESE 页结构天然约束其规模)。内存与库大小无关
// (79MB 真实库实测,内存恒定)。
package parsers

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ye-mengwen/fengtu/internal/model"
	"www.velocidex.com/golang/go-ese/parser"
)

// SRUM 表名(ESE 表名即 GUID 字符串,对 spec 写)。
const (
	srumTableIDMap        = "SruDbIdMapTable"
	srumTableNetwork      = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
	srumTableConnectivity = "{DD6636C4-8929-4683-974E-22C046A43763}"
	srumTableAppResource  = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
)

// OLE Automation 日期合理性窗(树庭 _OA_MIN/_OA_MAX:2000-01-01 ~
// 2100-01-01,越窗不猜);25569 = 1899-12-30 距 1970-01-01 的天数。
const (
	srumOAMin           = 36526.0
	srumOAMax           = 73050.0
	srumOAEpochUnixDays = 25569.0
)

// srumISO 留证时间格式(树庭 %Y-%m-%dT%H:%M:%SZ 同款)。
const srumISO = "2006-01-02T15:04:05Z"

// errSrumCancel Close 提前终止泵的哨兵(非解析错误,不上报)。
var errSrumCancel = errors.New("srum: 流已关闭,泵提前终止")

// SrumParser SRUDB.dat 解析器。
type SrumParser struct{}

type srumStream struct {
	f    *os.File
	ch   chan model.Record
	done chan struct{}
	once sync.Once
	wg   sync.WaitGroup
}

// srumPump 泵:单 goroutine 顺序解 id_map + 三表,产 record 入 channel。
type srumPump struct {
	ctx     *parser.ESEContext
	catalog *parser.Catalog
	ch      chan model.Record
	done    chan struct{}
	wg      *sync.WaitGroup

	lineNo    int
	idMap     map[int64]string
	unmapped  int64
	rowErrors int64
	missing   []string
	nNetwork  int64
	nConnect  int64
	nAppRes   int64
}

// Records 打开 SRUDB.dat:ESE 头/catalog 校验在打开期完成(结构不符 →
// 文件级如实 failed)。
func (SrumParser) Records(path string) (Stream, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("srum 打开失败: %w", err)
	}
	ctx, err := parser.NewESEContext(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("ESE 数据库头校验失败: %w", err)
	}
	// catalog 读取防 panic(go-ese 页层在脏库上无边界校验):打开期
	// 结构损坏 → 文件级如实 failed
	catalog, err := func() (catalog *parser.Catalog, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("catalog 读取 panic(库健壮性): %v", r)
			}
		}()
		return parser.ReadCatalog(ctx)
	}()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("ESE catalog 读取失败: %w", err)
	}
	s := &srumStream{f: f, ch: make(chan model.Record, 64),
		done: make(chan struct{})}
	s.wg.Add(1)
	p := &srumPump{ctx: ctx, catalog: catalog, ch: s.ch, done: s.done,
		wg: &s.wg, idMap: map[int64]string{}}
	go p.run()
	return s, nil
}

// Next 取下一记录(行级事件按表序:network_usage → network_connectivity
// → app_resource_usage,收尾 srum_summary)。
func (s *srumStream) Next() (model.Record, bool) {
	rec, ok := <-s.ch
	return rec, ok
}

// Err 流级致命错误;打开期错误经 Records 返回,表遍历损坏进 bad 记录,
// 故此处恒 nil。
func (s *srumStream) Err() error { return nil }

// Close 停泵(即发即停)并关闭句柄。
func (s *srumStream) Close() error {
	s.once.Do(func() { close(s.done) })
	s.wg.Wait()
	return s.f.Close()
}

// ---- ESE 页遍历(边界安全,对 MS-ESENT spec 写) ----

// srumPageNodes 枚举一页的节点(记录)值。go-ese GetPageValues 把整个
// itagState uint16 当 tag 数——版本 0x620 rev≥12 起该字段高 4 位是保留
// tag 数(MS-ESENT PGHDR.itagState,dissect.esedb page.py 同款解读)——
// 导致遍历到大量陈旧 tag(1.5MB 真实样本实锤:47 活行被放大成 19 万
// value);此处按 spec 修正:tagCount = itagState & 0x0FFF,reserved =
// max(itagState>>12, 1),节点 = tag[1..tagCount-reserved](tag 0 是
// common key,跳过)。itagState 超页容 → 页损坏,按空页处理(不猜)。
func srumPageNodes(ctx *parser.ESEContext, header *parser.PageHeader,
	id int64) []*parser.Value {
	itagState := header.AvailablePageTag()
	tagCount := int(itagState & 0x0FFF)
	reserved := int(itagState >> 12)
	if reserved == 0 {
		reserved = 1
	}
	nodeCount := tagCount - reserved
	maxTags := int(ctx.PageSize / 4)
	if nodeCount <= 0 || tagCount > maxTags {
		return nil
	}
	var out []*parser.Value
	for t := 1; t <= nodeCount; t++ {
		tagOff := header.Offset + ctx.PageSize - int64(4*(t+1))
		tag := ctx.Profile.Tag(ctx.Reader, tagOff)
		valueOff := header.EndOffset(ctx) + int64(tag.ValueOffset(ctx))
		size := int(tag.ValueSize(ctx))
		if size < 0 || size > int(ctx.PageSize) {
			continue // 单 tag 损坏:跳过,不猜
		}
		buffer := make([]byte, size)
		n, _ := ctx.Reader.ReadAt(buffer, valueOff)
		if n < size {
			continue // 截断读:跳过,不猜
		}
		out = append(out, parser.NewValue(ctx, tag, id, buffer))
	}
	return out
}

// srumWalkPages B 树遍历(结构同 go-ese _walkPages:分支递归 + 页级
// NextPageNumber 链,seen 防脏库回环;枚举换 srumPageNodes 修正版)。
func srumWalkPages(ctx *parser.ESEContext, id int64, seen map[int64]bool,
	cb func(value *parser.Value) error) error {
	if id <= 0 || seen[id] {
		return nil
	}
	seen[id] = true
	header := ctx.GetPage(id)
	nodes := srumPageNodes(ctx, header, id)
	if len(nodes) == 0 {
		return nil
	}
	for _, value := range nodes {
		if header.IsLeaf() {
			if err := cb(value); err != nil {
				return err
			}
		} else if header.IsBranch() {
			branch := parser.NewESENT_BRANCH_ENTRY(ctx, value)
			if err := srumWalkPages(ctx, branch.ChildPageNumber(),
				seen, cb); err != nil {
				return err
			}
		}
	}
	if next := header.NextPageNumber(); next > 0 {
		if err := srumWalkPages(ctx, int64(next), seen, cb); err != nil {
			return err
		}
	}
	return nil
}

// srumWalkTable 表数据 B 树流式遍历入口(FatherDataPageNumber 为根)。
func srumWalkTable(ctx *parser.ESEContext, table *parser.Table,
	cb func(value *parser.Value) error) error {
	return srumWalkPages(ctx, int64(table.FatherDataPageNumber),
		map[int64]bool{}, cb)
}

// ---- ESE 行解码(边界安全,对 MS-ESENT spec 写;见文件头选型说明) ----

// srumParseUint16 有界读 LE uint16;越界 → false(调用方判行损坏)。
func srumParseUint16(b []byte, off int64) (uint16, bool) {
	if off < 0 || off+2 > int64(len(b)) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(b[off:]), true
}

// srumParseTaggedValues tagged 段 → (列 id → 原始字节)。
// go-ese ParseTaggedValues 的边界安全重写:tag 数组越界/偏移回退/flag
// 跳过越界的条目一律丢弃(不猜),绝不 panic。
func srumParseTaggedValues(buffer []byte) map[uint32][]byte {
	result := map[uint32][]byte{}
	if len(buffer) < 4 {
		return result
	}
	type recTag struct {
		id    uint32
		start uint64
		flags uint64
	}
	rd := func(off int64) (uint16, bool) { return srumParseUint16(buffer, off) }
	// 首个 tag 的 DataOffset = tag 数组总长(每 tag 4 字节)
	first, ok := rd(2)
	if !ok {
		return result
	}
	firstData := int64(first & 0x1fff)
	if firstData < 4 || firstData > int64(len(buffer)) || firstData%4 != 0 {
		return result // tag 数组头损坏:整段不可信,不猜
	}
	var tags []recTag
	for off := int64(0); off+4 <= firstData; off += 4 {
		id, ok1 := rd(off)
		d, ok2 := rd(off + 2)
		if !ok1 || !ok2 {
			break
		}
		tags = append(tags, recTag{id: uint32(id),
			start: uint64(d & 0x1fff), flags: uint64(d) >> 14})
	}
	for i, tag := range tags {
		end := uint64(len(buffer))
		if i < len(tags)-1 {
			end = tags[i+1].start
		}
		start := tag.start
		if tag.flags > 0 {
			start++ // 首字节是 flag,跳过(go-ese 同款)
		}
		if start > end || end > uint64(len(buffer)) {
			continue // 条目损坏:丢弃,不猜
		}
		result[tag.id] = buffer[start:end]
	}
	return result
}

// srumFixedValue 固定段列解码(类型清单对 go-ese tagToRecord 全覆盖;
// DateTime 返原始位模式,Binary 返原始字节——见文件头)。列类型不认识
// → false(不置值,不猜)。
func srumFixedValue(ctx *parser.ESEContext, buf []byte, off int64,
	col *parser.ColumnSpec) (any, bool) {
	rd := func(n int64) ([]byte, bool) {
		if off < 0 || off+n > int64(len(buf)) {
			return nil, false
		}
		return buf[off : off+n], true
	}
	u16 := func() (uint16, bool) { return srumParseUint16(buf, off) }
	u32 := func() (uint32, bool) {
		b, ok := rd(4)
		if !ok {
			return 0, false
		}
		return binary.LittleEndian.Uint32(b), true
	}
	u64 := func() (uint64, bool) {
		b, ok := rd(8)
		if !ok {
			return 0, false
		}
		return binary.LittleEndian.Uint64(b), true
	}
	switch col.Type {
	case "Boolean":
		if col.SpaceUsage == 1 {
			if b, ok := rd(1); ok {
				return b[0] > 0, true
			}
		}
	case "Signed byte": // go-ese 按无符号读(实测 IdType 0~3,无差)
		if col.SpaceUsage == 1 {
			if b, ok := rd(1); ok {
				return b[0], true
			}
		}
	case "Signed short":
		if col.SpaceUsage == 2 {
			if v, ok := u16(); ok {
				return int16(v), true
			}
		}
	case "Unsigned short":
		if col.SpaceUsage == 2 {
			if v, ok := u16(); ok {
				return v, true
			}
		}
	case "Signed long":
		if col.SpaceUsage == 4 {
			if v, ok := u32(); ok {
				return int32(v), true
			}
		}
	case "Unsigned long":
		if col.SpaceUsage == 4 {
			if v, ok := u32(); ok {
				return v, true
			}
		}
	case "Single precision FP":
		if col.SpaceUsage == 4 {
			if v, ok := u32(); ok {
				return math.Float32frombits(v), true
			}
		}
	case "Double precision FP":
		if col.SpaceUsage == 8 {
			if v, ok := u64(); ok {
				return math.Float64frombits(v), true
			}
		}
	case "DateTime": // 原始位模式!OA/FILETIME 语义由调用方按树庭口径解
		if col.SpaceUsage == 8 {
			if v, ok := u64(); ok {
				return v, true
			}
		}
	case "Long long", "Currency":
		if col.SpaceUsage == 8 {
			if v, ok := u64(); ok {
				return v, true
			}
		}
	case "GUID":
		if col.SpaceUsage == 16 {
			if _, ok := rd(16); ok {
				return ctx.Profile.GUID(bytes.NewReader(buf), off).AsString(), true
			}
		}
	case "Binary":
		if col.SpaceUsage >= 0 && col.SpaceUsage < 1024 {
			if b, ok := rd(col.SpaceUsage); ok {
				return b, true
			}
		}
	}
	return nil, false
}

// srumDecodeRow ESE 行(tag)→ 列名→值 映射;行结构损坏 → error
// (调用方计 row_errors 跳过,零静默)。布局同 go-ese tagToRecord:
// 固定段(identifier ≤ LastFixedType)→ 变长段(127 < id ≤
// LastVariableDataType,长度表累计偏移)→ tagged 段(id > 255)。
func srumDecodeRow(ctx *parser.ESEContext, table *parser.Table,
	value *parser.Value) (map[string]any, error) {
	buf := value.Buffer
	tag := parser.NewESENT_LEAF_ENTRY(ctx, value)
	entryData := tag.EntryData()
	if entryData < 0 || entryData+4 > int64(len(buf)) {
		return nil, errors.New("dd 头越界")
	}
	dd := ctx.Profile.ESENT_DATA_DEFINITION_HEADER(tag.Reader, entryData)
	lastFixedType := dd.LastFixedType() // int8
	if lastFixedType < 0 {
		// go-ese 此处 uint32(int8) 爆炸成 0xFFFFFFFF → 整行错位;
		// 如实判行损坏
		return nil, errors.New("LastFixedType 负值(行结构损坏)")
	}
	lastFixed := uint32(lastFixedType)
	lastVar := uint32(dd.LastVariableDataType())
	varSizeOff := entryData + int64(dd.VariableSizeOffset())
	if varSizeOff < 0 || varSizeOff > int64(len(buf)) {
		return nil, errors.New("VariableSizeOffset 越界")
	}
	offset := entryData + int64(dd.Size())
	prevItemLen := int64(0)
	varData := int64(0)
	if lastVar > 127 {
		varData = int64(lastVar-127) * 2 // 长度表占字节数
	}
	result := map[string]any{}
	var tagged map[uint32][]byte
	taggedDone := false

	for _, column := range table.Columns {
		switch {
		case column.Identifier <= lastFixed: // 固定段
			if column.SpaceUsage < 0 ||
				offset+column.SpaceUsage > int64(len(buf)) {
				return nil, fmt.Errorf("固定段列 %s 越界", column.Name)
			}
			if v, ok := srumFixedValue(ctx, buf, offset, column); ok {
				result[column.Name] = v
			}
			offset += column.SpaceUsage
		case column.Identifier > 127 &&
			column.Identifier <= lastVar: // 变长段
			idx := int64(column.Identifier) - 127 - 1
			itemLen16, ok := srumParseUint16(buf, varSizeOff+idx*2)
			if !ok {
				return nil, fmt.Errorf("变长段列 %s 长度槽越界", column.Name)
			}
			itemLen := int64(itemLen16)
			if itemLen16&0x8000 > 0 { // 空值标记(树庭 None)
				itemLen = prevItemLen
				result[column.Name] = nil
			} else {
				if itemLen < prevItemLen {
					return nil, fmt.Errorf("变长段列 %s 长度回退", column.Name)
				}
				start := varSizeOff + varData
				n := itemLen - prevItemLen
				if start < 0 || start+n > int64(len(buf)) {
					return nil, fmt.Errorf("变长段列 %s 数据越界", column.Name)
				}
				data := buf[start : start+n]
				switch column.Type {
				case "Binary":
					result[column.Name] = data
				case "Text":
					result[column.Name] = parser.ParseText(
						bytes.NewReader(buf), start, n, column.Flags)
				default: // 未知变长类型:不置值,不猜
				}
			}
			varData += itemLen - prevItemLen
			prevItemLen = itemLen
		case column.Identifier > 255: // tagged 段
			if !taggedDone {
				taggedDone = true
				start := varSizeOff + varData
				if start < 0 {
					start = 0
				}
				if start > int64(len(buf)) {
					start = int64(len(buf))
				}
				tagged = srumParseTaggedValues(buf[start:])
			}
			raw, pres := tagged[column.Identifier]
			if !pres {
				continue
			}
			switch column.Type {
			case "Binary", "Long Binary":
				result[column.Name] = raw
			case "Long Text":
				result[column.Name] = parser.ParseLongText(raw, column.Flags)
			case "Boolean":
				if len(raw) >= 1 {
					result[column.Name] = raw[0] > 0
				}
			case "Signed byte":
				if len(raw) >= 1 {
					result[column.Name] = raw[0]
				}
			case "Signed short":
				if len(raw) >= 2 {
					result[column.Name] = int16(binary.LittleEndian.Uint16(raw))
				}
			case "Unsigned short":
				if len(raw) >= 2 {
					result[column.Name] = binary.LittleEndian.Uint16(raw)
				}
			case "Signed long":
				if len(raw) >= 4 {
					result[column.Name] = int32(binary.LittleEndian.Uint32(raw))
				}
			case "Unsigned long":
				if len(raw) >= 4 {
					result[column.Name] = binary.LittleEndian.Uint32(raw)
				}
			case "Single precision FP":
				if len(raw) >= 4 {
					result[column.Name] = math.Float32frombits(
						binary.LittleEndian.Uint32(raw))
				}
			case "Double precision FP":
				if len(raw) >= 8 {
					result[column.Name] = math.Float64frombits(
						binary.LittleEndian.Uint64(raw))
				}
			case "DateTime": // 原始位模式(见固定段同名注释)
				if len(raw) >= 8 {
					result[column.Name] = binary.LittleEndian.Uint64(raw)
				}
			case "Long long", "Currency":
				if len(raw) >= 8 {
					result[column.Name] = binary.LittleEndian.Uint64(raw)
				}
			case "GUID":
				if len(raw) >= 16 {
					result[column.Name] = ctx.Profile.GUID(
						bytes.NewReader(raw), 0).AsString()
				}
			default: // 未知 tagged 类型:不置值,不猜
			}
		}
	}
	return result, nil
}

// ---- 行值取值/整型归一(解码器按列类型给 Go 值,宽度不一) ----

// srumRowVal 取列值;缺列/空值标记 → nil(调用方判空,不猜)。
func srumRowVal(row map[string]any, col string) any {
	return row[col]
}

// srumInt64 列值 → int64(整型家族收窄;未知类型/负值越界 → false,不猜)。
func srumInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int32:
		return int64(n), true
	case int16:
		return int64(n), true
	case int8:
		return int64(n), true
	case uint64:
		if n <= math.MaxInt64 {
			return int64(n), true
		}
		return 0, false
	case uint32:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint8:
		return int64(n), true
	}
	return 0, false
}

// srumUint64 列值 → uint64(位模式保留,OA/FILETIME 解码用)。
func srumUint64(v any) (uint64, bool) {
	switch n := v.(type) {
	case uint64:
		return n, true
	case int64:
		return uint64(n), true
	case uint32:
		return uint64(n), true
	case int32:
		if n >= 0 {
			return uint64(n), true
		}
		return 0, false
	case uint16:
		return uint64(n), true
	case int16:
		if n >= 0 {
			return uint64(n), true
		}
		return 0, false
	case uint8:
		return uint64(n), true
	case int8:
		if n >= 0 {
			return uint64(n), true
		}
		return 0, false
	}
	return 0, false
}

// srumNormInt 列值 → 归一整型(可收窄一律 int64;uint64 超 int64 上限
// 原样透传;其它类型原样透传——树庭 rec.get 同样不做类型校验,不猜不丢)。
func srumNormInt(v any) any {
	if n, ok := srumInt64(v); ok {
		return n
	}
	return v
}

// ---- 解码助手(纯函数,合成单测覆盖) ----

// srumOAToUTC SRUM TimeStamp(int64,位模式为 OLE Automation 日期 double)
// → UTC;越合理性窗/NaN → false(不猜)。树庭 _oa_ts_to_utc 同语义:
// 1899-12-30 起算天数,timedelta 微秒精度,strftime 截断到秒。
func srumOAToUTC(raw uint64) (time.Time, bool) {
	days := math.Float64frombits(raw)
	if math.IsNaN(days) || days < srumOAMin || days > srumOAMax {
		return time.Time{}, false
	}
	us := int64(math.Round((days - srumOAEpochUnixDays) * 86400.0 * 1e6))
	return time.Unix(us/1_000_000, us%1_000_000*1000).UTC(), true
}

// srumSIDToString 二进制 SID → S-1-... 字符串;结构不合法 → false
// (不猜)。树庭 _sid_to_str 同语义:rev(1)+子机构数(1)+颁发机构
// (6,BE)+子机构×4(LE)。
func srumSIDToString(blob []byte) (string, bool) {
	if len(blob) < 8 || blob[0] != 1 {
		return "", false
	}
	subCount := int(blob[1])
	if len(blob) < 8+subCount*4 {
		return "", false
	}
	var authority uint64
	for _, b := range blob[2:8] {
		authority = authority<<8 | uint64(b)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "S-1-%d", authority)
	for i := 0; i < subCount; i++ {
		fmt.Fprintf(&sb, "-%d", binary.LittleEndian.Uint32(blob[8+i*4:]))
	}
	return sb.String(), true
}

// srumUTF16StripNUL UTF-16LE 字节串 → string,去尾 NUL(树庭
// bytes.decode("utf-16-le", errors="replace").rstrip("\x00") 同语义:
// 奇数尾字节补 U+FFFD,仅去尾部 NUL,串内 NUL 保留)。
func srumUTF16StripNUL(b []byte) string {
	s := utf16le(b)
	if len(b)%2 != 0 {
		s += "" // errors="replace":孤尾字节 → U+FFFD
	}
	return strings.TrimRight(s, "\x00")
}

// srumDecodeIDBlob SruDbIdMapTable.IdBlob → 可读名称(树庭
// _decode_id_blob 同语义)。blob 为 nil(SID 结构不合法/列缺失)→
// false(不猜);IdType==3 走 SID;其余 UTF-16LE 去尾 NUL。
func srumDecodeIDBlob(idType int64, v any) (string, bool) {
	var blob []byte
	switch b := v.(type) {
	case nil:
		return "", false
	case []byte:
		blob = b
	case string:
		return b, true // 文本列原值透传(树庭 isinstance str 分支)
	default:
		return "", false
	}
	if idType == 3 {
		return srumSIDToString(blob)
	}
	return srumUTF16StripNUL(blob), true
}

// ---- 泵主体 ----

func (p *srumPump) run() {
	defer close(p.ch)
	defer p.wg.Done()

	// ① ID→名称映射表(IdType 0/1 字符串,3 二进制 SID)
	if !p.loadIDMap() {
		return // 已取消
	}
	// ②网络用量 → ③网络连接 → ④应用资源
	if !p.dumpNetworkUsage() {
		return
	}
	if !p.dumpConnectivity() {
		return
	}
	if !p.dumpAppResource() {
		return
	}
	p.send(p.summaryRecord())
}

// cancelled 快速判停(回调入口)。
func (p *srumPump) cancelled() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// send 产一记录;Close → false(调用方中止遍历)。
func (p *srumPump) send(rec model.Record) bool {
	p.lineNo++
	rec.LineNo = p.lineNo
	select {
	case p.ch <- rec:
		return true
	case <-p.done:
		return false
	}
}

// hasTable 表存在性预检(区分「表缺失」与「遍历中途损坏」)。
func (p *srumPump) hasTable(name string) bool {
	_, pres := p.catalog.Tables.Get(name)
	return pres
}

// walkRows 表行遍历骨架:逐页流式,行解码失败计 row_errors 跳过;遍历
// 中途损坏(含 go-ese 页层 panic)产 bad 记录 + row_errors,不拖垮整
// 文件(树庭此处整任务 failed,口径差见头注)。rowFn 返回 false =
// Close 取消;函数返回 false 仅表示取消。
func (p *srumPump) walkRows(name string, rowFn func(row map[string]any) bool) bool {
	tblAny, _ := p.catalog.Tables.Get(name)
	table := tblAny.(*parser.Table)
	err := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("页遍历 panic(库健壮性): %v", r)
			}
		}()
		return srumWalkTable(p.ctx, table,
			func(value *parser.Value) error {
				if p.cancelled() {
					return errSrumCancel
				}
				row, derr := srumDecodeRow(p.ctx, table, value)
				if derr != nil {
					p.rowErrors++ // 行结构损坏:计数跳过,零静默
					return nil
				}
				cont := true
				func() {
					defer func() {
						if r := recover(); r != nil {
							p.rowErrors++ // 行级异常不中止遍历(树庭 try/except)
						}
					}()
					cont = rowFn(row)
				}()
				if !cont {
					return errSrumCancel
				}
				return nil
			})
	}()
	if err != nil {
		if errors.Is(err, errSrumCancel) {
			return false
		}
		p.rowErrors++
		reason := fmt.Sprintf("表 %s 遍历中途损坏: %v", name, err)
		rec := model.Record{Kind: model.KindBad, Reason: &reason, Raw: name}
		return p.send(rec)
	}
	return true
}

// loadIDMap 解 SruDbIdMapTable;表缺失 → missing_tables 如实记
// (false 仅表示 Close 取消)。
func (p *srumPump) loadIDMap() bool {
	if !p.hasTable(srumTableIDMap) {
		p.missing = append(p.missing, srumTableIDMap+": 表不存在")
		return true
	}
	return p.walkRows(srumTableIDMap, func(row map[string]any) bool {
		idType, _ := srumInt64(srumRowVal(row, "IdType"))
		name, ok := srumDecodeIDBlob(idType, srumRowVal(row, "IdBlob"))
		idx, okIdx := srumInt64(srumRowVal(row, "IdIndex"))
		if ok && okIdx { // 树庭:name 非 None 且 IdIndex 非 None 才映射
			p.idMap[idx] = name
		}
		return true
	})
}

// nameOf IdIndex → 名称;未映射计 unmapped_ids 如实(树庭 name_of 同语义)。
// 返回 any:未映射/缺列 → nil(字段置 nil,不猜)。
func (p *srumPump) nameOf(v any) any {
	idx, ok := srumInt64(v)
	if !ok {
		return nil
	}
	name, ok := p.idMap[idx]
	if !ok {
		p.unmapped++
		return nil
	}
	return name
}

// rowTimeStampOA 取 TimeStamp 列按 OA 解码;合法 → ISO 留证 + UTC 直通。
func (p *srumPump) rowTimeStampOA(row map[string]any) (string, *time.Time) {
	if raw, ok := srumUint64(srumRowVal(row, "TimeStamp")); ok {
		if t, ok2 := srumOAToUTC(raw); ok2 {
			return t.Format(srumISO), &t
		}
	}
	return "", nil
}

// srumLocator 树庭 int(rec.get("AutoIncId") or n):AutoIncId 缺失/0 → 行序。
func srumLocator(row map[string]any, n int64) int64 {
	if v, ok := srumInt64(srumRowVal(row, "AutoIncId")); ok && v != 0 {
		return v
	}
	return n
}

// dumpNetworkUsage ②网络用量表 → srum_network_usage。
func (p *srumPump) dumpNetworkUsage() bool {
	if !p.hasTable(srumTableNetwork) {
		p.missing = append(p.missing, srumTableNetwork+": 表不存在")
		return true
	}
	return p.walkRows(srumTableNetwork, func(row map[string]any) bool {
		tsISO, dt := p.rowTimeStampOA(row)
		norm := map[string]any{
			"event_type":     "srum_network_usage",
			"app":            p.nameOf(srumRowVal(row, "AppId")),
			"user_sid":       p.nameOf(srumRowVal(row, "UserId")),
			"bytes_sent":     srumNormInt(srumRowVal(row, "BytesSent")),
			"bytes_recvd":    srumNormInt(srumRowVal(row, "BytesRecvd")),
			"interface_luid": srumNormInt(srumRowVal(row, "InterfaceLuid")),
			"timestamp_utc":  nil,
		}
		if dt != nil {
			norm["timestamp_utc"] = tsISO
		}
		loc := srumLocator(row, p.nNetwork)
		if !p.send(model.Record{Kind: model.KindEvent, Norm: norm,
			Raw:         fmt.Sprintf("table=%s auto_inc_id=%d", srumTableNetwork, loc),
			TsUTCDirect: dt}) {
			return false // Close 取消
		}
		p.nNetwork++
		return true
	})
}

// dumpConnectivity ③网络连接表 → srum_network_connectivity
// (ConnectStartTime 是 FILETIME)。
func (p *srumPump) dumpConnectivity() bool {
	if !p.hasTable(srumTableConnectivity) {
		p.missing = append(p.missing, srumTableConnectivity+": 表不存在")
		return true
	}
	return p.walkRows(srumTableConnectivity, func(row map[string]any) bool {
		var dt *time.Time
		connectStartISO := ""
		if raw, ok := srumUint64(srumRowVal(row, "ConnectStartTime")); ok {
			if t, ok2 := FiletimeToUTC(raw); ok2 {
				connectStartISO = t.Format(srumISO)
				dt = &t
			}
		}
		norm := map[string]any{
			"event_type":         "srum_network_connectivity",
			"app":                p.nameOf(srumRowVal(row, "AppId")),
			"user_sid":           p.nameOf(srumRowVal(row, "UserId")),
			"connected_time_sec": srumNormInt(srumRowVal(row, "ConnectedTime")),
			"interface_luid":     srumNormInt(srumRowVal(row, "InterfaceLuid")),
			"connect_start_utc":  nil,
		}
		if dt != nil {
			norm["connect_start_utc"] = connectStartISO
		}
		loc := srumLocator(row, p.nConnect)
		if !p.send(model.Record{Kind: model.KindEvent, Norm: norm,
			Raw:         fmt.Sprintf("table=%s auto_inc_id=%d", srumTableConnectivity, loc),
			TsUTCDirect: dt}) {
			return false
		}
		p.nConnect++
		return true
	})
}

// dumpAppResource ④应用资源表 → srum_app_resource_usage(读写字节 =
// 前台+后台求和,缺省按 0,树庭同款)。
func (p *srumPump) dumpAppResource() bool {
	if !p.hasTable(srumTableAppResource) {
		p.missing = append(p.missing, srumTableAppResource+": 表不存在")
		return true
	}
	return p.walkRows(srumTableAppResource, func(row map[string]any) bool {
		tsISO, dt := p.rowTimeStampOA(row)
		sum64 := func(colA, colB string) int64 {
			a, _ := srumInt64(srumRowVal(row, colA))
			b, _ := srumInt64(srumRowVal(row, colB))
			return a + b
		}
		norm := map[string]any{
			"event_type":            "srum_app_resource_usage",
			"app":                   p.nameOf(srumRowVal(row, "AppId")),
			"user_sid":              p.nameOf(srumRowVal(row, "UserId")),
			"foreground_cycle_time": srumNormInt(srumRowVal(row, "ForegroundCycleTime")),
			"background_cycle_time": srumNormInt(srumRowVal(row, "BackgroundCycleTime")),
			"face_time":             srumNormInt(srumRowVal(row, "FaceTime")),
			"bytes_read":            sum64("ForegroundBytesRead", "BackgroundBytesRead"),
			"bytes_written":         sum64("ForegroundBytesWritten", "BackgroundBytesWritten"),
			"timestamp_utc":         nil,
		}
		if dt != nil {
			norm["timestamp_utc"] = tsISO
		}
		loc := srumLocator(row, p.nAppRes)
		if !p.send(model.Record{Kind: model.KindEvent, Norm: norm,
			Raw:         fmt.Sprintf("table=%s auto_inc_id=%d", srumTableAppResource, loc),
			TsUTCDirect: dt}) {
			return false
		}
		p.nAppRes++
		return true
	})
}

// summaryRecord 收尾 srum_summary(树庭 summary 同键:tables 三表计数 /
// id_map_entries / unmapped_ids / row_errors / missing_tables / note)。
func (p *srumPump) summaryRecord() model.Record {
	missing := p.missing
	if missing == nil {
		missing = []string{}
	}
	summary := map[string]any{
		"tables": map[string]int64{
			"network_usage":        p.nNetwork,
			"network_connectivity": p.nConnect,
			"app_resource_usage":   p.nAppRes,
		},
		"id_map_entries": int64(len(p.idMap)),
		"unmapped_ids":   p.unmapped,
		"row_errors":     p.rowErrors,
		"missing_tables": missing,
		"note": "SRUM 三表流式解析(逐页读,内存与库大小无关);" +
			"TimeStamp 按 OLE Automation double 位模式解码(对 spec 写," +
			"树庭实测同款);ConnectStartTime 为 FILETIME;UTC 原生直通;" +
			"行级异常/未映射 ID/缺失表如实计数",
	}
	return model.Record{Kind: model.KindEvent, Raw: "<srum_summary>",
		Norm: map[string]any{"event_type": "srum_summary", "summary": summary}}
}
