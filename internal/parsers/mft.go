// $MFT 裸文件流式解析(M3):两遍式(祖先名字表 → 流式出行),语义逐字段
// 移植树庭 backend/app/parsers/mft.py(金标准基准)。
//
// 格式契约(NTFS $MFT,对公开 spec 写):
//   - 定长 1024 字节记录,FILE 魔数 + USA fixup(每 512 字节扇区尾 2 字节
//     校验回写);fixup 失配/非 FILE → 坏记录计数,不中断;
//   - 只取 $STANDARD_INFORMATION(0x10)与 $FILE_NAME(0x30)——spec 上
//     恒常驻,实测遇非常驻 → 计数跳过(诚实,不猜);属性值 struct 自解析;
//   - 记录号 = 文件内偏移/1024;Flags bit0=in_use(0=已删除痕迹) bit1=目录;
//   - 全路径经 $FN 父记录引用链拼接(根=记录 5「.」父指自身),卷根相对
//     ($MFT 不携带盘符);链深上限 64 + 环检测;父不可达 → 孤儿退化为
//     $FN 文件名,orphan_paths 如实计数;
//   - 多 $FN 取最优命名空间(WIN32_DOS>WIN32>POSIX>DOS);多非 DOS $FN =
//     硬链接(timestomp 判定排除,spec 决定的系统性偏斜)。
//
// 内存纪律(2026-09-22 OOM 事故后立为硬纪律):
//   - IO 恒流式:逐记录 ReadAt(单条 1KB),任意时刻读入字节与文件大小
//     无关;>2GB 文件天然按记录块处理,不整读;
//   - 祖先名字表只收**目录记录**(NTFS 语义:父引用必指向目录;文件记录
//     名随自身行带出,不入表)——紧凑 map 而非按全量记录数的并行数组。
//     与树庭全量数组的差异(如实):父引用指向非目录记录 = 结构异常,
//     树庭拼得出路径,本实现按孤儿退化并计数(证据不丢,parent_record
//     字段仍在);
//   - 上限:祖先表 mftMaxAncestors 条(默认 512k,单条 ~150B,封顶 ~75MB;
//     真机目录占比实测 <10%,170 万记录的 MFT 仅数万条)、路径缓存
//     mftMaxDirCache 条(超过即停缓存,解析照常走链,只是慢)、timestomp
//     事件缓冲 500+500 条;超限一律如实计数(ancestor_overflow 等),
//     绝不静默、绝不无界;
//   - 回归测试:TestMFT_AncestorCapGuard 喂「声明大量目录记录」的合成
//     输入,断言表被上限截断 + 堆增量受控。
//
// 与树庭的另一差异(如实):树庭行级入独立 mft_entries 表;丰图统一进
// events(行记录 ts 留 nil 快照语义,六时间戳全在 fields;timestomp
// 候选事件 ts 取 si_created UTC 直通,与树庭一致)。
package parsers

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"

	"github.com/ye-mengwen/fengtu/internal/model"
)

const (
	mftRecordSize    = 1024
	mftPathDepthCap  = 64
	mftAttrEnd       = 0xFFFFFFFF
	mftAttrSI        = 0x10
	mftAttrFN        = 0x30
	mftFlagInUse     = 0x1
	mftFlagDirectory = 0x2
	// timestomp 事件上限(防服务化噪声淹没;全量候选仍可查,见文件头)
	mftTSCapDeleted = 500
	mftTSCapInUse   = 500
	// timestomp 阈值:$FN 创建晚于 $SI 创建 >60s 才算候选(方向敏感)
	mftTSMinDeltaSec = 60
)

// 内存上限(见文件头「内存纪律」;变量以便回归测试覆盖为小值)。
var (
	// mftMaxAncestors 祖先名字表上限(目录记录条数;超出如实计数,路径退化)。
	mftMaxAncestors = 512_000
	// mftMaxDirCache 路径缓存上限(超了不缓存,解析照常)。
	mftMaxDirCache = 131_072
)

// $FN 命名空间优先级:数值小者优先(WIN32_DOS=3 / WIN32=1 是规范名)。
var mftNSPriority = map[byte]int{3: 0, 1: 1, 0: 2, 2: 3}

// MftParser $MFT 解析器。
type MftParser struct{}

// mftAncestor 祖先名字表条目(仅目录记录)。
type mftAncestor struct {
	parent uint64
	name   string
}

// mftScan 单条记录的解析结果。
type mftScan struct {
	flags       uint16
	si          [4]uint64 // created/modified/mft_changed/accessed(FILETIME)
	hasFN       bool
	fnParent    uint64
	fnName      string
	fnCreated   uint64
	fnModified  uint64
	fnSize      uint64
	fnNS        byte
	nonDOSFNs   int // 非 DOS 命名空间 $FN 数(>1 = 硬链接)
	nonresident int // 非常驻 SI/FN 计数(spec 上不该出现,如实)
}

// mftStream 两遍式记录流(内存与文件大小无关,见文件头)。
type mftStream struct {
	f     *os.File
	total int
	// 祖先名字表(仅目录;compact map,带上限)
	ancestors        map[uint64]mftAncestor
	ancestorOverflow int64
	// 第一遍统计
	stats    map[string]int64
	tsEvents []model.Record // 封顶内的 timestomp 候选(先放出)
	tsDirs   map[string]int64
	// 第二遍推进态
	seg      int
	scratch  []byte // 记录读取复用缓冲(1KB,见 readRecord 纪律)
	dirCache map[uint64]string
	orphans  int64
	summary  *model.Record
	done     bool
	err      error
}

// Records 打开 $MFT 并跑第一遍(空文件/全坏 → 文件级失败,如实)。
func (MftParser) Records(path string) (Stream, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("$MFT 打开失败: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("$MFT stat 失败: %w", err)
	}
	total := int(fi.Size() / mftRecordSize)
	if total == 0 {
		f.Close()
		return nil, fmt.Errorf("空文件或不足一条记录(%d 字节),如实 failed", fi.Size())
	}
	s := &mftStream{
		f: f, total: total,
		ancestors: map[uint64]mftAncestor{},
		stats:     map[string]int64{}, tsDirs: map[string]int64{},
		dirCache: map[uint64]string{},
		scratch:  make([]byte, mftRecordSize),
	}
	if fi.Size()%mftRecordSize != 0 {
		// 尾部不足一条记录:按整记录数截断处理,如实计数(采集拷贝截尾是常态)
		s.stats["truncated_tail_bytes"] = fi.Size() % mftRecordSize
	}
	s.pass1()
	if s.stats["valid"] == 0 {
		f.Close()
		return nil, fmt.Errorf("无有效 FILE 记录(共扫 %d 条,全坏/垃圾字节),"+
			"如实 failed", total)
	}
	return s, nil
}

// readRecord 读一条记录并做 USA fixup(单条 1KB,IO 恒流式,缓冲复用——
// 百万级记录文件逐条 make 会造成数 GB 分配搅动,OOM 事故后立的纪律);
// 失败原因分层:io 失败 → (nil, ioErr);魔数/fixup 失配 → (nil, nil)
// (坏记录,调用方计数)。返回切片属内部缓冲,下次调用即覆写。
func (s *mftStream) readRecord(seg int) ([]byte, error) {
	buf := s.scratch
	n, err := s.f.ReadAt(buf, int64(seg)*mftRecordSize)
	if err != nil && n < mftRecordSize {
		return nil, fmt.Errorf("记录 %d 读取失败: %w", seg, err)
	}
	if string(buf[:4]) != "FILE" {
		return nil, nil
	}
	usaOfs := int(binary.LittleEndian.Uint16(buf[4:6]))
	usaCnt := int(binary.LittleEndian.Uint16(buf[6:8]))
	if usaCnt == 0 || usaOfs+2*usaCnt > mftRecordSize {
		return nil, nil // USA 结构越界:坏记录
	}
	for i := 1; i < usaCnt; i++ {
		end := i * 512
		if end > mftRecordSize {
			break // 记录仅 2 扇区,多余 USA 槽忽略(spec 上 count=3)
		}
		if buf[end-2] != buf[usaOfs] || buf[end-1] != buf[usaOfs+1] {
			return nil, nil // fixup 签名校验失配:坏记录
		}
		buf[end-2] = buf[usaOfs+2*i]
		buf[end-1] = buf[usaOfs+2*i+1]
	}
	return buf, nil
}

// scanRecord 解析 $SI/$FN(树庭 _scan_record 同语义;坏记录 → nil)。
func scanRecord(buf []byte) *mftScan {
	flags := binary.LittleEndian.Uint16(buf[22:24])
	attrOff := int(binary.LittleEndian.Uint16(buf[20:22]))
	out := &mftScan{flags: flags}
	bestPri := -1
	off := attrOff
	for off+16 <= len(buf) {
		atype := binary.LittleEndian.Uint32(buf[off:])
		alen := int(binary.LittleEndian.Uint32(buf[off+4:]))
		if atype == mftAttrEnd || alen == 0 {
			break
		}
		if off+alen > len(buf) {
			break // 属性长度越界:记录损坏截断,停止遍历
		}
		if atype == mftAttrSI || atype == mftAttrFN {
			if buf[off+8] != 0 {
				out.nonresident++ // 非常驻 SI/FN:spec 上不该出现,计数不猜
			} else {
				vlen := int(binary.LittleEndian.Uint32(buf[off+16:]))
				voff := int(binary.LittleEndian.Uint16(buf[off+20:]))
				if voff+vlen <= alen && off+voff+vlen <= len(buf) {
					val := buf[off+voff : off+voff+vlen]
					if atype == mftAttrSI && len(val) >= 32 {
						for i := 0; i < 4; i++ {
							out.si[i] = binary.LittleEndian.Uint64(val[8*i:])
						}
					} else if atype == mftAttrFN && len(val) >= 66 {
						parent := binary.LittleEndian.Uint64(val[0:8]) & 0xFFFFFFFFFFFF
						nlen := int(val[64])
						ns := val[65]
						if 66+nlen*2 <= len(val) {
							name := utf16le(val[66 : 66+nlen*2])
							if ns == 0 || ns == 1 || ns == 3 {
								out.nonDOSFNs++
							}
							pri, ok := mftNSPriority[ns]
							if !ok {
								pri = 9
							}
							if bestPri < 0 || pri < bestPri {
								bestPri = pri
								out.hasFN = true
								out.fnParent = parent
								out.fnName = name
								out.fnCreated = binary.LittleEndian.Uint64(val[8:16])
								out.fnModified = binary.LittleEndian.Uint64(val[16:24])
								out.fnSize = binary.LittleEndian.Uint64(val[48:56])
								out.fnNS = ns
							}
						}
					}
				}
			}
		}
		off += alen
	}
	return out
}

// resolvePath 父引用链 → 全路径(树庭 _resolve_path 同语义,基于祖先表)。
// parts 从近到远收祖先名,命中缓存时缓存值即该目录完整路径;
// ok=false = 父不可达(第一遍=父未扫到计 deferred;第二遍=孤儿计 orphans)。
func (s *mftStream) resolvePath(seg int, sc *mftScan) (string, bool) {
	var parts []string
	seen := map[uint64]bool{}
	cur := sc.fnParent
	for {
		if p, hit := s.dirCache[cur]; hit {
			parts = append(parts, p)
			break
		}
		a, has := s.ancestors[cur]
		if !has {
			return "", false // 父不可达(未扫到/不存在/超限被截/非目录父)
		}
		if seen[cur] || len(parts) >= mftPathDepthCap {
			return "", false // 环/超深:按孤儿处理
		}
		seen[cur] = true
		if a.parent == cur { // 根记录(5「.」):父引用指向自身
			parts = append(parts, "")
			break
		}
		parts = append(parts, a.name)
		cur = a.parent
	}
	path := sc.fnName
	for i := 0; i < len(parts); i++ { // 近→远逐层前插;根/缓存空前缀跳过
		if parts[i] == "" {
			continue
		}
		path = parts[i] + "\\" + path
	}
	// 只缓存目录的完整路径(孩子们复用),缓存超限即停缓存(解析照常走链);
	// 根记录自身行路径是「.」但作为父前缀是空——缓存空前缀
	if sc.flags&mftFlagDirectory != 0 && len(s.dirCache) < mftMaxDirCache {
		p := path
		if a, ok := s.ancestors[uint64(seg)]; ok && a.parent == uint64(seg) {
			p = ""
		}
		s.dirCache[uint64(seg)] = p
	}
	return path, true
}

// pass1 轻扫:祖先名字表 + 统计 + timestomp 候选(树庭第一遍同语义)。
func (s *mftStream) pass1() {
	for seg := 0; seg < s.total; seg++ {
		buf, err := s.readRecord(seg)
		if err != nil {
			s.stats["read_errors"]++
			break // 读取失败:到这儿为止(如实计数,截断/介质错)
		}
		if buf == nil {
			s.stats["bad"]++
			continue
		}
		sc := scanRecord(buf)
		s.stats["valid"]++
		s.stats["nonresident_skipped"] += int64(sc.nonresident)
		isDir := sc.flags&mftFlagDirectory != 0
		if sc.flags&mftFlagInUse != 0 {
			s.stats["in_use"]++
		} else {
			s.stats["deleted"]++
		}
		if isDir {
			s.stats["dirs"]++
		}
		if !sc.hasFN {
			s.stats["no_fn"]++ // 扩展记录等无 $FN:计数不落行(诚实)
			continue
		}
		s.stats["named_rows"]++
		if isDir {
			if len(s.ancestors) < mftMaxAncestors {
				s.ancestors[uint64(seg)] = mftAncestor{parent: sc.fnParent,
					name: sc.fnName}
			} else {
				s.ancestorOverflow++ // 超限:如实计数,相关路径退化不猜
			}
		}

		// 第一遍语义的路径解析(树庭同款):此刻祖先表只到当前记录,
		// 父链未扫到 → 解析失败计 deferred,事件路径退化为 $FN 名(证据不丢)
		p1, p1ok := s.resolvePath(seg, sc)
		if !p1ok {
			s.stats["deferred"]++
		}

		// timestomp 候选:$FN 创建晚于 $SI 创建超阈值(方向敏感,见文件头)
		siC, okSI := FiletimeToUTC(sc.si[0])
		fnC, okFN := FiletimeToUTC(sc.fnCreated)
		if okSI && okFN && fnC.Sub(siC).Seconds() > mftTSMinDeltaSec {
			if sc.nonDOSFNs > 1 {
				s.stats["ts_hardlink_skipped"]++ // 硬链接系统性偏斜,排除计数
			} else {
				s.stats["timestomp"]++
				inUse := sc.flags&mftFlagInUse != 0
				pathNow := p1
				if !p1ok {
					pathNow = sc.fnName
				}
				dir := "<卷根或父链未解析>"
				if i := lastIndexByte(pathNow, '\\'); i >= 0 {
					dir = pathNow[:i]
				}
				s.tsDirs[dir]++
				capOK := (inUse && s.stats["ts_emitted"] < mftTSCapInUse) ||
					(!inUse && s.stats["ts_emitted_deleted"] < mftTSCapDeleted)
				if capOK {
					if inUse {
						s.stats["ts_emitted"]++
					} else {
						s.stats["ts_emitted_deleted"]++
					}
					norm := map[string]any{
						"event_type":          "mft_timestomp_candidate",
						"record_number":       seg,
						"path":                pathNow,
						"filename":            sc.fnName,
						"parent_record":       sc.fnParent,
						"in_use":              inUse,
						"si_created_utc":      siC.Format("2006-01-02T15:04:05Z"),
						"fn_created_utc":      fnC.Format("2006-01-02T15:04:05Z"),
						"fn_minus_si_seconds": fnC.Sub(siC).Seconds(),
						"si_modified_utc":     filetimeISOorNil(sc.si[1]),
						"fn_modified_utc":     filetimeISOorNil(sc.fnModified),
						"rule": "$FN 创建晚于 $SI 创建 >60s(典型 timestomp 特征;" +
							"备份还原/服务化拷贝亦可造成,候选需人工复核;硬链接记录已排除)",
						"threshold_seconds": mftTSMinDeltaSec,
					}
					rec := model.Record{
						LineNo: seg + 1, Kind: model.KindEvent, Norm: norm,
						Raw:         fmt.Sprintf("MFT#%d %s", seg, sc.fnName),
						TsUTCDirect: &siC,
					}
					s.tsEvents = append(s.tsEvents, rec)
				}
			}
		}
	}
}

// Next 先放 pass1 的 timestomp 候选,再流式出行,最后 summary。
func (s *mftStream) Next() (model.Record, bool) {
	if s.err != nil {
		return model.Record{}, false
	}
	if len(s.tsEvents) > 0 {
		rec := s.tsEvents[0]
		s.tsEvents = s.tsEvents[1:]
		return rec, true
	}
	for !s.done {
		if s.seg >= s.total {
			s.done = true
			s.summary = s.buildSummary()
			break
		}
		seg := s.seg
		s.seg++
		buf, err := s.readRecord(seg)
		if err != nil || buf == nil {
			continue // 坏记录/读失败:第一遍已计数,本无行
		}
		sc := scanRecord(buf)
		if !sc.hasFN {
			continue
		}
		path, ok := s.resolvePath(seg, sc)
		if !ok {
			s.orphans++ // 孤儿退化(文件名,如实计数)
			path = sc.fnName
		}
		isDir := sc.flags&mftFlagDirectory != 0
		norm := map[string]any{
			"event_type":    "mft_entry",
			"record_number": seg,
			"path":          path,
			"name":          sc.fnName,
			"parent_record": sc.fnParent,
			"is_dir":        isDir,
			"in_use":        sc.flags&mftFlagInUse != 0,
			"fn_namespace":  sc.fnNS,
		}
		// 非法 FILETIME → 键省略(树庭 None/NULL 同语义,不留空串)
		for k, v := range map[string]uint64{
			"si_created_utc": sc.si[0], "si_modified_utc": sc.si[1],
			"si_mft_changed_utc": sc.si[2], "si_accessed_utc": sc.si[3],
			"fn_created_utc": sc.fnCreated, "fn_modified_utc": sc.fnModified,
		} {
			if s := FiletimeISO(v); s != "" {
				norm[k] = s
			}
		}
		if !isDir {
			norm["size"] = sc.fnSize // 目录不落 size(树庭同约定)
		}
		return model.Record{
			LineNo: seg + 1, Kind: model.KindEvent, Norm: norm,
			Raw: fmt.Sprintf("MFT#%d %s", seg, path),
		}, true
	}
	if s.summary != nil {
		rec := *s.summary
		s.summary = nil
		return rec, true
	}
	return model.Record{}, false
}

// buildSummary 收尾 mft_summary 事件(树庭 summary 字段同名同义)。
func (s *mftStream) buildSummary() *model.Record {
	top := topPairs(s.tsDirs, 10)
	norm := map[string]any{
		"event_type":                 "mft_summary",
		"total_records":              s.total,
		"valid_records":              s.stats["valid"],
		"bad_records":                s.stats["bad"],
		"read_errors":                s.stats["read_errors"],
		"no_fn_records":              s.stats["no_fn"],
		"nonresident_si_fn_skipped":  s.stats["nonresident_skipped"],
		"in_use_records":             s.stats["in_use"],
		"deleted_records":            s.stats["deleted"], // in_use=false:已删除痕迹
		"directories":                s.stats["dirs"],
		"files":                      s.stats["valid"] - s.stats["dirs"],
		"named_rows":                 s.stats["named_rows"],
		"orphan_paths":               s.orphans,
		"deferred_rows":              s.stats["deferred"],
		"ancestor_table_entries":     len(s.ancestors),
		"ancestor_overflow":          s.ancestorOverflow,
		"ancestor_table_cap":         mftMaxAncestors,
		"timestomp_candidates":       s.stats["timestomp"],
		"timestomp_hardlink_skipped": s.stats["ts_hardlink_skipped"],
		"timestomp_events_emitted":   s.stats["ts_emitted"] + s.stats["ts_emitted_deleted"],
		"timestomp_events_truncated": s.stats["timestomp"] >
			s.stats["ts_emitted"]+s.stats["ts_emitted_deleted"],
		"timestomp_top_dirs": top,
		"note": "行级记录入 events(event_type=mft_entry,快照语义 ts 留 nil," +
			"六时间戳全在 fields,UTC 原生);已删除记录 in_use=false 可过滤;" +
			"timestomp 候选全量经 fn_created_utc>si_created_utc 可查,事件仅" +
			"发射高信号子集(上限 500+500),截断已如实标注;路径为卷根相对" +
			"($MFT 不携带盘符),孤儿退化为 $FN 文件名;祖先名字表仅目录记录" +
			"(带上限,超限如实计 ancestor_overflow),内存与文件大小无关",
	}
	if t := s.stats["truncated_tail_bytes"]; t > 0 {
		norm["truncated_tail_bytes"] = t // 尾部不足一记录:截尾处理(如实)
	}
	return &model.Record{
		LineNo: s.total + 1, Kind: model.KindEvent, Norm: norm,
		Raw: "<mft_summary>",
	}
}

// filetimeISOorNil 非法 FILETIME → nil(树庭 _ft_iso None 同语义)。
func filetimeISOorNil(ft uint64) any {
	if s := FiletimeISO(ft); s != "" {
		return s
	}
	return nil
}

// topPairs 计数 map → 前 n 名 [{key,count}](字典序定同分,输出确定)。
func topPairs(m map[string]int64, n int) []map[string]any {
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
		out = append(out, map[string]any{"dir": p.k, "count": p.v})
	}
	return out
}

func lastIndexByte(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func (s *mftStream) Err() error { return s.err }

func (s *mftStream) Close() error { return s.f.Close() }
