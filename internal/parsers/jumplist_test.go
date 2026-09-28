// JumpList 解析器合成样本测试:手搓最小 CFB(v3,MS-CFB)容器 + DestList
// 字节级边界用例 + customDestinations 拼接 + 内存纪律回归。
// 真实案件样本永不入测试(纪律),CFB 由 buildCFB 按 spec 纯字节构造。
package parsers

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// ---- 合成夹具构造(对 spec 写字节级构造) ----

// buildDestList 造 DestList 流字节(version 头 + 0x82 字节定长前缀条目
// (路径起于 +0x82,树庭 _parse_destlist 布局)+ UTF-16LE 路径 +
// u32 尺寸属性尾)。
func buildDestList(version uint32, entryNos []uint32, paths []string,
	fts []uint64, trailerLen int) []byte {
	buf := make([]byte, 0x20)
	binary.LittleEndian.PutUint32(buf[0:], version)
	binary.LittleEndian.PutUint32(buf[4:], uint32(len(paths)))
	for i, p := range paths {
		e := make([]byte, 0x84)
		binary.LittleEndian.PutUint32(e[0x58:], entryNos[i])
		binary.LittleEndian.PutUint64(e[0x64:], fts[i])
		u := utf16.Encode([]rune(p))
		binary.LittleEndian.PutUint16(e[0x80:], uint16(len(u)))
		buf = append(buf, e[:0x82]...) // 路径起于 +0x82(树庭 _parse_destlist)
		for _, c := range u {
			var b [2]byte
			binary.LittleEndian.PutUint16(b[:], c)
			buf = append(buf, b[:]...)
		}
		var tb [4]byte
		binary.LittleEndian.PutUint32(tb[:], uint32(trailerLen))
		buf = append(buf, tb[:]...)
		buf = append(buf, make([]byte, trailerLen)...)
	}
	return buf
}

// jlTestStream 合成 CFB 内的一条流。
type jlTestStream struct {
	name string
	data []byte
}

// jlDirEntry 落一条 128 字节 CFB 目录项(v3)。
func jlDirEntry(buf []byte, name string, objType byte, left, right, child,
	start uint32, size uint64) {
	u := utf16.Encode([]rune(name))
	for i, c := range u {
		binary.LittleEndian.PutUint16(buf[i*2:], c)
	}
	binary.LittleEndian.PutUint16(buf[64:], uint16((len(u)+1)*2)) // 含 NUL
	buf[66] = objType                                             // 5=root 2=stream
	buf[67] = 1                                                   // black
	binary.LittleEndian.PutUint32(buf[68:], left)
	binary.LittleEndian.PutUint32(buf[72:], right)
	binary.LittleEndian.PutUint32(buf[76:], child)
	binary.LittleEndian.PutUint32(buf[116:], start)
	binary.LittleEndian.PutUint64(buf[120:], size)
}

// buildCFB 造最小合法 CFB(v3,512 字节扇区;流全走 ministream,≤3 条,
// 兄弟链挂右枝)。布局:扇区0=FAT,1=目录,2..=ministream,尾=miniFAT。
func buildCFB(t *testing.T, streams []jlTestStream) []byte {
	t.Helper()
	if len(streams) == 0 || len(streams) > 3 {
		t.Fatalf("合成 CFB 只支持 1-3 条流: %d", len(streams))
	}
	const sector = 512
	const noStream = 0xFFFFFFFF
	const endOfChain = 0xFFFFFFFE
	var mini []byte
	miniStart := make([]uint32, len(streams))
	for i, s := range streams {
		if len(s.data) == 0 {
			t.Fatal("合成流数据为空(迷你流起点语义不支持,用例不需要)")
		}
		miniStart[i] = uint32(len(mini) / 64)
		mini = append(mini, s.data...)
		for len(mini)%64 != 0 {
			mini = append(mini, 0)
		}
	}
	for len(mini)%sector != 0 {
		mini = append(mini, 0)
	}
	msSectors := uint32(len(mini) / sector)
	fatSn, dirSn, miniSn := uint32(0), uint32(1), uint32(2)
	miniFatSn := miniSn + msSectors

	put := func(b []byte, sn, v uint32) {
		binary.LittleEndian.PutUint32(b[sn*4:], v)
	}
	// FAT
	fat := make([]byte, sector)
	for i := 0; i < sector/4; i++ {
		put(fat, uint32(i), 0xFFFFFFFF) // FREESECT
	}
	put(fat, fatSn, 0xFFFFFFFD) // FATSECT
	put(fat, dirSn, endOfChain)
	for j := uint32(0); j < msSectors; j++ {
		v := uint32(endOfChain)
		if j+1 < msSectors {
			v = miniSn + j + 1
		}
		put(fat, miniSn+j, v)
	}
	put(fat, miniFatSn, endOfChain)

	// miniFAT(每条流的 64 字节迷你扇区链)
	miniFat := make([]byte, sector)
	for i := 0; i < sector/4; i++ {
		put(miniFat, uint32(i), 0xFFFFFFFF)
	}
	for i, s := range streams {
		cnt := uint32((len(s.data) + 63) / 64)
		for j := uint32(0); j < cnt; j++ {
			v := uint32(endOfChain)
			if j+1 < cnt {
				v = miniStart[i] + j + 1
			}
			put(miniFat, miniStart[i]+j, v)
		}
	}

	// 目录(根 + 右倾兄弟链)
	dir := make([]byte, sector)
	jlDirEntry(dir[0:], "Root Entry", 5, noStream, noStream, 1,
		miniSn, uint64(len(mini)))
	for i, s := range streams {
		right := uint32(noStream)
		if i+1 < len(streams) {
			right = uint32(i + 2)
		}
		jlDirEntry(dir[(i+1)*128:], s.name, 2, noStream, right, noStream,
			miniStart[i], uint64(len(s.data)))
	}

	// 头(v3;DIFAT[0]=FAT 扇区 0)
	hdr := make([]byte, sector)
	copy(hdr, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	binary.LittleEndian.PutUint16(hdr[24:], 0x003E) // minor
	binary.LittleEndian.PutUint16(hdr[26:], 3)      // major v3
	binary.LittleEndian.PutUint16(hdr[28:], 0xFFFE) // LE
	binary.LittleEndian.PutUint16(hdr[30:], 9)      // sector shift
	binary.LittleEndian.PutUint16(hdr[32:], 6)      // mini shift
	binary.LittleEndian.PutUint32(hdr[44:], 1)      // num FAT
	binary.LittleEndian.PutUint32(hdr[48:], dirSn)
	binary.LittleEndian.PutUint32(hdr[56:], 4096) // mini cutoff
	binary.LittleEndian.PutUint32(hdr[60:], miniFatSn)
	binary.LittleEndian.PutUint32(hdr[64:], 1) // num miniFAT
	binary.LittleEndian.PutUint32(hdr[68:], endOfChain)
	for i := 0; i < 109; i++ {
		binary.LittleEndian.PutUint32(hdr[76+i*4:], 0xFFFFFFFF)
	}
	binary.LittleEndian.PutUint32(hdr[76:], fatSn) // DIFAT[0]

	out := append(hdr, fat...)
	out = append(out, dir...)
	out = append(out, mini...)
	return append(out, miniFat...)
}

// ---- automaticDestinations(CFB) ----

func TestJumpList_AutomaticCFB(t *testing.T) {
	ftAcc0, ftAcc1 := ft(1600000000), ft(1600001000)
	dest := buildDestList(6, []uint32{3, 7},
		[]string{`C:\Tools\evil.exe`, `D:\doc.txt`},
		[]uint64{ftAcc0, ftAcc1}, 4)
	cfb := buildCFB(t, []jlTestStream{
		{name: "DestList", data: dest},
		{name: "1", data: buildLNK(`C:\Tools\evil.exe`, "/q -x")},
		{name: "2", data: []byte("garbage-not-an-lnk-blob")},
	})
	stream, err := JumpListParser{}.Records(
		writeTemp(t, "a1b2c3.automaticDestinations-ms", cfb))
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, stream)
	if len(recs) != 4 { // 2 destlist + 1 lnk + 1 summary
		t.Fatalf("记录数不符: %d", len(recs))
	}
	// DestList 条目 0
	r0 := recs[0]
	if r0.Kind != model.KindEvent ||
		r0.Norm["event_type"] != "jumplist_entry" ||
		r0.Norm["app_id"] != "a1b2c3" ||
		r0.Norm["source"] != "destlist" ||
		r0.Norm["entry_no"] != 3 ||
		r0.Norm["target_path"] != `C:\Tools\evil.exe` ||
		r0.Norm["accessed_utc"] != "2020-09-13T12:26:40Z" {
		t.Fatalf("destlist 条目字段不符: %+v", r0.Norm)
	}
	if r0.TsUTCDirect == nil ||
		!r0.TsUTCDirect.Equal(time.Unix(1600000000, 0).UTC()) {
		t.Fatalf("destlist TsUTCDirect 不符: %v", r0.TsUTCDirect)
	}
	if _, has := r0.Norm["arguments"]; has {
		t.Fatal("destlist 条目不应有 arguments")
	}
	if recs[1].Norm["entry_no"] != 7 ||
		recs[1].Norm["target_path"] != `D:\doc.txt` {
		t.Fatalf("destlist 条目 1 不符: %+v", recs[1].Norm)
	}
	// LNK 流条目
	r2 := recs[2]
	if r2.Norm["source"] != "lnk_stream" || r2.Norm["entry_no"] != 1 ||
		r2.Norm["target_path"] != `C:\Tools\evil.exe` ||
		r2.Norm["arguments"] != "/q -x" ||
		r2.Norm["created_utc"] != "2020-09-13T12:26:40Z" ||
		r2.Norm["modified_utc"] != "2020-09-13T12:28:20Z" ||
		r2.Norm["accessed_utc"] != "2020-09-13T12:30:00Z" {
		t.Fatalf("lnk 流条目字段不符: %+v", r2.Norm)
	}
	if r2.TsUTCDirect == nil ||
		!r2.TsUTCDirect.Equal(time.Unix(1600000100, 0).UTC()) {
		t.Fatalf("lnk 条目 ts 应取 modified: %v", r2.TsUTCDirect)
	}
	// summary
	sum := recs[3].Norm
	if sum["event_type"] != "jumplist_summary" ||
		sum["app_id"] != "a1b2c3" ||
		sum["entries"] != int64(3) ||
		sum["entry_errors"] != int64(1) ||
		sum["destlist_status"] != "ok" {
		t.Fatalf("summary 不符: %+v", sum)
	}
	notes, _ := sum["notes"].([]string)
	joined := strings.Join(notes, "|")
	if !strings.Contains(joined, "流 2: ") {
		t.Fatalf("坏 LNK 流未如实入 notes: %v", notes)
	}
}

// TestJumpList_DestListParse 直接喂字节测 parseDestList 边界(树庭
// _parse_destlist 同款状态文案逐字对齐)。
func TestJumpList_DestListParse(t *testing.T) {
	// 头不足
	if _, st := parseDestList([]byte{1, 2, 3}); st != "DestList 头不足 32 字节" {
		t.Fatalf("短头状态不符: %q", st)
	}
	// 空 DestList
	empty := make([]byte, 0x20)
	if _, st := parseDestList(empty); st != "空 DestList(version=0 或无条目)" {
		t.Fatalf("空 DestList 状态不符: %q", st)
	}
	// 正常 2 条,已知版本
	d := buildDestList(6, []uint32{1, 2},
		[]string{`C:\a.exe`, `C:\b.txt`}, []uint64{ft(1600000000), ft(1600000100)}, 0)
	entries, st := parseDestList(d)
	if st != "ok" || len(entries) != 2 ||
		entries[0].target != `C:\a.exe` || entries[1].entryNo != 2 {
		t.Fatalf("正常解析不符: st=%q entries=%+v", st, entries)
	}
	// 未知版本:同布局尝试,如实标注
	d9 := buildDestList(9, []uint32{1}, []string{`C:\a.exe`},
		[]uint64{ft(1600000000)}, 0)
	if _, st := parseDestList(d9); st != "ok(版本 9 未在已知表内,同布局解析成功)" {
		t.Fatalf("未知版本状态不符: %q", st)
	}
	// 截断:声明 3 条只给 2 条
	dt := buildDestList(6, []uint32{1, 2}, []string{`C:\a.exe`, `C:\b.txt`},
		[]uint64{ft(1600000000), ft(1600000100)}, 0)
	binary.LittleEndian.PutUint32(dt[4:], 3)
	entries, st = parseDestList(dt)
	if st != "条目 2/3 处截断,已产出前 2 条" || len(entries) != 2 {
		t.Fatalf("截断降级不符: st=%q n=%d", st, len(entries))
	}
	// 路径越界:路径长超大
	dp := buildDestList(6, []uint32{1}, []string{`C:\a.exe`},
		[]uint64{ft(1600000000)}, 0)
	binary.LittleEndian.PutUint16(dp[0x20+0x80:], 0xFFFF)
	if _, st := parseDestList(dp); st != "条目 0/1 路径越界,已产出前 0 条" {
		t.Fatalf("路径越界状态不符: %q", st)
	}
	// 尾部残留
	dr := append(buildDestList(6, []uint32{1}, []string{`C:\a.exe`},
		[]uint64{ft(1600000000)}, 0), 0, 0, 0)
	if _, st := parseDestList(dr); st != "尾部残留 3 字节,条目已全产出版本存疑" {
		t.Fatalf("尾部残留状态不符: %q", st)
	}
}

// ---- customDestinations ----

// buildCustom 造 customDestinations(u32==2 头 + blobs,条目间 20 字节
// 分隔=u32 前缀 + 16 字节 CLSID)。
func buildCustom(blobs ...[]byte) []byte {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint32(buf[0:], 2)
	for i, b := range blobs {
		if i > 0 {
			buf = append(buf, make([]byte, 20)...)
		}
		buf = append(buf, b...)
	}
	return buf
}

func TestJumpList_CustomFields(t *testing.T) {
	good := buildLNK(`C:\A\tool.exe`, "-x")
	// 坏条目:签名在,但 HasLinkInfo 越界(条目级失败计数,零静默)
	bad := make([]byte, 0x4C)
	copy(bad, lnkMagic)
	binary.LittleEndian.PutUint32(bad[0x14:], 0x02)
	data := buildCustom(good, bad)
	stream, err := JumpListParser{}.Records(
		writeTemp(t, "ff00.customDestinations-ms", data))
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, stream)
	if len(recs) != 2 { // 1 entry + 1 summary
		t.Fatalf("记录数不符: %d", len(recs))
	}
	r0 := recs[0]
	if r0.Norm["event_type"] != "jumplist_entry" ||
		r0.Norm["app_id"] != "ff00" ||
		r0.Norm["source"] != "custom_lnk" ||
		r0.Norm["target_path"] != `C:\A\tool.exe` ||
		r0.Norm["arguments"] != "-x" ||
		r0.Norm["modified_utc"] != "2020-09-13T12:28:20Z" {
		t.Fatalf("custom 条目字段不符: %+v", r0.Norm)
	}
	if _, has := r0.Norm["entry_no"]; has {
		t.Fatal("custom_lnk 条目不应有 entry_no(树庭同款)")
	}
	if r0.TsUTCDirect == nil {
		t.Fatal("custom 条目 ts 应取 modifiedFT")
	}
	sum := recs[1].Norm
	if sum["entries"] != int64(1) || sum["entry_errors"] != int64(1) {
		t.Fatalf("summary 计数不符: %+v", sum)
	}
	if _, has := sum["pinned_tail_note"]; !has {
		t.Fatal("缺 pinned_tail_note")
	}
	notes, _ := sum["notes"].([]string)
	if !strings.Contains(strings.Join(notes, "|"), "条目 @") {
		t.Fatalf("坏条目未如实入 notes: %v", notes)
	}
	// 空容器(仅头):如实标注
	stream2, err := JumpListParser{}.Records(
		writeTemp(t, "aa.customDestinations-ms", buildCustom()))
	if err != nil {
		t.Fatal(err)
	}
	recs2 := drain(t, stream2)
	if len(recs2) != 1 || recs2[0].Norm["entries"] != int64(0) {
		t.Fatalf("空容器不符: %+v", recs2)
	}
	notes2, _ := recs2[0].Norm["notes"].([]string)
	if !strings.Contains(strings.Join(notes2, "|"), "无 LNK 条目") {
		t.Fatalf("空容器未如实标注: %v", notes2)
	}
}

// ---- 文件级失败(零静默) ----

func TestJumpList_FileLevelFailures(t *testing.T) {
	// 非 CFB
	if _, err := (JumpListParser{}).Records(writeTemp(t,
		"x.automaticDestinations-ms", []byte("not a cfb container at all"))); err == nil {
		t.Fatal("非 CFB 应文件级如实 failed")
	}
	// custom 头版本 != 2
	bad := make([]byte, 16)
	binary.LittleEndian.PutUint32(bad[0:], 99)
	if _, err := (JumpListParser{}).Records(writeTemp(t,
		"x.customDestinations-ms", bad)); err == nil {
		t.Fatal("头版本 != 2 应文件级如实 failed")
	}
	// 空文件
	if _, err := (JumpListParser{}).Records(writeTemp(t,
		"e.customDestinations-ms", nil)); err == nil {
		t.Fatal("空文件应文件级如实 failed")
	}
	// 未知名后缀
	if _, err := (JumpListParser{}).Records(writeTemp(t,
		"x.txt", []byte("whatever"))); err == nil {
		t.Fatal("未知后缀应如实报错")
	}
}

// 内存纪律:超大声明输入(200MB custom,超上限)文件级快速如实 failed,
// 不整读、堆增量 << 64MB。
func TestJumpList_MemoryFlat(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过大输入内存用例")
	}
	p := filepath.Join(t.TempDir(), "big.customDestinations-ms")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(200 << 20); err != nil {
		t.Skipf("大文件不可用: %v", err)
	}
	f.Sync()

	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	_, err = JumpListParser{}.Records(p)
	runtime.GC()
	runtime.ReadMemStats(&m1)
	if err == nil {
		t.Fatal("超上限 custom 应文件级如实 failed")
	}
	delta := int64(m1.HeapAlloc) - int64(m0.HeapAlloc)
	if delta > 64<<20 {
		t.Fatalf("200MB 声明输入堆增量 %d MB 超 64MB 纪律线", delta>>20)
	}
	t.Logf("200MB 声明输入:堆增量 %.1f MB,如实失败: %v",
		float64(delta)/(1<<20), err)
}
