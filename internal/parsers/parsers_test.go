// 树庭面原生解析器合成样本测试(M3):正样本逐字段焊死 + 负样本
// (坏签名/未知版本/截断/锚点不符)如实失败,零静默。
package parsers

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// ft(unix 秒)→ FILETIME。
func ft(sec int64) uint64 { return uint64(sec+11644473600) * 10_000_000 }

func drain(t *testing.T, s Stream) []model.Record {
	t.Helper()
	defer s.Close()
	var out []model.Record
	for {
		rec, ok := s.Next()
		if !ok {
			break
		}
		out = append(out, rec)
	}
	if err := s.Err(); err != nil {
		t.Fatalf("流错误: %v", err)
	}
	return out
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// ==================== Prefetch ====================

// buildPF 造一个未压缩 SCCA .pf(按 libscca 布局填字段)。
func buildPF(version uint32, runCount uint32, runOff int, timesOff int,
	lastRun uint64) []byte {
	buf := make([]byte, 0x200)
	binary.LittleEndian.PutUint32(buf[0:], version)
	copy(buf[4:], "SCCA")
	binary.LittleEndian.PutUint32(buf[0x0C:], uint32(len(buf)))
	name := []rune("EVIL.EXE")
	for i, r := range name {
		binary.LittleEndian.PutUint16(buf[0x10+2*i:], uint16(r))
	}
	binary.LittleEndian.PutUint32(buf[0x4C:], 0xDEADBEEF)
	binary.LittleEndian.PutUint32(buf[0x58:], 5) // 引用文件数
	if runOff > 0 {
		binary.LittleEndian.PutUint32(buf[runOff:], runCount)
	}
	binary.LittleEndian.PutUint64(buf[timesOff:], lastRun)
	return buf
}

func TestPrefetch_V23(t *testing.T) {
	// V23:0x98 次数,0x80 单次 FILETIME(2021-03-04T05:06:07Z)
	last := ft(1614834367)
	buf := buildPF(23, 7, 0x98, 0x80, last)
	stream, err := PrefetchParser{}.Records(writeTemp(t, "EVIL.EXE-12345678.pf", buf))
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, stream)
	if len(recs) != 1 || recs[0].Kind != model.KindEvent {
		t.Fatalf("记录数/类别不符: %+v", recs)
	}
	n := recs[0].Norm
	if n["exe_name"] != "EVIL.EXE" || n["version"] != uint32(23) ||
		n["run_count"] != uint32(7) || n["referenced_file_count"] != uint32(5) ||
		n["compressed"] != false || n["prefetch_hash"] != "DEADBEEF" {
		t.Fatalf("字段不符: %+v", n)
	}
	if n["last_run_utc"] != "2021-03-04T05:06:07Z" {
		t.Fatalf("last_run_utc 不符: %v", n["last_run_utc"])
	}
	if recs[0].TsUTCDirect == nil ||
		!recs[0].TsUTCDirect.Equal(time.Unix(1614834367, 0).UTC()) {
		t.Fatalf("TsUTCDirect 不符: %v", recs[0].TsUTCDirect)
	}
}

func TestPrefetch_V30Heuristic(t *testing.T) {
	last := ft(1614834367)
	// 0xCC 非零 → 次数在 0xC8(V30/V31 启发式,PECmd 同款)
	buf := buildPF(30, 0, 0, 0x80, last)
	binary.LittleEndian.PutUint32(buf[0xC8:], 42)
	binary.LittleEndian.PutUint32(buf[0xCC:], 1) // 非零标记
	stream, err := PrefetchParser{}.Records(writeTemp(t, "A.EXE-00000001.pf", buf))
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, stream)
	if recs[0].Norm["run_count"] != uint32(42) {
		t.Fatalf("V30 启发式计数位置不符: %+v", recs[0].Norm)
	}
	// 0xCC 为零 → 次数在 0xD0
	buf2 := buildPF(31, 0, 0, 0x80, last)
	binary.LittleEndian.PutUint32(buf2[0xD0:], 9)
	stream2, err := PrefetchParser{}.Records(writeTemp(t, "B.EXE-00000002.pf", buf2))
	if err != nil {
		t.Fatal(err)
	}
	if r := drain(t, stream2); r[0].Norm["run_count"] != uint32(9) {
		t.Fatalf("V31 0xD0 计数位置不符: %+v", r[0].Norm)
	}
}

func TestPrefetch_Negative(t *testing.T) {
	// 非 SCCA
	if _, err := (PrefetchParser{}).Records(
		writeTemp(t, "bad.pf", []byte("not a prefetch file at all, garbage bytes"))); err == nil {
		t.Fatal("坏签名应文件级失败")
	}
	// 未知版本
	buf := buildPF(99, 1, 0x90, 0x78, ft(1614834367))
	if _, err := (PrefetchParser{}).Records(writeTemp(t, "v99.pf", buf)); err == nil {
		t.Fatal("未知版本应如实 failed,不猜")
	}
	// 截断
	if _, err := (PrefetchParser{}).Records(
		writeTemp(t, "tiny.pf", []byte("SCCA"))); err == nil {
		t.Fatal("截断应如实 failed")
	}
}

// ==================== LNK ====================

// buildLNK 造最小 LNK(HasLinkInfo|IsUnicode,带 VolumeID 与 Arguments)。
func buildLNK(target string, args string) []byte {
	header := make([]byte, 0x4C)
	copy(header, lnkMagic)
	binary.LittleEndian.PutUint32(header[0x14:], 0x02|0x80|0x20) // LinkInfo|Unicode|HasArgs
	binary.LittleEndian.PutUint64(header[0x1C:], ft(1600000000)) // created
	binary.LittleEndian.PutUint64(header[0x24:], ft(1600000100)) // modified
	binary.LittleEndian.PutUint64(header[0x2C:], ft(1600000200)) // accessed

	// VolumeID(0x14 字节):size/driveType=3(FIXED)/serial/labelOff
	vol := make([]byte, 0x14)
	binary.LittleEndian.PutUint32(vol[0:], 0x14)
	binary.LittleEndian.PutUint32(vol[4:], 3)
	binary.LittleEndian.PutUint32(vol[8:], 0xA0B1C2D3)

	// LocalBasePathUnicode(UTF-16LE + NUL)
	tgt := make([]byte, 0, 64)
	for _, r := range target {
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], uint16(r))
		tgt = append(tgt, b[:]...)
	}
	tgt = append(tgt, 0, 0)

	liSize := 0x24 + len(vol) + len(tgt)
	li := make([]byte, liSize)
	binary.LittleEndian.PutUint32(li[0:], uint32(liSize))
	binary.LittleEndian.PutUint32(li[4:], 0x24)                     // header≥0x24 → Unicode 可用
	binary.LittleEndian.PutUint32(li[8:], 0x01)                     // VolumeIDAndLocalBasePath
	binary.LittleEndian.PutUint32(li[0x0C:], 0x24)                  // VolumeID 偏移
	binary.LittleEndian.PutUint32(li[0x1C:], uint32(0x24+len(vol))) // Unicode 路径偏移
	copy(li[0x24:], vol)
	copy(li[0x24+len(vol):], tgt)

	// StringData:Arguments(count 前缀 UTF-16LE)
	sd := make([]byte, 0, 64)
	var cb [2]byte
	binary.LittleEndian.PutUint16(cb[:], uint16(len([]rune(args))))
	sd = append(sd, cb[:]...)
	for _, r := range args {
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], uint16(r))
		sd = append(sd, b[:]...)
	}

	out := append(header, li...)
	return append(out, sd...)
}

func TestLNK_Fields(t *testing.T) {
	buf := buildLNK(`C:\Tools\evil.exe`, "/q -x")
	stream, err := LnkParser{}.Records(writeTemp(t, "evil.exe.lnk", buf))
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, stream)
	if len(recs) != 1 || recs[0].Kind != model.KindEvent {
		t.Fatalf("记录数/类别不符: %+v", recs)
	}
	n := recs[0].Norm
	if n["target"] != `C:\Tools\evil.exe` || n["arguments"] != "/q -x" {
		t.Fatalf("目标/参数不符: %+v", n)
	}
	if n["drive_type"] != uint32(3) || n["drive_type_label"] != "DRIVE_FIXED" ||
		n["volume_serial"] != "A0B1C2D3" {
		t.Fatalf("VolumeID 字段不符: %+v", n)
	}
	if n["target_created"] == nil || n["target_modified"] == nil {
		t.Fatalf("目标时间戳缺失: %+v", n)
	}
	if recs[0].TsUTCDirect != nil || recs[0].DTLocal != nil {
		t.Fatal("lnk 应为快照型(ts 留 nil,§9.3)")
	}
}

func TestLNK_BadMagic(t *testing.T) {
	stream, err := LnkParser{}.Records(
		writeTemp(t, "bad.lnk", []byte("definitely not an lnk")))
	if err != nil {
		t.Fatal(err) // 读取成功,结构坏 → 流内 bad,不文件级失败
	}
	recs := drain(t, stream)
	if len(recs) != 1 || recs[0].Kind != model.KindBad {
		t.Fatalf("坏 lnk 应产 bad 记录: %+v", recs)
	}
}

// ==================== USN CSV ====================

// buildUSNCSV 造 GBK 编码的 USN CSV(前置块 + 本地化表头 + 数据行)。
func buildUSNCSV(t *testing.T, rows []string) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteString("USN 日志 ID    : 0x01dd0f6c6dd3e5e3\r\n")
	b.WriteString("第一个 USN     : 50331648\r\n\r\n")
	b.WriteString("Usn,文件名,文件名长度,原因编号,原因,时间戳,文件属性编号,文件属性," +
		"文件 ID,父文件 ID,源信息号,源信息,安全 ID,主要版本,次要版本,记录长度\r\n")
	for _, r := range rows {
		b.WriteString(r + "\r\n")
	}
	out, err := io.ReadAll(transform.NewReader(&b,
		simplifiedchinese.GBK.NewEncoder()))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func usnRow(usn, name, reasonHex, reasonText, ts string) string {
	return usn + ",\"" + name + "\",22," + reasonHex + ",\"" + reasonText +
		"\",\"" + ts + "\",0x00000080,\"正常\"," +
		"0000000000000000000700000001dc6c,00000000000000000005000000000167," +
		"0x00000000,\"*无*\",0,3,0,104"
}

func TestUSNCSV_Fields(t *testing.T) {
	rows := []string{
		usnRow("50331648", "evil.exe", "0x80000100", "文件创建 | 关闭",
			"2026/7/9 15:15:46"),
		usnRow("50331744", "notes.txt", "0x00002000", "重命名:新名称",
			"2026/7/9 15:15:47"),
	}
	stream, err := UsnCSVParser{}.Records(
		writeTemp(t, "usn_journal_C.csv", buildUSNCSV(t, rows)))
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, stream)
	if len(recs) != 3 { // 2 事件 + 1 summary
		t.Fatalf("记录数不符: %d", len(recs))
	}
	r0 := recs[0]
	if r0.Kind != model.KindEvent || r0.Norm["path"] != "evil.exe" ||
		r0.Norm["reason_hex"] != "0x80000100" || r0.Norm["usn"] != uint64(50331648) {
		t.Fatalf("首行字段不符: %+v", r0.Norm)
	}
	flags, _ := r0.Norm["reason_flags"].([]string)
	joined := ""
	for _, f := range flags {
		joined += f + "|"
	}
	if joined != "FILE_CREATE|CLOSE|" {
		t.Fatalf("原因位解码不符: %v", flags)
	}
	if r0.DTLocal == nil || r0.DTLocal.Year() != 2026 || r0.TsRaw == nil {
		t.Fatalf("本地时间未解出: %+v", r0)
	}
	sum := recs[2].Norm
	if sum["event_type"] != "usn_journal_summary" ||
		sum["journal_id"] != "0x01dd0f6c6dd3e5e3" ||
		sum["valid_rows"] != int64(2) || sum["file_creates"] != int64(1) {
		t.Fatalf("summary 不符: %+v", sum)
	}
}

func TestUSNCSV_BadRowsAndUnknownBits(t *testing.T) {
	rows := []string{
		usnRow("50331648", "evil.exe", "0x40000100", "文件创建", "2026/7/9 15:15:46"),
		"abc,\"x.txt\",22,0x00000100,\"文件创建\",\"2026/7/9 15:15:46\",0x00000080," +
			"\"正常\",f,p,0x00000000,\"*无*\",0,3,0,104", // Usn 非数字 → bad
		usnRow("50331744", "y.txt", "not-a-hex", "?", "2026/7/9 15:15:47"), // 锚点不符 → bad
	}
	stream, err := UsnCSVParser{}.Records(
		writeTemp(t, "usn_journal_D.csv", buildUSNCSV(t, rows)))
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, stream)
	var ev, bad, sumN int
	var sum map[string]any
	for _, r := range recs {
		switch {
		case r.Kind == model.KindBad:
			bad++
		case r.Norm["event_type"] == "usn_journal_summary":
			sumN++
			sum = r.Norm
		default:
			ev++
		}
	}
	if ev != 1 || bad != 2 || sumN != 1 {
		t.Fatalf("事件/坏行/summary 计数不符: ev=%d bad=%d sum=%d", ev, bad, sumN)
	}
	// 未知位如实 UNKNOWN_ 列出
	flags := recs[0].Norm["reason_flags"].([]string)
	found := false
	for _, f := range flags {
		if f == "UNKNOWN_0x40000000" {
			found = true
		}
	}
	if !found {
		t.Fatalf("未知原因位未如实列出: %v", flags)
	}
	if sum["bad_rows"] != int64(2) {
		t.Fatalf("summary bad_rows 不符: %+v", sum)
	}
}

func TestUSNCSV_NoHeader(t *testing.T) {
	stream, err := UsnCSVParser{}.Records(writeTemp(t, "x.csv",
		buildUSNCSV(t, nil))) // 有表头但零数据行 → 文件级如实 failed
	if err != nil {
		return // Records 直接拒也合规
	}
	defer stream.Close()
	for {
		_, ok := stream.Next()
		if !ok {
			break
		}
	}
	if stream.Err() == nil {
		t.Fatal("零有效行应文件级如实 failed,不猜")
	}
}

// ==================== $MFT ====================

// mftFN 造一个 $FN 属性内容。
type mftFN struct {
	parent  uint64
	created uint64
	name    string
	ns      byte
}

// buildMFTRecord 造一条 1024 字节记录(USA fixup 正确落位;corruptUSA=true
// 造 fixup 失配坏记录)。
func buildMFTRecord(flags uint16, si [4]uint64, fn *mftFN, corruptUSA bool) []byte {
	buf := make([]byte, mftRecordSize)
	copy(buf, "FILE")
	binary.LittleEndian.PutUint16(buf[4:], 0x30)  // USA offset
	binary.LittleEndian.PutUint16(buf[6:], 3)     // USA count(2 扇区+1)
	binary.LittleEndian.PutUint16(buf[20:], 0x38) // 首属性偏移
	binary.LittleEndian.PutUint16(buf[22:], flags)
	// USA:sig=0xAAAA,原字节 0x1111/0x2222
	binary.LittleEndian.PutUint16(buf[0x30:], 0xAAAA)
	binary.LittleEndian.PutUint16(buf[0x32:], 0x1111)
	binary.LittleEndian.PutUint16(buf[0x34:], 0x2222)
	if !corruptUSA {
		binary.LittleEndian.PutUint16(buf[510:], 0xAAAA)
		binary.LittleEndian.PutUint16(buf[1022:], 0xAAAA)
	}

	off := 0x38
	// $SI(常驻,48 字节值)
	binary.LittleEndian.PutUint32(buf[off:], mftAttrSI)
	binary.LittleEndian.PutUint32(buf[off+4:], uint32(24+48))
	buf[off+8] = 0 // 常驻
	binary.LittleEndian.PutUint32(buf[off+16:], 48)
	binary.LittleEndian.PutUint16(buf[off+20:], 24)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(buf[off+24+8*i:], si[i])
	}
	off += 24 + 48
	// $FN
	if fn != nil {
		vlen := 66 + len(fn.name)*2
		alen := 24 + vlen
		binary.LittleEndian.PutUint32(buf[off:], mftAttrFN)
		binary.LittleEndian.PutUint32(buf[off+4:], uint32(alen))
		buf[off+8] = 0
		binary.LittleEndian.PutUint32(buf[off+16:], uint32(vlen))
		binary.LittleEndian.PutUint16(buf[off+20:], 24)
		v := buf[off+24:]
		binary.LittleEndian.PutUint64(v[0:], fn.parent)
		binary.LittleEndian.PutUint64(v[8:], fn.created)
		binary.LittleEndian.PutUint64(v[16:], fn.created) // modified 同造
		v[64] = byte(len(fn.name))
		v[65] = fn.ns
		for i, r := range fn.name {
			binary.LittleEndian.PutUint16(v[66+2*i:], uint16(r))
		}
		off += alen
	}
	binary.LittleEndian.PutUint32(buf[off:], mftAttrEnd)
	return buf
}

func TestMFT_TwoPass(t *testing.T) {
	siBase := ft(1577836800) // 2020-01-01T00:00:00Z
	var recs [][]byte
	mk := func(flags uint16, fn *mftFN) []byte {
		return buildMFTRecord(flags, [4]uint64{siBase, siBase, siBase, siBase}, fn, false)
	}
	// 0-4:普通文件(父=根 5)
	for i := 0; i < 5; i++ {
		recs = append(recs, mk(mftFlagInUse, &mftFN{parent: 5, created: siBase,
			name: "f" + string(rune('0'+i)) + ".txt", ns: 3}))
	}
	// 5:根目录「.」(父指自身)
	recs = append(recs, mk(mftFlagInUse|mftFlagDirectory,
		&mftFN{parent: 5, created: siBase, name: ".", ns: 3}))
	// 6:Windows 目录
	recs = append(recs, mk(mftFlagInUse|mftFlagDirectory,
		&mftFN{parent: 5, created: siBase, name: "Windows", ns: 3}))
	// 7:evil.exe,$FN 创建晚 $SI 120s → timestomp 候选
	recs = append(recs, buildMFTRecord(mftFlagInUse,
		[4]uint64{siBase, siBase, siBase, siBase},
		&mftFN{parent: 6, created: siBase + 120*10_000_000, name: "evil.exe", ns: 3},
		false))
	// 8:已删除文件(flags=0)
	recs = append(recs, mk(0, &mftFN{parent: 6, created: siBase, name: "old.log", ns: 3}))
	// 9:坏魔数
	bad := make([]byte, mftRecordSize)
	copy(bad, "BAAD")
	recs = append(recs, bad)
	// 10:fixup 失配
	recs = append(recs, buildMFTRecord(mftFlagInUse,
		[4]uint64{siBase, siBase, siBase, siBase},
		&mftFN{parent: 5, created: siBase, name: "x.txt", ns: 3}, true))
	// 11:孤儿(父 999 越界)
	recs = append(recs, mk(mftFlagInUse,
		&mftFN{parent: 999, created: siBase, name: "orphan.bin", ns: 3}))

	var buf bytes.Buffer
	for _, r := range recs {
		buf.Write(r)
	}
	stream, err := MftParser{}.Records(writeTemp(t, "MFT.bin", buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	out := drain(t, stream)

	var entries, tsCand int
	var summary map[string]any
	var evilPath, orphanPath, rootPath string
	for _, r := range out {
		switch r.Norm["event_type"] {
		case "mft_entry":
			entries++
			switch r.Norm["name"] {
			case "evil.exe":
				evilPath, _ = r.Norm["path"].(string)
			case "orphan.bin":
				orphanPath, _ = r.Norm["path"].(string)
			case ".":
				rootPath, _ = r.Norm["path"].(string)
			}
			if r.Norm["name"] == "old.log" && r.Norm["in_use"] != false {
				t.Fatal("已删除文件 in_use 应为 false")
			}
		case "mft_timestomp_candidate":
			tsCand++
			if r.TsUTCDirect == nil {
				t.Fatal("timestomp 事件 ts 应取 si_created UTC 直通")
			}
		case "mft_summary":
			summary = r.Norm
		}
	}
	if entries != 10 || tsCand != 1 || summary == nil {
		t.Fatalf("记录分布不符: entries=%d ts=%d summary=%v", entries, tsCand, summary != nil)
	}
	if evilPath != `Windows\evil.exe` {
		t.Fatalf("父链路径拼接不符: %q", evilPath)
	}
	if orphanPath != "orphan.bin" {
		t.Fatalf("孤儿应退化为 $FN 名: %q", orphanPath)
	}
	if rootPath != "." {
		t.Fatalf("根记录路径应退化为自身名: %q", rootPath)
	}
	if summary["valid_records"] != int64(10) || summary["bad_records"] != int64(2) ||
		summary["deleted_records"] != int64(1) || summary["directories"] != int64(2) ||
		summary["timestomp_candidates"] != int64(1) ||
		summary["orphan_paths"] != int64(1) {
		t.Fatalf("summary 计数不符: %+v", summary)
	}
}

func TestMFT_Empty(t *testing.T) {
	if _, err := (MftParser{}).Records(writeTemp(t, "MFT.bin", nil)); err == nil {
		t.Fatal("空文件应如实 failed")
	}
	if _, err := (MftParser{}).Records(writeTemp(t, "MFT.bin",
		make([]byte, mftRecordSize))); err == nil {
		t.Fatal("全垃圾记录应如实 failed(零有效 FILE)")
	}
}

// ==================== registry hive ====================

// 合成夹具:Velocidex regparser testdata NTUSER.DAT(Apache-2.0,
// 复制自模块 testdata,见 testdata/parsers/PROVENANCE)。
func TestHive_NTUSER(t *testing.T) {
	stream, err := HiveParser{}.Records("../../testdata/parsers/NTUSER.DAT")
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, stream)
	if len(recs) < 1000 {
		t.Fatalf("NTUSER.DAT 值事件过少(%d),遍历疑似不完整", len(recs))
	}
	var values, bad int
	var sum map[string]any
	softwareKeySeen := false
	for _, r := range recs {
		switch r.Kind {
		case model.KindBad:
			bad++
		default:
			if r.Norm["event_type"] == "registry_hive_summary" {
				sum = r.Norm["summary"].(map[string]any)
				continue
			}
			values++
			kp, _ := r.Norm["key_path"].(string)
			if bytes.Contains([]byte(kp), []byte("Software")) {
				softwareKeySeen = true
			}
			if r.Norm["value_type"] == nil || r.Norm["value_name"] == nil {
				t.Fatalf("值事件缺字段: %+v", r.Norm)
			}
		}
	}
	if !softwareKeySeen {
		t.Fatal("未见到 Software 键路径(遍历缺失)")
	}
	if sum == nil {
		t.Fatal("缺 summary")
	}
	// 汇总对账:values_emitted = 值事件数 + bad 值数(零静默)
	if got, _ := sum["values_emitted"].(int); got != values {
		t.Fatalf("summary values_emitted=%v,实际值事件 %d(对账不符)", got, values)
	}
	if got, _ := sum["bad_values"].(int); got != bad {
		t.Fatalf("summary bad_values=%v,实际 bad %d(对账不符)", got, bad)
	}
	t.Logf("values=%d bad=%d", values, bad)
}

func TestHive_NonHive(t *testing.T) {
	if _, err := (HiveParser{}).Records(
		writeTemp(t, "SAM", []byte("not a hive at all"))); err == nil {
		t.Fatal("非 regf 应文件级如实 failed")
	}
}

// ==================== MFT 内存纪律回归(2026-09-22 OOM 事故后立) ====================

// 伪造「海量目录记录」输入:祖先表被上限截断,超限如实计数,堆增量受控。
func TestMFT_AncestorCapGuard(t *testing.T) {
	oldCap := mftMaxAncestors
	mftMaxAncestors = 1000
	defer func() { mftMaxAncestors = oldCap }()

	const nDirs = 100000 // 100k 目录记录 ≈ 100MB 输入
	siBase := ft(1577836800)
	f, err := os.Create(filepath.Join(t.TempDir(), "MFT.bin"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// 记录 5:根;6..nDirs+4:目录(父=5);尾部再带一个普通文件
	rec := buildMFTRecord(mftFlagInUse|mftFlagDirectory,
		[4]uint64{siBase, siBase, siBase, siBase},
		&mftFN{parent: 5, created: siBase, name: "d", ns: 3}, false)
	// 预写根记录(记录 0-4 填空坏记录槽)
	zeros := make([]byte, mftRecordSize)
	for i := 0; i < 5; i++ {
		if _, err := f.Write(zeros); err != nil {
			t.Fatal(err)
		}
	}
	root := buildMFTRecord(mftFlagInUse|mftFlagDirectory,
		[4]uint64{siBase, siBase, siBase, siBase},
		&mftFN{parent: 5, created: siBase, name: ".", ns: 3}, false)
	if _, err := f.Write(root); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < nDirs; i++ {
		if _, err := f.Write(rec); err != nil {
			t.Fatal(err)
		}
	}
	f.Sync()

	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	stream, err := MftParser{}.Records(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	var summary map[string]any
	for {
		r, ok := stream.Next()
		if !ok {
			break
		}
		if r.Norm["event_type"] == "mft_summary" {
			summary = r.Norm
		}
	}
	stream.Close()
	runtime.GC()
	runtime.ReadMemStats(&m1)

	if summary == nil {
		t.Fatal("缺 summary")
	}
	if got := summary["ancestor_table_entries"]; got != 1000 {
		t.Fatalf("祖先表未被上限截断: %v", got)
	}
	if ov, _ := summary["ancestor_overflow"].(int64); ov <= 0 {
		t.Fatalf("超限未如实计数: %v", ov)
	}
	// 堆增量闸:100MB 输入,工作集必须远小于输入(纪律:内存与文件大小无关)
	delta := int64(m1.HeapAlloc) - int64(m0.HeapAlloc)
	if delta > 64<<20 {
		t.Fatalf("堆增量 %d MB 超 64MB 纪律线(内存与文件大小相关,回归!)",
			delta>>20)
	}
	t.Logf("堆增量 %.1f MB,祖先表 %v 条,溢出 %v", float64(delta)/(1<<20),
		summary["ancestor_table_entries"], summary["ancestor_overflow"])
}

// 伪造「声明巨大记录数」输入(3GB 稀疏文件,全零→全坏):解析如实失败,
// 不整读、不预分配、内存平坦。
func TestMFT_HugeSparseNoAlloc(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过 3GB 稀疏文件用例")
	}
	f, err := os.Create(filepath.Join(t.TempDir(), "MFT.bin"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(3 << 30); err != nil { // 3GB 稀疏(声明 300 万条记录)
		t.Skipf("稀疏文件不可用: %v", err)
	}
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	_, err = MftParser{}.Records(f.Name())
	runtime.GC()
	runtime.ReadMemStats(&m1)
	if err == nil {
		t.Fatal("全零 3GB 输入应如实 failed(零有效 FILE 记录)")
	}
	delta := int64(m1.HeapAlloc) - int64(m0.HeapAlloc)
	if delta > 64<<20 {
		t.Fatalf("3GB 声明输入堆增量 %d MB 超纪律线(预分配回归!)", delta>>20)
	}
	t.Logf("3GB 声明输入:堆增量 %.1f MB,如实失败: %v", float64(delta)/(1<<20), err)
}
