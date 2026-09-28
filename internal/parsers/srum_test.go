// SRUM 解析器测试:解码助手(OA 时间/SID/IdBlob)合成正负样本 +
// 非 ESE 文件级失败。
//
// 说明:ESE 数据库无法手工合成(页结构/目录 B 树),故流式路径
// (go-ese DumpTable → 事件)用真实样本开发期人工抽查背书(数字见
// 内部台账),不进仓库;此处焊死全部可合成面:
// 解码纯函数逐分支 + 打开期结构校验 + 大输入打开失败内存平坦。
package parsers

import (
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// oaBits OA 天数 → TimeStamp 列 int64 位模式。
func oaBits(days float64) uint64 { return math.Float64bits(days) }

func TestSRUM_OATimestamp(t *testing.T) {
	// 正样本:2020-01-01T00:00:00Z = unix 1577836800 → OA 43831.0
	ts, ok := srumOAToUTC(oaBits(43831.0))
	if !ok || ts.Format(srumISO) != "2020-01-01T00:00:00Z" {
		t.Fatalf("OA 43831.0 解码不符: %v ok=%v", ts, ok)
	}
	// 小数天:43831.5 → 2020-01-01T12:00:00Z
	ts, ok = srumOAToUTC(oaBits(43831.5))
	if !ok || ts.Format(srumISO) != "2020-01-01T12:00:00Z" {
		t.Fatalf("OA 43831.5 解码不符: %v ok=%v", ts, ok)
	}
	// 窗边界:36526(2000-01-01)/73050(2100-01-01)恰好合法
	if _, ok := srumOAToUTC(oaBits(36526.0)); !ok {
		t.Fatal("窗下界 36526 应合法")
	}
	if _, ok := srumOAToUTC(oaBits(73050.0)); !ok {
		t.Fatal("窗上界 73050 应合法")
	}
	// 负样本:越窗/0/NaN/负天数 → 不猜
	for _, bits := range []uint64{
		oaBits(36525.999), oaBits(73050.001), oaBits(0),
		math.Float64bits(math.NaN()), oaBits(-1),
	} {
		if _, ok := srumOAToUTC(bits); ok {
			t.Fatalf("越窗 OA 位模式 %#x 应判非法,不猜", bits)
		}
	}
}

func TestSRUM_SIDString(t *testing.T) {
	// S-1-5-18:rev=1,子机构数=1,颁发机构=5,子机构=18
	blob := []byte{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}
	s, ok := srumSIDToString(blob)
	if !ok || s != "S-1-5-18" {
		t.Fatalf("SID 解码不符: %q ok=%v", s, ok)
	}
	// S-1-5-21-1000-2000(多子机构)
	blob = []byte{1, 3, 0, 0, 0, 0, 0, 5,
		21, 0, 0, 0, 0xE8, 0x03, 0, 0, 0xD0, 0x07, 0, 0}
	s, ok = srumSIDToString(blob)
	if !ok || s != "S-1-5-21-1000-2000" {
		t.Fatalf("多子机构 SID 解码不符: %q ok=%v", s, ok)
	}
	// 零子机构 → S-1-5
	s, ok = srumSIDToString([]byte{1, 0, 0, 0, 0, 0, 0, 5})
	if !ok || s != "S-1-5" {
		t.Fatalf("零子机构 SID 解码不符: %q ok=%v", s, ok)
	}
	// 负样本:长度不足 / rev≠1 / 子机构截断 → 不猜
	if _, ok := srumSIDToString([]byte{1, 1, 0}); ok {
		t.Fatal("长度不足应判非法")
	}
	if _, ok := srumSIDToString([]byte{2, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}); ok {
		t.Fatal("rev≠1 应判非法")
	}
	if _, ok := srumSIDToString([]byte{1, 2, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}); ok {
		t.Fatal("子机构截断应判非法")
	}
}

func TestSRUM_IDBlob(t *testing.T) {
	// IdType 1:UTF-16LE 串去尾 NUL
	blob := append(utf16Bytes("svchost.exe"), 0, 0)
	name, ok := srumDecodeIDBlob(1, blob)
	if !ok || name != "svchost.exe" {
		t.Fatalf("IdBlob 字符串解码不符: %q ok=%v", name, ok)
	}
	// IdType 0 同走 UTF-16 路径
	name, ok = srumDecodeIDBlob(0, blob)
	if !ok || name != "svchost.exe" {
		t.Fatalf("IdType 0 解码不符: %q ok=%v", name, ok)
	}
	// 奇数尾字节 → U+FFFD(errors="replace" 同语义)
	odd := append(utf16Bytes("ab"), 0xff)
	name, ok = srumDecodeIDBlob(1, odd)
	if !ok || name != "ab" {
		t.Fatalf("奇数长 IdBlob 解码不符: %q ok=%v", name, ok)
	}
	// IdType 3:二进制 SID
	name, ok = srumDecodeIDBlob(3,
		[]byte{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0})
	if !ok || name != "S-1-5-18" {
		t.Fatalf("IdBlob SID 解码不符: %q ok=%v", name, ok)
	}
	// IdType 3 结构不合法 → 不映射(不猜)
	if _, ok := srumDecodeIDBlob(3,
		[]byte{2, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}); ok {
		t.Fatal("坏 SID 结构应判 false")
	}
	// blob 缺失 → false
	if _, ok := srumDecodeIDBlob(1, nil); ok {
		t.Fatal("blob 缺失应判 false")
	}
	// 文本列原值(树庭 isinstance str 分支)→ 透传
	name, ok = srumDecodeIDBlob(1, "plain-text-name")
	if !ok || name != "plain-text-name" {
		t.Fatalf("文本透传不符: %q ok=%v", name, ok)
	}
	// 空 blob → 空串仍映射(树庭 "" is not None)
	name, ok = srumDecodeIDBlob(1, []byte{})
	if !ok || name != "" {
		t.Fatalf("空 blob 应映射为空串: %q ok=%v", name, ok)
	}
}

// utf16Bytes 测试助手:ASCII 串 → UTF-16LE 字节。
func utf16Bytes(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func TestSRUM_TaggedValues(t *testing.T) {
	// go-ese catalog.go 注释中的 spec 样例:tag 0x100(flag=1,首字节
	// 跳过)/0x1a4/0x1a5
	buf := []byte{0x00, 0x01, 0x0c, 0x40, 0xa4, 0x01, 0x21, 0x00,
		0xa5, 0x01, 0x23, 0x00, 0x01, 0x6c, 0x00, 0x61,
		0x00, 0x62, 0x00, 0x5c, 0x00, 0x64, 0x00, 0x63,
		0x00, 0x2d, 0x00, 0x31, 0x00, 0x24, 0x00, 0x00,
		0x00, 0x3d, 0x00, 0xf9, 0x00}
	got := srumParseTaggedValues(buf)
	if len(got) != 3 {
		t.Fatalf("tag 数不符: %v", got)
	}
	// tag 0x100:flags=1 → 数据 [0x0d:0x21)
	if v := got[0x100]; len(v) != 0x21-0x0d || v[0] != 0x6c {
		t.Fatalf("tag 0x100 不符: %x", v)
	}
	// tag 0x1a4:[0x21:0x23);0x1a5:[0x23:尾)
	if v := got[0x1a4]; len(v) != 2 {
		t.Fatalf("tag 0x1a4 不符: %x", v)
	}
	if v := got[0x1a5]; len(v) != len(buf)-0x23 {
		t.Fatalf("tag 0x1a5 不符: %x", v)
	}
	// 负样本:缓冲过短/tag 数组头损坏/条目偏移回退 → 不 panic,丢弃不猜
	if g := srumParseTaggedValues([]byte{0x01, 0x02}); len(g) != 0 {
		t.Fatal("过短缓冲应得空表")
	}
	// firstData 越界
	bad := []byte{0x00, 0x01, 0xff, 0x1f, 0x00, 0x00, 0x00, 0x00}
	if g := srumParseTaggedValues(bad); len(g) != 0 {
		t.Fatal("tag 数组头越界应得空表")
	}
	// 偏移回退(第二条 start < 前一条 start)→ 回退条目丢弃
	rev := []byte{0x00, 0x01, 0x10, 0x00, 0xa4, 0x01, 0x08, 0x00,
		0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x00,
		0x11, 0x22}
	g := srumParseTaggedValues(rev)
	if _, has := g[0x1a4]; has {
		t.Fatal("偏移回退条目应丢弃")
	}
}

func TestSRUM_NonESE(t *testing.T) {
	// 非 ESE 头 → 文件级如实 failed
	if _, err := (SrumParser{}).Records(writeTemp(t, "SRUDB.dat",
		[]byte("this is definitely not an ESE database file, just garbage bytes"))); err == nil {
		t.Fatal("非 ESE 头应文件级如实 failed")
	}
	// 空文件 → 文件级如实 failed
	if _, err := (SrumParser{}).Records(writeTemp(t, "SRUDB.dat", nil)); err == nil {
		t.Fatal("空文件应文件级如实 failed")
	}
	// 不存在的路径 → 文件级如实 failed
	if _, err := (SrumParser{}).Records(
		filepath.Join(t.TempDir(), "nope.dat")); err == nil {
		t.Fatal("不存在路径应如实 failed")
	}
}

// 内存纪律:ESE 无法手工合成,大输入用例覆盖「超大非 ESE 文件打开即败」
// 路径内存平坦;流式路径的 64MB 纪律由真实样本开发期实测背书
// (79MB 库堆增量实测)。
func TestSRUM_HugeNonESEFlat(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过大输入用例")
	}
	f, err := os.Create(filepath.Join(t.TempDir(), "SRUDB.dat"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(512 << 20); err != nil { // 512MB 稀疏
		t.Skipf("稀疏文件不可用: %v", err)
	}
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	_, err = SrumParser{}.Records(f.Name())
	runtime.GC()
	runtime.ReadMemStats(&m1)
	if err == nil {
		t.Fatal("全零 512MB 输入应如实 failed(非 ESE 头)")
	}
	delta := int64(m1.HeapAlloc) - int64(m0.HeapAlloc)
	if delta > 64<<20 {
		t.Fatalf("512MB 输入打开失败路径堆增量 %d MB 超纪律线(整读回归!)",
			delta>>20)
	}
	t.Logf("512MB 非 ESE 输入:堆增量 %.1f MB,如实失败: %v",
		float64(delta)/(1<<20), err)
}

// 编译期契约钉住:SrumParser 实现 Parser。
var _ Parser = SrumParser{}

// 钉住时间助手与共享 FiletimeToUTC 的一致性(FILETIME 路径回归):
// ConnectStartTime 走 FiletimeToUTC,与 efu/mft 同一实现。
func TestSRUM_FiletimeConsistency(t *testing.T) {
	ftv := ft(1600000000) // 2020-09-13T12:26:40Z
	ts, ok := FiletimeToUTC(ftv)
	if !ok || ts.Format(srumISO) != "2020-09-13T12:26:40Z" {
		t.Fatalf("FILETIME 解码不符: %v ok=%v", ts, ok)
	}
	if !ts.Equal(time.Unix(1600000000, 0).UTC()) {
		t.Fatalf("TsUTCDirect 语义不符: %v", ts)
	}
}
