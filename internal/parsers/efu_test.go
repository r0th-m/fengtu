// EFU 解析器合成样本测试 + 内存纪律回归。
package parsers

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// buildEFU 造 EFU 内容(UTF-8,带 BOM;rows 为数据行)。
func buildEFU(rows []string) []byte {
	var b strings.Builder
	b.WriteString("\xEF\xBB\xBF\"Filename\",\"Size\",\"Date Modified\",\"Date Created\",\"Attributes\"\r\n") // UTF-8 BOM
	for _, r := range rows {
		b.WriteString(r + "\r\n")
	}
	return []byte(b.String())
}

func TestEFU_Fields(t *testing.T) {
	mod := ft(1600000000) // 2020-09-13T12:26:40Z
	cre := ft(1590000000)
	rows := []string{
		fmt.Sprintf(`"C:\Tools\evil.exe",12345,%d,%d,32`, mod, cre),
		fmt.Sprintf(`"C:\Docs\readme.txt",,%d,,16`, mod), // 无创建时间
		`"D:\dir1",,,,16`,    // 目录:无大小
		`"C:\noext",10,,,32`, // 无扩展名
	}
	stream, err := EfuParser{}.Records(writeTemp(t, "everything.efu", buildEFU(rows)))
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, stream)
	if len(recs) != 5 { // 4 行级 + 1 summary
		t.Fatalf("记录数不符: %d", len(recs))
	}
	r0 := recs[0]
	if r0.Kind != model.KindEvent ||
		r0.Norm["event_type"] != "file_listing_entry" ||
		r0.Norm["path"] != `C:\Tools\evil.exe` ||
		r0.Norm["filename"] != "evil.exe" ||
		r0.Norm["extension"] != "exe" ||
		r0.Norm["size_bytes"] != int64(12345) {
		t.Fatalf("首行字段不符: %+v", r0.Norm)
	}
	if r0.Norm["date_modified_utc"] != "2020-09-13T12:26:40Z" ||
		r0.Norm["date_created_utc"] == nil {
		t.Fatalf("时间字段不符: %+v", r0.Norm)
	}
	if r0.TsUTCDirect == nil ||
		!r0.TsUTCDirect.Equal(time.Unix(1600000000, 0).UTC()) {
		t.Fatalf("TsUTCDirect 不符: %v", r0.TsUTCDirect)
	}
	// 目录行:size_bytes 缺省不猜
	if _, has := recs[2].Norm["size_bytes"]; has {
		t.Fatalf("目录行不应有 size_bytes: %+v", recs[2].Norm)
	}
	// 无扩展名行:extension 缺省
	if _, has := recs[3].Norm["extension"]; has {
		t.Fatalf("无扩展名行不应有 extension: %+v", recs[3].Norm)
	}
	sum := recs[4].Norm["summary"].(map[string]any)
	if recs[4].Norm["event_type"] != "file_listing_summary" ||
		sum["total_rows"] != int64(4) || sum["bad_rows"] != int64(0) {
		t.Fatalf("summary 不符: %+v", sum)
	}
}

func TestEFU_BadRowsAndNegative(t *testing.T) {
	// 字段数不齐 → bad 计数,行内有路径仍照出;无路径行跳过
	rows := []string{
		`"C:\a.exe",1,133000000000000000,133000000000000000,32,EXTRA`,
		`"C:\b.exe",2`, // 缺列
		`,,,`,          // 无路径
	}
	stream, err := EfuParser{}.Records(writeTemp(t, "x.efu", buildEFU(rows)))
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, stream)
	var entries int
	var sum map[string]any
	for _, r := range recs {
		if r.Norm["event_type"] == "file_listing_entry" {
			entries++
		} else {
			sum = r.Norm["summary"].(map[string]any)
		}
	}
	if entries != 2 {
		t.Fatalf("行级事件数不符(无路径行应跳过): %d", entries)
	}
	if sum["total_rows"] != int64(3) || sum["bad_rows"] != int64(3) {
		t.Fatalf("bad 计数不符: %+v", sum)
	}
	// 无表头 → 文件级 failed
	if _, err := (EfuParser{}).Records(writeTemp(t, "bad.efu",
		[]byte("hello,world\r\n1,2\r\n"))); err == nil {
		t.Fatal("无 filename 列应文件级如实 failed")
	}
	// 空文件 → 文件级 failed
	if _, err := (EfuParser{}).Records(writeTemp(t, "empty.efu", nil)); err == nil {
		t.Fatal("空文件应文件级如实 failed")
	}
}

// 内存纪律:超大合成 EFU(约 200MB 逻辑行)流式解析,堆增量 << 64MB。
func TestEFU_MemoryFlat(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过大输入内存用例")
	}
	f, err := os.Create(filepath.Join(t.TempDir(), "big.efu"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.WriteString("\"Filename\",\"Size\",\"Date Modified\",\"Date Created\",\"Attributes\"\r\n")
	row := fmt.Sprintf(`"C:\very\deep\directory\structure\with\a\long\path\file_%d.exe",12345,133000000000000000,133000000000000000,32`, 0) + "\r\n"
	const target = 200 << 20 // 200MB 输入
	written := 0
	buf := strings.Repeat(row, 1000)
	for written < target {
		n, _ := f.WriteString(buf)
		written += n
	}
	f.Sync()

	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	stream, err := EfuParser{}.Records(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for {
		rec, ok := stream.Next()
		if !ok {
			break
		}
		if rec.Norm["event_type"] == "file_listing_summary" {
			total = rec.Norm["summary"].(map[string]any)["total_rows"].(int64)
		}
	}
	stream.Close()
	runtime.GC()
	runtime.ReadMemStats(&m1)
	delta := int64(m1.HeapAlloc) - int64(m0.HeapAlloc)
	if delta > 64<<20 {
		t.Fatalf("200MB 输入堆增量 %d MB 超 64MB 纪律线(流式回归!)", delta>>20)
	}
	t.Logf("200MB EFU:total_rows=%d,堆增量 %.1f MB", total, float64(delta)/(1<<20))
}
