// M3 树庭面原生解析路由的接线测试:映射表 rule → native 解析器 →
// 统一管线落库(kind=native、parser label、log_type 随行)。
package ingest

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/ye-mengwen/fengtu/internal/parsers"
)

// 造一个最小 V23 .pf(0x98 次数,0x80 时间;与 parsers 包测试同款布局)。
func writeTestPF(t *testing.T, dir string) string {
	t.Helper()
	buf := make([]byte, 0x200)
	binary.LittleEndian.PutUint32(buf[0:], 23)
	copy(buf[4:], "SCCA")
	binary.LittleEndian.PutUint32(buf[0x0C:], uint32(len(buf)))
	name := []rune("T.EXE")
	for i, r := range name {
		binary.LittleEndian.PutUint16(buf[0x10+2*i:], uint16(r))
	}
	binary.LittleEndian.PutUint32(buf[0x98:], 3)
	binary.LittleEndian.PutUint64(buf[0x80:], (1600000000+11644473600)*10_000_000)
	p := filepath.Join(dir, "T.EXE-12345678.pf")
	if err := os.WriteFile(p, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIngestNativeFile_Prefetch(t *testing.T) {
	meta, events := newFakeMeta(), &fakeEvents{}
	pfPath := writeTestPF(t, t.TempDir())
	spec := Spec{CaseName: "c1", Path: pfPath, Kind: KindNative,
		ParserLabel: "native:prefetch", Workers: 2, BatchRows: 10}
	p, err := parsers.For("prefetch")
	if err != nil {
		t.Fatal(err)
	}
	st, err := IngestNativeFile(context.Background(), meta, events, spec, p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Events != 1 || st.Bad != 0 {
		t.Fatalf("账不符: %+v", st)
	}
	src := meta.sources[0]
	if src.Kind != KindNative {
		t.Fatalf("源类别应为 native: %q", src.Kind)
	}
	_ = events
}

// TestMapping_NativeRouteValidation 映射表 native 规则的装载校验。
func TestMapping_NativeRouteValidation(t *testing.T) {
	// route=native 缺 parser → 拒载
	_, err := LoadArtifactMap(`
name: t
package_root_regex: ^Forensic_
rules:
  - match: "*.pf"
    artifact: prefetch
    route: native
`)
	if err == nil {
		t.Fatal("route=native 缺 parser 应拒载")
	}
	// log_type 不在词表 → 拒载
	_, err = LoadArtifactMap(`
name: t
package_root_regex: ^Forensic_
rules:
  - match: "*.csv"
    artifact: usn_journal
    route: native
    parser: usn_csv
    log_type: nope_not_a_type
`)
	if err == nil {
		t.Fatal("未知 log_type 应拒载")
	}
	// 正样本:usn_journal 词表已注册
	m, err := LoadArtifactMap(`
name: t
package_root_regex: ^Forensic_
rules:
  - match: "usn_journal_*.csv"
    artifact: usn_journal
    route: native
    parser: usn_csv
    log_type: usn_journal
`)
	if err != nil {
		t.Fatal(err)
	}
	r := m.Match("usn_journal_C.csv")
	if r == nil || r.Parser != "usn_csv" || r.LogType != "usn_journal" {
		t.Fatalf("usn 规则不符: %+v", r)
	}
}
