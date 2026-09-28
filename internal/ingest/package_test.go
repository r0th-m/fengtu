// 一案多包主机建模测试(§3 修正稿):两包两主机合成案件——
// 每包独立摄入,主机键从包根目录名提取,同案归并可查。
package ingest

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// mkPackage 造一个最小合法采集包(2 个文本文件,raw 路由)。
func mkPackage(t *testing.T, root, name string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Join(dir, "REG_dumps"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "systeminfo.txt"),
		[]byte("Host Name: X\nOS Name: Y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "REG_dumps", "REG_Run.txt"),
		[]byte("HKEY\\Run\n    A    REG_SZ    B\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestPackage_MultiHost 两包两主机合成案件:各自摄入,主机键各自提取,
// 同案两主机归并可查(sources.host)。
func TestPackage_MultiHost(t *testing.T) {
	m, err := LoadArtifactMap(`
name: t
package_root_regex: ^Forensic_[^_/]+_[^/]+$
host_regex: ^Forensic_(?P<host>[^_/]+)_[^/]+$
rules:
  - match: "*.txt"
    artifact: text_snapshot
    route: raw
`)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	pkgA := mkPackage(t, root, "Forensic_10.0.0.1_alpha")
	pkgB := mkPackage(t, root, "Forensic_10.0.0.2_beta")

	meta := newFakeMeta()
	ev := &fakeEvents{}
	ctx := context.Background()

	repA, err := IngestPackage(ctx, meta, ev, PackageSpec{
		CaseName: "case-multi", Root: pkgA, Map: m})
	if err != nil {
		t.Fatalf("包 A 摄入失败: %v", err)
	}
	repB, err := IngestPackage(ctx, meta, ev, PackageSpec{
		CaseName: "case-multi", Root: pkgB, Map: m})
	if err != nil {
		t.Fatalf("包 B 摄入失败: %v", err)
	}
	if repA.Host != "10.0.0.1" || repB.Host != "10.0.0.2" {
		t.Fatalf("主机键提取错误: A=%q B=%q", repA.Host, repB.Host)
	}
	if repA.Package != "Forensic_10.0.0.1_alpha" || repB.Package != "Forensic_10.0.0.2_beta" {
		t.Fatalf("登记根名错误: A=%q B=%q", repA.Package, repB.Package)
	}
	// 同案 4 源,主机/包键各归各
	if len(meta.sources) != 4 {
		t.Fatalf("源数不符: %d", len(meta.sources))
	}
	hosts := map[string]int{}
	for _, s := range meta.sources {
		if s.CaseID != "case-multi" && meta.cases["case-multi"] != s.CaseID {
			t.Fatalf("源案件归属错误: %+v", s)
		}
		hosts[s.Host]++
		if s.Package == "" {
			t.Fatalf("包内源 package 键不应为空: %+v", s)
		}
	}
	if len(hosts) != 2 || hosts["10.0.0.1"] != 2 || hosts["10.0.0.2"] != 2 {
		t.Fatalf("主机归并不符: %v", hosts)
	}
}

// TestPackage_DisplayRootSuffix 同一主机二次采包:DisplayRoot 带 #N
// 后缀登记(调用方决策),主机键仍从真实包名提取(归并不受影响)。
func TestPackage_DisplayRootSuffix(t *testing.T) {
	m, err := LoadArtifactMap(`
name: t
package_root_regex: ^Forensic_[^_/]+_[^/]+$
host_regex: ^Forensic_(?P<host>[^_/]+)_[^/]+$
rules:
  - match: "*.txt"
    artifact: text_snapshot
    route: raw
`)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	pkg := mkPackage(t, root, "Forensic_10.0.0.1_alpha")
	meta := newFakeMeta()
	ctx := context.Background()

	rep, err := IngestPackage(ctx, meta, &fakeEvents{}, PackageSpec{
		CaseName: "c", Root: pkg, Map: m, DisplayRoot: "Forensic_10.0.0.1_alpha#2"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Package != "Forensic_10.0.0.1_alpha#2" {
		t.Fatalf("登记根名未带后缀: %q", rep.Package)
	}
	if rep.Host != "10.0.0.1" {
		t.Fatalf("主机键应从真实包名提取: %q", rep.Host)
	}
	for _, s := range meta.sources {
		if s.Package != "Forensic_10.0.0.1_alpha#2" || s.Host != "10.0.0.1" {
			t.Fatalf("源主机/包键不符: %+v", s)
		}
	}
}

// TestPackageTimezone LinuxSC 包级时区自动推导(0.32.0-linuxsc):
// _COLLECTION_TIME.txt 的 Timezone=<IANA> 行 → 包级 TZDeclared;
// 无此行/文件缺失 → 空串(不猜);用户显式指定优先(不覆盖)。
func TestPackageTimezone(t *testing.T) {
	root := t.TempDir()
	// LinuxSC 形态
	if err := os.WriteFile(filepath.Join(root, "_COLLECTION_TIME.txt"),
		[]byte("LinuxSC Collection Started: 2026/07/28 星期二 17:25:28\nTimezone=Asia/Beijing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if tz := packageTimezone(root); tz != "Asia/Beijing" {
		t.Fatalf("Timezone 行提取错误: %q", tz)
	}
	// WinInfoSC 形态(w32tm 中文输出,无 Timezone= 键)→ 空串
	root2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(root2, "_COLLECTION_TIME.txt"),
		[]byte("WinInfoSC Collection Started: 2026/07/25 13:29:56\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if tz := packageTimezone(root2); tz != "" {
		t.Fatalf("无 Timezone 键应得空串: %q", tz)
	}
	// 文件缺失 → 空串
	if tz := packageTimezone(t.TempDir()); tz != "" {
		t.Fatalf("文件缺失应得空串: %q", tz)
	}
}
