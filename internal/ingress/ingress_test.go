// ingress 焊死:分块上传(齐块/越界/逐块校验/续传幂等/大小不符)、
// zip 展开(单层/嵌套跳过/zip slip 拒绝/GBK 条目名)、清单对账正负样本。
package ingress

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
)

func shaOfBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestUploadChunkRoundTrip(t *testing.T) {
	m, err := OpenManager(filepath.Join(t.TempDir(), "up"), 8)
	if err != nil {
		t.Fatalf("管理器打开失败: %v", err)
	}
	content := []byte("0123456789abcdefghij") // 20 字节 = 2 整块 + 4 字节末块
	meta, err := m.Init("case-a", "access.log", int64(len(content)),
		shaOfBytes(content), "nginx_combined", "", "", "alice")
	if err != nil {
		t.Fatalf("Init 失败: %v", err)
	}
	// 乱序传块(续传场景)
	if err := m.PutChunk(meta.ID, 1, bytes.NewReader(content[8:16]), ""); err != nil {
		t.Fatalf("块 1 失败: %v", err)
	}
	if err := m.PutChunk(meta.ID, 0, bytes.NewReader(content[:8]),
		shaOfBytes(content[:8])); err != nil {
		t.Fatalf("块 0(带逐块校验)失败: %v", err)
	}
	// 缺块不能 complete
	if _, _, _, err := m.Complete(meta.ID); err == nil {
		t.Fatal("缺块应拒 complete")
	}
	// 续传账:已收 0、1
	_, got, err := m.Status(meta.ID)
	if err != nil || len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("续传账不符: %v %v", got, err)
	}
	// 大小不符拒收
	if err := m.PutChunk(meta.ID, 2, bytes.NewReader(content[16:18]), ""); err == nil {
		t.Fatal("末块大小不符应拒")
	}
	// 逐块校验不过拒收
	if err := m.PutChunk(meta.ID, 2, bytes.NewReader(content[16:]),
		strings.Repeat("ab", 32)); err == nil {
		t.Fatal("逐块校验不过应拒")
	}
	if err := m.PutChunk(meta.ID, 2, bytes.NewReader(content[16:]), ""); err != nil {
		t.Fatalf("末块失败: %v", err)
	}
	// 越界块
	if err := m.PutChunk(meta.ID, 3, bytes.NewReader(content[:8]), ""); err == nil {
		t.Fatal("分块序号越界应拒")
	}

	gotMeta, rc, cleanup, err := m.Complete(meta.ID)
	if err != nil {
		t.Fatalf("Complete 失败: %v", err)
	}
	defer cleanup()
	assembled, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("拼接读失败: %v", err)
	}
	if !bytes.Equal(assembled, content) {
		t.Fatalf("拼接内容不符: %q", assembled)
	}
	if gotMeta.Filename != "access.log" || gotMeta.Actor != "alice" {
		t.Fatalf("账不符: %+v", gotMeta)
	}
	cleanup()
	if _, err := os.Stat(m.dirOf(meta.ID)); !os.IsNotExist(err) {
		t.Fatal("cleanup 后暂存目录应清除")
	}
}

func TestUploadInitNegative(t *testing.T) {
	m, _ := OpenManager(filepath.Join(t.TempDir(), "up"), 8)
	sum := strings.Repeat("ab", 32)
	bad := []struct{ caseName, filename, sha string; size int64 }{
		{"", "a.log", sum, 10},                       // 缺案件名
		{"c", "../evil.log", sum, 10},                // 路径注入
		{"c", `..\evil.log`, sum, 10},                // Windows 路径注入
		{"c", "a.log", "xyz", 10},                    // 非法 sha256
		{"c", "a.log", sum, 0},                       // 空文件
	}
	for i, b := range bad {
		if _, err := m.Init(b.caseName, b.filename, b.size, b.sha, "", "", "", "u"); err == nil {
			t.Fatalf("负样本 #%d 应拒: %+v", i, b)
		}
	}
	if _, err := m.Init("c", "a.log", 10, sum, "nginx_combined", "some-desc", "", "u"); err == nil {
		t.Fatal("format 与 desc 二选一")
	}
}

// buildZip 造测试 zip(entries: 名 → 内容;nameRaw=true 时条目名直写原始字节)。
func buildZip(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "t.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("zip 创建失败: %v", err)
	}
	zw := zip.NewWriter(f)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip 条目创建失败: %v", err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatalf("zip 条目写入失败: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip 收尾失败: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("zip 关闭失败: %v", err)
	}
	return p
}

func TestExpandZipFilesMode(t *testing.T) {
	z := buildZip(t, map[string][]byte{
		"a.log":        []byte("aaa"),
		"sub/b.log":    []byte("bbb"),
		"nested.zip":   []byte("PK fake"),
		"sub/evil.zip": []byte("PK fake2"),
	})
	exp, err := ExpandZip(z, filepath.Join(t.TempDir(), "x"),
		func(string) bool { return false })
	if err != nil {
		t.Fatalf("展开失败: %v", err)
	}
	if exp.Mode != "files" {
		t.Fatalf("应为文件模式: %s", exp.Mode)
	}
	if len(exp.Files) != 2 {
		t.Fatalf("应展 2 个文件: %d", len(exp.Files))
	}
	if len(exp.Skipped) != 2 {
		t.Fatalf("嵌套 zip 应跳过如实记: %v", exp.Skipped)
	}
	for _, ef := range exp.Files {
		if ef.SHA256 == "" || ef.Size <= 0 {
			t.Fatalf("展开文件缺哈希/大小账: %+v", ef)
		}
	}
}

func TestExpandZipSlipRejected(t *testing.T) {
	z := buildZip(t, map[string][]byte{
		"../escape.txt": []byte("evil"),
	})
	if _, err := ExpandZip(z, filepath.Join(t.TempDir(), "x"),
		func(string) bool { return false }); err == nil {
		t.Fatal("zip slip 应整包拒绝")
	}
}

func TestExpandZipPackageModeWithManifest(t *testing.T) {
	root := "Forensic_10.0.0.1_TESTHOST"
	fileA := []byte("content-a")
	fileB := []byte("content-b")
	manifest := fmt.Sprintf(
		"WinInfoSC Forensic Collection - SHA256 Manifest\n"+
			"Host=TESTHOST IP=10.0.0.1 Generated=2026/01/01 00:00:00\n"+
			"================================================\n"+
			"%s  C:\\collect\\%s\\a.txt\n"+
			"%s  C:\\collect\\%s\\sub\\b.txt\n",
		shaOfBytes(fileA), root, shaOfBytes(fileB), root)
	z := buildZip(t, map[string][]byte{
		root + "/_HASH_MANIFEST.txt": []byte(manifest),
		root + "/a.txt":              fileA,
		root + "/sub/b.txt":          fileB,
	})
	exp, err := ExpandZip(z, filepath.Join(t.TempDir(), "x"),
		func(name string) bool { return strings.HasPrefix(name, "Forensic_") })
	if err != nil {
		t.Fatalf("包模式展开失败: %v", err)
	}
	if exp.Mode != "package" || exp.PackageName != root {
		t.Fatalf("应为包模式: %+v", exp)
	}
	if exp.Manifest == nil || !exp.Manifest.Present {
		t.Fatal("应有清单报告")
	}
	if !exp.Manifest.Pass() {
		t.Fatalf("清单应通过: %+v", exp.Manifest)
	}
	if exp.Manifest.OK != 2 || exp.Manifest.Entries != 2 {
		t.Fatalf("清单账不符: %+v", exp.Manifest)
	}
}

func TestVerifyManifestMismatchAndMissing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Forensic_10.0.0.1_TESTHOST")
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	fileA := []byte("content-a")
	if err := os.WriteFile(filepath.Join(root, "a.txt"), fileA, 0o644); err != nil {
		t.Fatal(err)
	}
	// b.txt 内容被改(mismatch);c.txt 清单有盘上无(missing);extra.txt 盘上多出(extra)
	if err := os.WriteFile(filepath.Join(root, "sub", "b.txt"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "extra.txt"), []byte("late-footprint"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf(
		"%s  C:\\collect\\Forensic_10.0.0.1_TESTHOST\\a.txt\n"+
			"%s  C:\\collect\\Forensic_10.0.0.1_TESTHOST\\sub\\b.txt\n"+
			"%s  C:\\collect\\Forensic_10.0.0.1_TESTHOST\\c.txt\n",
		shaOfBytes(fileA), shaOfBytes([]byte("original-b")),
		shaOfBytes([]byte("ghost-c")))
	if err := os.WriteFile(filepath.Join(root, "_HASH_MANIFEST.txt"),
		[]byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := VerifyManifest(root)
	if err != nil {
		t.Fatalf("清单对账失败: %v", err)
	}
	if rep.Pass() {
		t.Fatalf("有 mismatch/missing 应判负: %+v", rep)
	}
	if len(rep.Mismatch) != 1 || rep.Mismatch[0] != "sub/b.txt" {
		t.Fatalf("mismatch 账不符: %+v", rep)
	}
	if len(rep.Missing) != 1 || rep.Missing[0] != "c.txt" {
		t.Fatalf("missing 账不符: %+v", rep)
	}
	if rep.Extra != 1 {
		t.Fatalf("extra 账不符(多出文件如实计数不判负): %+v", rep)
	}
	if rep.OK != 1 {
		t.Fatalf("ok 账不符: %+v", rep)
	}
}

func TestVerifyManifestGBKNames(t *testing.T) {
	// 清单与盘上文件名均为 GBK 编码的中文(中文 Windows 采集常态)
	root := filepath.Join(t.TempDir(), "Forensic_10.0.0.1_TESTHOST")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	gbkName, err := simplifiedchinese.GBK.NewEncoder().String("用户目录.txt")
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("gbk-named-file")
	// 盘上文件名按 UTF-8(zip 条目 GBK → decodeEntryName 还原为 UTF-8,
	// 落盘是 UTF-8 名);清单行路径是 GBK 字节 → decodeManifestText 还原。
	if err := os.WriteFile(filepath.Join(root, "用户目录.txt"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	manifestLine := fmt.Sprintf("%s  C:\\collect\\Forensic_10.0.0.1_TESTHOST\\%s\n",
		shaOfBytes(content), gbkName)
	if err := os.WriteFile(filepath.Join(root, "_HASH_MANIFEST.txt"),
		[]byte(manifestLine), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := VerifyManifest(root)
	if err != nil {
		t.Fatalf("清单对账失败: %v", err)
	}
	if !rep.Pass() || rep.OK != 1 {
		t.Fatalf("GBK 文件名应对账通过: %+v", rep)
	}
}

func TestExpandZipNoManifestIsHonest(t *testing.T) {
	root := "Forensic_10.0.0.1_TESTHOST"
	z := buildZip(t, map[string][]byte{
		root + "/a.txt": []byte("x"),
	})
	exp, err := ExpandZip(z, filepath.Join(t.TempDir(), "x"),
		func(name string) bool { return strings.HasPrefix(name, "Forensic_") })
	if err != nil {
		t.Fatalf("展开失败: %v", err)
	}
	if exp.Manifest == nil || exp.Manifest.Present {
		t.Fatalf("无清单应如实记 Present=false: %+v", exp.Manifest)
	}
	if !exp.Manifest.Pass() {
		t.Fatal("无清单不判负(老包放行,如实记)")
	}
}

func TestVerifyManifestDefaultNoHash(t *testing.T) {
	// WinInfoSC 默认档(2026-09-26 起):采集时不逐文件哈希,清单只写
	// 「Mode=DEFAULT_NO_HASH」声明——无可对账条目,如实记 NoHash 放行,
	// 完整性哈希由平台入库时计算;声明段中/英说明行不计坏行。
	root := filepath.Join(t.TempDir(), "Forensic_10.0.0.1_TESTHOST")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := "WinInfoSC Forensic Collection - Integrity Manifest\n" +
		"Host=TESTHOST IP=10.0.0.1 Generated=2026/09/26 00:00:00\n" +
		"Mode=DEFAULT_NO_HASH\n" +
		"================================================\n" +
		"[NOT HASHED AT COLLECTION TIME - default mode]\n" +
		"File integrity SHA256 is computed by the analysis platform at ingest.\n" +
		"Custody between collection and ingest is the collector's responsibility.\n"
	if err := os.WriteFile(filepath.Join(root, "_HASH_MANIFEST.txt"),
		[]byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := VerifyManifest(root)
	if err != nil {
		t.Fatalf("清单对账失败: %v", err)
	}
	if !rep.Present || !rep.NoHash {
		t.Fatalf("默认档声明应如实记 Present+NoHash: %+v", rep)
	}
	if !rep.Pass() {
		t.Fatalf("默认档声明无可对账条目,应放行: %+v", rep)
	}
	if rep.BadLines != 0 {
		t.Fatalf("声明段说明行不应计坏行: %+v", rep)
	}
	if rep.Entries != 0 {
		t.Fatalf("默认档无哈希条目: %+v", rep)
	}
}
