// LinuxSC RecoveredBinaries 登记视图焊死:exe/memfd 两种命名契约 + 坏名
// 仍登记(缺键语义)+ artifact_sha256 自算 + _no_hits.txt 声明。
package parsers

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// writeBinCase 落 .bin 测试样本并返回路径。
func writeBinCase(t *testing.T, name string, content []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "RecoveredBinaries", name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// 正样本 1:pid<PID>_exe_<名称>.bin → kind=exe;sha256 自算(树庭由
// 摄取层算好传入,丰图 parser 只有 path,自算——见 linux_recovered.go 头)。
func TestLinuxRecoveredExe(t *testing.T) {
	content := []byte("fake recovered binary content")
	path := writeBinCase(t, "pid1234_exe_sshd.bin", content)
	recs := collectSSHRecs(t, LinuxRecoveredParser{}, path)
	if len(recs) != 1 || recs[0].Kind != model.KindEvent {
		t.Fatalf("应一条事件: %v", recs)
	}
	e := recs[0].Norm
	if e["source"] != "recovered_binaries" || e["file"] != "pid1234_exe_sshd.bin" ||
		e["pid"] != "1234" || e["kind"] != "exe" || e["exe_name"] != "sshd" ||
		e["naming_contract"] != "true" {
		t.Fatalf("exe 命名字段错: %v", e)
	}
	if _, has := e["fd"]; has {
		t.Fatalf("exe 形态不应有 fd: %v", e)
	}
	want := fmt.Sprintf("%x", sha256.Sum256(content))
	if e["artifact_sha256"] != want {
		t.Fatalf("artifact_sha256 = %v, want %v", e["artifact_sha256"], want)
	}
	if recs[0].LineNo != 1 || recs[0].Raw != "pid1234_exe_sshd.bin" {
		t.Fatalf("事件应锚 LineNo=1 且 Raw=基名: %+v", recs[0])
	}
}

// 正样本 2:pid<PID>_fd<N>_memfd.bin → kind=memfd,exe_name 不写。
func TestLinuxRecoveredMemfd(t *testing.T) {
	path := writeBinCase(t, "pid45_fd3_memfd.bin", []byte("memfd dump"))
	recs := collectSSHRecs(t, LinuxRecoveredParser{}, path)
	e := recs[0].Norm
	if e["pid"] != "45" || e["kind"] != "memfd" || e["fd"] != "3" ||
		e["naming_contract"] != "true" {
		t.Fatalf("memfd 命名字段错: %v", e)
	}
	if _, has := e["exe_name"]; has {
		t.Fatalf("memfd 形态不应有 exe_name: %v", e)
	}
}

// 负样本:命名契约外仍登记(naming_contract="false",pid/kind 缺键);
// 文件读不到 = 文件级 fatal,如实报错。
func TestLinuxRecoveredBadName(t *testing.T) {
	path := writeBinCase(t, "random_dump.bin", []byte("???"))
	recs := collectSSHRecs(t, LinuxRecoveredParser{}, path)
	e := recs[0].Norm
	if e["naming_contract"] != "false" || e["file"] != "random_dump.bin" {
		t.Fatalf("契约外登记错: %v", e)
	}
	for _, k := range []string{"pid", "kind", "exe_name", "fd"} {
		if _, has := e[k]; has {
			t.Fatalf("契约外不应有 %s 键: %v", k, e)
		}
	}
	if _, has := e["artifact_sha256"]; !has {
		t.Fatalf("契约外仍应有 artifact_sha256: %v", e)
	}
	// 读不到 → 整个 Records 返回错误
	if _, err := (LinuxRecoveredParser{}).Records(
		filepath.Join(filepath.Dir(path), "不存在.bin")); err == nil {
		t.Fatal("读文件失败应返回错误")
	}
}

// _no_hits.txt:第一个非空 strip 行 → note;空文件 note 不写。
func TestLinuxRecoveredNoHits(t *testing.T) {
	path := writeBinCase(t, "_no_hits.txt",
		[]byte("\n\n(无 deleted exe / memfd fd 命中, 未发现可恢复样本)\n"))
	recs := collectSSHRecs(t, LinuxRecoveredNoHitsParser{}, path)
	if len(recs) != 1 || recs[0].Kind != model.KindEvent {
		t.Fatalf("应一条事件: %v", recs)
	}
	e := recs[0].Norm
	if e["source"] != "recovered_binaries" || e["result"] != "no_hits" ||
		e["note"] != "(无 deleted exe / memfd fd 命中, 未发现可恢复样本)" {
		t.Fatalf("no_hits 事件错: %v", e)
	}

	empty := writeBinCase(t, "_no_hits.txt", []byte("\n\n"))
	e = collectSSHRecs(t, LinuxRecoveredNoHitsParser{}, empty)[0].Norm
	if e["result"] != "no_hits" {
		t.Fatalf("空声明事件错: %v", e)
	}
	if _, has := e["note"]; has {
		t.Fatalf("空文件不应有 note: %v", e)
	}
}
