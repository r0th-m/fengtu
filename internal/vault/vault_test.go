// Package vault 金库测试:写前校验/只读位/幂等/读前校验/按行回查。
package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func shaOf(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func openTestVault(t *testing.T) *Vault {
	t.Helper()
	v, err := Open(filepath.Join(t.TempDir(), "vault"))
	if err != nil {
		t.Fatalf("金库打开失败: %v", err)
	}
	return v
}

func TestPutAndReadBack(t *testing.T) {
	v := openTestVault(t)
	content := []byte("line1\nline2\nline3\n")
	sum := shaOf(content)
	n, err := v.Put(sum, bytes.NewReader(content))
	if err != nil {
		t.Fatalf("Put 失败: %v", err)
	}
	if n != int64(len(content)) {
		t.Fatalf("字节数不符: got %d want %d", n, len(content))
	}
	// 只读位
	st, err := os.Stat(v.Path(sum))
	if err != nil {
		t.Fatalf("落位后 stat 失败: %v", err)
	}
	if st.Mode().Perm() != 0o444 {
		t.Fatalf("只读位不符: got %o want 444", st.Mode().Perm())
	}
	// 按行回查
	lines, err := v.Lines(sum, 2, 3)
	if err != nil {
		t.Fatalf("Lines 失败: %v", err)
	}
	if len(lines) != 2 || lines[0] != "line2" || lines[1] != "line3" {
		t.Fatalf("回查行不符: %v", lines)
	}
}

func TestPutHashMismatchRejected(t *testing.T) {
	v := openTestVault(t)
	content := []byte("evidence")
	wrong := strings.Repeat("ab", 32)
	if _, err := v.Put(wrong, bytes.NewReader(content)); err == nil {
		t.Fatal("哈希不符应拒收入库")
	}
	if v.Exists(wrong) {
		t.Fatal("哈希不符的内容不得落库")
	}
	// 临时文件不得残留
	entries, _ := os.ReadDir(filepath.Join(v.root))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("拒收后临时文件残留: %s", e.Name())
		}
	}
}

func TestPutIdempotent(t *testing.T) {
	v := openTestVault(t)
	content := []byte("same evidence")
	sum := shaOf(content)
	if _, err := v.Put(sum, bytes.NewReader(content)); err != nil {
		t.Fatalf("首次 Put 失败: %v", err)
	}
	if _, err := v.Put(sum, bytes.NewReader(content)); err != nil {
		t.Fatalf("幂等 Put 失败: %v", err)
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	v := openTestVault(t)
	content := []byte("original")
	sum := shaOf(content)
	if _, err := v.Put(sum, bytes.NewReader(content)); err != nil {
		t.Fatalf("Put 失败: %v", err)
	}
	// 模拟外部篡改(提权绕过只读位)
	_ = os.Chmod(v.Path(sum), 0o644)
	if err := os.WriteFile(v.Path(sum), []byte("tampered"), 0o644); err != nil {
		t.Fatalf("篡改注入失败: %v", err)
	}
	if err := v.Verify(sum); err == nil {
		t.Fatal("篡改后 Verify 应报证据完整性存疑")
	}
}

func TestLinesLastLineNoNewline(t *testing.T) {
	v := openTestVault(t)
	content := []byte("a\r\nb\nc") // CRLF + 末行无换行
	sum := shaOf(content)
	if _, err := v.Put(sum, bytes.NewReader(content)); err != nil {
		t.Fatalf("Put 失败: %v", err)
	}
	lines, err := v.Lines(sum, 1, 99)
	if err != nil {
		t.Fatalf("Lines 失败: %v", err)
	}
	want := []string{"a", "b", "c"}
	if len(lines) != 3 {
		t.Fatalf("行数不符: %v", lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("第 %d 行不符: got %q want %q", i+1, lines[i], want[i])
		}
	}
}
