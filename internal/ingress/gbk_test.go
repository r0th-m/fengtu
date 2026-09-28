// GBK 条目名(zip 未置 UTF-8 标志位,名是 GBK 原始字节)还原测试。
package ingress

import (
	"path/filepath"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
)

func TestExpandZipGBKEntryName(t *testing.T) {
	gbkName, err := simplifiedchinese.GBK.NewEncoder().String("中文名.txt")
	if err != nil {
		t.Fatal(err)
	}
	z := buildZip(t, map[string][]byte{
		gbkName: []byte("zzz"),
	})
	exp, err := ExpandZip(z, filepath.Join(t.TempDir(), "x"),
		func(string) bool { return false })
	if err != nil {
		t.Fatalf("展开失败: %v", err)
	}
	if len(exp.Files) != 1 {
		t.Fatalf("应展 1 个文件: %d", len(exp.Files))
	}
	if exp.Files[0].Name != "中文名.txt" {
		t.Fatalf("GBK 条目名还原失败: %q", exp.Files[0].Name)
	}
	if filepath.Base(exp.Files[0].Path) != "中文名.txt" {
		t.Fatalf("GBK 落盘名不符: %q", exp.Files[0].Path)
	}
}
