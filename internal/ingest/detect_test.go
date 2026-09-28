package ingest

import (
	"os"
	"path/filepath"
	"testing"
)

// SniffText 合成样本契约(2026-09-23 通用缺陷修复:raw 兜底源金库回查门禁)。
func TestSniffText(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, content []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, content, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"ransom.readme", []byte("Your files are encrypted.\nContact us.\n"), true},
		{"taskxml", []byte("<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n<Task>\n"), true},
		{"utf8bom.txt", append([]byte{0xEF, 0xBB, 0xBF}, []byte("中文行\n")...), true},
		{"utf16le.dat", append([]byte{0xFF, 0xFE}, []byte("A\x00B\x00")...), true},
		{"empty", nil, true},
		{"binary.enc", []byte{0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00}, false},
		{"nul-late.bin", append([]byte("开头像文本\n第二行也正常\n"), append([]byte("第三行"), 0x00, 0x01)...), false},
		{"ctrlflood", []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4}, false},
	}
	for _, c := range cases {
		got, err := SniffText(mk(c.name, c.data))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s: SniffText=%v 期望 %v", c.name, got, c.want)
		}
	}
	if _, err := SniffText(filepath.Join(dir, "不存在")); err == nil {
		t.Error("不存在文件应如实报错")
	}
}
