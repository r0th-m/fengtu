package ingest

import (
	"encoding/json"
	"strings"
	"testing"
)

// 快速编码器与标准库(SetEscapeHTML(false))对拍:语义等价(按解码值比)。
func TestFieldsJSON_EquivalentToStdlib(t *testing.T) {
	samples := []map[string]any{
		{},
		{"a": "b"},
		{"zh": "信息/中文", "quote": `say "hi" \ <tag> &`, "ctrl": "a\nb\tc\r"},
		{"n": json.Number("123"), "f": json.Number("1.50"), "b": true, "nil": nil},
		{"i": int64(-7), "fl": 3.25},
		{"nested": map[string]any{"x": "y", "deep": map[string]any{"k": 1.0}}},
		{"list": []any{"a", json.Number("2"), nil, true}, "sl": []string{"p", "q"}},
		{"extras": map[string]any{"thread": "main"}, "level": "信息", "message": "服务器版本: Apache"},
	}
	for i, m := range samples {
		got := appendFieldsJSON(nil, m)
		var gotV, wantV any
		if err := json.Unmarshal(got, &gotV); err != nil {
			t.Fatalf("#%d 产出非法 JSON: %s (%v)", i, got, err)
		}
		want, _ := json.Marshal(m)
		if err := json.Unmarshal(want, &wantV); err != nil {
			t.Fatalf("#%d 标准库失败", i)
		}
		gj, _ := json.Marshal(gotV)
		wj, _ := json.Marshal(wantV)
		if string(gj) != string(wj) {
			t.Fatalf("#%d 语义不等价:\n got %s\nwant %s", i, gj, wj)
		}
		// HTML 字符不转义(SetEscapeHTML(false) 等价):出现 < 转义形才判负
		if strings.Contains(string(got), "\\u003c") {
			t.Fatalf("#%d HTML 被转义: %s", i, got)
		}
	}
}

func TestFieldsJSON_Escaping(t *testing.T) {
	got := string(appendFieldsJSON(nil, map[string]any{"k": "a\"b\\c\nd\x01e"}))
	for _, frag := range []string{`\"`, `\\`, `\n`, `\u0001`} {
		if !strings.Contains(got, frag) {
			t.Fatalf("缺转义 %s: %s", frag, got)
		}
	}
}

func BenchmarkFieldsJSON(b *testing.B) {
	m := map[string]any{
		"src_ip": "142.67.85.140", "method": "GET", "path": "/static/style.css",
		"status": 301, "bytes": 56087, "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)",
		"extras": map[string]any{"time_offset": "+0800"},
	}
	b.ReportAllocs()
	buf := make([]byte, 0, 512)
	for i := 0; i < b.N; i++ {
		buf = appendFieldsJSON(buf[:0], m)
	}
	_ = buf
}
