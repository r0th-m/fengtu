package ingest

import (
	"io"
	"strings"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// 合成多行日志:`@n` 起始行 + `\t` 续行,行界即块界。
func blockStartAt(line string) bool { return strings.HasPrefix(line, "@") }

func collectBatches(t *testing.T, cr *ChunkReader) []*Batch {
	t.Helper()
	var out []*Batch
	for {
		b, err := cr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("Next 出错: %v", err)
		}
		out = append(out, b)
	}
}

func allLines(batches []*Batch) []string {
	var out []string
	for _, b := range batches {
		out = append(out, b.Lines...)
	}
	return out
}

func TestChunkReader_MultilineSafeBoundary(t *testing.T) {
	// 20 块 × (起始行 + 2 续行),target 小到必然多块共用一批
	var sb strings.Builder
	var want []string
	for i := 0; i < 20; i++ {
		for _, l := range []string{"@start-" + strings.Repeat("x", i%5), "\tcont-a", "\tcont-b"} {
			sb.WriteString(l + "\n")
			want = append(want, l)
		}
	}
	cr := NewChunkReader(strings.NewReader(sb.String()), "utf-8", blockStartAt, 47)
	batches := collectBatches(t, cr)

	got := allLines(batches)
	if len(got) != len(want) {
		t.Fatalf("行数不符: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 行不符: got %q want %q", i, got[i], want[i])
		}
	}
	// 每批必须以块起始行开头(未闭合块整体移交,不拦腰)
	base := 1
	for _, b := range batches {
		if !blockStartAt(b.Lines[0]) {
			t.Fatalf("批次以非起始行开头: %q", b.Lines[0])
		}
		if b.BaseLineNo != base {
			t.Fatalf("行号不连续: got base %d want %d", b.BaseLineNo, base)
		}
		base += len(b.Lines)
	}
}

func TestChunkReader_NoTrailingNewline(t *testing.T) {
	cr := NewChunkReader(strings.NewReader("@a\n@b\n@c-no-eol"), "utf-8", blockStartAt, 1<<20)
	got := allLines(collectBatches(t, cr))
	want := []string{"@a", "@b", "@c-no-eol"}
	if len(got) != 3 {
		t.Fatalf("行数不符: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %q want %q", got[i], want[i])
		}
	}
}

func TestChunkReader_CRLFAcrossChunk(t *testing.T) {
	// 让 \r 恰好落在块尾:target 正好切在 "ab\r" 之后
	data := "@ab\r\n@cd\r\n@ef\r\n"
	// "@ab\r\n" = 5 字节;target=5 → 块 1 读到 "@ab\r",对齐逻辑须把 \n 一并消费
	cr := NewChunkReader(strings.NewReader(data), "utf-8", blockStartAt, 5)
	got := allLines(collectBatches(t, cr))
	want := []string{"@ab", "@cd", "@ef"}
	if len(got) != len(want) {
		t.Fatalf("CRLF 跨块行数不符: %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("CRLF 跨块第 %d 行: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestChunkReader_GBKAcrossChunk(t *testing.T) {
	// GBK 双字节字符 × N,target 切在字符中间——换行对齐后不应出现 U+FFFD
	gbkLine := strings.Repeat("中文测试", 10) // UTF-8 下 40 字节
	data := "@h\n" + gbkLine + "\n@t\n"
	// GBK 编码构造:直接用 descform 的 GBK 编码路径造字节
	gbkBytes := mustGBK(t, data)
	cr := NewChunkReader(strings.NewReader(string(gbkBytes)), "gbk", blockStartAt, 11)
	got := allLines(collectBatches(t, cr))
	if len(got) != 3 {
		t.Fatalf("GBK 行数不符: %q", got)
	}
	if got[1] != gbkLine {
		t.Fatalf("GBK 内容碎裂: got %q want %q", got[1], gbkLine)
	}
	if strings.ContainsRune(got[1], '�') {
		t.Fatalf("GBK 出现替换符(字符被拦腰): %q", got[1])
	}
}

func mustGBK(t *testing.T, s string) []byte {
	t.Helper()
	out, err := simplifiedchinese.GBK.NewEncoder().Bytes([]byte(s))
	if err != nil {
		t.Fatalf("GBK 编码失败: %v", err)
	}
	return out
}

func TestChunkReader_HugeBlockForcedEmit(t *testing.T) {
	// 一个巨块(续行永不命中起始):carry 超 4×target 后强制切批,
	// 数据不丢(引擎侧会把后续批标孤儿,这里只验不丢行)。
	var sb strings.Builder
	var want []string
	sb.WriteString("@big\n")
	want = append(want, "@big")
	for i := 0; i < 100; i++ {
		l := "\t" + strings.Repeat("c", 8)
		sb.WriteString(l + "\n")
		want = append(want, l)
	}
	cr := NewChunkReader(strings.NewReader(sb.String()), "utf-8", blockStartAt, 64)
	got := allLines(collectBatches(t, cr))
	if len(got) != len(want) {
		t.Fatalf("巨块行数丢失: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("巨块第 %d 行不符", i)
		}
	}
}

func TestChunkReader_Empty(t *testing.T) {
	cr := NewChunkReader(strings.NewReader(""), "utf-8", blockStartAt, 64)
	if _, err := cr.Next(); err != io.EOF {
		t.Fatalf("空输入应 EOF, got %v", err)
	}
}

func TestChunkReader_LineNumbersContinuousAcrossForcedSplit(t *testing.T) {
	// 无多行(isBlockStart 恒真)+ 极小 target:行号必须 1..N 连续
	var sb strings.Builder
	n := 500
	for i := 1; i <= n; i++ {
		sb.WriteString("line-content-padding\n")
	}
	cr := NewChunkReader(strings.NewReader(sb.String()), "utf-8", AlwaysBlockStart, 100)
	base := 1
	for _, b := range collectBatches(t, cr) {
		if b.BaseLineNo != base {
			t.Fatalf("行号断档: got %d want %d", b.BaseLineNo, base)
		}
		base += len(b.Lines)
	}
	if base != n+1 {
		t.Fatalf("总行数: got %d want %d", base-1, n)
	}
}
