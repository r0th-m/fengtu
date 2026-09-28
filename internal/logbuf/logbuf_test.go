// 环形日志账焊死:按行切/容量覆盖最老/Tail 翻页(before 游标)/空行不入账。
package logbuf

import (
	"fmt"
	"testing"
)

func TestRingOverwrite(t *testing.T) {
	b := New(3)
	for i := 1; i <= 5; i++ {
		b.Add(fmt.Sprintf("line-%d", i))
	}
	got := b.Tail(10, 0)
	if len(got) != 3 || got[0].Line != "line-3" || got[2].Line != "line-5" {
		t.Fatalf("环形覆盖不符: %+v", got)
	}
	// seq 单调递增不重用
	if got[0].Seq != 3 || got[2].Seq != 5 {
		t.Fatalf("seq 不符: %+v", got)
	}
}

func TestTailBeforeCursor(t *testing.T) {
	b := New(10)
	for i := 1; i <= 6; i++ {
		b.Add(fmt.Sprintf("line-%d", i))
	}
	got := b.Tail(2, 5) // seq<5 的最近 2 条 = line-3,line-4
	if len(got) != 2 || got[0].Line != "line-3" || got[1].Line != "line-4" {
		t.Fatalf("before 翻页不符: %+v", got)
	}
	got = b.Tail(2, 2) // 只剩 line-1
	if len(got) != 1 || got[0].Line != "line-1" {
		t.Fatalf("before 边界不符: %+v", got)
	}
}

func TestWriteSplitsLines(t *testing.T) {
	b := New(10)
	if n, err := b.Write([]byte("第一段\n第二")); n != 5*3+1 || err != nil {
		// 字节数:「第一段\n」=10,「第二」=6,共 16
		t.Fatalf("Write 返回值不符: %d %v", n, err)
	}
	b.Write([]byte("段\n\n第三段\n")) // 中间空行不入账
	got := b.Tail(10, 0)
	if len(got) != 3 || got[0].Line != "第一段" || got[1].Line != "第二段" ||
		got[2].Line != "第三段" {
		t.Fatalf("按行切/半截拼接/空行过滤不符: %+v", got)
	}
}

func TestTailLimitClamp(t *testing.T) {
	b := New(10)
	b.Add("x")
	if got := b.Tail(0, 0); len(got) != 1 { // limit<=0 走默认 200,数据只有 1
		t.Fatalf("默认 limit 不符: %+v", got)
	}
}
