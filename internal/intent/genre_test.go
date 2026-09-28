// fact 体裁契约测试(M3):三态焊死——合规中文事实 / 英文过程叙述 /
// 无汉字结论(无锚点结论态由 TestVerdictDowngradeWithoutAnchors 既有覆盖)。
package intent

import (
	"context"
	"strings"
	"testing"
)

// ---- 单元:factGenreViolation 三态 ----

func TestGenreViolation_Unit(t *testing.T) {
	cases := []struct {
		name    string
		summary string
		wantBad bool
	}{
		{"合规中文结论+锚点", "主机存在计划任务持久化:evil.exe 每 5 分钟自启(锚点 s1:L42)", false},
		{"中文结论含英文引用", "发现可疑命令行 `powershell -enc SQBFAFgA...`,判定为混淆执行", false},
		{"中文过程叙述开头_我将", "我将检查进程列表", true},
		{"中文过程叙述开头_我先", "我先看一下网络连接,再查进程", true},
		{"中文过程叙述开头_让我", "让我先列出所有源", true},
		{"英文过程叙述_I'll", "I'll start by checking the prefetch files", true},
		{"英文过程叙述_I will", "I will now examine the registry", true},
		{"英文过程叙述_Let me", "Let me search for the artifacts first", true},
		{"英文结论无过程腔但零汉字", "All evidence reviewed, nothing suspicious found", true},
		{"引用符开头仍拦过程腔", "> 我将逐条核实锚点", true},
		{"空串不归体裁闸管", "", false},
	}
	for _, c := range cases {
		got := factGenreViolation(c.summary)
		if (got != "") != c.wantBad {
			t.Fatalf("%s: violation=%q, 期望违规=%v", c.name, got, c.wantBad)
		}
	}
}

// ---- 集成:supported 但体裁违规 → 降级 doubt 并如实记录 ----

func TestGenreViolationDowngradesToDoubt(t *testing.T) {
	eng, fs, fa, _ := testEngine(nil)
	eng.Start(context.Background())
	defer eng.Close()
	fa.runFn = func(_, _, _ string, _ <-chan string) []AIEvent {
		return []AIEvent{{Kind: "text", Text: "```json\n" +
			`{"verdict":"supported",` +
			`"summary":"I'll start by checking the logs and found evil.exe",` +
			`"anchors":[{"source_id":"s1","line_no":42}],` +
			`"children":[]}` + "\n```"}}
	}
	ctx := context.Background()
	n, err := eng.CreateHuman(ctx, "case-1", "tester", "查进程执行痕迹", "", 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := waitFor(func() bool {
		got, _ := fs.GetNode(ctx, n.ID)
		return got.Status == StatusDoubt
	}, "体裁违规 supported 降级 doubt"); err != nil {
		t.Fatal(err)
	}
	got, _ := fs.GetNode(ctx, n.ID)
	if !strings.Contains(got.CloseNote, "体裁不合规") {
		t.Fatalf("降级说明缺体裁缘由: %q", got.CloseNote)
	}
}

// 零汉字结论(无过程腔)同样降级。
func TestGenreViolationEnglishConclusion(t *testing.T) {
	eng, fs, fa, _ := testEngine(nil)
	eng.Start(context.Background())
	defer eng.Close()
	fa.runFn = func(_, _, _ string, _ <-chan string) []AIEvent {
		return []AIEvent{{Kind: "text", Text: "```json\n" +
			`{"verdict":"denied","summary":"All clean, nothing found",` +
			`"anchors":[],"children":[]}` + "\n```"}}
	}
	ctx := context.Background()
	n, _ := eng.CreateHuman(ctx, "case-1", "tester", "查外连", "", 0, "", "")
	if err := waitFor(func() bool {
		got, _ := fs.GetNode(ctx, n.ID)
		return got.Status == StatusDoubt
	}, "零汉字结论降级 doubt"); err != nil {
		t.Fatal(err)
	}
}

// 合规事实不受体裁闸影响:supported 带锚点原样通过。
func TestGenreCompliantFactPasses(t *testing.T) {
	eng, fs, fa, _ := testEngine(nil)
	eng.Start(context.Background())
	defer eng.Close()
	fa.runFn = func(_, _, _ string, _ <-chan string) []AIEvent {
		return []AIEvent{{Kind: "text", Text: "```json\n" +
			`{"verdict":"supported",` +
			`"summary":"存在可疑进程执行:evil.exe 运行 3 次(锚点 s1:L42)",` +
			`"anchors":[{"source_id":"s1","line_no":42}],` +
			`"children":[]}` + "\n```"}}
	}
	ctx := context.Background()
	n, err := eng.CreateHuman(ctx, "case-1", "tester", "查进程执行痕迹", "", 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := waitFor(func() bool {
		got, _ := fs.GetNode(ctx, n.ID)
		return got.Status == StatusSupported
	}, "合规 fact supported 原样通过"); err != nil {
		t.Fatal(err)
	}
	got, _ := fs.GetNode(ctx, n.ID)
	if strings.Contains(got.CloseNote, "体裁") {
		t.Fatalf("合规 fact 被体裁闸误伤: %q", got.CloseNote)
	}
}
