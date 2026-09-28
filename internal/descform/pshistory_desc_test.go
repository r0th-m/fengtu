// 真实 desc 配置焊死(0.25.0-datasource-unlock):configs/desc/pshistory.yaml
// 逐行成事件(command/cmdline 同值双写)、空行恒 skip、快照型 ts 恒 nil;
// 负样本:全空白文件零事件零坏行。
package descform

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ye-mengwen/fengtu/internal/model"
)

func loadRealDesc(t *testing.T, name string) *CompiledDesc {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "configs", "desc", name+".yaml"))
	if err != nil {
		t.Fatalf("真实 desc 不可读: %v", err)
	}
	d, err := CompileText(string(raw))
	if err != nil {
		t.Fatalf("真实 desc 编译失败: %v", err)
	}
	return d
}

func TestRealDesc_PSHistory(t *testing.T) {
	d := loadRealDesc(t, "pshistory")
	if d.LogType != "command_history" {
		t.Fatalf("pshistory 品类 = %q, want command_history", d.LogType)
	}
	lines := []string{
		"ls",
		"",
		"  7z a -p archive.7z C:\\data\\  ",
		"Get-ChildItem | Out-File x.txt",
	}
	var recs []model.Record
	for r := range d.Parse(lines) {
		recs = append(recs, r)
	}
	if len(recs) != 4 {
		t.Fatalf("行账 = %d, want 4", len(recs))
	}
	// 正样本:逐行成事件,command/cmdline 同值(去首尾空白),raw 留原文
	for _, i := range []int{0, 2, 3} {
		r := recs[i]
		if r.Kind != model.KindEvent {
			t.Fatalf("行 %d 应为 event: %+v", i+1, r)
		}
		if r.TsUTC != nil || r.DTLocal != nil {
			t.Fatalf("行 %d 快照型 ts 应恒 nil: %+v", i+1, r)
		}
		cmd, _ := r.Norm["command"].(string)
		cl, _ := r.Norm["cmdline"].(string)
		if cmd == "" || cmd != cl {
			t.Fatalf("行 %d command/cmdline 双写不符: %q / %q", i+1, cmd, cl)
		}
	}
	if got := recs[2].Norm["command"]; got != `7z a -p archive.7z C:\data\` {
		t.Fatalf("行 3 去首尾空白不符: %q", got)
	}
	if recs[2].Raw != lines[2] {
		t.Fatalf("raw 须留原文: %q", recs[2].Raw)
	}
	// 空行恒 skip
	if recs[1].Kind != model.KindSkip {
		t.Fatalf("空行应 skip: %+v", recs[1])
	}
}

// 负样本:全空白文件 → 零事件零坏行(不造事件不报错)。
func TestRealDesc_PSHistoryBlank(t *testing.T) {
	d := loadRealDesc(t, "pshistory")
	var ev, bad, skip int
	for r := range d.Parse([]string{"", "   ", "\t"}) {
		switch r.Kind {
		case model.KindEvent:
			ev++
		case model.KindBad:
			bad++
		default:
			skip++
		}
	}
	if ev != 0 || bad != 0 || skip != 3 {
		t.Fatalf("空白样本账 = ev%d bad%d skip%d, want 0/0/3", ev, bad, skip)
	}
}
