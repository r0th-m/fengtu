// LinuxSC RootkitHunt Ebury IOC 清单解析器焊死:中文月名 ls -l 行 +
// symlink 目标 / 普通文件行 / total 与垃圾行 skip / 空文件 0 事件合法。
package parsers

import (
	"testing"
)

// 正样本:中文月名 ls -l 行(树庭契约:非贪婪回溯取最后 token,不按
// 日期列解析),symlink 与普通文件各一。
func TestLinuxEburyIOC(t *testing.T) {
	path := writeSSHCase(t, "RootkitHunt/ebury_ioc_libs.txt",
		"total 0\n"+
			"lrwxrwxrwx. 1 root root 18 7月   7 2024 /lib64/libkeyutils.so.1 -> libkeyutils.so.1.5\n"+
			"-rwxr-xr-x. 1 root root 15688 6月  10 2014 /lib64/libkeyutils.so.1.5\n"+
			"这不是 ls -l 行\n")
	recs := collectSSHRecs(t, LinuxEburyIOCParser{}, path)
	evs := eventsOf(recs)
	if len(evs) != 2 {
		t.Fatalf("事件数 = %d, want 2(recs=%v)", len(evs), recs)
	}
	e := evs[0].Norm
	if e["source"] != "ebury_ioc_libs" || e["mode"] != "lrwxrwxrwx" ||
		e["owner"] != "root" || e["size"] != "18" ||
		e["path"] != "/lib64/libkeyutils.so.1" ||
		e["link_target"] != "libkeyutils.so.1.5" ||
		e["is_symlink"] != "true" {
		t.Fatalf("symlink 行错: %v", e)
	}
	e = evs[1].Norm
	if e["mode"] != "-rwxr-xr-x" || e["size"] != "15688" ||
		e["path"] != "/lib64/libkeyutils.so.1.5" ||
		e["is_symlink"] != "false" {
		t.Fatalf("普通文件行错: %v", e)
	}
	if _, has := e["link_target"]; has {
		t.Fatalf("非 symlink 不应有 link_target: %v", e)
	}
	// total/垃圾行 skip 留账,零静默
	if len(recs) != 4 {
		t.Fatalf("行账 = %d, want 4", len(recs))
	}
	// 快照型恒无时间
	for _, r := range evs {
		if r.TsUTC != nil || r.DTLocal != nil {
			t.Fatalf("快照型不应有时间: %+v", r)
		}
	}
}

// 空文件 = 0 事件,合法(IOC 未命中,不当作失败)。
func TestLinuxEburyIOCEmpty(t *testing.T) {
	path := writeSSHCase(t, "RootkitHunt/ebury_ioc_libs.txt", "")
	recs := collectSSHRecs(t, LinuxEburyIOCParser{}, path)
	if len(recs) != 0 {
		t.Fatalf("空文件记录数 = %d, want 0", len(recs))
	}
}
