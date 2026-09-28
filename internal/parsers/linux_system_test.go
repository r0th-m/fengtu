// LinuxSC SystemInfo 账户面解析器焊死:passwd 7 段契约 + account 双写 +
// empty_password 派生;group 4 段契约 + members 列表。
package parsers

import (
	"reflect"
	"testing"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// passwd:恰好 7 段才解析;空口令字段派生 empty_password="true"
// (规则引擎表达不了「等于空串」,见 linux_system.go 头)。
func TestLinuxPasswd(t *testing.T) {
	path := writeSSHCase(t, "SystemInfo/etc/passwd",
		"# 注释\n\n"+
			"root:x:0:0:root:/root:/bin/bash\n"+
			"daemon::1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"+
			"bad:line:too:few\n"+
			"to:many:fields:here:a:b:c:d\n")
	recs := collectSSHRecs(t, LinuxPasswdParser{}, path)
	evs := eventsOf(recs)
	if len(evs) != 2 {
		t.Fatalf("事件数 = %d, want 2(recs=%v)", len(evs), recs)
	}
	e := evs[0].Norm
	if e["source"] != "passwd" || e["username"] != "root" ||
		e["password_field"] != "x" || e["uid"] != "0" || e["gid"] != "0" ||
		e["gecos"] != "root" || e["home"] != "/root" ||
		e["shell"] != "/bin/bash" || e["account"] != "root" {
		t.Fatalf("root 行错: %v", e)
	}
	if _, has := e["empty_password"]; has {
		t.Fatalf("password_field=x 不应派生 empty_password: %v", e)
	}
	e = evs[1].Norm
	if e["username"] != "daemon" || e["password_field"] != "" ||
		e["uid"] != "1" || e["empty_password"] != "true" {
		t.Fatalf("空口令派生错: %v", e)
	}
	// 非 7 段 skip 留账
	if len(recs) != 6 {
		t.Fatalf("行账 = %d, want 6", len(recs))
	}
	if recs[4].Kind != model.KindSkip || *recs[4].Reason != "非 passwd 行,不硬解" {
		t.Fatalf("6 段行应 skip: %+v", recs[4])
	}
	// 快照型恒无时间
	for _, r := range evs {
		if r.TsUTC != nil || r.DTLocal != nil {
			t.Fatalf("快照型不应有时间: %+v", r)
		}
	}
}

// group:恰好 4 段;members 逗号切滤空,有才写。
func TestLinuxGroup(t *testing.T) {
	path := writeSSHCase(t, "SystemInfo/etc/group",
		"root:x:0:\n"+
			"sudo:x:27:alice,bob\n"+
			"wheel:x:10:alice\n"+
			"bad:line:x\n")
	recs := collectSSHRecs(t, LinuxGroupParser{}, path)
	evs := eventsOf(recs)
	if len(evs) != 3 {
		t.Fatalf("事件数 = %d, want 3(recs=%v)", len(evs), recs)
	}
	e := evs[0].Norm
	if e["source"] != "group" || e["group"] != "root" || e["gid"] != "0" {
		t.Fatalf("root 组错: %v", e)
	}
	if _, has := e["members"]; has {
		t.Fatalf("空成员组不应有 members: %v", e)
	}
	if !reflect.DeepEqual(evs[1].Norm["members"], []string{"alice", "bob"}) ||
		evs[1].Norm["gid"] != "27" {
		t.Fatalf("sudo 组成员错: %v", evs[1].Norm)
	}
	if !reflect.DeepEqual(evs[2].Norm["members"], []string{"alice"}) {
		t.Fatalf("wheel 组成员错: %v", evs[2].Norm)
	}
	if len(recs) != 4 || recs[3].Kind != model.KindSkip {
		t.Fatalf("3 段行应 skip 留账: %v", recs)
	}
}
