// linux_net.go 的单元测试:ss / netstat / conntrack 三个 LinuxSC 网络面
// 解析器。样本全部自造(格式对 spec,值对断言;禁止真实案件值)。
package parsers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// runLinuxNet 写临时文件 → 跑解析器 → 收全量记录。
func runLinuxNet(t *testing.T, p Parser, content string) []model.Record {
	t.Helper()
	path := filepath.Join(t.TempDir(), "in.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("写临时文件失败: %v", err)
	}
	st, err := p.Records(path)
	if err != nil {
		t.Fatalf("Records 打开失败: %v", err)
	}
	defer st.Close()
	var recs []model.Record
	for {
		rec, ok := st.Next()
		if !ok {
			break
		}
		recs = append(recs, rec)
	}
	if err := st.Err(); err != nil {
		t.Fatalf("流错误: %v", err)
	}
	return recs
}

func TestLinuxSSParser(t *testing.T) {
	content := strings.Join([]string{
		`Netid  State      Recv-Q Send-Q Local Address:Port               Peer Address:Port`,
		``,
		`udp    UNCONN     0      0         *:68                    *:*                   users:(("dhclient",pid=570,fd=6))`,
		`tcp    LISTEN     0      128       *:22                    *:*                   users:(("sshd",pid=2224,fd=3))`,
		`tcp    SYN-RECV   0      0      192.168.0.73%if415659752:22                 88.198.70.24:56457`,
		`tcp    LISTEN     0      128    [::]:22                 [::]:*                   users:(("sshd",pid=2224,fd=4))`,
		`udp    UNCONN     0      0      [::1]:323                [::]:*                   users:(("chronyd",pid=522,fd=6))`,
		`tcp    LISTEN     0      128`,
	}, "\n")
	recs := runLinuxNet(t, LinuxSSParser{}, content)
	if len(recs) != 8 {
		t.Fatalf("记录数 = %d, 期望 8", len(recs))
	}
	// 表头/空行 skip
	if recs[0].Kind != model.KindSkip || recs[0].Reason == nil ||
		!strings.Contains(*recs[0].Reason, "表头") {
		t.Fatalf("表头行应为 skip+表头原因: %+v", recs[0])
	}
	if recs[1].Kind != model.KindSkip || recs[1].Reason == nil ||
		*recs[1].Reason != "空行" {
		t.Fatalf("空行应为 skip: %+v", recs[1])
	}
	// udp 行:users 归属 + 通配地址
	r := recs[2]
	if r.Kind != model.KindEvent {
		t.Fatalf("L3 应为 event: %+v", r)
	}
	assertNorm(t, r, "source", "ss_tuanp")
	assertNorm(t, r, "proto", "udp")
	assertNorm(t, r, "state", "UNCONN")
	assertNorm(t, r, "local_addr", "*")
	assertNorm(t, r, "local_port", "68")
	assertNorm(t, r, "process_name", "dhclient")
	assertNorm(t, r, "pid", "570") // 规则锚定字段,字符串
	if _, has := r.Norm["remote_port"]; has {
		t.Fatalf("*:* 通配 remote_port 不应写入: %v", r.Norm)
	}
	// 快照型:ts 一律不设
	if r.TsRaw != nil || r.DTLocal != nil || r.TsUTC != nil {
		t.Fatalf("快照型 ts 必须全 nil: %+v", r)
	}
	// LISTEN tcp
	r = recs[3]
	assertNorm(t, r, "proto", "tcp")
	assertNorm(t, r, "state", "LISTEN")
	assertNorm(t, r, "local_port", "22")
	assertNorm(t, r, "pid", "2224")
	// 无 users 段(恰好 6 段):%ifname 剥除,无进程归属键
	r = recs[4]
	assertNorm(t, r, "state", "SYN-RECV")
	assertNorm(t, r, "local_addr", "192.168.0.73")
	assertNorm(t, r, "local_port", "22")
	assertNorm(t, r, "remote_addr", "88.198.70.24")
	assertNorm(t, r, "remote_port", "56457")
	if _, has := r.Norm["process_name"]; has {
		t.Fatalf("无 users 段不应有 process_name: %v", r.Norm)
	}
	if _, has := r.Norm["pid"]; has {
		t.Fatalf("无 users 段不应有 pid: %v", r.Norm)
	}
	// IPv6 [::]:22
	r = recs[5]
	assertNorm(t, r, "local_addr", "::")
	assertNorm(t, r, "local_port", "22")
	// [::1]:323;对端 [::]:* → addr "::"、port "*"(splitLAddr 括号分支
	// 契约:端口段原样返回,与树庭 `port or None` 一致,"*" 非空故保留)
	r = recs[6]
	assertNorm(t, r, "local_addr", "::1")
	assertNorm(t, r, "local_port", "323")
	assertNorm(t, r, "remote_addr", "::")
	assertNorm(t, r, "remote_port", "*")
	// 残缺行(5 段)→ skip 留账
	if recs[7].Kind != model.KindSkip || recs[7].Reason == nil ||
		!strings.Contains(*recs[7].Reason, "列数不足") {
		t.Fatalf("残缺行应为 skip+列数不足: %+v", recs[7])
	}
}

func TestLinuxNetstatParser(t *testing.T) {
	content := strings.Join([]string{
		`Active Internet connections (servers and established)`,
		`Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name`,
		`tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      2224/sshd`,
		`udp        0      0 0.0.0.0:68              0.0.0.0:*                           570/dhclient`,
		`tcp        0      0 192.168.0.73:22         88.198.70.24:56457      SYN_RECV    -`,
		`tcp6       0      0 :::22                   :::*                    LISTEN      2224/sshd`,
		``,
		`tcp        0      0 0.0.0.0:22`,
	}, "\n")
	recs := runLinuxNet(t, LinuxNetstatParser{}, content)
	if len(recs) != 8 {
		t.Fatalf("记录数 = %d, 期望 8", len(recs))
	}
	// 标题/表头 skip
	for i, want := range []string{"Active", "Proto"} {
		if recs[i].Kind != model.KindSkip || recs[i].Reason == nil ||
			!strings.Contains(*recs[i].Reason, "表头") {
			t.Fatalf("%s 行应为 skip+表头: %+v", want, recs[i])
		}
	}
	// tcp LISTEN 带归属
	r := recs[2]
	assertNorm(t, r, "source", "netstat_tuanp")
	assertNorm(t, r, "proto", "tcp")
	assertNorm(t, r, "state", "LISTEN")
	assertNorm(t, r, "local_addr", "0.0.0.0")
	assertNorm(t, r, "local_port", "22")
	assertNorm(t, r, "remote_addr", "0.0.0.0")
	if _, has := r.Norm["remote_port"]; has {
		t.Fatalf("0.0.0.0:* 通配 remote_port 不应写入: %v", r.Norm)
	}
	assertNorm(t, r, "pid", "2224")
	assertNorm(t, r, "process_name", "sshd")
	if r.TsRaw != nil || r.DTLocal != nil || r.TsUTC != nil {
		t.Fatalf("快照型 ts 必须全 nil: %+v", r)
	}
	// udp 无 State 列:parts[5] 是 owner,不是 state
	r = recs[3]
	assertNorm(t, r, "proto", "udp")
	if _, has := r.Norm["state"]; has {
		t.Fatalf("udp 无 State 列,state 不应写入: %v", r.Norm)
	}
	assertNorm(t, r, "pid", "570")
	assertNorm(t, r, "process_name", "dhclient")
	// owner "-" 无 "/" → pid/process_name 均不写
	r = recs[4]
	assertNorm(t, r, "state", "SYN_RECV")
	assertNorm(t, r, "remote_port", "56457")
	if _, has := r.Norm["pid"]; has {
		t.Fatalf("owner=- 不应有 pid: %v", r.Norm)
	}
	// tcp6 裸双冒号 :::22 → addr "::" port "22"(splitLAddr 契约)
	r = recs[5]
	assertNorm(t, r, "proto", "tcp6")
	assertNorm(t, r, "local_addr", "::")
	assertNorm(t, r, "local_port", "22")
	// 空行 / 残缺行 skip
	if recs[6].Kind != model.KindSkip || *recs[6].Reason != "空行" {
		t.Fatalf("空行应为 skip: %+v", recs[6])
	}
	if recs[7].Kind != model.KindSkip ||
		!strings.Contains(*recs[7].Reason, "列数不足") {
		t.Fatalf("残缺行应为 skip+列数不足: %+v", recs[7])
	}
}

func TestLinuxConntrackParser(t *testing.T) {
	content := strings.Join([]string{
		``,
		`tcp      6 431999 ESTABLISHED src=192.168.1.2 dst=8.8.8.8 sport=51234 dport=443 src=8.8.8.8 dst=192.168.1.2 sport=443 dport=51234 [ASSURED] mark=0 use=1`,
		`tcp      6 93 SYN_SENT src=10.0.0.1 dst=10.0.0.2 sport=52476 dport=6443 [UNREPLIED] src=10.0.0.2 dst=10.0.0.1 sport=6443 dport=52476 mark=0 use=1`,
		`icmp     1 29 src=192.168.1.2 dst=8.8.8.8 type=8 code=0 id=1234 src=8.8.8.8 dst=192.168.1.2 type=0 code=0 id=1234 mark=0 use=1`,
		`garbage line`,
	}, "\n")
	recs := runLinuxNet(t, LinuxConntrackParser{}, content)
	// 空行 + 4 数据行 + 1 summary = 6
	if len(recs) != 6 {
		t.Fatalf("记录数 = %d, 期望 6", len(recs))
	}
	if recs[0].Kind != model.KindSkip || *recs[0].Reason != "空行" {
		t.Fatalf("空行应为 skip: %+v", recs[0])
	}
	// ESTABLISHED:同键取首现(原向五元组)+ flags + 双写
	r := recs[1]
	assertNorm(t, r, "source", "conntrack")
	assertNorm(t, r, "proto", "tcp")
	assertNorm(t, r, "timeout", "431999") // 原始字符串留存
	assertNorm(t, r, "state", "ESTABLISHED")
	assertNorm(t, r, "src", "192.168.1.2")
	assertNorm(t, r, "dst", "8.8.8.8")
	assertNorm(t, r, "sport", "51234")
	assertNorm(t, r, "dport", "443")
	assertNorm(t, r, "flags", "ASSURED")
	assertNorm(t, r, "mark", "0")
	// 双写(丰图适配):dst/dport 同步到 remote_addr/remote_port
	assertNorm(t, r, "remote_addr", "8.8.8.8")
	assertNorm(t, r, "remote_port", "443")
	if r.TsRaw != nil || r.DTLocal != nil || r.TsUTC != nil {
		t.Fatalf("快照型 ts 必须全 nil: %+v", r)
	}
	// SYN_SENT + [UNREPLIED]
	r = recs[2]
	assertNorm(t, r, "state", "SYN_SENT")
	assertNorm(t, r, "flags", "UNREPLIED")
	assertNorm(t, r, "dport", "6443")
	// icmp:parts[3] 以 src= 开头 → state 不写
	r = recs[3]
	assertNorm(t, r, "proto", "icmp")
	assertNorm(t, r, "timeout", "29")
	if _, has := r.Norm["state"]; has {
		t.Fatalf("icmp 无状态变体,state 不应写入: %v", r.Norm)
	}
	assertNorm(t, r, "src", "192.168.1.2")
	assertNorm(t, r, "dst", "8.8.8.8")
	// 残缺行 → skip(malformed 计数)
	if recs[4].Kind != model.KindSkip ||
		!strings.Contains(*recs[4].Reason, "列数不足") {
		t.Fatalf("残缺行应为 skip+列数不足: %+v", recs[4])
	}
	// summary:末位一条,LineNo=1,Raw=""
	sum := recs[5]
	if sum.Kind != model.KindEvent || sum.LineNo != 1 || sum.Raw != "" {
		t.Fatalf("summary 形态不符: %+v", sum)
	}
	assertNorm(t, sum, "source", "conntrack")
	assertNorm(t, sum, "kind_note", "conntrack_summary")
	assertNormInt(t, sum, "total_lines", 4)
	assertNormInt(t, sum, "malformed_lines", 1)
	assertNormInt(t, sum, "emitted_entries", 3)
	assertNormInt(t, sum, "truncated_entries", 0)
	assertNorm(t, sum, "capped", "false")
}

func TestLinuxConntrackCap(t *testing.T) {
	// 20001 行有效行:超 20000 上限 → 逐行事件 20000 条,capped=true
	var b strings.Builder
	line := `tcp      6 100 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=1000 dport=22 [ASSURED] mark=0 use=1`
	for i := 0; i < 20001; i++ {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	recs := runLinuxNet(t, LinuxConntrackParser{}, b.String())
	events, skips := 0, 0
	for _, r := range recs {
		switch r.Kind {
		case model.KindEvent:
			events++
		case model.KindSkip:
			skips++
		}
	}
	// 20000 逐行事件 + 1 summary;超上限那 1 行 skip 留账
	if events != 20001 || skips != 1 {
		t.Fatalf("events=%d skips=%d, 期望 20001/1", events, skips)
	}
	sum := recs[len(recs)-1]
	assertNorm(t, sum, "kind_note", "conntrack_summary")
	assertNormInt(t, sum, "total_lines", 20001)
	assertNormInt(t, sum, "malformed_lines", 0)
	assertNormInt(t, sum, "emitted_entries", 20000)
	assertNormInt(t, sum, "truncated_entries", 1)
	assertNorm(t, sum, "capped", "true")
}

func assertNorm(t *testing.T, r model.Record, key, want string) {
	t.Helper()
	got, ok := r.Norm[key]
	if !ok {
		t.Fatalf("L%d 缺 norm[%q](norm=%v)", r.LineNo, key, r.Norm)
	}
	s, ok := got.(string)
	if !ok {
		t.Fatalf("L%d norm[%q] 应为字符串, 实得 %T(%v)", r.LineNo, key, got, got)
	}
	if s != want {
		t.Fatalf("L%d norm[%q] = %q, 期望 %q", r.LineNo, key, s, want)
	}
}

func assertNormInt(t *testing.T, r model.Record, key string, want int) {
	t.Helper()
	got, ok := r.Norm[key]
	if !ok {
		t.Fatalf("L%d 缺 norm[%q](norm=%v)", r.LineNo, key, r.Norm)
	}
	n, ok := got.(int)
	if !ok {
		t.Fatalf("L%d norm[%q] 应为 int, 实得 %T(%v)", r.LineNo, key, got, got)
	}
	if n != want {
		t.Fatalf("L%d norm[%q] = %d, 期望 %d", r.LineNo, key, n, want)
	}
}
