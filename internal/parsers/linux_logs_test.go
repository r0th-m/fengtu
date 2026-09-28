// LinuxSC 日志面解析器焊死:双变体行式/年份推断(含跨年 rollover 与
// 无元信息不归一)/sshd 四分支/journal 中文月/last 双形态/lastlog 三面/
// yumlog;负样本(垃圾行/空行/表头/头注)全 skip 留账。
// 测试数据全部自造,不断言任何真实案件值(IP/主机名均为 RFC5737 文档段)。
package parsers

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// writeLLog 在 dir 下落测试样本并返回路径(dir 须已存在)。
func writeLLog(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// writeLLogPkg 造一个迷你采集包结构:root/_COLLECTION_TIME.txt +
// root/<rel> 样本文件,返回样本路径。采集时刻 2026-01-15 10:00:00
// (用于跨年 rollover 验证:12 月日志 → 2025)。
func writeLLogPkg(t *testing.T, rel, content string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "_COLLECTION_TIME.txt"),
		[]byte("LinuxSC Collection Started: 2026/01/15 Thursday 10:00:00\nTimezone=Asia/Shanghai\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return writeLLog(t, root, rel, content)
}

func collectLLog(t *testing.T, p Parser, path string) []model.Record {
	t.Helper()
	st, err := p.Records(path)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	defer st.Close()
	var out []model.Record
	for {
		rec, ok := st.Next()
		if !ok {
			break
		}
		out = append(out, rec)
	}
	if err := st.Err(); err != nil {
		t.Fatalf("流错误: %v", err)
	}
	return out
}

func llogEvents(recs []model.Record) []model.Record {
	var out []model.Record
	for _, r := range recs {
		if r.Kind == model.KindEvent {
			out = append(out, r)
		}
	}
	return out
}

// wantDT 断言 DTLocal 为给定 naive 墙钟。
func wantDT(t *testing.T, r model.Record, want time.Time) {
	t.Helper()
	if r.DTLocal == nil || !r.DTLocal.Equal(want) {
		t.Fatalf("DTLocal = %v, want %v(rec=%+v)", r.DTLocal, want, r)
	}
}

// ---- linux_authlog ----

// ISO 变体(UOS 形态:空格分隔、CRON pam_unix session 锚定行首)。
func TestLinuxAuthlogISO(t *testing.T) {
	path := writeLLog(t, t.TempDir(), "auth.log",
		"2026-07-01 00:17:01 testhost CRON[11308]:  pam_unix(cron:session): session opened for user root by (uid=0)\n"+
			"2026-07-01T00:17:02 testhost CRON[11308]:  pam_unix(cron:session): session closed for user root\n"+
			"\n"+
			"这不是日志行\n")
	recs := collectLLog(t, LinuxAuthlogParser{}, path)
	evs := llogEvents(recs)
	if len(evs) != 2 || len(recs) != 4 {
		t.Fatalf("事件/总行 = %d/%d, want 2/4", len(evs), len(recs))
	}
	e := evs[0]
	if e.Norm["source"] != "auth_log" || e.Norm["host"] != "testhost" ||
		e.Norm["tag"] != "CRON" || e.Norm["pid"] != "11308" {
		t.Fatalf("ISO 基础字段错: %v", e.Norm)
	}
	// pid 必须字符串(规则锚定)
	if _, ok := e.Norm["pid"].(string); !ok {
		t.Fatalf("pid 非字符串: %T", e.Norm["pid"])
	}
	if e.Norm["action"] != "session_opened" || e.Norm["user"] != "root" {
		t.Fatalf("ISO session 分支错: %v", e.Norm)
	}
	if _, has := e.Norm["src_ip"]; has {
		t.Fatalf("session 不应有 src_ip: %v", e.Norm)
	}
	if *e.TsRaw != "2026-07-01 00:17:01" {
		t.Fatalf("TsRaw = %q", *e.TsRaw)
	}
	wantDT(t, e, time.Date(2026, 7, 1, 0, 17, 1, 0, time.UTC))
	// ISO 自带年份:不写 year_inferred
	if _, has := e.Norm["year_inferred"]; has {
		t.Fatalf("ISO 变体不应有 year_inferred: %v", e.Norm)
	}
	if evs[1].Norm["action"] != "session_closed" {
		t.Fatalf("T 分隔变体 action 错: %v", evs[1].Norm)
	}
	// 负样本:空行 + 垃圾行全 skip 带原因
	if recs[2].Kind != model.KindSkip || *recs[2].Reason != "空行" {
		t.Fatalf("空行账错: %+v", recs[2])
	}
	if recs[3].Kind != model.KindSkip || recs[3].Reason == nil {
		t.Fatalf("垃圾行账错: %+v", recs[3])
	}
}

// syslog 变体:sshd 四分支(Accepted/Failed/Invalid/session)+ 年份推断。
func TestLinuxAuthlogSyslogVariants(t *testing.T) {
	path := writeLLogPkg(t, "Logs/var/log/secure",
		"Dec 20 16:46:24 testnode sshd[1234]: Accepted password for alice from 203.0.113.9 port 51234 ssh2\n"+
			"Dec 20 16:46:25 testnode sshd[1234]: Failed password for invalid user bob from 203.0.113.8 port 22 ssh2\n"+
			"Dec 20 16:46:26 testnode sshd[1234]: Invalid user mallory from 203.0.113.7\n"+
			"Dec 20 16:46:27 testnode sshd[1234]: pam_unix(sshd:session): session opened for user alice by (uid=0)\n"+
			"Dec 20 16:46:28 testnode sshd[1234]: Server listening on 0.0.0.0 port 22.\n"+
			"Foo 20 16:46:29 testnode sshd[1234]: Accepted password for x from 203.0.113.1 port 1 ssh2\n")
	evs := llogEvents(collectLLog(t, LinuxAuthlogParser{}, path))
	// Foo 月份不识 → skip;共 5 事件
	if len(evs) != 5 {
		t.Fatalf("事件数 = %d, want 5", len(evs))
	}
	// Accepted 分支 + 跨年 rollover(采集 2026-01-15,日志 12 月 → 2025)
	e := evs[0]
	if e.Norm["action"] != "accepted" || e.Norm["user"] != "alice" ||
		e.Norm["src_ip"] != "203.0.113.9" {
		t.Fatalf("Accepted 分支错: %v", e.Norm)
	}
	if *e.TsRaw != "2025-12-20 16:46:24" {
		t.Fatalf("跨年 TsRaw = %q, want 2025-12-20 16:46:24", *e.TsRaw)
	}
	wantDT(t, e, time.Date(2025, 12, 20, 16, 46, 24, 0, time.UTC))
	if e.Norm["year_inferred"] != true || e.Norm["year_rollover"] != true {
		t.Fatalf("rollover 标注错: %v", e.Norm)
	}
	// Failed + invalid user 前缀吸收
	if evs[1].Norm["action"] != "failed" || evs[1].Norm["user"] != "bob" ||
		evs[1].Norm["src_ip"] != "203.0.113.8" {
		t.Fatalf("Failed 分支错: %v", evs[1].Norm)
	}
	// Invalid user
	if evs[2].Norm["action"] != "invalid_user" || evs[2].Norm["user"] != "mallory" {
		t.Fatalf("Invalid user 分支错: %v", evs[2].Norm)
	}
	// session 锚定行首(authlog 契约)
	if evs[3].Norm["action"] != "session_opened" || evs[3].Norm["user"] != "alice" {
		t.Fatalf("session 分支错: %v", evs[3].Norm)
	}
	// 非 sshd 认证消息:action/user/src_ip 三键都不写(树庭 None 语义)
	for _, k := range []string{"action", "user", "src_ip"} {
		if _, has := evs[4].Norm[k]; has {
			t.Fatalf("普通行不应有 %s: %v", k, evs[4].Norm)
		}
	}
}

// 无采集元信息:TsRaw 留原文、DTLocal 不设(不归一,如实)。
func TestLinuxAuthlogNoMeta(t *testing.T) {
	path := writeLLog(t, t.TempDir(), "secure",
		"Jul  5 08:00:00 testnode sshd[99]: Accepted password for carol from 203.0.113.5 port 2222 ssh2\n")
	evs := llogEvents(collectLLog(t, LinuxAuthlogParser{}, path))
	if len(evs) != 1 {
		t.Fatalf("事件数 = %d, want 1", len(evs))
	}
	e := evs[0]
	if e.DTLocal != nil || e.TsUTCDirect != nil {
		t.Fatalf("无元信息不应归一: %+v", e)
	}
	if *e.TsRaw != "Jul 5 08:00:00" {
		t.Fatalf("无元信息 TsRaw = %q, want 原文", *e.TsRaw)
	}
	for _, k := range []string{"year_inferred", "year_rollover"} {
		if _, has := e.Norm[k]; has {
			t.Fatalf("无元信息不应有 %s: %v", k, e.Norm)
		}
	}
	// action 仍抽取(与 ts 无关)
	if e.Norm["action"] != "accepted" {
		t.Fatalf("无元信息 action 错: %v", e.Norm)
	}
}

// ---- linux_syslog ----

// source=文件基名、unit=tag(journal 面契约)、session search 模式。
func TestLinuxSyslog(t *testing.T) {
	path := writeLLogPkg(t, "Logs/var/log/messages",
		"Dec 20 16:46:24 testnode kernel: Linux version 9.9.9-test (builder@test) #1 SMP\n"+
			// search 模式:pam_unix 不在行首也命中(authlog 锚定则不中)
			"Dec 20 16:46:25 testnode CRON[99]: prefix noise pam_unix(cron:session): session opened for user root\n"+
			// 月份不识:syslog 契约照产事件、ts 不设(树庭 parse_syslog_file 同款)
			"Foo 20 16:46:26 testnode kernel: odd month line\n"+
			"\n")
	recs := collectLLog(t, LinuxSyslogParser{}, path)
	evs := llogEvents(recs)
	if len(evs) != 3 || len(recs) != 4 {
		t.Fatalf("事件/总行 = %d/%d, want 3/4", len(evs), len(recs))
	}
	e := evs[0]
	if e.Norm["source"] != "messages" {
		t.Fatalf("source = %v, want messages", e.Norm["source"])
	}
	if e.Norm["unit"] != "kernel" || e.Norm["tag"] != "kernel" {
		t.Fatalf("unit=tag 契约错: %v", e.Norm)
	}
	// 无 pid 的行不写 pid
	if _, has := e.Norm["pid"]; has {
		t.Fatalf("无 pid 行不应写 pid: %v", e.Norm)
	}
	// search 模式 session 命中
	if evs[1].Norm["action"] != "session_opened" || evs[1].Norm["unit"] != "CRON" {
		t.Fatalf("search 模式 session 错: %v", evs[1].Norm)
	}
	if evs[1].Norm["year_inferred"] != true {
		t.Fatalf("syslog 变体应有 year_inferred: %v", evs[1].Norm)
	}
	// 月份不识照产:month_unrecognized 标注,ts 不设
	e2 := evs[2]
	if e2.Norm["month_unrecognized"] != "true" || e2.DTLocal != nil || e2.TsRaw != nil {
		t.Fatalf("月份不识行账错: %+v", e2)
	}
	if e2.Norm["message"] != "odd month line" {
		t.Fatalf("月份不识行 message 错: %v", e2.Norm)
	}
}

// 同一「pam_unix 不在行首」行,authlog(锚定)不抽 action——两面对拍。
func TestLinuxSyslogVsAuthlogAnchor(t *testing.T) {
	line := "Dec 20 16:46:25 testnode CRON[99]: prefix noise pam_unix(cron:session): session opened for user root\n"
	pkg := writeLLogPkg(t, "Logs/var/log/secure", line)
	evsA := llogEvents(collectLLog(t, LinuxAuthlogParser{}, pkg))
	if len(evsA) != 1 {
		t.Fatalf("authlog 事件数 = %d, want 1", len(evsA))
	}
	if _, has := evsA[0].Norm["action"]; has {
		t.Fatalf("authlog 锚定契约不应命中非行首 session: %v", evsA[0].Norm)
	}
}

// ---- linux_journal_full ----

func TestLinuxJournalFull(t *testing.T) {
	path := writeLLog(t, t.TempDir(), "journalctl_full_shortiso.txt",
		"-- Logs begin at Tue 2026-07-28 17:06:30 CST, end at Tue 2026-07-28 17:13:51 CST. --\n"+
			"2026-07-28T17:06:30+0800 testnode kernel: Linux version 9.9.9-test\n"+
			"2026-07-28T17:06:38+0800 testnode sshd[1004]: Accepted publickey for dave from 203.0.113.10 port 40000 ssh2\n"+
			"-- No entries --\n"+
			"garbage line\n")
	recs := collectLLog(t, LinuxJournalFullParser{}, path)
	evs := llogEvents(recs)
	if len(evs) != 2 || len(recs) != 5 {
		t.Fatalf("事件/总行 = %d/%d, want 2/5", len(evs), len(recs))
	}
	if *recs[0].Reason != "journalctl 头注" || *recs[3].Reason != "journalctl 头注" {
		t.Fatalf("头注账错: %+v / %+v", recs[0], recs[3])
	}
	e := evs[0]
	if e.Norm["source"] != "journalctl_full_shortiso" || e.Norm["host"] != "testnode" ||
		e.Norm["unit"] != "kernel" || e.Norm["ts_offset"] != "+0800" {
		t.Fatalf("journal_full 字段错: %v", e.Norm)
	}
	// UTC 直通:17:06:30+0800 → 09:06:30Z;DTLocal 不设
	if e.TsUTCDirect == nil || !e.TsUTCDirect.Equal(time.Date(2026, 7, 28, 9, 6, 30, 0, time.UTC)) {
		t.Fatalf("TsUTCDirect = %v, want 2026-07-28T09:06:30Z", e.TsUTCDirect)
	}
	if e.DTLocal != nil {
		t.Fatalf("直通面不应设 DTLocal: %+v", e)
	}
	if *e.TsRaw != "2026-07-28T17:06:30+0800" {
		t.Fatalf("TsRaw = %q", *e.TsRaw)
	}
	// sshd 行:pid + action(search 模式)
	e2 := evs[1]
	if e2.Norm["pid"] != "1004" || e2.Norm["action"] != "accepted" ||
		e2.Norm["user"] != "dave" || e2.Norm["src_ip"] != "203.0.113.10" {
		t.Fatalf("journal_full sshd 行错: %v", e2.Norm)
	}
}

// ---- linux_journal_short ----

// 中文月 + 英文月 + 月份不识照产事件 + source 按文件名。
func TestLinuxJournalShort(t *testing.T) {
	path := writeLLogPkg(t, "Logs/journalctl_sshd_unit.txt",
		"-- Logs begin at Sat 2026-06-13 07:23:40 CST. --\n"+
			"12月 20 17:17:44 testpc sshd[15569]: Server listening on 0.0.0.0 port 22.\n"+
			"Dec 20 17:17:45 testpc sshd[15569]: Accepted password for erin from 203.0.113.11 port 50000 ssh2\n"+
			"Xyz 20 17:17:46 testpc sshd[15569]: weird month line\n")
	evs := llogEvents(collectLLog(t, LinuxJournalShortParser{}, path))
	if len(evs) != 3 {
		t.Fatalf("事件数 = %d, want 3(月份不识照产)", len(evs))
	}
	// 中文月 + 跨年 rollover(采集 2026-01-15 → 12 月 = 2025)
	e := evs[0]
	if e.Norm["source"] != "journalctl_sshd_unit" || e.Norm["unit"] != "sshd" ||
		e.Norm["pid"] != "15569" {
		t.Fatalf("中文月行字段错: %v", e.Norm)
	}
	if *e.TsRaw != "2025-12-20 17:17:44" {
		t.Fatalf("中文月 TsRaw = %q", *e.TsRaw)
	}
	wantDT(t, e, time.Date(2025, 12, 20, 17, 17, 44, 0, time.UTC))
	if e.Norm["year_inferred"] != true || e.Norm["year_rollover"] != true {
		t.Fatalf("中文月 rollover 标注错: %v", e.Norm)
	}
	// 英文月
	if *evs[1].TsRaw != "2025-12-20 17:17:45" || evs[1].Norm["action"] != "accepted" {
		t.Fatalf("英文月行错: TsRaw=%v norm=%v", evs[1].TsRaw, evs[1].Norm)
	}
	// 月份不识:事件照产,ts 不设(TsRaw=nil)
	e3 := evs[2]
	if e3.TsRaw != nil || e3.DTLocal != nil || e3.TsUTCDirect != nil {
		t.Fatalf("月份不识不应设 ts: %+v", e3)
	}
	if e3.Norm["message"] != "weird month line" {
		t.Fatalf("月份不识行 message 错: %v", e3.Norm)
	}
}

// journalctl_xe 文件名 → source=journalctl_xe;无元信息 → TsRaw 留原文。
func TestLinuxJournalShortXeNoMeta(t *testing.T) {
	path := writeLLog(t, t.TempDir(), "journalctl_xe.txt",
		"7月 28 17:20:15 testpc sshd[16034]: pam_unix(sshd:session): session closed for user fred\n")
	evs := llogEvents(collectLLog(t, LinuxJournalShortParser{}, path))
	if len(evs) != 1 {
		t.Fatalf("事件数 = %d, want 1", len(evs))
	}
	e := evs[0]
	if e.Norm["source"] != "journalctl_xe" {
		t.Fatalf("source = %v, want journalctl_xe", e.Norm["source"])
	}
	if *e.TsRaw != "7月 28 17:20:15" {
		t.Fatalf("无元信息 TsRaw = %q, want 原文", *e.TsRaw)
	}
	if e.DTLocal != nil {
		t.Fatalf("无元信息不应设 DTLocal: %+v", e)
	}
	if e.Norm["action"] != "session_closed" || e.Norm["user"] != "fred" {
		t.Fatalf("xe session 抽取错: %v", e.Norm)
	}
}

// ---- linux_last ----

func TestLinuxLast(t *testing.T) {
	path := writeLLog(t, t.TempDir(), "last.txt",
		"alice    pts/1        203.0.113.9      Tue Jul 28 17:22:13 2026   still logged in\n"+
			"alice    pts/1        ::1              Tue Jul 28 17:20:13 2026 - Tue Jul 28 17:20:15 2026  (00:00)\n"+
			"reboot   system boot  9.9.9-test       Tue Jul 28 17:15:07 2026   still running\n"+
			"\n"+
			"wtmp begins Tue Jul 28 17:06:32 2026\n")
	recs := collectLLog(t, LinuxLastParser{}, path)
	evs := llogEvents(recs)
	if len(evs) != 3 || len(recs) != 5 {
		t.Fatalf("事件/总行 = %d/%d, want 3/5", len(evs), len(recs))
	}
	if *recs[4].Reason != "wtmp/btmp 起始注记(结构行)" {
		t.Fatalf("wtmp 尾注账错: %+v", recs[4])
	}
	// still logged in:无 end
	e := evs[0]
	if e.Norm["source"] != "last" || e.Norm["user"] != "alice" ||
		e.Norm["tty"] != "pts/1" || e.Norm["from_host"] != "203.0.113.9" ||
		e.Norm["status"] != "still logged in" {
		t.Fatalf("still-logged-in 行错: %v", e.Norm)
	}
	if e.Norm["start"] != "2026-07-28 17:22:13" || *e.TsRaw != "2026-07-28 17:22:13" {
		t.Fatalf("start/TsRaw 错: %v / %v", e.Norm["start"], e.TsRaw)
	}
	wantDT(t, e, time.Date(2026, 7, 28, 17, 22, 13, 0, time.UTC))
	if _, has := e.Norm["end"]; has {
		t.Fatalf("无结束段不应写 end: %v", e.Norm)
	}
	// 带 end 行:from_host=::1(原样留存),status=(00:00)
	e2 := evs[1]
	if e2.Norm["from_host"] != "::1" || e2.Norm["end"] != "2026-07-28 17:20:15" ||
		e2.Norm["status"] != "(00:00)" {
		t.Fatalf("带 end 行错: %v", e2.Norm)
	}
	// reboot 行:tty=system,from_host 非贪婪捕到 weekday 前全文
	// ("boot  9.9.9-test",内核版本号原样留存,不清洗——树庭正同)
	if evs[2].Norm["from_host"] != "boot  9.9.9-test" || evs[2].Norm["status"] != "still running" {
		t.Fatalf("reboot 行错: %v", evs[2].Norm)
	}
}

// lastb.txt → source=lastb;垃圾行 skip。
func TestLinuxLastb(t *testing.T) {
	path := writeLLog(t, t.TempDir(), "lastb.txt",
		"mallory  ssh:notty    203.0.113.66     Tue Jul 28 03:00:00 2026 - Tue Jul 28 03:00:01 2026  (00:00)\n"+
			"garbage\n"+
			"btmp begins Tue Jul 28 03:00:02 2026\n")
	recs := collectLLog(t, LinuxLastParser{}, path)
	evs := llogEvents(recs)
	if len(evs) != 1 {
		t.Fatalf("事件数 = %d, want 1", len(evs))
	}
	if evs[0].Norm["source"] != "lastb" || evs[0].Norm["tty"] != "ssh:notty" {
		t.Fatalf("lastb 字段错: %v", evs[0].Norm)
	}
	if recs[1].Kind != model.KindSkip || recs[2].Kind != model.KindSkip {
		t.Fatalf("负样本账错: %+v", recs)
	}
}

// ---- linux_lastlog ----

func TestLinuxLastlog(t *testing.T) {
	path := writeLLog(t, t.TempDir(), "lastlog.txt",
		"Username         Port     From             Latest\n"+
			"root             pts/1    203.0.113.9      Tue Jul 28 17:12:46 +0800 2026\n"+
			"daemon                                     **Never logged in**\n"+
			"nobody           pts/9    198.51.100.2     周二 7月 27 09:00:00 +0800 2026\n"+
			"\n")
	recs := collectLLog(t, LinuxLastlogParser{}, path)
	evs := llogEvents(recs)
	if len(evs) != 3 || len(recs) != 5 {
		t.Fatalf("事件/总行 = %d/%d, want 3/5", len(evs), len(recs))
	}
	if recs[0].Kind != model.KindSkip || *recs[0].Reason != "表头" {
		t.Fatalf("表头账错: %+v", recs[0])
	}
	// 数据行(英文月):UTC 直通 17:12:46+0800 → 09:12:46Z
	e := evs[0]
	if e.Norm["source"] != "lastlog" || e.Norm["user"] != "root" ||
		e.Norm["port"] != "pts/1" || e.Norm["from_host"] != "203.0.113.9" ||
		e.Norm["never"] != "false" || e.Norm["ts_offset"] != "+0800" {
		t.Fatalf("lastlog 数据行错: %v", e.Norm)
	}
	if e.TsUTCDirect == nil || !e.TsUTCDirect.Equal(time.Date(2026, 7, 28, 9, 12, 46, 0, time.UTC)) {
		t.Fatalf("lastlog TsUTCDirect = %v, want 2026-07-28T09:12:46Z", e.TsUTCDirect)
	}
	// Never logged in:never="true"(字符串),无 ts
	e2 := evs[1]
	if e2.Norm["user"] != "daemon" || e2.Norm["never"] != "true" {
		t.Fatalf("never 行错: %v", e2.Norm)
	}
	if e2.TsUTCDirect != nil || e2.TsRaw != nil {
		t.Fatalf("never 行不应有 ts: %+v", e2)
	}
	// 中文月数据行
	if evs[2].Norm["user"] != "nobody" || evs[2].Norm["ts_offset"] != "+0800" {
		t.Fatalf("中文月 lastlog 行错: %v", evs[2].Norm)
	}
	if evs[2].TsUTCDirect == nil ||
		!evs[2].TsUTCDirect.Equal(time.Date(2026, 7, 27, 1, 0, 0, 0, time.UTC)) {
		t.Fatalf("中文月 TsUTCDirect = %v", evs[2].TsUTCDirect)
	}
}

// ---- linux_yumlog ----

func TestLinuxYumlog(t *testing.T) {
	path := writeLLogPkg(t, "Logs/var/log/yum.log",
		"Dec 12 16:46:24 Installed: passwd-0.80-1.x86_64\n"+
			"Dec 12 16:46:25 Updated: openssl-1.1.1k-1.x86_64\n"+
			"\n"+
			"garbage line\n")
	recs := collectLLog(t, LinuxYumlogParser{}, path)
	evs := llogEvents(recs)
	if len(evs) != 2 || len(recs) != 4 {
		t.Fatalf("事件/总行 = %d/%d, want 2/4", len(evs), len(recs))
	}
	e := evs[0]
	if e.Norm["source"] != "yum_log" || e.Norm["message"] != "Installed: passwd-0.80-1.x86_64" {
		t.Fatalf("yumlog 字段错: %v", e.Norm)
	}
	// 跨年 rollover(采集 2026-01-15,日志 12 月 → 2025)
	if *e.TsRaw != "2025-12-12 16:46:24" {
		t.Fatalf("yumlog TsRaw = %q", *e.TsRaw)
	}
	wantDT(t, e, time.Date(2025, 12, 12, 16, 46, 24, 0, time.UTC))
	if e.Norm["year_inferred"] != true || e.Norm["year_rollover"] != true {
		t.Fatalf("yumlog rollover 标注错: %v", e.Norm)
	}
}

// yumlog 无元信息:TsRaw 留原文,不归一。
func TestLinuxYumlogNoMeta(t *testing.T) {
	path := writeLLog(t, t.TempDir(), "yum.log",
		"Mar 12 16:46:24 Erased: oldpkg-1.0-1.x86_64\n")
	evs := llogEvents(collectLLog(t, LinuxYumlogParser{}, path))
	if len(evs) != 1 {
		t.Fatalf("事件数 = %d, want 1", len(evs))
	}
	if *evs[0].TsRaw != "Mar 12 16:46:24" || evs[0].DTLocal != nil {
		t.Fatalf("无元信息 yumlog 错: TsRaw=%v DTLocal=%v", evs[0].TsRaw, evs[0].DTLocal)
	}
}

// 注册表:7 个日志面 parser 名可解析。
func TestLinuxLogsRegistered(t *testing.T) {
	for _, name := range []string{
		"linux_authlog", "linux_syslog", "linux_journal_full",
		"linux_journal_short", "linux_last", "linux_lastlog", "linux_yumlog",
	} {
		if _, err := For(name); err != nil {
			t.Fatalf("%s 未注册: %v", name, err)
		}
	}
}

// rsyslog 高精度格式(RSYSLOG_FileFormat:小数秒+显式偏移)——
// 真实样本(Ubuntu 24 系)回归:既非传统 syslog 亦非无偏移 ISO,
// 两个旧变体都不中;带偏移走 TsUTCDirect 直通,不依赖声明时区。
func TestLinuxAuthlogPreciseTS(t *testing.T) {
	path := writeLLogPkg(t, "Logs/var/log/auth.log",
		"2026-09-21T02:04:51.698311+00:00 testnode systemd-logind[5130]: New seat seat0.\n"+
			"2026-09-21T02:23:07.599552+00:00 testnode sshd-session[11190]: Accepted password for alice from 203.0.113.9 port 51122 ssh2\n")
	evs := llogEvents(collectLLog(t, LinuxAuthlogParser{}, path))
	if len(evs) != 2 {
		t.Fatalf("事件数 = %d, want 2", len(evs))
	}
	e := evs[1]
	if e.Norm["action"] != "accepted" || e.Norm["user"] != "alice" ||
		e.Norm["src_ip"] != "203.0.113.9" || e.Norm["tag"] != "sshd-session" {
		t.Fatalf("高精度行抽取错: %v", e.Norm)
	}
	if e.TsUTCDirect == nil {
		t.Fatalf("带偏移行应 TsUTCDirect 直通: %+v", e)
	}
	want := time.Date(2026, 9, 21, 2, 23, 7, 599552000, time.UTC)
	if !e.TsUTCDirect.Equal(want) {
		t.Fatalf("TsUTCDirect = %v, want %v", e.TsUTCDirect, want)
	}
	// DTLocal 不设(直通优先,不双写)
	if e.DTLocal != nil {
		t.Fatalf("直通事件不应再设 DTLocal: %+v", e)
	}
}
