// 持久化面 9 个 parser 焊死:cron(全用户/系统/spool)/anacrontab/systemd
// unit 与 drop-in/udev/pam/shell 配置,正负样本 + 锚定字段字符串口径 +
// 快照型无时间戳。测试数据自造(契约见 LINUXSC_SPEC.md/树庭同名校验)。
package parsers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// writePersist 落测试样本(rel 可带多级目录,如 Persistence/home/u/.bashrc)。
func writePersist(t *testing.T, rel, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// collectPersist 跑一个 parser 收全量记录。
func collectPersist(t *testing.T, p Parser, path string) []model.Record {
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

// assertNoTs 快照型:任何记录都不许带时间。
func assertNoTs(t *testing.T, recs []model.Record) {
	t.Helper()
	for _, r := range recs {
		if r.TsUTC != nil || r.DTLocal != nil || r.TsRaw != nil || r.TsUTCDirect != nil {
			t.Fatalf("快照型不应有时间: %+v", r)
		}
	}
}

// ---- linux_cron_all ----

// 正样本:分节 + 环境变量行 + 注释 + @keyword + 五段 + no crontab。
func TestLinuxCronAllParser(t *testing.T) {
	path := writePersist(t, "Persistence/crontab_all_users.txt",
		"SHELL=/bin/bash\n"+
			"===== root =====\n"+
			"# root 的例行任务\n"+
			"0 5 * * * /usr/bin/backup.sh --full\n"+
			"@daily /bin/echo hi\n"+
			"\n"+
			"===== alice =====\n"+
			"no crontab for alice\n")
	recs := collectPersist(t, LinuxCronAllParser{}, path)
	evs := eventsOf(recs)
	if len(evs) != 3 {
		t.Fatalf("事件数 = %d, want 3(recs=%v)", len(evs), recs)
	}
	e := evs[0].Norm
	if e["source"] != "crontab_all_users" || e["user"] != "root" ||
		e["schedule"] != "0 5 * * *" || e["command"] != "/usr/bin/backup.sh --full" {
		t.Fatalf("五段条目字段错: %v", e)
	}
	e = evs[1].Norm
	if e["schedule"] != "@daily" || e["command"] != "/bin/echo hi" || e["user"] != "root" {
		t.Fatalf("@keyword 条目字段错: %v", e)
	}
	e = evs[2].Norm
	if e["user"] != "alice" || e["section_empty"] != "true" ||
		e["source"] != "crontab_all_users" {
		t.Fatalf("no crontab 事件错: %v", e)
	}
	// 零静默:8 行全有账
	if len(recs) != 8 {
		t.Fatalf("行账 = %d, want 8", len(recs))
	}
	assertNoTs(t, recs)
}

// 负样本:分节前的条目行属主未知 skip;"no crontab" 大小写不敏感。
func TestLinuxCronAllPreSection(t *testing.T) {
	path := writePersist(t, "Persistence/crontab_all_users.txt",
		"1 2 3 4 5 /bin/orphan.sh\n"+
			"===== bob =====\n"+
			"No Crontab For bob\n")
	recs := collectPersist(t, LinuxCronAllParser{}, path)
	if recs[0].Kind != model.KindSkip || recs[0].Reason == nil ||
		*recs[0].Reason != "分节外条目行,属主未知" {
		t.Fatalf("节前条目应 skip: %+v", recs[0])
	}
	evs := eventsOf(recs)
	if len(evs) != 1 || evs[0].Norm["section_empty"] != "true" ||
		evs[0].Norm["user"] != "bob" {
		t.Fatalf("大小写不敏感 no crontab 未识别: %v", evs)
	}
}

// ---- linux_cron_sys ----

// 正样本:系统 crontab 带 user 列;负样本:缺列垃圾行 skip。
func TestLinuxCronSysParser(t *testing.T) {
	path := writePersist(t, "Persistence/etc/crontab",
		"SHELL=/bin/sh\n"+
			"# m h dom mon dow user command\n"+
			"17 * * * * root cd / && run-parts /etc/cron.hourly\n"+
			"@reboot www-data /opt/app/start.sh -d\n"+
			"bad line here\n")
	recs := collectPersist(t, LinuxCronSysParser{}, path)
	evs := eventsOf(recs)
	if len(evs) != 2 {
		t.Fatalf("事件数 = %d, want 2(recs=%v)", len(evs), recs)
	}
	e := evs[0].Norm
	if e["source"] != "cron_sys" || e["file"] != "crontab" ||
		e["schedule"] != "17 * * * *" ||
		e["user"] != "root" || e["command"] != "cd / && run-parts /etc/cron.hourly" {
		t.Fatalf("系统 crontab 条目错: %v", e)
	}
	e = evs[1].Norm
	if e["schedule"] != "@reboot" || e["user"] != "www-data" ||
		e["command"] != "/opt/app/start.sh -d" {
		t.Fatalf("@reboot 条目错: %v", e)
	}
	if recs[4].Kind != model.KindSkip || *recs[4].Reason != "非 cron 条目行" {
		t.Fatalf("垃圾行应 skip: %+v", recs[4])
	}
	assertNoTs(t, recs)
}

// cron.d 下的文件:source 恒 cron_sys(规则分流锚点),file=文件基名。
func TestLinuxCronSysCronD(t *testing.T) {
	path := writePersist(t, "Persistence/etc/cron.d/sysstat",
		"*/10 * * * * root /usr/lib/sa/sa1 1 1\n")
	evs := eventsOf(collectPersist(t, LinuxCronSysParser{}, path))
	if len(evs) != 1 || evs[0].Norm["source"] != "cron_sys" ||
		evs[0].Norm["file"] != "sysstat" {
		t.Fatalf("cron.d source/file 错: %v", evs)
	}
}

// ---- linux_anacrontab ----

func TestLinuxAnacrontabParser(t *testing.T) {
	path := writePersist(t, "Persistence/etc/anacrontab",
		"# /etc/anacrontab\n"+
			"HOME=/root\n"+
			"\n"+
			"1 5 cron.daily run-parts /etc/cron.daily\n"+
			"@monthly 15 monthly-job /usr/bin/monthly.sh\n"+
			"garbage line\n")
	recs := collectPersist(t, LinuxAnacrontabParser{}, path)
	evs := eventsOf(recs)
	if len(evs) != 2 {
		t.Fatalf("事件数 = %d, want 2(recs=%v)", len(evs), recs)
	}
	e := evs[0].Norm
	if e["source"] != "anacrontab" || e["schedule"] != "1" ||
		e["delay_minutes"] != "5" || e["job_id"] != "cron.daily" ||
		e["command"] != "run-parts /etc/cron.daily" {
		t.Fatalf("anacrontab 数字周期条目错: %v", e)
	}
	if _, has := e["user"]; has {
		t.Fatalf("anacrontab 不写 user: %v", e)
	}
	e = evs[1].Norm
	if e["schedule"] != "@monthly" || e["delay_minutes"] != "15" ||
		e["job_id"] != "monthly-job" {
		t.Fatalf("@monthly 条目错: %v", e)
	}
	if recs[5].Kind != model.KindSkip {
		t.Fatalf("垃圾行应 skip: %+v", recs[5])
	}
	assertNoTs(t, recs)
}

// ---- linux_cron_spool ----

// 正样本:文件名即用户;坏行逐行 bad(丰图零静默,树庭是 summary)。
func TestLinuxCronSpoolParser(t *testing.T) {
	path := writePersist(t, "Persistence/var/spool/cron/crontabs/root",
		"# DO NOT EDIT\n"+
			"MAILTO=root\n"+
			"*/5 * * * * /usr/bin/php /var/www/cron.php\n"+
			// 真坏行:不足五段时间字段(「this is not a cron line !!」是
			// 5 token+命令,按树庭正则合法匹配,不算坏行——别拿它当负样本)
			"* * * root cmd\n")
	recs := collectPersist(t, LinuxCronSpoolParser{}, path)
	evs := eventsOf(recs)
	if len(evs) != 1 {
		t.Fatalf("事件数 = %d, want 1(recs=%v)", len(evs), recs)
	}
	e := evs[0].Norm
	if e["source"] != "cron_spool" || e["user"] != "root" ||
		e["schedule"] != "*/5 * * * *" || e["command"] != "/usr/bin/php /var/www/cron.php" {
		t.Fatalf("spool 条目错: %v", e)
	}
	// 坏行:Kind=bad + Reason,不静默、不加 summary
	if recs[3].Kind != model.KindBad || *recs[3].Reason != "cron spool 坏行" {
		t.Fatalf("坏行应 bad: %+v", recs[3])
	}
	for _, r := range recs {
		if r.Norm["bad_lines"] != nil {
			t.Fatalf("丰图不产 summary 事件: %+v", r)
		}
	}
	assertNoTs(t, recs)
}

// ---- linux_systemd ----

// 正样本:续行拼接 + 多 ExecStart + User/Type/Description/WantedBy。
func TestLinuxSystemdUnitParser(t *testing.T) {
	content := "[Unit]\n" +
		"Description=Test Daemon\n" +
		"; 分号注释\n" +
		"\n" +
		"[Service]\n" +
		"Type=simple\n" +
		"ExecStart=/usr/bin/daemon \\\n" +
		"  --flag1 \\\n" +
		"  --flag2\n" +
		"ExecStartPre=/bin/pre-run\n" +
		"ExecStart=/usr/bin/second %i\n" +
		"User=www\n" +
		"\n" +
		"[Install]\n" +
		"WantedBy=multi-user.target\n"
	path := writePersist(t, "Persistence/etc/systemd/system/testd.service", content)
	recs := collectPersist(t, LinuxSystemdUnitParser{}, path)
	if len(recs) != 1 || recs[0].Kind != model.KindEvent {
		t.Fatalf("一文件一条事件: %+v", recs)
	}
	r := recs[0]
	if r.LineNo != 1 {
		t.Fatalf("LineNo = %d, want 1", r.LineNo)
	}
	e := r.Norm
	if e["source"] != "testd.service" || e["unit"] != "testd.service" {
		t.Fatalf("source/unit 错: %v", e)
	}
	if e["description"] != "Test Daemon" || e["type"] != "simple" || e["user"] != "www" {
		t.Fatalf("描述/类型/用户错: %v", e)
	}
	// 续行拼接:拼接点不加空格;同名键保序 "\n" join;specifier 原样
	want := "/usr/bin/daemon --flag1 --flag2\n/usr/bin/second %i"
	if e["exec_start"] != want {
		t.Fatalf("exec_start = %q, want %q", e["exec_start"], want)
	}
	if e["exec_start_pre"] != "/bin/pre-run" {
		t.Fatalf("exec_start_pre 错: %v", e)
	}
	if e["wanted_by"] != "multi-user.target" {
		t.Fatalf("wanted_by 错: %v", e)
	}
	secs, ok := e["sections"].([]string)
	if !ok || strings.Join(secs, ",") != "Install,Service,Unit" {
		t.Fatalf("sections 排序错: %v", e["sections"])
	}
	if len([]rune(r.Raw)) > 2000 || !strings.Contains(r.Raw, "Description=Test Daemon") {
		t.Fatalf("Raw 留证错: %q", r.Raw)
	}
	assertNoTs(t, recs)
}

// timer 单元:on_calendar 提取;无 Service 节不写 type/user。
func TestLinuxSystemdTimerParser(t *testing.T) {
	path := writePersist(t, "Persistence/etc/systemd/system/logrotate.timer",
		"[Unit]\nDescription=Daily rotation\n\n"+
			"[Timer]\nOnCalendar=daily\nOnCalendar=*-*-* 02:00:00\n\n"+
			"[Install]\nWantedBy=timers.target\nRequiredBy=basic.target\n")
	evs := eventsOf(collectPersist(t, LinuxSystemdUnitParser{}, path))
	if len(evs) != 1 {
		t.Fatalf("事件数 = %d, want 1", len(evs))
	}
	e := evs[0].Norm
	if e["on_calendar"] != "daily\n*-*-* 02:00:00" {
		t.Fatalf("on_calendar 错: %v", e)
	}
	if e["required_by"] != "basic.target" {
		t.Fatalf("required_by 错: %v", e)
	}
	if _, has := e["type"]; has {
		t.Fatalf("无 Service 节不应有 type: %v", e)
	}
}

// ---- linux_systemd_dropin ----

// 正样本:drop-in ExecStart 覆盖(持久化抓手)+ directives_text 留存;
// 无续行处理(行尾 \ 原样进值)。
func TestLinuxSystemdDropinParser(t *testing.T) {
	path := writePersist(t, "Persistence/etc/systemd/system/sshd.service.d/override.conf",
		"# override\n"+
			"[Service]\n"+
			"ExecStart=\n"+
			"ExecStart=/usr/sbin/sshd -D $OPTIONS\n")
	recs := collectPersist(t, LinuxSystemdDropinParser{}, path)
	if len(recs) != 1 {
		t.Fatalf("一文件一条事件: %+v", recs)
	}
	e := recs[0].Norm
	if e["source"] != "override.conf" || e["unit"] != "override.conf" ||
		e["drop_in"] != "true" {
		t.Fatalf("dropin 基本字段错: %v", e)
	}
	// 同名键保序:先清空覆盖再实值(systemd 契约)
	if e["exec_start"] != "\n/usr/sbin/sshd -D $OPTIONS" {
		t.Fatalf("dropin exec_start 错: %q", e["exec_start"])
	}
	dt, ok := e["directives_text"].(string)
	if !ok || !strings.Contains(dt, "Service.ExecStart=/usr/sbin/sshd -D $OPTIONS") {
		t.Fatalf("directives_text 错: %v", e["directives_text"])
	}
	secs, _ := e["sections"].([]string)
	if len(secs) != 1 || secs[0] != "Service" {
		t.Fatalf("dropin sections 错: %v", e["sections"])
	}
	assertNoTs(t, recs)
}

// ---- linux_udev ----

// 正样本:RUN/PROGRAM/has_exec=false 行都产事件;注释空行 skip。
func TestLinuxUdevParser(t *testing.T) {
	path := writePersist(t, "Persistence/etc/udev/rules.d/99-evil.rules",
		"# comment\n"+
			"\n"+
			`ACTION=="add", SUBSYSTEM=="usb", RUN+="/usr/bin/logger plug" PROGRAM="/bin/id"`+"\n"+
			`KERNEL=="sda", MODE="0660"`+"\n"+
			`ACTION=="add", IMPORT{program}="/sbin/blkid -o udev -p $tempnode"`+"\n")
	recs := collectPersist(t, LinuxUdevParser{}, path)
	evs := eventsOf(recs)
	if len(evs) != 3 {
		t.Fatalf("事件数 = %d, want 3(非注释行全产): %v", len(evs), recs)
	}
	e := evs[0].Norm
	if e["source"] != "99-evil.rules" || e["rule_file"] != "99-evil.rules" ||
		e["has_exec"] != "true" || e["run"] != "/usr/bin/logger plug" ||
		e["program"] != "/bin/id" {
		t.Fatalf("RUN/PROGRAM 行错: %v", e)
	}
	if e["raw"] != `ACTION=="add", SUBSYSTEM=="usb", RUN+="/usr/bin/logger plug" PROGRAM="/bin/id"` {
		t.Fatalf("raw 整行留证错: %v", e)
	}
	e = evs[1].Norm
	if e["has_exec"] != "false" {
		t.Fatalf("无执行赋值行 has_exec 应为 \"false\": %v", e)
	}
	if _, has := e["run"]; has {
		t.Fatalf("无 RUN 不写 run: %v", e)
	}
	e = evs[2].Norm
	if e["import_program"] != "/sbin/blkid -o udev -p $tempnode" || e["has_exec"] != "true" {
		t.Fatalf("IMPORT 行错: %v", e)
	}
	assertNoTs(t, recs)
}

// ---- linux_pam ----

// 正样本:[control=bracket] / @include / pam_exec;负样本:非指令行 skip。
func TestLinuxPamParser(t *testing.T) {
	path := writePersist(t, "Persistence/etc/pam.d/sshd",
		"# PAM sshd\n"+
			"auth [success=ok new_authtok_reqd=ok] pam_unix.so\n"+
			"auth required pam_exec.so /usr/local/bin/check.sh debug\n"+
			"@include common-auth\n"+
			"Auth required pam_upper.so\n")
	recs := collectPersist(t, LinuxPamParser{}, path)
	evs := eventsOf(recs)
	if len(evs) != 3 {
		t.Fatalf("事件数 = %d, want 3(recs=%v)", len(evs), recs)
	}
	e := evs[0].Norm
	if e["source"] != "pam_d" || e["service"] != "sshd" || e["type"] != "auth" ||
		e["control"] != "[success=ok new_authtok_reqd=ok]" ||
		e["module"] != "pam_unix.so" || e["is_pam_exec"] != "false" {
		t.Fatalf("bracket control 行错: %v", e)
	}
	if _, has := e["args"]; has {
		t.Fatalf("无参数不写 args: %v", e)
	}
	e = evs[1].Norm
	if e["is_pam_exec"] != "true" || e["args"] != "/usr/local/bin/check.sh debug" ||
		e["control"] != "required" {
		t.Fatalf("pam_exec 行错: %v", e)
	}
	e = evs[2].Norm
	if e["directive"] != "@include" || e["target"] != "common-auth" ||
		e["service"] != "sshd" {
		t.Fatalf("@include 行错: %v", e)
	}
	// 大写开头非 [a-z]+ type → 不硬解,skip
	if recs[4].Kind != model.KindSkip || *recs[4].Reason != "非 PAM 指令行" {
		t.Fatalf("非指令行应 skip: %+v", recs[4])
	}
	assertNoTs(t, recs)
}

// ---- linux_shellcfg ----

// 正样本:home 用户 rc,owner 从路径推;alias 优先于 export。
func TestLinuxShellcfgParser(t *testing.T) {
	path := writePersist(t, "Persistence/home/alice/.bashrc",
		"# ~/.bashrc\n"+
			"\n"+
			"export PATH=/usr/local/bin:$PATH\n"+
			"alias ll='ls -alF'\n"+
			"HISTSIZE=1000\n")
	recs := collectPersist(t, LinuxShellConfigParser{}, path)
	if len(recs) != 1 || recs[0].Kind != model.KindEvent {
		t.Fatalf("一文件一条事件: %+v", recs)
	}
	r := recs[0]
	e := r.Norm
	if e["source"] != ".bashrc" || e["file"] != ".bashrc" || e["owner"] != "alice" {
		t.Fatalf("基本字段/owner 错: %v", e)
	}
	if e["line_count"] != 5 || e["non_comment_lines"] != 3 {
		t.Fatalf("行数留证错: %v", e)
	}
	if e["exports"] != "export PATH=/usr/local/bin:$PATH\nHISTSIZE=1000" {
		t.Fatalf("exports 错: %q", e["exports"])
	}
	if e["aliases"] != "alias ll='ls -alF'" {
		t.Fatalf("aliases 错: %q", e["aliases"])
	}
	if _, has := e["exports_truncated"]; has {
		t.Fatalf("未截断不写 exports_truncated: %v", e)
	}
	if r.LineNo != 1 || !strings.Contains(r.Raw, "alias ll") {
		t.Fatalf("Raw 留证错: %q", r.Raw)
	}
	assertNoTs(t, recs)
}

// root 段属主 + etc 下无 owner + export 上限 50 截断。
func TestLinuxShellcfgTruncation(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("# profile\n")
	for i := 0; i < 60; i++ {
		sb.WriteString("export SAME_KEY=v\n") // 收整行不查重(树庭契约),同名即可
	}
	path := writePersist(t, "Persistence/etc/profile", sb.String())
	e := eventsOf(collectPersist(t, LinuxShellConfigParser{}, path))[0].Norm
	if _, has := e["owner"]; has {
		t.Fatalf("etc/ 下不写 owner: %v", e)
	}
	if e["exports_truncated"] != "true" {
		t.Fatalf("60>50 应截断标记: %v", e)
	}
	if n := len(strings.Split(e["exports"].(string), "\n")); n != 50 {
		t.Fatalf("exports 截断条数 = %d, want 50", n)
	}

	path = writePersist(t, "Persistence/root/.bashrc", "export PS1='#'\n")
	e = eventsOf(collectPersist(t, LinuxShellConfigParser{}, path))[0].Norm
	if e["owner"] != "root" {
		t.Fatalf("root 段属主错: %v", e)
	}
}

// 注册表:9 个 parser 名可解析(映射表路由的前提)。
func TestLinuxPersistRegistered(t *testing.T) {
	for _, name := range []string{
		"linux_cron_all", "linux_cron_sys", "linux_anacrontab",
		"linux_cron_spool", "linux_systemd", "linux_systemd_dropin",
		"linux_udev", "linux_pam", "linux_shellcfg",
	} {
		if _, err := For(name); err != nil {
			t.Fatalf("%s 未注册: %v", name, err)
		}
	}
}
