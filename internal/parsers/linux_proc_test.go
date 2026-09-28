// linux_proc 进程面解析器焊死:ps 中文 START/森林前缀/11 列切分、identity
// 内核线程空列与 mismatch、shmtmp 分节/中文日期/symlink/含空格名取舍、
// lsof 9 段兜底与 10 段全列、exe_deleted/fd_memfd/maps 正则边界。
// 测试数据全部自造,不引用真实案件值。
package parsers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// collectLinuxProc 落自造样本并按指定 parser 全量收集记录。
func collectLinuxProc(t *testing.T, p Parser, name, content string) []model.Record {
	t.Helper()
	fp := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(fp, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := p.Records(fp)
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

// 正样本:中文 locale START 列(6月30)+ 森林前缀原样保留 + COMMAND 内部
// 多空格保留 + 中部重复表头也 skip + 快照型无时间。
func TestLinuxPSBasic(t *testing.T) {
	recs := collectLinuxProc(t, LinuxPSParser{}, "ps_auxwwf.txt",
		"USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"+
			"root         2  0.0  0.0      0     0 ?        S    6月30   0:00 [kthreadd]\n"+
			"root         3  0.0  0.0      0     0 ?        I<   6月30   0:00  \\_ [rcu_gp]\n"+
			"\n"+
			"  USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"+
			"thtf      4210  1.5  0.3 123456  7890 pts/0    S+   7月28   0:01 /usr/sbin/sshd  -D   -o Listen\n",
	)
	evs := eventsOf(recs)
	if len(evs) != 3 {
		t.Fatalf("事件数 = %d, want 3(recs=%v)", len(evs), recs)
	}
	e := evs[0].Norm
	if e["source"] != "ps_auxwwf" || e["user"] != "root" || e["pid"] != "2" ||
		e["cpu"] != "0.0" || e["vsz"] != "0" || e["tty"] != "?" ||
		e["stat"] != "S" || e["start"] != "6月30" || e["time"] != "0:00" ||
		e["command"] != "[kthreadd]" {
		t.Fatalf("首条字段错: %v", e)
	}
	// cmdline 同值双写(统一面)+ account 双写
	if e["cmdline"] != "[kthreadd]" || e["account"] != "root" {
		t.Fatalf("cmdline/account 双写错: %v", e)
	}
	// 森林前缀 `\_` 原样保留进 command(不剥)
	if evs[1].Norm["command"] != `\_ [rcu_gp]` {
		t.Fatalf("森林前缀未保留: %v", evs[1].Norm)
	}
	// COMMAND 内部多空格保留(树庭 split(None,10) 契约,非 Fields 压扁)
	if evs[2].Norm["command"] != "/usr/sbin/sshd  -D   -o Listen" {
		t.Fatalf("COMMAND 内部空白被压: %q", evs[2].Norm["command"])
	}
	// 表头×2 + 空行 = 3 行 skip,行账零静默
	if len(recs) != 6 {
		t.Fatalf("总行账 = %d, want 6", len(recs))
	}
	for _, r := range evs {
		if r.TsUTC != nil || r.DTLocal != nil {
			t.Fatalf("快照型不应有时间: %+v", r)
		}
	}
}

// 负样本:列数不足 skip;垃圾文件零事件。
func TestLinuxPSShort(t *testing.T) {
	recs := collectLinuxProc(t, LinuxPSParser{}, "ps_auxwwf.txt",
		"USER PID %CPU\nroot 2 0.0 0.0 0 0 ? S 6月30 0:00\n这不是 ps 输出\n")
	evs := eventsOf(recs)
	if len(evs) != 0 {
		t.Fatalf("事件数 = %d, want 0", len(evs))
	}
	if len(recs) != 3 {
		t.Fatalf("总行账 = %d, want 3(全 skip)", len(recs))
	}
}

// 正样本:TSV 契约;内核线程 cmdline/exe 空列;comm≠exe 基名标 mismatch。
func TestLinuxProcIdentityBasic(t *testing.T) {
	recs := collectLinuxProc(t, LinuxProcIdentityParser{}, "proc_cmdline_comm_exe_compare.txt",
		"PID\tCOMM\tCMDLINE\tEXE\n"+
			"1\tsystemd\t/sbin/init splash \t/usr/lib/systemd/systemd\n"+
			"2\tkthreadd\t\t\n"+
			"4210\tevild\t/tmp/.x/evild \t/usr/sbin/cron\n",
	)
	evs := eventsOf(recs)
	if len(evs) != 3 {
		t.Fatalf("事件数 = %d, want 3(recs=%v)", len(evs), recs)
	}
	e := evs[0].Norm
	if e["source"] != "proc_cmdline_comm_exe_compare" || e["pid"] != "1" ||
		e["comm"] != "systemd" || e["cmdline"] != "/sbin/init splash" ||
		e["exe"] != "/usr/lib/systemd/systemd" ||
		e["exe_missing"] != "false" || e["comm_exe_mismatch"] != "false" {
		t.Fatalf("首条字段错: %v", e)
	}
	// 内核线程:cmdline/exe 空串 → 不写;exe_missing "true";mismatch 恒 "false"
	e = evs[1].Norm
	if e["exe_missing"] != "true" || e["comm_exe_mismatch"] != "false" {
		t.Fatalf("内核线程布尔错: %v", e)
	}
	if _, has := e["cmdline"]; has {
		t.Fatalf("空 cmdline 不应落字段: %v", e)
	}
	if _, has := e["exe"]; has {
		t.Fatalf("空 exe 不应落字段: %v", e)
	}
	// comm(evild)≠ exe 基名(cron)→ mismatch
	e = evs[2].Norm
	if e["comm_exe_mismatch"] != "true" || e["exe_missing"] != "false" {
		t.Fatalf("mismatch 判定错: %v", e)
	}
}

// 负样本:首行表头才 skip;非首行 PID 开头按数据行处理;TSV 不足 4 段 skip。
func TestLinuxProcIdentityHeaderOnlyFirst(t *testing.T) {
	recs := collectLinuxProc(t, LinuxProcIdentityParser{}, "proc_cmdline_comm_exe_compare.txt",
		"1\tsystemd\t/sbin/init\t/sbin/init\n"+
			"PID\tnotheader\t\t\n"+
			"only\ttwo\n",
	)
	evs := eventsOf(recs)
	if len(evs) != 2 {
		t.Fatalf("事件数 = %d, want 2(非首行 PID 行是数据,2 段行 skip)", len(evs))
	}
	if evs[1].Norm["pid"] != "PID" {
		t.Fatalf("非首行 PID 开头应按数据行解析: %v", evs[1].Norm)
	}
}

// 正样本:分节 + 中文日期列 + symlink 行(最后 " -> " 切)+ 含空格文件名
// 只取最后一词(契约取舍)+ 目录项。
func TestLinuxShmTmpBasic(t *testing.T) {
	recs := collectLinuxProc(t, LinuxShmTmpParser{}, "shm_tmp_listing.txt",
		"== /dev/shm ==\n"+
			"总用量 0\n"+
			"drwxrwxrwt  2 root root   40 6月  30 16:03 .\n"+
			"-rw-r--r--  1 thtf    thtf     10151 7月  28 17:15 2026_209.svg\n"+
			"drwxrwxrwt  2 root root   40 7月  28 17:15 subdir\n"+
			"== /run/shm ==\n"+
			"lrwxrwxrwx  1 root root    8 7月  28 17:15 link -> /tmp/target file\n"+
			"-rw-r--r--  1 root root    5 7月  28 17:15 my evil file.sh\n",
	)
	evs := eventsOf(recs)
	if len(evs) != 4 {
		t.Fatalf("事件数 = %d, want 4(recs=%v)", len(evs), recs)
	}
	e := evs[0].Norm
	if e["source"] != "shm_tmp_listing" || e["dir"] != "/dev/shm" ||
		e["name"] != "2026_209.svg" || e["mode"] != "-rw-r--r--" ||
		e["owner"] != "thtf" || e["size"] != "10151" ||
		e["is_dir"] != "false" || e["is_symlink"] != "false" {
		t.Fatalf("普通文件字段错: %v", e)
	}
	if evs[1].Norm["is_dir"] != "true" {
		t.Fatalf("目录项 is_dir 错: %v", evs[1].Norm)
	}
	// symlink 行:无 size/is_dir 字段(树庭契约);dir 跟随新分节
	e = evs[2].Norm
	if e["dir"] != "/run/shm" || e["name"] != "link" ||
		e["link_target"] != "/tmp/target file" || e["is_symlink"] != "true" {
		t.Fatalf("symlink 字段错: %v", e)
	}
	if _, has := e["size"]; has {
		t.Fatalf("symlink 行不应有 size: %v", e)
	}
	if _, has := e["is_dir"]; has {
		t.Fatalf("symlink 行不应有 is_dir: %v", e)
	}
	// 含空格文件名:只拿最后一词(契约取舍)
	if evs[3].Norm["name"] != "file.sh" {
		t.Fatalf("含空格名取舍错: %v", evs[3].Norm)
	}
	// 分节×2/total/点行 skip 留账:8 行 = 4 事件 + 4 skip
	if len(recs) != 8 {
		t.Fatalf("总行账 = %d, want 8", len(recs))
	}
}

// 负样本:列数不足 skip;垃圾文件零事件。
func TestLinuxShmTmpShort(t *testing.T) {
	recs := collectLinuxProc(t, LinuxShmTmpParser{}, "shm_tmp_listing.txt",
		"== /tmp ==\n随便一行\n-rw-r--r-- 1 root\n")
	if n := len(eventsOf(recs)); n != 0 {
		t.Fatalf("事件数 = %d, want 0", n)
	}
}

// 正样本:10 段全列(name 含 " (deleted)" 尾缀)+ 9 段兜底 + 解析层零过滤
// (fd=txt 原样入库)+ 表头 skip。
func TestLinuxLsofDeletedBasic(t *testing.T) {
	recs := collectLinuxProc(t, LinuxLsofDeletedParser{}, "lsof_deleted_open.txt",
		"COMMAND    PID  USER   FD   TYPE DEVICE SIZE/OFF    NLINK     NAME\n"+
			"deepin-de  1215 root    9r   REG    8,5  1726154     0   657132 /usr/lib/dpkg-db/status (deleted)\n"+
			"bash       999  thtf   txt    REG    8,1     100     1 /tmp/x\n",
	)
	evs := eventsOf(recs)
	if len(evs) != 2 {
		t.Fatalf("事件数 = %d, want 2(recs=%v)", len(evs), recs)
	}
	e := evs[0].Norm
	if e["source"] != "lsof_deleted_open" || e["command"] != "deepin-de" ||
		e["pid"] != "1215" || e["user"] != "root" || e["fd"] != "9r" ||
		e["type"] != "REG" || e["size_off"] != "1726154" || e["nlink"] != "0" ||
		e["name"] != "/usr/lib/dpkg-db/status (deleted)" {
		t.Fatalf("10 段字段错: %v", e)
	}
	// 9 段兜底:name 取第 9 段;fd=txt 零过滤原样入库(规则层判可疑)
	e = evs[1].Norm
	if e["fd"] != "txt" || e["nlink"] != "1" || e["name"] != "/tmp/x" {
		t.Fatalf("9 段兜底错: %v", e)
	}
}

// 负样本:不足 9 段 skip。
func TestLinuxLsofDeletedShort(t *testing.T) {
	recs := collectLinuxProc(t, LinuxLsofDeletedParser{}, "lsof_deleted_open.txt",
		"bash 999 thtf txt REG 8,1 100 1\n")
	if n := len(eventsOf(recs)); n != 0 {
		t.Fatalf("8 段应 skip,事件数 = %d", n)
	}
}

// 正样本:行内 search(允许 ls 前段);非贪婪 exe 不含 "(deleted)";
// exe 路径含空格。
func TestLinuxProcExeDeletedBasic(t *testing.T) {
	recs := collectLinuxProc(t, LinuxProcExeDeletedParser{}, "proc_exe_deleted.txt",
		"lrwxrwxrwx 1 root root 0 7月  28 17:15 /proc/1234/exe -> /tmp/.hidden (deleted)\n"+
			"/proc/5678/exe -> /usr/bin/bash\n"+
			"/proc/9/exe -> /tmp/a b (deleted)\n",
	)
	evs := eventsOf(recs)
	if len(evs) != 2 {
		t.Fatalf("事件数 = %d, want 2(无 deleted 行不中)", len(evs))
	}
	if evs[0].Norm["pid"] != "1234" || evs[0].Norm["exe"] != "/tmp/.hidden" ||
		evs[0].Norm["source"] != "proc_exe_deleted" {
		t.Fatalf("首条字段错: %v", evs[0].Norm)
	}
	if evs[1].Norm["pid"] != "9" || evs[1].Norm["exe"] != "/tmp/a b" {
		t.Fatalf("含空格 exe 错: %v", evs[1].Norm)
	}
}

// 正样本:memfd 句柄;非 memfd 行不中。
func TestLinuxProcFdMemfdBasic(t *testing.T) {
	recs := collectLinuxProc(t, LinuxProcFdMemfdParser{}, "proc_fd_memfd.txt",
		"lrwx------ 1 root root 64 7月  28 /proc/2000/fd/3 -> /memfd:payload (deleted)\n"+
			"lrwx------ 1 root root 64 7月  28 /proc/2000/fd/4 -> /tmp/plain (deleted)\n",
	)
	evs := eventsOf(recs)
	if len(evs) != 1 {
		t.Fatalf("事件数 = %d, want 1", len(evs))
	}
	e := evs[0].Norm
	if e["source"] != "proc_fd_memfd" || e["pid"] != "2000" || e["fd"] != "3" ||
		e["memfd_name"] != "payload" {
		t.Fatalf("字段错: %v", e)
	}
}

// 正样本:整行锚定;deleted 尾缀被可选组吃掉不进 path;deleted 布尔
// 字符串化;不带 (deleted) 的行 deleted="false"。
func TestLinuxProcMapsBasic(t *testing.T) {
	recs := collectLinuxProc(t, LinuxProcMapsParser{}, "proc_maps_suspicious_exec.txt",
		"/proc/3210/maps:7f00a1b2c000-7f00a1b2e000 rwxp 00000000 00:00 0 /memfd:run (deleted)\n"+
			"/proc/3210/maps:7f00a1b2e000-7f00a1b30000 r-xp 00000000 08:01 123 /tmp/x.so\n"+
			"垃圾行不锚定 /proc/1/maps:7f00-7f20 rwxp 0 0 0 /x\n",
	)
	evs := eventsOf(recs)
	if len(evs) != 2 {
		t.Fatalf("事件数 = %d, want 2(非整行锚定不中)", len(evs))
	}
	e := evs[0].Norm
	if e["source"] != "proc_maps_suspicious_exec" || e["pid"] != "3210" ||
		e["range"] != "7f00a1b2c000-7f00a1b2e000" || e["perms"] != "rwxp" ||
		e["path"] != "/memfd:run" || e["deleted"] != "true" {
		t.Fatalf("deleted 行字段错: %v", e)
	}
	e = evs[1].Norm
	if e["path"] != "/tmp/x.so" || e["deleted"] != "false" {
		t.Fatalf("非 deleted 行字段错: %v", e)
	}
}
