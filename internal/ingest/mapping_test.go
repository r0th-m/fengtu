package ingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testMapYAML = `
name: wininfosc-test
package_root_regex: ^Forensic_[^_/]+_[^/]+$
rules:
  - match: Windows_logs/*.evtx
    artifact: windows_event_log
    route: evtx_native
  - match: _HASH_MANIFEST.txt
    artifact: hash_manifest
    route: raw
  - match: REG_*.txt
    artifact: registry_query
    route: raw
  - match: "*.csv"
    artifact: csv_snapshot
    route: raw
  - match: bound.log
    artifact: bound_log
    route: desc
    desc: bound-format
`

func loadTestMap(t *testing.T) *ArtifactMap {
	t.Helper()
	m, err := LoadArtifactMap(testMapYAML)
	if err != nil {
		t.Fatalf("映射表加载失败: %v", err)
	}
	return m
}

func TestMapping_RootRegex(t *testing.T) {
	m := loadTestMap(t)
	for _, ok := range []string{
		"Forensic_192.168.9.9_host-a", "Forensic_10.0.0.1_X", "Forensic_fd00::1_h",
	} {
		if !m.IsPackageRoot(ok) {
			t.Fatalf("应识别为采集包根: %s", ok)
		}
	}
	for _, bad := range []string{
		"random-dir", "Forensic_", "forensic_1.2.3.4_h", "Forensic_1.2.3.4",
	} {
		if m.IsPackageRoot(bad) {
			t.Fatalf("不应识别为采集包根: %s", bad)
		}
	}
}

func TestMapping_MatchFirstWins(t *testing.T) {
	m := loadTestMap(t)
	cases := []struct {
		rel      string
		artifact string
		route    Route
	}{
		{"Windows_logs/Security.evtx", "windows_event_log", RouteEVTXNative},
		{"_HASH_MANIFEST.txt", "hash_manifest", RouteRaw},
		{"REG_USB.txt", "registry_query", RouteRaw},
		{"sub/REG_LSA.txt", "registry_query", RouteRaw}, // 无 / 模式配文件名
		{"tasklist_process.csv", "csv_snapshot", RouteRaw},
		{"bound.log", "bound_log", RouteDesc},
	}
	for _, c := range cases {
		r := m.Match(c.rel)
		if r == nil {
			t.Fatalf("%s 应命中规则", c.rel)
		}
		if r.Artifact != c.artifact || r.Route != c.route {
			t.Fatalf("%s: got (%s,%s) want (%s,%s)",
				c.rel, r.Artifact, r.Route, c.artifact, c.route)
		}
	}
}

func TestMapping_UnmappedFallsBack(t *testing.T) {
	m := loadTestMap(t)
	for _, rel := range []string{"SAM", "MFT.bin", "Prefetch/XYZ.EXE-12345678.pf", "x.dat"} {
		if r := m.Match(rel); r != nil {
			t.Fatalf("%s 不应命中任何规则(兜底 unmapped)", rel)
		}
	}
}

func TestMapping_Validation(t *testing.T) {
	for _, y := range []string{
		"name: x\nrules: []\n",                           // 缺 root regex
		"name: x\npackage_root_regex: '[['\nrules: []\n", // 坏 regex
		"name: x\npackage_root_regex: x\nrules:\n- match: a\n  artifact: b\n  route: nope\n", // 坏 route
		"name: x\npackage_root_regex: x\nrules:\n- match: a\n  artifact: b\n  route: desc\n", // desc 缺名
	} {
		if _, err := LoadArtifactMap(y); err == nil {
			t.Fatalf("应拒绝非法映射表: %q", y)
		}
	}
}

// TestRealMap_AntiOverfit 真实映射表:加载有效 + 规则不得含具体主机值。
func TestRealMap_AntiOverfit(t *testing.T) {
	p := filepath.Join("..", "..", "configs", "wininfosc-map.yaml")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("真实映射表不可读: %v", err)
	}
	m, err := LoadArtifactMap(string(raw))
	if err != nil {
		t.Fatalf("真实映射表非法: %v", err)
	}
	// 防过拟合负样本:验收主机名/IP 形态的哨兵值绝不出现在规则里
	for _, host := range []string{"benchhost01", "CASEHOST99", "192.168.9.9", "10.99.0.1"} {
		if strings.Contains(string(raw), host) {
			t.Fatalf("映射表含主机特定值 %q(过拟合)", host)
		}
	}
	// 结构正样本:规范里的典型路径必须正确路由
	checks := []struct {
		rel   string
		route Route
	}{
		{"Windows_logs/System.evtx", RouteEVTXNative},
		{"_HASH_MANIFEST.txt", RouteRaw},
		{"REG_USBSTOR.txt", RouteRaw},
		{"tasklist_services.csv", RouteRaw},
		{"systeminfo.txt", RouteRaw},
	}
	for _, c := range checks {
		r := m.Match(c.rel)
		if r == nil || r.Route != c.route {
			t.Fatalf("%s 路由不符: %+v", c.rel, r)
		}
	}
	// M3 树庭面原生解析路由(parser 名随规则带出;usn 须带品类)
	nativeChecks := []struct {
		rel, parser, logType string
	}{
		{"Prefetch/ABC.EXE-DEF0.pf", "prefetch", ""},
		{"MFT.bin", "mft", ""},
		{"usn_journal_C.csv", "usn_csv", "usn_journal"},
		{"Users/test/NTUSER.DAT", "registry_hive", ""},
		{"Recent/x.lnk", "lnk", ""},
		// M3b:SAM/SECURITY 专题、SYSTEM 复合(通用+Shimcache)、新源
		{"SAM", "sam_accounts", ""},
		{"SECURITY", "security_policy", ""},
		{"SYSTEM", "system_hive", ""},
		{"SOFTWARE", "registry_hive", ""},
		{"everything.efu", "efu", ""},
		{"JumpList/abc123.automaticDestinations-ms", "jumplist", ""},
		{"Recent/CustomDestinations/abc123.customDestinations-ms", "jumplist", ""},
		{"Users/u/Browser/Edge/History", "browser_chromium_history", ""},
		{"Users/u/Browser/Firefox/p.default-release/places.sqlite",
			"browser_firefox_places", ""},
		{"SRUDB.dat", "srum", ""},
		{"ActivitiesCache/u/ActivitiesCache.db", "win_activities", ""},
	}
	for _, c := range nativeChecks {
		r := m.Match(c.rel)
		if r == nil || r.Route != RouteNative || r.Parser != c.parser ||
			r.LogType != c.logType {
			t.Fatalf("%s 原生路由不符: %+v", c.rel, r)
		}
	}
	// tasklist CSV 不得被 usn 规则抢走(首条命中即停,顺序敏感)
	if r := m.Match("tasklist_services.csv"); r == nil || r.Route != RouteRaw {
		t.Fatalf("tasklist_services.csv 被误路由: %+v", r)
	}

	// 0.25.0-datasource-unlock:PSHistory(desc)与 netstat(native)路由
	if r := m.Match("PSHistory/ConsoleHost_history.txt"); r == nil ||
		r.Route != RouteDesc || r.Desc != "pshistory" {
		t.Fatalf("PSHistory 路由不符: %+v", r)
	}
	for _, rel := range []string{"netstat.txt", "netstat_established.txt"} {
		r := m.Match(rel)
		if r == nil || r.Route != RouteNative || r.Parser != "netstat" ||
			r.LogType != "net_connection" {
			t.Fatalf("%s 路由不符: %+v", rel, r)
		}
	}
	// 负样本:近似名不抢路由(对 spec 写,不宽泛匹配)
	for _, rel := range []string{"netstat_old.txt", "PSHistory/other.txt",
		"ConsoleHost_history.txt"} {
		if r := m.Match(rel); r == nil || r.Route != RouteRaw {
			t.Fatalf("近似名 %s 被误路由: %+v", rel, r)
		}
	}
}

// TestMapping_HostRegex 主机键提取(一案多包,§3 修正稿):
// 命名组 host 命中 → 主机键;不声明/不匹配 → 空串(未建模,如实)。
func TestMapping_HostRegex(t *testing.T) {
	m, err := LoadArtifactMap(`
name: t
package_root_regex: ^Forensic_[^_/]+_[^/]+$
host_regex: ^Forensic_(?P<host>[^_/]+)_[^/]+$
rules:
  - match: "*.txt"
    artifact: text_snapshot
    route: raw
`)
	if err != nil {
		t.Fatalf("含 host_regex 的映射表应合法: %v", err)
	}
	if got := m.HostOfPackage("Forensic_10.0.0.1_alpha"); got != "10.0.0.1" {
		t.Fatalf("主机键提取错误: %q", got)
	}
	if got := m.HostOfPackage("random-dir"); got != "" {
		t.Fatalf("不匹配包名应得空串: %q", got)
	}

	// 缺命名捕获组 → 装载即拒(注册表不许说谎)
	if _, err := LoadArtifactMap(`
name: t
package_root_regex: ^Forensic_.+$
host_regex: ^Forensic_[^_/]+_[^/]+$
rules:
  - match: "*.txt"
    artifact: text_snapshot
    route: raw
`); err == nil {
		t.Fatalf("host_regex 缺 (?P<host>...) 命名组应拒载")
	}

	// 不声明 host_regex → HostOfPackage 恒空(老映射表兼容)
	plain := loadTestMap(t)
	if got := plain.HostOfPackage("Forensic_10.0.0.1_alpha"); got != "" {
		t.Fatalf("未声明 host_regex 应恒空: %q", got)
	}
}

// TestRealMap_HostRegex 真实映射表主机提取:结构性正负样本(防过拟合:
// 只断结构语义,断言里出现的样本值是测试数据,不进映射表)。
func TestRealMap_HostRegex(t *testing.T) {
	p := filepath.Join("..", "..", "configs", "wininfosc-map.yaml")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("真实映射表不可读: %v", err)
	}
	m, err := LoadArtifactMap(string(raw))
	if err != nil {
		t.Fatalf("真实映射表非法: %v", err)
	}
	if got := m.HostOfPackage("Forensic_203.0.113.9_WEB-01"); got != "203.0.113.9" {
		t.Fatalf("真实映射表主机键提取错误: %q", got)
	}
	if got := m.HostOfPackage("not-a-package"); got != "" {
		t.Fatalf("非包名应得空串: %q", got)
	}
}

// TestRealMap_LinuxSC 真实映射表的 LinuxSC 路由(0.32.0-linuxsc):
// 包根双族识别 + 各品类 native/desc 路由 + 兜底不抢单。
func TestRealMap_LinuxSC(t *testing.T) {
	p := filepath.Join("..", "..", "configs", "wininfosc-map.yaml")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("真实映射表不可读: %v", err)
	}
	m, err := LoadArtifactMap(string(raw))
	if err != nil {
		t.Fatalf("真实映射表非法: %v", err)
	}
	// 包根:LinuxSC 族识别 + 主机键提取(主机名段可含连字符)
	if !m.IsPackageRoot("LinuxSC_203.0.113.9_web-01") {
		t.Fatal("LinuxSC 包根未识别")
	}
	if got := m.HostOfPackage("LinuxSC_203.0.113.9_web-01"); got != "203.0.113.9" {
		t.Fatalf("LinuxSC 主机键提取错误: %q", got)
	}
	checks := []struct {
		rel, parser, artifact, logType string
	}{
		{"Logs/var/log/auth.log", "linux_authlog", "auth_log", "audit_log"},
		{"Logs/var/log/secure", "linux_authlog", "auth_log", "audit_log"},
		{"Logs/var/log/messages", "linux_syslog", "syslog", "app_log"},
		{"Logs/journalctl_full_shortiso.txt", "linux_journal_full", "journal_export", "app_log"},
		{"Logs/journalctl_sshd_unit.txt", "linux_journal_short", "journal_export", "app_log"},
		{"Logs/last.txt", "linux_last", "login_history", "audit_log"},
		{"Logs/lastb.txt", "linux_last", "login_history", "audit_log"},
		{"Network/ss_tuanp.txt", "linux_ss", "net_connection", "net_connection"},
		{"Network/netstat_tuanp.txt", "linux_netstat", "net_connection", "net_connection"},
		{"Network/conntrack_L.txt", "linux_conntrack", "conntrack", ""},
		{"SystemInfo/etc/passwd", "linux_passwd", "local_account", ""},
		{"Persistence/crontab_all_users.txt", "linux_cron_all", "scheduled_task", ""},
		{"Persistence/etc/crontab", "linux_cron_sys", "scheduled_task", ""},
		{"Persistence/etc/cron.d/0hourly", "linux_cron_sys", "scheduled_task", ""},
		{"Persistence/var/spool/cron/crontabs/u", "linux_cron_spool", "scheduled_task", ""},
		{"Persistence/etc/systemd/system/sshd.service", "linux_systemd", "systemd_unit", ""},
		{"Persistence/usr/lib/systemd/system/cron.service.d/override.conf",
			"linux_systemd_dropin", "systemd_unit", ""},
		{"Persistence/etc/udev/rules.d/99-x.rules", "linux_udev", "udev_rule", ""},
		{"Persistence/etc/pam.d/sshd", "linux_pam", "pam_rule", ""},
		{"Persistence/etc/profile", "linux_shellcfg", "shell_config", ""},
		{"Persistence/home/u/.bashrc", "linux_shellcfg", "shell_config", ""},
		{"SSH/root/.ssh/authorized_keys", "linux_authkeys", "ssh_key", ""},
		{"SSH/home/u/.ssh/authorized_keys2", "linux_authkeys", "ssh_key", ""},
		{"SSH/ldd_sshd.txt", "linux_sshd_libs", "sshd_lib_deps", ""},
		{"RootkitHunt/ebury_ioc_libs.txt", "linux_ebury_ioc", "ebury_ioc", ""},
		{"RecoveredBinaries/pid6921_fd34_memfd.bin", "linux_recovered", "recovered_binary", ""},
		{"RecoveredBinaries/_no_hits.txt", "linux_recovered_nohits", "recovered_binary", ""},
		{"ProcInfo/ps_auxwwf.txt", "linux_ps", "process_snapshot", ""},
		{"ProcInfo/proc_cmdline_comm_exe_compare.txt", "linux_proc_identity", "proc_identity", ""},
		{"ProcInfo/shm_tmp_listing.txt", "linux_shmtmp", "shm_tmp_listing", ""},
		{"ProcInfo/lsof_deleted_open.txt", "linux_lsof_deleted", "deleted_file_suspect", ""},
	}
	for _, c := range checks {
		r := m.Match(c.rel)
		if r == nil || r.Route != RouteNative || r.Parser != c.parser ||
			r.Artifact != c.artifact || r.LogType != c.logType {
			t.Fatalf("%s 路由不符: %+v", c.rel, r)
		}
	}
	// desc 路由:dpkg.log
	if r := m.Match("Logs/var/log/dpkg.log"); r == nil ||
		r.Route != RouteDesc || r.Desc != "linux-dpkg" {
		t.Fatalf("dpkg.log 路由不符: %+v", r)
	}
	// raw 兜底:/var/log 二进制与未接面(不被 *.txt 兜底抢先)
	for _, rel := range []string{"Logs/var/log/wtmp", "Logs/var/log/audit/audit.log",
		"Network/proc_net_raw.txt", "RootkitHunt/bpftool_prog_list.txt"} {
		r := m.Match(rel)
		if r == nil || r.Route != RouteRaw {
			t.Fatalf("%s 应落 raw 兜底: %+v", rel, r)
		}
	}
	// RecoveredBinaries/*.bin 不得被 *.bin 兜底抢走(顺序敏感)
	if r := m.Match("RecoveredBinaries/x.bin"); r == nil || r.Route != RouteNative {
		t.Fatalf("RecoveredBinaries/*.bin 被误路由: %+v", r)
	}
	// Windows 侧不受 LinuxSC 规则影响(回归闸)
	for _, rel := range []string{"Windows_logs/System.evtx", "REG_Run.txt", "systeminfo.txt"} {
		r := m.Match(rel)
		if r == nil || (rel != "Windows_logs/System.evtx" && r.Route != RouteRaw) {
			t.Fatalf("Windows 路由被 LinuxSC 规则干扰: %s → %+v", rel, r)
		}
	}
}
