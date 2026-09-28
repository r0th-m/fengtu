// Package parsers 树庭面原生解析器:registry hive(通用遍历)/ $MFT /
// Prefetch / .lnk / USN CSV(M3);EFU 文件清单 / JumpList(CFB)/ 浏览器
// SQLite(Chromium History + Firefox places)/ SRUM(ESE)/ ActivitiesCache /
// Shimcache 二进制 / SAM / SECURITY 专题 / SYSTEM 复合(M3b,全量补齐)。
//
// 语义基准 = 树庭 backend/app/parsers/(金标准,逐字段对拍,见
// tools/parsers_golden.py);格式契约全部对公开 spec 写(regf/NTFS $MFT/
// libscca/MS-SHLLINK/MS-CFB/SQLite/MS-ESENT/Mandiant ShimCacheParser/
// RegRipper samparse·auditpol·lsa + MS-LSAD/fsutil /csv),不对具体案件值写。
//
// 统一契约:
//   - 产出 model.Record 流(Stream),与 evtx 原生路径同形,进统一管线;
//   - UTC 原生时间走 TsUTCDirect 直通(树庭是 utc_to_local_ts_raw 回转
//     本地再归一;丰图管线原生支持 UTC 直通,语义等价且不再依赖时区声明);
//   - 坏文件/空 hive/截断:如实 bad 记录或打开即失败(job failed),
//     单文件失败不拖垮整包,零静默;
//   - 解析器零 CGO(regparser/go-prefetch 均为纯 Go,MAM 解压用库内
//     纯 Go LZXpress-Huffman,不用 Windows 回调变体,跨平台结果确定)。
package parsers

import (
	"fmt"
	"time"
	"unicode/utf16"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// Stream 逐记录流(与 ingest.EvtxStream 同形;行号=事件序,1 起,
// 流内已编好,管线适配器 BaseLineNo 恒 1)。
type Stream interface {
	// Next 取下一记录;ok=false 表示结束(致命错误经 Err() 暴露)。
	Next() (rec model.Record, ok bool)
	// Err 流级致命错误;无错返回 nil。
	Err() error
	// Close 释放底层句柄。
	Close() error
}

// Parser 原生解析器:打开文件返回记录流(打开期失败=文件级 fatal,
// 如实 failed;记录级损坏进 bad 记录)。
type Parser interface {
	Records(path string) (Stream, error)
}

// registry 原生解析器注册表(对 spec 写:名字即映射表 YAML 的 parser 值)。
var registry = map[string]Parser{
	// M3
	"registry_hive": HiveParser{},
	"mft":           MftParser{},
	"prefetch":      PrefetchParser{},
	"lnk":           LnkParser{},
	"usn_csv":       UsnCSVParser{},
	// M3b(全量补齐切片)
	"efu":                      EfuParser{},
	"jumplist":                 JumpListParser{},
	"browser_chromium_history": BrowserChromiumHistoryParser{},
	"browser_firefox_places":   BrowserFirefoxPlacesParser{},
	"srum":                     SrumParser{},
	"win_activities":           ActivitiesCacheParser{},
	"shimcache_hive":           ShimcacheHiveParser{},
	"sam_accounts":             SamAccountsParser{},
	"security_policy":          SecurityPolicyParser{},
	"system_hive":              SystemHiveParser{}, // 通用遍历+Shimcache 专题复合
	// 0.25.0-datasource-unlock
	"netstat": NetstatParser{}, // netstat -ano[b] 文本快照(GBK/英文通吃)

	// 0.32.0-linuxsc(LinuxSC 采集包;语义基准 = 树庭 backend/app/parsers/
	// linux_*.py,逐文件对照移植;共享件见 linux.go)
	"linux_authlog":          LinuxAuthlogParser{},         // Logs/var/log/{auth.log,secure}
	"linux_syslog":           LinuxSyslogParser{},          // Logs/var/log/{messages,syslog,cron}
	"linux_journal_full":     LinuxJournalFullParser{},     // Logs/journalctl_full_shortiso.txt
	"linux_journal_short":    LinuxJournalShortParser{},    // Logs/journalctl_{sshd_unit,xe}.txt
	"linux_last":             LinuxLastParser{},            // Logs/{last,lastb}.txt
	"linux_lastlog":          LinuxLastlogParser{},         // Logs/lastlog.txt
	"linux_yumlog":           LinuxYumlogParser{},          // Logs/var/log/yum.log
	"linux_ss":               LinuxSSParser{},              // Network/ss_tuanp.txt
	"linux_netstat":          LinuxNetstatParser{},         // Network/netstat_tuanp.txt
	"linux_conntrack":        LinuxConntrackParser{},       // Network/conntrack_L.txt
	"linux_passwd":           LinuxPasswdParser{},          // SystemInfo/etc/passwd
	"linux_group":            LinuxGroupParser{},           // SystemInfo/etc/group
	"linux_cron_all":         LinuxCronAllParser{},         // Persistence/crontab_all_users.txt
	"linux_cron_sys":         LinuxCronSysParser{},         // Persistence/etc/{crontab,cron.d/*}
	"linux_anacrontab":       LinuxAnacrontabParser{},      // Persistence/etc/anacrontab
	"linux_cron_spool":       LinuxCronSpoolParser{},       // Persistence/var/spool/cron/**
	"linux_systemd":          LinuxSystemdUnitParser{},     // Persistence/**/*.service 等单元
	"linux_systemd_dropin":   LinuxSystemdDropinParser{},   // Persistence/**/*.d/*.conf
	"linux_udev":             LinuxUdevParser{},            // Persistence/**/udev/rules.d/*.rules
	"linux_pam":              LinuxPamParser{},             // Persistence/etc/pam.d/*
	"linux_shellcfg":         LinuxShellConfigParser{},     // profile/bashrc/zshrc/用户 rc
	"linux_authkeys":         LinuxAuthorizedKeysParser{},  // SSH/**/.ssh/authorized_keys*
	"linux_sshd_config":      LinuxSshdConfigParser{},      // SSH/etc/ssh/sshd_config
	"linux_sshd_effective":   LinuxSshdEffectiveParser{},   // SSH/sshd_T_effective_config.txt
	"linux_sshd_libs":        LinuxSshdLibsParser{},        // SSH/ldd_sshd.txt
	"linux_ssh_dir_perms":    LinuxSSHDirPermsParser{},     // SSH/user_ssh_dir_permissions.txt
	"linux_ebury_ioc":        LinuxEburyIOCParser{},        // RootkitHunt/ebury_ioc_libs.txt
	"linux_recovered":        LinuxRecoveredParser{},       // RecoveredBinaries/*.bin
	"linux_recovered_nohits": LinuxRecoveredNoHitsParser{}, // RecoveredBinaries/_no_hits.txt
	"linux_ps":               LinuxPSParser{},              // ProcInfo/ps_auxwwf.txt
	"linux_proc_identity":    LinuxProcIdentityParser{},    // ProcInfo/proc_cmdline_comm_exe_compare.txt
	"linux_shmtmp":           LinuxShmTmpParser{},          // ProcInfo/shm_tmp_listing.txt
	"linux_lsof_deleted":     LinuxLsofDeletedParser{},     // ProcInfo/lsof_deleted_open.txt
	"linux_proc_exe_deleted": LinuxProcExeDeletedParser{},  // ProcInfo/proc_exe_deleted.txt
	"linux_proc_fd_memfd":    LinuxProcFdMemfdParser{},     // ProcInfo/proc_fd_memfd.txt
	"linux_proc_maps":        LinuxProcMapsParser{},        // ProcInfo/proc_maps_suspicious_exec.txt
}

// For 按名取原生解析器;未知名如实报错(不猜)。
func For(name string) (Parser, error) {
	p, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("未知原生解析器: %q(注册表见 parsers.go registry)", name)
	}
	return p, nil
}

// ---- FILETIME(100ns,UTC)→ time.Time(树庭 common.filetime_to_utc 同语义) ----

// filetimeEpochDelta 1601-01-01 → 1970-01-01 的 100ns 数。
const filetimeEpochDelta = 116444736000000000

// FiletimeToUTC FILETIME → UTC;非法值(0/负/溢出)→ false(不猜)。
func FiletimeToUTC(ft uint64) (time.Time, bool) {
	if ft == 0 || ft < filetimeEpochDelta {
		return time.Time{}, false
	}
	sec := (ft - filetimeEpochDelta) / 10_000_000
	nsec := (ft - filetimeEpochDelta) % 10_000_000 * 100
	if sec > 253402300799 { // time.Time 上限(9999-12-31),溢出如实判非法
		return time.Time{}, false
	}
	return time.Unix(int64(sec), int64(nsec)).UTC(), true
}

// FiletimeISO FILETIME → RFC3339 UTC 字符串(事件 data 留证用);
// 非法 → 空串(调用方置 nil,不猜)。
func FiletimeISO(ft uint64) string {
	if t, ok := FiletimeToUTC(ft); ok {
		return t.Format("2006-01-02T15:04:05Z")
	}
	return ""
}

// utf16le UTF-16LE 字节串 → string(utf16.Decode 正经解代理对;
// 奇数字节截尾——UTF-16 最小单元 2 字节)。
func utf16le(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return string(utf16.Decode(u16))
}

// cstr16 UTF-16LE 串按首个 NUL 截断(prefetch 可执行名等定长 NUL 填槽)。
func cstr16(b []byte) string {
	s := utf16le(b)
	for i, r := range s {
		if r == 0 {
			return s[:i]
		}
	}
	return s
}
