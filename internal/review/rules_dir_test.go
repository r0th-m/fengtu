// 真实规则目录焊死:configs/rules 全量装载——索图系 11 条 + 树庭系
// (0.22.0 迁 12 条 + 0.25.0-datasource-unlock 迁 16 条:PSHistory 7 +
// netstat 4 + 实体层 5 + 0.32.0-linuxsc 迁 28 条:LinuxSC 数据源解锁,
// 逐条核对锚字段在丰图解析产物中存在)+ 0.32.1-case-distilled 1 条
// (案件蒸馏,account-mgmt-system-subject)。
// target ∈ any|entity(其余分类待 log_type 落地,写别的拒载);
// 抽验子串数防迁移缩水(与树庭/索图源文件逐条核对过的数;
// 实体规则 min_hosts 是保留键非字段条件,不计子串)。
package review

import (
	"path/filepath"
	"testing"
)

func TestRealRulesDir_Builtin(t *testing.T) {
	rules, err := LoadRulesDir(filepath.Join("..", "..", "configs", "rules"))
	if err != nil {
		t.Fatalf("真实规则目录装载失败: %v", err)
	}
	byID := map[string]*Rule{}
	for _, r := range rules {
		byID[r.ID] = r
		if r.Target != "any" && r.Target != "entity" {
			t.Fatalf("规则 %s target 须为 any|entity(其余待 log_type 落地,写别的拒载)", r.ID)
		}
	}
	// 23 条:索图系 11 + 树庭系 12
	want := map[string]int{ // id → match 子串总数(防缩水抽验)
		// 索图系(0.21.0 已迁)
		"scanner-ua":              14,
		"abnormal-method":         4,
		"cmd-exec-params":         13,
		"path-traversal":          7,
		"sensitive-path":          10,
		"sqli-time-based":         5,
		"sqli-union-select":       7,
		"waf-checker-ua":          1,
		"webshell-filename":       12,
		"xss-javascript-protocol": 2,
		"xss-script-handler":      9,
		// 树庭系(0.22.0 迁移;值为树庭源文件逐条核对数)
		"exfil-compression-tool-prefetch":   9, // exe_name 9
		"lateral-service-installed":         2, // channel+event_id
		"lateral-service-writable-dir":      6, // channel+event_id+路径 4
		"lateral-remote-task-created":       2,
		"lateral-remote-exec-tool-prefetch": 6, // exe_name 6
		"ransom-security-log-cleared":       2,
		"ransom-shadow-delete-cmdline":      6, // channel+event_id+命令 4
		"ransom-shadow-tool-prefetch":       3, // exe_name 3
		"suspicious-run-key-non-system-dir": 7, // 键位 1+路径 6
		"browser-extension-forcelist":       1,
		"miner-service-writable-dir":        7, // 键位+值名+路径 5
		"miner-known-tool-prefetch":         9, // exe_name 9
		// 树庭系 0.25.0-datasource-unlock(PSHistory 7 + netstat 4 + 实体层 5)
		"exfil-archive-create-cmdline":    5,
		"exfil-encrypted-archive-cmdline": 5,
		"exfil-upload-tool-cmdline":       8,
		"lateral-recon-cmdline":           5,
		"ransom-shadow-delete-pshistory":  4,
		"miner-stratum-url-cmdline":       3,
		"miner-tool-flags-cmdline":        4,
		"exfil-transfer-port-outbound":    7,  // 端口 6+state
		"lateral-admin-port-connection":   5,  // 端口 4+state
		"linux-lateral-internal-ssh-conn": 4,  // 端口+state+前缀 2
		"miner-pool-port-outbound":        7,  // 端口 6+state
		"exfil-cloud-storage-domain":      16, // entity_type+域名 15
		"miner-pool-domain-entity":        10, // entity_type+域名 9
		"xhost-shared-public-ip":          2,  // entity_type+qualifier
		"xhost-shared-account-sid":        2,
		"xhost-shared-file-hash":          2,
		// 树庭系 0.32.0-linuxsc(LinuxSC 数据源解锁 28 条;source/unit
		// 分流替代树庭 target=event_type;值为逐条核对数)
		"linux-sshd-accepted-authlog":         3,  // source+action+src_ip
		"linux-sshd-accepted-journal":         4,  // unit 2(sshd+sshd-session)+action+src_ip
		"linux-lateral-root-accepted-authlog": 4,  // +user
		"linux-lateral-root-accepted-journal": 5,  // +user
		"linux-lateral-tunnel-tool-cmdline":   7,  // source+工具 6
		"linux-conntrack-unreplied-out":       2,  // state+flags
		"linux-uid0-account":                  2,  // source+uid
		"linux-empty-password-account":        2,  // source+empty_password(派生)
		"linux-cron-suspicious-exec":          10, // source 4+命令 6
		"linux-systemd-suspicious-path":       3,
		"linux-udev-exec-shm":                 2, // has_exec+raw
		"linux-pam-exec-hook":                 1,
		"linux-ld-preload-export":             1,
		"linux-ssh-suspicious-authkey":        4, // risk_flags 4 标
		"linux-memfd-recovered-binary":        2, // source+kind
		"linux-ebury-libns2":                  2, // source+path
		"linux-ebury-sshd-lib":                2, // source+is_ioc
		"linux-miner-known-tool-cmdline":      6, // source+矿工 5
		"linux-miner-stratum-cmdline":         4, // source+协议 3
		"linux-miner-pool-port-conntrack":     6, // 矿池端口 6
		"linux-miner-proc-exe-writable":       4, // source+目录 3
		"linux-exfil-archive-cmdline":         6, // source+打包 5
		"linux-exfil-copy-cmdline":            3, // source+scp/rsync
		"linux-exfil-upload-cmdline":          6, // source+上传 5
		"linux-exfil-shmtmp-archive":          7, // source+扩展名 6(_endswith)
		"linux-ransom-note-shmtmp":            7, // source+勒索信特征 6
		"linux-ransom-deleted-held-file":      4, // source+type+nlink+name_prefix
		"linux-ransom-destructive-cmdline":    9, // source+破坏命令 8
		// 0.32.1-case-distilled(案件蒸馏:SYSTEM 免登录通道候选)
		"account-mgmt-system-subject": 9, // channel+event_id 6+data 2
	}
	if len(rules) != len(want) {
		t.Fatalf("规则数应为 %d(实得 %d)", len(want), len(rules))
	}
	for id, subs := range want {
		r := byID[id]
		if r == nil {
			t.Fatalf("规则 %s 未装载", id)
		}
		n := 0
		for _, fm := range r.Match {
			n += len(fm.Subs)
		}
		if n != subs {
			t.Fatalf("规则 %s 子串数 %d ≠ 源 %d(迁移缩水?)", id, n, subs)
		}
	}
}
