// 切片七 M1 收尾算子焊死(合成正负样本,全部对 spec 写——事件号/路径
// 白名单/阈值走 YAML params;IP 用文档保留段,主机/账户/路径用通用名,
// 无任何案件值)。
package operator

import (
	"fmt"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ye-mengwen/fengtu/internal/query"
)

// evtxData 合成 evtx 事件(event_id 顶层 + 语义字段同层,与 evtx 原生
// 解析器归一输出同形)。
func evtxData(t *testing.T, srcID string, line int, eid int64, data map[string]any) query.Event {
	m := map[string]any{"event_id": eid, "computer": "WS-T"}
	for k, v := range data {
		m[k] = v
	}
	return query.Event{SourceID: srcID, LineNo: line, TS: tsAt(line), Kind: "event",
		Fields: fieldsJSON(t, m)}
}

func TestServiceInstall(t *testing.T) {
	spec := compileSpec(t, `
id: host-service-install
title: x
family: host
severity: high
applicable_to: {log_types: [windows_event_log]}
params:
  events: ["7045"]
  writable_dir_patterns: ['(?i)\\appdata\\', '(?i)\\temp\\', '(?i)\\programdata\\']
implemented: true
`)
	src := Source{ID: "s-sys", Kind: "evtx", LogType: "windows_event_log"}
	evs := []query.Event{
		// 正:映像落可写目录 → 两翼咬合强疑似
		evtxData(t, "s-sys", 1, 7045, map[string]any{
			"ServiceName": "updsvc", "ImagePath": `C:\Users\pub\AppData\Local\Temp\u.exe`,
			"StartType": "2", "ServiceStartAccount": "LocalSystem"}),
		// 正:普通路径 7045 → 单点疑似(v1 lateral-service-installed 语义)
		evtxData(t, "s-sys", 2, 7045, map[string]any{
			"ServiceName": "legit", "ImagePath": `C:\Program Files\app\svc.exe`}),
		evtxData(t, "s-sys", 3, 7040, map[string]any{"ServiceName": "x"}), // 非 7045
		evtxData(t, "s-sys", 4, 7045, map[string]any{}),                    // 无语义字段不判
	}
	findings, err := impls["host-service-install"].Run(spec, []Source{src}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("应 2 命中(可写目录+普通各一): %+v", findings)
	}
	if gradeOf(t, findings[0]) != GradeStrong {
		t.Fatalf("可写目录翼应为强疑似: %s", gradeOf(t, findings[0]))
	}
	if gradeOf(t, findings[1]) != GradeSuspect {
		t.Fatalf("普通 7045 应为疑似: %s", gradeOf(t, findings[1]))
	}
	if findings[0].Detail["image_path"] == "" || findings[0].Detail["writable_dir_hit"] == "" {
		t.Fatalf("detail 未直给原始量: %+v", findings[0].Detail)
	}
}

func TestProcessTreeAnomaly(t *testing.T) {
	spec := compileSpec(t, `
id: host-process-tree
title: x
family: host
severity: medium
applicable_to: {log_types: [windows_event_log]}
params:
  events: ["4688"]
  lookalike_targets: [svchost, lsass]
  system_dirs: ['c:\windows\system32\']
implemented: true
`)
	src := Source{ID: "s-sec", Kind: "evtx", LogType: "windows_event_log"}
	evs := []query.Event{
		// 正:精确同名但位置异常(两翼咬合强疑似)
		evtxData(t, "s-sec", 1, 4688, map[string]any{
			"NewProcessName": `C:\Users\pub\svchost.exe`}),
		// 正:形近名(edit1)落在系统目录也判(白名单护真名不护形近)
		evtxData(t, "s-sec", 2, 4688, map[string]any{
			"NewProcessName": `C:\Windows\System32\svch0st.exe`}),
		// 负:真系统进程在系统目录
		evtxData(t, "s-sec", 3, 4688, map[string]any{
			"NewProcessName": `C:\Windows\System32\svchost.exe`}),
		// 负:非目标进程
		evtxData(t, "s-sec", 4, 4688, map[string]any{
			"NewProcessName": `C:\Users\pub\notepad2.exe`}),
		// 负:无路径(内核进程)不判,不猜
		evtxData(t, "s-sec", 5, 4688, map[string]any{"NewProcessName": "Registry"}),
	}
	findings, err := impls["host-process-tree"].Run(spec, []Source{src}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("应 2 命中(错位同名+形近名): %+v", findings)
	}
	if gradeOf(t, findings[0]) != GradeStrong ||
		findings[0].Detail["similarity"] != "exact" {
		t.Fatalf("错位同名应为强疑似: %+v", findings[0].Detail)
	}
	if gradeOf(t, findings[1]) != GradeSuspect ||
		findings[1].Detail["similarity"] != "edit1" {
		t.Fatalf("形近名应为疑似: %+v", findings[1].Detail)
	}
}

func TestTimeCluster(t *testing.T) {
	spec := compileSpec(t, `
id: host-time-cluster
title: x
family: host
severity: high
applicable_to: {log_types: [usn_journal]}
params:
  window_seconds: 300
  min_events: 100
  reason_bits: 8967
  ext_exclude: [tmp, log]
implemented: true
`)
	src := Source{ID: "s-usn", LogType: "usn_journal"}
	mk := func(line, sec int, name, reasonHex string) query.Event {
		return query.Event{SourceID: "s-usn", LineNo: line, TS: tsAt(sec), Kind: "event",
			Fields: fieldsJSON(t, map[string]any{
				"path": name, "extras": map[string]any{"reason_hex": reasonHex}})}
	}
	var evs []query.Event
	// 正:120 条 .locked 写在 200 秒窗内(0x2=DATA_EXTEND)
	for i := 0; i < 120; i++ {
		evs = append(evs, mk(1000+i, i, "doc"+strconv.Itoa(i)+".locked", "0x00000002"))
	}
	// 负样本混入:底噪后缀(.tmp 排除)/非写原因(0x4000 INDEXABLE_CHANGE)
	for i := 0; i < 50; i++ {
		evs = append(evs, mk(2000+i, i, "cache"+strconv.Itoa(i)+".tmp", "0x00000002"))
		evs = append(evs, mk(3000+i, i, "meta"+strconv.Itoa(i)+".ini", "0x00004000"))
	}
	// 每小时一条的正常写:最密窗远不达阈
	for i := 0; i < 20; i++ {
		evs = append(evs, mk(4000+i, 3600*i, "note"+strconv.Itoa(i)+".txt", "0x00000002"))
	}
	findings, err := impls["host-time-cluster"].Run(spec, []Source{src}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("应只报最密一簇: %+v", findings)
	}
	f := findings[0]
	if f.Detail["events_in_window"].(int) < 120 {
		t.Fatalf("簇规模不符: %+v", f.Detail)
	}
	exts := f.Detail["ext_breakdown"].(map[string]int)
	if exts["locked"] != 120 {
		t.Fatalf("后缀分布未直给: %+v", exts)
	}
	if gradeOf(t, f) != GradeWeak {
		t.Fatalf("统计依据应为弱信号: %s", gradeOf(t, f))
	}
	// 负:去掉密集簇后零命中
	evs = evs[120:]
	findings, err = impls["host-time-cluster"].Run(spec, []Source{src}, streamOf(evs))
	if err != nil || len(findings) != 0 {
		t.Fatalf("无密集窗应零命中: %v %+v", err, findings)
	}
}

func TestCredentialFace(t *testing.T) {
	spec := compileSpec(t, `
id: host-credential-face
title: x
family: host
severity: high
applicable_to: {log_types: [windows_event_log]}
params:
  explicit_events: ["4648"]
  sam_events: ["4656", "4663"]
  sam_object_patterns: ['(?i)\\REGISTRY\\MACHINE\\(SAM|SECURITY)']
  sam_process_allowlist: ['(?i)\\(lsass|winlogon)\.exe$']
implemented: true
`)
	src := Source{ID: "s-sec", Kind: "evtx", LogType: "windows_event_log"}
	evs := []query.Event{
		// 正:4648 显式凭据打远端
		evtxData(t, "s-sec", 1, 4648, map[string]any{
			"SubjectUserName": "alice", "TargetUserName": "admin",
			"TargetServerName": "198.51.100.9", "ProcessName": `C:\Windows\System32\cmd.exe`}),
		// 正:非系统进程碰 SAM(两翼咬合 → 强疑似)
		evtxData(t, "s-sec", 2, 4663, map[string]any{
			"ObjectName": `\REGISTRY\MACHINE\SAM`, "ProcessName": `C:\Tools\dump.exe`,
			"SubjectUserName": "bob"}),
		// 负:4648 localhost 结构性排除
		evtxData(t, "s-sec", 3, 4648, map[string]any{
			"TargetUserName": "x", "TargetServerName": "localhost"}),
		// 负:lsass 访问 SAM 是常态(白名单)
		evtxData(t, "s-sec", 4, 4663, map[string]any{
			"ObjectName": `\REGISTRY\MACHINE\SAM`,
			"ProcessName": `C:\Windows\System32\lsass.exe`}),
		// 负:4663 其他对象
		evtxData(t, "s-sec", 5, 4663, map[string]any{
			"ObjectName": `C:\docs\a.txt`, "ProcessName": `C:\x.exe`}),
	}
	findings, err := impls["host-credential-face"].Run(spec, []Source{src}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("应 2 命中(4648 远端 + SAM 非系统进程): %+v", findings)
	}
	if findings[0].Detail["wing"] != "explicit_credential" ||
		gradeOf(t, findings[0]) != GradeSuspect {
		t.Fatalf("4648 翼不符: %+v", findings[0].Detail)
	}
	if findings[1].Detail["wing"] != "sam_access" ||
		gradeOf(t, findings[1]) != GradeStrong {
		t.Fatalf("SAM 翼应为强疑似: %+v", findings[1].Detail)
	}
}

// ---- Web 族余量三算子 ----

func webFieldsEvent(srcID string, line int, ip, ua, path, bytes string, ts *time.Time) query.Event {
	return query.Event{SourceID: srcID, LineNo: line, TS: ts, Kind: "event",
		Raw:    ip + " " + path,
		Fields: fmt.Sprintf(`{"src_ip":%q,"ua":%q,"path":%q,"bytes":%q}`, ip, ua, path, bytes)}
}

func TestKeyDivergence(t *testing.T) {
	spec := compileSpec(t, `
id: web-key-divergence
title: x
family: web
severity: low
applicable_to: {log_types: [web_access]}
params:
  key_field: src_ip
  dimension: ua
  min_distinct: 50
implemented: true
`)
	src := Source{ID: "s-web", LogType: "web_access"}
	var evs []query.Event
	for i := 0; i < 60; i++ { // 正:单 IP 60 种 UA
		evs = append(evs, webFieldsEvent("s-web", i, "203.0.113.10",
			"agent-"+strconv.Itoa(i), "/a", "10", tsAt(i)))
	}
	for i := 0; i < 10; i++ { // 负:另一 IP 只有 2 种 UA
		evs = append(evs, webFieldsEvent("s-web", 100+i, "203.0.113.11",
			"ua-"+strconv.Itoa(i%2), "/a", "10", tsAt(100+i)))
	}
	findings, err := impls["web-key-divergence"].Run(spec, []Source{src}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].MatchedValue != "203.0.113.10" {
		t.Fatalf("同键分化命中不符: %+v", findings)
	}
	if findings[0].Detail["distinct_values"].(int) != 60 ||
		gradeOf(t, findings[0]) != GradeWeak {
		t.Fatalf("detail/档位不符: %+v", findings[0].Detail)
	}
}

func TestCrossKeySameValue(t *testing.T) {
	spec := compileSpec(t, `
id: web-cross-key-same-value
title: x
family: web
severity: low
applicable_to: {log_types: [web_access]}
params:
  value_field: ua
  key_field: src_ip
  min_keys: 3
  max_df: 5
  exclude_value_patterns: ['(?i)^mozilla/5\.0.*(chrome|safari)']
implemented: true
`)
	src := Source{ID: "s-web", LogType: "web_access"}
	var evs []query.Event
	// 正:稀有 UA 跨 3 IP(df=3)
	for i, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		evs = append(evs, webFieldsEvent("s-web", i, ip, "rarebot/9.9", "/x", "1", tsAt(i)))
	}
	// 负:主流浏览器 UA 跨 5 IP(结构性排除)
	for i := 0; i < 5; i++ {
		evs = append(evs, webFieldsEvent("s-web", 10+i,
			"203.0.113.1"+strconv.Itoa(i),
			"Mozilla/5.0 (Windows NT 10.0) Chrome/120.0 Safari/537.36", "/y", "1", tsAt(10+i)))
	}
	// 负:稀有 UA 只跨 2 IP(不达 min_keys)
	for i, ip := range []string{"203.0.113.8", "203.0.113.9"} {
		evs = append(evs, webFieldsEvent("s-web", 20+i, ip, "two-only/1.0", "/z", "1", tsAt(20+i)))
	}
	// 负:值跨 3 键但 df=6 超 max_df(不稀有)
	for i := 0; i < 6; i++ {
		evs = append(evs, webFieldsEvent("s-web", 30+i,
			"203.0.113.2"+strconv.Itoa(i%3), "common-tool/1.0", "/w", "1", tsAt(30+i)))
	}
	findings, err := impls["web-cross-key-same-value"].Run(spec, []Source{src}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].MatchedValue != "rarebot/9.9" {
		t.Fatalf("异键同值命中不符: %+v", findings)
	}
	f := findings[0]
	if f.Detail["key_count"].(int) != 3 || f.Detail["df"].(int) != 3 {
		t.Fatalf("detail 未直给键数/df: %+v", f.Detail)
	}
	if gradeOf(t, f) != GradeStrong {
		t.Fatalf("≥2 独立键+同值咬合应为强疑似: %s", gradeOf(t, f))
	}
}

func TestSizeOutlier(t *testing.T) {
	spec := compileSpec(t, `
id: web-outlier
title: x
family: web
severity: low
applicable_to: {log_types: [web_access]}
params:
  key_field: path
  bytes_field: bytes
  ratio: 3.0
  min_samples: 10
implemented: true
`)
	src := Source{ID: "s-web", LogType: "web_access"}
	var evs []query.Event
	// /api:10 条 100 字节 + 2 条 1000 字节(比率 10 ≥ 3)
	for i := 0; i < 10; i++ {
		evs = append(evs, webFieldsEvent("s-web", i, "203.0.113.1", "ua", "/api", "100", tsAt(i)))
	}
	evs = append(evs, webFieldsEvent("s-web", 10, "203.0.113.1", "ua", "/api", "1000", tsAt(10)))
	evs = append(evs, webFieldsEvent("s-web", 11, "203.0.113.1", "ua", "/api", "1000", tsAt(11)))
	// /big:9 条(样本不足,不判)
	for i := 0; i < 9; i++ {
		evs = append(evs, webFieldsEvent("s-web", 20+i, "203.0.113.1", "ua", "/big",
			strconv.Itoa(100+i*500), tsAt(20+i)))
	}
	findings, err := impls["web-outlier"].Run(spec, []Source{src}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].MatchedValue != "/api" {
		t.Fatalf("尺寸离群命中不符: %+v", findings)
	}
	f := findings[0]
	if f.Detail["median_bytes"].(float64) != 100 || f.Detail["outlier_count"].(int) != 2 {
		t.Fatalf("detail 未直给中位数/离群数: %+v", f.Detail)
	}
	if gradeOf(t, f) != GradeWeak {
		t.Fatalf("统计依据应为弱信号: %s", gradeOf(t, f))
	}
}

// TestRealRegistry_AllImplemented 真实注册表:切片七后全部算子已实现
// (清单无「谎话」也无「空挂」)。
func TestRealRegistry_AllImplemented(t *testing.T) {
	reg, err := LoadDir(filepath.Join("..", "..", "configs", "operators"))
	if err != nil {
		t.Fatalf("真实注册表装载失败: %v", err)
	}
	want := []string{
		"web-bruteforce-chain", "web-sequence-chain", "web-beacon-periodicity",
		"web-ip-rate-spike",
		"web-key-divergence", "web-cross-key-same-value", "web-outlier",
		"host-auth-chain", "host-persistence-task", "host-service-install",
		"host-process-tree", "host-time-cluster", "host-credential-face",
		"cross-entity-multi-source", "cross-host-entity",
	}
	got := map[string]bool{}
	for _, s := range reg.Specs() {
		got[s.ID] = true
		if !s.Implemented {
			t.Fatalf("算子 %s 未实现(切片七后注册表应无空挂)", s.ID)
		}
	}
	for _, id := range want {
		if !got[id] {
			t.Fatalf("算子 %s 未注册", id)
		}
	}
}
