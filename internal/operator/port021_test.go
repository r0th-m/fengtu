// 0.21.0-operator-port 焊死(合成正负样本,全部对 spec 写;IP 用文档保留段,
// 无任何案件值)。数值口径与索图 Python runner(rules.py,stub 检索层)
// 逐条对拍——权威期望由 .verify/port021_crosscheck.py 跑出:
//
//	size_outlier:  离群行 line 10/11,value 1000,median 100,方向 偏大,
//	               matched_value "path=/api method=GET status=200"
//	divergence:    代表行 1,matched_value "×10.0",ratio 10.0;
//	               零桶分化 matched_value "∞",ratio null
//	sequence:      锚点行 6,first_step_count 5,chain_line_nos [5,6],
//	               matched_value "src_ip=203.0.113.1 path=/login"
package operator

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/ye-mengwen/fengtu/internal/query"
)

// webEv 复合字段合成 web 事件(path/method/status/bytes/src_ip/ua)。
func webEv(srcID string, line int, sec int, m map[string]string) query.Event {
	fields := "{"
	first := true
	for k, v := range m {
		if !first {
			fields += ","
		}
		fields += fmt.Sprintf("%q:%q", k, v)
		first = false
	}
	fields += "}"
	return query.Event{SourceID: srcID, LineNo: line, TS: tsAt(sec),
		Kind: "event", Fields: fields}
}

// ---- ① web-outlier 复合键增强(索图 size_outlier 对拍) ----

func TestSizeOutlierComposite(t *testing.T) {
	spec := compileSpec(t, `
id: web-outlier
title: x
family: web
severity: low
applicable_to: {log_types: [web_access]}
params:
  key_fields: [path, method, status]
  bytes_field: bytes
  ratio: 3.0
  min_samples: 10
  max_outliers: 3
implemented: true
`)
	src := Source{ID: "s-web", LogType: "web_access"}
	var evs []query.Event
	mk := func(line int, path, method, status, bytes string) query.Event {
		return webEv("s-web", line, line, map[string]string{
			"path": path, "method": method, "status": status, "bytes": bytes})
	}
	// /api GET 200:10 条 100B + 2 条 1000B(中位数 100,离群 2 条偏大)
	for i := 0; i < 10; i++ {
		evs = append(evs, mk(i, "/api", "GET", "200", "100"))
	}
	evs = append(evs, mk(10, "/api", "GET", "200", "1000"))
	evs = append(evs, mk(11, "/api", "GET", "200", "1000"))
	// /api POST 200:10 条全 100B(同 path 不同 method/status 不串组,带内无离群)
	for i := 0; i < 10; i++ {
		evs = append(evs, mk(20+i, "/api", "POST", "200", "100"))
	}
	findings, err := impls["web-outlier"].Run(spec, []Source{src}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("复合键尺寸离群应 1 命中: %+v", findings)
	}
	f := findings[0]
	// 对拍:matched_value/中位数/离群行/方向 与索图 runner 一致
	if f.MatchedValue != "path=/api method=GET status=200" {
		t.Fatalf("复合键命中值不符(索图 _key_str 口径): %q", f.MatchedValue)
	}
	if f.MatchedField != "path,method,status" {
		t.Fatalf("matched_field 应为复合键字段: %q", f.MatchedField)
	}
	if f.Detail["median_bytes"].(float64) != 100 ||
		f.Detail["outlier_count"].(int) != 2 {
		t.Fatalf("中位数/离群数不符: %+v", f.Detail)
	}
	outliers := f.Detail["outliers"].([]map[string]any)
	if len(outliers) != 2 ||
		outliers[0]["line_no"].(int) != 10 || outliers[1]["line_no"].(int) != 11 {
		t.Fatalf("离群行应为 [10 11](|dev| 降序,同 dev 行号升序): %+v", outliers)
	}
	if outliers[0]["direction"].(string) != "偏大" ||
		outliers[0]["bytes"].(float64) != 1000 {
		t.Fatalf("离群方向/数值不符: %+v", outliers[0])
	}
	if f.LineNo != 10 {
		t.Fatalf("锚点=偏离最大的离群行: %d", f.LineNo)
	}
	if gradeOf(t, f) != GradeWeak {
		t.Fatalf("统计依据应为弱信号: %s", gradeOf(t, f))
	}
}

func TestSizeOutlier_LegacyAndBoundaries(t *testing.T) {
	// 旧配置兼容:单 key_field 照常工作(负样本焊死)
	legacy := compileSpec(t, `
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
	mkB := func(line int, path, bytes string) query.Event {
		return webEv("s-web", line, line, map[string]string{
			"path": path, "bytes": bytes})
	}
	for i := 0; i < 10; i++ {
		evs = append(evs, mkB(i, "/api", "100"))
	}
	evs = append(evs, mkB(10, "/api", "1000")) // 10x ≥ 3 离群
	// /edge:中位数 100,边界值 300 恰好 3.0x——严格偏离(索图 >/<)不命中
	for i := 0; i < 9; i++ {
		evs = append(evs, mkB(20+i, "/edge", "100"))
	}
	evs = append(evs, mkB(29, "/edge", "300"))
	// /zero:中位数 0 的组不判比率(防除零,如实跳过)
	for i := 0; i < 10; i++ {
		evs = append(evs, mkB(40+i, "/zero", "0"))
	}
	findings, err := impls["web-outlier"].Run(legacy, []Source{src}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].MatchedValue != "/api" {
		t.Fatalf("旧单键配置应照常命中 /api(边界 3.0x 不命中,零中位数跳过): %+v", findings)
	}
	if findings[0].Detail["outlier_count"].(int) != 1 {
		t.Fatalf("旧配置离群数: %+v", findings[0].Detail)
	}

	// max_outliers 帽:5 条离群只拎 3 条,按 |dev| 降序
	spec := compileSpec(t, `
id: web-outlier
title: x
family: web
severity: low
applicable_to: {log_types: [web_access]}
params:
  key_field: path
  ratio: 3.0
  min_samples: 10
  max_outliers: 3
implemented: true
`)
	evs = nil
	for i := 0; i < 10; i++ {
		evs = append(evs, mkB(i, "/cap", "100"))
	}
	for i, b := range []string{"400", "500", "600", "700", "800"} {
		evs = append(evs, mkB(10+i, "/cap", b))
	}
	findings, err = impls["web-outlier"].Run(spec, []Source{src}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("max_outliers 组应 1 命中: %+v", findings)
	}
	f := findings[0]
	if f.Detail["outlier_count"].(int) != 5 {
		t.Fatalf("outlier_count 应记全量 5(帽只限拎出条数): %+v", f.Detail)
	}
	outliers := f.Detail["outliers"].([]map[string]any)
	if len(outliers) != 3 ||
		outliers[0]["bytes"].(float64) != 800 ||
		outliers[1]["bytes"].(float64) != 700 ||
		outliers[2]["bytes"].(float64) != 600 {
		t.Fatalf("应按 |dev| 降序拎前 3(800/700/600): %+v", outliers)
	}
	if f.LineNo != 14 {
		t.Fatalf("锚点=dev 最大行(800B,L14): %d", f.LineNo)
	}
}

// ---- ② web-key-divergence 均值比模式(索图 same_key_divergence 对拍) ----

func TestKeyDivergenceMeanRatio(t *testing.T) {
	spec := compileSpec(t, `
id: web-key-divergence
title: x
family: web
severity: low
applicable_to: {log_types: [web_access]}
params:
  key_fields: [path, src_ip, ua]
  diverge_field: method
  metric: bytes
  min_group_events: 10
  diverge_ratio: 3.0
implemented: true
`)
	src := Source{ID: "s-web", LogType: "web_access"}
	var evs []query.Event
	mk := func(line int, path, ip, method, bytes string) query.Event {
		return webEv("s-web", line, line, map[string]string{
			"path": path, "src_ip": ip, "ua": "ua", "method": method,
			"bytes": bytes})
	}
	// /a 组:GET×6 均值 100,POST×4 均值 1000(总 10,ratio=10 ≥ 3 命中)
	for i := 0; i < 6; i++ {
		evs = append(evs, mk(1+i, "/a", "203.0.113.1", "GET", "100"))
	}
	for i := 0; i < 4; i++ {
		evs = append(evs, mk(7+i, "/a", "203.0.113.1", "POST", "1000"))
	}
	// /b 组:GET×6 均值 100,POST×4 均值 200(ratio 2 < 3 不命中)
	for i := 0; i < 6; i++ {
		evs = append(evs, mk(20+i, "/b", "203.0.113.1", "GET", "100"))
	}
	for i := 0; i < 4; i++ {
		evs = append(evs, mk(26+i, "/b", "203.0.113.1", "POST", "200"))
	}
	// /c 组:总 8 < min_group_events(小样本噪声闸)
	for i := 0; i < 4; i++ {
		evs = append(evs, mk(40+i, "/c", "203.0.113.1", "GET", "100"))
		evs = append(evs, mk(50+i, "/c", "203.0.113.1", "POST", "900"))
	}
	findings, err := impls["web-key-divergence"].Run(spec, []Source{src}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("均值比分化应 1 命中: %+v", findings)
	}
	f := findings[0]
	// 对拍:代表行 1、matched_value ×10.0、ratio 10.0
	if f.LineNo != 1 || f.MatchedField != "method" || f.MatchedValue != "×10.0" {
		t.Fatalf("对拍口径不符(代表行/字段/比率文本): L%d %s %q",
			f.LineNo, f.MatchedField, f.MatchedValue)
	}
	if f.Detail["ratio"].(float64) != 10.0 ||
		f.Detail["group"].(string) != "path=/a src_ip=203.0.113.1 ua=ua" {
		t.Fatalf("ratio/group 不符: %+v", f.Detail)
	}
	buckets := f.Detail["buckets"].([]map[string]any)
	if len(buckets) != 2 || buckets[0]["value"].(string) != "GET" ||
		buckets[0]["avg"].(float64) != 100 ||
		buckets[1]["avg"].(float64) != 1000 {
		t.Fatalf("buckets 未直给分桶均值: %+v", buckets)
	}
	if gradeOf(t, f) != GradeWeak {
		t.Fatalf("统计依据应为弱信号: %s", gradeOf(t, f))
	}

	// 零桶分化:GET 均值 0、POST 均值 50 → 无限分化如实命中(索图 ∞)
	evs = nil
	for i := 0; i < 5; i++ {
		evs = append(evs, mk(1+i, "/z", "203.0.113.2", "GET", "0"))
	}
	for i := 0; i < 5; i++ {
		evs = append(evs, mk(6+i, "/z", "203.0.113.2", "POST", "50"))
	}
	findings, err = impls["web-key-divergence"].Run(spec, []Source{src}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].MatchedValue != "∞" ||
		findings[0].Detail["ratio"] != nil {
		t.Fatalf("零桶应为无限分化如实命中(∞/ratio=null): %+v", findings)
	}
}

func TestKeyDivergence_LegacyDistinctStillWorks(t *testing.T) {
	// 旧 distinct 计数模式兼容:不写 diverge_field 即回旧语义
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
	for i := 0; i < 60; i++ {
		evs = append(evs, webEv("s-web", i, i, map[string]string{
			"src_ip": "203.0.113.10", "ua": "agent-" + strconv.Itoa(i)}))
	}
	findings, err := impls["web-key-divergence"].Run(spec, []Source{src}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].MatchedValue != "203.0.113.10" ||
		findings[0].Detail["distinct_values"].(int) != 60 {
		t.Fatalf("旧 distinct 模式应照常命中: %+v", findings)
	}
}

// ---- ③ web-sequence-chain 通用序列引擎(索图 sequence 对拍) ----

const sequenceYAML = `
id: web-sequence-chain
title: x
family: web
severity: high
applicable_to: {log_types: [web_access]}
params:
  key_fields: [src_ip, path]
  steps:
    - {field: status, in: ["401", "403"]}
    - {field: status, in: ["200"]}
  window_seconds: 300
  min_first_step_count: 5
implemented: true
`

func TestSequenceChain(t *testing.T) {
	spec := compileSpec(t, sequenceYAML)
	src := Source{ID: "s-web", LogType: "web_access"}
	var evs []query.Event
	mk := func(line, sec int, ip, status string) query.Event {
		return webEv("s-web", line, sec, map[string]string{
			"src_ip": ip, "path": "/login", "status": status})
	}
	// ip1:401×5(sec 1..5)→ sec 10 一个 200(窗口 300 内成链)
	for i := 0; i < 5; i++ {
		evs = append(evs, mk(1+i, 1+i, "203.0.113.1", "401"))
	}
	evs = append(evs, mk(6, 10, "203.0.113.1", "200"))
	// ip2:401×4(不达 min_first_step_count)+ 200,不命中
	for i := 0; i < 4; i++ {
		evs = append(evs, mk(10+i, 1+i, "203.0.113.2", "401"))
	}
	evs = append(evs, mk(14, 10, "203.0.113.2", "200"))
	// ip3:401×5 后 200 在 sec 400(距末次 401 超 300s 窗,断链不命中)
	for i := 0; i < 5; i++ {
		evs = append(evs, mk(20+i, 1+i, "203.0.113.3", "401"))
	}
	evs = append(evs, mk(25, 400, "203.0.113.3", "200"))
	// ts 缺失事件不参与(如实计数)
	evs = append(evs, query.Event{SourceID: "s-web", LineNo: 30, Kind: "event",
		Fields: `{"src_ip":"203.0.113.1","path":"/login","status":"401"}`})

	findings, err := impls["web-sequence-chain"].Run(spec, []Source{src}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("通用链应 1 命中(次数闸/超窗各拦一组): %+v", findings)
	}
	f := findings[0]
	// 对拍:锚点行 6、首步计数 5、链行号 [5 6]
	if f.LineNo != 6 || f.Detail["first_step_count"].(int) != 5 {
		t.Fatalf("锚点/首步计数不符: L%d %+v", f.LineNo, f.Detail)
	}
	chain := f.Detail["chain_line_nos"].([]int)
	if len(chain) != 2 || chain[0] != 5 || chain[1] != 6 {
		t.Fatalf("链行号应为 [5 6](末次首步→末步): %+v", chain)
	}
	if f.MatchedValue != "src_ip=203.0.113.1 path=/login" {
		t.Fatalf("复合键命中值不符: %q", f.MatchedValue)
	}
	if f.Detail["events_without_ts"].(int) != 1 {
		t.Fatalf("ts 缺失应如实计数: %+v", f.Detail)
	}
	if gradeOf(t, f) != GradeStrong {
		t.Fatalf("多步链咬合应为强疑似: %s", gradeOf(t, f))
	}
}

func TestSequenceChain_ThreeStepsAndParams(t *testing.T) {
	// 三步链:扫描(404)→ 打点(200 敏感路径)→ 利用(POST)
	spec := compileSpec(t, `
id: web-sequence-chain
title: x
family: web
severity: high
applicable_to: {log_types: [web_access]}
params:
  key_fields: [src_ip]
  steps:
    - {field: status, in: ["404"]}
    - {field: path, in: ["/admin", "/.env"]}
    - {field: method, in: ["post"]}
  window_seconds: 120
  min_first_step_count: 3
implemented: true
`)
	src := Source{ID: "s-web", LogType: "web_access"}
	mk := func(line, sec int, ip, status, path, method string) query.Event {
		return webEv("s-web", line, sec, map[string]string{
			"src_ip": ip, "status": status, "path": path, "method": method})
	}
	evs := []query.Event{
		mk(1, 1, "203.0.113.5", "404", "/x1", "GET"),
		mk(2, 2, "203.0.113.5", "404", "/x2", "GET"),
		mk(3, 3, "203.0.113.5", "404", "/x3", "GET"),
		mk(4, 30, "203.0.113.5", "200", "/.env", "GET"),   // step2(in 大小写不敏感)
		mk(5, 60, "203.0.113.5", "200", "/admin", "POST"), // step3
		// 另一 IP:链不完整(缺末步)不命中
		mk(6, 1, "203.0.113.6", "404", "/y1", "GET"),
		mk(7, 2, "203.0.113.6", "404", "/y2", "GET"),
		mk(8, 3, "203.0.113.6", "404", "/y3", "GET"),
		mk(9, 30, "203.0.113.6", "200", "/.env", "GET"),
	}
	findings, err := impls["web-sequence-chain"].Run(spec, []Source{src}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].MatchedValue != "203.0.113.5" ||
		findings[0].LineNo != 5 {
		t.Fatalf("三步链应 1 命中(锚点=末步行): %+v", findings)
	}
	if len(findings[0].Detail["chain_line_nos"].([]int)) != 3 {
		t.Fatalf("链应含 3 行: %+v", findings[0].Detail)
	}

	// 参数校验:steps 缺/超窗缺/步数越界一律拒(不静默降级)
	for _, y := range []string{
		"\nid: web-sequence-chain\ntitle: x\nfamily: web\nseverity: high\napplicable_to: {log_types: [web_access]}\nparams:\n  key_fields: [src_ip]\n  window_seconds: 60\nimplemented: true\n",
		"\nid: web-sequence-chain\ntitle: x\nfamily: web\nseverity: high\napplicable_to: {log_types: [web_access]}\nparams:\n  key_fields: [src_ip]\n  steps: [{field: status, in: [\"401\"]}]\n  window_seconds: 60\nimplemented: true\n",
	} {
		s := compileSpec(t, y)
		if _, err := impls["web-sequence-chain"].Run(s, []Source{src}, streamOf(nil)); err == nil {
			t.Fatalf("坏参数应拒: %s", y)
		}
	}
}

// ---- ④ exclude_kb 引用机制 ----

func TestExcludeKBLoadAndMatch(t *testing.T) {
	// 装载期解析:<算子目录>/../excludes/<名>.yaml;缺失/坏结构拒载
	base := t.TempDir()
	opsDir := filepath.Join(base, "operators")
	if err := os.MkdirAll(filepath.Join(base, "excludes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(opsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	opYAML := `
id: web-cross-key-same-value
title: x
family: web
severity: low
applicable_to: {log_types: [web_access]}
params:
  value_field: ua
  key_field: src_ip
  min_keys: 2
  max_df: 10
  exclude_kb: test_list
implemented: true
`
	if err := os.WriteFile(filepath.Join(opsDir, "a.yaml"), []byte(opYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	// 清单缺失 → 拒载
	if _, err := LoadDir(opsDir); err == nil {
		t.Fatal("引用的排除清单缺失应拒载")
	}
	// 清单落盘 → 装载成功,token 小写化
	kbYAML := "id: test_list\ntokens:\n  - Googlebot\n  - 'curl/'\n"
	if err := os.WriteFile(filepath.Join(base, "excludes", "test_list.yaml"),
		[]byte(kbYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	reg, err := LoadDir(opsDir)
	if err != nil {
		t.Fatalf("清单落盘后应装载成功: %v", err)
	}
	spec := reg.Specs()[0]
	if len(spec.ExcludeKBTokens) != 2 || spec.ExcludeKBTokens[0] != "googlebot" {
		t.Fatalf("token 应小写化装载: %+v", spec.ExcludeKBTokens)
	}

	// 匹配语义:值小写化后子串包含(词根不在开头也排除,对齐索图)
	src := Source{ID: "s-web", LogType: "web_access"}
	var evs []query.Event
	mk := func(line int, ip, ua string) query.Event {
		return webEv("s-web", line, line, map[string]string{
			"src_ip": ip, "ua": ua})
	}
	// 爬虫 UA(compatible 形态,词根不在开头)跨 3 IP:KB 子串排除,不命中
	for i, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		evs = append(evs, mk(i, ip, "Mozilla/5.0 (compatible; Googlebot/2.1; +http://example.com/bot)"))
	}
	// 稀有自定义 UA 跨 2 IP:正常命中(min_keys=2)
	for i, ip := range []string{"203.0.113.8", "203.0.113.9"} {
		evs = append(evs, mk(10+i, ip, "raretool/0.1"))
	}
	findings, err := impls["web-cross-key-same-value"].Run(spec, []Source{src}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].MatchedValue != "raretool/0.1" {
		t.Fatalf("KB 排除后应只命中稀有自定义 UA: %+v", findings)
	}
}

// ---- ⑤ cross-host-entity 实体类型扩展(树庭 xhost 对拍) ----

func TestCrossHostEntitySID(t *testing.T) {
	spec := compileSpec(t, `
id: cross-host-entity
title: x
family: cross
severity: medium
applicable_to:
  log_types: [windows_event_log]
params:
  min_hosts: 2
  entity_type: account_sid
implemented: true
`)
	mk := func(srcID string, line int, sid string) query.Event {
		return query.Event{SourceID: srcID, LineNo: line, TS: tsAt(line), Kind: "event",
			Fields: fieldsJSON(t, map[string]any{
				"event_id": 4624, "data": map[string]any{"TargetUserSid": sid}})}
	}
	shared := "S-1-5-21-3623811015-3361044348-30300820-5001"
	evs := []query.Event{
		mk("h1-sec", 1, shared),                     // 主机 1
		mk("h2-sec", 1, shared),                     // 主机 2 → 跨机命中
		mk("h1-sec", 2, "S-1-5-18"),                 // 熟知 SID(不硬排,但不跨机)
		mk("h1-sec", 3, "not-a-sid"),                // 非法值不参与
		mk("h3-sec", 1, "S-1-5-21-111-222-333-500"), // 单主机独有,不命中
	}
	findings, err := impls["cross-host-entity"].Run(spec, []Source{
		{ID: "h1-sec", Kind: "evtx", LogType: "windows_event_log", Host: "10.0.0.1"},
		{ID: "h2-sec", Kind: "evtx", LogType: "windows_event_log", Host: "10.0.0.2"},
		{ID: "h3-sec", Kind: "evtx", LogType: "windows_event_log", Host: "10.0.0.3"},
	}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("同 SID 跨两机应 1 命中: %+v", findings)
	}
	f := findings[0]
	if f.MatchedValue != shared || f.Detail["entity_type"].(string) != "account_sid" ||
		f.Detail["host_count"] != 2 {
		t.Fatalf("SID 命中实体/类型/主机数不符: %+v", f.Detail)
	}
	if gradeOf(t, f) != GradeStrong {
		t.Fatalf("≥2 主机独立证据点+同实体咬合应为强疑似: %s", gradeOf(t, f))
	}
}

func TestCrossHostEntityFileHash(t *testing.T) {
	spec := compileSpec(t, `
id: cross-host-entity
title: x
family: cross
severity: high
applicable_to:
  log_types: [windows_event_log]
params:
  min_hosts: 2
  entity_type: file_sha256
implemented: true
`)
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	mk := func(srcID string, line int, h string) query.Event {
		return query.Event{SourceID: srcID, LineNo: line, TS: tsAt(line), Kind: "event",
			Fields: fieldsJSON(t, map[string]any{"sha256": h})}
	}
	evs := []query.Event{
		mk("h1-file", 1, hash), // 主机 1
		mk("h2-file", 1, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), // 主机 2(大写,归一后同值)
		mk("h1-file", 2, "deadbeef"), // 非法(非 64 hex)不参与
		mk("hz-file", 1, hash),       // 未建模主机不参与
	}
	findings, err := impls["cross-host-entity"].Run(spec, []Source{
		{ID: "h1-file", Kind: "evtx", LogType: "windows_event_log", Host: "10.0.0.1"},
		{ID: "h2-file", Kind: "evtx", LogType: "windows_event_log", Host: "10.0.0.2"},
		{ID: "hz-file", Kind: "evtx", LogType: "windows_event_log", Host: ""},
	}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("同 sha256 跨两机应 1 命中(未建模不计): %+v", findings)
	}
	f := findings[0]
	if f.MatchedValue != hash || f.Detail["host_count"] != 2 ||
		f.Detail["unmodeled_sources_skipped"].(int) != 1 {
		t.Fatalf("哈希命中不符(归一小写/主机数/未建模账): %+v", f.Detail)
	}
	// ip 模式旧配置不受影响(实体类型缺省=ip,公网闸照旧)
	ipSpec := compileSpec(t, crossHostYAML)
	pub := "203.0.113.77"
	evs = []query.Event{
		hostWebEvent("h1-web", 1, pub, tsAt(1)),
		hostWebEvent("h2-web", 1, pub, tsAt(2)),
		hostWebEvent("h2-web", 2, "10.9.9.9", tsAt(3)), // 私网结构性排除
	}
	findings, err = impls["cross-host-entity"].Run(ipSpec, []Source{
		{ID: "h1-web", LogType: "web_access", Host: "10.0.0.1"},
		{ID: "h2-web", LogType: "web_access", Host: "10.0.0.2"},
	}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].MatchedValue != pub ||
		findings[0].Detail["entity_type"].(string) != "ip" {
		t.Fatalf("ip 缺省模式应照旧: %+v", findings)
	}
}
