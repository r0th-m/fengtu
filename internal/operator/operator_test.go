// 算子焊死(合成正负样本,全部对 spec 写——阈值/状态码/模式走 YAML
// params;IP 用文档保留段,主机/账户用通用名,无任何案件值)。
package operator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ye-mengwen/fengtu/internal/query"
)

// ---- 公共合成工具 ----

func fieldsJSON(t *testing.T, m map[string]any) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func tsAt(sec int) *time.Time {
	t := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC).Add(time.Duration(sec) * time.Second)
	return &t
}

// streamOf 内存事件 → StreamFunc(按 sourceID 过滤,行号升序)。
func streamOf(events []query.Event) StreamFunc {
	return func(sourceID string, fn func(query.Event) error) error {
		for _, ev := range events {
			if ev.SourceID != sourceID {
				continue
			}
			if err := fn(ev); err != nil {
				return err
			}
		}
		return nil
	}
}

func compileSpec(t *testing.T, y string) *Spec {
	t.Helper()
	spec, err := compile("test.yaml", y)
	if err != nil {
		t.Fatalf("算子编译失败: %v", err)
	}
	return spec
}

func gradeOf(t *testing.T, f Finding) string {
	t.Helper()
	g, err := Grade(f.Evidence)
	if err != nil {
		t.Fatalf("证据结构不成立: %v", err)
	}
	return g
}

// ---- Grade 证据结构三面 ----

func TestGradeRules(t *testing.T) {
	if g, _ := Grade(Evidence{StatisticalOnly: true, Exclusions: []string{"排除 X"}}); g != GradeWeak {
		t.Fatalf("统计依据应为弱信号: %s", g)
	}
	if _, err := Grade(Evidence{StatisticalOnly: true}); err == nil {
		t.Fatal("弱信号缺排除项声明应不成立(§6.2)")
	}
	if g, _ := Grade(Evidence{IndependentPoints: 2, ChainLinked: true}); g != GradeStrong {
		t.Fatalf("≥2 独立点+链咬合应为强疑似: %s", g)
	}
	if g, _ := Grade(Evidence{IndependentPoints: 2}); g != GradeSuspect {
		t.Fatalf("独立点无链咬合应为疑似: %s", g)
	}
	if g, _ := Grade(Evidence{IndependentPoints: 1}); g != GradeSuspect {
		t.Fatalf("单点应为疑似: %s", g)
	}
}

// ---- 注册表装载正负 ----

func TestRegistryLoad(t *testing.T) {
	dir := t.TempDir()
	good := `
id: web-bruteforce-chain
title: x
family: web
severity: high
applicable_to:
  log_types: [web_access]
implemented: true
`
	unimpl := `
id: web-not-yet-built
title: y
family: web
severity: low
applicable_to:
  log_types: [web_access]
implemented: false
`
	for name, text := range map[string]string{"a.yaml": good, "b.yaml": unimpl} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	reg, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("装载失败: %v", err)
	}
	if len(reg.Specs()) != 2 {
		t.Fatalf("注册数: %d", len(reg.Specs()))
	}
	if _, ok := reg.Impl("web-bruteforce-chain"); !ok {
		t.Fatal("已实现算子应可取实现")
	}
	if _, ok := reg.Impl("web-not-yet-built"); ok {
		t.Fatal("未实现算子不应有实现")
	}
}

func TestRegistryRejectsLies(t *testing.T) {
	dir := t.TempDir()
	// implemented:true 但代码无实现 = 注册表说谎,拒载
	lie := `
id: web-not-yet-built
title: y
family: web
severity: low
applicable_to:
  log_types: [web_access]
implemented: true
`
	if err := os.WriteFile(filepath.Join(dir, "lie.yaml"), []byte(lie), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir); err == nil || !strings.Contains(err.Error(), "无实现") {
		t.Fatalf("谎报实现的注册表应拒载: %v", err)
	}
}

func TestDomainMatch(t *testing.T) {
	spec := compileSpec(t, `
id: web-outlier
title: y
family: web
severity: low
applicable_to:
  log_types: [web_access]
implemented: false
`)
	if !spec.Match(Source{ID: "a", LogType: "web_access"}) {
		t.Fatal("web_access 源应命中 web 算子适用域")
	}
	if spec.Match(Source{ID: "b", LogType: "windows_event_log"}) {
		t.Fatal("evtx 源不应命中 web 算子适用域")
	}
	if spec.Match(Source{ID: "c"}) {
		t.Fatal("无品类源不应命中按 log_type 声明的适用域")
	}
}

// ---- web-bruteforce-chain ----

const bfYAML = `
id: web-bruteforce-chain
title: x
family: web
severity: high
applicable_to:
  log_types: [web_access]
params:
  fail_threshold: 3
  window_seconds: 60
  window_lines: 10
  fail_status: ["401", "403"]
  success_status: ["200"]
implemented: true
`

func webEvent(line int, ip, status string, ts *time.Time) query.Event {
	return query.Event{SourceID: "s-web", LineNo: line, TS: ts,
		Kind: "event", Raw: ip + " " + status,
		Fields: fmt.Sprintf(`{"src_ip":%q,"status":%q}`, ip, status)}
}

func TestBruteForcePositive(t *testing.T) {
	spec := compileSpec(t, bfYAML)
	ip := "203.0.113.10"
	var evs []query.Event
	for i := 1; i <= 3; i++ { // 失败×3(达阈)
		evs = append(evs, webEvent(i, ip, "401", tsAt(i)))
	}
	evs = append(evs, webEvent(4, ip, "200", tsAt(4))) // 窗口内成功
	findings, err := impls["web-bruteforce-chain"].Run(spec,
		[]Source{{ID: "s-web", LogType: "web_access"}}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("爆破链应 1 命中: %d", len(findings))
	}
	f := findings[0]
	if f.LineNo != 4 || f.MatchedValue != ip {
		t.Fatalf("锚点应为成功行 L4: %+v", f)
	}
	if gradeOf(t, f) != GradeStrong {
		t.Fatalf("失败序列+成功链咬合应为强疑似: %s", gradeOf(t, f))
	}
	if f.Detail["fail_count"] != 3 || f.Detail["window_basis"] != "seconds" {
		t.Fatalf("detail 统计量: %+v", f.Detail)
	}
}

func TestBruteForceNegatives(t *testing.T) {
	spec := compileSpec(t, bfYAML)
	ip := "203.0.113.10"
	// 负 1:失败未达阈
	evs := []query.Event{webEvent(1, ip, "401", tsAt(1)),
		webEvent(2, ip, "401", tsAt(2)), webEvent(3, ip, "200", tsAt(3))}
	// 负 2:成功在窗口外(ts 超 window_seconds=60)
	for i := 4; i <= 6; i++ {
		evs = append(evs, webEvent(i, "198.51.100.9", "401", tsAt(i)))
	}
	evs = append(evs, webEvent(7, "198.51.100.9", "200", tsAt(600)))
	findings, err := impls["web-bruteforce-chain"].Run(spec,
		[]Source{{ID: "s-web", LogType: "web_access"}}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("未达阈/窗口外应零命中: %+v", findings)
	}
}

func TestBruteForceNoTSLineFallback(t *testing.T) {
	spec := compileSpec(t, bfYAML)
	ip := "203.0.113.10"
	var evs []query.Event
	for i := 1; i <= 3; i++ {
		evs = append(evs, webEvent(i, ip, "403", nil)) // 无时区源 ts=nil
	}
	evs = append(evs, webEvent(5, ip, "200", nil)) // 行距 2 ≤ window_lines 10
	findings, err := impls["web-bruteforce-chain"].Run(spec,
		[]Source{{ID: "s-web", LogType: "web_access"}}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Detail["window_basis"] != "lines" {
		t.Fatalf("无时区源应降级行距窗并如实记 basis: %+v", findings)
	}
}

// ---- web-beacon-periodicity ----

const beaconYAML = `
id: web-beacon-periodicity
title: x
family: web
severity: medium
applicable_to:
  log_types: [web_access]
params:
  min_samples: 6
  min_span_seconds: 50
  max_cv: 0.1
implemented: true
`

func TestBeaconPositiveAndNegatives(t *testing.T) {
	spec := compileSpec(t, beaconYAML)
	ip := "203.0.113.20"
	var evs []query.Event
	// 正:严格 10s 间隔 ×8(跨度 70s ≥50,cv≈0)
	for i := 0; i < 8; i++ {
		evs = append(evs, webEvent(i+1, ip, "200", tsAt(i*10)))
	}
	// 负:抖动巨大(cv 远超 0.1)
	jit := []int{0, 1, 30, 31, 90, 91, 200, 400}
	for i, s := range jit {
		evs = append(evs, webEvent(100+i, "198.51.100.21", "200", tsAt(s)))
	}
	findings, err := impls["web-beacon-periodicity"].Run(spec,
		[]Source{{ID: "s-web", LogType: "web_access"}}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("应只有周期 IP 命中: %+v", findings)
	}
	f := findings[0]
	if f.MatchedValue != ip {
		t.Fatalf("命中 IP 错: %+v", f.MatchedValue)
	}
	if gradeOf(t, f) != GradeWeak {
		t.Fatalf("统计依据应为弱信号: %s", gradeOf(t, f))
	}
	if len(f.Evidence.Exclusions) == 0 {
		t.Fatal("弱信号必须带排除项声明")
	}
	cv, _ := f.Detail["cv"].(float64)
	if cv > 0.001 {
		t.Fatalf("严格周期 cv 应≈0: %v", cv)
	}
}

// ---- web-ip-rate-spike ----

const spikeYAML = `
id: web-ip-rate-spike
title: x
family: web
severity: medium
applicable_to:
  log_types: [web_access]
params:
  bucket_seconds: 60
  min_buckets: 5
  z_threshold: 3.0
  min_bucket_count: 20
implemented: true
`

func TestIPRateSpike(t *testing.T) {
	spec := compileSpec(t, spikeYAML)
	ip := "203.0.113.30"
	var evs []query.Event
	line := 0
	// 基线:10 桶每桶 5 个;突刺:1 桶 100 个(z≈(100-13.6)/28≈3.1)
	for b := 0; b < 10; b++ {
		for i := 0; i < 5; i++ {
			line++
			evs = append(evs, webEvent(line, ip, "200", tsAt(b*60+i)))
		}
	}
	for i := 0; i < 100; i++ {
		line++
		evs = append(evs, webEvent(line, ip, "200", tsAt(10*60+i%50)))
	}
	// 平稳 IP:每域内不产生突刺
	for b := 0; b < 10; b++ {
		for i := 0; i < 6; i++ {
			line++
			evs = append(evs, webEvent(line, "198.51.100.31", "200", tsAt(b*60+i)))
		}
	}
	findings, err := impls["web-ip-rate-spike"].Run(spec,
		[]Source{{ID: "s-web", LogType: "web_access"}}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].MatchedValue != ip {
		t.Fatalf("应只有突刺 IP 命中: %+v", findings)
	}
	if gradeOf(t, findings[0]) != GradeWeak {
		t.Fatalf("速率突刺应为弱信号: %s", gradeOf(t, findings[0]))
	}
	if findings[0].Detail["bucket_count"] != 100 {
		t.Fatalf("突刺桶计数: %+v", findings[0].Detail)
	}
}

// ---- host-auth-chain ----

const authYAML = `
id: host-auth-chain
title: x
family: host
severity: high
applicable_to:
  log_types: [windows_event_log]
params:
  fail_event: 4625
  success_event: 4624
  fail_threshold: 3
  window_seconds: 120
implemented: true
`

func evtxEvent(t *testing.T, line, eid int, account string, sec int) query.Event {
	return query.Event{SourceID: "s-evtx", LineNo: line, TS: tsAt(sec), Kind: "event",
		Fields: fieldsJSON(t, map[string]any{
			"event_id": eid, "computer": "WS-01",
			"data": map[string]any{"TargetUserName": account, "LogonType": "3",
				"IpAddress": "203.0.113.40"},
		})}
}

func TestAuthChain(t *testing.T) {
	spec := compileSpec(t, authYAML)
	var evs []query.Event
	// 正:alice 失败×3 → 窗口内成功
	for i := 1; i <= 3; i++ {
		evs = append(evs, evtxEvent(t, i, 4625, "alice", i*10))
	}
	evs = append(evs, evtxEvent(t, 4, 4624, "alice", 40))
	// 负:bob 失败×3 → 窗口外成功
	for i := 5; i <= 7; i++ {
		evs = append(evs, evtxEvent(t, i, 4625, "bob", i*10))
	}
	evs = append(evs, evtxEvent(t, 8, 4624, "bob", 1000))
	// 负:机器账户($ 后缀)结构性排除
	for i := 9; i <= 11; i++ {
		evs = append(evs, evtxEvent(t, i, 4625, "svc-host$", i*10))
	}
	evs = append(evs, evtxEvent(t, 12, 4624, "svc-host$", 120))
	findings, err := impls["host-auth-chain"].Run(spec,
		[]Source{{ID: "s-evtx", Kind: "evtx", LogType: "windows_event_log"}},
		streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("应只有 alice 命中: %+v", findings)
	}
	f := findings[0]
	if f.MatchedValue != "alice" || f.LineNo != 4 {
		t.Fatalf("锚点/账户错: %+v", f)
	}
	if gradeOf(t, f) != GradeStrong {
		t.Fatalf("认证链应为强疑似: %s", gradeOf(t, f))
	}
	if f.Detail["fail_count"] != 3 {
		t.Fatalf("detail 统计量: %+v", f.Detail)
	}
}

// 回归(真实勒索案件实战挖出):长周期爆破——第 N 次失败与成功相隔
// 数日,但成功前几秒仍有失败;窗口必须从最近一次失败起算,否则永不成链。
func TestAuthChain_LongCampaign(t *testing.T) {
	spec := compileSpec(t, authYAML)
	var evs []query.Event
	// carol:第 1~3 次失败在 t=10/20/30(达阈),之后持续失败三个月,
	// 最后一次失败在 t=10000000,成功在 t=10000005(最近失败 5s 后)
	for i := 1; i <= 3; i++ {
		evs = append(evs, evtxEvent(t, i, 4625, "carol", i*10))
	}
	evs = append(evs, evtxEvent(t, 4, 4625, "carol", 5000000))
	evs = append(evs, evtxEvent(t, 5, 4625, "carol", 10000000))
	evs = append(evs, evtxEvent(t, 6, 4624, "carol", 10000005))
	// dave:同样长周期,但最后一次失败离成功 1000s(窗口 120s 外)→ 不命中
	for i := 7; i <= 9; i++ {
		evs = append(evs, evtxEvent(t, i, 4625, "dave", i*10))
	}
	evs = append(evs, evtxEvent(t, 10, 4625, "dave", 10000000))
	evs = append(evs, evtxEvent(t, 11, 4624, "dave", 10001000))
	findings, err := impls["host-auth-chain"].Run(spec,
		[]Source{{ID: "s-evtx", Kind: "evtx", LogType: "windows_event_log"}},
		streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].MatchedValue != "carol" {
		t.Fatalf("长周期爆破应只命中 carol: %+v", findings)
	}
	if findings[0].Detail["fail_last_line"] != 5 {
		t.Fatalf("detail 应带最近失败行: %+v", findings[0].Detail)
	}
}

// ---- host-persistence-task ----

const taskYAML = `
id: host-persistence-task
title: x
family: host
severity: medium
applicable_to:
  log_types: [windows_event_log]
params:
  events: ["4698", "4702"]
  benign_name_patterns:
    - '(?i)(microsoft|windows)'
  suspicious_exec_patterns:
    - '(?i)\\(temp|tmp)\\'
    - '(?i)\b(powershell(\.exe)?|cmd\.exe)\b'
implemented: true
`

func taskEvent(t *testing.T, line, eid int, name, command string) query.Event {
	content := "<Task><Actions><Exec><Command>" + command + "</Command></Exec></Actions></Task>"
	return query.Event{SourceID: "s-evtx", LineNo: line, TS: tsAt(line), Kind: "event",
		Fields: fieldsJSON(t, map[string]any{
			"event_id": eid, "computer": "WS-01",
			"data": map[string]any{"TaskName": name, "TaskContent": content,
				"SubjectUserName": "admin"},
		})}
}

func TestPersistenceTask(t *testing.T) {
	spec := compileSpec(t, taskYAML)
	evs := []query.Event{
		// 正:名像系统任务,实落 temp → 名实不符
		taskEvent(t, 1, 4698, `\Microsoft\Windows\UpdateTask`, `C:\Users\Public\..\AppData\Local\Temp\x.exe`),
		// 负:名像系统任务,动作也正当
		taskEvent(t, 2, 4698, `\Microsoft\Windows\Cleanup`, `C:\Windows\System32\cleanmgr.exe`),
		// 负:名字本来就不像系统任务(不归「名实不符」管)
		taskEvent(t, 3, 4698, `my-custom-job`, `C:\Temp\x.exe`),
	}
	// 修:正样本命令含 temp 路径(模式 (?i)\\(temp|tmp)\\)
	findings, err := impls["host-persistence-task"].Run(spec,
		[]Source{{ID: "s-evtx", Kind: "evtx", LogType: "windows_event_log"}},
		streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("应只有名实不符任务命中: %+v", findings)
	}
	if gradeOf(t, findings[0]) != GradeSuspect {
		t.Fatalf("单点+上下文应为疑似: %s", gradeOf(t, findings[0]))
	}
	if !strings.Contains(findings[0].Detail["task_name"].(string), "Microsoft") {
		t.Fatalf("detail 任务名: %+v", findings[0].Detail)
	}
}

// ---- cross-entity-multi-source ----

const crossYAML = `
id: cross-entity-multi-source
title: x
family: cross
severity: high
applicable_to:
  log_types: [web_access, windows_event_log]
params:
  min_sources: 2
  ip_fields:
    web_access: [src_ip]
    windows_event_log: [IpAddress]
implemented: true
`

func TestCrossEntity(t *testing.T) {
	spec := compileSpec(t, crossYAML)
	pub := "203.0.113.50"
	evs := []query.Event{
		webEvent(1, pub, "200", tsAt(1)),           // web 源出现
		webEvent(2, "192.168.1.9", "200", tsAt(2)), // 私网结构性排除
		evtxEvent(t, 3, 4625, "carol", 5),          // evtx 源同公网 IP(203.0.113.40)
	}
	// 让 evtx 事件带同一公网 IP
	evs[2] = query.Event{SourceID: "s-evtx", LineNo: 3, TS: tsAt(5), Kind: "event",
		Fields: fieldsJSON(t, map[string]any{
			"event_id": 4625, "computer": "WS-01",
			"data": map[string]any{"TargetUserName": "carol", "IpAddress": pub},
		})}
	findings, err := impls["cross-entity-multi-source"].Run(spec, []Source{
		{ID: "s-web", LogType: "web_access"},
		{ID: "s-evtx", Kind: "evtx", LogType: "windows_event_log"},
	}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("同公网 IP 两源复现应 1 命中: %+v", findings)
	}
	f := findings[0]
	if f.MatchedValue != pub || f.Detail["source_count"] != 2 {
		t.Fatalf("命中实体/源数错: %+v", f)
	}
	if gradeOf(t, f) != GradeStrong {
		t.Fatalf("两独立源+同实体咬合应为强疑似: %s", gradeOf(t, f))
	}
}

func TestCrossEntityPrivateExcluded(t *testing.T) {
	spec := compileSpec(t, crossYAML)
	priv := "192.168.10.10"
	evs := []query.Event{
		webEvent(1, priv, "200", tsAt(1)),
		{SourceID: "s-evtx", LineNo: 2, TS: tsAt(2), Kind: "event",
			Fields: fieldsJSON(t, map[string]any{
				"event_id": 4625, "data": map[string]any{"IpAddress": priv}})},
	}
	findings, err := impls["cross-entity-multi-source"].Run(spec, []Source{
		{ID: "s-web", LogType: "web_access"},
		{ID: "s-evtx", Kind: "evtx", LogType: "windows_event_log"},
	}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("私网 IP 跨源复现是拓扑常态,应零命中: %+v", findings)
	}
}

func TestCrossEntitySingleSource(t *testing.T) {
	spec := compileSpec(t, crossYAML)
	pub := "203.0.113.60"
	evs := []query.Event{webEvent(1, pub, "200", tsAt(1)), webEvent(2, pub, "200", tsAt(2))}
	findings, err := impls["cross-entity-multi-source"].Run(spec,
		[]Source{{ID: "s-web", LogType: "web_access"}}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("单源复现不构跨源证据: %+v", findings)
	}
}

// ---- 切片七:cross-host-entity(同实体 ≥2 主机,跨机案核心) ----

const crossHostYAML = `
id: cross-host-entity
title: x
family: cross
severity: high
applicable_to:
  log_types: [web_access, windows_event_log]
params:
  min_hosts: 2
  ip_fields:
    web_access: [src_ip]
    windows_event_log: [IpAddress, SourceNetworkAddress]
implemented: true
`

// hostWebEvent 带源归属的合成 web 事件(多源多主机用)。
func hostWebEvent(srcID string, line int, ip string, ts *time.Time) query.Event {
	return query.Event{SourceID: srcID, LineNo: line, TS: ts,
		Kind: "event", Raw: ip, Fields: fmt.Sprintf(`{"src_ip":%q}`, ip)}
}

// 两包两主机合成案件:同公网 IP 在两台主机各自的源里出现 → 跨主机命中。
func TestCrossHostEntity_TwoHosts(t *testing.T) {
	spec := compileSpec(t, crossHostYAML)
	pub := "203.0.113.77"
	evs := []query.Event{
		hostWebEvent("h1-web", 1, pub, tsAt(1)),
		hostWebEvent("h1-web", 2, "192.168.1.5", tsAt(2)),
		{SourceID: "h2-evtx", LineNo: 9, TS: tsAt(9), Kind: "event",
			Fields: fieldsJSON(t, map[string]any{
				"event_id": 4625, "data": map[string]any{"IpAddress": pub}})},
	}
	findings, err := impls["cross-host-entity"].Run(spec, []Source{
		{ID: "h1-web", LogType: "web_access", Host: "10.0.0.1"},
		{ID: "h2-evtx", Kind: "evtx", LogType: "windows_event_log", Host: "10.0.0.2"},
	}, streamOf(evs))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("同公网 IP 跨两主机应 1 命中: %+v", findings)
	}
	f := findings[0]
	if f.MatchedValue != pub || f.Detail["host_count"] != 2 {
		t.Fatalf("命中实体/主机数错: %+v", f.Detail)
	}
	hosts, ok := f.Detail["hosts"].([]map[string]any)
	if !ok || len(hosts) != 2 {
		t.Fatalf("detail 未直给各主机出处: %+v", f.Detail["hosts"])
	}
	if gradeOf(t, f) != GradeStrong {
		t.Fatalf("≥2 主机独立证据点+同实体咬合应为强疑似: %s", gradeOf(t, f))
	}
}

// 不误伤三连:私网跨机(拓扑常态)/公网单机/未建模主机,都零命中。
func TestCrossHostEntity_Negatives(t *testing.T) {
	spec := compileSpec(t, crossHostYAML)

	// 私网 IP 两主机复现:结构性排除
	priv := "10.9.9.9"
	evs := []query.Event{
		hostWebEvent("h1-web", 1, priv, tsAt(1)),
		hostWebEvent("h2-web", 1, priv, tsAt(2)),
	}
	findings, err := impls["cross-host-entity"].Run(spec, []Source{
		{ID: "h1-web", LogType: "web_access", Host: "10.0.0.1"},
		{ID: "h2-web", LogType: "web_access", Host: "10.0.0.2"},
	}, streamOf(evs))
	if err != nil || len(findings) != 0 {
		t.Fatalf("私网跨机复现应零命中: %v %+v", err, findings)
	}

	// 公网 IP 只在单主机多源出现:跨源不跨机,本算子不命中
	pub := "203.0.113.88"
	evs = []query.Event{
		hostWebEvent("h1-web", 1, pub, tsAt(1)),
		hostWebEvent("h1-web2", 1, pub, tsAt(2)),
	}
	findings, err = impls["cross-host-entity"].Run(spec, []Source{
		{ID: "h1-web", LogType: "web_access", Host: "10.0.0.1"},
		{ID: "h1-web2", LogType: "web_access", Host: "10.0.0.1"},
	}, streamOf(evs))
	if err != nil || len(findings) != 0 {
		t.Fatalf("单主机多源复现不构跨机证据: %v %+v", err, findings)
	}

	// 主机未建模(host="")的源不参与跨主机关联
	evs = []query.Event{
		hostWebEvent("h1-web", 1, pub, tsAt(1)),
		hostWebEvent("hz-web", 1, pub, tsAt(2)),
	}
	findings, err = impls["cross-host-entity"].Run(spec, []Source{
		{ID: "h1-web", LogType: "web_access", Host: "10.0.0.1"},
		{ID: "hz-web", LogType: "web_access", Host: ""},
	}, streamOf(evs))
	if err != nil || len(findings) != 0 {
		t.Fatalf("未建模主机不应参与跨机归并: %v %+v", err, findings)
	}
}

// TestRealRegistry_CrossHost 真实注册表:cross-host-entity 已实现且
// 跨层两算子并存(清单如实)。
func TestRealRegistry_CrossHost(t *testing.T) {
	reg, err := LoadDir(filepath.Join("..", "..", "configs", "operators"))
	if err != nil {
		t.Fatalf("真实注册表装载失败: %v", err)
	}
	spec := func(id string) *Spec {
		for _, s := range reg.Specs() {
			if s.ID == id {
				return s
			}
		}
		return nil
	}
	ch := spec("cross-host-entity")
	if ch == nil || !ch.Implemented {
		t.Fatalf("cross-host-entity 应已实现: %+v", ch)
	}
	if _, ok := reg.Impl("cross-host-entity"); !ok {
		t.Fatal("cross-host-entity 声明 implemented:true 但代码无实现")
	}
}

