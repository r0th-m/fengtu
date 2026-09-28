// target=entity 规则焊死(0.25.0-datasource-unlock):
//   - 装载:实体字段词表/裸键 eq 语义/min_hosts 保留键/非法组合拒载;
//   - 单机实体规则:逐实体匹配,锚点=首见 source+行;
//   - 跨机规则:qualifier=global 聚合 COUNT(DISTINCT host)>=min_hosts;
//     私网(host_scoped)与未建模主机结构性排除(防假联动)。
package review

import (
	"context"
	"strings"
	"testing"

	"github.com/ye-mengwen/fengtu/internal/entity"
	"github.com/ye-mengwen/fengtu/internal/query"
)

// newEngineWithStore 实体规则测试引擎(检索层用空 fakeQuerier——
// 实体规则不走事件检索层)。
func newEngineWithStore(t *testing.T, st Store, ruleYAML string) *Engine {
	t.Helper()
	r, err := CompileRule("t.yaml", ruleYAML)
	if err != nil {
		t.Fatalf("规则编译失败: %v", err)
	}
	eng, err := NewEngine([]*Rule{r}, query.NewService(&fakeQuerier{}), st)
	if err != nil {
		t.Fatalf("引擎构造失败: %v", err)
	}
	return eng
}

// fakeEntityStore 在 fakeStore 上接实体清单(EntityLister)。
type fakeEntityStore struct {
	*fakeStore
	ents []entity.Row
}

func (f *fakeEntityStore) ListEntities(context.Context, string) ([]entity.Row, error) {
	return f.ents, nil
}

// ---- 装载校验 ----

func TestCompileEntityRule(t *testing.T) {
	// 正样本:单机实体规则(裸键 = eq,树庭附录 A 语义)
	r, err := CompileRule("t.yaml", `
id: exfil-cloud-storage-domain
title: 网盘域名实体
severity: medium
target: entity
match:
  entity_type: [domain]
  raw_value_contains: [pan.baidu, mega.nz]
`)
	if err != nil {
		t.Fatalf("实体规则装载失败: %v", err)
	}
	if r.MinHosts != 0 || len(r.Match) != 2 {
		t.Fatalf("实体规则编译态错: %+v", r)
	}
	if r.Match[0].Op != MatchOpEq {
		t.Fatalf("实体规则裸键应 eq(树庭附录 A),实得 %q", r.Match[0].Op)
	}
	if r.Match[1].Op != MatchOpContains {
		t.Fatalf("_contains 后缀应 contains,实得 %q", r.Match[1].Op)
	}

	// 正样本:跨机规则(min_hosts 保留键)
	r, err = CompileRule("t2.yaml", `
id: xhost-shared-public-ip
title: 同一公网 IP 出现在多台主机
severity: medium
target: entity
match:
  entity_type: [ip]
  qualifier: [global]
  min_hosts: 2
`)
	if err != nil {
		t.Fatalf("跨机实体规则装载失败: %v", err)
	}
	if r.MinHosts != 2 || len(r.Match) != 2 {
		t.Fatalf("跨机规则编译态错: %+v", r)
	}

	// 负样本:未知实体字段 / min_hosts 非法 / min_hosts 用于事件规则
	for _, bad := range []string{`
id: bad-1
title: x
severity: low
target: entity
match:
  src_ip: [x]
`, `
id: bad-2
title: x
severity: low
target: entity
match:
  entity_type: [ip]
  min_hosts: 1
`, `
id: bad-3
title: x
severity: low
target: entity
match:
  entity_type: [ip]
  min_hosts: [2]
`, `
id: bad-4
title: x
severity: low
target: any
match:
  src_ip: [x]
  min_hosts: 2
`} {
		if _, err := CompileRule("bad.yaml", bad); err == nil {
			t.Fatalf("非法实体规则应拒载: %s", bad)
		}
	}
}

// ---- 单机实体规则扫描 ----

func TestScanEntityRuleSingleHost(t *testing.T) {
	st := &fakeEntityStore{fakeStore: newFakeStore(), ents: []entity.Row{
		{CaseID: "c1", Host: "h1", EntityType: "domain", RawValue: "Pan.Baidu.com",
			CanonicalKey: "dom:pan.baidu.com", Qualifier: "global", SourceID: "s1", LineNo: 7},
		{CaseID: "c1", Host: "h1", EntityType: "domain", RawValue: "internal.corp",
			CanonicalKey: "dom:internal.corp", Qualifier: "global", SourceID: "s1", LineNo: 9},
		{CaseID: "c1", Host: "h1", EntityType: "ip", RawValue: "pan.baidu.com", // 类型不符不命中
			CanonicalKey: "ip:1.2.3.4", Qualifier: "global", SourceID: "s1", LineNo: 11},
	}}
	eng := newEngineWithStore(t, st, `
id: exfil-cloud-storage-domain
title: 网盘域名实体
severity: medium
target: entity
match:
  entity_type: [domain]
  raw_value_contains: [pan.baidu, mega.nz]
`)
	sum, err := eng.Scan(context.Background(), "c1", "tester", nil)
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	if sum.Rules[0].Scanned != 3 || sum.Rules[0].HitsNew != 1 {
		t.Fatalf("扫描账错: %+v", sum.Rules[0])
	}
	hits, _ := eng.Hits(context.Background(), "c1", HitFilter{})
	if len(hits) != 1 {
		t.Fatalf("候选数 = %d, want 1", len(hits))
	}
	h := hits[0]
	if h.SourceID != "s1" || h.LineNo != 7 || h.MatchedField != "entity_type" {
		t.Fatalf("锚点/命中字段错: %+v", h)
	}
	if h.Status != "pending" || h.EvidenceGrade != "suspect" {
		t.Fatalf("候选态错(判断权归人): %+v", h)
	}
	if !strings.Contains(h.DetailJSON, "disclaimer") || !strings.Contains(h.Snippet, "dom:pan.baidu.com") {
		t.Fatalf("detail/snippet 留证不全: %+v", h)
	}
}

// ---- 跨机实体规则:私网排除 + min_hosts 闸 ----

func TestScanEntityRuleCrossHost(t *testing.T) {
	st := &fakeEntityStore{fakeStore: newFakeStore(), ents: []entity.Row{
		// 公网 IP 跨两机 → 命中
		{CaseID: "c1", Host: "h1", EntityType: "ip", RawValue: "8.8.8.8",
			CanonicalKey: "ip:8.8.8.8", Qualifier: "global", SourceID: "s1", LineNo: 3},
		{CaseID: "c1", Host: "h2", EntityType: "ip", RawValue: "8.8.8.8",
			CanonicalKey: "ip:8.8.8.8", Qualifier: "global", SourceID: "s2", LineNo: 5},
		// 同一公网 IP 同机两源 → 主机数 1,不达闸
		{CaseID: "c1", Host: "h1", EntityType: "ip", RawValue: "9.9.9.9",
			CanonicalKey: "ip:9.9.9.9", Qualifier: "global", SourceID: "s1", LineNo: 8},
		{CaseID: "c1", Host: "h1", EntityType: "ip", RawValue: "9.9.9.9",
			CanonicalKey: "ip:9.9.9.9", Qualifier: "global", SourceID: "s3", LineNo: 2},
		// 私网(host_scoped)同值跨机 → 结构性排除,永不命中
		{CaseID: "c1", Host: "h1", EntityType: "ip", RawValue: "192.168.1.10",
			CanonicalKey: "ip:192.168.1.10@h1", Qualifier: "host_scoped", SourceID: "s1", LineNo: 1},
		{CaseID: "c1", Host: "h2", EntityType: "ip", RawValue: "192.168.1.10",
			CanonicalKey: "ip:192.168.1.10@h2", Qualifier: "host_scoped", SourceID: "s2", LineNo: 1},
		// 公网但主机未建模 → 不计数
		{CaseID: "c1", Host: "", EntityType: "ip", RawValue: "8.8.8.8",
			CanonicalKey: "ip:8.8.8.8", Qualifier: "global", SourceID: "s4", LineNo: 1},
	}}
	eng := newEngineWithStore(t, st, `
id: xhost-shared-public-ip
title: 同一公网 IP 出现在多台主机
severity: medium
target: entity
match:
  entity_type: [ip]
  qualifier: [global]
  min_hosts: 2
`)
	sum, err := eng.Scan(context.Background(), "c1", "tester", nil)
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	if sum.Rules[0].HitsNew != 1 {
		t.Fatalf("跨机命中 = %d, want 1(仅 8.8.8.8): %+v", sum.Rules[0].HitsNew, sum.Rules[0])
	}
	hits, _ := eng.Hits(context.Background(), "c1", HitFilter{})
	if len(hits) != 1 {
		t.Fatalf("候选数 = %d, want 1", len(hits))
	}
	h := hits[0]
	if h.MatchedField != "canonical_key" || h.MatchedValue != "ip:8.8.8.8" {
		t.Fatalf("跨机命中键错: %+v", h)
	}
	if !strings.Contains(h.DetailJSON, `"host_count":2`) ||
		!strings.Contains(h.DetailJSON, `"h1"`) || !strings.Contains(h.DetailJSON, `"h2"`) {
		t.Fatalf("跨机 detail 主机清单缺: %s", h.DetailJSON)
	}
	if !strings.Contains(h.DetailJSON, `"unmodeled_entities_skipped":1`) {
		t.Fatalf("未建模主机计数应如实记: %s", h.DetailJSON)
	}

	// 重跑去重幂等
	sum2, err := eng.Scan(context.Background(), "c1", "tester", nil)
	if err != nil {
		t.Fatalf("重扫失败: %v", err)
	}
	if sum2.Rules[0].HitsNew != 0 || sum2.Rules[0].HitsDup != 1 {
		t.Fatalf("重跑去重幂等失守: %+v", sum2.Rules[0])
	}
}

// 存储未接实体层 → 实体规则如实报错(不静默跳过)。
func TestScanEntityRuleNoEntityStore(t *testing.T) {
	eng := newEngineWithStore(t, newFakeStore(), `
id: xhost-shared-public-ip
title: x
severity: low
target: entity
match:
  entity_type: [ip]
  min_hosts: 2
`)
	_, err := eng.Scan(context.Background(), "c1", "tester", nil)
	if err == nil || !strings.Contains(err.Error(), "实体") {
		t.Fatalf("无实体存储应如实报错: %v", err)
	}
}
