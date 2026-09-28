// 扫描引擎:规则(数据) → 检索层流式扫描(单一检索层纪律) → 候选落库
// (pending,去重幂等,预算帽) → 轮次台账;人裁决通路。
// 切片四起:全量扫描(不指定 rule_ids)同时跑适用域算子(DESIGN §6.1)——
// 算子按源品类路由,不匹配的源不实例化,账上如实记「按域跳过」;
// 命中 evidence_grade 由系统按证据结构算(§6.2 第三面),签名族默认
// 「疑似」如实标。
package review

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ye-mengwen/fengtu/internal/entity"
	"github.com/ye-mengwen/fengtu/internal/operator"
	"github.com/ye-mengwen/fengtu/internal/query"
)

// Engine 规则引擎。
type Engine struct {
	rules map[string]*Rule
	order []string // 装载序(文件名字典序)
	qs    *query.Service
	store Store
	ops   *operator.Registry // nil = 不跑算子(向后兼容)
	now   func() time.Time
}

// NewEngine 构造(rules 来自 LoadRulesDir/CompileRule)。
func NewEngine(rules []*Rule, qs *query.Service, store Store) (*Engine, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("引擎至少需一条规则")
	}
	e := &Engine{rules: map[string]*Rule{}, qs: qs, store: store, now: time.Now}
	for _, r := range rules {
		if _, dup := e.rules[r.ID]; dup {
			return nil, fmt.Errorf("规则 id 冲突: %q", r.ID)
		}
		e.rules[r.ID] = r
		e.order = append(e.order, r.ID)
	}
	return e, nil
}

// SetClock 测试注入时钟。
func (e *Engine) SetClock(now func() time.Time) { e.now = now }

// SetOperators 接入算子注册表(全量扫描时按适用域路由执行)。
func (e *Engine) SetOperators(reg *operator.Registry) { e.ops = reg }

// Rules 全部已装载规则(装载序)。
func (e *Engine) Rules() []*Rule {
	out := make([]*Rule, 0, len(e.order))
	for _, id := range e.order {
		out = append(out, e.rules[id])
	}
	return out
}

// fieldValue 从 fields JSON 取字段文本值:字符串直取,数字/布尔格式化,
// 嵌套对象/数组(如 evtx 的 data=EventData)串化为 JSON 文本后参与子串
// 匹配(CH 侧 JSONExtractString 对嵌套值同样返回串化 JSON,已实测对齐,
// 宽筛与严判同源);缺失 → 空,该字段条件不成立。
func fieldValue(fieldsJSON, field string) string {
	if field == "" || fieldsJSON == "" {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(fieldsJSON), &m); err != nil {
		return ""
	}
	v, ok := m[field]
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return fmt.Sprintf("%v", t)
	case bool:
		return fmt.Sprintf("%v", t)
	case map[string]any, []any:
		// SetEscapeHTML(false):与 CH JSONExtractString 的串化口径对齐
		// (默认 json.Marshal 会把 <>& 转 \uXXXX,子串匹配会劈叉)。
		var b strings.Builder
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(t); err != nil {
			return ""
		}
		return strings.TrimRight(b.String(), "\n")
	default:
		return ""
	}
}

// condHit 单条匹配条件(op + 值列表 OR)对字段文本的判定(大小写不敏感,
// hay 已转小写、subs 编译期已转小写)。
func condHit(hayLower string, fm FieldMatch) (string, bool) {
	for _, sub := range fm.Subs {
		switch fm.Op {
		case MatchOpEq:
			if hayLower == sub {
				return sub, true
			}
		case MatchOpPrefix:
			if strings.HasPrefix(hayLower, sub) {
				return sub, true
			}
		case MatchOpEndsWith:
			if strings.HasSuffix(hayLower, sub) {
				return sub, true
			}
		default: // contains(裸键存量默认 + 显式 _contains)
			if strings.Contains(hayLower, sub) {
				return sub, true
			}
		}
	}
	return "", false
}

// matchRule 一条事件套一条规则(引擎按 spec 执行,Go 侧复判:
// SQL 预筛与 Go 复判同一 conds,复判给出 matched_field/matched_value)。
//
// 语义(对齐树庭附录 A):去后缀后同一字段的多条件之间取 OR,不同字段
// 之间 AND;命中返回首个命中字段(声明序)与首个命中值(列表序),
// 否则 ok=false。
func matchRule(r *Rule, fieldsJSON, raw string) (field, value string, ok bool) {
	// 按声明序分组成「字段 → 条件列表」(同字段保持声明序)。
	var groups []struct {
		field string
		conds []FieldMatch
	}
	idx := map[string]int{}
	for _, fm := range r.Match {
		if i, has := idx[fm.Field]; has {
			groups[i].conds = append(groups[i].conds, fm)
			continue
		}
		idx[fm.Field] = len(groups)
		groups = append(groups, struct {
			field string
			conds []FieldMatch
		}{field: fm.Field, conds: []FieldMatch{fm}})
	}
	for _, g := range groups {
		var hay string
		if g.field == "raw" {
			hay = raw
		} else {
			hay = fieldValue(fieldsJSON, g.field)
		}
		hayLower := strings.ToLower(hay)
		matched := ""
		for _, fm := range g.conds { // 同字段多条件 OR
			if v, hit := condHit(hayLower, fm); hit {
				matched = v
				break
			}
		}
		if matched == "" {
			return "", "", false // 字段条件 AND:任一不命中即整体不命中
		}
		if field == "" {
			field, value = g.field, matched
		}
	}
	return field, value, true
}

// matchConds 规则 match → 检索层字段条件(SQL 预筛与 Go 复判同源)。
//
// 下推纪律:eq/prefix 都是 contains 的子集(eq ⇒ contains,prefix ⇒
// contains),所以 SQL 侧统一以 contains 宽筛(同字段多条件值取并集),
// Go 复判按声明的 op 严判——宽筛放行、严判定夺,语义零损耗,检索层
// 零改动。嵌套字段(evtx data)CH JSONExtractString 返回串化 JSON,
// 与 Go fieldValue 串化口径已实测对齐。
func matchConds(r *Rule) []query.FieldCond {
	var conds []query.FieldCond
	idx := map[string]int{}
	for _, fm := range r.Match {
		if i, has := idx[fm.Field]; has {
			conds[i].Values = append(conds[i].Values, fm.Subs...)
			continue
		}
		idx[fm.Field] = len(conds)
		conds = append(conds, query.FieldCond{
			Field: fm.Field, Op: query.OpContains, Values: append([]string{}, fm.Subs...),
		})
	}
	return conds
}

// Scan 跑一轮扫描(ruleIDs 空 = 全量;轮次每案件递增,台账如实)。
// 返回总账;单规则失败即整轮失败(轮次账留 failed 摘要,零静默)。
func (e *Engine) Scan(ctx context.Context, caseID, actor string,
	ruleIDs []string) (*ScanSummary, error) {

	var picked []*Rule
	if len(ruleIDs) == 0 {
		picked = e.Rules()
	} else {
		for _, id := range ruleIDs {
			r, ok := e.rules[id]
			if !ok {
				return nil, fmt.Errorf("未知规则 id: %q", id)
			}
			picked = append(picked, r)
		}
	}
	ruleIDsJSON := ""
	if len(ruleIDs) > 0 {
		b, _ := json.Marshal(ruleIDs)
		ruleIDsJSON = string(b)
	}
	runID, round, err := e.store.CreateScanRun(ctx, caseID, actor, ruleIDsJSON, e.now())
	if err != nil {
		return nil, fmt.Errorf("扫描轮次开账失败: %w", err)
	}

	sum := &ScanSummary{RunID: runID, RoundNo: round}
	var scanErr error
	for _, r := range picked {
		rs := RuleSummary{RuleID: r.ID}
		if r.Target == "entity" {
			// 实体层规则(0.25.0):扫 PG entities 表,不走事件检索层
			serr := e.scanEntityRule(ctx, r, caseID, round, &rs)
			sum.Rules = append(sum.Rules, rs)
			if serr != nil {
				scanErr = fmt.Errorf("规则 %s 扫描失败: %w", r.ID, serr)
				break
			}
			continue
		}
		params := query.Params{CaseID: caseID, Conds: matchConds(r)}
		serr := e.qs.StreamMatch(ctx, params, func(ev query.Event) error {
			rs.Scanned++
			field, value, ok := matchRule(r, ev.Fields, ev.Raw)
			if !ok {
				return nil // 宽筛放行,严判不命中
			}
			if rs.HitsNew >= r.MaxHits {
				rs.Truncated++
				return nil // 预算帽:超出如实记 truncated,不落库
			}
			snippet := ev.Raw
			if utf8.RuneCountInString(snippet) > snippetMaxRunes {
				snippet = string([]rune(snippet)[:snippetMaxRunes])
			}
			detail, _ := json.Marshal(map[string]string{
				"rule_title": r.Title,
				"note":       r.Note,
				"disclaimer": Disclaimer,
				"evidence":   "签名族命中:单点+上下文,默认「疑似」档(§6.2 如实标)",
			})
			inserted, err := e.store.InsertHit(ctx, Hit{
				CaseID: caseID, SourceID: ev.SourceID, LineNo: ev.LineNo,
				RuleID: r.ID, Severity: r.Severity,
				MatchedField: field, MatchedValue: value,
				Snippet: snippet, TsUTC: ev.TS, Status: "pending",
				RoundNo: round, EvidenceGrade: operator.GradeSuspect,
				DetailJSON: string(detail),
			}, e.now())
			if err != nil {
				return fmt.Errorf("候选落库失败(%s L%d): %w", ev.SourceID, ev.LineNo, err)
			}
			if inserted {
				rs.HitsNew++
			} else {
				rs.HitsDup++
			}
			return nil
		})
		sum.Rules = append(sum.Rules, rs)
		if serr != nil {
			scanErr = fmt.Errorf("规则 %s 扫描失败: %w", r.ID, serr)
			break
		}
	}

	// 全量扫描(不指定 rule_ids)跑适用域算子;指定规则集的扫描不夹带算子
	// (轮次语义:勾什么扫什么)。
	if scanErr == nil && len(ruleIDs) == 0 && e.ops != nil {
		opSums, oerr := e.scanOperators(ctx, caseID, round)
		sum.Operators = opSums
		if oerr != nil {
			scanErr = oerr
		}
	}

	summaryJSON, _ := json.Marshal(sum)
	statusNote := ""
	if scanErr != nil {
		summaryJSON, _ = json.Marshal(map[string]any{
			"run_id": runID, "round_no": round, "failed": scanErr.Error(),
			"rules": sum.Rules,
		})
		statusNote = fmt.Sprintf("(轮次账已记 failed 摘要)")
	}
	if ferr := e.store.FinishScanRun(ctx, runID, string(summaryJSON)); ferr != nil && scanErr == nil {
		scanErr = fmt.Errorf("扫描轮次收尾失败: %w", ferr)
	}
	if scanErr != nil {
		return sum, fmt.Errorf("%w%s", scanErr, statusNote)
	}
	return sum, nil
}

// ---- 实体层规则(target=entity,0.25.0-datasource-unlock) ----

// entityFieldValue 实体行字段取值(EntityMatchFields 四列;缺失 → 空,
// 该字段条件不成立,与事件规则同语义)。
func entityFieldValue(ent entity.Row, field string) string {
	switch field {
	case "entity_type":
		return ent.EntityType
	case "raw_value":
		return ent.RawValue
	case "canonical_key":
		return ent.CanonicalKey
	case "qualifier":
		return ent.Qualifier
	}
	return ""
}

// matchEntity 实体行套一条实体规则(matchRule 同语义:同字段条件 OR、
// 不同字段 AND、大小写不敏感;命中返回首个命中字段与值)。
func matchEntity(r *Rule, ent entity.Row) (field, value string, ok bool) {
	var groups []struct {
		field string
		conds []FieldMatch
	}
	idx := map[string]int{}
	for _, fm := range r.Match {
		if i, has := idx[fm.Field]; has {
			groups[i].conds = append(groups[i].conds, fm)
			continue
		}
		idx[fm.Field] = len(groups)
		groups = append(groups, struct {
			field string
			conds []FieldMatch
		}{field: fm.Field, conds: []FieldMatch{fm}})
	}
	for _, g := range groups {
		hayLower := strings.ToLower(entityFieldValue(ent, g.field))
		matched := ""
		for _, fm := range g.conds {
			if v, hit := condHit(hayLower, fm); hit {
				matched = v
				break
			}
		}
		if matched == "" {
			return "", "", false
		}
		if field == "" {
			field, value = g.field, matched
		}
	}
	return field, value, true
}

// scanEntityRule 实体层规则扫描(单机:逐实体匹配;跨机:min_hosts≥2 时
// 对 qualifier=global 实体按 canonical_key 聚合 COUNT(DISTINCT host)>=
// min_hosts——树庭 §8.2 语义;私网/host_scoped 实体结构性排除,主机未
// 建模的实体不计数,账上如实记)。
func (e *Engine) scanEntityRule(ctx context.Context, r *Rule, caseID string,
	round int, rs *RuleSummary) error {

	lister, ok := e.store.(EntityLister)
	if !ok {
		return fmt.Errorf("实体规则需要实体存储(entities 表),当前存储未实现 EntityLister")
	}
	ents, err := lister.ListEntities(ctx, caseID)
	if err != nil {
		return err
	}
	rs.Scanned = int64(len(ents))

	insert := func(ent entity.Row, field, value string, detail map[string]any) error {
		if rs.HitsNew >= r.MaxHits {
			rs.Truncated++
			return nil
		}
		detail["rule_title"] = r.Title
		detail["note"] = r.Note
		detail["disclaimer"] = Disclaimer
		detail["evidence"] = "实体层签名命中:按 canonical_key/qualifier 结构匹配,默认「疑似」档(§6.2 如实标)"
		dj, _ := json.Marshal(detail)
		snippet := ent.RawValue + " (" + ent.CanonicalKey + ")"
		if utf8.RuneCountInString(snippet) > snippetMaxRunes {
			snippet = string([]rune(snippet)[:snippetMaxRunes])
		}
		inserted, err := e.store.InsertHit(ctx, Hit{
			CaseID: caseID, SourceID: ent.SourceID, LineNo: ent.LineNo,
			RuleID: r.ID, Severity: r.Severity,
			MatchedField: field, MatchedValue: value,
			Snippet: snippet, Status: "pending",
			RoundNo: round, EvidenceGrade: operator.GradeSuspect,
			DetailJSON: string(dj),
		}, e.now())
		if err != nil {
			return fmt.Errorf("实体候选落库失败(%s L%d): %w", ent.SourceID, ent.LineNo, err)
		}
		if inserted {
			rs.HitsNew++
		} else {
			rs.HitsDup++
		}
		return nil
	}

	if r.MinHosts < 2 { // 单机实体规则:逐实体匹配
		for _, ent := range ents {
			field, value, hit := matchEntity(r, ent)
			if !hit {
				continue
			}
			if err := insert(ent, field, value, map[string]any{
				"entity_type": ent.EntityType, "host": ent.Host,
				"canonical_key": ent.CanonicalKey, "qualifier": ent.Qualifier,
			}); err != nil {
				return err
			}
		}
		return nil
	}

	// 跨机聚合:qualifier=global 是唯一入场券(结构性闸,不依赖规则声明)
	type xagg struct {
		hosts  map[string]bool
		anchor entity.Row
	}
	groups := map[string]*xagg{}
	unmodeled := 0
	for _, ent := range ents {
		if ent.Qualifier != entity.QualGlobal {
			continue // 私网/host_scoped 永不跨机(§9.2,防假联动)
		}
		if ent.Host == "" {
			unmodeled++
			continue
		}
		if _, _, hit := matchEntity(r, ent); !hit {
			continue
		}
		g := groups[ent.CanonicalKey]
		if g == nil {
			g = &xagg{hosts: map[string]bool{}, anchor: ent}
			groups[ent.CanonicalKey] = g
		}
		g.hosts[ent.Host] = true
	}
	for key, g := range groups {
		if len(g.hosts) < r.MinHosts {
			continue
		}
		hosts := make([]string, 0, len(g.hosts))
		for h := range g.hosts {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		if err := insert(g.anchor, "canonical_key", key, map[string]any{
			"entity_type": g.anchor.EntityType, "canonical_key": key,
			"host_count": len(hosts), "hosts": hosts,
			"unmodeled_entities_skipped": unmodeled,
		}); err != nil {
			return err
		}
	}
	return nil
}

// Verdict 人裁决(accepted|rejected;留裁决人/时刻/备注;审计由 web 层追加)。
func (e *Engine) Verdict(ctx context.Context, hitID, actor, status, note string) (*Hit, error) {
	if !verdictStatuses[status] {
		return nil, fmt.Errorf("裁决状态须为 accepted|rejected: %q", status)
	}
	// 先查后改:无此候选如实 404(也让非 UUID 形态的 id 不走 SQL 报错)
	h, err := e.store.GetHit(ctx, hitID)
	if err != nil {
		return nil, fmt.Errorf("候选查询失败: %w", err)
	}
	if h == nil {
		return nil, fmt.Errorf("无此候选: %s", hitID)
	}
	ok, err := e.store.SetVerdict(ctx, hitID, actor, status, note, e.now())
	if err != nil {
		return nil, fmt.Errorf("裁决落库失败: %w", err)
	}
	if !ok {
		// CAS 落空(先查后改之间被并发抢先):候选仍在 = 已被他人裁决
		// (409 语义);候选没了 = 并发删除,按无此候选如实 404
		cur, gerr := e.store.GetHit(ctx, hitID)
		if gerr != nil {
			return nil, fmt.Errorf("裁决冲突回查失败: %w", gerr)
		}
		if cur == nil {
			return nil, fmt.Errorf("无此候选: %s", hitID)
		}
		return nil, fmt.Errorf("%w(现状态 %s)", ErrVerdictConflict, cur.Status)
	}
	return e.store.GetHit(ctx, hitID)
}

// Hits 待审区查询。
func (e *Engine) Hits(ctx context.Context, caseID string, f HitFilter) ([]Hit, error) {
	if f.Status != "" && f.Status != "pending" && !verdictStatuses[f.Status] {
		return nil, fmt.Errorf("status 过滤须为 pending|accepted|rejected: %q", f.Status)
	}
	return e.store.ListHits(ctx, caseID, f)
}

// ScanRuns 轮次台账。
func (e *Engine) ScanRuns(ctx context.Context, caseID string) ([]ScanRun, error) {
	return e.store.ListScanRuns(ctx, caseID)
}

// scanOperators 适用域算子执行:按源品类路由(不匹配的源不实例化,账上
// 如实记「按域跳过」),命中 detail 直给原始统计量,evidence_grade 由
// 系统按证据结构算(Grade),预算帽与去重幂等同签名规则。
func (e *Engine) scanOperators(ctx context.Context, caseID string,
	round int) ([]OperatorSummary, error) {

	srcs, err := e.store.ListSourcesForScan(ctx, caseID)
	if err != nil {
		return nil, fmt.Errorf("算子路由源清单查询失败: %w", err)
	}
	opSrcs := make([]operator.Source, 0, len(srcs))
	for _, s := range srcs {
		opSrcs = append(opSrcs, operator.Source{
			ID: s.ID, Kind: s.Kind, LogType: s.LogType, ArtifactType: s.ArtifactType,
			Host: s.Host,
		})
	}
	stream := func(sourceID string, fn func(query.Event) error) error {
		return e.qs.StreamMatch(ctx,
			query.Params{CaseID: caseID, SourceID: sourceID}, fn)
	}

	var sums []OperatorSummary
	for _, spec := range e.ops.Specs() {
		os := OperatorSummary{OpID: spec.ID, Implemented: spec.Implemented}
		sums = append(sums, os) // 先占位,下面按下标回填(未实现也要在账上)
		cur := &sums[len(sums)-1]
		if !spec.Implemented {
			cur.Note = "未实现(只注册不实例化,§6.1)"
			continue
		}
		impl, ok := e.ops.Impl(spec.ID)
		if !ok {
			cur.Note = "未实现(只注册不实例化,§6.1)"
			cur.Implemented = false
			continue
		}
		var matched []operator.Source
		for _, s := range opSrcs {
			if spec.Match(s) {
				matched = append(matched, s)
			} else {
				cur.SkippedDomain++
			}
		}
		cur.MatchedSources = len(matched)
		if len(matched) == 0 {
			cur.Note = "无适用域内源,全部按域跳过"
			continue
		}
		findings, rerr := impl.Run(spec, matched, stream)
		if rerr != nil {
			return sums, fmt.Errorf("算子 %s 执行失败: %w", spec.ID, rerr)
		}
		cur.Findings = len(findings)
		maxHits := spec.MaxHits
		if maxHits <= 0 {
			maxHits = DefaultMaxHits
		}
		for _, f := range findings {
			if cur.HitsNew >= maxHits {
				cur.Truncated++
				continue
			}
			grade, gerr := operator.Grade(f.Evidence)
			if gerr != nil {
				return sums, fmt.Errorf("算子 %s 证据结构不成立: %w", spec.ID, gerr)
			}
			snippet := f.Snippet
			if utf8.RuneCountInString(snippet) > snippetMaxRunes {
				snippet = string([]rune(snippet)[:snippetMaxRunes])
			}
			detail, _ := json.Marshal(map[string]any{
				"op_title": spec.Title, "note": spec.Note,
				"disclaimer": Disclaimer,
				"stats":      f.Detail, // 原始统计量直给,不包装置信度(§6.2)
				"evidence":   f.Evidence,
			})
			inserted, ierr := e.store.InsertHit(ctx, Hit{
				CaseID: caseID, SourceID: f.SourceID, LineNo: f.LineNo,
				RuleID: spec.ID, Severity: spec.Severity,
				MatchedField: f.MatchedField, MatchedValue: f.MatchedValue,
				Snippet: snippet, TsUTC: f.TS, Status: "pending",
				RoundNo: round, EvidenceGrade: grade,
				DetailJSON: string(detail),
			}, e.now())
			if ierr != nil {
				return sums, fmt.Errorf("算子 %s 候选落库失败(%s L%d): %w",
					spec.ID, f.SourceID, f.LineNo, ierr)
			}
			if inserted {
				cur.HitsNew++
			} else {
				cur.HitsDup++
			}
		}
	}
	return sums, nil
}

// RuleStats 规则/算子裁决统计(窗口由调用方给,API 口径近 90 天):
// 候选数/接受数/接受率直给;裁决样本足够且接受率为 0 → 待复审(退役闸,
// §6.2 第四面)。已装载规则/算子零命中也列(计数 0,如实)。
func (e *Engine) RuleStats(ctx context.Context, caseID string,
	since time.Time) ([]RuleStat, error) {

	raw, err := e.store.RuleStatsRaw(ctx, caseID, since)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]*RuleStat, len(raw))
	out := make([]RuleStat, 0, len(raw)+len(e.order))
	for i := range raw {
		st := raw[i]
		decided := st.Accepted + st.Rejected
		if decided > 0 {
			rate := float64(st.Accepted) / float64(decided)
			st.AcceptanceRate = &rate
			st.NeedsReview = decided >= NeedsReviewMinDecided && st.Accepted == 0
		}
		byID[st.RuleID] = &st
		out = append(out, st)
	}
	// 零命中规则/算子补零档(装载序),清单一眼看全
	known := func(id string) bool { _, ok := byID[id]; return ok }
	for _, id := range e.order {
		if !known(id) {
			out = append(out, RuleStat{RuleID: id})
		}
	}
	if e.ops != nil {
		for _, spec := range e.ops.Specs() {
			if !known(spec.ID) {
				out = append(out, RuleStat{RuleID: spec.ID})
			}
		}
	}
	return out, nil
}
