// web 层 API 契约测试(httptest 全闭环):
// 首启 → 登录 → 分块上传(乱序+逐块校验) → 异步摄入 → 检索 → 原文回查 →
// 规则扫描 → 待审 → 裁决 → 审计链校验;外加登录闸/拒收/负样本。
//
// fakeCH 是 in-memory 检索执行器:按 builder 生成的 SQL 形态逐占位符
// 求值(不是罐头返回)——契约测试走的是真 SQL 语义。
package web

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ye-mengwen/fengtu/internal/audit"
	"github.com/ye-mengwen/fengtu/internal/ingest"
	"github.com/ye-mengwen/fengtu/internal/ingest/store"
	"github.com/ye-mengwen/fengtu/internal/intent"
	"github.com/ye-mengwen/fengtu/internal/query"
	"github.com/ye-mengwen/fengtu/internal/review"
)

// ---- fakeCH:按 SQL 占位符顺序求值的 in-memory CH ----

type fakeCH struct {
	mu           sync.Mutex
	rows         []query.Event
	caseBySource map[string]string // source_id → case_id(InsertEvents 建账)
	lastQ        string
	lastA        []any
	deletedRows  int // 重解析通路删除行数(测试断言用)
}

func newFakeCH() *fakeCH { return &fakeCH{caseBySource: map[string]string{}} }

// DeleteEventsForSource 重解析通路(fake):删该源全部行并记账。
func (f *fakeCH) DeleteEventsForSource(_ context.Context, caseID, sourceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	kept := f.rows[:0]
	deleted := 0
	for _, r := range f.rows {
		if r.SourceID == sourceID && f.caseBySource[sourceID] == caseID {
			deleted++
			continue
		}
		kept = append(kept, r)
	}
	f.rows = kept
	f.deletedRows += deleted
	return nil
}

// DeleteEventsForCase 案件删除级联(fake):删该案全部行并记账。
func (f *fakeCH) DeleteEventsForCase(_ context.Context, caseID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	kept := f.rows[:0]
	deleted := 0
	for _, r := range f.rows {
		if f.caseBySource[r.SourceID] == caseID {
			deleted++
			continue
		}
		kept = append(kept, r)
	}
	f.rows = kept
	f.deletedRows += deleted
	return nil
}

// CountEventsForCase 案件事件计数(fake;删除前审计快照)。
func (f *fakeCH) CountEventsForCase(_ context.Context, caseID string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for _, r := range f.rows {
		if f.caseBySource[r.SourceID] == caseID {
			n++
		}
	}
	return n, nil
}

func (f *fakeCH) InsertEvents(_ context.Context, rows []ingest.EventRow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range rows {
		f.rows = append(f.rows, query.Event{
			SourceID: r.SourceID, LineNo: r.LineNo, TS: r.TS,
			Kind: r.Kind, Fields: r.Fields, Raw: r.Raw,
		})
		f.caseBySource[r.SourceID] = r.CaseID
	}
	return nil
}

func (f *fakeCH) QueryEvents(_ context.Context, sql string, args ...any) ([]query.Event, error) {
	f.mu.Lock()
	f.lastQ, f.lastA = sql, args
	f.mu.Unlock()
	matched := f.evalFilter(sql, args)
	// LIMIT/OFFSET(末两个 int 参数)
	limit, offset := 100, 0
	if n := len(args); n >= 2 {
		if l, ok := args[n-2].(int); ok {
			limit = l
		}
		if o, ok := args[n-1].(int); ok {
			offset = o
		}
	}
	if offset > len(matched) {
		return nil, nil
	}
	matched = matched[offset:]
	if len(matched) > limit {
		matched = matched[:limit]
	}
	return matched, nil
}

func (f *fakeCH) StreamEvents(_ context.Context, sql string, args []any,
	fn func(query.Event) error) error {
	for _, e := range f.evalFilter(sql, args) {
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

// QueryStats 聚合(fake 只认时间线两种形态;未知形态 panic,与 evalFilter 同纪律)。
func (f *fakeCH) QueryStats(_ context.Context, sql string, args ...any) ([]query.StatRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	caseID, _ := args[0].(string)
	inCase := func(r query.Event) bool { return f.caseBySource[r.SourceID] == caseID }
	switch {
	case strings.Contains(sql, "toStartOfHour"): // 小时桶密度
		agg := map[string]int64{}
		for _, r := range f.rows {
			if r.TS == nil || !inCase(r) {
				continue
			}
			k := strconv.FormatInt(r.TS.Unix()-r.TS.Unix()%3600, 10)
			agg[k]++
		}
		out := make([]query.StatRow, 0, len(agg))
		for k, c := range agg {
			out = append(out, query.StatRow{Key: k, Count: c})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
		return out, nil
	case strings.Contains(sql, "ts IS NULL"): // 无时区源单列
		agg := map[string]int64{}
		for _, r := range f.rows {
			if r.TS != nil || !inCase(r) {
				continue
			}
			agg[r.SourceID]++
		}
		out := make([]query.StatRow, 0, len(agg))
		for k, c := range agg {
			out = append(out, query.StatRow{Key: k, Count: c})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
		return out, nil
	default:
		panic("fakeCH.QueryStats: 未知 SQL 形态: " + sql)
	}
}

// evalFilter 逐占位符求值(builder 形态白名单;未知形态直接 panic——
// 防 builder 改了形态而 fake 静默放宽)。
//
// 语义:条件组 AND;组内(OR 括号组 / IN 列表)OR。行级:
// case 过滤按 source→case 映射(fakeCH 不存 case_id 列,从 InsertEvents
// 的 EventRow 建 source→case 索引)。
func (f *fakeCH) evalFilter(sql string, args []any) []query.Event {
	f.mu.Lock()
	rows := append([]query.Event(nil), f.rows...)
	caseBySource := make(map[string]string, len(f.caseBySource))
	for k, v := range f.caseBySource {
		caseBySource[k] = v
	}
	f.mu.Unlock()

	type condGroup struct {
		field, op string
		values    []string
	}
	var caseID, kind, sourceID string
	var sourceIDs map[string]bool
	var groups []condGroup
	var tsFrom, tsTo *time.Time

	// 当前占位符是否在前一个 AND 之后的 OR 组内(同组后续值)
	inORGroup := func(idx int) bool {
		clauseStart := strings.LastIndex(sql[:idx], " AND ")
		return strings.Contains(sql[clauseStart:idx], " OR ")
	}
	appendValue := func(field, op, value string, orCont bool) {
		if orCont && len(groups) > 0 && groups[len(groups)-1].field == field {
			groups[len(groups)-1].values = append(groups[len(groups)-1].values, value)
			return
		}
		groups = append(groups, condGroup{field, op, []string{value}})
	}

	ai := 0
	next := func() any { a := args[ai]; ai++; return a }
	pos := 0
	for ai < len(args) {
		rel := strings.Index(sql[pos:], "?")
		if rel < 0 {
			break
		}
		idx := pos + rel
		prefix := sql[max(0, idx-60):idx]
		advance := idx + 1
		switch {
		case strings.HasSuffix(prefix, "case_id = "):
			caseID = next().(string)
		case strings.HasSuffix(prefix, "kind = "):
			kind = next().(string)
		case strings.HasSuffix(prefix, "source_id = "):
			sourceID = next().(string)
		case strings.HasSuffix(prefix, "source_id IN ("):
			// 源集合限定:IN (...) 内全部占位符(SourceIDs,切片七/8b)
			rest := sql[idx+1:]
			end := strings.Index(rest, ")")
			n := 1 + strings.Count(rest[:end], "?") // 首个 ? 在 idx 处,补 1
			sourceIDs = map[string]bool{}
			for i := 0; i < n; i++ {
				sourceIDs[next().(string)] = true
			}
			advance = idx + 1 + end + 1
		case strings.HasSuffix(prefix, "positionCaseInsensitive(raw, "):
			appendValue("raw", "contains", next().(string), inORGroup(idx))
		case strings.HasSuffix(prefix, "ts >= "):
			t := next().(time.Time)
			tsFrom = &t
		case strings.HasSuffix(prefix, "ts <= "):
			t := next().(time.Time)
			tsTo = &t
		case strings.HasSuffix(prefix, "JSONExtractString(fields, "):
			field := next().(string)
			rest := sql[idx+1:]
			switch {
			case strings.HasPrefix(rest, ") IN ("):
				// eq 多值:IN (...) 内全部占位符同组
				end := strings.Index(rest, ")")
				seg := rest[:end]
				n := strings.Count(seg, "?")
				groups = append(groups, condGroup{field, "eq", nil})
				for i := 0; i < n; i++ {
					groups[len(groups)-1].values = append(
						groups[len(groups)-1].values, next().(string))
				}
				advance = idx + 1 + end + 1
			case strings.HasPrefix(rest, ") = "):
				// eq 单值
				vrel := strings.Index(rest, "?")
				appendValue(field, "eq", next().(string), false)
				advance = idx + 1 + vrel + 1
			case strings.HasPrefix(rest, "), "):
				// contains:值在紧随的下一个 ?;OR 组续值
				vrel := strings.Index(rest, "?")
				appendValue(field, "contains", next().(string), inORGroup(idx))
				advance = idx + 1 + vrel + 1
			default:
				panic("fakeCH: JSONExtractString 未知后缀: " + rest[:min(20, len(rest))])
			}
		case strings.HasSuffix(prefix, "LIMIT "), strings.HasSuffix(prefix, "OFFSET "):
			next() // 分页参数,QueryEvents 另行处理
		default:
			panic("fakeCH: 未知 SQL 形态(占位符前缀): " + prefix)
		}
		pos = advance
		if pos > len(sql) {
			break
		}
	}

	var out []query.Event
	for _, e := range rows {
		if caseID != "" && caseBySource[e.SourceID] != caseID {
			continue
		}
		if kind != "" && e.Kind != kind {
			continue
		}
		if sourceID != "" && e.SourceID != sourceID {
			continue
		}
		if sourceIDs != nil && !sourceIDs[e.SourceID] {
			continue
		}
		ok := true
		for _, g := range groups {
			hay := strings.ToLower(e.Raw)
			if g.field != "raw" {
				hay = strings.ToLower(extractField(e.Fields, g.field))
			}
			groupHit := false
			for _, v := range g.values {
				if g.op == "eq" {
					if g.field != "raw" && extractField(e.Fields, g.field) == v {
						groupHit = true
					}
					if g.field == "raw" && e.Raw == v {
						groupHit = true
					}
				} else if strings.Contains(hay, strings.ToLower(v)) {
					groupHit = true
				}
			}
			if !groupHit {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if tsFrom != nil && (e.TS == nil || e.TS.Before(*tsFrom)) {
			continue
		}
		if tsTo != nil && (e.TS == nil || e.TS.After(*tsTo)) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func extractField(fieldsJSON, field string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(fieldsJSON), &m); err != nil {
		return ""
	}
	switch v := m[field].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

// ---- fakeMeta:案件/源/摄入任务账/指纹判定 ----

type fakeMeta struct {
	mu       sync.Mutex
	cases    map[string]string // name → id
	profiles map[string]store.CaseProfile // caseID → 应急元数据(向导)
	archived map[string]bool              // caseID → 已归档(0.18.0)
	runningIntents map[string]int64       // caseID → 在跑意图数(在跑闸测试注入)
	sources  []store.Source
	jobs     map[string]*store.JobState // sourceID → 最新任务账
	next     int
	// 0.27.0 案件封存/迁移(fake;意图图/锚点账,与真库同语义)。
	intentNodes map[string][]*intent.Node // caseID → 节点(创建序)
	intentEdges map[string][]*intent.Edge // caseID → 边(创建序)
	sealAnchors []store.SealAnchor        // 全量锚点(按 CaseID 过滤)
	// 切片十:平台页聚合面的 fake 账(测试按需塞,零值=空如实)。
	llmRecords []store.LLMRecord
	awaiting   []*intent.Node
	pendingParking int64 // 0.24.0 停车场待处置计数(侧边栏徽标测试注入)
	// listPackagesDelay 测试注入(M4 同包名并发):模拟慢查询拉宽
	// 「ListPackages 查重 → 登记」窗口,无 pkgRegLocks 时两并发同包名
	// 必然撞登记冲突——锁存废由测试如实判决。生产 0。
	listPackagesDelay time.Duration
	// 0.31.0 研判报告版本账(fake;与真库同语义:版本按 case+kind 递增)。
	caseReports map[string][]store.CaseReport // caseID → 版本(写入序)
}

func newFakeMeta() *fakeMeta {
	return &fakeMeta{cases: map[string]string{}, archived: map[string]bool{},
		runningIntents: map[string]int64{},
		profiles:       map[string]store.CaseProfile{}, jobs: map[string]*store.JobState{},
		intentNodes: map[string][]*intent.Node{}, intentEdges: map[string][]*intent.Edge{}}
}

func (f *fakeMeta) EnsureCase(_ context.Context, name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id, ok := f.cases[name]; ok {
		return id, nil
	}
	f.next++
	// UUID 形态(schema 001_init 案件主键是 UUID;工作区案件闸按形态预检)
	id := fmt.Sprintf("00000000-0000-0000-0000-%012d", f.next)
	f.cases[name] = id
	return id, nil
}

func (f *fakeMeta) RegisterSource(_ context.Context, s ingest.SourceInfo) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, es := range f.sources {
		if es.CaseID == s.CaseID && es.Path == s.Path {
			return "", fmt.Errorf("同案同路径(%s)重复摄入,拒绝登记", s.Path)
		}
	}
	f.next++
	id := fmt.Sprintf("src-%08d-0000-0000-0000-000000000000", f.next)
	f.sources = append(f.sources, store.Source{
		ID: id, CaseID: s.CaseID, Path: s.Path, SHA256: s.SHA256,
		SizeBytes: s.SizeBytes, Kind: string(s.Kind),
		ArtifactType: s.ArtifactType, Host: s.Host, Package: s.Package,
		DetectStatus: "none",
		CreatedAt:    time.Now().UTC(),
	})
	return id, nil
}

func (f *fakeMeta) StartJob(_ context.Context, sourceID, caseID, parser string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jobs[sourceID] = &store.JobState{Status: "running", Parser: parser}
	return "job-" + sourceID, nil
}

func (f *fakeMeta) FinishJob(_ context.Context, jobID string, fin ingest.JobFinish) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	sourceID := strings.TrimPrefix(jobID, "job-")
	j, ok := f.jobs[sourceID]
	if !ok {
		return nil
	}
	j.Status = fin.Status
	j.RowsTotal, j.RowsEvent, j.RowsBad, j.RowsSkip =
		fin.RowsTotal, fin.RowsEvent, fin.RowsBad, fin.RowsSkip
	return nil
}

func (f *fakeMeta) LatestJob(_ context.Context, sourceID string) (*store.JobState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	j, ok := f.jobs[sourceID]
	if !ok {
		return nil, nil
	}
	cp := *j
	return &cp, nil
}

// ListPackages 一案多包:已登记包根名清单(fake)。
func (f *fakeMeta) ListPackages(_ context.Context, caseID string) ([]string, error) {
	if f.listPackagesDelay > 0 {
		time.Sleep(f.listPackagesDelay) // 测试注入:拉宽查重→登记窗口
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, s := range f.sources {
		if s.CaseID == caseID && s.Package != "" && !seen[s.Package] {
			seen[s.Package] = true
			out = append(out, s.Package)
		}
	}
	return out, nil
}

func (f *fakeMeta) SetDetection(_ context.Context, sourceID string, d store.Detection) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.sources {
		if f.sources[i].ID == sourceID {
			f.sources[i].DetectFormat = d.Format
			f.sources[i].DetectConfidence = d.Confidence
			f.sources[i].DetectStatus = d.Status
			if d.LogType != "" {
				f.sources[i].LogType = d.LogType
			}
			return nil
		}
	}
	return fmt.Errorf("无此源: %s", sourceID)
}

func (f *fakeMeta) MarkParsedText(_ context.Context, sourceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.sources {
		if f.sources[i].ID == sourceID && f.sources[i].Kind == "raw" {
			f.sources[i].Kind = "text"
		}
	}
	return nil
}

func (f *fakeMeta) ListCases(context.Context) ([]store.Case, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.Case
	for name, id := range f.cases {
		n := 0
		for _, s := range f.sources {
			if s.CaseID == id {
				n++
			}
		}
		prof := f.profiles[id]
		c := store.Case{ID: id, Name: name, Sources: n,
			IncidentType: prof.IncidentType, Background: prof.Background,
			GoalPresets: prof.GoalPresets}
		if f.archived[id] {
			t := time.Now().UTC()
			c.ArchivedAt = &t
		}
		out = append(out, c)
	}
	return out, nil
}

func (f *fakeMeta) GetCase(_ context.Context, id string) (*store.Case, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for name, cid := range f.cases {
		if cid == id {
			prof := f.profiles[id]
			c := &store.Case{ID: id, Name: name,
				IncidentType: prof.IncidentType, Background: prof.Background,
				GoalPresets: prof.GoalPresets}
			if f.archived[id] {
				t := time.Now().UTC()
				c.ArchivedAt = &t
			}
			return c, nil
		}
	}
	return nil, nil
}

// ---- 0.18.0 案件生命周期(fake;与真库同语义) ----

func (f *fakeMeta) RenameCase(_ context.Context, id, name string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, taken := f.cases[name]; taken {
		return false, fmt.Errorf("任务名已被占用: %s", name)
	}
	for n, cid := range f.cases {
		if cid == id {
			delete(f.cases, n)
			f.cases[name] = id
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeMeta) SetCaseArchived(_ context.Context, id string, archived bool) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, cid := range f.cases {
		if cid == id {
			f.archived[id] = archived
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeMeta) CaseArchived(_ context.Context, caseID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.archived[caseID], nil
}

// CaseInFlight 在跑闸(fake):jobs=任务账 running 数,intents 测试注入。
func (f *fakeMeta) CaseInFlight(_ context.Context, caseID string) (int64, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var jobs int64
	caseSources := map[string]bool{}
	for _, s := range f.sources {
		if s.CaseID == caseID {
			caseSources[s.ID] = true
		}
	}
	for sid, j := range f.jobs {
		if caseSources[sid] && j.Status == "running" {
			jobs++
		}
	}
	return jobs, f.runningIntents[caseID], nil
}

// DeleteCase 级联硬删(fake):清该案源/任务账/档案标记/案件本身,回报行数。
// 实体锚点(entities,015)fake 未建账——真库已在 sources 前补删(pg_case.go),
// 此处 Entities 恒 0 如实(如需实体级断言,先给 fake 建 entities 账)。
func (f *fakeMeta) DeleteCase(_ context.Context, caseID string) (*store.CaseDeleteReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	found := ""
	for n, cid := range f.cases {
		if cid == caseID {
			found = n
		}
	}
	if found == "" {
		return nil, fmt.Errorf("无此案件: %s", caseID)
	}
	rep := &store.CaseDeleteReport{Tables: map[string]int64{}}
	kept := f.sources[:0]
	for _, s := range f.sources {
		if s.CaseID == caseID {
			rep.Sources++
			delete(f.jobs, s.ID)
			continue
		}
		kept = append(kept, s)
	}
	f.sources = kept
	delete(f.cases, found)
	delete(f.profiles, caseID)
	delete(f.archived, caseID)
	return rep, nil
}

func (f *fakeMeta) CountSourcesByHash(_ context.Context, sha256 string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for _, s := range f.sources {
		if s.SHA256 == sha256 {
			n++
		}
	}
	return n, nil
}

// SetCaseProfile 案件应急元数据写入(fake;与真库同语义:无此案件报错)。
func (f *fakeMeta) SetCaseProfile(_ context.Context, caseID string, prof store.CaseProfile) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, cid := range f.cases {
		if cid == caseID {
			presets := prof.GoalPresets
			if presets == nil {
				presets = []string{}
			}
			f.profiles[caseID] = store.CaseProfile{
				IncidentType: prof.IncidentType, Background: prof.Background,
				GoalPresets: presets}
			return nil
		}
	}
	return fmt.Errorf("无此案件: %s", caseID)
}

func (f *fakeMeta) ListSources(_ context.Context, caseID string) ([]store.Source, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.Source
	for _, s := range f.sources {
		if s.CaseID == caseID {
			out = append(out, s)
		}
	}
	return out, nil
}

func (f *fakeMeta) GetSource(_ context.Context, id string) (*store.Source, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.sources {
		if s.ID == id {
			cp := s
			return &cp, nil
		}
	}
	return nil, nil
}

// ---- 0.27.0 案件封存/迁移(fake;与真库同语义) ----

// EnsureNewCase 永远建新案(fake):名撞加「(导入)」「(导入2)」后缀;
// 并发互斥由 f.mu 保证(与 PG 侧逐名 INSERT ON CONFLICT DO NOTHING 同语义)。
func (f *fakeMeta) EnsureNewCase(_ context.Context, baseName string) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for n := 0; ; n++ {
		cand := baseName
		switch {
		case n == 1:
			cand = baseName + "(导入)"
		case n > 1:
			cand = fmt.Sprintf("%s(导入%d)", baseName, n)
		}
		if _, taken := f.cases[cand]; taken {
			continue
		}
		f.next++
		id := fmt.Sprintf("00000000-0000-0000-0000-%012d", f.next)
		f.cases[cand] = id
		return id, cand, nil
	}
}

// ListSealAnchors 案件锚点全量(fake;源 sha256/path 读时 join,与 PG 同口径)。
func (f *fakeMeta) ListSealAnchors(_ context.Context, caseID string) ([]store.SealAnchor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	byID := map[string]store.Source{}
	for _, s := range f.sources {
		byID[s.ID] = s
	}
	var out []store.SealAnchor
	for _, a := range f.sealAnchors {
		if a.CaseID != caseID {
			continue
		}
		cp := a
		if s, ok := byID[a.SourceID]; ok {
			cp.SourceSHA256 = s.SHA256
			cp.SourcePath = s.Path
		}
		out = append(out, cp)
	}
	return out, nil
}

func (f *fakeMeta) ListNodes(_ context.Context, caseID string) ([]*intent.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []*intent.Node{}
	for _, n := range f.intentNodes[caseID] {
		cp := *n
		out = append(out, &cp)
	}
	return out, nil
}

func (f *fakeMeta) ListEdges(_ context.Context, caseID string) ([]*intent.Edge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []*intent.Edge{}
	for _, e := range f.intentEdges[caseID] {
		cp := *e
		out = append(out, &cp)
	}
	return out, nil
}

// SealInsertNode 迁移意图节点全列落库(fake;id 生成回写,与 PG 同语义)。
func (f *fakeMeta) SealInsertNode(_ context.Context, n *intent.Node) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	n.ID = fmt.Sprintf("30000000-0000-0000-0000-%012d", f.next)
	cp := *n
	f.intentNodes[n.CaseID] = append(f.intentNodes[n.CaseID], &cp)
	return nil
}

// CreateEdge 血缘边落库(fake;唯一约束幂等:重复边如实跳过,与 PG 同语义)。
func (f *fakeMeta) CreateEdge(_ context.Context, e *intent.Edge) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, x := range f.intentEdges[e.CaseID] {
		if x.FromID == e.FromID && x.ToID == e.ToID && x.Kind == e.Kind {
			return nil // 重复边:幂等跳过
		}
	}
	f.next++
	cp := *e
	cp.ID = fmt.Sprintf("40000000-0000-0000-0000-%012d", f.next)
	cp.CreatedAt = time.Now().UTC()
	f.intentEdges[e.CaseID] = append(f.intentEdges[e.CaseID], &cp)
	return nil
}

// AddAnchors 挂证据图锚点(fake;hit_id 空则置空,与 PG nilIfEmpty 同语义)。
func (f *fakeMeta) AddAnchors(_ context.Context, caseID, nodeID, kind string,
	anchors []intent.Anchor) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range anchors {
		f.sealAnchors = append(f.sealAnchors, store.SealAnchor{
			CaseID: caseID, NodeID: nodeID, SourceID: a.SourceID,
			LineNo: a.LineNo, HitID: a.HitID, Kind: kind, Note: a.Note,
		})
	}
	return nil
}

func (f *fakeMeta) ListSourcesWithJobs(_ context.Context, caseID string) ([]store.SourceState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.SourceState
	for _, s := range f.sources {
		if s.CaseID != caseID {
			continue
		}
		st := store.SourceState{Source: s}
		if j, ok := f.jobs[s.ID]; ok {
			cp := *j
			st.Job = &cp
		}
		out = append(out, st)
	}
	return out, nil
}

// ---- 切片十:平台页聚合面(fake,与真库同口径的内存投影) ----

func (f *fakeMeta) GlobalStats(context.Context) (*store.GlobalStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var active, archivedN int64
	for _, id := range f.cases {
		if f.archived[id] {
			archivedN++
		} else {
			active++
		}
	}
	return &store.GlobalStats{
		Cases:            active,
		ArchivedCases:    archivedN,
		Sources:          int64(len(f.sources)),
		PendingApprovals: int64(len(f.awaiting)),
		LLMRecords:       int64(len(f.llmRecords)),
		Activity:         []store.ActivityDay{},
	}, nil
}

func (f *fakeMeta) ListAwaitingIntents(context.Context) ([]*intent.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*intent.Node, len(f.awaiting))
	copy(out, f.awaiting)
	return out, nil
}

// CountPendingParking 全局停车场待处置计数(fake;测试经 f.pendingParking 注入)。
func (f *fakeMeta) CountPendingParking(context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pendingParking, nil
}

func (f *fakeMeta) ListLLMRecords(_ context.Context, caseID string,
	limit, offset int) ([]store.LLMRecord, int64, error) {

	f.mu.Lock()
	defer f.mu.Unlock()
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var filtered []store.LLMRecord
	for _, r := range f.llmRecords {
		if caseID == "" || r.CaseID == caseID {
			filtered = append(filtered, r)
		}
	}
	total := int64(len(filtered))
	if offset > len(filtered) {
		return []store.LLMRecord{}, total, nil
	}
	filtered = filtered[offset:]
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}
	out := make([]store.LLMRecord, len(filtered))
	copy(out, filtered)
	return out, total, nil
}

func (f *fakeMeta) GetLLMRecord(_ context.Context, id string) (*store.LLMRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.llmRecords {
		if r.ID == id {
			cp := r
			return &cp, nil
		}
	}
	return nil, nil
}

// ---- 0.31.0 研判报告版本账(fake;与真库同语义:版本库内自增/清单倒序/详情含原文) ----

func (f *fakeMeta) InsertCaseReport(_ context.Context, r *store.CaseReport) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	ver := 1
	for _, x := range f.caseReports[r.CaseID] {
		if x.Kind == r.Kind && x.Version >= ver {
			ver = x.Version + 1
		}
	}
	f.next++
	r.ID = fmt.Sprintf("50000000-0000-0000-0000-%012d", f.next)
	r.Version = ver
	r.CreatedAt = time.Now().UTC()
	cp := *r
	if f.caseReports == nil {
		f.caseReports = map[string][]store.CaseReport{}
	}
	f.caseReports[r.CaseID] = append(f.caseReports[r.CaseID], cp)
	return nil
}

func (f *fakeMeta) ListCaseReports(_ context.Context, caseID, kind string) ([]store.CaseReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []store.CaseReport{}
	for _, x := range f.caseReports[caseID] {
		if x.Kind != kind {
			continue
		}
		cp := x
		cp.Content = "" // 与 PG 同口径:清单不带 content
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version > out[j].Version })
	return out, nil
}

func (f *fakeMeta) GetCaseReport(_ context.Context, caseID, kind string,
	version int) (*store.CaseReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, x := range f.caseReports[caseID] {
		if x.Kind == kind && x.Version == version {
			cp := x
			return &cp, nil
		}
	}
	return nil, nil
}

// ---- fakeAudit:内存哈希链 ----

var _ MetaFace = (*fakeMeta)(nil) // 编译期闸:fake 与接口同步

type fakeAudit struct {
	mu      sync.Mutex
	entries []audit.Entry
}

func (f *fakeAudit) AppendAudit(_ context.Context, caseID, actor, action, scope string,
	detail any) (int64, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	detailJSON := ""
	if detail != nil {
		b, _ := json.Marshal(detail)
		detailJSON = string(b)
	}
	seq := int64(len(f.entries)) + 1
	prev := audit.Genesis
	if len(f.entries) > 0 {
		prev = f.entries[len(f.entries)-1].EntryHash
	}
	ts := time.Now().UTC()
	e := audit.Entry{Seq: seq, CaseID: caseID, TS: ts, Actor: actor,
		Action: action, Scope: scope, DetailJSON: detailJSON, PrevHash: prev}
	e.EntryHash = audit.ComputeHash(seq, caseID, ts, actor, action, scope,
		detailJSON, prev)
	f.entries = append(f.entries, e)
	return seq, e.EntryHash, nil
}

func (f *fakeAudit) ListAudit(_ context.Context, caseID string, limit int) ([]audit.Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []audit.Entry
	for _, e := range f.entries {
		if caseID == "" || e.CaseID == caseID {
			out = append(out, e)
		}
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (f *fakeAudit) AllAudit(context.Context) ([]audit.Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]audit.Entry(nil), f.entries...), nil
}

// ---- fakeReviewStore(review.Store) ----

type fakeReviewStore struct {
	mu      sync.Mutex
	rounds  map[string]int
	runs    []review.ScanRun
	hits    []review.Hit
	index   map[string]bool
	sources []review.ScanSource // 适用域路由源清单(测试注入;meta 已联时不用)
	meta    *fakeMeta           // 与真库同语义:源账同一存储
	nextID  int
}

func newFakeReviewStore() *fakeReviewStore {
	return &fakeReviewStore{rounds: map[string]int{}, index: map[string]bool{}}
}

func (f *fakeReviewStore) CreateScanRun(_ context.Context, caseID, actor, ruleIDsJSON string,
	now time.Time) (string, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rounds[caseID]++
	round := f.rounds[caseID]
	f.nextID++
	id := fmt.Sprintf("run-%d", f.nextID)
	f.runs = append(f.runs, review.ScanRun{ID: id, CaseID: caseID,
		RoundNo: round, RuleIDsJSON: ruleIDsJSON, Actor: actor, CreatedAt: now})
	return id, round, nil
}

func (f *fakeReviewStore) InsertHit(_ context.Context, h review.Hit, now time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := h.SourceID + "|" + strconv.Itoa(h.LineNo) + "|" + h.RuleID
	if f.index[key] {
		return false, nil
	}
	f.index[key] = true
	f.nextID++
	h.ID = fmt.Sprintf("hit-%d", f.nextID)
	h.CreatedAt = now
	f.hits = append(f.hits, h)
	return true, nil
}

func (f *fakeReviewStore) FinishScanRun(_ context.Context, runID, summaryJSON string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.runs {
		if f.runs[i].ID == runID {
			f.runs[i].SummaryJSON = summaryJSON
		}
	}
	return nil
}

func (f *fakeReviewStore) ListHits(_ context.Context, caseID string, fl review.HitFilter) ([]review.Hit, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []review.Hit
	for _, h := range f.hits {
		if h.CaseID != caseID {
			continue
		}
		if fl.Status != "" && h.Status != fl.Status {
			continue
		}
		if fl.Round != 0 && h.RoundNo != fl.Round {
			continue
		}
		out = append(out, h)
	}
	return out, nil
}

func (f *fakeReviewStore) GetHit(_ context.Context, id string) (*review.Hit, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.hits {
		if f.hits[i].ID == id {
			cp := f.hits[i]
			return &cp, nil
		}
	}
	return nil, nil
}

// SetVerdict 人裁决(fake 真模拟 CAS:仅 pending 可落,已被裁决返回
// ok=false——与 PG `AND status='pending'` 同语义,否则并发裁决测试无效)。
func (f *fakeReviewStore) SetVerdict(_ context.Context, id, actor, status, note string,
	now time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.hits {
		if f.hits[i].ID == id {
			if f.hits[i].Status != "pending" {
				return false, nil
			}
			f.hits[i].Status = status
			f.hits[i].ReviewedBy = actor
			f.hits[i].ReviewedAt = &now
			f.hits[i].ReviewNote = note
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeReviewStore) ListScanRuns(_ context.Context, caseID string) ([]review.ScanRun, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []review.ScanRun
	for _, r := range f.runs {
		if r.CaseID == caseID {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeReviewStore) ListSourcesForScan(context.Context, string) ([]review.ScanSource, error) {
	// 与 PG 同语义:kind text|evtx 或已判定品类的源(真库两张表同库,
	// fake 直接引 fakeMeta,路由口径不漂移)
	if f.meta != nil {
		f.meta.mu.Lock()
		defer f.meta.mu.Unlock()
		var out []review.ScanSource
		for _, s := range f.meta.sources {
			if s.Kind == "text" || s.Kind == "evtx" || s.LogType != "" {
				out = append(out, review.ScanSource{
					ID: s.ID, Kind: s.Kind, LogType: s.LogType,
					ArtifactType: s.ArtifactType,
				})
			}
		}
		return out, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]review.ScanSource(nil), f.sources...), nil
}

func (f *fakeReviewStore) RuleStatsRaw(_ context.Context, caseID string,
	since time.Time) ([]review.RuleStat, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	agg := map[string]*review.RuleStat{}
	var order []string
	for _, h := range f.hits {
		if h.CaseID != caseID || h.CreatedAt.Before(since) {
			continue
		}
		st := agg[h.RuleID]
		if st == nil {
			st = &review.RuleStat{RuleID: h.RuleID}
			agg[h.RuleID] = st
			order = append(order, h.RuleID)
		}
		st.Candidates++
		switch h.Status {
		case "accepted":
			st.Accepted++
		case "rejected":
			st.Rejected++
		default:
			st.Pending++
		}
	}
	var out []review.RuleStat
	for _, id := range order {
		out = append(out, *agg[id])
	}
	return out, nil
}
