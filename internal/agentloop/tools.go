// 只读工具集(§7 一寸不让):六个案件数据工具 + 案件工作区只读两件
// (workspace_list/workspace_read,切片十三,WorkspaceDir 配置即挂),全部
// 声明只读+并发安全,绑会话案件;norma 默认的 Write/Edit/Bash 一律不注册
// (Options.Tools 只传这些)。
//
// 工具对 spec 写、不夹案件值:案件上下文来自会话绑定与工具返回,
// 不进工具描述/参数默认值。
package agentloop

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/tool"

	"github.com/ye-mengwen/fengtu/internal/ingest"
	"github.com/ye-mengwen/fengtu/internal/ingest/store"
	"github.com/ye-mengwen/fengtu/internal/operator"
	"github.com/ye-mengwen/fengtu/internal/query"
	"github.com/ye-mengwen/fengtu/internal/review"
)

// viewLinesCap 金库回查单次上限(§7 拍板 200 行/次)。
const viewLinesCap = 200

// runOpMaxAnchors run_operator 返回给模型的锚点条数上限(全文在待审区)。
const runOpMaxAnchors = 20

// listSourcesDefaultLimit/listSourcesMaxLimit list_sources 分页(切片七:
// 大案件一次全量返回吃掉 worker 大半 token 预算——736 源案件实测熔断,
// 分页是修复;指引同步改为「先 list_hits/search 再按需取源」)。
const (
	listSourcesDefaultLimit = 100
	listSourcesMaxLimit     = 300
)

// hostScopeSources 会话主机范围 → 该主机源 id 集(空 host_scope → nil,nil,
// 不限定;主机无源 → 空集,工具如实返回空)。系统闸:不靠模型自觉。
func (s *Service) hostScopeSources(ctx context.Context,
	sess *store.AISession) (map[string]bool, []string, error) {

	if sess.HostScope == "" {
		return nil, nil, nil
	}
	srcs, err := s.deps.Meta.ListSources(ctx, sess.CaseID)
	if err != nil {
		return nil, nil, err
	}
	set := map[string]bool{}
	var ids []string
	for _, src := range srcs {
		if src.Host == sess.HostScope {
			set[src.ID] = true
			ids = append(ids, src.ID)
		}
	}
	return set, ids, nil
}

func readonly(json.RawMessage) bool { return true }

func allowAll(context.Context, json.RawMessage, permission.Context) permission.Decision {
	return permission.Allowed()
}

// buildTools 装配只读工具集(绑 sess.CaseID;全部只读+并发安全)。
// web_search(切片十一)是第七个、也是唯一联网工具:仅当平台设置
// web_search_enabled 开 且 外发总开关 outbound_enabled 开(外发同意闸,
// 搜索也是外发)且后端可用(brave-free/tavily 缺 key 如实不挂)才挂载——
// 开关关=工具根本不在清单里,不靠模型自觉。
func (s *Service) buildTools(sess *store.AISession, cfg ResolvedConfig) []tool.CoreTool {
	tools := []tool.CoreTool{
		s.toolSearchEvents(sess), s.toolGetStats(sess), s.toolRunOperator(sess),
		s.toolViewLines(sess), s.toolListSources(sess), s.toolListHits(sess),
	}
	// 切片十三:案件工作区只读工具(用户补充材料,参考不是证据);
	// WorkspaceDir 配置即挂,空目录/未建由工具如实返回空
	if s.deps.WorkspaceDir != "" {
		tools = append(tools, s.toolWorkspaceList(sess), s.toolWorkspaceRead(sess))
	}
	if ws, ok := s.toolWebSearch(cfg); ok {
		tools = append(tools, ws)
	}
	return tools
}

// toolWebSearch 装配 web_search(ARTEX 同款后端:ddgs 免 key / brave-free /
// tavily;走全局代理)。ok=false = 开关关/外发关/带 key 后端缺 key,如实不挂。
func (s *Service) toolWebSearch(cfg ResolvedConfig) (tool.CoreTool, bool) {
	if !cfg.WebSearchEnabled || !cfg.OutboundEnabled {
		return nil, false
	}
	if cfg.WebSearchBackend != searchBackendDDGS && cfg.SearchAPIKey == "" {
		return nil, false // 带 key 后端缺 key:如实不挂(设置页有 search_key_set 呈现)
	}
	probe := s.deps.SearchProbe
	if probe == nil {
		probe = tool.WebSearchProbe
	}
	wsCfg := tool.WebSearchConfig{
		Backend:      cfg.WebSearchBackend,
		BraveAPIKey:  cfg.SearchAPIKey,
		TavilyAPIKey: cfg.SearchAPIKey,
		Proxy:        cfg.GlobalProxy, // 全局代理生效范围:LLM 请求 + 联网搜索
	}
	return tool.Build(tool.Spec{
		Name: "web_search",
		Description: "联网搜索参考信息(标题/URL/摘要,默认 5 条,上限 20;发起外部网络请求," +
			"走全局代理如已配置)。应急场景用来查较新的威胁报告/IOC 披露/厂商通告。" +
			"证据链纪律(一寸不让):搜索结果是参考不是证据——网页内容一律不能当锚点," +
			"一切结论的锚点仍只能锚案件采集物(source_id+line_no);网页只当线索," +
			"它指向的方向要落回案件数据查实后才算数。",
		Schema: objSchema(map[string]any{
			"query": strProp("搜索词"),
			"limit": intProp("返回上限(默认 5,最大 20)"),
		}, "query"),
		ReadOnly: readonly, Concurrent: readonly, Permissions: allowAll,
		Run: func(ctx context.Context, input json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var p struct {
				Query string `json:"query"`
				Limit int    `json:"limit"`
			}
			if err := decode(input, &p); err != nil {
				return tool.Errorf(err.Error()), nil
			}
			q := strings.TrimSpace(p.Query)
			if q == "" {
				return tool.Errorf("query 必填"), nil
			}
			limit := p.Limit
			if limit <= 0 {
				limit = 5
			}
			if limit > 20 {
				limit = 20
			}
			// 硬墙钟上限:慢/被限流的后端不能挂死 loop(与 norma 同款纪律)
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			results, err := probe(cctx, wsCfg, q, limit)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("联网搜索失败(%s): %s",
					cfg.WebSearchBackend, err.Error())), nil
			}
			if results == nil {
				results = []tool.SearchResult{}
			}
			return asJSON(map[string]any{
				"backend": cfg.WebSearchBackend, "query": q, "results": results,
				"note": "搜索结果是参考不是证据:网页内容不能当锚点;" +
					"结论锚点仍只能锚案件采集物(source_id+line_no)",
			})
		},
	}), true
}

func decode(input json.RawMessage, v any) error {
	if err := json.Unmarshal(input, v); err != nil {
		return fmt.Errorf("参数 JSON 解析失败: %w", err)
	}
	return nil
}

func objSchema(props map[string]any, required ...string) map[string]any {
	s := map[string]any{
		"type": "object", "properties": props,
		"additionalProperties": false,
	}
	// required 空数组必须省略该键:零值 nil 切片序列化成 null,
	// DeepSeek 等厂商按 JSON Schema 严格校验直接 400(台架实测坑)
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func strProp(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func intProp(desc string) map[string]any { return map[string]any{"type": "integer", "description": desc} }

func asJSON(v any) (tool.Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return tool.Result{}, err
	}
	return tool.Text(string(b)), nil
}

// toolResultCapBytes 单条工具结果字节上限(切片七台架实测:某 3000+ 源
// 主机,一页 300 源=97KB、50 条检索=50KB,几轮就烧穿会话
// token 预算——统一截断闸,截断如实标 truncated 并指引用更窄条件)。
const toolResultCapBytes = 30000

// asJSONCapped 带截断闸的 JSON 结果(arrKey 是 payload 里的数组键;
// 超闸则截短数组前缀,补 truncated=true 与指引 note)。
func asJSONCapped(v map[string]any, arrKey string) (tool.Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return tool.Result{}, err
	}
	if len(b) <= toolResultCapBytes {
		return tool.Text(string(b)), nil
	}
	arr, _ := v[arrKey].([]map[string]any)
	if arr == nil {
		// 非数组形态截不动结构,截字符串本体(保底,如实标)
		v["truncated"] = true
		v["note"] = "结果过大已截断;用更窄条件/更小 limit 重查"
		b, _ = json.Marshal(v)
		if len(b) > toolResultCapBytes {
			b = append(b[:toolResultCapBytes], []byte("…(truncated)")...)
		}
		return tool.Text(string(b)), nil
	}
	lo, hi := 0, len(arr)
	for lo < hi { // 二分最大可容纳前缀
		mid := (lo + hi + 1) / 2
		v[arrKey] = arr[:mid]
		b, err = json.Marshal(v)
		if err != nil {
			return tool.Result{}, err
		}
		if len(b) <= toolResultCapBytes-300 { // 留给 truncated/note 的余量
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	v[arrKey] = arr[:lo]
	v["truncated"] = true
	v["note"] = "结果过大已截断(单条工具结果上限 30KB,预算纪律);" +
		"用更窄检索条件/更小 limit/分页 offset 续查"
	b, err = json.Marshal(v)
	if err != nil {
		return tool.Result{}, err
	}
	return tool.Text(string(b)), nil
}

// ---- search_events:事件检索(走切片三单一检索层) ----

// searchEventFieldsCap/searchEventRawCap 检索结果单条截断(切片七实测:
// evtx 事件 fields 2~4KB/条,30 条就烧穿会话预算——截断呈现,全文用
// view_lines 回查;与 norma 工具输出截断同纪律)。
const (
	searchEventFieldsCap = 500
	searchEventRawCap    = 300
)

func capRunes(s string, n int) string {
	if utf8.RuneCountInString(s) > n {
		return string([]rune(s)[:n]) + "…"
	}
	return s
}

func (s *Service) toolSearchEvents(sess *store.AISession) tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "search_events",
		Description: "检索案件事件(会话已绑定案件,无需 case_id)。q=全文词;" +
			"cond=字段条件(field:op:value,op=eq|contains,可多条 AND);" +
			"ts_from/ts_to=RFC3339 时间窗(无时区源不参与,如实)。结果带" +
			" source_id+line_no 锚点,可配 view_lines 回查原文。",
		Schema: objSchema(map[string]any{
			"q":       strProp("全文词(raw 子串,大小写不敏感)"),
			"cond":    map[string]any{"type": "array", "items": strProp("field:op:value"), "description": "字段条件,多条 AND"},
			"ts_from": strProp("RFC3339 起(可空)"),
			"ts_to":   strProp("RFC3339 止(可空)"),
			"limit":   intProp("返回上限(默认 100,最大 1000)"),
		}),
		ReadOnly: readonly, Concurrent: readonly, Permissions: allowAll,
		Run: func(ctx context.Context, input json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var p struct {
				Q      string   `json:"q"`
				Conds  []string `json:"cond"`
				TSFrom string   `json:"ts_from"`
				TSTo   string   `json:"ts_to"`
				Limit  int      `json:"limit"`
			}
			if err := decode(input, &p); err != nil {
				return tool.Errorf(err.Error()), nil
			}
			params := query.Params{CaseID: sess.CaseID, Q: p.Q, Limit: p.Limit}
			// 主机范围闸(切片七):会话绑主机 → 检索限定该主机源集合
			if sess.HostScope != "" {
				_, ids, herr := s.hostScopeSources(ctx, sess)
				if herr != nil {
					return tool.Errorf("主机范围源集合查询失败: " + herr.Error()), nil
				}
				params.SourceIDs = ids
			}
			for _, raw := range p.Conds {
				parts := strings.SplitN(raw, ":", 3)
				if len(parts) != 3 {
					return tool.Errorf("cond 形如 field:op:value: " + raw), nil
				}
				params.Conds = append(params.Conds, query.FieldCond{
					Field: parts[0], Op: query.CondOp(parts[1]), Values: []string{parts[2]}})
			}
			if p.TSFrom != "" {
				t, err := time.Parse(time.RFC3339, p.TSFrom)
				if err != nil {
					return tool.Errorf("ts_from 须为 RFC3339: " + p.TSFrom), nil
				}
				params.TSFrom = &t
			}
			if p.TSTo != "" {
				t, err := time.Parse(time.RFC3339, p.TSTo)
				if err != nil {
					return tool.Errorf("ts_to 须为 RFC3339: " + p.TSTo), nil
				}
				params.TSTo = &t
			}
				events, err := s.deps.Query.Search(ctx, params)
				if err != nil {
					return tool.Errorf(fmt.Sprintf("检索失败: %s", err.Error())), nil
				}
				if events == nil {
					events = []query.Event{}
				}
				// 截断呈现(预算纪律;锚点不截——source_id/line_no 完整)
				out := make([]map[string]any, 0, len(events))
				for _, ev := range events {
					out = append(out, map[string]any{
						"source_id": ev.SourceID, "line_no": ev.LineNo,
						"ts": ev.TS, "kind": ev.Kind,
						"fields": capRunes(ev.Fields, searchEventFieldsCap),
						"raw":    capRunes(ev.Raw, searchEventRawCap),
					})
				}
				return asJSONCapped(map[string]any{
					"count": len(out), "events": out,
					"note": "命中≠结论;按源+行号主键序返回(未按 ts 排序);" +
						"fields/raw 截断呈现(500/300 字),全文用 view_lines 回查锚点",
				}, "events")
		},
	})
}

// ---- get_stats:聚合统计(按状态码/日/源;CH 侧聚合) ----

func (s *Service) toolGetStats(sess *store.AISession) tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "get_stats",
		Description: "案件事件聚合统计(会话已绑定案件)。group=status(状态码)" +
			"|day(按日,无时区源不参与)|source(按源)。看分布、找异常突刺用。",
		Schema: objSchema(map[string]any{
			"group": strProp("status|day|source"),
			"limit": intProp("桶上限(默认 50,最大 500)"),
		}, "group"),
		ReadOnly: readonly, Concurrent: readonly, Permissions: allowAll,
		Run: func(ctx context.Context, input json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var p struct {
				Group string `json:"group"`
				Limit int    `json:"limit"`
			}
			if err := decode(input, &p); err != nil {
				return tool.Errorf(err.Error()), nil
			}
			sp := query.StatsParams{
				CaseID: sess.CaseID, Group: query.StatGroup(p.Group), Limit: p.Limit}
			// 主机范围闸(切片七):聚合同样限定该主机源集合
			if sess.HostScope != "" {
				_, ids, herr := s.hostScopeSources(ctx, sess)
				if herr != nil {
					return tool.Errorf("主机范围源集合查询失败: " + herr.Error()), nil
				}
				sp.SourceIDs = ids
			}
			sql, args, err := query.BuildStatsSQL(sp)
			if err != nil {
				return tool.Errorf(err.Error()), nil
			}
			rows, err := s.deps.Events.QueryStats(ctx, sql, args...)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("聚合失败: %s", err.Error())), nil
			}
			if rows == nil {
				rows = []query.StatRow{}
			}
			buckets := make([]map[string]any, 0, len(rows))
			for _, r := range rows {
				buckets = append(buckets, map[string]any{"key": r.Key, "count": r.Count})
			}
			return asJSONCapped(map[string]any{
				"group": p.Group, "buckets": buckets,
				"note": "统计分布是线索不是结论(§6.2);异常桶需回查事件核实",
			}, "buckets")
		},
	})
}

// ---- run_operator:适用域算子(切片四确定性执行层;命中落待审区 pending) ----

func (s *Service) toolRunOperator(sess *store.AISession) tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "run_operator",
		Description: "跑一个适用域算子(确定性检测,如 web-bruteforce-chain 爆破链/" +
			"web-beacon-periodicity 信标周期/web-ip-rate-spike 速率突刺/host-auth-chain" +
			" 认证链/host-persistence-task 驻留计划任务/cross-entity-multi-source 跨源" +
			"实体)。算子按源品类自动路由;命中以 pending 落待审区(人裁决才算数)。" +
			"params 覆盖注册表默认参数(键必须与注册表 params 完全一致,如 host-auth-chain" +
			" 的 window_seconds/fail_threshold;未声明的键不生效,会在返回的" +
			" ignored_params 里如实列出);source_id 限定单源。",
		Schema: objSchema(map[string]any{
			"name":      strProp("算子 id(GET /api/operators 可见全清单)"),
			"params":    map[string]any{"type": "object", "description": "参数覆盖(键同注册表 params)"},
			"source_id": strProp("限定单源(可空=按适用域全路由)"),
		}, "name"),
		ReadOnly: readonly, Concurrent: readonly, Permissions: allowAll,
		Run: func(ctx context.Context, input json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var p struct {
				Name     string         `json:"name"`
				Params   map[string]any `json:"params"`
				SourceID string         `json:"source_id"`
			}
			if err := decode(input, &p); err != nil {
				return tool.Errorf(err.Error()), nil
			}
			return s.runOperator(ctx, sess, p.Name, p.Params, p.SourceID)
		},
	})
}

func (s *Service) runOperator(ctx context.Context, sess *store.AISession,
	name string, params map[string]any, sourceID string) (tool.Result, error) {

	var spec *operator.Spec
	for _, sp := range s.deps.Ops.Specs() {
		if sp.ID == name {
			spec = sp
			break
		}
	}
	if spec == nil {
		var avail []string
		for _, sp := range s.deps.Ops.Specs() {
			avail = append(avail, sp.ID)
		}
		return tool.Errorf(fmt.Sprintf("未知算子: %q(可选: %s)",
			name, strings.Join(avail, ", "))), nil
	}
	if !spec.Implemented {
		return tool.Errorf(fmt.Sprintf("算子 %s 未实现(只注册不实例化,§6.1 如实标)", name)), nil
	}
	impl, ok := s.deps.Ops.Impl(name)
	if !ok {
		return tool.Errorf(fmt.Sprintf("算子 %s 未实现(只注册不实例化,§6.1 如实标)", name)), nil
	}

	// params 覆盖:拷注册表 spec 再叠加(不改注册表本体)。
	// 未在注册表声明的覆盖键不生效(算子只读声明键)——如实回执,
	// 不静默吞键(2026-09-22 实战:AI 按工具描述旧示例写 window_sec,
	// 实际键 window_seconds,静默吞键=调参空调,白烧 50s 全量扫描)。
	cp := *spec
	merged := map[string]any{}
	for k, v := range spec.Params {
		merged[k] = v
	}
	var ignored []string
	for k, v := range params {
		if _, ok := spec.Params[k]; !ok {
			ignored = append(ignored, k)
			continue
		}
		merged[k] = v
	}
	cp.Params = merged

	srcs, err := s.deps.ReviewStore.ListSourcesForScan(ctx, sess.CaseID)
	if err != nil {
		return tool.Result{}, fmt.Errorf("算子路由源清单查询失败: %w", err)
	}
	var matched []operator.Source
	skipped := 0
	skippedHost := 0 // 主机范围外(切片七会话闸;与按域跳过分列,账不混)
	for _, src := range srcs {
		os := operator.Source{ID: src.ID, Kind: src.Kind,
			LogType: src.LogType, ArtifactType: src.ArtifactType, Host: src.Host}
		if sess.HostScope != "" && src.Host != sess.HostScope {
			skippedHost++
			continue
		}
		if sourceID != "" && src.ID != sourceID {
			continue
		}
		if cp.Match(os) {
			matched = append(matched, os)
		} else {
			skipped++
		}
	}
	if len(matched) == 0 {
		return asJSON(map[string]any{
			"operator": name, "matched_sources": 0,
			"skipped_host_scope": skippedHost, "host_scope": sess.HostScope,
			"ignored_params": ignored, "valid_params": paramKeys(spec),
			"note": "适用域内无源(按域跳过/主机范围外/source_id 不在域内),未执行",
		})
	}

	stream := func(sid string, fn func(query.Event) error) error {
		return s.deps.Query.StreamMatch(ctx,
			query.Params{CaseID: sess.CaseID, SourceID: sid}, fn)
	}
	findings, err := impl.Run(&cp, matched, stream)
	if err != nil {
		return tool.Result{}, fmt.Errorf("算子 %s 执行失败: %w", name, err)
	}

	// 命中落待审区(pending;走已有轮次账,actor 锚「真人 via AI」)
	runID, round, err := s.deps.ReviewStore.CreateScanRun(ctx, sess.CaseID,
		"ai:"+sess.CreatedBy, `["`+name+`"]`, s.deps.Now().UTC())
	if err != nil {
		return tool.Result{}, fmt.Errorf("算子轮次开账失败: %w", err)
	}
	maxHits := cp.MaxHits
	if maxHits <= 0 {
		maxHits = review.DefaultMaxHits
	}
	hitsNew, hitsDup, truncated := 0, 0, 0
	var anchors []map[string]any
	for _, f := range findings {
		grade, gerr := operator.Grade(f.Evidence)
		if gerr != nil {
			_ = s.deps.ReviewStore.FinishScanRun(ctx, runID,
				fmt.Sprintf(`{"failed":%q}`, gerr.Error()))
			return tool.Result{}, fmt.Errorf("算子 %s 证据结构不成立: %w", name, gerr)
		}
		if hitsNew >= maxHits {
			truncated++
			continue
		}
		snippet := f.Snippet
		if utf8.RuneCountInString(snippet) > 240 {
			snippet = string([]rune(snippet)[:240])
		}
		detail, _ := json.Marshal(map[string]any{
			"op_title": cp.Title, "note": cp.Note,
			"disclaimer": review.Disclaimer,
			"via":        "ai_session:" + sess.ID,
			"stats":      f.Detail, "evidence": f.Evidence,
		})
		inserted, ierr := s.deps.ReviewStore.InsertHit(ctx, review.Hit{
			CaseID: sess.CaseID, SourceID: f.SourceID, LineNo: f.LineNo,
			RuleID: cp.ID, Severity: cp.Severity,
			MatchedField: f.MatchedField, MatchedValue: f.MatchedValue,
			Snippet: snippet, TsUTC: f.TS, Status: "pending",
			RoundNo: round, EvidenceGrade: grade, DetailJSON: string(detail),
		}, s.deps.Now().UTC())
		if ierr != nil {
			_ = s.deps.ReviewStore.FinishScanRun(ctx, runID,
				fmt.Sprintf(`{"failed":%q}`, ierr.Error()))
			return tool.Result{}, fmt.Errorf("算子 %s 候选落库失败: %w", name, ierr)
		}
		if inserted {
			hitsNew++
		} else {
			hitsDup++
		}
		if len(anchors) < runOpMaxAnchors {
			anchors = append(anchors, map[string]any{
				"source_id": f.SourceID, "line_no": f.LineNo,
				"matched_field": f.MatchedField, "matched_value": f.MatchedValue,
				"snippet": snippet, "evidence_grade": grade,
			})
		}
	}
	summary, _ := json.Marshal(map[string]any{
		"run_id": runID, "round_no": round, "operator": name, "via_ai": sess.ID,
		"findings": len(findings), "hits_new": hitsNew, "hits_dup": hitsDup,
		"truncated": truncated, "matched_sources": len(matched),
	})
	if err := s.deps.ReviewStore.FinishScanRun(ctx, runID, string(summary)); err != nil {
		return tool.Result{}, fmt.Errorf("算子轮次收尾失败: %w", err)
	}
	return asJSON(map[string]any{
		"operator": name, "round_no": round,
		"matched_sources": len(matched), "skipped_domain": skipped,
		"skipped_host_scope": skippedHost, "host_scope": sess.HostScope,
		"findings": len(findings), "hits_new": hitsNew, "hits_dup": hitsDup,
		"truncated": truncated, "anchors": anchors,
		"ignored_params": ignored, "valid_params": paramKeys(spec),
		"note": "命中≠结论:已落待审区 pending,判断权归人(§1);汇报措辞用「疑似候选」",
	})
}

// paramKeys 注册表声明的可覆盖参数键(回执给模型,防 hallucinate 键名)。
func paramKeys(spec *operator.Spec) []string {
	keys := make([]string, 0, len(spec.Params))
	for k := range spec.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---- view_lines:金库原文回查(单次 ≤200 行) ----

func (s *Service) toolViewLines(sess *store.AISession) tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "view_lines",
		Description: fmt.Sprintf("按行号区间回查源原文([from,to],1 起,闭区间,"+
			"单次最多 %d 行)。只适用行式文本源;evtx/二进制源的事件原文在检索结果"+
			" raw 列。核实锚点上下文用。", viewLinesCap),
		Schema: objSchema(map[string]any{
			"source_id": strProp("源 id(list_sources 可得)"),
			"from":      intProp("起始行号(≥1)"),
			"to":        intProp("结束行号(≥from)"),
		}, "source_id", "from", "to"),
		ReadOnly: readonly, Concurrent: readonly, Permissions: allowAll,
		Run: func(ctx context.Context, input json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var p struct {
				SourceID string `json:"source_id"`
				From     int    `json:"from"`
				To       int    `json:"to"`
			}
			if err := decode(input, &p); err != nil {
				return tool.Errorf(err.Error()), nil
			}
			if p.From < 1 || p.To < p.From || p.To-p.From+1 > viewLinesCap {
				return tool.Errorf(fmt.Sprintf(
					"行号区间非法: 1≤from≤to 且单次 ≤%d 行(收到 [%d,%d])",
					viewLinesCap, p.From, p.To)), nil
			}
			src, err := s.deps.Meta.GetSource(ctx, p.SourceID)
			if err != nil {
				return tool.Result{}, err
			}
			if src == nil || src.CaseID != sess.CaseID {
				return tool.Errorf("无此源(或不属本案件): " + p.SourceID), nil
			}
			// 主机范围闸(切片七):会话绑主机 → 回查不得越界
			if sess.HostScope != "" && src.Host != sess.HostScope {
				return tool.Errorf(fmt.Sprintf(
					"该源在会话主机范围(%s)之外,不可回查", sess.HostScope)), nil
			}
			if src.Kind != "text" {
				// raw 兜底源内容嗅探:后缀生僻的文本(勒索信 *.readme、
				// 无扩展名任务 XML 等)允许行式回查;二进制如实拒绝
				if len(src.SHA256) != 64 {
					return tool.Errorf("行号回查仅适用行式文本源;该源类别为 " +
						string(src.Kind) + "(哈希登记异常,不可嗅探)"), nil
				}
				ok, serr := ingest.SniffText(s.deps.Vault.Path(src.SHA256))
				if serr != nil {
					return tool.Errorf("金库嗅探失败: " + serr.Error()), nil
				}
				if !ok {
					return tool.Errorf("行号回查仅适用行式文本源;该源类别为 " +
						string(src.Kind) + "(内容嗅探=二进制)"), nil
				}
			}
			lines, err := s.deps.Vault.Lines(src.SHA256, p.From, p.To)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("金库回查失败: %s", err.Error())), nil
			}
			out := make([]map[string]any, len(lines))
			for i, line := range lines {
				out[i] = map[string]any{"no": p.From + i,
					"text": strings.ToValidUTF8(line, "�")}
			}
			return asJSON(map[string]any{
				"source_id": src.ID, "sha256": src.SHA256,
				"from": p.From, "to": p.To, "lines": out,
			})
		},
	})
}

// ---- list_sources:案件源清单(分页) ----

func (s *Service) toolListSources(sess *store.AISession) tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "list_sources",
		Description: "列案件源清单(id/路径/类别/品类/主机/解析状态),分页返回。" +
			"大案件源很多:先 list_hits/search_events 缩小范围,再按需分页取源清单" +
			"(默认每页 100,最大 300;total 给总数)。会话绑主机范围时只列该主机。",
		Schema: objSchema(map[string]any{
			"limit":  intProp("每页条数(默认 100,最大 300)"),
			"offset": intProp("偏移(默认 0)"),
		}),
		ReadOnly: readonly, Concurrent: readonly, Permissions: allowAll,
		Run: func(ctx context.Context, input json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var p struct {
				Limit  int `json:"limit"`
				Offset int `json:"offset"`
			}
			if err := decode(input, &p); err != nil {
				return tool.Errorf(err.Error()), nil
			}
			if p.Limit <= 0 {
				p.Limit = listSourcesDefaultLimit
			}
			if p.Limit > listSourcesMaxLimit {
				p.Limit = listSourcesMaxLimit
			}
			if p.Offset < 0 {
				return tool.Errorf("offset 须 ≥0"), nil
			}
			srcs, err := s.deps.Meta.ListSources(ctx, sess.CaseID)
			if err != nil {
				return tool.Result{}, err
			}
			// 主机范围闸(切片七):会话绑主机 → 只列该主机的源
			filtered := srcs[:0]
			for _, src := range srcs {
				if sess.HostScope != "" && src.Host != sess.HostScope {
					continue
				}
				filtered = append(filtered, src)
			}
			total := len(filtered)
			if p.Offset > total {
				p.Offset = total
			}
			end := p.Offset + p.Limit
			if end > total {
				end = total
			}
			out := make([]map[string]any, 0, end-p.Offset)
			for _, src := range filtered[p.Offset:end] {
				out = append(out, map[string]any{
					"source_id": src.ID, "path": src.Path, "kind": src.Kind,
					"artifact_type": src.ArtifactType, "log_type": src.LogType,
					"host": src.Host, "package": src.Package,
					"detect_format": src.DetectFormat, "detect_status": src.DetectStatus,
					"size_bytes": src.SizeBytes,
				})
			}
			return asJSONCapped(map[string]any{
				"total": total, "offset": p.Offset, "limit": p.Limit,
				"count": len(out), "sources": out, "host_scope": sess.HostScope,
				"note": "分页返回;total 是(主机范围内)源总数,offset+count<total 时还有下一页",
			}, "sources")
		},
	})
}

// ---- list_hits:待审区候选(紧凑投影) ----

func (s *Service) toolListHits(sess *store.AISession) tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "list_hits",
		Description: "列待审区候选(会话已绑定案件;status=pending|accepted|" +
			"rejected,空=全部)。紧凑投影(id/源/行号/规则/级别/命中值/证据等级)," +
			"detail 不全量返回(大案件预算纪律:切片七实测 184 条全量 detail_json " +
			"一次烧穿会话预算)——要上下文用 view_lines 回查锚点原文。",
		Schema: objSchema(map[string]any{
			"status": strProp("pending|accepted|rejected(可空=全部)"),
			"limit":  intProp("返回上限(默认 50,最大 200)"),
		}),
		ReadOnly: readonly, Concurrent: readonly, Permissions: allowAll,
		Run: func(ctx context.Context, input json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var p struct {
				Status string `json:"status"`
				Limit  int    `json:"limit"`
			}
			if err := decode(input, &p); err != nil {
				return tool.Errorf(err.Error()), nil
			}
			if p.Limit <= 0 {
				p.Limit = 50
			}
			if p.Limit > 200 {
				p.Limit = 200
			}
			hits, err := s.deps.Review.Hits(ctx, sess.CaseID,
				review.HitFilter{Status: p.Status, Limit: p.Limit})
			if err != nil {
				return tool.Errorf(err.Error()), nil
			}
			// 主机范围闸(切片七):会话绑主机 → 只给该主机源的候选
			if sess.HostScope != "" {
				set, _, herr := s.hostScopeSources(ctx, sess)
				if herr != nil {
					return tool.Errorf("主机范围源集合查询失败: " + herr.Error()), nil
				}
				filtered := hits[:0]
				for _, h := range hits {
					if set[h.SourceID] {
						filtered = append(filtered, h)
					}
				}
				hits = filtered
			}
			out := make([]map[string]any, 0, len(hits))
			for _, h := range hits {
				snippet := h.Snippet
				if utf8.RuneCountInString(snippet) > 120 {
					snippet = string([]rune(snippet)[:120])
				}
				out = append(out, map[string]any{
					"id": h.ID, "source_id": h.SourceID, "line_no": h.LineNo,
					"rule_id": h.RuleID, "severity": h.Severity,
					"matched_field": h.MatchedField, "matched_value": h.MatchedValue,
					"snippet": snippet, "status": h.Status, "round_no": h.RoundNo,
					"evidence_grade": h.EvidenceGrade,
				})
			}
			return asJSONCapped(map[string]any{
				"count": len(out), "hits": out,
				"note": "紧凑投影(detail 不随清单返回);命中≠结论:候选判断权归人(§1);" +
					"核实锚点用 view_lines(source_id+行号)回查原文",
			}, "hits")
		},
	})
}
