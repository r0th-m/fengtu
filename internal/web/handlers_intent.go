// 意图链端点(切片六,DESIGN §6/§6.4):意图图查询/人手写意图/节点详情
// (执行过程流)/审批门/人工停止/源覆盖/playbook 模板清单。
// 治理语义在 intent.Engine 收口,本层只做结果映射。
package web

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ye-mengwen/fengtu/internal/agentloop"
	"github.com/ye-mengwen/fengtu/internal/ingest/store"
	"github.com/ye-mengwen/fengtu/internal/intent"
)

// IntentFace web 层需要的意图引擎面(intent.Engine 实现;单测 fake)。
type IntentFace interface {
	Graph(ctx context.Context, caseID string) ([]*intent.Node, []*intent.Edge, error)
	Detail(ctx context.Context, nodeID string) (*intent.Node, []*intent.Event, error)
	CreateHuman(ctx context.Context, caseID, actor, text, scope string,
		budgetSeconds int, parentID, hostScope string) (*intent.Node, error)
	Approve(ctx context.Context, nodeID, actor string, approve bool) (*intent.Node, error)
	Stop(ctx context.Context, nodeID, actor string) error
	Coverage(ctx context.Context, caseID string) ([]*intent.SourceCoverage, error)
	SeedTemplate(ctx context.Context, caseID, templateID, actor string) (*intent.Node, int, error)
	SeedRules(ctx context.Context, caseID, actor string, seeds []intent.RuleSeed) (int, error)
	// SeedGoals 应急目的预设落 goal 节点(交互改造·新建任务向导;幂等)。
	SeedGoals(ctx context.Context, caseID, actor string, texts []string) (int, error)
	SetCaseDeadline(ctx context.Context, caseID string, at *time.Time) error
	// SubscribeGraph 图变更订阅(切片 8b SSE 增量流;cancel 退订)。
	SubscribeGraph(caseID string) (<-chan intent.GraphChange, func())
	// GraphReplay 断线游标回放(交互改造切片二,ARTEX Last-Event-ID 语义):
	// since=客户端最后收到的帧序号;resumable=true 时 missed=(since, latest]
	// 缺帧,客户端免快照续播;false(首连/游标过老/超前)→ 全量快照兜底。
	GraphReplay(caseID string, since int64) (missed []intent.GraphChange, latest int64, resumable bool)
	// Activity 播报轮询兜底(0.23.0-live-feed):回放缓冲内序号 > since 的
	// feed 帧;帧序号=去重签名,被挤出缓冲的区间如实缺(latest 续游标)。
	Activity(caseID string, since int64) (items []intent.GraphChange, latest int64)
	Templates() []*intent.Template
	// 交互改造切片三(设计 §3 运行中操控):steer 纠偏 / add_hint 线索 /
	// 操作约束 CRUD。
	Steer(ctx context.Context, nodeID, actor, text string) error
	AddHint(ctx context.Context, caseID, actor, text, parentID string) (*intent.Node, error)
	Constraints(ctx context.Context, caseID string) ([]*intent.Constraint, error)
	AddConstraint(ctx context.Context, caseID, actor, text string) (*intent.Constraint, error)
	RemoveConstraint(ctx context.Context, caseID, id, actor string) error
	// 停车场(0.24.0-convergence L2):清单/人点展开/人点丢弃/预算可观测。
	Parking(ctx context.Context, caseID string) ([]*intent.ParkingEntry, error)
	DeployParking(ctx context.Context, id, actor string) (*intent.ParkingEntry, *intent.Node, error)
	DismissParking(ctx context.Context, id, actor string) (*intent.ParkingEntry, error)
	Budget(ctx context.Context, caseID string) (*intent.BudgetStatus, error)
	// Blackboard 案件黑板(0.28.0):四段派生视图,与 worker 注入同一份逻辑。
	Blackboard(ctx context.Context, caseID string) (*intent.Blackboard, error)
	// ReevalGoals goal 收官重估(0.29.1-goal-lifecycle;幂等,返回变化数)。
	// 报告生成时调用=旧 goal 的一次性重估路径(与 worker 写回触发点同函数)。
	ReevalGoals(ctx context.Context, caseID string) (int, error)
}

// AgentLoopFace 意图 worker 适配器需要的 agentloop 面(切片六新增三方法;
// 切片七 CreateSessionBudget 加 hostScope——意图主机范围随会话绑定)。
type AgentLoopFace interface {
	CreateSessionBudget(ctx context.Context, caseID, actor string,
		budgetTokens int64, hostScope string) (*store.AISession, error)
	RunWithSystem(ctx context.Context, sessionID, prompt,
		systemExtra string) (<-chan agentloop.Event, error)
	Abort(ctx context.Context, id, actor string) error
	// Cancel 取消正在跑的 loop 但不动会话账(steer 纠偏续跑用;幂等)。
	Cancel(ctx context.Context, id string) error
}

// AIRunnerAdapter agentloop → intent.AIRunner 适配器(打破 import 环:
// intent 包不见 agentloop/store 类型,壳事件在此投影为 intent.AIEvent)。
type AIRunnerAdapter struct {
	AI AgentLoopFace
}

func (a AIRunnerAdapter) CreateSessionBudget(ctx context.Context, caseID, actor string,
	budgetTokens int64, hostScope string) (string, error) {

	sess, err := a.AI.CreateSessionBudget(ctx, caseID, actor, budgetTokens, hostScope)
	if err != nil {
		return "", err
	}
	return sess.ID, nil
}

func (a AIRunnerAdapter) RunWithSystem(ctx context.Context, sessionID, prompt,
	systemExtra string) (<-chan intent.AIEvent, error) {

	src, err := a.AI.RunWithSystem(ctx, sessionID, prompt, systemExtra)
	if err != nil {
		return nil, err
	}
	out := make(chan intent.AIEvent, 32)
	go func() {
		defer close(out)
		for ev := range src {
			out <- intent.AIEvent{
				Kind: ev.Kind, Text: ev.Text, ToolName: ev.ToolName,
				ToolInput: ev.ToolInput, ToolOutput: ev.ToolOutput,
				Reason: ev.Reason, ErrText: ev.ErrText,
			}
		}
	}()
	return out, nil
}

func (a AIRunnerAdapter) Abort(ctx context.Context, id, actor string) error {
	return a.AI.Abort(ctx, id, actor)
}

func (a AIRunnerAdapter) Cancel(ctx context.Context, id string) error {
	return a.AI.Cancel(ctx, id)
}

// intentReady 意图引擎未装配(Deps.Intent nil)→ 503 如实,不崩。
func (s *Server) intentReady(w http.ResponseWriter) bool {
	if s.deps.Intent == nil {
		writeErr(w, http.StatusServiceUnavailable,
			"意图链引擎未启用(server 未装配 intent;见启动日志)")
		return false
	}
	return true
}

func (s *Server) actorOf(r *http.Request) string {
	if u := userFrom(r.Context()); u != nil {
		return u.Username
	}
	return "system"
}

// intentErr 意图层错误 → HTTP 状态(无此意图/案件 404;状态冲突 409;余 400)。
func intentErr(w http.ResponseWriter, err error) {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "无此意图") || strings.Contains(msg, "无此案件") ||
		strings.Contains(msg, "父意图不存在") || strings.Contains(msg, "父节点不存在") ||
		strings.Contains(msg, "无此约束") || strings.Contains(msg, "无此停车场条目"):
		writeErr(w, http.StatusNotFound, msg)
	case strings.Contains(msg, "不在待批状态") || strings.Contains(msg, "不在运行中") ||
		strings.Contains(msg, "已被处理") || strings.Contains(msg, "正在收尾") ||
		strings.Contains(msg, "已被处置") || strings.Contains(msg, "已不在 parked"):
		writeErr(w, http.StatusConflict, msg)
	default:
		writeErr(w, http.StatusBadRequest, msg)
	}
}

// listIntents 意图图(节点+边;前端力导向图数据,§6 意图图)。
func (s *Server) listIntents(w http.ResponseWriter, r *http.Request) {
	if !s.intentReady(w) {
		return
	}
	caseID := r.PathValue("id")
	c, err := s.deps.Meta.GetCase(r.Context(), caseID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if c == nil {
		writeErr(w, http.StatusNotFound, "无此案件: "+caseID)
		return
	}
	nodes, edges, err := s.deps.Intent.Graph(r.Context(), caseID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if nodes == nil {
		nodes = []*intent.Node{}
	}
	if edges == nil {
		edges = []*intent.Edge{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes": nodes, "edges": edges,
		"note": "节点五型(goal/intent/fact/finding/hint);closed_exhausted=" +
			"时间耗尽覆盖可能不全(如实标,非失败);awaiting_approval=审批门挂起",
	})
}

// createIntent 人手写意图(三源播种之一;人提出的自由执行,不过审批门)。
func (s *Server) createIntent(w http.ResponseWriter, r *http.Request) {
	if !s.intentReady(w) {
		return
	}
	caseID := r.PathValue("id")
	c, err := s.deps.Meta.GetCase(r.Context(), caseID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if c == nil {
		writeErr(w, http.StatusNotFound, "无此案件: "+caseID)
		return
	}
	if caseArchivedGuard(c) {
		writeErr(w, http.StatusConflict,
			"案件已归档(只读可看,不派新意图);解归档后恢复: POST /api/cases/{id}/unarchive")
		return
	}
	var body struct {
		Text          string `json:"text"`
		Scope         string `json:"scope"` // case|all(空=case;人提出的 all 也自由执行)
		BudgetSeconds int    `json:"budget_seconds"`
		ParentID      string `json:"parent_id"`
		HostScope     string `json:"host_scope"` // 空=全案件;主机键=限定该主机(§3 修正稿)
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	n, err := s.deps.Intent.CreateHuman(r.Context(), caseID, s.actorOf(r),
		body.Text, body.Scope, body.BudgetSeconds, body.ParentID, body.HostScope)
	if err != nil {
		intentErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"node": n})
}

// getIntent 节点详情 + 执行过程流(§6 执行过程流)。
func (s *Server) getIntent(w http.ResponseWriter, r *http.Request) {
	if !s.intentReady(w) {
		return
	}
	n, evs, err := s.deps.Intent.Detail(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if n == nil {
		writeErr(w, http.StatusNotFound, "无此意图: "+r.PathValue("id"))
		return
	}
	if evs == nil {
		evs = []*intent.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"node": n, "events": evs,
		"note": "执行过程流逐步留痕(plan/text/tool_use/tool_result/eval/spawn/" +
			"budget/stop);finding 候选在待审区(GET /api/cases/{id}/hits)",
	})
}

// approveIntent 审批门:批准/拒绝挂起意图(进审计哈希链)。
func (s *Server) approveIntent(w http.ResponseWriter, r *http.Request) {
	if !s.intentReady(w) {
		return
	}
	var body struct {
		Approve bool `json:"approve"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	n, err := s.deps.Intent.Approve(r.Context(), r.PathValue("id"),
		s.actorOf(r), body.Approve)
	if err != nil {
		intentErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"node": n})
}

// stopIntent 人工停止运行中意图(写回后关)。
func (s *Server) stopIntent(w http.ResponseWriter, r *http.Request) {
	if !s.intentReady(w) {
		return
	}
	if err := s.deps.Intent.Stop(r.Context(), r.PathValue("id"), s.actorOf(r)); err != nil {
		intentErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"stopped": r.PathValue("id"),
		"note":    "已中断执行;worker 写回已得后关闭(如实)",
	})
}

// coverage 源覆盖图数据(§6 源覆盖图后端;切片七升级为「主机 → 采集包 →
// 源」三级聚簇,§3 修正稿一案多包)。flat sources 列表保留兼容。
func (s *Server) coverage(w http.ResponseWriter, r *http.Request) {
	if !s.intentReady(w) {
		return
	}
	caseID := r.PathValue("id")
	c, err := s.deps.Meta.GetCase(r.Context(), caseID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if c == nil {
		writeErr(w, http.StatusNotFound, "无此案件: "+caseID)
		return
	}
	cov, err := s.deps.Intent.Coverage(r.Context(), caseID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cov == nil {
		cov = []*intent.SourceCoverage{}
	}
	explored := 0
	for _, c := range cov {
		if c.Explored {
			explored++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sources": cov, "sources_total": len(cov), "sources_explored": explored,
		"hosts": clusterCoverage(cov),
		"note": "三级聚簇:主机(host,空串=未建模散件)→ 采集包(package)→ 源;" +
			"explored=被任意意图执行摸过(回查/算子/锚点);" +
			"未 explored 的源=覆盖缺口,如实呈现(勒索案「查全没」的正面回答)",
	})
}

// coverageCluster 三级聚簇的中间结构(JSON 直出)。
type coverageCluster struct {
	Host         string                    `json:"host"` // 空串=未建模散件
	SourcesTotal int                       `json:"sources_total"`
	Explored     int                       `json:"explored"`
	Packages     []coveragePackageCluster  `json:"packages"`
}

type coveragePackageCluster struct {
	Package      string                    `json:"package"` // 空串=散件(非包摄入)
	SourcesTotal int                       `json:"sources_total"`
	Explored     int                       `json:"explored"`
	Sources      []*intent.SourceCoverage  `json:"sources"`
}

// clusterCoverage 主机→包→源三级聚合(键保序:字典序,空键(未建模/散件)
// 如实排前,不隐藏)。
func clusterCoverage(cov []*intent.SourceCoverage) []coverageCluster {
	hostOrder := []string{}
	hostMap := map[string][]*intent.SourceCoverage{}
	for _, c := range cov {
		if _, ok := hostMap[c.Host]; !ok {
			hostOrder = append(hostOrder, c.Host)
		}
		hostMap[c.Host] = append(hostMap[c.Host], c)
	}
	out := make([]coverageCluster, 0, len(hostOrder))
	for _, h := range hostOrder {
		cl := coverageCluster{Host: h}
		pkgOrder := []string{}
		pkgMap := map[string][]*intent.SourceCoverage{}
		for _, c := range hostMap[h] {
			if _, ok := pkgMap[c.Package]; !ok {
				pkgOrder = append(pkgOrder, c.Package)
			}
			pkgMap[c.Package] = append(pkgMap[c.Package], c)
			cl.SourcesTotal++
			if c.Explored {
				cl.Explored++
			}
		}
		for _, p := range pkgOrder {
			pc := coveragePackageCluster{Package: p, Sources: pkgMap[p]}
			for _, c := range pkgMap[p] {
				pc.SourcesTotal++
				if c.Explored {
					pc.Explored++
				}
			}
			cl.Packages = append(cl.Packages, pc)
		}
		out = append(out, cl)
	}
	return out
}

// intentEvents SSE 意图图增量流(切片 8b,§13 意图图实时生长;
// 交互改造切片二加断线游标,照抄 ARTEX sessions-tab 语义):
//   - 每帧带 id: <案件内递增序号>(snapshot 帧 id=基线序号);
//   - 断线重连:EventSource 自动回传 Last-Event-ID(或手工 ?since=),
//     游标可续 → 只回放缺帧(免全量快照,重渲染不打断);不可续
//     (首连/游标被挤出缓冲/进程重启序号归零)→ 全量快照兜底(如实);
//   - 无变更 15s 心跳(: ping);订阅通道溢出 = 慢订阅者,服务端关流,
//     客户端重连走同一游标/快照逻辑。
func (s *Server) intentEvents(w http.ResponseWriter, r *http.Request) {
	if !s.intentReady(w) {
		return
	}
	caseID := r.PathValue("id")
	c, err := s.deps.Meta.GetCase(r.Context(), caseID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if c == nil {
		writeErr(w, http.StatusNotFound, "无此案件: "+caseID)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "响应不支持流式")
		return
	}
	// 断线游标:Last-Event-ID 头优先(EventSource 自动重连带回),
	// ?since= 兼容手工/测试;非法值按首连处理(快照永远安全)。
	var since int64
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		since, _ = strconv.ParseInt(v, 10, 64)
	} else if v := r.URL.Query().Get("since"); v != "" {
		since, _ = strconv.ParseInt(v, 10, 64)
	}
	// 先订阅再定基线:订阅后的一切帧都在 ch 内,回放/快照与续播无缝衔接
	ch, cancel := s.deps.Intent.SubscribeGraph(caseID)
	defer cancel()
	missed, latest, resumable := s.deps.Intent.GraphReplay(caseID, since)
	watermark := latest // ≤ 基线的续播帧是回放/快照已覆盖的,去重跳过

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	send := func(event string, id int64, v any) bool {
		b, err := jsonMarshal(v)
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: ", id, event); err != nil {
			return false
		}
		if _, err := w.Write(append(b, '\n', '\n')); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	sendChange := func(gc intent.GraphChange) bool {
		var v any
		switch gc.Kind {
		case "node_added", "node_updated":
			v = gc.Node
		case "edge_added":
			v = gc.Edge
		case "feed": // 0.23.0 播报帧:序号在 id: 行,前端按 lastEventId 去重
			v = gc.Feed
		default:
			return true // 未知帧型跳过
		}
		return send(gc.Kind, gc.Seq, v)
	}

	if resumable {
		// 游标续播:只补缺帧,不重发快照(客户端图状态保留,不打断拖动)
		for _, gc := range missed {
			if !sendChange(gc) {
				return
			}
		}
	} else {
		// 快照兜底:首连/游标失效,全量对齐(id=基线序号,续播游标由此起算)
		nodes, edges, err := s.deps.Intent.Graph(r.Context(), caseID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if nodes == nil {
			nodes = []*intent.Node{}
		}
		if edges == nil {
			edges = []*intent.Edge{}
		}
		if !send("snapshot", latest, map[string]any{"nodes": nodes, "edges": edges}) {
			return
		}
	}
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case gc, open := <-ch:
			if !open {
				return // 溢出关流:客户端重连,游标可续补帧/不可续快照(如实兜底)
			}
			if gc.Seq > 0 && gc.Seq <= watermark {
				continue // 基线内重复帧(回放/快照已覆盖),去重
			}
			watermark = gc.Seq
			if !sendChange(gc) {
				return
			}
		case <-heartbeat.C:
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// activityItem 播报轮询条目(帧序号拍平进条目;字段与 intent.FeedItem 对齐)。
type activityItem struct {
	Seq    int64     `json:"seq"`
	NodeID string    `json:"node_id,omitempty"`
	Tier   string    `json:"tier"`
	Status string    `json:"status,omitempty"`
	Text   string    `json:"text"`
	Detail string    `json:"detail,omitempty"`
	TS     time.Time `json:"ts"`
}

// caseActivity 播报板轮询兜底(0.23.0-live-feed):GET ?since=<帧序号> →
// 回放缓冲内的 feed 帧(签名=seq,前端去重合并)。实时主路仍是 SSE
// (feed 帧随意图图通道下发),本端点只做首连回填与断缝补帧;
// 缓冲被挤出的区间如实缺(latest 供客户端续游标,不伪造连续)。
func (s *Server) caseActivity(w http.ResponseWriter, r *http.Request) {
	if !s.intentReady(w) {
		return
	}
	caseID := r.PathValue("id")
	c, err := s.deps.Meta.GetCase(r.Context(), caseID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if c == nil {
		writeErr(w, http.StatusNotFound, "无此案件: "+caseID)
		return
	}
	var since int64
	if v := r.URL.Query().Get("since"); v != "" {
		since, _ = strconv.ParseInt(v, 10, 64)
	}
	frames, latest := s.deps.Intent.Activity(caseID, since)
	items := []activityItem{}
	for _, f := range frames {
		if f.Feed == nil {
			continue
		}
		items = append(items, activityItem{
			Seq: f.Seq, NodeID: f.Feed.NodeID, Tier: f.Feed.Tier,
			Status: f.Feed.Status, Text: f.Feed.Text, Detail: f.Feed.Detail,
			TS: f.Feed.TS,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "latest": latest,
		"note": "播报轮询兜底(实时主路=SSE feed 帧);seq=案件内帧序号(去重签名);" +
			"回放缓冲有限(512 帧/案,与图变更共用),被挤出区间如实缺,以 latest 续游标",
	})
}

// listPlaybooks 已装载 playbook 意图模板清单。
func (s *Server) listPlaybooks(w http.ResponseWriter, _ *http.Request) {
	if !s.intentReady(w) {
		return
	}
	tpls := s.deps.Intent.Templates()
	if tpls == nil {
		tpls = []*intent.Template{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"playbooks": tpls,
		"note":      "playbook=预制的意图链模板;POST /api/cases/{id}/analyze 带 playbook 实例化",
	})
}

// ---- 停车场(0.24.0-convergence L2) ----

// caseParking 案件停车场清单(含已处置留痕;展开/丢弃走人批端点)。
func (s *Server) caseParking(w http.ResponseWriter, r *http.Request) {
	if !s.intentReady(w) {
		return
	}
	caseID := r.PathValue("id")
	c, err := s.deps.Meta.GetCase(r.Context(), caseID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if c == nil {
		writeErr(w, http.StatusNotFound, "无此案件: "+caseID)
		return
	}
	items, err := s.deps.Intent.Parking(r.Context(), caseID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if items == nil {
		items = []*intent.ParkingEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"note": "停车场=预算闸拦下/AI 登记的未展开线索(对应图上 parked 灰色虚线节点);" +
			"verdict=章节收官评估建议(AI 只建议);展开/丢弃永远人批:" +
			"POST /api/parking/{id}/deploy|/dismiss",
	})
}

// parkingDeploy 人点展开(归属建议=既有章:直转 open 走派发,视同人批;
// 新开章:先落新 goal 再转 open;进审计)。
func (s *Server) parkingDeploy(w http.ResponseWriter, r *http.Request) {
	if !s.intentReady(w) {
		return
	}
	entry, node, err := s.deps.Intent.DeployParking(r.Context(), r.PathValue("id"),
		s.actorOf(r))
	if err != nil {
		intentErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entry": entry, "node": node,
		"note": "已展开为正常意图转 open,planner 即派发;展开后的子派生仍过预算三闸",
	})
}

// parkingDismiss 人点丢弃(留痕:节点 closed+条目 dismissed+审计,不真删)。
func (s *Server) parkingDismiss(w http.ResponseWriter, r *http.Request) {
	if !s.intentReady(w) {
		return
	}
	entry, err := s.deps.Intent.DismissParking(r.Context(), r.PathValue("id"), s.actorOf(r))
	if err != nil {
		intentErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entry": entry, "note": "已丢弃并留痕(审计链+节点 close_note),不入图不派发",
	})
}

// parkingBatch 批量处置(0.29.0-batch-ops):{ids:[...], action:"deploy"|"dismiss"},
// 逐条走与单条同一语义(deploy=人批放行转 open,dismiss=丢弃留痕;已处置的
// 该条如实标失败不影响其余)。审计由引擎逐条落(与单条同构,不另记)。
// 判断权归人:批量也是人逐批拍板,无自动处置。
func (s *Server) parkingBatch(w http.ResponseWriter, r *http.Request) {
	if !s.intentReady(w) {
		return
	}
	var body struct {
		IDs    []string `json:"ids"`
		Action string   `json:"action"` // deploy|dismiss
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Action != "deploy" && body.Action != "dismiss" {
		writeErr(w, http.StatusBadRequest,
			fmt.Sprintf("action 须为 deploy|dismiss: %q", body.Action))
		return
	}
	ids := dedupIDs(body.IDs)
	if len(ids) == 0 {
		writeErr(w, http.StatusBadRequest, "ids 为空:批量处置至少一条")
		return
	}
	if len(ids) > maxBatchIDs {
		writeErr(w, http.StatusBadRequest,
			fmt.Sprintf("单次批量上限 %d 条(实传 %d)", maxBatchIDs, len(ids)))
		return
	}
	actor := s.actorOf(r)
	results := make([]batchItemResult, 0, len(ids))
	done := 0
	for _, id := range ids {
		var err error
		if body.Action == "deploy" {
			_, _, err = s.deps.Intent.DeployParking(r.Context(), id, actor)
		} else {
			_, err = s.deps.Intent.DismissParking(r.Context(), id, actor)
		}
		if err != nil {
			results = append(results, batchItemResult{ID: id, Error: err.Error()})
			continue
		}
		done++
		results = append(results, batchItemResult{ID: id, OK: true})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"results": results,
		"total":   len(ids), "done": done, "skipped": len(ids) - done,
		"note": "逐条同单条语义(已处置的 409 跳过如实报,原因在 results[].error);" +
			"展开视同人批直转 open 派发,丢弃留痕,审计逐条落",
	})
}

// caseBudget 预算可观测(0.24.0):三闸当前值 + 案意图数消耗 + 章分布 +
// 停车场待处置数。超闸历史在播报板/过程流(park 步)与审计链(intent.parked)。
func (s *Server) caseBudget(w http.ResponseWriter, r *http.Request) {
	if !s.intentReady(w) {
		return
	}
	caseID := r.PathValue("id")
	c, err := s.deps.Meta.GetCase(r.Context(), caseID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if c == nil {
		writeErr(w, http.StatusNotFound, "无此案件: "+caseID)
		return
	}
	st, err := s.deps.Intent.Budget(r.Context(), caseID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"budget": st,
		"note": "三闸只限自动派生(人工手写意图/线索不占额);闸值在系统配置页改," +
			"对之后派生即时生效;超闸历史查播报板「停车场」档与审计链 intent.parked",
	})
}

// caseBlackboard 案件黑板(0.28.0-blackboard):四段派生只读视图——已确认
// 事实(带锚点)/存疑发现/在查已查意图清单/停车场线索。与 worker systemExtra
// 注入同一份派生逻辑(intent.buildBlackboard),不两处实现;Xxx_total=全集
// 条数,切片=呈现条数,差值=上限截掉,如实。
func (s *Server) caseBlackboard(w http.ResponseWriter, r *http.Request) {
	if !s.intentReady(w) {
		return
	}
	caseID := r.PathValue("id")
	c, err := s.deps.Meta.GetCase(r.Context(), caseID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if c == nil {
		writeErr(w, http.StatusNotFound, "无此案件: "+caseID)
		return
	}
	bb, err := s.deps.Intent.Blackboard(r.Context(), caseID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"blackboard": bb,
		"note": "案件黑板=本案实时状态四段派生(不建新表;worker 注入同一份逻辑):" +
			"facts=proves 确认的已确认事实(带锚点);doubts=存疑发现;" +
			"intents=在查/已查清单(在查排前);parking=停车场待处置;" +
			"各段 xxx_total=全集条数,切片被上限截掉的差值如实呈现",
	})
}
