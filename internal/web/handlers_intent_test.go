// 意图链端点契约测试(fake IntentFace):图查询/手写意图/详情/审批/停止/
// 覆盖/playbook 清单/未装配 503/无此案 404/状态冲突 409。
package web

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ye-mengwen/fengtu/internal/intent"
)

type fakeIntent struct {
	nodes     map[string]*intent.Node
	edges     []*intent.Edge
	events    []*intent.Event
	seq       int
	approved  []bool
	stopped   []string
	steered   []string             // 切片三纠偏记录(nodeID:text)
	deadlines map[string]*time.Time
	graphCh   chan intent.GraphChange // SSE 增量测试喂帧口
	// GraphReplay 可编程应答(断线游标测试)
	replayMissed []intent.GraphChange
	replayLatest int64
	replayOK     bool
	// Activity 可编程应答(0.23.0 播报轮询测试)
	activityItems  []intent.GraphChange
	activityLatest int64
	constraints    []*intent.Constraint // 切片三操作约束
	parking        []*intent.ParkingEntry // 0.24.0 停车场条目(测试注入)
	blackboard     *intent.Blackboard     // 0.28.0 黑板可编程应答(nil=派生空板)
	blackboardErr  error
}

func newFakeIntent() *fakeIntent {
	return &fakeIntent{nodes: map[string]*intent.Node{},
		deadlines: map[string]*time.Time{}, graphCh: make(chan intent.GraphChange, 8)}
}

// SubscribeGraph 测试面:返回共享喂帧通道(测试直接写,不模拟溢出关流)。
func (f *fakeIntent) SubscribeGraph(_ string) (<-chan intent.GraphChange, func()) {
	return f.graphCh, func() {}
}

// GraphReplay 测试面:可编程应答(replayMissed/replayLatest/replayOK)。
func (f *fakeIntent) GraphReplay(_ string, since int64) ([]intent.GraphChange, int64, bool) {
	return f.replayMissed, f.replayLatest, f.replayOK
}

// Activity 测试面(0.23.0 播报轮询):可编程应答(activityItems/activityLatest)。
func (f *fakeIntent) Activity(_ string, since int64) ([]intent.GraphChange, int64) {
	var out []intent.GraphChange
	for _, gc := range f.activityItems {
		if gc.Seq > since {
			out = append(out, gc)
		}
	}
	return out, f.activityLatest
}

// ReevalGoals 测试面(0.29.1):fake 不做重估,如实零变化(报告端点契约
// 测试里 goal 状态由测试直接注入)。
func (f *fakeIntent) ReevalGoals(context.Context, string) (int, error) { return 0, nil }

func (f *fakeIntent) Graph(_ context.Context, caseID string) ([]*intent.Node, []*intent.Edge, error) {
	var ns []*intent.Node
	for _, n := range f.nodes {
		if n.CaseID == caseID {
			ns = append(ns, n)
		}
	}
	return ns, f.edges, nil
}

func (f *fakeIntent) Detail(_ context.Context, nodeID string) (*intent.Node, []*intent.Event, error) {
	return f.nodes[nodeID], f.events, nil
}

func (f *fakeIntent) CreateHuman(_ context.Context, caseID, actor, text, scope string,
	budgetSeconds int, parentID, hostScope string) (*intent.Node, error) {

	if text == "" {
		return nil, fmt.Errorf("意图文本必填")
	}
	if parentID == "ghost" {
		return nil, fmt.Errorf("父意图不存在(或不属本案件): %s", parentID)
	}
	f.seq++
	n := &intent.Node{ID: fmt.Sprintf("node-%d", f.seq), CaseID: caseID,
		Kind: intent.KindIntent, Text: text, Status: intent.StatusOpen,
		CreatedBy: intent.ByHuman, Scope: intent.ScopeCase, HostScope: hostScope,
		Depth: 1, BudgetSeconds: budgetSeconds, CreatedAt: time.Now()}
	f.nodes[n.ID] = n
	return n, nil
}

func (f *fakeIntent) Approve(_ context.Context, nodeID, actor string, approve bool) (*intent.Node, error) {
	n := f.nodes[nodeID]
	if n == nil {
		return nil, fmt.Errorf("无此意图: %s", nodeID)
	}
	if n.Status != intent.StatusAwaitingApproval {
		return nil, fmt.Errorf("意图不在待批状态(当前 %s),无需审批", n.Status)
	}
	f.approved = append(f.approved, approve)
	if approve {
		n.Status = intent.StatusOpen
	} else {
		n.Status = intent.StatusClosed
	}
	return n, nil
}

func (f *fakeIntent) Stop(_ context.Context, nodeID, actor string) error {
	n := f.nodes[nodeID]
	if n == nil {
		return fmt.Errorf("无此意图: %s", nodeID)
	}
	// 切片三 kill 扩展:open(未派发)直接关闭,零 AI 消耗
	if n.Status == intent.StatusOpen && n.Kind == intent.KindIntent {
		n.Status = intent.StatusClosed
		n.CloseNote = "人工终止(未派发即关闭,未消耗 AI)"
		f.stopped = append(f.stopped, nodeID)
		return nil
	}
	if n.Status != intent.StatusRunning {
		return fmt.Errorf("意图不在运行中(当前 %s),无法停止", n.Status)
	}
	f.stopped = append(f.stopped, nodeID)
	return nil
}

func (f *fakeIntent) Coverage(_ context.Context, caseID string) ([]*intent.SourceCoverage, error) {
	return []*intent.SourceCoverage{
		{SourceID: "src-1", Path: "pkg-a/a.log", Kind: "text", Host: "10.0.0.1",
			Package: "pkg-a", Explored: true, IntentIDs: []string{"node-1"},
			Facts: 1, Hits: 2},
		{SourceID: "src-2", Path: "pkg-a/b.log", Kind: "text", Host: "10.0.0.1",
			Package: "pkg-a"},
		{SourceID: "src-3", Path: "pkg-b/c.log", Kind: "text", Host: "10.0.0.2",
			Package: "pkg-b", Explored: true, IntentIDs: []string{"node-2"}},
		{SourceID: "src-4", Path: "loose.log", Kind: "text"}, // 散件:未建模
	}, nil
}

func (f *fakeIntent) SeedTemplate(_ context.Context, caseID, templateID, actor string) (*intent.Node, int, error) {
	n := &intent.Node{ID: "goal-1", CaseID: caseID, Kind: intent.KindGoal,
		Status: intent.StatusOpen, TemplateID: templateID}
	f.nodes[n.ID] = n
	return n, 2, nil
}

func (f *fakeIntent) SeedRules(_ context.Context, caseID, actor string, seeds []intent.RuleSeed) (int, error) {
	return len(seeds), nil
}

// SeedGoals 目的预设播种(fake):逐条建 goal 节点,返回新条数。
func (f *fakeIntent) SeedGoals(_ context.Context, caseID, actor string, texts []string) (int, error) {
	created := 0
	for _, t := range texts {
		created++
		n := &intent.Node{ID: fmt.Sprintf("goal-seed-%d", created), CaseID: caseID,
			Kind: intent.KindGoal, Text: t, Status: intent.StatusOpen,
			CreatedBy: intent.ByHuman}
		f.nodes[n.ID] = n
	}
	return created, nil
}

func (f *fakeIntent) SetCaseDeadline(_ context.Context, caseID string, at *time.Time) error {
	f.deadlines[caseID] = at
	return nil
}

// ---- 切片三:运行中操控(steer/hint/约束) ----

func (f *fakeIntent) Steer(_ context.Context, nodeID, actor, text string) error {
	n := f.nodes[nodeID]
	if n == nil {
		return fmt.Errorf("无此意图: %s", nodeID)
	}
	if strings.TrimSpace(text) == "" {
		return fmt.Errorf("纠偏内容必填")
	}
	if n.Status != intent.StatusRunning {
		return fmt.Errorf("意图不在运行中(当前 %s),纠偏只对在跑意图;"+
			"已结束的请补线索或手写新意图", n.Status)
	}
	f.steered = append(f.steered, nodeID+":"+text)
	return nil
}

func (f *fakeIntent) AddHint(_ context.Context, caseID, actor, text, parentID string) (*intent.Node, error) {
	if text == "" {
		return nil, fmt.Errorf("线索内容必填")
	}
	f.seq++
	n := &intent.Node{ID: fmt.Sprintf("hint-%d", f.seq), CaseID: caseID,
		Kind: intent.KindHint, Text: text, Status: intent.StatusClosed,
		CreatedBy: intent.ByHuman, Scope: intent.ScopeCase, ParentID: parentID,
		CreatedAt: time.Now()}
	f.nodes[n.ID] = n
	return n, nil
}

func (f *fakeIntent) Constraints(_ context.Context, caseID string) ([]*intent.Constraint, error) {
	out := []*intent.Constraint{}
	for _, c := range f.constraints {
		if c.CaseID == caseID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *fakeIntent) AddConstraint(_ context.Context, caseID, actor, text string) (*intent.Constraint, error) {
	if text == "" {
		return nil, fmt.Errorf("约束内容必填")
	}
	for _, c := range f.constraints {
		if c.CaseID == caseID && c.Text == text {
			return c, nil // 幂等
		}
	}
	f.seq++
	c := &intent.Constraint{ID: fmt.Sprintf("c-%d", f.seq), CaseID: caseID,
		Text: text, CreatedBy: actor, CreatedAt: time.Now()}
	f.constraints = append(f.constraints, c)
	return c, nil
}

func (f *fakeIntent) RemoveConstraint(_ context.Context, caseID, id, actor string) error {
	for i, c := range f.constraints {
		if c.ID == id && c.CaseID == caseID {
			f.constraints = append(f.constraints[:i], f.constraints[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("无此约束: %s", id)
}

func (f *fakeIntent) Templates() []*intent.Template {
	return []*intent.Template{{ID: "ransomware-triage", Title: "勒索排查"},
		{ID: "general-triage", Title: "通用排查"}}
}

// ---- 0.24.0 停车场(fake;条目账 parking,节点账复用 f.nodes) ----

func (f *fakeIntent) Parking(_ context.Context, caseID string) ([]*intent.ParkingEntry, error) {
	out := []*intent.ParkingEntry{}
	for _, p := range f.parking {
		if p.CaseID == caseID {
			out = append(out, p)
		}
	}
	return out, nil
}

func (f *fakeIntent) DeployParking(_ context.Context, id, actor string) (*intent.ParkingEntry, *intent.Node, error) {
	for _, p := range f.parking {
		if p.ID == id {
			if p.Status != intent.ParkingParked {
				return nil, nil, fmt.Errorf("停车场条目已被处置(当前 %s),不重复展开", p.Status)
			}
			n := f.nodes[p.NodeID]
			if n == nil {
				return nil, nil, fmt.Errorf("无此意图: %s", p.NodeID)
			}
			n.Status = intent.StatusOpen
			p.Status = intent.ParkingDeployed
			p.DecidedBy = actor
			return p, n, nil
		}
	}
	return nil, nil, fmt.Errorf("无此停车场条目: %s", id)
}

func (f *fakeIntent) DismissParking(_ context.Context, id, actor string) (*intent.ParkingEntry, error) {
	for _, p := range f.parking {
		if p.ID == id {
			if p.Status != intent.ParkingParked {
				return nil, fmt.Errorf("停车场条目已被处置(当前 %s),不重复丢弃", p.Status)
			}
			if n := f.nodes[p.NodeID]; n != nil {
				n.Status = intent.StatusClosed
			}
			p.Status = intent.ParkingDismissed
			p.DecidedBy = actor
			return p, nil
		}
	}
	return nil, fmt.Errorf("无此停车场条目: %s", id)
}

func (f *fakeIntent) Budget(_ context.Context, caseID string) (*intent.BudgetStatus, error) {
	st := &intent.BudgetStatus{Limits: intent.DefaultBudgetLimits(),
		Chapters: []intent.ChapterBudget{}}
	for _, n := range f.nodes {
		if n.CaseID == caseID && n.Kind == intent.KindIntent &&
			n.CreatedBy != intent.ByHuman && n.Status != intent.StatusParked {
			st.CaseIntents++
		}
	}
	for _, p := range f.parking {
		if p.CaseID == caseID && p.Status == intent.ParkingParked {
			st.Parked++
		}
	}
	return st, nil
}

// Blackboard 测试面(0.28.0):可编程应答(blackboard/blackboardErr);
// nil 时给空板(四段空集,如实)。
func (f *fakeIntent) Blackboard(_ context.Context, caseID string) (*intent.Blackboard, error) {
	if f.blackboardErr != nil {
		return nil, f.blackboardErr
	}
	if f.blackboard != nil {
		return f.blackboard, nil
	}
	return &intent.Blackboard{CaseID: caseID,
		Facts: []intent.BlackboardFact{}, Doubts: []intent.BlackboardDoubt{},
		Intents: []intent.BlackboardIntent{}, Parking: []*intent.ParkingEntry{}}, nil
}

func TestIntentEndpoints(t *testing.T) {
	e := newTestEnv(t)
	fi := newFakeIntent()
	e.srv.deps.Intent = fi
	e.login(t)

	// 造案件(上传流登记;fakeMeta 认它)
	tid := e.uploadFile(t, "intent-case", "a.log", []byte("10.0.0.1 - - [01/Jan/2024:00:00:00 +0000] \"GET / HTTP/1.1\" 200 1\n"), "")
	e.waitTask(t, tid)
	code, out := e.do(t, "GET", "/api/cases", nil)
	caseID := out["cases"].([]any)[0].(map[string]any)["id"].(string)

	// playbook 清单
	code, out = e.do(t, "GET", "/api/playbooks", nil)
	if code != 200 || len(out["playbooks"].([]any)) != 2 {
		t.Fatalf("playbook 清单失败: %d %v", code, out)
	}

	// 空图(零节点返回 [] 不返回 null)
	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/intents", nil)
	if code != 200 {
		t.Fatalf("意图图查询失败: %d %v", code, out)
	}
	if _, isArr := out["nodes"].([]any); !isArr {
		t.Fatalf("空图 nodes 应为 []: %v", out["nodes"])
	}
	// 无此案件 404
	code, _ = e.do(t, "GET", "/api/cases/nope/intents", nil)
	if code != http.StatusNotFound {
		t.Fatalf("无此案件应 404: %d", code)
	}

	// 手写意图 → 201 + 图里可见
	code, out = e.do(t, "POST", "/api/cases/"+caseID+"/intents",
		map[string]any{"text": "3306 有没有被外部直连", "budget_seconds": 30})
	if code != http.StatusCreated {
		t.Fatalf("手写意图失败: %d %v", code, out)
	}
	nodeID := out["node"].(map[string]any)["id"].(string)
	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/intents", nil)
	if code != 200 || len(out["nodes"].([]any)) != 1 {
		t.Fatalf("图里应见新意图: %d %v", code, out)
	}
	// 空文本 400;幽灵父意图 404
	code, _ = e.do(t, "POST", "/api/cases/"+caseID+"/intents", map[string]any{"text": ""})
	if code != http.StatusBadRequest {
		t.Fatalf("空文本应 400: %d", code)
	}
	code, _ = e.do(t, "POST", "/api/cases/"+caseID+"/intents",
		map[string]any{"text": "挂幽灵", "parent_id": "ghost"})
	if code != http.StatusNotFound {
		t.Fatalf("幽灵父意图应 404: %d", code)
	}

	// 详情(无此意图 404)
	code, out = e.do(t, "GET", "/api/intents/"+nodeID, nil)
	if code != 200 || out["node"] == nil {
		t.Fatalf("意图详情失败: %d %v", code, out)
	}
	code, _ = e.do(t, "GET", "/api/intents/nope", nil)
	if code != http.StatusNotFound {
		t.Fatalf("无此意图应 404: %d", code)
	}

	// 审批门:非待批 409;待批 → 批/拒
	code, _ = e.do(t, "POST", "/api/intents/"+nodeID+"/approve",
		map[string]any{"approve": true})
	if code != http.StatusConflict {
		t.Fatalf("非待批审批应 409: %d", code)
	}
	fi.nodes["gated"] = &intent.Node{ID: "gated", CaseID: "case-1",
		Kind: intent.KindIntent, Text: "批量核查", Status: intent.StatusAwaitingApproval,
		CreatedBy: intent.ByAI, Scope: intent.ScopeAll}
	code, out = e.do(t, "POST", "/api/intents/gated/approve", map[string]any{"approve": true})
	if code != 200 || out["node"].(map[string]any)["status"] != intent.StatusOpen {
		t.Fatalf("批准失败: %d %v", code, out)
	}

	// 停止(切片三 kill 扩展):open(未派发)→ 200 直接关闭;已终态 → 409;
	// 运行 → 200
	code, _ = e.do(t, "POST", "/api/intents/"+nodeID+"/stop", nil)
	if code != 200 || fi.nodes[nodeID].Status != intent.StatusClosed {
		t.Fatalf("open 意图终止应 200 并关闭: %d %v", code, fi.nodes[nodeID].Status)
	}
	code, _ = e.do(t, "POST", "/api/intents/"+nodeID+"/stop", nil)
	if code != http.StatusConflict {
		t.Fatalf("已终态停止应 409: %d", code)
	}
	fi.nodes[nodeID].Status = intent.StatusRunning
	code, _ = e.do(t, "POST", "/api/intents/"+nodeID+"/stop", nil)
	if code != 200 || len(fi.stopped) != 2 {
		t.Fatalf("停止失败: %d stopped=%v", code, fi.stopped)
	}

	// 源覆盖(切片七:三级聚簇 主机→包→源)
	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/coverage", nil)
	if code != 200 || out["sources_total"].(float64) != 4 ||
		out["sources_explored"].(float64) != 2 {
		t.Fatalf("源覆盖失败: %d %v", code, out)
	}
	hosts, ok := out["hosts"].([]any)
	if !ok || len(hosts) != 3 { // 10.0.0.1 / 10.0.0.2 / 空(散件)
		t.Fatalf("三级聚簇主机层失败: %v", out["hosts"])
	}
	byHost := map[string]any{}
	for _, h := range hosts {
		hm := h.(map[string]any)
		byHost[hm["host"].(string)] = hm
	}
	h1 := byHost["10.0.0.1"].(map[string]any)
	if h1["sources_total"].(float64) != 2 || h1["explored"].(float64) != 1 {
		t.Fatalf("主机层聚合错: %v", h1)
	}
	pkgs := h1["packages"].([]any)
	if len(pkgs) != 1 || pkgs[0].(map[string]any)["package"].(string) != "pkg-a" ||
		len(pkgs[0].(map[string]any)["sources"].([]any)) != 2 {
		t.Fatalf("包层聚合错: %v", pkgs)
	}
	loose := byHost[""].(map[string]any)
	if loose["sources_total"].(float64) != 1 {
		t.Fatalf("散件应归入空主机键,如实不隐藏: %v", loose)
	}
}

func TestIntentNotAssembled(t *testing.T) {
	e := newTestEnv(t)
	e.login(t) // Deps.Intent 未装(nil)
	for _, path := range []string{"/api/playbooks", "/api/cases/case-1/intents",
		"/api/cases/case-1/coverage", "/api/intents/x", "/api/cases/case-1/activity",
		"/api/cases/case-1/parking", "/api/cases/case-1/budget",
		"/api/cases/case-1/blackboard"} {
		code, _ := e.do(t, "GET", path, nil)
		if code != http.StatusServiceUnavailable {
			t.Fatalf("%s 未装配应 503: %d", path, code)
		}
	}
	for _, path := range []string{"/api/parking/p-1/deploy", "/api/parking/p-1/dismiss"} {
		code, _ := e.do(t, "POST", path, nil)
		if code != http.StatusServiceUnavailable {
			t.Fatalf("%s 未装配应 503: %d", path, code)
		}
	}
}

// TestIntentEventsSSE 意图图 SSE 增量流(切片 8b):首帧 snapshot 全量,
// 图变更按 node_added/node_updated/edge_added 逐帧推;未登录 401。
func TestIntentEventsSSE(t *testing.T) {
	e := newTestEnv(t)
	fi := newFakeIntent()
	e.srv.deps.Intent = fi
	e.login(t)
	tid := e.uploadFile(t, "sse-case", "a.log", []byte(nginxContent), "")
	e.waitTask(t, tid)
	_, out := e.do(t, "GET", "/api/cases", nil)
	caseID := out["cases"].([]any)[0].(map[string]any)["id"].(string)

	// 未登录 401
	req, _ := http.NewRequest("GET", e.ts.URL+"/api/cases/"+caseID+"/intents/events", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("SSE 请求失败: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("未登录应 401: %d", resp.StatusCode)
	}

	// 登录:快照 + 喂两帧增量
	fi.nodes["n1"] = &intent.Node{ID: "n1", CaseID: caseID, Kind: intent.KindGoal,
		Text: "目标", Status: intent.StatusOpen, CreatedBy: intent.ByRule,
		Scope: intent.ScopeCase, Depth: 0, CreatedAt: time.Now()}
	req, _ = http.NewRequest("GET", e.ts.URL+"/api/cases/"+caseID+"/intents/events", nil)
	req.Header.Set("Cookie", sessionCookie+"="+e.cookie)
	resp, err = (&http.Client{Timeout: 10 * time.Second}).Do(req) // 整体超时兜底(读阻塞不挂测试)
	if err != nil {
		t.Fatalf("SSE 请求失败: %v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type 应为 text/event-stream: %q", ct)
	}
	fi.graphCh <- intent.GraphChange{Kind: "node_added", Node: &intent.Node{
		ID: "n2", CaseID: caseID, Kind: intent.KindIntent, Text: "子意图",
		Status: intent.StatusOpen, CreatedBy: intent.ByAI, Scope: intent.ScopeCase,
		Depth: 1, CreatedAt: time.Now()}}
	fi.graphCh <- intent.GraphChange{Kind: "edge_added", Edge: &intent.Edge{
		ID: "e1", CaseID: caseID, FromID: "n1", ToID: "n2", Kind: intent.EdgeSpawns,
		CreatedAt: time.Now()}}

	// 读三帧(snapshot/node_added/edge_added),限时 5s
	type frame struct{ event, data string }
	frames := []frame{}
	buf := make([]byte, 4096)
	var acc string
	deadline := time.Now().Add(5 * time.Second)
	for len(frames) < 3 && time.Now().Before(deadline) {
		n, rerr := resp.Body.Read(buf)
		if rerr != nil {
			t.Fatalf("SSE 读取失败: %v", rerr)
		}
		acc += string(buf[:n])
		for {
			i := strings.Index(acc, "\n\n")
			if i < 0 {
				break
			}
			raw := acc[:i]
			acc = acc[i+2:]
			var fr frame
			for _, ln := range strings.Split(raw, "\n") {
				if strings.HasPrefix(ln, "event: ") {
					fr.event = strings.TrimPrefix(ln, "event: ")
				} else if strings.HasPrefix(ln, "data: ") {
					fr.data = strings.TrimPrefix(ln, "data: ")
				}
			}
			if fr.event != "" {
				frames = append(frames, fr)
			}
		}
	}
	if len(frames) < 3 {
		t.Fatalf("5s 内应收满 3 帧,实得 %d: %v", len(frames), frames)
	}
	if frames[0].event != "snapshot" ||
		!strings.Contains(frames[0].data, `"n1"`) {
		t.Fatalf("首帧应为 snapshot 全量: %+v", frames[0])
	}
	if frames[1].event != "node_added" || !strings.Contains(frames[1].data, `"n2"`) {
		t.Fatalf("次帧应为 node_added: %+v", frames[1])
	}
	if frames[2].event != "edge_added" || !strings.Contains(frames[2].data, `"spawns"`) {
		t.Fatalf("三帧应为 edge_added: %+v", frames[2])
	}
}

// TestCaseActivity 播报轮询兜底端点(0.23.0-live-feed):条目拍平(seq/tier/
// text)/since 游标过滤/无此案 404/空案 items=[]。
func TestCaseActivity(t *testing.T) {
	e := newTestEnv(t)
	fi := newFakeIntent()
	e.srv.deps.Intent = fi
	e.login(t)
	tid := e.uploadFile(t, "activity-case", "a.log", []byte(nginxContent), "")
	e.waitTask(t, tid)
	_, out := e.do(t, "GET", "/api/cases", nil)
	caseID := out["cases"].([]any)[0].(map[string]any)["id"].(string)

	// 空案:items=[] 不返回 null
	code, out := e.do(t, "GET", "/api/cases/"+caseID+"/activity", nil)
	if code != 200 {
		t.Fatalf("播报查询失败: %d %v", code, out)
	}
	if _, isArr := out["items"].([]any); !isArr {
		t.Fatalf("空案 items 应为 []: %v", out["items"])
	}

	// 无此案 404
	code, _ = e.do(t, "GET", "/api/cases/nope/activity", nil)
	if code != http.StatusNotFound {
		t.Fatalf("无此案应 404: %d", code)
	}

	// 喂帧:图帧不进(items 只含 feed),seq 拍平,since 过滤
	fi.activityItems = []intent.GraphChange{
		{Seq: 2, Kind: "feed", Feed: &intent.FeedItem{NodeID: "n1",
			Tier: intent.FeedSpawn, Text: "派生了新意图: 核查外联",
			TS: time.Now()}},
		{Seq: 4, Kind: "feed", Feed: &intent.FeedItem{NodeID: "n1",
			Tier: intent.FeedFinish, Status: intent.StatusSupported,
			Text: "发现可疑外联", TS: time.Now()}},
	}
	fi.activityLatest = 5
	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/activity", nil)
	if code != 200 {
		t.Fatalf("播报查询失败: %d %v", code, out)
	}
	items := out["items"].([]any)
	if len(items) != 2 || out["latest"].(float64) != 5 {
		t.Fatalf("应回 2 条 latest=5: %v", out)
	}
	first := items[0].(map[string]any)
	if first["seq"].(float64) != 2 || first["tier"] != intent.FeedSpawn ||
		first["node_id"] != "n1" {
		t.Fatalf("条目应拍平 seq/tier/node_id: %v", first)
	}
	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/activity?since=2", nil)
	items = out["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["seq"].(float64) != 4 {
		t.Fatalf("since=2 应只回 seq4: %v", items)
	}
}

// TestParkingEndpoints 停车场端点(0.24.0-convergence):空案 []/404/
// deploy/dismiss 人批流/已被处置 409/预算可观测/审批计数含停车场。
func TestParkingEndpoints(t *testing.T) {
	e := newTestEnv(t)
	fi := newFakeIntent()
	e.srv.deps.Intent = fi
	e.login(t)
	tid := e.uploadFile(t, "parking-case", "a.log", []byte(nginxContent), "")
	e.waitTask(t, tid)
	_, out := e.do(t, "GET", "/api/cases", nil)
	caseID := out["cases"].([]any)[0].(map[string]any)["id"].(string)

	// 空案 items=[] 不返回 null
	code, out := e.do(t, "GET", "/api/cases/"+caseID+"/parking", nil)
	if code != 200 {
		t.Fatalf("停车场查询失败: %d %v", code, out)
	}
	if _, isArr := out["items"].([]any); !isArr {
		t.Fatalf("空案 items 应为 []: %v", out["items"])
	}
	// 无此案 404
	code, _ = e.do(t, "GET", "/api/cases/nope/parking", nil)
	if code != http.StatusNotFound {
		t.Fatalf("无此案应 404: %d", code)
	}

	// 布景:两条停车场条目(闸下/AI 申请)+ 对应 parked 图节点
	fi.nodes["pn-1"] = &intent.Node{ID: "pn-1", CaseID: caseID, Kind: intent.KindIntent,
		Text: "闸下线索一", Status: intent.StatusParked, CreatedBy: intent.ByAI,
		Scope: intent.ScopeCase, CreatedAt: time.Now()}
	fi.nodes["pn-2"] = &intent.Node{ID: "pn-2", CaseID: caseID, Kind: intent.KindIntent,
		Text: "章外线索二", Status: intent.StatusParked, CreatedBy: intent.ByAI,
		Scope: intent.ScopeCase, CreatedAt: time.Now()}
	fi.parking = []*intent.ParkingEntry{
		{ID: "pk-1", CaseID: caseID, NodeID: "pn-1", Text: "闸下线索一",
			Reason: intent.ParkReasonFanout, SuggestGoalID: "g-1", SuggestLabel: "章一",
			Verdict: intent.VerdictDeploy, VerdictReason: "值得追",
			Status: intent.ParkingParked, CreatedBy: "ai", CreatedAt: time.Now()},
		{ID: "pk-2", CaseID: caseID, NodeID: "pn-2", Text: "章外线索二",
			Reason: intent.ParkReasonLead, SuggestLabel: "新开章:外泄追查",
			Status: intent.ParkingParked, CreatedBy: "ai", CreatedAt: time.Now()},
	}

	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/parking", nil)
	if code != 200 || len(out["items"].([]any)) != 2 {
		t.Fatalf("应回 2 条: %d %v", code, out)
	}
	first := out["items"].([]any)[0].(map[string]any)
	if first["reason"] != intent.ParkReasonFanout || first["verdict"] != intent.VerdictDeploy {
		t.Fatalf("条目字段缺失: %v", first)
	}

	// deploy:节点转 open,条目 deployed;二次 deploy 409
	code, out = e.do(t, "POST", "/api/parking/pk-1/deploy", nil)
	if code != 200 {
		t.Fatalf("deploy 失败: %d %v", code, out)
	}
	if out["node"].(map[string]any)["status"] != intent.StatusOpen {
		t.Fatalf("deploy 后节点应 open: %v", out["node"])
	}
	code, _ = e.do(t, "POST", "/api/parking/pk-1/deploy", nil)
	if code != http.StatusConflict {
		t.Fatalf("二次 deploy 应 409: %d", code)
	}
	// dismiss:留痕;无此条目 404
	code, out = e.do(t, "POST", "/api/parking/pk-2/dismiss", nil)
	if code != 200 || out["entry"].(map[string]any)["status"] != intent.ParkingDismissed {
		t.Fatalf("dismiss 失败: %d %v", code, out)
	}
	if fi.nodes["pn-2"].Status != intent.StatusClosed {
		t.Fatalf("dismiss 后节点应 closed: %s", fi.nodes["pn-2"].Status)
	}
	code, _ = e.do(t, "POST", "/api/parking/nope/dismiss", nil)
	if code != http.StatusNotFound {
		t.Fatalf("无此条目应 404: %d", code)
	}

	// 预算可观测:limits 默认 5/30/200;两条已处置后 parked=0
	code, out = e.do(t, "GET", "/api/cases/"+caseID+"/budget", nil)
	if code != 200 {
		t.Fatalf("预算查询失败: %d %v", code, out)
	}
	b := out["budget"].(map[string]any)
	lim := b["limits"].(map[string]any)
	if lim["fanout"].(float64) != 5 || lim["chapter"].(float64) != 30 ||
		lim["case"].(float64) != 200 {
		t.Fatalf("默认闸值不对: %v", lim)
	}
	if b["parked"].(float64) != 0 {
		t.Fatalf("处置完 parked 应 0: %v", b["parked"])
	}

	// 审批计数含停车场待处置(侧边栏徽标合并计数)
	e.meta.pendingParking = 3
	code, out = e.do(t, "GET", "/api/approvals", nil)
	if code != 200 || out["parked"].(float64) != 3 {
		t.Fatalf("审批面应带 parked 计数: %d %v", code, out)
	}
}

func readSSEFrames(t *testing.T, resp *http.Response, n int) []map[string]string {
	t.Helper()
	type frame = map[string]string
	frames := []frame{}
	buf := make([]byte, 4096)
	var acc string
	deadline := time.Now().Add(5 * time.Second)
	for len(frames) < n && time.Now().Before(deadline) {
		nn, rerr := resp.Body.Read(buf)
		if rerr != nil {
			t.Fatalf("SSE 读取失败: %v", rerr)
		}
		acc += string(buf[:nn])
		for {
			i := strings.Index(acc, "\n\n")
			if i < 0 {
				break
			}
			raw := acc[:i]
			acc = acc[i+2:]
			fr := frame{}
			for _, ln := range strings.Split(raw, "\n") {
				if strings.HasPrefix(ln, "id: ") {
					fr["id"] = strings.TrimPrefix(ln, "id: ")
				} else if strings.HasPrefix(ln, "event: ") {
					fr["event"] = strings.TrimPrefix(ln, "event: ")
				} else if strings.HasPrefix(ln, "data: ") {
					fr["data"] = strings.TrimPrefix(ln, "data: ")
				}
			}
			if fr["event"] != "" {
				frames = append(frames, fr)
			}
		}
	}
	if len(frames) < n {
		t.Fatalf("5s 内应收满 %d 帧,实得 %d: %v", n, len(frames), frames)
	}
	return frames
}

// TestIntentEventsSSECursor 断线游标(交互改造切片二):
// 游标可续 → 免快照只回放缺帧(带 id 行,续播帧去重);
// 游标不可续(过老/超前/首连)→ 快照兜底(id=基线序号)。
func TestIntentEventsSSECursor(t *testing.T) {
	e := newTestEnv(t)
	fi := newFakeIntent()
	e.srv.deps.Intent = fi
	e.login(t)
	tid := e.uploadFile(t, "sse-cursor-case", "a.log", []byte(nginxContent), "")
	e.waitTask(t, tid)
	_, out := e.do(t, "GET", "/api/cases", nil)
	caseID := out["cases"].([]any)[0].(map[string]any)["id"].(string)

	openSSE := func(lastID string) *http.Response {
		req, _ := http.NewRequest("GET", e.ts.URL+"/api/cases/"+caseID+"/intents/events", nil)
		req.Header.Set("Cookie", sessionCookie+"="+e.cookie)
		if lastID != "" {
			req.Header.Set("Last-Event-ID", lastID)
		}
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("SSE 请求失败: %v", err)
		}
		return resp
	}

	// 1) 游标可续:Last-Event-ID=41,replay 回 42/43 两帧 → 无 snapshot,
	//    先见回放帧(带 id),续播帧 Seq≤43 去重、>43 照推
	fi.replayOK = true
	fi.replayLatest = 43
	fi.replayMissed = []intent.GraphChange{
		{Seq: 42, Kind: "node_updated", Node: &intent.Node{ID: "n-a", CaseID: caseID,
			Kind: intent.KindIntent, Text: "缺帧一", Status: intent.StatusRunning,
			CreatedBy: intent.ByAI, Scope: intent.ScopeCase, CreatedAt: time.Now()}},
		{Seq: 43, Kind: "node_added", Node: &intent.Node{ID: "n-b", CaseID: caseID,
			Kind: intent.KindFact, Text: "缺帧二", Status: intent.StatusSupported,
			CreatedBy: intent.ByAI, Scope: intent.ScopeCase, CreatedAt: time.Now()}},
	}
	resp := openSSE("41")
	fi.graphCh <- intent.GraphChange{Seq: 43, Kind: "node_added", Node: &intent.Node{
		ID: "n-b", CaseID: caseID, Kind: intent.KindFact, Text: "缺帧二重复",
		Status: intent.StatusSupported, CreatedBy: intent.ByAI,
		Scope: intent.ScopeCase, CreatedAt: time.Now()}} // ≤基线,应去重
	fi.graphCh <- intent.GraphChange{Seq: 44, Kind: "node_updated", Node: &intent.Node{
		ID: "n-a", CaseID: caseID, Kind: intent.KindIntent, Text: "续播新帧",
		Status: intent.StatusSupported, CreatedBy: intent.ByAI,
		Scope: intent.ScopeCase, CreatedAt: time.Now()}}
	frames := readSSEFrames(t, resp, 3)
	resp.Body.Close()
	if frames[0]["event"] == "snapshot" {
		t.Fatalf("游标可续不应发快照: %v", frames[0])
	}
	if frames[0]["id"] != "42" || !strings.Contains(frames[0]["data"], "缺帧一") {
		t.Fatalf("首帧应为回放缺帧 42: %v", frames[0])
	}
	if frames[1]["id"] != "43" || frames[1]["event"] != "node_added" {
		t.Fatalf("次帧应为回放缺帧 43: %v", frames[1])
	}
	if frames[2]["id"] != "44" || !strings.Contains(frames[2]["data"], "续播新帧") {
		t.Fatalf("三帧应为续播新帧 44(43 重复帧应被去重): %v", frames)
	}

	// 2) 游标不可续(过老/超前)→ 快照兜底,id=基线序号
	fi.replayOK = false
	fi.replayLatest = 43
	fi.nodes["n1"] = &intent.Node{ID: "n1", CaseID: caseID, Kind: intent.KindGoal,
		Text: "目标", Status: intent.StatusOpen, CreatedBy: intent.ByRule,
		Scope: intent.ScopeCase, CreatedAt: time.Now()}
	resp = openSSE("7")
	frames = readSSEFrames(t, resp, 1)
	resp.Body.Close()
	if frames[0]["event"] != "snapshot" || frames[0]["id"] != "43" ||
		!strings.Contains(frames[0]["data"], `"n1"`) {
		t.Fatalf("游标失效应快照兜底且 id=基线: %v", frames[0])
	}
}

// TestCaseBlackboard 案件黑板端点契约(0.28.0):四段透传(与 worker 注入
// 同一份派生逻辑)、无此案 404、引擎失败 500、未装配 503(见
// TestIntentNotAssembled 清单)。
func TestCaseBlackboard(t *testing.T) {
	e := newTestEnv(t)
	fi := newFakeIntent()
	e.srv.deps.Intent = fi
	e.login(t)
	tid := e.uploadFile(t, "bb-case", "a.log", []byte(nginxContent), "")
	e.waitTask(t, tid)
	_, out := e.do(t, "GET", "/api/cases", nil)
	caseID := out["cases"].([]any)[0].(map[string]any)["id"].(string)

	fi.blackboard = &intent.Blackboard{
		CaseID: caseID,
		Facts: []intent.BlackboardFact{{NodeID: "f1", Text: "合成事实",
			Anchors: []intent.Anchor{{SourceID: "src-1", LineNo: 7}}}},
		FactsTotal:   1,
		Doubts:       []intent.BlackboardDoubt{{NodeID: "i2", Intent: "合成存疑意图", Summary: "缺数据"}},
		DoubtsTotal:  1,
		Intents:      []intent.BlackboardIntent{{NodeID: "i3", Text: "合成在查", Status: "running"}},
		IntentsTotal: 1,
		Parking:      []*intent.ParkingEntry{{ID: "p1", Text: "合成线索", Status: intent.ParkingParked}},
		ParkingTotal: 1,
	}
	code, out := e.do(t, "GET", "/api/cases/"+caseID+"/blackboard", nil)
	if code != 200 {
		t.Fatalf("黑板查询失败: %d %v", code, out)
	}
	bb := out["blackboard"].(map[string]any)
	if bb["case_id"] != caseID {
		t.Fatalf("case_id 应对: %v", bb["case_id"])
	}
	for _, key := range []string{"facts", "doubts", "intents", "parking"} {
		if len(bb[key].([]any)) != 1 {
			t.Fatalf("四段应各 1 条: %s=%v", key, bb[key])
		}
	}
	fact := bb["facts"].([]any)[0].(map[string]any)
	if fact["anchors"].([]any)[0].(map[string]any)["source_id"] != "src-1" {
		t.Fatalf("事实锚点应透传: %v", fact)
	}
	if bb["facts_total"].(float64) != 1 {
		t.Fatalf("total 字段应透传: %v", bb)
	}

	// 无此案 404;引擎失败 500
	code, _ = e.do(t, "GET", "/api/cases/nope/blackboard", nil)
	if code != http.StatusNotFound {
		t.Fatalf("无此案应 404: %d", code)
	}
	fi.blackboardErr = fmt.Errorf("合成:派生查询断")
	code, _ = e.do(t, "GET", "/api/cases/"+caseID+"/blackboard", nil)
	if code != http.StatusInternalServerError {
		t.Fatalf("派生失败应 500: %d", code)
	}
}
