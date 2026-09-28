// 单测 fake:内存版 intent.Store + 可编程 fake AIRunner(不烧真钱,
// 契约全在 mock 上验)。
package intent

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ---- fakeStore:内存意图图 ----

type fakeStore struct {
	mu          sync.Mutex
	seq         int
	nodes       map[string]*Node
	order       []string
	edges       []*Edge
	events      map[string][]*Event
	anchors     []anchorRec
	deadline    map[string]*time.Time
	archived    map[string]bool     // caseID → 已归档(0.18.0 归档闸测试注入)
	hosts       map[string][]string // caseID → 已建模主机键(切片七)
	constraints    []*Constraint // 操作约束(切片三)
	constraintsErr error         // 非 nil 时 ListConstraints 报错(fail-closed 测试)
	parking        []*ParkingEntry // 停车场条目(0.24.0)
	parkingErr     error           // 非 nil 时 ListParking 报错(黑板失败降级测试)
}

type anchorRec struct {
	nodeID, kind string
	anchor       Anchor
}

func newFakeStore() *fakeStore {
	return &fakeStore{nodes: map[string]*Node{}, events: map[string][]*Event{},
		deadline: map[string]*time.Time{}, archived: map[string]bool{},
		hosts: map[string][]string{}}
}

func (f *fakeStore) CreateNode(_ context.Context, n *Node) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	cp := *n
	cp.ID = fmt.Sprintf("node-%d", f.seq)
	cp.CreatedAt = time.Now()
	f.nodes[cp.ID] = &cp
	f.order = append(f.order, cp.ID)
	n.ID = cp.ID
	n.CreatedAt = cp.CreatedAt
	return nil
}

func (f *fakeStore) GetNode(_ context.Context, id string) (*Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.nodes[id]
	if !ok {
		return nil, nil
	}
	cp := *n
	return &cp, nil
}

func (f *fakeStore) ListNodes(_ context.Context, caseID string) ([]*Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*Node
	for _, id := range f.order {
		if f.nodes[id].CaseID == caseID {
			cp := *f.nodes[id]
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeStore) CreateEdge(_ context.Context, e *Edge) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, x := range f.edges {
		if x.FromID == e.FromID && x.ToID == e.ToID && x.Kind == e.Kind {
			return nil // 唯一约束幂等
		}
	}
	cp := *e
	f.seq++
	cp.ID = fmt.Sprintf("edge-%d", f.seq)
	cp.CreatedAt = time.Now()
	f.edges = append(f.edges, &cp)
	e.ID = cp.ID // 与 PG RETURNING 回写对齐(图变更广播以 id 判新)
	e.CreatedAt = cp.CreatedAt
	return nil
}

func (f *fakeStore) ListEdges(_ context.Context, caseID string) ([]*Edge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*Edge
	for _, e := range f.edges {
		if e.CaseID == caseID {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeStore) NextRunnable(_ context.Context, caseID string) (*Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range f.order {
		n := f.nodes[id]
		if n.CaseID == caseID && n.Kind == KindIntent && n.Status == StatusOpen {
			cp := *n
			return &cp, nil
		}
	}
	return nil, nil
}

func (f *fakeStore) MarkRunning(_ context.Context, id, sessionID string, at time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.nodes[id]
	if !ok || n.Status != StatusOpen {
		return false, nil
	}
	n.Status = StatusRunning
	n.SessionID = sessionID
	n.StartedAt = &at
	return true, nil
}

func (f *fakeStore) FinishNode(_ context.Context, id, status, resultText, closeNote string,
	evidence []Anchor, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.nodes[id]
	if !ok {
		return fmt.Errorf("无此节点: %s", id)
	}
	n.Status = status
	n.ResultText = resultText
	n.CloseNote = closeNote
	n.Evidence = evidence
	n.FinishedAt = &at
	return nil
}

// SetGoalStatus goal 收官重估(fake;与 PG 同口径:仅 open/closed_goal_*
// 的 goal 节点生效,at=nil 重开)。
func (f *fakeStore) SetGoalStatus(_ context.Context, id, status, closeNote string,
	at *time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.nodes[id]
	if !ok || n.Kind != KindGoal {
		return false, nil
	}
	if n.Status != StatusOpen && !isGoalClosedStatus(n.Status) {
		return false, nil
	}
	n.Status = status
	n.CloseNote = closeNote
	n.FinishedAt = at
	return true, nil
}

func (f *fakeStore) AddAnchors(_ context.Context, caseID, nodeID, kind string, anchors []Anchor) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range anchors {
		f.anchors = append(f.anchors, anchorRec{nodeID: nodeID, kind: kind, anchor: a})
	}
	return nil
}

func (f *fakeStore) AppendEvent(_ context.Context, caseID, nodeID, kind, text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events[nodeID] = append(f.events[nodeID], &Event{
		ID: int64(len(f.events[nodeID]) + 1), NodeID: nodeID, Kind: kind, Text: text})
	return nil
}

func (f *fakeStore) ListEvents(_ context.Context, nodeID string) ([]*Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.events[nodeID], nil
}

func (f *fakeStore) DecideApproval(_ context.Context, id string, approve bool, at time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.nodes[id]
	if !ok || n.Status != StatusAwaitingApproval {
		return false, nil
	}
	if approve {
		n.Status = StatusOpen
	} else {
		n.Status = StatusClosed
		n.CloseNote = "审批拒绝,不予执行"
		n.FinishedAt = &at
	}
	return true, nil
}

func (f *fakeStore) Coverage(_ context.Context, caseID string) ([]*SourceCoverage, error) {
	return []*SourceCoverage{}, nil
}

func (f *fakeStore) CaseDeadline(_ context.Context, caseID string) (*time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deadline[caseID], nil
}

// CaseArchived 归档闸(fake;测试经 f.archived 注入)。
func (f *fakeStore) CaseArchived(_ context.Context, caseID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.archived[caseID], nil
}

// ListHosts 已建模主机键(fake;测试经 f.hosts 注入)。
func (f *fakeStore) ListHosts(_ context.Context, caseID string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.hosts[caseID]))
	copy(out, f.hosts[caseID])
	return out, nil
}

func (f *fakeStore) SetCaseDeadline(_ context.Context, caseID string, at *time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deadline[caseID] = at
	return nil
}

// RecoverInFlight fake 无崩溃恢复语义(接口契约允许返回 nil)。
func (f *fakeStore) RecoverInFlight(context.Context) ([]string, error) { return nil, nil }

// ---- 停车场(0.24.0)----

func (f *fakeStore) CreateParking(_ context.Context, p *ParkingEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	cp := *p
	cp.ID = fmt.Sprintf("park-%d", f.seq)
	cp.CreatedAt = time.Now()
	if n, ok := f.nodes[cp.NodeID]; ok {
		cp.Text = n.Text
	}
	f.parking = append(f.parking, &cp)
	p.ID = cp.ID
	p.CreatedAt = cp.CreatedAt
	return nil
}

func (f *fakeStore) ListParking(_ context.Context, caseID string) ([]*ParkingEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.parkingErr != nil {
		return nil, f.parkingErr
	}
	out := []*ParkingEntry{}
	for _, p := range f.parking {
		if p.CaseID == caseID {
			cp := *p
			if n, ok := f.nodes[cp.NodeID]; ok {
				cp.Text = n.Text
			}
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeStore) GetParking(_ context.Context, id string) (*ParkingEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.parking {
		if p.ID == id {
			cp := *p
			if n, ok := f.nodes[cp.NodeID]; ok {
				cp.Text = n.Text
			}
			return &cp, nil
		}
	}
	return nil, nil
}

func (f *fakeStore) DecideParking(_ context.Context, id string, deploy bool,
	actor string, at time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.parking {
		if p.ID == id && p.Status == ParkingParked {
			if deploy {
				p.Status = ParkingDeployed
			} else {
				p.Status = ParkingDismissed
			}
			p.DecidedBy = actor
			p.DecidedAt = &at
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeStore) SetParkingVerdict(_ context.Context, id, verdict, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.parking {
		if p.ID == id && p.Status == ParkingParked {
			p.Verdict = verdict
			p.VerdictReason = reason
			return nil
		}
	}
	return fmt.Errorf("停车场条目不存在或已处置(评估建议不落): %s", id)
}

func (f *fakeStore) ParkedNodeDecision(_ context.Context, id string, deploy bool,
	closeNote, newParentID string, at time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.nodes[id]
	if !ok || n.Status != StatusParked {
		return false, nil
	}
	if deploy {
		n.Status = StatusOpen
		if newParentID != "" {
			n.ParentID = newParentID
		}
	} else {
		n.Status = StatusClosed
		n.CloseNote = closeNote
		n.FinishedAt = &at
	}
	return true, nil
}

// ---- 操作约束(切片三)----

func (f *fakeStore) ListConstraints(_ context.Context, caseID string) ([]*Constraint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.constraintsErr != nil {
		return nil, f.constraintsErr
	}
	out := []*Constraint{}
	for _, c := range f.constraints {
		if c.CaseID == caseID {
			cp := *c
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeStore) AddConstraint(_ context.Context, c *Constraint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	cp := *c
	cp.ID = fmt.Sprintf("constraint-%d", f.seq)
	cp.CreatedAt = time.Now()
	f.constraints = append(f.constraints, &cp)
	c.ID = cp.ID
	c.CreatedAt = cp.CreatedAt
	return nil
}

func (f *fakeStore) DeleteConstraint(_ context.Context, caseID, id string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, c := range f.constraints {
		if c.ID == id && c.CaseID == caseID {
			f.constraints = append(f.constraints[:i], f.constraints[i+1:]...)
			return true, nil
		}
	}
	return false, nil
}

// ---- fakeAI:可编程 AIRunner ----

type fakeAI struct {
	mu sync.Mutex

	// behavior: nil=默认(回 supported+锚点收尾契约);否则逐会话自定义
	runFn func(sessID, prompt, systemExtra string, abort <-chan string) []AIEvent

	sessions   []string // 建过的会话 id 序
	budgets    []int64
	hostScopes []string          // 会话主机范围(切片七;与 sessions 对齐)
	prompts    map[string]string // sessID → prompt
	extras     map[string]string // sessID → systemExtra
	aborts     map[string]string // sessID → abort actor
	cancels    []string          // 纠偏中断记录(切片三,按序)
	abortChans map[string]chan string
}

func newFakeAI() *fakeAI {
	return &fakeAI{prompts: map[string]string{}, extras: map[string]string{},
		aborts: map[string]string{}, abortChans: map[string]chan string{}}
}

func (f *fakeAI) CreateSessionBudget(_ context.Context, caseID, actor string,
	budget int64, hostScope string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := fmt.Sprintf("sess-%d", len(f.sessions)+1)
	f.sessions = append(f.sessions, id)
	f.budgets = append(f.budgets, budget)
	f.hostScopes = append(f.hostScopes, hostScope)
	f.abortChans[id] = make(chan string, 1)
	return id, nil
}

func (f *fakeAI) RunWithSystem(_ context.Context, sessionID, prompt,
	systemExtra string) (<-chan AIEvent, error) {
	f.mu.Lock()
	f.prompts[sessionID] = prompt
	f.extras[sessionID] = systemExtra
	runFn := f.runFn
	abortCh := f.abortChans[sessionID]
	f.mu.Unlock()
	out := make(chan AIEvent, 16)
	go func() {
		defer close(out)
		var evs []AIEvent
		if runFn != nil {
			evs = runFn(sessionID, prompt, systemExtra, abortCh)
		} else {
			evs = []AIEvent{{Kind: "text", Text: defaultVerdictText}}
		}
		for _, ev := range evs {
			out <- ev
		}
	}()
	return out, nil
}

func (f *fakeAI) Abort(_ context.Context, id, actor string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.aborts[id] = actor
	if ch, ok := f.abortChans[id]; ok {
		select {
		case ch <- actor:
		default:
		}
	}
	return nil
}

// Cancel 纠偏中断(切片三):同 Abort 发信号让当前轮收尾,但不动会话账
// (fake 无账,记 cancels 供断言)。
func (f *fakeAI) Cancel(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancels = append(f.cancels, id)
	if ch, ok := f.abortChans[id]; ok {
		select {
		case ch <- "steer":
		default:
		}
	}
	return nil
}

// defaultVerdictText 默认收尾契约(supported + 1 锚点 + 1 子意图)。
const defaultVerdictText = "查完了。\n```json\n" +
	`{"verdict":"supported","summary":"疑似有异常迹象(锚点见附件)",` +
	`"anchors":[{"source_id":"src-1","line_no":42,"note":"命中行"}],` +
	`"children":["接着查来源 IP 的横向痕迹"]}` + "\n```"

// blockUntilAbort 行为:发一个 text 后阻塞到 Abort 再收尾(预算/停止实测用)。
func blockUntilAbort(text string) func(string, string, string, <-chan string) []AIEvent {
	return func(_ string, _, _ string, abort <-chan string) []AIEvent {
		<-abort
		return []AIEvent{{Kind: "text", Text: text},
			{Kind: "result", Reason: "aborted_tools"}}
	}
}

// ---- fakeAudit ----

type fakeAudit struct {
	mu      sync.Mutex
	actions []string
}

func (f *fakeAudit) AppendAudit(_ context.Context, caseID, actor, action, scope string,
	detail any) (int64, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actions = append(f.actions, action)
	return int64(len(f.actions)), "", nil
}

func (f *fakeAudit) has(action string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.actions {
		if a == action {
			return true
		}
	}
	return false
}

// ---- 测试用具 ----

// testEngine 装配(fake store/AI/audit;debounce 缩到 2ms)。
func testEngine(tplMap map[string]*Template) (*Engine, *fakeStore, *fakeAI, *fakeAudit) {
	fs := newFakeStore()
	fa := newFakeAI()
	fau := &fakeAudit{}
	eng := NewEngine(Deps{
		Store: fs, AI: fa, Audit: fau, Templates: tplMap,
		Debounce: 2 * time.Millisecond,
	})
	return eng, fs, fa, fau
}

// waitFor 轮询条件(引擎异步;3s 超时如实失败)。
func waitFor(cond func() bool, what string) error {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fmt.Errorf("等待超时: %s", what)
}

// twoLevelTpl 合成模板(根 a → 子 b;另根 c scope=all 验审批门)。
var twoLevelTpl = &Template{
	ID: "t-two", Goal: "合成目标",
	Intents: []TemplateIntent{
		{Key: "a", Text: "根意图 A"},
		{Key: "b", Text: "子意图 B", After: []string{"a"}},
		{Key: "c", Text: "批量意图 C", Scope: ScopeAll},
	},
}
