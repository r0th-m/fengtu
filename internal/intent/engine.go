// planner/worker 引擎(§6.4 ARTEX 骨架的防守侧改造):
//
//   - planner 是唯一意图派发者:事件驱动(图变更 → Wake → debounce → 读
//     意图图态势 → 派发),没有未覆盖方向则不派(如实静默,不硬造);
//   - worker 领一条意图:单意图单 norma 会话(切片五六个只读工具,system
//     prompt 带意图上下文)→ 执行留痕(intent_events 过程流)→ 系统按
//     证据结构评估(supported/denied/doubt,§6.2)→ 写回 fact(finding
//     走 run_operator 既有 pending 待审通路)→ 派生子意图(深度 ≤5);
//   - 四层预算:意图级 wall-clock(耗尽 → 停查→写回已得→closed_exhausted
//     如实)+ 案件级 deadline(到点 planner 停派,收尾模式)+ 会话级 token
//     (agentloop 熔断复用)+ 厂商级 max_tokens(设置层,先用着);
//   - 审批门:scope=all 且非人提出的意图挂 awaiting_approval,人批才放行;
//     批准/拒绝/手动停止全进审计哈希链。
package intent

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// AIEvent worker 消费的 AI 会话事件(壳事件的最小投影——intent 包不 import
// agentloop/store,防循环依赖;适配器在 web 层,见 aiRunnerAdapter)。
type AIEvent struct {
	Kind       string // text|thinking|tool_use|tool_result|usage|result|budget_exceeded|error
	Text       string
	ToolName   string
	ToolInput  string
	ToolOutput string
	Reason     string
	ErrText    string
}

// AIRunner worker 需要的 AI 会话面(agentloop.Service 经 web 层适配器实现;
// 单测 fake)。
type AIRunner interface {
	// CreateSessionBudget 单意图单会话(预算=会话级 token 层);返回会话 id。
	// hostScope 非空 = 意图主机范围:会话绑定主机,只读工具层强制限定
	// 在该主机的源集合(系统闸,不靠模型自觉)。
	CreateSessionBudget(ctx context.Context, caseID, actor string, budgetTokens int64,
		hostScope string) (string, error)
	// RunWithSystem 带意图上下文(附加 system 段)跑一轮;事件流到完即终态。
	RunWithSystem(ctx context.Context, sessionID, prompt, systemExtra string) (<-chan AIEvent, error)
	// Abort 中断正在跑的会话(预算耗尽/人工停止共用;账上标 aborted 终态)。
	Abort(ctx context.Context, id, actor string) error
	// Cancel 取消正在跑的 loop 但不动会话账(交互改造切片三 steer 纠偏语义:
	// 会话保持 active 可续跑,transcript 延续;没在跑即无操作,幂等)。
	Cancel(ctx context.Context, id string) error
}

// AuditAppender 审计链追加面(store.PG 实现)。
type AuditAppender interface {
	AppendAudit(ctx context.Context, caseID, actor, action, scope string, detail any) (int64, string, error)
}

// KBHeuristic 启发式知识库条目的最小投影(kb.Entry 的字段子集——intent 包
// 不 import kb,防层间耦合;适配由 web 层/调用方做)。
type KBHeuristic struct {
	Title     string
	Content   string
	AppliesTo []string
}

// KBProvider worker system 启发式参考段的数据面(kb.Service 实现;单测 fake)。
// 0.20.0-case-kb:注入 = 本案勾选 ∩ 全局启用(不再全量全局注入,省 token);
// 本案零勾选(含存量案件)如实给空集,不兜底全量。返回已截断的条目集与
// 被截掉的条数(注入段如实标注)。
type KBProvider interface {
	Heuristics(ctx context.Context, caseID string) (entries []KBHeuristic, truncated int, err error)
}

// Deps 引擎依赖(全部接口化,单测 fake 打全链)。
type Deps struct {
	Store    Store
	AI       AIRunner
	Audit    AuditAppender
	Templates map[string]*Template // playbook 模板(id → 模板;数据不是代码)
	Now       func() time.Time     // nil → time.Now
	// BudgetSeconds 意图级 wall-clock 默认(节点/模板未自带时;<0 用默认)。
	BudgetSeconds int
	// TokenBudget worker 会话 token 预算(会话级;≤0 用默认)。
	TokenBudget int64
	// Debounce planner 唤醒去抖(≤0 用默认 250ms;测试可缩)。
	Debounce time.Duration
	// ConcurrencyLimit worker 全局并发上限(切片十一;nil → DefaultConcurrency)。
	// 每次派发现读:平台设置 ai_settings.agent_concurrency 改动对之后的
	// 派发即时生效,不追回在跑 worker(与 ARTEX 同口径,如实)。
	ConcurrencyLimit func() int
	// BudgetLimits 分支预算三闸(0.24.0-convergence;nil → 默认 5/30/200)。
	// 每次派生现读:平台设置改动对之后的派生即时生效;只闸自动派生,
	// 人工手写意图/线索不受限(判断权归人)。
	BudgetLimits func() BudgetLimits
	// KB 启发式知识库面(0.19.0:worker system 注入「启发式参考」段;
	// nil = 不注入,如实缺省)。
	KB KBProvider
}

// Engine 意图链引擎(planner 循环 + worker 池,每案件串行派发)。
type Engine struct {
	deps Deps
	hub  *graphHub // 图变更广播(切片 8b SSE 增量)

	wake chan string

	mu             sync.Mutex
	processing     map[string]bool             // caseID → planner 在跑(重入只补唤醒)
	running        map[string]*runHandle       // nodeID → 执行柄(stop/预算共用)
	deadlineNoted  map[string]bool             // caseID → 收尾模式已审计(不刷屏)
	slots          *workerSlots                // worker 全局并发闸(切片十一)
	limitFn        func() int                  // 并发上限现读(Deps.ConcurrencyLimit 兜底默认)
	cancel         context.CancelFunc
	done           chan struct{}
}

// runHandle 运行中意图的中断柄(reason 先写后 Abort,worker 据此定终态)。
type runHandle struct {
	caseID    string
	sessionID string

	mu     sync.Mutex
	reason string   // ""|budget|user|steer(先写 reason 再 Abort/Cancel,读在流收尾后)
	steers []string // 人工纠偏队列(steer;同轮多条按序拼接成一条 user 消息)
	sealed bool     // 写回封口:封口后新纠偏如实拒(不丢消息装收到)
}

func (h *runHandle) setReason(r string) {
	h.mu.Lock()
	h.reason = r
	h.mu.Unlock()
}

func (h *runHandle) getReason() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.reason
}

// takeSteerOrSeal 一轮结束时的纠偏结算:有待纠偏且未被预算/人工停抢闸 →
// 取出拼接文本续跑;否则封口(此后 Steer 一律如实拒,不丢消息装收到)。
func (h *runHandle) takeSteerOrSeal() (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.reason == "budget" || h.reason == "user" {
		h.sealed = true
		h.steers = nil // 中断理由优先:预算/人工停抢闸,纠偏如实丢弃(不续跑)
		return "", false
	}
	if len(h.steers) > 0 {
		s := strings.Join(h.steers, "\n")
		h.steers = nil
		h.reason = "" // 纠偏已消费,下一轮回正常终态判定
		return s, true
	}
	h.sealed = true
	return "", false
}

// NewEngine 构造。
func NewEngine(d Deps) *Engine {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.BudgetSeconds <= 0 {
		d.BudgetSeconds = DefaultBudgetSeconds
	}
	if d.TokenBudget <= 0 {
		d.TokenBudget = DefaultTokenBudget
	}
	if d.Debounce <= 0 {
		d.Debounce = 250 * time.Millisecond
	}
	limitFn := d.ConcurrencyLimit
	if limitFn == nil {
		limitFn = func() int { return DefaultConcurrency }
	}
	return &Engine{
		deps: d, hub: newGraphHub(), wake: make(chan string, 256),
		processing: map[string]bool{}, running: map[string]*runHandle{},
		deadlineNoted: map[string]bool{}, done: make(chan struct{}),
		slots: newWorkerSlots(), limitFn: limitFn,
	}
}

// Start 起 planner 循环(事件驱动;ctx 取消即停)。
func (e *Engine) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	// 崩溃恢复(2026-09-23 实战:server 进程被杀后 open 意图无人派发、
	// running 成死节点):重置中断节点并唤醒所有仍有 open 意图的案件。
	if cases, err := e.deps.Store.RecoverInFlight(ctx); err != nil {
		// 恢复失败如实记事件流不可得(全局面),拒启动不至于——记审计即可
		_, _, _ = e.deps.Audit.AppendAudit(ctx, "", "system",
			"intent.recover_failed", "", map[string]any{"err": err.Error()})
	} else {
		for _, id := range cases {
			e.Wake(id)
		}
	}
	go func() {
		defer close(e.done)
		for {
			select {
			case <-ctx.Done():
				return
			case caseID := <-e.wake:
				// debounce:合并密集唤醒(图变更风暴不炸队列)
				t := time.NewTimer(e.deps.Debounce)
				select {
				case <-ctx.Done():
					t.Stop()
					return
				case <-t.C:
				}
				go e.processCase(context.Background(), caseID)
			}
		}
	}()
}

// Close 停 planner(等循环退出;运行中 worker 各自有预算兜底)。
func (e *Engine) Close() {
	if e.cancel != nil {
		e.cancel()
		<-e.done
	}
}

// Wake 图变更唤醒 planner(非阻塞;队列满如实丢——处理循环退出前会复查)。
func (e *Engine) Wake(caseID string) {
	select {
	case e.wake <- caseID:
	default:
	}
}

// ---- planner:读态势 → 派发(没有未覆盖方向则不派) ----

func (e *Engine) processCase(ctx context.Context, caseID string) {
	e.mu.Lock()
	if e.processing[caseID] {
		e.mu.Unlock()
		return // 已在跑:新唤醒的工作会被它的 NextRunnable 循环拾取
	}
	e.processing[caseID] = true
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		delete(e.processing, caseID)
		e.mu.Unlock()
		// 退出前复查:处理间隙播种的意图不丢(唤醒丢了也能续上)
		if n, err := e.deps.Store.NextRunnable(ctx, caseID); err == nil && n != nil {
			e.Wake(caseID)
		}
	}()

	for {
		// 归档闸(0.18.0):归档案停派新意图——在跑的 worker 各自有预算
		// 兜底如实跑完,这里只管不再领新的(与 deadline 收尾模式同形态,
		// 不刷屏审计:归档/解归档动作本身已在 web 层落 case.archive 账)。
		arch, aerr := e.deps.Store.CaseArchived(ctx, caseID)
		if aerr == nil && arch {
			return
		}
		// 案件级 deadline:到点进收尾模式——停派新意图(运行中的已同步
		// 跑完,这里只管不再领新的),审计一次不刷屏
		dl, err := e.deps.Store.CaseDeadline(ctx, caseID)
		if err == nil && dl != nil && !e.deps.Now().Before(*dl) {
			e.mu.Lock()
			noted := e.deadlineNoted[caseID]
			e.deadlineNoted[caseID] = true
			e.mu.Unlock()
			if !noted {
				_, _, _ = e.deps.Audit.AppendAudit(ctx, caseID, "planner",
					"intent.case_deadline", caseID, map[string]any{
						"deadline_at": dl.UTC().Format(time.RFC3339),
						"note":        "案件 deadline 到点,进入收尾模式:planner 停派新意图",
					})
			}
			return
		}
		node, err := e.deps.Store.NextRunnable(ctx, caseID)
		if err != nil || node == nil {
			return // 没有未覆盖方向:如实静默(§6.4 只在没有新方向时闭嘴)
		}
		// worker 全局并发闸(切片十一):超上限排队等位——等位期间过程流
		// 如实记「排队中(并发上限 N)」(等位时就可见,不是排到才补记);
		// 槽位空出(在跑 worker 收尾/被停)即补位。
		release, _, ok := e.slots.acquire(ctx, e.limitFn, func(limit int) {
			_ = e.deps.Store.AppendEvent(context.Background(), caseID, node.ID,
				"queue", fmt.Sprintf("排队中(并发上限 %d):等待空位后自动开工", limit))
		})
		if !ok {
			return // 引擎关闭途中:如实不领,意图留 open 待下次唤醒
		}
		e.runWorker(ctx, node) // 串行派发:审计耗时配对精确,预算语义干净
		release()
		// 让一刀:释放后若有等位者(其他案件排队中),让出调度让等位方先抢
		// 空槽——本案件的链路节点不霸占刚释放的槽(非严格 FIFO,如实)。
		runtime.Gosched()
	}
}

// ---- 播种(三源:模板/规则/人;AI 派生在 worker 写回路径) ----

// SeedTemplate 模板实例化:goal + 根意图(幂等:同案同模板只种一次)。
func (e *Engine) SeedTemplate(ctx context.Context, caseID, templateID, actor string) (*Node, int, error) {
	tpl, ok := e.deps.Templates[templateID]
	if !ok {
		return nil, 0, fmt.Errorf("未知 playbook 模板: %q(可选见 GET /api/playbooks)", templateID)
	}
	nodes, err := e.deps.Store.ListNodes(ctx, caseID)
	if err != nil {
		return nil, 0, err
	}
	for _, n := range nodes {
		if n.Kind == KindGoal && n.TemplateID == templateID {
			return n, 0, nil // 幂等:已实例化过
		}
	}
	goal := &Node{CaseID: caseID, Kind: KindGoal, Text: tpl.Goal,
		Status: StatusOpen, CreatedBy: ByRule, TemplateID: templateID,
		Scope: ScopeCase, BudgetSeconds: e.deps.BudgetSeconds}
	if err := ValidateNode(goal); err != nil {
		return nil, 0, err
	}
	if err := e.deps.Store.CreateNode(ctx, goal); err != nil {
		return nil, 0, err
	}
	e.emitNodeAdded(goal)
	roots := 0
	for _, ti := range tpl.Roots() {
		if _, err := e.spawnTemplateIntent(ctx, goal, tpl, ti, 1); err != nil {
			return goal, roots, err
		}
		roots++
	}
	_, _, _ = e.deps.Audit.AppendAudit(ctx, caseID, actor, "intent.seed_template",
		goal.ID, map[string]any{"template": templateID, "roots": roots})
	e.Wake(caseID)
	return goal, roots, nil
}

// spawnTemplateIntent 模板意图 → 节点(审批门按 GateStatus;回边 spawns)。
// host_scope=each 时按案件已建模主机逐台展开(template_key 带 @主机后缀,
// 幂等去重键不变形);主机键为空集的 each 如实不派(无主机可限定,
// 不悄悄退化成全案件)。
func (e *Engine) spawnTemplateIntent(ctx context.Context, parent *Node,
	tpl *Template, ti *TemplateIntent, depth int) (*Node, error) {

	if ti.HostScope == "each" {
		hosts, err := e.deps.Store.ListHosts(ctx, parent.CaseID)
		if err != nil {
			return nil, err
		}
		var first *Node
		for _, h := range hosts {
			cp := *ti
			cp.HostScope = h
			cp.Key = ti.Key + "@" + h
			n, err := e.spawnTemplateIntent(ctx, parent, tpl, &cp, depth)
			if err != nil {
				return first, err
			}
			if first == nil {
				first = n
			}
		}
		return first, nil // 零主机:如实不派(调用方计数为 0)
	}

	if depth > MaxDepth {
		return nil, nil // 深度闸:如实不派(模板校验已拦,这里是运行时兜底)
	}
	budget := ti.BudgetSeconds
	if budget <= 0 {
		budget = e.deps.BudgetSeconds
	}
	scope := ti.Scope
	if scope == "" {
		scope = ScopeCase
	}
	hostScope := ti.HostScope
	if hostScope == "all" {
		hostScope = "" // all ≡ 全案件(NULL 语义,§3 修正稿)
	}
	n := &Node{CaseID: parent.CaseID, Kind: KindIntent, Text: ti.Text,
		CreatedBy: ByRule, TemplateID: tpl.ID, TemplateKey: ti.Key,
		Scope: scope, HostScope: hostScope, ParentID: parent.ID, Depth: depth,
		BudgetSeconds: budget}
	n.Status = GateStatus(n.CreatedBy, n.Scope)
	if err := ValidateNode(n); err != nil {
		return nil, err
	}
	if err := e.deps.Store.CreateNode(ctx, n); err != nil {
		return nil, err
	}
	e.emitNodeAdded(n)
	ed := &Edge{CaseID: parent.CaseID, FromID: parent.ID, ToID: n.ID, Kind: EdgeSpawns}
	if err := e.deps.Store.CreateEdge(ctx, ed); err != nil {
		return nil, err
	}
	e.emitEdgeAdded(ed)
	return n, nil
}

// SeedRules 规则扫描候选自动派生意图(三源播种之一;同案同规则未终态去重)。
// 返回新派生条数;有 goal 则挂 goal 下(spawns 边)。
func (e *Engine) SeedRules(ctx context.Context, caseID, actor string, seeds []RuleSeed) (int, error) {
	nodes, err := e.deps.Store.ListNodes(ctx, caseID)
	if err != nil {
		return 0, err
	}
	var goalID string
	openRules := map[string]bool{}
	for _, n := range nodes {
		if n.Kind == KindGoal && goalID == "" {
			goalID = n.ID
		}
		if n.RuleID != "" && (n.Status == StatusOpen ||
			n.Status == StatusAwaitingApproval || n.Status == StatusRunning) {
			openRules[n.RuleID] = true
		}
	}
	created := 0
	for _, s := range seeds {
		if s.RuleID == "" || s.HitsNew <= 0 || openRules[s.RuleID] {
			continue // 零新增不派;同规则有未终态意图不重复派(幂等)
		}
		n := &Node{CaseID: caseID, Kind: KindIntent,
			Text: fmt.Sprintf("核实规则/算子 %s(%s)的 %d 条新增候选:逐条看锚点,"+
				"判断是真实迹象还是噪音;命中≠结论,候选仍在待审区等人裁决",
				s.RuleID, s.Title, s.HitsNew),
			CreatedBy: ByRule, RuleID: s.RuleID, Scope: ScopeCase,
			ParentID: goalID, Depth: 1, BudgetSeconds: e.deps.BudgetSeconds}
		n.Status = GateStatus(n.CreatedBy, n.Scope)
		if err := ValidateNode(n); err != nil {
			return created, err
		}
		if err := e.deps.Store.CreateNode(ctx, n); err != nil {
			return created, err
		}
		e.emitNodeAdded(n)
		if goalID != "" {
			ed := &Edge{CaseID: caseID, FromID: goalID, ToID: n.ID, Kind: EdgeSpawns}
			if err := e.deps.Store.CreateEdge(ctx, ed); err != nil {
				return created, err
			}
			e.emitEdgeAdded(ed)
		}
		openRules[s.RuleID] = true
		created++
	}
	if created > 0 {
		_, _, _ = e.deps.Audit.AppendAudit(ctx, caseID, actor, "intent.seed_rules",
			caseID, map[string]any{"created": created})
		e.Wake(caseID)
	}
	return created, nil
}

// CreateHuman 人手写意图(三源播种之一;人提出的自由执行,永不过审批门)。
// hostScope 空=全案件;具体主机键=worker 执行限定该主机(会话级强制)。
func (e *Engine) CreateHuman(ctx context.Context, caseID, actor, text, scope string,
	budgetSeconds int, parentID, hostScope string) (*Node, error) {

	text = strings.TrimSpace(text)
	if text == "" {
		return nil, fmt.Errorf("意图文本必填")
	}
	if utf8.RuneCountInString(text) > 500 {
		return nil, fmt.Errorf("意图文本过长(≤500 字)")
	}
	if scope == "" {
		scope = ScopeCase
	}
	depth := 1
	if parentID != "" {
		p, err := e.deps.Store.GetNode(ctx, parentID)
		if err != nil {
			return nil, err
		}
		if p == nil || p.CaseID != caseID {
			return nil, fmt.Errorf("父意图不存在(或不属本案件): %s", parentID)
		}
		depth = p.Depth + 1
		if depth > MaxDepth {
			return nil, fmt.Errorf("派生深度超上限(≤%d),不再展开", MaxDepth)
		}
	}
	n := &Node{CaseID: caseID, Kind: KindIntent, Text: text,
		CreatedBy: ByHuman, Scope: scope, HostScope: hostScope,
		ParentID: parentID, Depth: depth,
		BudgetSeconds: budgetSeconds, Status: StatusOpen}
	if err := ValidateNode(n); err != nil {
		return nil, err
	}
	if err := e.deps.Store.CreateNode(ctx, n); err != nil {
		return nil, err
	}
	e.emitNodeAdded(n)
	if parentID != "" {
		ed := &Edge{CaseID: caseID, FromID: parentID, ToID: n.ID, Kind: EdgeDerivedFrom}
		if err := e.deps.Store.CreateEdge(ctx, ed); err != nil {
			return nil, err
		}
		e.emitEdgeAdded(ed)
	}
	_, _, _ = e.deps.Audit.AppendAudit(ctx, caseID, actor, "intent.create",
		n.ID, map[string]any{"text": text, "scope": scope, "parent": parentID,
			"host_scope": hostScope})
	e.Wake(caseID)
	return n, nil
}

// SeedGoals 应急目的预设落 goal 节点(交互改造·新建任务向导,设计依据
// fengtu-interaction-design.md §1:目的=预设复选+自由补充,落库即多条
// goal 节点,预设优先,LLM 拆解降级为可选增强)。
//
// 纪律:
//   - 幂等:同案同文本 goal 不重复种(种子去重键=文本);空/全空白文本跳过;
//   - 人提出的目的 → CreatedBy=ByHuman(向导是人点的);
//   - **只落 goal,不 Wake**:goal 不可派发(NextRunnable 只领 intent),
//     播种本身零 AI 消耗;后续一键分析/手写意图来了,规则种子与模板根
//     意图自动挂到既有 goal 下(SeedRules 取首 goal 为锚)。
func (e *Engine) SeedGoals(ctx context.Context, caseID, actor string, texts []string) (int, error) {
	nodes, err := e.deps.Store.ListNodes(ctx, caseID)
	if err != nil {
		return 0, err
	}
	existing := map[string]bool{}
	for _, n := range nodes {
		if n.Kind == KindGoal {
			existing[n.Text] = true
		}
	}
	created := 0
	seen := map[string]bool{} // 本次入参内去重
	for _, t := range texts {
		t = strings.TrimSpace(t)
		if t == "" || existing[t] || seen[t] {
			continue
		}
		seen[t] = true
		goal := &Node{CaseID: caseID, Kind: KindGoal, Text: t,
			Status: StatusOpen, CreatedBy: ByHuman, Scope: ScopeCase,
			BudgetSeconds: e.deps.BudgetSeconds}
		if err := ValidateNode(goal); err != nil {
			return created, err
		}
		if err := e.deps.Store.CreateNode(ctx, goal); err != nil {
			return created, err
		}
		e.emitNodeAdded(goal)
		existing[goal.Text] = true
		created++
	}
	if created > 0 {
		_, _, _ = e.deps.Audit.AppendAudit(ctx, caseID, actor, "intent.seed_goals",
			caseID, map[string]any{"created": created, "source": "newcase_wizard"})
	}
	return created, nil
}

// ---- 审批门 ----

// Approve 批准/拒绝挂起意图(仅 awaiting_approval;进审计;批准即唤醒)。
func (e *Engine) Approve(ctx context.Context, nodeID, actor string, approve bool) (*Node, error) {
	n, err := e.deps.Store.GetNode(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	if n == nil {
		return nil, fmt.Errorf("无此意图: %s", nodeID)
	}
	if n.Status != StatusAwaitingApproval {
		return nil, fmt.Errorf("意图不在待批状态(当前 %s),无需审批", n.Status)
	}
	ok, err := e.deps.Store.DecideApproval(ctx, nodeID, approve, e.deps.Now().UTC())
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("意图已被处理(并发审批),当前状态以库为准")
	}
	action := "intent.approve"
	if !approve {
		action = "intent.reject"
	}
	_, _, _ = e.deps.Audit.AppendAudit(ctx, n.CaseID, actor, action, nodeID,
		map[string]any{"text": n.Text, "scope": n.Scope, "created_by": n.CreatedBy})
	// 播报·审批事件档(批准放行/驳回;「待审批」诞生时已在 emitFeedSpawn 落)
	if approve {
		e.emitFeedApproval(n.CaseID, nodeID, "审批通过,放行执行: "+n.Text, StatusOpen)
	} else {
		e.emitFeedApproval(n.CaseID, nodeID, "审批驳回,意图关闭: "+n.Text, StatusClosed)
	}
	if approve {
		e.Wake(n.CaseID)
	} else {
		// 驳回=终态:章可能因此收官,触发停车场收官评估(0.24.0;
		// 章未收官/无待评估条目如实零调用)
		e.maybeEvalChapter(ctx, n, nil)
		e.reevalGoalsQuiet(ctx, n.CaseID, nil) // goal 收官重估(0.29.1,幂等)
	}
	fresh, gerr := e.deps.Store.GetNode(ctx, nodeID)
	if gerr == nil && fresh != nil {
		e.hub.publish(n.CaseID, GraphChange{Kind: "node_updated", Node: fresh})
	}
	return fresh, gerr
}

// Stop 人工终止意图(kill;进审计哈希链):
//   - running → Abort,worker 写回已得后关(close_note「人工停止」);
//   - open(未派发)→ 直接关闭,零 AI 消耗(设计 §3 kill_work:终止意图,
//     不限于在跑);与 planner 认领竞态由 MarkRunning 的 open 门兜底
//     (先关者赢,认领失败如实不跑);
//   - 其他状态(待批走审批拒绝/已终态)→ 如实报错。
func (e *Engine) Stop(ctx context.Context, nodeID, actor string) error {
	n, err := e.deps.Store.GetNode(ctx, nodeID)
	if err != nil {
		return err
	}
	if n == nil {
		return fmt.Errorf("无此意图: %s", nodeID)
	}
	if n.Status == StatusOpen && n.Kind == KindIntent {
		if err := e.deps.Store.FinishNode(ctx, nodeID, StatusClosed, "",
			"人工终止(未派发即关闭,未消耗 AI)", nil, e.deps.Now().UTC()); err != nil {
			return err
		}
		_, _, _ = e.deps.Audit.AppendAudit(ctx, n.CaseID, actor, "intent.stop",
			nodeID, map[string]any{"text": n.Text, "was": "open"})
		e.emitNodeUpdated(ctx, nodeID)
		e.emitFeedFinish(n.CaseID, nodeID, StatusClosed, "",
			"人工终止(未派发即关闭,未消耗 AI)") // 播报·终结档
		// open→closed 是终态:章可能因此收官,触发停车场收官评估(0.24.0)
		e.maybeEvalChapter(ctx, n, nil)
		e.reevalGoalsQuiet(ctx, n.CaseID, nil) // goal 收官重估(0.29.1,幂等)
		return nil
	}
	e.mu.Lock()
	h, running := e.running[nodeID]
	if running {
		h.setReason("user")
	}
	e.mu.Unlock()
	if !running {
		return fmt.Errorf("意图不在运行中(当前 %s),无法停止", n.Status)
	}
	if err := e.deps.AI.Abort(ctx, h.sessionID, "stop:"+actor); err != nil {
		return fmt.Errorf("停止失败: %w", err)
	}
	e.slots.poke() // 唤醒等位队列重估(该 worker 的槽在写回后释放;poke 只加速不抢跑)
	_, _, _ = e.deps.Audit.AppendAudit(ctx, n.CaseID, actor, "intent.stop",
		nodeID, map[string]any{"text": n.Text})
	return nil
}

// Steer 人工纠偏(交互改造切片三,设计 §3 steer_work 照抄:对在跑意图发人工
// 消息,人在环路的低成本入口)。语义:中断当前轮(不动会话账,与 Abort 的
// 终态语义不同),同一 AI 会话续跑(transcript 延续),纠偏文本作为新的
// user 消息;wall-clock 预算不因此延长(计时器不重置)。
// 只对在跑意图;已结束/未派发的请补线索(AddHint)或手写新意图。
func (e *Engine) Steer(ctx context.Context, nodeID, actor, text string) error {
	text = strings.TrimSpace(text)
	if text == "" {
		return fmt.Errorf("纠偏内容必填")
	}
	if utf8.RuneCountInString(text) > 500 {
		return fmt.Errorf("纠偏内容过长(≤500 字)")
	}
	n, err := e.deps.Store.GetNode(ctx, nodeID)
	if err != nil {
		return err
	}
	if n == nil {
		return fmt.Errorf("无此意图: %s", nodeID)
	}
	e.mu.Lock()
	h, running := e.running[nodeID]
	e.mu.Unlock()
	if !running {
		return fmt.Errorf("意图不在运行中(当前 %s),纠偏只对在跑意图;"+
			"已结束的请补线索或手写新意图", n.Status)
	}
	h.mu.Lock()
	if h.sealed || h.reason == "budget" || h.reason == "user" {
		h.mu.Unlock()
		return fmt.Errorf("意图正在收尾,本次纠偏未赶上(可补线索或手写新意图)")
	}
	h.steers = append(h.steers, text)
	if h.reason == "" {
		h.reason = "steer"
	}
	h.mu.Unlock()
	// 中断当前轮;worker 见纠偏队列即同会话续跑(见 runWorker 纠偏循环)
	if err := e.deps.AI.Cancel(ctx, h.sessionID); err != nil {
		return fmt.Errorf("纠偏中断失败: %w", err)
	}
	e.slots.poke() // 同 Stop:唤醒等位队列重估(槽仍在写回后释放,不抢跑)
	_, _, _ = e.deps.Audit.AppendAudit(ctx, n.CaseID, actor, "intent.steer",
		nodeID, map[string]any{"text": text})
	return nil
}

// ---- 查询面(web 层消费) ----

// Graph 意图图(节点+边)。
func (e *Engine) Graph(ctx context.Context, caseID string) ([]*Node, []*Edge, error) {
	nodes, err := e.deps.Store.ListNodes(ctx, caseID)
	if err != nil {
		return nil, nil, err
	}
	edges, err := e.deps.Store.ListEdges(ctx, caseID)
	if err != nil {
		return nil, nil, err
	}
	return nodes, edges, nil
}

// Detail 节点详情 + 执行过程流。
func (e *Engine) Detail(ctx context.Context, nodeID string) (*Node, []*Event, error) {
	n, err := e.deps.Store.GetNode(ctx, nodeID)
	if err != nil || n == nil {
		return n, nil, err
	}
	evs, err := e.deps.Store.ListEvents(ctx, nodeID)
	if err != nil {
		return n, nil, err
	}
	return n, evs, nil
}

// Coverage 源覆盖(按源:被哪些意图执行过、出过几条事实)。
func (e *Engine) Coverage(ctx context.Context, caseID string) ([]*SourceCoverage, error) {
	return e.deps.Store.Coverage(ctx, caseID)
}

// SetCaseDeadline 设案件级 deadline(nil=清除)。
func (e *Engine) SetCaseDeadline(ctx context.Context, caseID string, at *time.Time) error {
	if err := e.deps.Store.SetCaseDeadline(ctx, caseID, at); err != nil {
		return err
	}
	e.mu.Lock()
	delete(e.deadlineNoted, caseID) // 重设后收尾模式可再审计一次
	e.mu.Unlock()
	return nil
}

// Templates 已装载模板清单(API 呈现用)。
func (e *Engine) Templates() []*Template {
	out := make([]*Template, 0, len(e.deps.Templates))
	for _, t := range e.deps.Templates {
		out = append(out, t)
	}
	return out
}
