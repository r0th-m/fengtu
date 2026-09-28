// Package intent 意图链引擎(DESIGN §6/§6.4):双图(意图图每案件 +
// 证据图锚点复用 hits/sources)+ planner/worker 分工 + 四层预算 + 审批门。
//
// 纪律(与 DESIGN §1/§6 同源):
//   - 执行层只读:worker 只用切片五的六个只读工具(单意图单 norma 会话,
//     system prompt 带意图上下文),没有任何写能力;
//   - 判断权归人:finding 一律以 pending 落既有待审区(run_operator 工具
//     已有通路),意图节点只记「系统按证据结构算出的评估」;
//   - 评估不许拍脑袋(§6.2):verdict 由系统校验——supported 必须带锚点,
//     无锚点断言降级 doubt;模型只给材料,档位系统算;
//   - 预算四层如实:意图级 wall-clock 耗尽 → 停查→写回已得→
//     closed_exhausted(不是失败,如实标「时间耗尽,覆盖可能不全」);
//     案件级 deadline 到点 → planner 停派(收尾模式);会话级 token 复用
//     agentloop 熔断;厂商级 max_tokens/rate_per_second 先记账;
//   - 审批门:AI/规则派生的批量执行意图(scope=all)挂 awaiting_approval,
//     人批准才运行;人提出的意图自由执行;批准/拒绝进审计哈希链;
//   - 没有未覆盖方向则不派(planner 如实静默,不硬造意图)。
package intent

import (
	"context"
	"fmt"
	"time"
)

// 节点类型/状态/来源/边血缘(与 migrations/005_slice6.sql CHECK 一致)。
const (
	KindGoal    = "goal"
	KindIntent  = "intent"
	KindFact    = "fact"
	KindFinding = "finding"
	KindHint    = "hint"

	StatusOpen             = "open"
	StatusAwaitingApproval = "awaiting_approval"
	StatusRunning          = "running"
	StatusSupported        = "supported"
	StatusDenied           = "denied"
	StatusDoubt            = "doubt"
	StatusClosedExhausted  = "closed_exhausted"
	StatusClosed           = "closed"
	// StatusParked 停车场(0.24.0;常量集中在 parking.go,此处注释指路)。
	// parked=预算闸/AI 申请拦下的未展开线索:不可派发,人点展开才转 open。
	// StatusStopped 迁移终止(0.27.0 案件封存/迁移,017 迁移 CHECK 同口径):
	// 跨实例导入时源案在跑(running)/待批(awaiting_approval)意图的落库态
	// ——迁移不续跑(执行上下文/AI 会话不随包),终态,人看过证据后重新派。
	StatusStopped = "stopped"

	// goal 收官机器评估态(0.29.1-goal-lifecycle,020 迁移 CHECK 同口径):
	// goal 本不可派发(NextRunnable 只领 open intent),子树内全部意图到终态
	// 后系统按证据结构给机器评估档——措辞如实「机器评估,收官定论归人」。
	// 三态同为终态,不进派发队列;子树重新出现未终态意图(停车场展开等)
	// 重估回 open(机器评估态不作数,如实)。
	StatusClosedGoalMet     = "closed_goal_met"     // 子树意图全部 supported
	StatusClosedGoalPartial = "closed_goal_partial" // 部分 supported
	StatusClosedGoalUnmet   = "closed_goal_unmet"   // 零 supported

	ByHuman = "human"
	ByAI    = "ai"
	ByRule  = "rule"

	EdgeSpawns      = "spawns"
	EdgeDerivedFrom = "derived_from"
	EdgeYields      = "yields"
	EdgeProves      = "proves"

	ScopeCase = "case"
	ScopeAll  = "all"
)

// MaxDepth 派生深度上限(防无限展开,§6)。
const MaxDepth = 5

// DefaultBudgetSeconds 意图级 wall-clock 默认(10 分钟,可配)。
const DefaultBudgetSeconds = 600

// DefaultTokenBudget worker 会话 token 预算(会话级,复用 agentloop 熔断。
// 这是「累计账」语义:DeepSeek 每轮全量重发上下文(64k 窗口近满),
// 累计 ≈ 60k × 轮数——切片七台架实测 736 源案件一条「盘点+抽查」意图
// 13 轮即 50.7 万;按 15~25 轮并留裕量定 100 万(保险丝语义,防失控
// 不防正常排查;DeepSeek 缓存命中价约 1/10,1M 累计 ≈ 几角钱/意图)。
// 环境变量 FENGTU_INTENT_TOKEN_BUDGET 可覆盖。
// 历史:100k(切片六 736 源熔断)→ 500k(切片七 13 轮仍熔断)→ 1M。
const DefaultTokenBudget = 1000000

// Node 意图图节点。
type Node struct {
	ID            string     `json:"id"`
	CaseID        string     `json:"case_id"`
	Kind          string     `json:"kind"`
	Text          string     `json:"text"`
	Status        string     `json:"status"`
	CreatedBy     string     `json:"created_by"`
	RuleID        string     `json:"rule_id,omitempty"`
	TemplateID    string     `json:"template_id,omitempty"`
	TemplateKey   string     `json:"template_key,omitempty"`
	Scope         string     `json:"scope"`
	// HostScope 主机范围(§3 修正稿一案多包):空=全案件(NULL 语义);
	// 具体主机键=worker 执行查询限定在该主机的源集合(会话级强制)。
	HostScope     string     `json:"host_scope,omitempty"`
	ParentID      string     `json:"parent_id,omitempty"`
	Depth         int        `json:"depth"`
	Evidence      []Anchor   `json:"evidence"`
	ResultText    string     `json:"result_text,omitempty"`
	CloseNote     string     `json:"close_note,omitempty"`
	SessionID     string     `json:"session_id,omitempty"`
	BudgetSeconds int        `json:"budget_seconds"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// Edge 血缘边。
type Edge struct {
	ID        string    `json:"id"`
	CaseID    string    `json:"case_id"`
	FromID    string    `json:"from_id"`
	ToID      string    `json:"to_id"`
	Kind      string    `json:"kind"`
	CreatedAt time.Time `json:"created_at"`
}

// Anchor 证据锚点(证据图:节点 → 既有 sources/hits,复用不另造)。
type Anchor struct {
	SourceID string `json:"source_id,omitempty"`
	LineNo   int    `json:"line_no,omitempty"`
	HitID    string `json:"hit_id,omitempty"`
	Note     string `json:"note,omitempty"`
}

// Event 执行过程流一步(§6 执行过程流)。
type Event struct {
	ID        int64     `json:"id"`
	NodeID    string    `json:"node_id"`
	Kind      string    `json:"kind"`
	Text      string    `json:"text"`
	CreatedAt time.Time `json:"created_at"`
}

// Constraint 案件级操作约束(交互改造切片三,设计 §3 set_constraints 应急映射:
// 「不得触碰的生产系统清单/只读原则/时间窗」——人增人删,注入 worker system
// 最高优先;机器不自动抽取(自动抽取要猜,判断权归人)。
type Constraint struct {
	ID        string    `json:"id"`
	CaseID    string    `json:"case_id"`
	Text      string    `json:"text"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// SourceCoverage 源覆盖一行(「这份源到底查没查过」的可计算回答)。
type SourceCoverage struct {
	SourceID  string   `json:"source_id"`
	Path      string   `json:"path"`
	Kind      string   `json:"kind"`
	LogType   string   `json:"log_type"`
	Host      string   `json:"host"`    // 主机键(三级聚簇第一层;空=未建模)
	Package   string   `json:"package"` // 采集包登记根名(三级聚簇第二层)
	Explored  bool     `json:"explored"`    // 被任意意图执行摸过(检索/回查/算子/锚点)
	IntentIDs []string `json:"intent_ids"`  // 摸过它的意图节点
	Facts     int      `json:"facts"`       // 挂在它身上的 fact 节点数
	Hits      int      `json:"hits"`        // 待审区候选数(复用 hits)
}

// RuleSeed 规则扫描候选派生的意图种子(web 层从扫描总账翻译)。
type RuleSeed struct {
	RuleID  string
	Title   string
	HitsNew int
}

// Store 意图图/证据图存储(PG 实现在 internal/ingest/store,单测 fake)。
type Store interface {
	CreateNode(ctx context.Context, n *Node) error
	GetNode(ctx context.Context, id string) (*Node, error)
	ListNodes(ctx context.Context, caseID string) ([]*Node, error)
	CreateEdge(ctx context.Context, e *Edge) error
	ListEdges(ctx context.Context, caseID string) ([]*Edge, error)
	// NextRunnable 取最老一条 open 意图(nil=没有未覆盖方向,planner 静默)。
	NextRunnable(ctx context.Context, caseID string) (*Node, error)
	// MarkRunning open→running 认领(ok=false=已被领走/状态已变)。
	MarkRunning(ctx context.Context, id, sessionID string, at time.Time) (bool, error)
	// FinishNode 写回终态(状态/摘要/关闭说明/证据锚点)。
	FinishNode(ctx context.Context, id, status, resultText, closeNote string,
		evidence []Anchor, at time.Time) error
	// SetGoalStatus goal 收官重估落账(0.29.1):仅对 open/closed_goal_* 的
	// goal 节点生效(幂等;其他状态/类型 ok=false 如实)。at=nil 表示重开
	// (finished_at 清空)——子树重新出现未终态意图时 goal 回 open。
	SetGoalStatus(ctx context.Context, id, status, closeNote string,
		at *time.Time) (bool, error)
	// AddAnchors 挂证据图锚点(kind=evidence|explored)。
	AddAnchors(ctx context.Context, caseID, nodeID, kind string, anchors []Anchor) error
	AppendEvent(ctx context.Context, caseID, nodeID, kind, text string) error
	ListEvents(ctx context.Context, nodeID string) ([]*Event, error)
	// DecideApproval 审批门落账:awaiting_approval → open(批准)/closed(拒绝);
	// ok=false = 不在待批状态(并发审批如实)。
	DecideApproval(ctx context.Context, id string, approve bool, at time.Time) (bool, error)
	// Coverage 按源聚合「被哪些意图执行过、出过几条事实」。
	Coverage(ctx context.Context, caseID string) ([]*SourceCoverage, error)
	// ListHosts 案件已建模主机键清单(模板 host_scope=each 实例化域)。
	ListHosts(ctx context.Context, caseID string) ([]string, error)
	// CaseDeadline 案件级 wall-clock deadline(超期进收尾模式)。
	CaseDeadline(ctx context.Context, caseID string) (*time.Time, error)
	SetCaseDeadline(ctx context.Context, caseID string, at *time.Time) error
	// CaseArchived 案件是否已归档(0.18.0):归档=planner 停派新意图
	// (在跑的如实跑完),与 deadline 收尾模式同形态。无此案件按未归档。
	CaseArchived(ctx context.Context, caseID string) (bool, error)
	// 操作约束(交互改造切片三,设计 §3 set_constraints 应急映射):
	// 案件级,人增人删,worker system 注入(最高优先,只加码不松绑)。
	ListConstraints(ctx context.Context, caseID string) ([]*Constraint, error)
	// AddConstraint 约束落库(id/created_at 回写)。
	AddConstraint(ctx context.Context, c *Constraint) error
	// DeleteConstraint 删约束(ok=false=无此约束;硬删,历史在审计链)。
	DeleteConstraint(ctx context.Context, caseID, id string) (bool, error)
	// RecoverInFlight 崩溃恢复(2026-09-23 实战:server 进程死亡后,
	// running 意图成死节点、open 意图无人派发):中断的 running 意图重置回
	// open(逐条记事件留痕),返回仍有 open 意图待派的案件清单(引擎启动
	// 时逐个唤醒)。无恢复语义的实现(单测 fake)返回 nil。
	RecoverInFlight(ctx context.Context) ([]string, error)
	// ---- 停车场(0.24.0-convergence L2,migrations/014) ----
	// CreateParking 停车场条目落库(id/created_at 回写)。
	CreateParking(ctx context.Context, p *ParkingEntry) error
	// ListParking 案件停车场清单(含已处置留痕;Text join 图节点快照)。
	ListParking(ctx context.Context, caseID string) ([]*ParkingEntry, error)
	// GetParking 取条目(nil=无)。
	GetParking(ctx context.Context, id string) (*ParkingEntry, error)
	// DecideParking 处置落账:parked→deployed|dismissed(decided_by/at);
	// ok=false=不在 parked(并发处置如实)。
	DecideParking(ctx context.Context, id string, deploy bool, actor string, at time.Time) (bool, error)
	// SetParkingVerdict 章节收官评估建议写入(verdict=deploy|dismiss;
	// 只建议不自动开,展开仍走人点 deploy)。
	SetParkingVerdict(ctx context.Context, id, verdict, reason string) error
	// ParkedNodeDecision parked 图节点去留:deploy→open(newParentID 非空=
	// 新开章挂靠,parent 重指)/dismiss→closed(closeNote 如实);
	// ok=false=不在 parked(并发处置/状态已变如实)。
	ParkedNodeDecision(ctx context.Context, id string, deploy bool,
		closeNote, newParentID string, at time.Time) (bool, error)
}

// GateStatus 创建时定初始状态:AI/规则派生的批量执行意图(scope=all)
// 过审批门挂起;人提出的意图自由执行(§6 闸)。
func GateStatus(createdBy, scope string) string {
	if scope == ScopeAll && createdBy != ByHuman {
		return StatusAwaitingApproval
	}
	return StatusOpen
}

// ValidateNode 节点字段合法性(写库前拦,不依赖 DB CHECK 才报错)。
func ValidateNode(n *Node) error {
	switch n.Kind {
	case KindGoal, KindIntent, KindFact, KindFinding, KindHint:
	default:
		return fmt.Errorf("节点类型非法: %q", n.Kind)
	}
	if n.Text == "" {
		return fmt.Errorf("节点文本必填")
	}
	switch n.CreatedBy {
	case ByHuman, ByAI, ByRule:
	default:
		return fmt.Errorf("created_by 非法: %q", n.CreatedBy)
	}
	if n.Scope != ScopeCase && n.Scope != ScopeAll {
		return fmt.Errorf("scope 非法: %q", n.Scope)
	}
	if len(n.HostScope) > 128 {
		return fmt.Errorf("host_scope 过长(≤128 字符)")
	}
	if n.Depth < 0 || n.Depth > MaxDepth {
		return fmt.Errorf("派生深度超上限(≤%d): %d", MaxDepth, n.Depth)
	}
	if n.BudgetSeconds <= 0 {
		n.BudgetSeconds = DefaultBudgetSeconds
	}
	return nil
}
