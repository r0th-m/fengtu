// intent.Store 的 PostgreSQL 实现(双图:意图图节点/边 + 证据图锚点 +
// 执行过程流 + 源覆盖计算;migrations/005_slice6.sql)。
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ye-mengwen/fengtu/internal/intent"
)

func marshalAnchors(a []intent.Anchor) string {
	if a == nil {
		return "[]"
	}
	b, err := json.Marshal(a)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func unmarshalAnchors(raw []byte) []intent.Anchor {
	out := []intent.Anchor{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

// CreateNode 意图图节点落库(id/created_at 回写)。
func (p *PG) CreateNode(ctx context.Context, n *intent.Node) error {
	err := p.pool.QueryRow(ctx, `
		INSERT INTO intent_nodes
			(case_id, kind, text, status, created_by, rule_id, template_id,
			 template_key, scope, host_scope, parent_id, depth, evidence, budget_seconds)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		RETURNING id, created_at`,
		n.CaseID, n.Kind, n.Text, n.Status, n.CreatedBy, n.RuleID, n.TemplateID,
		n.TemplateKey, n.Scope, n.HostScope, nilIfEmpty(n.ParentID), n.Depth,
		marshalAnchors(n.Evidence), n.BudgetSeconds).
		Scan(&n.ID, &n.CreatedAt)
	if err != nil {
		return fmt.Errorf("意图节点落库失败: %w", err)
	}
	return nil
}

const intentNodeCols = `id, case_id, kind, text, status, created_by, rule_id,
	template_id, template_key, scope, host_scope, COALESCE(parent_id::text, ''), depth,
	evidence, result_text, close_note, COALESCE(session_id::text, ''),
	budget_seconds, started_at, finished_at, created_at`

func scanIntentNode(row interface{ Scan(...any) error }) (*intent.Node, error) {
	var n intent.Node
	var evidence []byte
	err := row.Scan(&n.ID, &n.CaseID, &n.Kind, &n.Text, &n.Status, &n.CreatedBy,
		&n.RuleID, &n.TemplateID, &n.TemplateKey, &n.Scope, &n.HostScope,
		&n.ParentID, &n.Depth,
		&evidence, &n.ResultText, &n.CloseNote, &n.SessionID, &n.BudgetSeconds,
		&n.StartedAt, &n.FinishedAt, &n.CreatedAt)
	if err != nil {
		return nil, err
	}
	n.Evidence = unmarshalAnchors(evidence)
	return &n, nil
}

// GetNode 取节点(nil=无)。
func (p *PG) GetNode(ctx context.Context, id string) (*intent.Node, error) {
	n, err := scanIntentNode(p.pool.QueryRow(ctx,
		`SELECT `+intentNodeCols+` FROM intent_nodes WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("意图节点查询失败: %w", err)
	}
	return n, nil
}

// ListNodes 案件全部节点(创建序)。
func (p *PG) ListNodes(ctx context.Context, caseID string) ([]*intent.Node, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT `+intentNodeCols+` FROM intent_nodes WHERE case_id = $1
		 ORDER BY created_at, id`, caseID)
	if err != nil {
		return nil, fmt.Errorf("意图节点清单查询失败: %w", err)
	}
	defer rows.Close()
	out := []*intent.Node{}
	for rows.Next() {
		n, err := scanIntentNode(rows)
		if err != nil {
			return nil, fmt.Errorf("意图节点行解析失败: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// CreateEdge 血缘边落库(唯一约束幂等:重复边如实跳过)。
func (p *PG) CreateEdge(ctx context.Context, e *intent.Edge) error {
	err := p.pool.QueryRow(ctx, `
		INSERT INTO intent_edges (case_id, from_id, to_id, kind)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (from_id, to_id, kind) DO NOTHING
		RETURNING id, created_at`, e.CaseID, e.FromID, e.ToID, e.Kind).
		Scan(&e.ID, &e.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // 重复边:幂等跳过
		}
		return fmt.Errorf("意图边落库失败: %w", err)
	}
	return nil
}

// ListEdges 案件全部边。
func (p *PG) ListEdges(ctx context.Context, caseID string) ([]*intent.Edge, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, case_id, from_id, to_id, kind, created_at
		FROM intent_edges WHERE case_id = $1 ORDER BY created_at, id`, caseID)
	if err != nil {
		return nil, fmt.Errorf("意图边清单查询失败: %w", err)
	}
	defer rows.Close()
	out := []*intent.Edge{}
	for rows.Next() {
		var e intent.Edge
		if err := rows.Scan(&e.ID, &e.CaseID, &e.FromID, &e.ToID,
			&e.Kind, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("意图边行解析失败: %w", err)
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// NextRunnable 最老一条 open 意图(nil=没有未覆盖方向,planner 静默)。
func (p *PG) NextRunnable(ctx context.Context, caseID string) (*intent.Node, error) {
	n, err := scanIntentNode(p.pool.QueryRow(ctx, `
		SELECT `+intentNodeCols+` FROM intent_nodes
		WHERE case_id = $1 AND status = 'open' AND kind = 'intent'
		ORDER BY created_at, id LIMIT 1`, caseID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("可派发意图查询失败: %w", err)
	}
	return n, nil
}

// MarkRunning 认领(open→running;ok=false=已被领走)。
func (p *PG) MarkRunning(ctx context.Context, id, sessionID string, at time.Time) (bool, error) {
	tag, err := p.pool.Exec(ctx, `
		UPDATE intent_nodes
		SET status = 'running', session_id = $2, started_at = $3
		WHERE id = $1 AND status = 'open'`, id, sessionID, at)
	if err != nil {
		return false, fmt.Errorf("意图认领失败: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// FinishNode 写回终态。
func (p *PG) FinishNode(ctx context.Context, id, status, resultText, closeNote string,
	evidence []intent.Anchor, at time.Time) error {

	_, err := p.pool.Exec(ctx, `
		UPDATE intent_nodes
		SET status = $2, result_text = $3, close_note = $4, evidence = $5,
		    finished_at = $6
		WHERE id = $1`, id, status, resultText, closeNote,
		marshalAnchors(evidence), at)
	if err != nil {
		return fmt.Errorf("意图写回失败: %w", err)
	}
	return nil
}

// SetGoalStatus goal 收官重估落账(0.29.1):仅对 open/closed_goal_* 的 goal
// 节点生效(幂等;ok=false=并发下状态已变,如实以库为准)。at=nil 重开
// (finished_at 清空,close_note 清空)。
func (p *PG) SetGoalStatus(ctx context.Context, id, status, closeNote string,
	at *time.Time) (bool, error) {

	tag, err := p.pool.Exec(ctx, `
		UPDATE intent_nodes
		SET status = $2, close_note = $3, finished_at = $4
		WHERE id = $1 AND kind = 'goal'
		  AND status IN ('open', 'closed_goal_met', 'closed_goal_partial',
		                 'closed_goal_unmet')`, id, status, closeNote, at)
	if err != nil {
		return false, fmt.Errorf("goal 收官落账失败: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// AddAnchors 挂证据图锚点(kind=evidence|explored)。
func (p *PG) AddAnchors(ctx context.Context, caseID, nodeID, kind string,
	anchors []intent.Anchor) error {

	for _, a := range anchors {
		var src any
		if a.SourceID != "" {
			src = a.SourceID
		}
		var line any
		if a.LineNo > 0 {
			line = a.LineNo
		}
		var hit any
		if a.HitID != "" {
			hit = a.HitID
		}
		if _, err := p.pool.Exec(ctx, `
			INSERT INTO evidence_anchors (case_id, node_id, source_id, line_no, hit_id, kind, note)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			caseID, nodeID, src, line, hit, kind, a.Note); err != nil {
			return fmt.Errorf("证据锚点落库失败: %w", err)
		}
	}
	return nil
}

// AppendEvent 执行过程流落一步。
func (p *PG) AppendEvent(ctx context.Context, caseID, nodeID, kind, text string) error {
	if _, err := p.pool.Exec(ctx, `
		INSERT INTO intent_events (case_id, node_id, kind, text)
		VALUES ($1, $2, $3, $4)`, caseID, nodeID, kind, text); err != nil {
		return fmt.Errorf("意图过程流落账失败: %w", err)
	}
	return nil
}

// ListEvents 节点执行过程流(逐步留痕,顺序回放)。
func (p *PG) ListEvents(ctx context.Context, nodeID string) ([]*intent.Event, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, node_id, kind, text, created_at
		FROM intent_events WHERE node_id = $1 ORDER BY id`, nodeID)
	if err != nil {
		return nil, fmt.Errorf("意图过程流查询失败: %w", err)
	}
	defer rows.Close()
	out := []*intent.Event{}
	for rows.Next() {
		var e intent.Event
		if err := rows.Scan(&e.ID, &e.NodeID, &e.Kind, &e.Text, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("意图过程流行解析失败: %w", err)
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// DecideApproval 审批门落账(awaiting_approval → open|closed;ok=false=非待批)。
func (p *PG) DecideApproval(ctx context.Context, id string, approve bool, at time.Time) (bool, error) {
	var tag pgconn.CommandTag
	var err error
	if approve {
		tag, err = p.pool.Exec(ctx, `
			UPDATE intent_nodes SET status = 'open'
			WHERE id = $1 AND status = 'awaiting_approval'`, id)
	} else {
		tag, err = p.pool.Exec(ctx, `
			UPDATE intent_nodes
			SET status = 'closed', close_note = '审批拒绝,不予执行', finished_at = $2
			WHERE id = $1 AND status = 'awaiting_approval'`, id, at)
	}
	if err != nil {
		return false, fmt.Errorf("意图审批落账失败: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// Coverage 源覆盖:按源聚合「被哪些意图执行过、出过几条事实、候选数」
// (证据图锚点 + 复用 hits;含 host/package 两列供三级聚簇,§3 修正稿)。
func (p *PG) Coverage(ctx context.Context, caseID string) ([]*intent.SourceCoverage, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT s.id, s.path, s.kind, COALESCE(s.log_type, ''), s.host, s.package,
		       COALESCE(array_agg(DISTINCT ea.node_id::text)
		         FILTER (WHERE ea.node_id IS NOT NULL), '{}'),
		       COUNT(DISTINCT n.id) FILTER (WHERE n.kind = 'fact'),
		       (SELECT COUNT(*) FROM hits h WHERE h.source_id = s.id)
		FROM sources s
		LEFT JOIN evidence_anchors ea ON ea.source_id = s.id
		LEFT JOIN intent_nodes n ON n.id = ea.node_id
		WHERE s.case_id = $1
		GROUP BY s.id, s.path, s.kind, s.log_type, s.host, s.package
		ORDER BY s.host, s.package, s.path`, caseID)
	if err != nil {
		return nil, fmt.Errorf("源覆盖查询失败: %w", err)
	}
	defer rows.Close()
	out := []*intent.SourceCoverage{}
	for rows.Next() {
		var c intent.SourceCoverage
		c.IntentIDs = []string{}
		if err := rows.Scan(&c.SourceID, &c.Path, &c.Kind, &c.LogType,
			&c.Host, &c.Package, &c.IntentIDs, &c.Facts, &c.Hits); err != nil {
			return nil, fmt.Errorf("源覆盖行解析失败: %w", err)
		}
		c.Explored = len(c.IntentIDs) > 0
		out = append(out, &c)
	}
	return out, rows.Err()
}

// CaseDeadline 案件级 deadline(nil=未设)。
func (p *PG) CaseDeadline(ctx context.Context, caseID string) (*time.Time, error) {
	var dl *time.Time
	err := p.pool.QueryRow(ctx,
		`SELECT deadline_at FROM cases WHERE id = $1`, caseID).Scan(&dl)
	if err != nil {
		return nil, fmt.Errorf("案件 deadline 查询失败: %w", err)
	}
	return dl, nil
}

// SetCaseDeadline 设/清案件级 deadline。
func (p *PG) SetCaseDeadline(ctx context.Context, caseID string, at *time.Time) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE cases SET deadline_at = $2 WHERE id = $1`, caseID, at)
	if err != nil {
		return fmt.Errorf("案件 deadline 落库失败: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("无此案件: %s", caseID)
	}
	return nil
}

// RecoverInFlight 崩溃恢复:中断的 running 意图重置回 open(逐条记事件
// 留痕),返回仍有 open 意图待派的案件清单(引擎启动时逐个唤醒)。
func (p *PG) RecoverInFlight(ctx context.Context) ([]string, error) {
	rows, err := p.pool.Query(ctx, `
		UPDATE intent_nodes SET status = 'open'
		WHERE kind = 'intent' AND status = 'running'
		RETURNING id::text, case_id::text`)
	if err != nil {
		return nil, fmt.Errorf("崩溃恢复重置 running 失败: %w", err)
	}
	type recovered struct{ id, caseID string }
	var rec []recovered
	for rows.Next() {
		var r recovered
		if err := rows.Scan(&r.id, &r.caseID); err != nil {
			rows.Close()
			return nil, fmt.Errorf("崩溃恢复读回失败: %w", err)
		}
		rec = append(rec, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("崩溃恢复重置 running 失败: %w", err)
	}
	for _, r := range rec {
		// 留痕:谁被重置、为什么(审计面零静默)
		if _, err := p.pool.Exec(ctx, `
			INSERT INTO intent_events (case_id, node_id, kind, text)
			VALUES ($1, $2, 'system',
			        'server 重启:worker 随进程中断,意图重新入队(running→open)')`,
			r.caseID, r.id); err != nil {
			return nil, fmt.Errorf("崩溃恢复留痕失败: %w", err)
		}
	}
	rows2, err := p.pool.Query(ctx, `
		SELECT DISTINCT case_id::text FROM intent_nodes
		WHERE kind = 'intent' AND status = 'open'`)
	if err != nil {
		return nil, fmt.Errorf("崩溃恢复案件清单查询失败: %w", err)
	}
	defer rows2.Close()
	var out []string
	for rows2.Next() {
		var id string
		if err := rows2.Scan(&id); err != nil {
			return nil, fmt.Errorf("崩溃恢复案件清单读回失败: %w", err)
		}
		out = append(out, id)
	}
	return out, rows2.Err()
}

var _ intent.Store = (*PG)(nil)
