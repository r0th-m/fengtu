// 停车场的 PostgreSQL 实现(0.24.0-convergence,migrations/014):
// intent_parking 条目 CRUD + parked 图节点去留 + 全局待处置计数。
// Text 不落表——读出时 join intent_nodes.text(节点文本不可变,快照语义一致)。
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ye-mengwen/fengtu/internal/intent"
)

// parkingCols 条目读出列(Text 来自 intent_nodes join;suggest_goal_id 可空)。
const parkingCols = `p.id, p.case_id, p.node_id, n.text,
	COALESCE(p.source_node_id::text, ''), COALESCE(p.suggest_goal_id::text, ''),
	p.suggest_label, p.reason, p.verdict, p.verdict_reason, p.status,
	p.created_by, p.created_at, p.decided_at, p.decided_by`

const parkingJoin = ` FROM intent_parking p
	JOIN intent_nodes n ON n.id = p.node_id `

func scanParking(row interface{ Scan(...any) error }) (*intent.ParkingEntry, error) {
	var p intent.ParkingEntry
	err := row.Scan(&p.ID, &p.CaseID, &p.NodeID, &p.Text,
		&p.SourceNodeID, &p.SuggestGoalID, &p.SuggestLabel, &p.Reason,
		&p.Verdict, &p.VerdictReason, &p.Status,
		&p.CreatedBy, &p.CreatedAt, &p.DecidedAt, &p.DecidedBy)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// CreateParking 停车场条目落库(id/created_at 回写)。
func (p *PG) CreateParking(ctx context.Context, e *intent.ParkingEntry) error {
	var src any
	if e.SourceNodeID != "" {
		src = e.SourceNodeID
	}
	var goal any
	if e.SuggestGoalID != "" {
		goal = e.SuggestGoalID
	}
	err := p.pool.QueryRow(ctx, `
		INSERT INTO intent_parking
			(case_id, node_id, source_node_id, suggest_goal_id, suggest_label,
			 reason, status, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, 'parked', $7)
		RETURNING id, created_at`,
		e.CaseID, e.NodeID, src, goal, e.SuggestLabel, e.Reason, e.CreatedBy).
		Scan(&e.ID, &e.CreatedAt)
	if err != nil {
		return fmt.Errorf("停车场条目落库失败: %w", err)
	}
	return nil
}

// ListParking 案件停车场清单(创建序;含已处置留痕,前端分区呈现)。
func (p *PG) ListParking(ctx context.Context, caseID string) ([]*intent.ParkingEntry, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT `+parkingCols+parkingJoin+`WHERE p.case_id = $1
		 ORDER BY p.created_at, p.id`, caseID)
	if err != nil {
		return nil, fmt.Errorf("停车场清单查询失败: %w", err)
	}
	defer rows.Close()
	out := []*intent.ParkingEntry{}
	for rows.Next() {
		e, err := scanParking(rows)
		if err != nil {
			return nil, fmt.Errorf("停车场行解析失败: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetParking 取条目(nil=无)。
func (p *PG) GetParking(ctx context.Context, id string) (*intent.ParkingEntry, error) {
	e, err := scanParking(p.pool.QueryRow(ctx,
		`SELECT `+parkingCols+parkingJoin+`WHERE p.id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("停车场条目查询失败: %w", err)
	}
	return e, nil
}

// DecideParking 处置落账(parked→deployed|dismissed;ok=false=已被处置)。
func (p *PG) DecideParking(ctx context.Context, id string, deploy bool,
	actor string, at time.Time) (bool, error) {

	status := intent.ParkingDismissed
	if deploy {
		status = intent.ParkingDeployed
	}
	tag, err := p.pool.Exec(ctx, `
		UPDATE intent_parking
		SET status = $2, decided_by = $3, decided_at = $4
		WHERE id = $1 AND status = 'parked'`, id, status, actor, at)
	if err != nil {
		return false, fmt.Errorf("停车场处置落账失败: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// SetParkingVerdict 章节收官评估建议写入(只写建议列,不动处置状态——
// 展开/丢弃永远人批)。
func (p *PG) SetParkingVerdict(ctx context.Context, id, verdict, reason string) error {
	tag, err := p.pool.Exec(ctx, `
		UPDATE intent_parking SET verdict = $2, verdict_reason = $3
		WHERE id = $1 AND status = 'parked'`, id, verdict, reason)
	if err != nil {
		return fmt.Errorf("停车场评估建议落账失败: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("停车场条目不存在或已处置(评估建议不落): %s", id)
	}
	return nil
}

// ParkedNodeDecision parked 图节点去留:deploy→open(newParentID 非空=新开章
// 挂靠,parent 重指)/dismiss→closed(closeNote 如实);ok=false=不在 parked。
func (p *PG) ParkedNodeDecision(ctx context.Context, id string, deploy bool,
	closeNote, newParentID string, at time.Time) (bool, error) {

	var err error
	var rows int64
	if deploy {
		if newParentID != "" {
			r, e2 := p.pool.Exec(ctx, `
				UPDATE intent_nodes SET status = 'open', parent_id = $2
				WHERE id = $1 AND status = 'parked'`, id, newParentID)
			err, rows = e2, r.RowsAffected()
		} else {
			r, e2 := p.pool.Exec(ctx, `
				UPDATE intent_nodes SET status = 'open'
				WHERE id = $1 AND status = 'parked'`, id)
			err, rows = e2, r.RowsAffected()
		}
	} else {
		r, e2 := p.pool.Exec(ctx, `
			UPDATE intent_nodes
			SET status = 'closed', close_note = $2, finished_at = $3
			WHERE id = $1 AND status = 'parked'`, id, closeNote, at)
		err, rows = e2, r.RowsAffected()
	}
	if err != nil {
		return false, fmt.Errorf("停车场节点去留落库失败: %w", err)
	}
	return rows == 1, nil
}

// CountPendingParking 全局待处置停车场条数(侧边栏计数;判断权归人入口)。
func (p *PG) CountPendingParking(ctx context.Context) (int64, error) {
	var n int64
	err := p.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM intent_parking WHERE status = 'parked'`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("停车场待处置计数失败: %w", err)
	}
	return n, nil
}
