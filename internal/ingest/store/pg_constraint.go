// 案件级操作约束的 PostgreSQL 实现(交互改造切片三,migrations/008_runtime_control.sql;
// 设计 §3 set_constraints 应急映射——人增人删,worker system 注入)。
package store

import (
	"context"
	"fmt"

	"github.com/ye-mengwen/fengtu/internal/intent"
)

// ListConstraints 案件约束清单(创建序;worker system 注入与 API 呈现共用)。
func (p *PG) ListConstraints(ctx context.Context, caseID string) ([]*intent.Constraint, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, case_id, text, created_by, created_at
		FROM case_constraints WHERE case_id = $1 ORDER BY created_at, id`, caseID)
	if err != nil {
		return nil, fmt.Errorf("约束清单查询失败: %w", err)
	}
	defer rows.Close()
	out := []*intent.Constraint{}
	for rows.Next() {
		var c intent.Constraint
		if err := rows.Scan(&c.ID, &c.CaseID, &c.Text, &c.CreatedBy, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("约束行解析失败: %w", err)
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// AddConstraint 约束落库(id/created_at 回写)。
func (p *PG) AddConstraint(ctx context.Context, c *intent.Constraint) error {
	err := p.pool.QueryRow(ctx, `
		INSERT INTO case_constraints (case_id, text, created_by)
		VALUES ($1, $2, $3) RETURNING id, created_at`,
		c.CaseID, c.Text, c.CreatedBy).Scan(&c.ID, &c.CreatedAt)
	if err != nil {
		return fmt.Errorf("约束落库失败: %w", err)
	}
	return nil
}

// DeleteConstraint 删约束(ok=false=无此约束;硬删,历史在审计链)。
// case_id 同查防跨案误删(id 是 UUID 虽难猜,但证据链纪律不依赖难猜)。
func (p *PG) DeleteConstraint(ctx context.Context, caseID, id string) (bool, error) {
	tag, err := p.pool.Exec(ctx,
		`DELETE FROM case_constraints WHERE id = $1 AND case_id = $2`, id, caseID)
	if err != nil {
		return false, fmt.Errorf("约束删除失败: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
