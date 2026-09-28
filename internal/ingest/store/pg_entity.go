// 实体层(0.25.0-datasource-unlock):entities 表的写入(摄入管线抽取)
// 与读取(review 引擎 target:entity 规则扫描)。
//
// 写入纪律:去重幂等 UNIQUE(case_id, host, canonical_key) + ON CONFLICT
// DO NOTHING——重跑摄入/重复解析不滚锚点(锚点保首见);判断权归人,
// 实体层只供候选,不自动定论。
package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/ye-mengwen/fengtu/internal/entity"
)

// entityInsertBatch 多行 INSERT 的单批行数(参数占位上限内)。
const entityInsertBatch = 500

// InsertEntities 批量落实体(摄取管线 EntitySink 实现;空切片直接返回)。
func (p *PG) InsertEntities(ctx context.Context, rows []entity.Row) error {
	for start := 0; start < len(rows); start += entityInsertBatch {
		end := start + entityInsertBatch
		if end > len(rows) {
			end = len(rows)
		}
		chunk := rows[start:end]
		var b strings.Builder
		b.WriteString(`INSERT INTO entities
			(case_id, host, entity_type, raw_value, canonical_key, qualifier,
			 source_id, line_no) VALUES `)
		args := make([]any, 0, len(chunk)*8)
		for i, r := range chunk {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
				len(args)+1, len(args)+2, len(args)+3, len(args)+4,
				len(args)+5, len(args)+6, len(args)+7, len(args)+8)
			args = append(args, r.CaseID, r.Host, r.EntityType, r.RawValue,
				r.CanonicalKey, r.Qualifier, r.SourceID, r.LineNo)
		}
		b.WriteString(" ON CONFLICT (case_id, host, canonical_key) DO NOTHING")
		if _, err := p.pool.Exec(ctx, b.String(), args...); err != nil {
			return fmt.Errorf("实体批量落库失败(批 %d 行): %w", len(chunk), err)
		}
	}
	return nil
}

// ListEntities 案件内全部实体(review 引擎 target:entity 规则扫描用;
// 按写入序,首见锚点在前)。
func (p *PG) ListEntities(ctx context.Context, caseID string) ([]entity.Row, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT case_id, host, entity_type, raw_value, canonical_key, qualifier,
			source_id, line_no
		FROM entities WHERE case_id = $1 ORDER BY id`, caseID)
	if err != nil {
		return nil, fmt.Errorf("实体查询失败: %w", err)
	}
	defer rows.Close()
	var out []entity.Row
	for rows.Next() {
		var r entity.Row
		if err := rows.Scan(&r.CaseID, &r.Host, &r.EntityType, &r.RawValue,
			&r.CanonicalKey, &r.Qualifier, &r.SourceID, &r.LineNo); err != nil {
			return nil, fmt.Errorf("实体行解析失败: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
