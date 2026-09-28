// 研判报告(AI 生成)版本账的 PG 实现(0.31.0;migrations/021_narrative_reports.sql)。
// 纪律:content 存 LLM 产出原文不加工(证据链如实);版本号单条 INSERT 内
// SELECT MAX+1 子查询算出,(case_id, kind, version) 唯一约束兜底并发双写
// (撞了如实报错,不静默覆盖);读侧按元数据动态拼报告头/截断标注。
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// CaseReport 一版研判报告(版本递增,历史全留;判断权归人=只有初稿没有定论)。
type CaseReport struct {
	ID        string    `json:"id"`
	CaseID    string    `json:"case_id"`
	Kind      string    `json:"kind"` // narrative(021 CHECK 约束)
	Version   int       `json:"version"`
	Content   string    `json:"content"` // LLM 产出原文(markdown;报告头读侧拼)
	TokensIn  int64     `json:"tokens_in"`
	TokensOut int64     `json:"tokens_out"`
	Truncated bool      `json:"truncated"` // token 预算熔断截断(如实)
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// InsertCaseReport 落一版(版本号库内自增;并发撞唯一约束如实报错)。
func (p *PG) InsertCaseReport(ctx context.Context, r *CaseReport) error {
	err := p.pool.QueryRow(ctx, `
		INSERT INTO case_reports
			(case_id, kind, version, content, tokens_in, tokens_out,
			 truncated, created_by)
		VALUES ($1, $2,
			(SELECT COALESCE(MAX(version), 0) + 1 FROM case_reports
			 WHERE case_id = $1 AND kind = $2),
			$3, $4, $5, $6, $7)
		RETURNING id, version, created_at`,
		r.CaseID, r.Kind, r.Content, r.TokensIn, r.TokensOut,
		r.Truncated, r.CreatedBy).
		Scan(&r.ID, &r.Version, &r.CreatedAt)
	if err != nil {
		return fmt.Errorf("研判报告落账失败: %w", err)
	}
	return nil
}

const caseReportCols = `id, case_id, kind, version, content, tokens_in, tokens_out,
	truncated, created_by, created_at`

func scanCaseReport(row interface{ Scan(...any) error }) (*CaseReport, error) {
	var r CaseReport
	err := row.Scan(&r.ID, &r.CaseID, &r.Kind, &r.Version, &r.Content,
		&r.TokensIn, &r.TokensOut, &r.Truncated, &r.CreatedBy, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ListCaseReports 案件报告版本清单(版本倒序;content 不随行回(列表免背大字段),
// 取空串——看内容走 GetCaseReport)。
func (p *PG) ListCaseReports(ctx context.Context, caseID, kind string) ([]CaseReport, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, case_id, kind, version, '', tokens_in, tokens_out,
			truncated, created_by, created_at
		FROM case_reports WHERE case_id = $1 AND kind = $2
		ORDER BY version DESC`, caseID, kind)
	if err != nil {
		return nil, fmt.Errorf("研判报告清单查询失败: %w", err)
	}
	defer rows.Close()
	out := []CaseReport{}
	for rows.Next() {
		r, err := scanCaseReport(rows)
		if err != nil {
			return nil, fmt.Errorf("研判报告行解析失败: %w", err)
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// GetCaseReport 取一案一版(nil = 无此版本,如实)。
func (p *PG) GetCaseReport(ctx context.Context, caseID, kind string,
	version int) (*CaseReport, error) {

	r, err := scanCaseReport(p.pool.QueryRow(ctx,
		`SELECT `+caseReportCols+` FROM case_reports
		 WHERE case_id = $1 AND kind = $2 AND version = $3`,
		caseID, kind, version))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("研判报告查询失败: %w", err)
	}
	return r, nil
}
