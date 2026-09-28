// LLM 录制账的 PG 实现(切片十;migrations/009_llm_records.sql)。
// 写侧由 agentloop recordingProvider 挂钩调用;读侧供 web 录制页列表/详情。
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// LLMRecord 一次厂商调用的录制账(元数据默认;full 档才带 prompt/response)。
type LLMRecord struct {
	ID         string    `json:"id"`
	SessionID  string    `json:"session_id"` // 空=无会话上下文(如实)
	CaseID     string    `json:"case_id"`
	Kind       string    `json:"kind"` // chat|intent
	Model      string    `json:"model"`
	Status     string    `json:"status"` // ok|error
	Err        string    `json:"err,omitempty"`
	TokensIn   int64     `json:"tokens_in"`
	TokensOut  int64     `json:"tokens_out"`
	DurationMs int64     `json:"duration_ms"`
	Prompt     *string   `json:"prompt,omitempty"`   // full 档才落
	Response   *string   `json:"response,omitempty"` // full 档才落
	CreatedAt  time.Time `json:"created_at"`
}

// InsertLLMRecord 落一条录制账(写失败由调用方如实记日志,不杀 loop)。
func (p *PG) InsertLLMRecord(ctx context.Context, r *LLMRecord) error {
	var sessArg, caseArg *string
	if r.SessionID != "" {
		sessArg = &r.SessionID
	}
	if r.CaseID != "" {
		caseArg = &r.CaseID
	}
	err := p.pool.QueryRow(ctx, `
		INSERT INTO llm_records
			(session_id, case_id, kind, model, status, err,
			 tokens_in, tokens_out, duration_ms, prompt, response)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, created_at`,
		sessArg, caseArg, r.Kind, r.Model, r.Status, r.Err,
		r.TokensIn, r.TokensOut, r.DurationMs, r.Prompt, r.Response).
		Scan(&r.ID, &r.CreatedAt)
	if err != nil {
		return fmt.Errorf("LLM 录制落账失败: %w", err)
	}
	return nil
}

const llmRecordCols = `id, COALESCE(session_id::text, ''), COALESCE(case_id::text, ''),
	kind, model, status, err, tokens_in, tokens_out, duration_ms,
	prompt, response, created_at`

func scanLLMRecord(row interface{ Scan(...any) error }) (*LLMRecord, error) {
	var r LLMRecord
	err := row.Scan(&r.ID, &r.SessionID, &r.CaseID, &r.Kind, &r.Model,
		&r.Status, &r.Err, &r.TokensIn, &r.TokensOut, &r.DurationMs,
		&r.Prompt, &r.Response, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ListLLMRecords 录制清单(created_at 倒序;caseID 空=全部)。
// 返回切片 + 过滤后总数(分页用)。
func (p *PG) ListLLMRecords(ctx context.Context, caseID string,
	limit, offset int) ([]LLMRecord, int64, error) {

	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	where := ""
	args := []any{}
	if caseID != "" {
		where = "WHERE case_id = $1"
		args = append(args, caseID)
	}
	var total int64
	if err := p.pool.QueryRow(ctx,
		`SELECT count(*) FROM llm_records `+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("LLM 录制计数失败: %w", err)
	}
	args = append(args, limit, offset)
	rows, err := p.pool.Query(ctx, `
		SELECT `+llmRecordCols+` FROM llm_records `+where+`
		ORDER BY created_at DESC, id DESC
		LIMIT $`+fmt.Sprint(len(args)-1)+` OFFSET $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("LLM 录制清单查询失败: %w", err)
	}
	defer rows.Close()
	out := []LLMRecord{}
	for rows.Next() {
		r, err := scanLLMRecord(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("LLM 录制行解析失败: %w", err)
		}
		out = append(out, *r)
	}
	return out, total, rows.Err()
}

// GetLLMRecord 单条详情(nil = 无此记录;prompt/response 仅 full 档有值)。
func (p *PG) GetLLMRecord(ctx context.Context, id string) (*LLMRecord, error) {
	r, err := scanLLMRecord(p.pool.QueryRow(ctx,
		`SELECT `+llmRecordCols+` FROM llm_records WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("LLM 录制查询失败: %w", err)
	}
	return r, nil
}
