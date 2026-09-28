// Package store 真库实现:PG(元数据账)+ ClickHouse(事件)。
// 单测不碰这里(fake 实现打全链);本包由台架实测验收。
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ye-mengwen/fengtu/internal/ingest"
)

// PG MetaStore 的 PostgreSQL 实现。
type PG struct {
	pool *pgxpool.Pool
}

// NewPG 连接并 ping(dsn 形如 postgres://user:pass@host:5432/fengtu)。
func NewPG(ctx context.Context, dsn string) (*PG, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("PG 连接配置失败: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("PG 不可达: %w", err)
	}
	return &PG{pool: pool}, nil
}

// Close 关闭连接池。
func (p *PG) Close() { p.pool.Close() }

// EnsureCase 案件名 → id(不存在则建;并发下同名归唯一约束)。
func (p *PG) EnsureCase(ctx context.Context, name string) (string, error) {
	var id string
	err := p.pool.QueryRow(ctx, `
		INSERT INTO cases (name) VALUES ($1)
		ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		RETURNING id`, name).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("cases 登记失败: %w", err)
	}
	return id, nil
}

// EnsureNewCase 永远建新案(0.27.0 案件封存/迁移导入专用):名撞加
// 「(导入)」后缀,再撞「(导入2)」类推。并发安全:逐名 INSERT ...
// ON CONFLICT DO NOTHING,撞名(含并发对撞)即试下一个,两个并发导入
// 永不并进同一案(与 EnsureCase 的归并语义相反,调用方别混用)。
func (p *PG) EnsureNewCase(ctx context.Context, baseName string) (id, name string, err error) {
	for n := 0; ; n++ {
		cand := baseName
		switch {
		case n == 1:
			cand = baseName + "(导入)"
		case n > 1:
			cand = fmt.Sprintf("%s(导入%d)", baseName, n)
		}
		err := p.pool.QueryRow(ctx, `
			INSERT INTO cases (name) VALUES ($1)
			ON CONFLICT (name) DO NOTHING
			RETURNING id`, cand).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			continue // 名撞(含并发对撞):试下一个后缀
		}
		if err != nil {
			return "", "", fmt.Errorf("cases 登记失败: %w", err)
		}
		return id, cand, nil
	}
}

// RegisterSource 登记源;(case_id, path) 冲突 = 同案同路径重复摄入,如实报错。
// 同 sha256 多路径不冲突(采集包内重复内容文件是常态,各登各的溯源链)。
func (p *PG) RegisterSource(ctx context.Context, s ingest.SourceInfo) (string, error) {
	var id string
	err := p.pool.QueryRow(ctx, `
		INSERT INTO sources (case_id, path, sha256, size_bytes, kind, artifact_type,
			log_type, host, package)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id`,
		s.CaseID, s.Path, s.SHA256, s.SizeBytes, string(s.Kind), s.ArtifactType,
		nilIfEmpty(s.LogType), s.Host, s.Package,
	).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return "", fmt.Errorf("同案同路径(%s)重复摄入,拒绝登记", s.Path)
		}
		return "", fmt.Errorf("sources 登记失败: %w", err)
	}
	return id, nil
}

// StartJob 开任务账(status=running)。
func (p *PG) StartJob(ctx context.Context, sourceID, caseID, parser string) (string, error) {
	var id string
	err := p.pool.QueryRow(ctx, `
		INSERT INTO ingest_jobs (source_id, case_id, status, parser)
		VALUES ($1, $2, 'running', $3)
		RETURNING id`, sourceID, caseID, parser).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("ingest_jobs 开账失败: %w", err)
	}
	return id, nil
}

// FinishJob 收尾任务账(行数/耗时/错误如实)。
func (p *PG) FinishJob(ctx context.Context, jobID string, f ingest.JobFinish) error {
	var errText *string
	if f.Err != "" {
		errText = &f.Err
	}
	var note *string
	if f.Note != "" {
		note = &f.Note
	}
	_, err := p.pool.Exec(ctx, `
		UPDATE ingest_jobs
		SET status = $2, rows_total = $3, rows_event = $4, rows_bad = $5,
		    rows_skip = $6, bytes_in = $7, finished_at = now(),
		    duration_ms = $8, error = $9, note = $10
		WHERE id = $1`,
		jobID, f.Status, f.RowsTotal, f.RowsEvent, f.RowsBad, f.RowsSkip,
		f.BytesIn, f.Duration.Milliseconds(), errText, note)
	if err != nil {
		return fmt.Errorf("ingest_jobs 收尾失败: %w", err)
	}
	return nil
}

// CountJobRows 台架对账用:查任务账目(非管线路径)。
func (p *PG) CountJobRows(ctx context.Context, jobID string) (total, event, bad, skip int64, err error) {
	err = p.pool.QueryRow(ctx, `
		SELECT rows_total, rows_event, rows_bad, rows_skip
		FROM ingest_jobs WHERE id = $1`, jobID).
		Scan(&total, &event, &bad, &skip)
	return
}

var _ ingest.MetaStore = (*PG)(nil)
