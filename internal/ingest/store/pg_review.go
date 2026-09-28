// review.Store 的 PostgreSQL 实现(待审区:候选/轮次/裁决)。
package store

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ye-mengwen/fengtu/internal/review"
)

// scanLockSeed advisory lock 种子(与审计锁错开)。
const scanLockSeed = 913

func scanLockKey(caseID string) int64 {
	h := fnv.New64a()
	h.Write([]byte(caseID))
	return int64(h.Sum64()&0x7fffffffffffffff) + scanLockSeed
}

// CreateScanRun 开一轮扫描(锁内 max+1:并发同案扫描不撞轮次)。
func (p *PG) CreateScanRun(ctx context.Context, caseID, actor, ruleIDsJSON string,
	_ time.Time) (string, int, error) {

	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return "", 0, fmt.Errorf("扫描轮次事务开启失败: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)",
		scanLockKey(caseID)); err != nil {
		return "", 0, fmt.Errorf("扫描轮次锁获取失败: %w", err)
	}
	var round int
	err = tx.QueryRow(ctx,
		"SELECT COALESCE(MAX(round_no), 0) + 1 FROM scan_runs WHERE case_id = $1",
		caseID).Scan(&round)
	if err != nil {
		return "", 0, fmt.Errorf("扫描轮次查询失败: %w", err)
	}
	var id string
	err = tx.QueryRow(ctx, `
		INSERT INTO scan_runs (case_id, round_no, rule_ids_json, actor)
		VALUES ($1, $2, $3, $4) RETURNING id`,
		caseID, round, nilIfEmpty(ruleIDsJSON), actor).Scan(&id)
	if err != nil {
		return "", 0, fmt.Errorf("扫描轮次开账失败: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", 0, fmt.Errorf("扫描轮次提交失败: %w", err)
	}
	return id, round, nil
}

// InsertHit 落候选(唯一约束去重:inserted=false = 重跑命中旧候选)。
func (p *PG) InsertHit(ctx context.Context, h review.Hit, _ time.Time) (bool, error) {
	if h.EvidenceGrade == "" {
		h.EvidenceGrade = "suspect" // 缺省档(签名族语义),不空写(NOT NULL)
	}
	tag, err := p.pool.Exec(ctx, `
		INSERT INTO hits (case_id, source_id, line_no, rule_id, severity,
			matched_field, matched_value, snippet, ts_utc, status,
			round_no, evidence_grade, detail_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', $10, $11, $12)
		ON CONFLICT (source_id, line_no, rule_id) DO NOTHING`,
		h.CaseID, h.SourceID, h.LineNo, h.RuleID, h.Severity,
		h.MatchedField, h.MatchedValue, h.Snippet, h.TsUTC,
		h.RoundNo, h.EvidenceGrade, h.DetailJSON)
	if err != nil {
		return false, fmt.Errorf("候选落库失败: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// FinishScanRun 收尾轮次摘要。
func (p *PG) FinishScanRun(ctx context.Context, runID, summaryJSON string) error {
	_, err := p.pool.Exec(ctx,
		"UPDATE scan_runs SET summary_json = $2 WHERE id = $1", runID, summaryJSON)
	if err != nil {
		return fmt.Errorf("扫描轮次收尾失败: %w", err)
	}
	return nil
}

const hitCols = `id, case_id, source_id, line_no, rule_id, severity,
	matched_field, matched_value, snippet, ts_utc, status, round_no,
	evidence_grade, COALESCE(detail_json, ''), created_at,
	COALESCE(reviewed_by, ''), reviewed_at, COALESCE(review_note, '')`

func scanHit(row interface{ Scan(...any) error }) (*review.Hit, error) {
	var h review.Hit
	var reviewedAt *time.Time
	err := row.Scan(&h.ID, &h.CaseID, &h.SourceID, &h.LineNo, &h.RuleID,
		&h.Severity, &h.MatchedField, &h.MatchedValue, &h.Snippet, &h.TsUTC,
		&h.Status, &h.RoundNo, &h.EvidenceGrade, &h.DetailJSON, &h.CreatedAt,
		&h.ReviewedBy, &reviewedAt, &h.ReviewNote)
	if err != nil {
		return nil, err
	}
	h.ReviewedAt = reviewedAt
	return &h, nil
}

// ListHits 待审区查询(case 内,按创建序;status/round 过滤)。
func (p *PG) ListHits(ctx context.Context, caseID string, f review.HitFilter) ([]review.Hit, error) {
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	q := "SELECT " + hitCols + " FROM hits WHERE case_id = $1"
	args := []any{caseID}
	n := 1
	if f.Status != "" {
		n++
		q += fmt.Sprintf(" AND status = $%d", n)
		args = append(args, f.Status)
	}
	if f.Round != 0 {
		n++
		q += fmt.Sprintf(" AND round_no = $%d", n)
		args = append(args, f.Round)
	}
	if len(f.SourceIDs) > 0 {
		q += fmt.Sprintf(" AND source_id IN (")
		for i, sid := range f.SourceIDs {
			if i > 0 {
				q += ", "
			}
			n++
			q += fmt.Sprintf("$%d", n)
			args = append(args, sid)
		}
		q += ")"
	}
	q += fmt.Sprintf(" ORDER BY created_at, id LIMIT %d OFFSET %d", limit, f.Offset)
	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("待审区查询失败: %w", err)
	}
	defer rows.Close()
	var out []review.Hit
	for rows.Next() {
		h, err := scanHit(rows)
		if err != nil {
			return nil, fmt.Errorf("候选行解析失败: %w", err)
		}
		out = append(out, *h)
	}
	return out, rows.Err()
}

// GetHit 按 id 取候选(无则 nil,nil;非法 UUID 形态按无此候选如实处理)。
func (p *PG) GetHit(ctx context.Context, id string) (*review.Hit, error) {
	h, err := scanHit(p.pool.QueryRow(ctx,
		"SELECT "+hitCols+" FROM hits WHERE id = $1", id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) || isBadUUID(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("候选查询失败: %w", err)
	}
	return h, nil
}

// isBadUUID PG 22P02(非法 UUID 文本)——语义上是「无此候选」而非系统错。
func isBadUUID(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "22P02"
}

// SetVerdict 人裁决落账(CAS:仅 pending 可裁决——并发第二人 UPDATE 命中
// 0 行,引擎侧回查区分 404/409;裁决一次性,不再允许静默改判)。
func (p *PG) SetVerdict(ctx context.Context, id, actor, status, note string,
	now time.Time) (bool, error) {
	tag, err := p.pool.Exec(ctx, `
		UPDATE hits SET status = $2, reviewed_by = $3, reviewed_at = $4,
			review_note = $5
		WHERE id = $1 AND status = 'pending'`,
		id, status, actor, now, nilIfEmpty(note))
	if err != nil {
		return false, fmt.Errorf("裁决落库失败: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ListScanRuns 轮次台账(倒序,最新在前)。
func (p *PG) ListScanRuns(ctx context.Context, caseID string) ([]review.ScanRun, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, case_id, round_no, COALESCE(rule_ids_json, ''), actor,
			COALESCE(summary_json, ''), created_at
		FROM scan_runs WHERE case_id = $1 ORDER BY round_no DESC`, caseID)
	if err != nil {
		return nil, fmt.Errorf("轮次台账查询失败: %w", err)
	}
	defer rows.Close()
	var out []review.ScanRun
	for rows.Next() {
		var r review.ScanRun
		if err := rows.Scan(&r.ID, &r.CaseID, &r.RoundNo, &r.RuleIDsJSON,
			&r.Actor, &r.SummaryJSON, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("轮次行解析失败: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListSourcesForScan 适用域路由的源清单(kind text|evtx——raw 源无事件,
// 不参与路由也不计「按域跳过」,账目口径如实)。
func (p *PG) ListSourcesForScan(ctx context.Context, caseID string) ([]review.ScanSource, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, kind, COALESCE(log_type, ''), COALESCE(artifact_type, ''), host
		FROM sources WHERE case_id = $1
			AND (kind IN ('text', 'evtx') OR log_type IS NOT NULL)
		ORDER BY created_at, id`, caseID)
	if err != nil {
		return nil, fmt.Errorf("算子路由源清单查询失败: %w", err)
	}
	defer rows.Close()
	var out []review.ScanSource
	for rows.Next() {
		var s review.ScanSource
		if err := rows.Scan(&s.ID, &s.Kind, &s.LogType, &s.ArtifactType, &s.Host); err != nil {
			return nil, fmt.Errorf("源行解析失败: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// RuleStatsRaw 按规则聚合窗口内候选/裁决计数(接受率/待复审闸在引擎算)。
func (p *PG) RuleStatsRaw(ctx context.Context, caseID string,
	since time.Time) ([]review.RuleStat, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT rule_id, count(*),
			count(*) FILTER (WHERE status = 'accepted'),
			count(*) FILTER (WHERE status = 'rejected'),
			count(*) FILTER (WHERE status = 'pending')
		FROM hits WHERE case_id = $1 AND created_at >= $2
		GROUP BY rule_id ORDER BY rule_id`, caseID, since)
	if err != nil {
		return nil, fmt.Errorf("规则统计查询失败: %w", err)
	}
	defer rows.Close()
	var out []review.RuleStat
	for rows.Next() {
		var st review.RuleStat
		if err := rows.Scan(&st.RuleID, &st.Candidates, &st.Accepted,
			&st.Rejected, &st.Pending); err != nil {
			return nil, fmt.Errorf("规则统计行解析失败: %w", err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

var _ review.Store = (*PG)(nil)
