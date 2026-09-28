// 审计哈希链的 PostgreSQL 实现:追加持 advisory xact lock 串行化
// (读末哈希 + 写新条同事务,索图 _APPEND_LOCK 竞态教训);seq 取
// MAX+1(锁内无竞态;不依赖 BIGSERIAL 递增值,回滚不留洞账)。
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ye-mengwen/fengtu/internal/audit"
)

// auditLockKey advisory lock 键(全库审计追加串行)。
const auditLockKey = 862601

// AppendAudit 追加一条审计(链式哈希;detail 任意可 JSON 化值,
// 落库为 canonical JSON——Go encoding/json 对 map 键排序,哈希可重算)。
// caseID 空串 = 无案件上下文。返回条目的 seq 与 entry_hash。
func (p *PG) AppendAudit(ctx context.Context, caseID, actor, action, scope string,
	detail any) (int64, string, error) {

	detailJSON := ""
	if detail != nil {
		b, err := json.Marshal(detail)
		if err != nil {
			return 0, "", fmt.Errorf("审计 detail 序列化失败: %w", err)
		}
		detailJSON = string(b)
	}
	// timestamptz 精度 = 微秒:纳秒截断落库,哈希输入必须与读回值一致
	// (否则全链重算时 ts 呈现不同,链对账假断——台架实测踩坑)
	ts := time.Now().UTC().Truncate(time.Microsecond)

	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return 0, "", fmt.Errorf("审计事务开启失败: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", auditLockKey); err != nil {
		return 0, "", fmt.Errorf("审计锁获取失败: %w", err)
	}
	var seq int64
	var prevHash string
	err = tx.QueryRow(ctx,
		"SELECT COALESCE(MAX(seq), 0) + 1 FROM audit_chain").Scan(&seq)
	if err != nil {
		return 0, "", fmt.Errorf("审计序号查询失败: %w", err)
	}
	err = tx.QueryRow(ctx,
		"SELECT COALESCE((SELECT entry_hash FROM audit_chain ORDER BY seq DESC LIMIT 1), '')").
		Scan(&prevHash)
	if err != nil {
		return 0, "", fmt.Errorf("审计末哈希查询失败: %w", err)
	}
	if prevHash == "" {
		prevHash = audit.Genesis
	}
	entryHash := audit.ComputeHash(seq, caseID, ts, actor, action, scope,
		detailJSON, prevHash)

	var caseArg *string
	if caseID != "" {
		caseArg = &caseID
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO audit_chain (seq, case_id, ts, actor, action, scope,
			detail_json, prev_hash, entry_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		seq, caseArg, ts, actor, action, nilIfEmpty(scope),
		nilIfEmpty(detailJSON), prevHash, entryHash)
	if err != nil {
		return 0, "", fmt.Errorf("审计落账失败: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, "", fmt.Errorf("审计提交失败: %w", err)
	}
	return seq, entryHash, nil
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ListAudit 按案件取链(caseID 空 = 全量;seq 升序)。
func (p *PG) ListAudit(ctx context.Context, caseID string, limit int) ([]audit.Entry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	var rows pgx.Rows
	var err error
	if caseID == "" {
		rows, err = p.pool.Query(ctx, `
			SELECT seq, COALESCE(case_id::text, ''), ts, actor, action,
				COALESCE(scope, ''), COALESCE(detail_json, ''),
				prev_hash, entry_hash
			FROM audit_chain ORDER BY seq LIMIT $1`, limit)
	} else {
		rows, err = p.pool.Query(ctx, `
			SELECT seq, COALESCE(case_id::text, ''), ts, actor, action,
				COALESCE(scope, ''), COALESCE(detail_json, ''),
				prev_hash, entry_hash
			FROM audit_chain WHERE case_id = $1 ORDER BY seq LIMIT $2`, caseID, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("审计查询失败: %w", err)
	}
	defer rows.Close()
	var out []audit.Entry
	for rows.Next() {
		var e audit.Entry
		if err := rows.Scan(&e.Seq, &e.CaseID, &e.TS, &e.Actor, &e.Action,
			&e.Scope, &e.DetailJSON, &e.PrevHash, &e.EntryHash); err != nil {
			return nil, fmt.Errorf("审计行解析失败: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AllAudit 全链(校验用;量随时间涨,校验本身是显式运维动作)。
func (p *PG) AllAudit(ctx context.Context) ([]audit.Entry, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT seq, COALESCE(case_id::text, ''), ts, actor, action,
			COALESCE(scope, ''), COALESCE(detail_json, ''),
			prev_hash, entry_hash
		FROM audit_chain ORDER BY seq`)
	if err != nil {
		return nil, fmt.Errorf("审计全链查询失败: %w", err)
	}
	defer rows.Close()
	var out []audit.Entry
	for rows.Next() {
		var e audit.Entry
		if err := rows.Scan(&e.Seq, &e.CaseID, &e.TS, &e.Actor, &e.Action,
			&e.Scope, &e.DetailJSON, &e.PrevHash, &e.EntryHash); err != nil {
			return nil, fmt.Errorf("审计行解析失败: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
