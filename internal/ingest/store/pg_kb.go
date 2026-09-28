// 启发式知识库的 PostgreSQL 实现(0.19.0-heuristic-kb,migrations/012_heuristic_kb.sql):
// 用户条目 CRUD(kb_entries)+ 内置条目启用态覆写(kb_builtin_state)。
// 0.27.1-kb-simplify:「启用」语义整体退役(生效以案件勾选为准)——
// kb_entries.enabled 列新写恒 true、存量原样保留;kb_builtin_state 表与
// SetBuiltinKBState/ListBuiltinKBStates 不再被业务面调用。表与列不急着删,
// 留待后续迁移清理,别再新建依赖。
package store

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/ye-mengwen/fengtu/internal/kb"
)

// ListUserKB 用户条目清单(创建序;API 呈现与注入合并共用)。
func (p *PG) ListUserKB(ctx context.Context) ([]*kb.Entry, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, title, content, applies_to, enabled, created_at, updated_at
		FROM kb_entries ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("知识库用户条目查询失败: %w", err)
	}
	defer rows.Close()
	out := []*kb.Entry{}
	for rows.Next() {
		var e kb.Entry
		if err := rows.Scan(&e.ID, &e.Title, &e.Content, &e.AppliesTo,
			&e.Enabled, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, fmt.Errorf("知识库条目行解析失败: %w", err)
		}
		e.Source = kb.SourceUser
		out = append(out, &e)
	}
	return out, rows.Err()
}

// CreateKB 用户条目落库(id/created_at/updated_at 回写)。
func (p *PG) CreateKB(ctx context.Context, e *kb.Entry) error {
	err := p.pool.QueryRow(ctx, `
		INSERT INTO kb_entries (title, content, applies_to, enabled, created_by)
		VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at, updated_at`,
		e.Title, e.Content, e.AppliesTo, e.Enabled, e.CreatedBy).
		Scan(&e.ID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		return fmt.Errorf("知识库条目落库失败: %w", err)
	}
	e.Source = kb.SourceUser
	return nil
}

// UpdateKB 改用户条目(ok=false=无此条目;updated_at 现写)。
func (p *PG) UpdateKB(ctx context.Context, e *kb.Entry) (bool, error) {
	tag, err := p.pool.Exec(ctx, `
		UPDATE kb_entries SET title = $2, content = $3, applies_to = $4,
			enabled = $5, updated_at = now()
		WHERE id = $1`, e.ID, e.Title, e.Content, e.AppliesTo, e.Enabled)
	if err != nil {
		return false, fmt.Errorf("知识库条目更新失败: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return false, nil
	}
	// 回读 updated_at(注入截断排序/UI 呈现用)
	_ = p.pool.QueryRow(ctx, `SELECT updated_at FROM kb_entries WHERE id = $1`,
		e.ID).Scan(&e.UpdatedAt)
	return true, nil
}

// DeleteKB 删用户条目(ok=false=无此条目;硬删,历史在审计链)。
// 同事务连带清各案勾选行(entry_id 是文本无外键,勾选行不连带会成死引用——
// 交集语义下死引用自然不注入,但账要干净)。
func (p *PG) DeleteKB(ctx context.Context, id string) (bool, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("知识库条目删除事务开启失败: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`DELETE FROM case_kb_entries WHERE entry_id = $1`, id); err != nil {
		return false, fmt.Errorf("案件勾选连带清理失败: %w", err)
	}
	tag, err := tx.Exec(ctx, `DELETE FROM kb_entries WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("知识库条目删除失败: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("知识库条目删除事务提交失败: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// SetBuiltinKBState 内置条目启用态覆写(upsert;返回现写 updated_at)。
func (p *PG) SetBuiltinKBState(ctx context.Context, id string, enabled bool) (time.Time, error) {
	var at time.Time
	err := p.pool.QueryRow(ctx, `
		INSERT INTO kb_builtin_state (id, enabled) VALUES ($1, $2)
		ON CONFLICT (id) DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = now()
		RETURNING updated_at`, id, enabled).Scan(&at)
	if err != nil {
		return at, fmt.Errorf("内置条目启用态覆写失败: %w", err)
	}
	return at, nil
}

// ListBuiltinKBStates 内置条目启用态覆写清单(只列显式覆写过的;未覆写=YAML 默认)。
func (p *PG) ListBuiltinKBStates(ctx context.Context) (map[string]bool, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, enabled FROM kb_builtin_state`)
	if err != nil {
		return nil, fmt.Errorf("内置条目启用态查询失败: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		var en bool
		if err := rows.Scan(&id, &en); err != nil {
			return nil, fmt.Errorf("内置条目启用态行解析失败: %w", err)
		}
		out[id] = en
	}
	return out, rows.Err()
}

// ---- 案件级 KB 勾选(0.20.0-case-kb,migrations/013_case_kb.sql) ----

// ListCaseKB 本案勾选的条目 id 集(创建序;无记录=空集,如实不注入)。
func (p *PG) ListCaseKB(ctx context.Context, caseID string) ([]string, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT entry_id FROM case_kb_entries
		WHERE case_id = $1 ORDER BY created_at, entry_id`, caseID)
	if err != nil {
		return nil, fmt.Errorf("案件 KB 勾选查询失败: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("案件 KB 勾选行解析失败: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// SetCaseKB 本案勾选集整体覆写(单事务:清旧插新;返回勾选差集 added/removed,
// 审计 kb.case_update 记账用)。入参假定已由 kb.Service 校验(已知条目+去重)。
func (p *PG) SetCaseKB(ctx context.Context, caseID, actor string, ids []string) (added, removed []string, err error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("案件 KB 勾选事务开启失败: %w", err)
	}
	defer tx.Rollback(ctx)

	oldRows, err := tx.Query(ctx,
		`SELECT entry_id FROM case_kb_entries WHERE case_id = $1`, caseID)
	if err != nil {
		return nil, nil, fmt.Errorf("案件 KB 旧勾选查询失败: %w", err)
	}
	oldSet := map[string]bool{}
	for oldRows.Next() {
		var id string
		if err := oldRows.Scan(&id); err != nil {
			oldRows.Close()
			return nil, nil, fmt.Errorf("案件 KB 旧勾选行解析失败: %w", err)
		}
		oldSet[id] = true
	}
	oldRows.Close()

	if _, err := tx.Exec(ctx,
		`DELETE FROM case_kb_entries WHERE case_id = $1`, caseID); err != nil {
		return nil, nil, fmt.Errorf("案件 KB 旧勾选清除失败: %w", err)
	}
	newSet := map[string]bool{}
	for _, id := range ids {
		newSet[id] = true
		if _, err := tx.Exec(ctx, `
			INSERT INTO case_kb_entries (case_id, entry_id, chosen_by)
			VALUES ($1, $2, $3)`, caseID, id, actor); err != nil {
			return nil, nil, fmt.Errorf("案件 KB 勾选落库失败(%s): %w", id, err)
		}
	}
	for id := range newSet {
		if !oldSet[id] {
			added = append(added, id)
		}
	}
	for id := range oldSet {
		if !newSet[id] {
			removed = append(removed, id)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("案件 KB 勾选事务提交失败: %w", err)
	}
	return added, removed, nil
}
