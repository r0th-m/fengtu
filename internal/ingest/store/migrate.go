// PG schema 迁移执行器:内嵌 migrations/*.sql(与 deploy/schema/pg/ 逐字节
// 一致,migrate_test.go 焊死防漂移),按文件名字典序幂等应用。
//
// 双入口纪律:
//   - 全新部署:docker initdb 顺序执行 deploy/schema/pg/*.sql;
//   - 既有库升级:fengtu server 启动时跑 Migrate(本文件)——
//     两条路产出同一 schema,焊死测试保证不漂移。
package store

import (
	"context"
	"embed"
	"fmt"
	"sort"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrate 应用未执行过的迁移(每个文件一个事务,已应用的跳过)。
func (p *PG) Migrate(ctx context.Context) error {
	if _, err := p.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			filename   TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("schema_migrations 建账失败: %w", err)
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("迁移目录读取失败: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		var applied bool
		err := p.pool.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE filename = $1)",
			name).Scan(&applied)
		if err != nil {
			return fmt.Errorf("迁移账目查询失败(%s): %w", name, err)
		}
		if applied {
			continue
		}
		sql, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("迁移读取失败(%s): %w", name, err)
		}
		tx, err := p.pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("迁移事务开启失败(%s): %w", name, err)
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("迁移执行失败(%s): %w", name, err)
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO schema_migrations (filename) VALUES ($1)", name); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("迁移记账失败(%s): %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("迁移提交失败(%s): %w", name, err)
		}
	}
	return nil
}
