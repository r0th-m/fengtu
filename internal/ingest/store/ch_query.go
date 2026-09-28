// query.Querier 的 ClickHouse 实现(单一检索层的执行侧)。
//
// 只读与保险丝焊在会话级(DESIGN §4.2「先利用后限制」的落点):
//   - readonly=2:只读查询 + 允许 SET(写操作 CH 侧直接拒,双保险——
//     检索层 builder 本来就只产出 SELECT);
//   - max_execution_time / max_memory_usage:默认大方不阉割,爆了如实报。
package store

import (
	"context"
	"fmt"

	ch "github.com/ClickHouse/clickhouse-go/v2"

	"github.com/ye-mengwen/fengtu/internal/query"
)

// 查询保险丝(台架 15GB VM 口径;预算内跑不满是查询的问题,如实报错)。
var querySettings = ch.Settings{
	"readonly":            2,
	"max_execution_time":  60,
	"max_memory_usage":    uint64(4) << 30,
}

// acquireQueryConn 取连接并持锁(单连接同一时刻只有一个查询——
// 与批量插入同一纪律;调用方用返回的 release 在迭代完后放锁)。
func (c *CH) acquireQueryConn() (ch.Conn, func()) {
	i := c.next.Add(1) % uint64(len(c.conns))
	c.locks[i].Lock()
	return c.conns[i], func() { c.locks[i].Unlock() }
}

func readOnlyCtx(ctx context.Context) context.Context {
	return ch.Context(ctx, ch.WithSettings(querySettings))
}

// QueryEvents 分页检索(只读;结果整批返回,limit ≤1000 有界)。
func (c *CH) QueryEvents(ctx context.Context, sql string, args ...any) ([]query.Event, error) {
	conn, release := c.acquireQueryConn()
	defer release()
	rows, err := conn.Query(readOnlyCtx(ctx), sql, args...)
	if err != nil {
		return nil, fmt.Errorf("检索查询失败: %w", err)
	}
	defer rows.Close()
	var out []query.Event
	for rows.Next() {
		var e query.Event
		var lineNo uint32
		if err := rows.Scan(&e.SourceID, &lineNo, &e.TS, &e.Kind,
			&e.Fields, &e.Raw); err != nil {
			return nil, fmt.Errorf("检索行解析失败: %w", err)
		}
		e.LineNo = int(lineNo)
		out = append(out, e)
	}
	return out, rows.Err()
}

// StreamEvents 全量流式扫描(规则引擎用;行级回调,不驻留内存)。
func (c *CH) StreamEvents(ctx context.Context, sql string, args []any,
	fn func(query.Event) error) error {
	conn, release := c.acquireQueryConn()
	defer release()
	rows, err := conn.Query(readOnlyCtx(ctx), sql, args...)
	if err != nil {
		return fmt.Errorf("扫描查询失败: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var e query.Event
		var lineNo uint32
		if err := rows.Scan(&e.SourceID, &lineNo, &e.TS, &e.Kind,
			&e.Fields, &e.Raw); err != nil {
			return fmt.Errorf("扫描行解析失败: %w", err)
		}
		e.LineNo = int(lineNo)
		if err := fn(e); err != nil {
			return err
		}
	}
	return rows.Err()
}

// QueryStats 聚合统计(只读;桶上限由 builder 定死,结果整批有界)。
func (c *CH) QueryStats(ctx context.Context, sql string, args ...any) ([]query.StatRow, error) {
	conn, release := c.acquireQueryConn()
	defer release()
	rows, err := conn.Query(readOnlyCtx(ctx), sql, args...)
	if err != nil {
		return nil, fmt.Errorf("聚合查询失败: %w", err)
	}
	defer rows.Close()
	var out []query.StatRow
	for rows.Next() {
		var r query.StatRow
		var n uint64
		if err := rows.Scan(&r.Key, &n); err != nil {
			return nil, fmt.Errorf("聚合行解析失败: %w", err)
		}
		r.Count = int64(n)
		out = append(out, r)
	}
	return out, rows.Err()
}

var _ query.Querier = (*CH)(nil)
var _ query.StatsQuerier = (*CH)(nil)
