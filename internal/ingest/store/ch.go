// ClickHouse 事件库实现(native 协议,PrepareBatch 批量插入)。
package store

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	ch "github.com/ClickHouse/clickhouse-go/v2"

	"github.com/ye-mengwen/fengtu/internal/ingest"
)

// CH EventStore 的 ClickHouse 实现(内置双连接池,InsertEvents 并发安全——
// 管线异步插入器多路并发,§4.1「批量插入零单点」)。
type CH struct {
	conns []ch.Conn
	locks []sync.Mutex // 每连接一把:单连接同一时刻只有一个批
	next  atomic.Uint64
}

// NewCH 连接并 ping(addr 形如 host:9000)。compress: "lz4"(默认)| "none"
// (台架同机/内网链路上关压缩可省插入侧 CPU,网络带宽充足时净赚)。
func NewCH(ctx context.Context, addr, user, password, compress string) (*CH, error) {
	c := &CH{}
	for i := 0; i < 2; i++ {
		opts := &ch.Options{
			Addr: []string{addr},
			Auth: ch.Auth{
				Database: "fengtu",
				Username: user,
				Password: password,
			},
		}
		if compress == "none" {
			opts.Compression = &ch.Compression{Method: ch.CompressionNone}
		}
		conn, err := ch.Open(opts)
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("CH 连接配置失败: %w", err)
		}
		if err := conn.Ping(ctx); err != nil {
			c.Close()
			return nil, fmt.Errorf("CH 不可达: %w", err)
		}
		c.conns = append(c.conns, conn)
		c.locks = append(c.locks, sync.Mutex{})
	}
	return c, nil
}

// Close 关闭全部连接。
func (c *CH) Close() error {
	for _, conn := range c.conns {
		_ = conn.Close()
	}
	return nil
}

// InsertEvents 批量插入一批事件行(调用方控制批大小 ≥5 万,§4.1)。
// 并发安全:连接轮转 + 每连接互斥(单连接同一时刻只有一个批)。
//
// max_partitions_per_insert_block 放大到 10000:分区键 (case_id,
// toDate(ts)) 下,跨百日的单源日志(取证常态——真实案件包 41 个
// evtx 撞上默认 100 上限)会撑爆单块分区数。日粒度分区的总量隐忧
// (100 案件 × 365 天)如实记为遗留,后续版本再定夺粒度。
func (c *CH) InsertEvents(ctx context.Context, rows []ingest.EventRow) error {
	ctx = ch.Context(ctx, ch.WithSettings(ch.Settings{
		"max_partitions_per_insert_block": 10000,
	}))
	i := c.next.Add(1) % uint64(len(c.conns))
	c.locks[i].Lock()
	defer c.locks[i].Unlock()
	conn := c.conns[i]
	batch, err := conn.PrepareBatch(ctx,
		"INSERT INTO fengtu.events (case_id, source_id, line_no, ts, kind, fields, raw)")
	if err != nil {
		return fmt.Errorf("CH 批准备失败: %w", err)
	}
	for _, r := range rows {
		if err := batch.Append(
			r.CaseID, r.SourceID, uint32(r.LineNo), r.TS, r.Kind, r.Fields, r.Raw,
		); err != nil {
			return fmt.Errorf("CH 行追加失败(L%d): %w", r.LineNo, err)
		}
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("CH 批发送失败: %w", err)
	}
	return nil
}

var _ ingest.EventStore = (*CH)(nil)

// DeleteEventsForSource 删除一个源的全部事件(切片七重解析通路:
// 改判格式后「先删后插」的删。CH 用 ALTER TABLE DELETE 轻量删除的
// mutation 形态;mutations_sync=1 同步等落地——删完才允许重解析插入,
// 幂等语义才成立。这是管理面操作,不经只读检索层。
func (c *CH) DeleteEventsForSource(ctx context.Context, caseID, sourceID string) error {
	ctx = ch.Context(ctx, ch.WithSettings(ch.Settings{
		"mutations_sync": 1, // 同步等 mutation 落地(0=异步火忘,重解析会撞旧行)
	}))
	i := c.next.Add(1) % uint64(len(c.conns))
	c.locks[i].Lock()
	defer c.locks[i].Unlock()
	if err := c.conns[i].Exec(ctx,
		"ALTER TABLE fengtu.events DELETE WHERE case_id = ? AND source_id = ?",
		caseID, sourceID); err != nil {
		return fmt.Errorf("CH 源事件删除失败(重解析前置): %w", err)
	}
	return nil
}

// DeleteEventsForCase 删除一个案件的全部事件(0.18.0 案件删除级联;
// 与重解析同款同步 mutation——删完才回 200,不留半删态)。
func (c *CH) DeleteEventsForCase(ctx context.Context, caseID string) error {
	ctx = ch.Context(ctx, ch.WithSettings(ch.Settings{
		"mutations_sync": 1,
	}))
	i := c.next.Add(1) % uint64(len(c.conns))
	c.locks[i].Lock()
	defer c.locks[i].Unlock()
	if err := c.conns[i].Exec(ctx,
		"ALTER TABLE fengtu.events DELETE WHERE case_id = ?", caseID); err != nil {
		return fmt.Errorf("CH 案件事件删除失败(案件删除级联): %w", err)
	}
	return nil
}

// CountEventsForCase 案件事件总数(删除前的审计快照;只读口径)。
func (c *CH) CountEventsForCase(ctx context.Context, caseID string) (int64, error) {
	conn, release := c.acquireQueryConn()
	defer release()
	row := conn.QueryRow(readOnlyCtx(ctx),
		"SELECT count() FROM fengtu.events WHERE case_id = ?", caseID)
	var n uint64
	if err := row.Scan(&n); err != nil {
		return 0, fmt.Errorf("CH 案件事件计数失败: %w", err)
	}
	return int64(n), nil
}
