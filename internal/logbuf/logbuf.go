// Package logbuf 平台运行日志的进程内环形缓冲(切片十,ARTEX system/logs
// 页的应急映射最小实现):main 的启动/运行输出 tee 一份进环形账,
// web 层 GET /api/logs 读最近 N 行(翻页用 before=seq 游标)。
// 如实边界:进程重启即清零(持久日志在 systemd journal,本页只看当前
// 进程);不解析级别,级别呈现由前端按行文本关键词标色(后端不猜)。
package logbuf

import (
	"strings"
	"sync"
	"time"
)

// Entry 一行日志。
type Entry struct {
	Seq  int64     `json:"seq"` // 单调递增,翻页游标(before=seq 取更早)
	TS   time.Time `json:"ts"`
	Line string    `json:"line"`
}

// Buffer 固定容量环形账(并发安全;io.Writer 按行切)。
type Buffer struct {
	mu      sync.Mutex
	cap     int
	entries []Entry // 逻辑环:物理追加,满则覆盖最老
	nextSeq int64
	partial string // 未换行的半截行(Write 按 \n 切,攒到完整才入账)
}

// New 容量 cap 的环形账(cap<=0 按 2000)。
func New(capacity int) *Buffer {
	if capacity <= 0 {
		capacity = 2000
	}
	return &Buffer{cap: capacity}
}

// Write 实现 io.Writer(tee 用):按行切,半截攒着;返回 len(p) 不拦主路。
func (b *Buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.partial += string(p)
	for {
		i := strings.IndexByte(b.partial, '\n')
		if i < 0 {
			break
		}
		b.appendLocked(strings.TrimRight(b.partial[:i], "\r"))
		b.partial = b.partial[i+1:]
	}
	return len(p), nil
}

// Add 直接落一行(main 不用 tee 时的显式入口)。
func (b *Buffer) Add(line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.appendLocked(line)
}

func (b *Buffer) appendLocked(line string) {
	if line == "" {
		return // 空行不入账(日志页只看有内容的行)
	}
	b.nextSeq++
	e := Entry{Seq: b.nextSeq, TS: time.Now(), Line: line}
	if len(b.entries) < b.cap {
		b.entries = append(b.entries, e)
		return
	}
	copy(b.entries, b.entries[1:])
	b.entries[b.cap-1] = e
}

// Tail 取最近 limit 行(seq 升序;before>0 = 只取 seq<before 的更早页)。
func (b *Buffer) Tail(limit int, before int64) []Entry {
	b.mu.Lock()
	defer b.mu.Unlock()
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	src := b.entries
	if before > 0 {
		// entries 物理升序:二分找 before 左界
		lo, hi := 0, len(src)
		for lo < hi {
			mid := (lo + hi) / 2
			if src[mid].Seq < before {
				lo = mid + 1
			} else {
				hi = mid
			}
		}
		src = src[:lo]
	}
	if len(src) > limit {
		src = src[len(src)-limit:]
	}
	out := make([]Entry, len(src))
	copy(out, src)
	return out
}
