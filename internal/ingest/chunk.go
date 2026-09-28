// Package ingest 摄入管线(DESIGN §4.1):
// 文件 → 分块读取 → N 个解析 worker(= CPU 核数)→ 归一化 →
// ClickHouse 批量插入(每批 ≥5 万行)→ PG 登记案件/源/任务。
//
// 本文件是分块读取器:按目标字节数切原始字节流,块界对齐到
// 「换行符 + 多行块起始行」双重安全点——
//   - 字节块必须结束于换行(GBK/UTF-8 的多字节字符不会被拦腰,
//     0x0A 不可能是两者的尾随字节);
//   - 一个多行块(堆栈)不跨批次:每批尾部未闭合的块整体移交下一批,
//     引擎因此永远看到完整块,不产生假孤儿;
//   - 行号全程 1 起物理行号,跨批连续——events.line_no + source_id
//     即「主机+源+行」的溯源锚。
package ingest

import (
	"bufio"
	"errors"
	"io"

	"github.com/ye-mengwen/fengtu/internal/descform"
)

// Batch 一批物理行(已解码、通用换行切分、不含行尾换行符)。
type Batch struct {
	Lines      []string
	BaseLineNo int // Lines[0] 的原文物理行号(1 起)
}

// ChunkReader 流式分块读取器。
type ChunkReader struct {
	r            *bufio.Reader
	encoding     string
	isBlockStart func(string) bool
	target       int // 目标块字节数(未含换行对齐的溢出)

	carry     []string // 上批移交的未闭合多行块(含其起始行)
	carryBase int      // carry[0] 的物理行号
	lineNo    int      // 已切出的物理行总数(不含 carry 重计)
	carryB    int      // carry 的累计字节量(防爆上限用)
	eof       bool
	bytesIn   int64  // 已消费的原始字节数(含解码前)
	buf       []byte // 复用读缓冲(target+4MB 净空,换行对齐不再重分配)
}

// NewChunkReader 构造分块读取器。targetBytes 是目标块大小(如 64<<20);
// isBlockStart 判定一行是否多行块起始(无多行的格式传恒 true)。
func NewChunkReader(r io.Reader, encoding string,
	isBlockStart func(string) bool, targetBytes int) *ChunkReader {
	return &ChunkReader{
		r:            bufio.NewReaderSize(r, 4<<20),
		encoding:     encoding,
		isBlockStart: isBlockStart,
		target:       targetBytes,
		carryBase:    1,
	}
}

// BytesIn 已消费的原始字节数。
func (c *ChunkReader) BytesIn() int64 { return c.bytesIn }

// maxCarryFactor carry 防爆上限 = target × 该系数;超限强制切批,
// 块内续行由引擎如实标「孤儿续行块」(零静默,不丢数据)。
const maxCarryFactor = 4

// Next 取下一批;结束返回 io.EOF。
func (c *ChunkReader) Next() (*Batch, error) {
	for {
		buf, err := c.readChunk()
		if err != nil {
			return nil, err
		}
		if len(buf) == 0 && c.eof {
			if len(c.carry) == 0 {
				return nil, io.EOF
			}
			// 收尾:剩余 carry 即最后一批
			b := &Batch{Lines: c.carry, BaseLineNo: c.carryBase}
			c.carry = nil
			return b, nil
		}

		text, err := descform.DecodeBytes(buf, c.encoding)
		if err != nil {
			return nil, err
		}
		lines := descform.SplitLines(text)

		base := c.carryBase
		all := make([]string, 0, len(c.carry)+len(lines))
		all = append(all, c.carry...)
		all = append(all, lines...)
		c.lineNo += len(lines)

		if c.eof {
			c.carry = nil
			if len(all) == 0 {
				return nil, io.EOF
			}
			return &Batch{Lines: all, BaseLineNo: base}, nil
		}

		// 找最后一个安全切点:某行(非首行)是块起始。
		// 切点之后的行是未闭合的块,整体移交下一批。
		split := -1
		for i := len(all) - 1; i >= 1; i-- {
			if c.isBlockStart(all[i]) {
				split = i
				break
			}
		}
		if split == -1 {
			// 整批都是同一巨块的续行:继续攒;超防爆上限则强制切,
			// 引擎会把无宿主的续行如实标孤儿(零静默)。
			c.carry = all
			c.carryBase = base
			c.carryB += len(buf)
			if c.carryB > maxCarryFactor*c.target {
				c.carry = nil
				c.carryBase = c.lineNo + 1
				c.carryB = 0
				return &Batch{Lines: all, BaseLineNo: base}, nil
			}
			continue
		}
		c.carry = all[split:]
		c.carryBase = base + split
		c.carryB = 0
		emit := all[:split]
		if len(emit) == 0 {
			continue
		}
		return &Batch{Lines: emit, BaseLineNo: base}, nil
	}
}

// readChunk 读 ≈target 字节并对齐到换行符(含 \r\n 跨块的处理)。
// 缓冲跨块复用:解码产出的行是全新字符串,不复用缓冲区内容,安全。
func (c *ChunkReader) readChunk() ([]byte, error) {
	if c.eof {
		return nil, nil
	}
	if c.buf == nil {
		c.buf = make([]byte, 0, c.target+(4<<20))
	}
	buf := c.buf[:c.target]
	n, err := io.ReadFull(c.r, buf)
	buf = buf[:n]
	c.bytesIn += int64(n)
	switch {
	case errors.Is(err, io.EOF):
		c.eof = true
		return buf, nil
	case errors.Is(err, io.ErrUnexpectedEOF):
		// 不足 target:文件尾声,本块即末块
		c.eof = true
		return buf, nil
	case err != nil:
		return nil, err
	}
	// 对齐到换行:向后读到 \n 为止(0x0A 不可能是 UTF-8/GBK 尾随字节,
	// 字节级找换行不会切碎多字节字符)。
	for {
		b, err := c.r.ReadByte()
		if errors.Is(err, io.EOF) {
			c.eof = true
			break
		}
		if err != nil {
			return nil, err
		}
		buf = append(buf, b)
		c.bytesIn++
		if b == '\n' {
			break
		}
	}
	// \r\n 跨块:块恰好结束于 \r,把可能跟随的 \n 一并消费,
	// 否则下一批会以空行开头(行号不变但多出假空行)。
	if len(buf) > 0 && buf[len(buf)-1] == '\r' && !c.eof {
		if peek, err := c.r.Peek(1); err == nil && peek[0] == '\n' {
			b, _ := c.r.ReadByte()
			buf = append(buf, b)
			c.bytesIn++
		}
	}
	return buf, nil
}
