// 管线核心:批次源 → N worker 解析 → 归一 → 批量插入(DESIGN §4.1)。
//
// 并发模型(无共享状态,背压自然):
//
//	批次源(单 reader) --批--> workers(N=CPU) --行--> 聚合器 --≥5万行--> CH
//
// 任何一环慢都会向上游传导阻塞,内存驻留有界(通道容量 × 批次大小)。
// worker 内零分配共享:每 worker 独立的 JSON 编码缓冲。
//
// 存储是接口:MetaStore(PG 案件/源/任务账)+ EventStore(CH 事件)。
// 单测用 fake 实现打全链;真库实现在 store/ 子包,台架实测。
package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"iter"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/ye-mengwen/fengtu/internal/descform"
	"github.com/ye-mengwen/fengtu/internal/entity"
	"github.com/ye-mengwen/fengtu/internal/model"
)

// EventRow 一行事件(CH events 表的行投影)。
type EventRow struct {
	CaseID   string
	SourceID string
	LineNo   int
	TS       *time.Time
	Kind     string
	Fields   string // 归一字段 JSON(bad 行含 reason)
	Raw      string
}

// SourceInfo PG sources 登记信息。
type SourceInfo struct {
	CaseID       string
	Path         string
	SHA256       string
	SizeBytes    int64
	Kind         Kind
	ArtifactType string
	LogType      string // 源品类(绑定即知:内置/desc 声明/evtx 原生;空=无品类)
	Host         string // 主机键(一案多包,包根目录名经 host_regex 提取;空=未建模)
	Package      string // 采集包登记根名(空=散件/单文件上传)
}

// JobFinish 任务收尾账目。
type JobFinish struct {
	Status    string // done | failed
	RowsTotal int64
	RowsEvent int64
	RowsBad   int64
	RowsSkip  int64
	BytesIn   int64
	Duration  time.Duration
	Err       string
	Note      string
}

// MetaStore 元数据账(PG)。
type MetaStore interface {
	EnsureCase(ctx context.Context, name string) (caseID string, err error)
	RegisterSource(ctx context.Context, s SourceInfo) (sourceID string, err error)
	StartJob(ctx context.Context, sourceID, caseID, parser string) (jobID string, err error)
	FinishJob(ctx context.Context, jobID string, f JobFinish) error
}

// EventStore 事件库(CH)。
type EventStore interface {
	InsertEvents(ctx context.Context, rows []EventRow) error
}

// EntitySink 实体落库(0.25.0-datasource-unlock):PG 实现见
// store/pg_entity.go。MetaStore 实现该接口时,管线在事件插入成功后
// 从事件字段抽实体落 PG 实体表(接口断言接入,不实现 = 不抽,如实)。
type EntitySink interface {
	InsertEntities(ctx context.Context, rows []entity.Row) error
}

// ParseFunc 与 descform 引擎同形的解析驱动(物理行 → 记录流)。
type ParseFunc func(lines []string) iter.Seq[model.Record]

// BatchSource 批次来源(文本分块 / jsonl 定长批)。
type BatchSource interface {
	Next() (*Batch, error)
}

// WorkItem 一个工作单元:Lines 是待解析原料(文本/jsonl 路径),
// Recs 是已解析记录(原生解析器路径,如 evtx 纯 Go 库)——二选一。
// BaseLineNo 是首个元素的原文物理行号/事件序(1 起),溯源锚。
type WorkItem struct {
	Lines      []string
	Recs       []model.Record
	BaseLineNo int
}

// WorkSource 工作单元来源(管线并行的最小抽象:
// 生产者单线程出单元,worker 池消费——解析在 worker 内做)。
type WorkSource interface {
	Next() (*WorkItem, error)
}

// batchWorkSource 文本/jsonl 路径适配:原料行交给 worker 内 parse。
type batchWorkSource struct{ src BatchSource }

func (s *batchWorkSource) Next() (*WorkItem, error) {
	b, err := s.src.Next()
	if err != nil {
		return nil, err
	}
	return &WorkItem{Lines: b.Lines, BaseLineNo: b.BaseLineNo}, nil
}

// AsWorkSource 把 BatchSource 包装为 WorkSource(文本路径)。
func AsWorkSource(src BatchSource) WorkSource { return &batchWorkSource{src} }

// Spec 一次文件摄入的参数。
type Spec struct {
	CaseName    string
	Path        string // 源文件路径(实际打开/哈希用)
	DisplayPath string // 登记进 sources.path 的路径(空 = 用 Path;
	// 上传接入场景:实际打开的是金库路径,登记要留客户端原文件名/包内相对路径)
	ParserLabel  string // desc:<name> / builtin:<name> / evtx_native / raw
	Kind         Kind
	ArtifactType string
	LogType      string // 源品类(适用域路由键;绑定即知的格式在此落)
	Host         string // 主机键(包摄入时由映射表 host_regex 提取)
	Package      string // 采集包登记根名(包摄入时填;散件空)
	TZDeclared   string // 源声明时区;空 = 不归一(nil 如实)
	Workers      int    // 0 → CPU 核数
	BatchRows    int    // CH 批量插入阈值;0 → 50000(§4.1 下限)
	ChunkBytes   int    // 文本分块目标字节;0 → 64MB(§4.1 下限)
}

// Stats 一次摄入的账(与 PG ingest_jobs 对应)。
type Stats struct {
	Events, Bad, Skip, Total int64
	BytesIn                  int64
	Duration                 time.Duration
}

func (s *Spec) withDefaults() {
	if s.Workers <= 0 {
		s.Workers = runtime.NumCPU()
	}
	if s.BatchRows <= 0 {
		s.BatchRows = 50000
	}
	if s.ChunkBytes <= 0 {
		s.ChunkBytes = 64 << 20
	}
}

// HashFile 流式计算文件 SHA256 与大小(证据链锚点)。
func HashFile(path string) (sum string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	size, err = io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

// regPath 登记用路径(DisplayPath 优先,空则实际路径)。
func (s *Spec) regPath() string {
	if s.DisplayPath != "" {
		return s.DisplayPath
	}
	return s.Path
}

// recordToRow 归一记录 → CH 行(ts 归一 + fields JSON + 行号重基)。
// buf 是 worker 私有编码缓冲(复用,零分配热路径)。
func recordToRow(rec *model.Record, tzDeclared string, buf *[]byte) EventRow {
	ts := descform.ResolveTsUTC(rec.DTLocal, tzDeclared, rec.TsUTCDirect)
	fields := rec.Norm
	if fields == nil {
		fields = map[string]any{}
	}
	if rec.Kind != model.KindEvent && rec.Reason != nil {
		// bad/skip 行:原因进 fields 留证(零静默,消费侧可查)
		fields = map[string]any{"reason": *rec.Reason}
	}
	*buf = appendFieldsJSON((*buf)[:0], fields)
	return EventRow{
		LineNo: rec.LineNo,
		TS:     ts,
		Kind:   rec.Kind,
		Fields: string(*buf),
		Raw:    rec.Raw,
	}
}

// Ingest 跑一条文件的完整摄入链:登记 → 解析 → 插入 → 记账。
// source 提供工作单元,parse 驱动原料行解析(Recs 路径不用,可 nil)。
func Ingest(ctx context.Context, meta MetaStore, events EventStore,
	spec Spec, source WorkSource, parse ParseFunc) (*Stats, error) {
	spec.withDefaults()
	start := time.Now()

	sum, size, err := HashFile(spec.Path)
	if err != nil {
		return nil, fmt.Errorf("原文哈希失败: %w", err)
	}
	caseID, err := meta.EnsureCase(ctx, spec.CaseName)
	if err != nil {
		return nil, fmt.Errorf("案件登记失败: %w", err)
	}
	sourceID, err := meta.RegisterSource(ctx, SourceInfo{
		CaseID: caseID, Path: spec.regPath(), SHA256: sum, SizeBytes: size,
		Kind: spec.Kind, ArtifactType: spec.ArtifactType, LogType: spec.LogType,
		Host: spec.Host, Package: spec.Package,
	})
	if err != nil {
		return nil, fmt.Errorf("源登记失败: %w", err)
	}
	jobID, err := meta.StartJob(ctx, sourceID, caseID, spec.ParserLabel)
	if err != nil {
		return nil, fmt.Errorf("任务登记失败: %w", err)
	}

	stats, runErr := runPipeline(ctx, events, entitySinkOf(meta), spec, caseID, sourceID, source, parse)
	stats.BytesIn = size
	stats.Duration = time.Since(start)

	fin := JobFinish{
		Status: "done", RowsTotal: stats.Total, RowsEvent: stats.Events,
		RowsBad: stats.Bad, RowsSkip: stats.Skip, BytesIn: stats.BytesIn,
		Duration: stats.Duration,
		Note: fmt.Sprintf("workers=%d batch_rows=%d chunk_bytes=%d",
			spec.Workers, spec.BatchRows, spec.ChunkBytes),
	}
	if runErr != nil {
		fin.Status = "failed"
		fin.Err = runErr.Error()
	}
	if ferr := meta.FinishJob(ctx, jobID, fin); ferr != nil && runErr == nil {
		runErr = fmt.Errorf("任务收尾记账失败: %w", ferr)
	}
	return stats, runErr
}

// runPipeline 纯计算链(登记之外的解析+插入),供 Ingest 与单测复用。
// sink 非 nil 时,事件行聚合的同时抽实体(键级去重,锚点保首见),
// 事件插入全部成功后批量落 PG(失败如实上抛,任务记 failed)。
//
// 并发模型(DESIGN §4.1「全部 IO 异步化、批量插入零单点」):
//
//	WorkSource(单 reader) → workers(N) 解析/建行 → 聚合 → 切片
//		→ insertCh → inserter×2 异步批量插入(插入不再堵聚合)
func runPipeline(ctx context.Context, events EventStore, sink EntitySink, spec Spec,
	caseID, sourceID string, source WorkSource, parse ParseFunc) (*Stats, error) {

	items := make(chan *WorkItem, spec.Workers*2)
	rowGroups := make(chan []EventRow, spec.Workers*2)

	// 单元生产者
	prodErr := make(chan error, 1)
	go func() {
		defer close(items)
		for {
			it, err := source.Next()
			if err == io.EOF {
				return
			}
			if err != nil {
				prodErr <- err
				return
			}
			select {
			case items <- it:
			case <-ctx.Done():
				prodErr <- ctx.Err()
				return
			}
		}
	}()

	// 解析/建行 workers
	var wg sync.WaitGroup
	for w := 0; w < spec.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 0, 8192)
			for it := range items {
				var rows []EventRow
				if it.Recs != nil { // 原生解析器路径:记录已就绪
					rows = make([]EventRow, 0, len(it.Recs))
					for i := range it.Recs {
						rec := it.Recs[i]
						rec.LineNo += it.BaseLineNo - 1
						row := recordToRow(&rec, spec.TZDeclared, &buf)
						row.CaseID = caseID
						row.SourceID = sourceID
						rows = append(rows, row)
					}
				} else { // 原料行路径:worker 内 parse
					rows = make([]EventRow, 0, len(it.Lines))
					for rec := range parse(it.Lines) {
						rec.LineNo += it.BaseLineNo - 1 // 重基到全文件物理行号
						row := recordToRow(&rec, spec.TZDeclared, &buf)
						row.CaseID = caseID
						row.SourceID = sourceID
						rows = append(rows, row)
					}
				}
				select {
				case rowGroups <- rows:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(rowGroups)
	}()

	// 异步插入器(双路,批量插入零单点;CH 实现内部连接池并发安全)
	insertCh := make(chan []EventRow, 4)
	insertErr := make(chan error, 2)
	var iwg sync.WaitGroup
	for i := 0; i < 2; i++ {
		iwg.Add(1)
		go func() {
			defer iwg.Done()
			for batch := range insertCh {
				if err := events.InsertEvents(ctx, batch); err != nil {
					select {
					case insertErr <- fmt.Errorf("批量插入失败(批 %d 行): %w",
						len(batch), err):
					default:
					}
					// 出错后继续排空(错误已记,聚合侧不能堵死)
					continue
				}
			}
		}()
	}

	// 聚合 + 严格按 BatchRows 切片(一个分块可能远超批量阈值,
	// 整批塞入会造成单批数十万行的大插入与内存尖峰——台架实测教训)
	stats := &Stats{}
	pending := make([]EventRow, 0, spec.BatchRows*2)
	flushN := func(n int) {
		if n == 0 {
			return
		}
		batch := make([]EventRow, n)
		copy(batch, pending[:n])
		insertCh <- batch
		copy(pending, pending[n:])
		pending = pending[:len(pending)-n]
	}
	// 实体抽取(键级去重:canonical_key|host;锚点保首见)
	entSeen := map[string]bool{}
	var entRows []entity.Row

	for rows := range rowGroups {
		for _, r := range rows {
			switch r.Kind {
			case model.KindEvent:
				stats.Events++
				if sink != nil {
					for _, c := range entity.Extract(r.Fields, spec.Host) {
						key := c.CanonicalKey + "|" + spec.Host
						if entSeen[key] {
							continue
						}
						entSeen[key] = true
						entRows = append(entRows, entity.Row{
							CaseID: caseID, Host: spec.Host,
							EntityType: c.EntityType, RawValue: c.RawValue,
							CanonicalKey: c.CanonicalKey, Qualifier: c.Qualifier,
							SourceID: sourceID, LineNo: r.LineNo,
						})
					}
				}
			case model.KindBad:
				stats.Bad++
			default:
				stats.Skip++
			}
		}
		stats.Total += int64(len(rows))
		pending = append(pending, rows...)
		for len(pending) >= spec.BatchRows {
			flushN(spec.BatchRows)
		}
	}
	flushN(len(pending))
	close(insertCh)
	iwg.Wait()

	select {
	case err := <-prodErr:
		if err != nil {
			return stats, err
		}
	default:
	}
	select {
	case err := <-insertErr:
		if err != nil {
			return stats, err
		}
	default:
	}
	// 事件全部落库后落实体(去重幂等在库侧 ON CONFLICT;失败如实上抛)
	if sink != nil && len(entRows) > 0 {
		if err := sink.InsertEntities(ctx, entRows); err != nil {
			return stats, fmt.Errorf("实体落库失败: %w", err)
		}
	}
	return stats, nil
}

// entitySinkOf meta 实现 EntitySink 时返回之(实体层接入点;未实现 = nil,
// 管线不抽实体——单测 fake 与纯 CH 台架不受影响)。
func entitySinkOf(meta MetaStore) EntitySink {
	if sink, ok := meta.(EntitySink); ok {
		return sink
	}
	return nil
}

// IngestParsed 解析一个已登记的源(一键分析主链路用:源在上传时已登记,
// 不再 EnsureCase/RegisterSource——(case_id, path) 唯一约束下重复登记
// 会被如实拒绝)。只开任务账 → 解析 → 插入 → 收尾账。
// 幂等由调用方判定(LatestJob:done 且非 raw 账 = 已解析,跳过)。
func IngestParsed(ctx context.Context, meta MetaStore, events EventStore,
	caseID, sourceID string, spec Spec, source WorkSource, parse ParseFunc) (*Stats, error) {
	spec.withDefaults()
	start := time.Now()

	jobID, err := meta.StartJob(ctx, sourceID, caseID, spec.ParserLabel)
	if err != nil {
		return nil, fmt.Errorf("任务登记失败: %w", err)
	}
	stats, runErr := runPipeline(ctx, events, entitySinkOf(meta), spec, caseID, sourceID, source, parse)
	stats.Duration = time.Since(start)

	fin := JobFinish{
		Status: "done", RowsTotal: stats.Total, RowsEvent: stats.Events,
		RowsBad: stats.Bad, RowsSkip: stats.Skip, BytesIn: stats.BytesIn,
		Duration: stats.Duration,
		Note: fmt.Sprintf("workers=%d batch_rows=%d chunk_bytes=%d",
			spec.Workers, spec.BatchRows, spec.ChunkBytes),
	}
	if runErr != nil {
		fin.Status = "failed"
		fin.Err = runErr.Error()
	}
	if ferr := meta.FinishJob(ctx, jobID, fin); ferr != nil && runErr == nil {
		runErr = fmt.Errorf("任务收尾记账失败: %w", ferr)
	}
	return stats, runErr
}

// IngestTextParsed 已登记文本源再解析(指纹/改判后的主链路解析动作)。
func IngestTextParsed(ctx context.Context, meta MetaStore, events EventStore,
	caseID, sourceID string, spec Spec, encoding string, parse ParseFunc,
	isBlockStart func(string) bool) (*Stats, error) {

	f, err := os.Open(spec.Path)
	if err != nil {
		return nil, fmt.Errorf("源文件打开失败: %w", err)
	}
	defer f.Close()
	src := NewChunkReader(f, encoding, isBlockStart, spec.ChunkBytesOrDefault())
	return IngestParsed(ctx, meta, events, caseID, sourceID, spec,
		AsWorkSource(src), parse)
}

// IngestEVTXParsed 已登记 evtx 源再解析。
func IngestEVTXParsed(ctx context.Context, meta MetaStore, events EventStore,
	caseID, sourceID string, spec Spec, parser EvtxParser) (*Stats, error) {

	stream, err := parser.Records(spec.Path)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	return IngestParsed(ctx, meta, events, caseID, sourceID, spec,
		NewEVTXWorkSource(stream, 4096), nil)
}
