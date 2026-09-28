// 三种路由的文件级入口:文本(desc/内置)、evtx(原生库)、raw(登记)。
// M3 起加第四种:native(树庭面原生解析器,internal/parsers)。
package ingest

import (
	"context"
	"fmt"
	"os"

	"github.com/ye-mengwen/fengtu/internal/parsers"
)

// IngestTextFile 行式文本摄入(desc 引擎或内置格式驱动)。
// isBlockStart 来自 descform.CompiledDesc.IsBlockStart(无多行恒 true)。
func IngestTextFile(ctx context.Context, meta MetaStore, events EventStore,
	spec Spec, encoding string, parse ParseFunc,
	isBlockStart func(string) bool) (*Stats, error) {

	f, err := os.Open(spec.Path)
	if err != nil {
		return nil, fmt.Errorf("源文件打开失败: %w", err)
	}
	defer f.Close()
	src := NewChunkReader(f, encoding, isBlockStart, spec.ChunkBytesOrDefault())
	return Ingest(ctx, meta, events, spec, AsWorkSource(src), parse)
}

// IngestEVTXFile evtx 摄入:原生解析库(Velocidex/evtx)→ 统一管线。
// parser 是薄接口 EvtxParser 的实现(替换点,见 evtx.go)。
func IngestEVTXFile(ctx context.Context, meta MetaStore, events EventStore,
	spec Spec, parser EvtxParser) (*Stats, error) {

	stream, err := parser.Records(spec.Path)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	return Ingest(ctx, meta, events, spec, NewEVTXWorkSource(stream, 4096), nil)
}

// IngestNativeFile 树庭面原生解析摄入(M3):internal/parsers 的解析器
// (registry hive/MFT/Prefetch/lnk/USN CSV)产出记录流,走同一管线。
// parsers.Stream 与 EvtxStream 同形(Go 接口结构化满足),共用适配器。
func IngestNativeFile(ctx context.Context, meta MetaStore, events EventStore,
	spec Spec, parser parsers.Parser) (*Stats, error) {

	stream, err := parser.Records(spec.Path)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	return Ingest(ctx, meta, events, spec, NewEVTXWorkSource(stream, 4096), nil)
}

// RegisterRawFile 原文登记不解析(其余类别的路由终点)。
// 登记 sources + 一行 parser=raw 的任务账(rows 恒 0,如实)。
func RegisterRawFile(ctx context.Context, meta MetaStore, spec Spec) error {
	sum, size, err := HashFile(spec.Path)
	if err != nil {
		return fmt.Errorf("原文哈希失败: %w", err)
	}
	caseID, err := meta.EnsureCase(ctx, spec.CaseName)
	if err != nil {
		return fmt.Errorf("案件登记失败: %w", err)
	}
	sourceID, err := meta.RegisterSource(ctx, SourceInfo{
		CaseID: caseID, Path: spec.regPath(), SHA256: sum, SizeBytes: size,
		Kind: spec.Kind, ArtifactType: spec.ArtifactType, LogType: spec.LogType,
		Host: spec.Host, Package: spec.Package,
	})
	if err != nil {
		return fmt.Errorf("源登记失败: %w", err)
	}
	jobID, err := meta.StartJob(ctx, sourceID, caseID, "raw")
	if err != nil {
		return fmt.Errorf("任务登记失败: %w", err)
	}
	return meta.FinishJob(ctx, jobID, JobFinish{
		Status: "done", BytesIn: size, Note: "原文登记不解析(route=raw)",
	})
}

// ChunkBytesOrDefault 分块目标字节(0 → 64MB,§4.1 下限)。
func (s *Spec) ChunkBytesOrDefault() int {
	if s.ChunkBytes <= 0 {
		return 64 << 20
	}
	return s.ChunkBytes
}
