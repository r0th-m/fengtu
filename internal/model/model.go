// Package model 定义归一化记录模型(DESIGN §5 事件骨架的单机切片)。
//
// 一条记录 = 一行(或多行块)原文的解析产物,语义照索图 base.LineOutcome:
// kind: event(成事件) | bad(坏行,零静默) | skip(空行/表头)。
// ts_raw 原样保留;ts_utc 由「行内本地时间 + 源声明时区」归一,
// 时区未知则 nil 如实标注,不硬归一、不猜。
package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// Kind 枚举。
const (
	KindEvent = "event"
	KindBad   = "bad"
	KindSkip  = "skip"
)

// Record 是一条归一化记录。
type Record struct {
	LineNo            int            // 原文物理行号(1 起);多行块锚起始行
	Kind              string         // event | bad | skip
	TsRaw             *string        // 行内时间原文(有则保留)
	TsUTC             *time.Time     // 归一 UTC;时区未知/非事件 → nil
	Norm              map[string]any // 归一字段(+extras,不丢数据)
	Raw               string         // 原文(多行块含续行全文)
	Reason            *string        // bad/skip 的明确原因
	ContinuationLines int            // 多行合并续行数(0 = 单行)

	// DTLocal 行内本地时间(naive 墙钟,UTC location 承载)——解析中间态,
	// 不进 JSON;ts_utc 由 descform.ResolveTsUTC 按源声明时区归一。
	DTLocal *time.Time `json:"-"`
	// TsUTCDirect UTC 原生格式直通(如 evtx SystemTime,本切片未用,
	// 契约照索图保留:直通 > dt_local+声明时区 > nil 如实)。
	TsUTCDirect *time.Time `json:"-"`
}

// FormatUTC 输出与金标准约定的规范形式:
// RFC3339,UTC 用 "Z",微秒非零时带 6 位小数。
func FormatUTC(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond() != 0 {
		return t.Format("2006-01-02T15:04:05.000000Z07:00")
	}
	return t.Format("2006-01-02T15:04:05Z07:00")
}

// recordJSON 是 Record 的 JSON 投影(键序固定,便于肉眼 diff;
// golden 对照按语义比较,不依赖键序)。
type recordJSON struct {
	LineNo            int            `json:"line_no"`
	Kind              string         `json:"kind"`
	TsRaw             *string        `json:"ts_raw"`
	TsUTC             *string        `json:"ts_utc"`
	Norm              map[string]any `json:"norm"`
	Raw               string         `json:"raw"`
	Reason            *string        `json:"reason,omitempty"`
	ContinuationLines int            `json:"continuation_lines"`
}

// MarshalJSON 实现 json.Marshaler。
func (r Record) MarshalJSON() ([]byte, error) {
	var tsUTC *string
	if r.TsUTC != nil {
		s := FormatUTC(*r.TsUTC)
		tsUTC = &s
	}
	norm := r.Norm
	if norm == nil {
		norm = map[string]any{}
	}
	return json.Marshal(recordJSON{
		LineNo:            r.LineNo,
		Kind:              r.Kind,
		TsRaw:             r.TsRaw,
		TsUTC:             tsUTC,
		Norm:              norm,
		Raw:               r.Raw,
		Reason:            r.Reason,
		ContinuationLines: r.ContinuationLines,
	})
}

// AppendJSONL 把记录以 JSONL 形式追加到 buf(不转义 HTML,
// 与 Python json.dumps(ensure_ascii=False) 的语义对齐)。
func (r Record) AppendJSONL(buf *bytes.Buffer) error {
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("记录编码失败(L%d): %w", r.LineNo, err)
	}
	return nil
}
