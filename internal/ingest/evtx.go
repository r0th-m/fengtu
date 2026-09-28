// EVTX 摄入:纯 Go 原生解析(Velocidex/evtx),走统一归一模型。
//
// 架构决策(2026-09-21 用户拍板,替换 M0 sidecar 草案):evtx 不经外部
// 进程,直接 import Velocidex/evtx 逐事件解析——
//   - 库:www.velocidex.com/golang/evtx v0.2.0(Velociraptor 生产同款,
//     2026-09 仍在维护;模块规范路径是 www.velocidex.com/golang/evtx,
//     与 github.com/Velocidex/evtx 同源);
//   - 调用收在 EvtxParser 薄接口后面,将来换实现只动本文件;
//   - 解析产物与其他格式同一套 model.Record(TsUTCDirect 直通 UTC,
//     坏事件逐条 bad,零静默);
//   - **零静默补强**:Velocidex chunk.Parse 在遇到坏记录时会截断当前
//     chunk 剩余记录且只返回 nil error(库行为,源码可见)——本文件按
//     chunk 头声明的 LastEventRecID 对账,缺尾如实补 bad 记录,不静默。
package ingest

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"time"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/evtx"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// EvtxParser evtx 原生解析的薄接口(替换点;当前实现 VelocidexParser)。
type EvtxParser interface {
	// Records 打开 evtx 文件,返回逐事件记录流。
	// 行号 = 事件序(1 起);坏事件逐条 bad 记录(零静默)。
	Records(path string) (EvtxStream, error)
}

// EvtxStream 逐事件记录流。
type EvtxStream interface {
	// Next 取下一事件;ok=false 表示结束(致命错误经 Err() 暴露)。
	Next() (rec model.Record, ok bool)
	// Err 流级致命错误(如 chunk 损坏);无错返回 nil。
	Err() error
	// Close 释放底层句柄。
	Close() error
}

// VelocidexParser 默认实现:www.velocidex.com/golang/evtx。
type VelocidexParser struct{}

// Records 打开文件并解析 chunk 头(此时不读事件体)。
func (VelocidexParser) Records(path string) (EvtxStream, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("evtx 打开失败: %w", err)
	}
	chunks, err := evtx.GetChunks(fd)
	if err != nil {
		fd.Close()
		return nil, fmt.Errorf("evtx chunk 头解析失败(%s): %w", path, err)
	}
	return &velocidexStream{fd: fd, chunks: chunks}, nil
}

// velocidexStream 逐 chunk 推进的记录流。
// pendingBad:chunk 截断/整chunk 失败的 bad 记录,排在该 chunk
// 已解析记录之后交出(行号序即事件序,如实)。
type velocidexStream struct {
	fd         *os.File
	chunks     []*evtx.Chunk
	chunkIdx   int
	buf        []*evtx.EventRecord
	pos        int
	pendingBad *model.Record
	lineNo     int
	err        error
}

func (s *velocidexStream) Next() (model.Record, bool) {
	for {
		if s.pos < len(s.buf) {
			r := s.buf[s.pos]
			s.pos++
			s.lineNo++
			return velocidexEventToRecord(s.lineNo, r), true
		}
		if s.pendingBad != nil {
			rec := *s.pendingBad
			s.pendingBad = nil
			return rec, true
		}
		if s.chunkIdx >= len(s.chunks) {
			return model.Record{}, false
		}
		chunk := s.chunks[s.chunkIdx]
		s.chunkIdx++
		recs, err := chunk.Parse(0)
		if err != nil {
			// chunk 级失败(如截断样本的尾 chunk):如实 bad 记录并继续,
			// 不做流级致命(零静默,账目可查;文件头级错误在 Records() 拦)
			s.lineNo++
			reason := fmt.Sprintf("chunk #%d(offset %d)解析失败: %v",
				s.chunkIdx-1, chunk.Offset, err)
			s.pendingBad = &model.Record{
				LineNo: s.lineNo, Kind: model.KindBad, Reason: &reason,
				Raw: fmt.Sprintf("<chunk offset=%d error>", chunk.Offset),
			}
			continue
		}
		s.buf = recs
		s.pos = 0
		// 零静默对账:库在坏记录处截断本 chunk(返回已解析部分+nil)。
		// 按 chunk 头声明的记录区间对账,缺口补 bad 记录。
		if len(recs) > 0 {
			if lastID := recs[len(recs)-1].Header.RecordID; lastID < chunk.Header.LastEventRecID {
				s.lineNo++
				gap := chunk.Header.LastEventRecID - lastID
				reason := fmt.Sprintf(
					"chunk 内 %d 条记录解析被截断(record_id %d..%d 缺失,库行为如实标注)",
					gap, lastID+1, chunk.Header.LastEventRecID)
				s.pendingBad = &model.Record{
					LineNo: s.lineNo, Kind: model.KindBad, Reason: &reason,
					Raw: fmt.Sprintf("<chunk offset=%d truncated>", chunk.Offset),
				}
			}
		} else if chunk.Header.LastEventRecNumber > 0 {
			// 整 chunk 一条都解析不出但头部声明有记录:如实 bad
			s.lineNo++
			reason := fmt.Sprintf(
				"chunk 声明 %d 条记录全部解析失败(record_id %d..%d)",
				chunk.Header.LastEventRecID-chunk.Header.FirstEventRecID+1,
				chunk.Header.FirstEventRecID, chunk.Header.LastEventRecID)
			s.pendingBad = &model.Record{
				LineNo: s.lineNo, Kind: model.KindBad, Reason: &reason,
				Raw: fmt.Sprintf("<chunk offset=%d unreadable>", chunk.Offset),
			}
		}
	}
}

func (s *velocidexStream) Err() error { return s.err }

func (s *velocidexStream) Close() error { return s.fd.Close() }

// velocidexEventToRecord 一条 Velocidex 事件 → 归一记录。
//
// 语义对齐树庭 backend/app/parsers/evtx_log.py(金标准对照基准):
//   - event_id 取 System.EventID(库结构为 {"Value": n},容忍裸数字);
//   - ts:System.TimeCreated.SystemTime(unix 秒 float,UTC 原生)→
//     TsUTCDirect 直通;缺失/非法 → ts 留 nil 如实;
//   - channel/computer/record_id/provider 照抽;
//   - EventData 已天然平铺(无 #text 包装),空则兜底 UserData;
//   - raw 留事件全 JSON(全保真)。
func velocidexEventToRecord(lineNo int, r *evtx.EventRecord) model.Record {
	raw := ""
	if b, err := json.Marshal(r.Event); err == nil {
		raw = string(b)
	}
	root, ok := r.Event.(*ordereddict.Dict)
	if !ok {
		reason := "事件根节点非 dict(库结构异常)"
		return model.Record{LineNo: lineNo, Raw: raw, Kind: model.KindBad, Reason: &reason}
	}
	event := dictGet(root, "Event")
	system := dictGet(event, "System")
	if system == nil {
		reason := "缺 Event.System 节点"
		return model.Record{LineNo: lineNo, Raw: raw, Kind: model.KindBad, Reason: &reason}
	}

	eventID, ok := evtxIDValue(system, "EventID")
	if !ok {
		reason := "EventID 非法(转不出 int)"
		return model.Record{LineNo: lineNo, Raw: raw, Kind: model.KindBad, Reason: &reason}
	}

	norm := map[string]any{"event_id": eventID}
	if v, ok := strValue(system, "Channel"); ok {
		norm["channel"] = v
	}
	if v, ok := strValue(system, "Computer"); ok {
		norm["computer"] = v
	}
	if rid, ok := evtxIDValue(system, "EventRecordID"); ok {
		norm["record_id"] = rid
	} else {
		norm["record_id"] = int64(r.Header.RecordID) // 头部兜底(如实:值同源)
	}
	if p := dictGet(system, "Provider"); p != nil {
		if name, ok := strValue(p, "Name"); ok {
			norm["provider"] = name
		}
	}

	var tsUTC *time.Time
	var tsRaw *string
	if tc := dictGet(system, "TimeCreated"); tc != nil {
		if v, has := tc.Get("SystemTime"); has {
			if sec, ok := toFloat(v); ok {
				s := strconv.FormatFloat(sec, 'f', -1, 64)
				tsRaw = &s // unix 秒原文留证
				whole := int64(sec)
				// Round 而非截断:float64 秒的亚毫秒表示在±1µs 边界
				// 系统性偏下,四舍五入到纳秒(与 ISO 文本路径的差收敛到
				// ≤1ms,金标准对拍在该容差内,如实标注)
				nsec := int64(math.Round((sec - float64(whole)) * 1e9))
				t := time.Unix(whole, nsec).UTC()
				tsUTC = &t
			}
		}
	}

	data := map[string]any{}
	liftEventData(data, dictGet(event, "EventData"))
	if len(data) == 0 { // 部分通道数据在 UserData(与树庭同款兜底)
		plainInto(data, dictGet(event, "UserData"))
	}
	norm["data"] = data

	return model.Record{
		LineNo:      lineNo,
		Kind:        model.KindEvent,
		TsRaw:       tsRaw,
		TsUTCDirect: tsUTC,
		Norm:        norm,
		Raw:         raw,
	}
}

// dictGet ordereddict 取值并断言子 dict。
func dictGet(d *ordereddict.Dict, key string) *ordereddict.Dict {
	if d == nil {
		return nil
	}
	v, ok := d.Get(key)
	if !ok {
		return nil
	}
	sub, _ := v.(*ordereddict.Dict)
	return sub
}

// strValue dict 键的字符串值。
func strValue(d *ordereddict.Dict, key string) (string, bool) {
	v, ok := d.Get(key)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// evtxIDValue EventID/EventRecordID → int64;容忍 {"Value": n} 与裸数字。
func evtxIDValue(d *ordereddict.Dict, key string) (int64, bool) {
	v, ok := d.Get(key)
	if !ok {
		return 0, false
	}
	if sub, isDict := v.(*ordereddict.Dict); isDict {
		if inner, has := sub.Get("Value"); has {
			return toInt64(inner)
		}
		return 0, false
	}
	return toInt64(v)
}

func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint8:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		return int64(n), true
	case float64:
		return int64(n), true
	case string:
		i, err := strconv.ParseInt(n, 10, 64)
		return i, err == nil
	}
	return 0, false
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint64:
		return float64(n), true
	case string:
		f, err := strconv.ParseFloat(n, 64)
		return f, err == nil
	}
	return 0, false
}

// plainInto ordereddict 展平为原生 map(递归;字段编码器吃原生类型)。
func plainInto(out map[string]any, d *ordereddict.Dict) {
	if d == nil {
		return
	}
	for _, k := range d.Keys() {
		v, _ := d.Get(k)
		out[k] = toPlain(v)
	}
}

// liftEventData EventData 平铺 + Name 属性提升(与 python-evtx/树庭同约定:
// <Data Name="Status">0x..</Data> → 顶层键 Status=0x..)。
//
// 背景:python-evtx 把 Data 元素的 Name 属性用作 JSON 键(取证语义的
// 事实标准——IpAddress/TargetUserName 等关键字段都以该键出现);
// Velocidex 把 Name 内联为子键({"Data": {"Name":..,"Value":..}})。
// 不提升则关键字段全部落在 "Data" 壳里(金标准实测:Status 等字段
// 存在性对拍失败)。无名 Data 元素保留 "Data" 键原样。
func liftEventData(out map[string]any, d *ordereddict.Dict) {
	if d == nil {
		return
	}
	for _, k := range d.Keys() {
		v, _ := d.Get(k)
		if k != "Data" {
			out[k] = toPlain(v)
			continue
		}
		switch t := v.(type) {
		case *ordereddict.Dict:
			if !liftNamedData(out, t) {
				out["Data"] = toPlain(v)
			}
		case []any:
			var unnamed []any
			for _, e := range t {
				if ed, ok := e.(*ordereddict.Dict); ok && liftNamedData(out, ed) {
					continue
				}
				unnamed = append(unnamed, toPlain(e))
			}
			if len(unnamed) > 0 {
				out["Data"] = unnamed
			}
		default:
			out["Data"] = toPlain(v)
		}
	}
}

// liftNamedData 单个 Data 元素:{"Name": X, "Value": V} 形态则提升为
// out[X]=V 并返回 true。
func liftNamedData(out map[string]any, d *ordereddict.Dict) bool {
	nameV, hasName := d.Get("Name")
	name, isStr := nameV.(string)
	if !hasName || !isStr || name == "" {
		return false
	}
	val, hasVal := d.Get("Value")
	if !hasVal {
		return false
	}
	out[name] = toPlain(val)
	return true
}

func toPlain(v any) any {
	switch t := v.(type) {
	case *ordereddict.Dict:
		m := map[string]any{}
		plainInto(m, t)
		return m
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = toPlain(e)
		}
		return out
	default:
		return v
	}
}

// evtxWorkSource EvtxStream → WorkItem 适配(定长记录批)。
// 记录行号在流内已按全局事件序编好,BaseLineNo 恒 1(重基公式 +0)。
type evtxWorkSource struct {
	stream EvtxStream
	batchN int
	done   bool
}

// NewEVTXWorkSource 构造适配器(每批 batchN 条事件)。
func NewEVTXWorkSource(stream EvtxStream, batchN int) WorkSource {
	return &evtxWorkSource{stream: stream, batchN: batchN}
}

func (s *evtxWorkSource) Next() (*WorkItem, error) {
	if s.done {
		return nil, io.EOF
	}
	recs := make([]model.Record, 0, s.batchN)
	for len(recs) < s.batchN {
		rec, ok := s.stream.Next()
		if !ok {
			s.done = true
			break
		}
		recs = append(recs, rec)
	}
	if len(recs) == 0 {
		if err := s.stream.Err(); err != nil {
			return nil, err
		}
		return nil, io.EOF
	}
	return &WorkItem{Recs: recs, BaseLineNo: 1}, nil
}
