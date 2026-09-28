package ingest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/evtx"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// ---- EvtxParser 接口的 fake:管线全链测试不碰真库/真文件 ----

type fakeEvtxStream struct {
	recs []model.Record
	pos  int
	err  error
}

func (s *fakeEvtxStream) Next() (model.Record, bool) {
	if s.pos >= len(s.recs) {
		return model.Record{}, false
	}
	r := s.recs[s.pos]
	s.pos++
	return r, true
}
func (s *fakeEvtxStream) Err() error   { return s.err }
func (s *fakeEvtxStream) Close() error { return nil }

type fakeEvtxParser struct {
	streams map[string]*fakeEvtxStream
	err     error
}

func (p *fakeEvtxParser) Records(path string) (EvtxStream, error) {
	if p.err != nil {
		return nil, p.err
	}
	if s, ok := p.streams[path]; ok {
		return s, nil
	}
	return nil, fmt.Errorf("fake: 无此文件 %s", path)
}

func TestIngestEVTX_EndToEnd(t *testing.T) {
	ts := int64(1784850715) // 2026-07-23T23:51:55Z
	mk := func(i int) model.Record {
		sec := float64(ts) + float64(i)*0.5
		return evtxRecordForTest(i+1, 4624, "Security", "HOST-A", sec)
	}
	var recs []model.Record
	for i := 0; i < 100; i++ {
		recs = append(recs, mk(i))
	}
	p := writeTemp(t, "dummy-evtx-bytes")
	parser := &fakeEvtxParser{streams: map[string]*fakeEvtxStream{
		p: {recs: recs},
	}}

	meta := newFakeMeta()
	events := &fakeEvents{}
	spec := Spec{
		CaseName: "case-evtx", Path: p, Kind: KindEVTX,
		ParserLabel: "evtx_native:velocidex",
		Workers:     4, BatchRows: 30,
	}
	st, err := IngestEVTXFile(context.Background(), meta, events, spec, parser)
	if err != nil {
		t.Fatalf("evtx 摄入失败: %v", err)
	}
	if st.Events != 100 || st.Bad != 0 {
		t.Fatalf("账目: %+v", st)
	}
	// 行号 1..100 全覆盖(溯源锚)
	seen := map[int]bool{}
	for _, r := range events.rows {
		seen[r.LineNo] = true
	}
	for i := 1; i <= 100; i++ {
		if !seen[i] {
			t.Fatalf("行号缺失: %d", i)
		}
	}
	// ts 直通 UTC(SystemTime unix 秒 float → 秒位一致;并发插入,按行号找)
	var r0 *EventRow
	for i := range events.rows {
		if events.rows[i].LineNo == 1 {
			r0 = &events.rows[i]
		}
	}
	if r0 == nil || r0.TS == nil || r0.TS.Unix() != ts {
		t.Fatalf("ts 直通: %+v", r0)
	}
	if got := meta.jobs[0].fin; got == nil || got.Status != "done" || got.RowsEvent != 100 {
		t.Fatalf("任务账: %+v", got)
	}
}

func TestIngestEVTX_ParserErrorFailsJob(t *testing.T) {
	parser := &fakeEvtxParser{err: fmt.Errorf("文件头损坏")}
	meta := newFakeMeta()
	events := &fakeEvents{}
	spec := Spec{CaseName: "c", Path: "bad.evtx", Kind: KindEVTX, ParserLabel: "evtx_native"}
	if _, err := IngestEVTXFile(context.Background(), meta, events, spec, parser); err == nil {
		t.Fatalf("解析器开流失败应如实上抛")
	}
}

// evtxRecordForTest 测试用记录(与 velocidexEventToRecord 产出同构)。
func evtxRecordForTest(lineNo int, eventID int64, channel, computer string,
	unixSec float64) model.Record {
	sec := int64(unixSec)
	nsec := int64((unixSec - float64(sec)) * 1e9)
	t := unixUTC(sec, nsec)
	s := fmt.Sprintf("%v", unixSec)
	return model.Record{
		LineNo: lineNo, Kind: model.KindEvent, TsRaw: &s, TsUTCDirect: t,
		Norm: map[string]any{
			"event_id": eventID, "channel": channel, "computer": computer,
			"record_id": int64(lineNo), "data": map[string]any{"k": "v"},
		},
		Raw: fmt.Sprintf(`{"Event":{"System":{"EventRecordID":%d}}}`, lineNo),
	}
}

// ---- velocidexEventToRecord:用真实库类型构造合成事件 ----

func eventRecordForTest(ev *ordereddict.Dict) *evtx.EventRecord {
	return &evtx.EventRecord{Event: ev}
}

func unixUTC(sec, nsec int64) *time.Time {
	t := time.Unix(sec, nsec).UTC()
	return &t
}

func dictOf(pairs ...any) *ordereddict.Dict {
	d := ordereddict.NewDict()
	for i := 0; i+1 < len(pairs); i += 2 {
		d.Set(pairs[i].(string), pairs[i+1])
	}
	return d
}

func TestVelocidexEventToRecord_Synthetic(t *testing.T) {
	ev := dictOf("Event", dictOf(
		"System", dictOf(
			"Provider", dictOf("Name", "Microsoft-Windows-Security-Auditing"),
			"EventID", dictOf("Value", 4672),
			"TimeCreated", dictOf("SystemTime", 1784850715.6273327),
			"EventRecordID", 2183611,
			"Channel", "Security",
			"Computer", "HOST-X",
		),
		"EventData", dictOf(
			"SubjectUserName", "SYSTEM",
			"SubjectLogonId", 999,
		),
	))
	rec := velocidexEventToRecord(5, eventRecordForTest(ev))
	if rec.Kind != model.KindEvent {
		t.Fatalf("应成事件: %+v", rec)
	}
	if rec.Norm["event_id"] != int64(4672) ||
		rec.Norm["channel"] != "Security" ||
		rec.Norm["computer"] != "HOST-X" ||
		rec.Norm["provider"] != "Microsoft-Windows-Security-Auditing" ||
		rec.Norm["record_id"] != int64(2183611) {
		t.Fatalf("norm 主干: %v", rec.Norm)
	}
	data, _ := rec.Norm["data"].(map[string]any)
	if data["SubjectUserName"] != "SYSTEM" || data["SubjectLogonId"] != 999 {
		t.Fatalf("EventData 平铺: %v", data)
	}
	if rec.TsUTCDirect == nil {
		t.Fatalf("SystemTime 应直通 ts_utc")
	}
	// 1784850715.6273327 → 2026-07-23T23:51:55.627Z(毫秒精度)
	if got := rec.TsUTCDirect.Format("2006-01-02T15:04:05.000Z07:00"); got != "2026-07-23T23:51:55.627Z" {
		t.Fatalf("ts_utc: %s", got)
	}
	if rec.TsRaw == nil || *rec.TsRaw == "" {
		t.Fatalf("ts_raw 留证")
	}
	if rec.Raw == "" {
		t.Fatalf("raw 应留事件全 JSON")
	}
}

func TestVelocidexEventToRecord_NegativeSamples(t *testing.T) {
	// 缺 System → bad
	rec := velocidexEventToRecord(1, eventRecordForTest(dictOf("Event", dictOf())))
	if rec.Kind != model.KindBad {
		t.Fatalf("缺 System 应 bad: %+v", rec)
	}
	// EventID 转不出 int → bad(零静默)
	ev := dictOf("Event", dictOf("System", dictOf("EventID", dictOf("Value", "abc"))))
	if rec := velocidexEventToRecord(1, eventRecordForTest(ev)); rec.Kind != model.KindBad {
		t.Fatalf("EventID 非法应 bad: %+v", rec)
	}
	// 缺 SystemTime → 成事件但 ts=nil 如实
	ev2 := dictOf("Event", dictOf("System", dictOf(
		"EventID", dictOf("Value", 1), "Channel", "System")))
	rec2 := velocidexEventToRecord(1, eventRecordForTest(ev2))
	if rec2.Kind != model.KindEvent || rec2.TsUTCDirect != nil {
		t.Fatalf("缺 SystemTime 应 ts=nil: %+v", rec2)
	}
	// EventID 裸数字变体 → 容忍
	ev3 := dictOf("Event", dictOf("System", dictOf("EventID", 7036)))
	if rec3 := velocidexEventToRecord(1, eventRecordForTest(ev3)); rec3.Kind != model.KindEvent ||
		rec3.Norm["event_id"] != int64(7036) {
		t.Fatalf("裸数字 EventID 应容忍: %+v", rec3)
	}
}
