package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ye-mengwen/fengtu/internal/descform"
)

// ---- fake stores:单测打全链,不碰真库 ----

type fakeMeta struct {
	mu      sync.Mutex
	cases   map[string]string
	sources []SourceInfo
	jobs    []fakeJob
	seq     int
}

type fakeJob struct {
	sourceID, caseID, parser string
	fin                      *JobFinish
}

func newFakeMeta() *fakeMeta { return &fakeMeta{cases: map[string]string{}} }

func (f *fakeMeta) nextID() string {
	f.seq++
	return fmt.Sprintf("id-%d", f.seq)
}

func (f *fakeMeta) EnsureCase(_ context.Context, name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id, ok := f.cases[name]; ok {
		return id, nil
	}
	id := f.nextID()
	f.cases[name] = id
	return id, nil
}

func (f *fakeMeta) RegisterSource(_ context.Context, s SourceInfo) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ex := range f.sources {
		if ex.CaseID == s.CaseID && ex.Path == s.Path { // 唯一约束 (case_id, path)
			return "", fmt.Errorf("重复源")
		}
	}
	f.sources = append(f.sources, s)
	return f.nextID(), nil
}

func (f *fakeMeta) StartJob(_ context.Context, sourceID, caseID, parser string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jobs = append(f.jobs, fakeJob{sourceID: sourceID, caseID: caseID, parser: parser})
	return fmt.Sprintf("job-%d", len(f.jobs)), nil
}

func (f *fakeMeta) FinishJob(_ context.Context, jobID string, fin JobFinish) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var idx int
	if _, err := fmt.Sscanf(jobID, "job-%d", &idx); err != nil || idx < 1 || idx > len(f.jobs) {
		return fmt.Errorf("job 不存在: %s", jobID)
	}
	f.jobs[idx-1].fin = &fin
	return nil
}

type fakeEvents struct {
	mu      sync.Mutex
	rows    []EventRow
	batches []int // 每次插入的行数(验批量纪律)
}

func (f *fakeEvents) InsertEvents(_ context.Context, rows []EventRow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batches = append(f.batches, len(rows))
	f.rows = append(f.rows, rows...)
	return nil
}

// ---- 端到端:nginx 小文件,全链 ----

const nginxSampleLine = `1.2.3.4 - - [04/Aug/2026:00:00:01 +0800] "GET /a HTTP/1.1" 200 123 "-" "UA-x"`

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sample.log")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIngestText_EndToEnd(t *testing.T) {
	var sb strings.Builder
	n := 300
	for i := 0; i < n; i++ {
		sb.WriteString(nginxSampleLine + "\n")
	}
	sb.WriteString("bad line here\n") // 一条坏行(零静默)
	p := writeTemp(t, sb.String())

	meta := newFakeMeta()
	events := &fakeEvents{}
	spec := Spec{
		CaseName: "case-a", Path: p, Kind: KindText,
		ParserLabel: "builtin:nginx_combined", TZDeclared: "Asia/Shanghai",
		Workers: 4, BatchRows: 50, ChunkBytes: 512, // 小参数强制多批/多次插入
	}
	st, err := IngestTextFile(context.Background(), meta, events, spec,
		"utf-8", descform.ParseNginxCombined, AlwaysBlockStart)
	if err != nil {
		t.Fatalf("摄入失败: %v", err)
	}
	if st.Events != int64(n) || st.Bad != 1 || st.Total != int64(n+1) {
		t.Fatalf("账目不符: %+v", st)
	}

	// 事件行:行号集合恰好 1..n+1 全覆盖(跨批重基正确)
	seen := map[int]bool{}
	var ev EventRow
	for _, r := range events.rows {
		if seen[r.LineNo] {
			t.Fatalf("行号重复: %d", r.LineNo)
		}
		seen[r.LineNo] = true
		if r.Kind == "event" {
			ev = r
		}
	}
	for i := 1; i <= n+1; i++ {
		if !seen[i] {
			t.Fatalf("行号缺失: %d", i)
		}
	}

	// ts 归一:+0800 声明 → UTC 前一日 16:00:01
	wantTS := time.Date(2026, 8, 3, 16, 0, 1, 0, time.UTC)
	if ev.TS == nil || !ev.TS.Equal(wantTS) {
		t.Fatalf("ts_utc: got %v want %v", ev.TS, wantTS)
	}
	if !strings.Contains(ev.Fields, `"status":200`) || !strings.Contains(ev.Fields, `"src_ip":"1.2.3.4"`) {
		t.Fatalf("fields JSON: %s", ev.Fields)
	}

	// 批量纪律:每次插入 ≤ BatchRows(严格切片,整分块不超塞)
	for _, b := range events.batches {
		if b <= 0 || b > 50 {
			t.Fatalf("批大小越界: %d", b)
		}
	}

	// 溯源锚:source 登记 sha256 与原文一致;job 账目与 stats 一致
	raw, _ := os.ReadFile(p)
	sum := sha256.Sum256(raw)
	if meta.sources[0].SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha256 登记不符")
	}
	fin := meta.jobs[0].fin
	if fin == nil || fin.Status != "done" || fin.RowsEvent != int64(n) || fin.RowsBad != 1 {
		t.Fatalf("任务账: %+v", fin)
	}
	if fin.BytesIn != int64(len(raw)) || fin.Duration <= 0 {
		t.Fatalf("字节/耗时账: %+v", fin)
	}
}

func TestIngestText_DuplicateSourceRejected(t *testing.T) {
	p := writeTemp(t, nginxSampleLine+"\n")
	meta := newFakeMeta()
	events := &fakeEvents{}
	spec := Spec{CaseName: "c", Path: p, Kind: KindText, ParserLabel: "builtin:nginx_combined"}
	if _, err := IngestTextFile(context.Background(), meta, events, spec,
		"utf-8", descform.ParseNginxCombined, AlwaysBlockStart); err != nil {
		t.Fatalf("首次摄入失败: %v", err)
	}
	if _, err := IngestTextFile(context.Background(), meta, events, spec,
		"utf-8", descform.ParseNginxCombined, AlwaysBlockStart); err == nil {
		t.Fatalf("同案同源重复摄入应拒绝")
	}
}

func TestRegisterRaw(t *testing.T) {
	p := writeTemp(t, "binary-ish\x00\x01 content")
	meta := newFakeMeta()
	spec := Spec{CaseName: "c", Path: p, Kind: KindRaw, ArtifactType: "binary_artifact"}
	if err := RegisterRawFile(context.Background(), meta, spec); err != nil {
		t.Fatalf("raw 登记失败: %v", err)
	}
	if len(meta.sources) != 1 || meta.sources[0].ArtifactType != "binary_artifact" {
		t.Fatalf("源登记: %+v", meta.sources)
	}
	fin := meta.jobs[0].fin
	if fin == nil || fin.Status != "done" || fin.RowsTotal != 0 {
		t.Fatalf("raw 任务账: %+v", fin)
	}
	if meta.jobs[0].parser != "raw" {
		t.Fatalf("parser 标: %s", meta.jobs[0].parser)
	}
}

func TestIngestText_MultilineFileEndToEnd(t *testing.T) {
	// log4j 形态:3 事件 + 1 堆栈块(2 续行)+ 1 坏行,跨多块不碎
	descYAML := `
name: t-log4j
kind: regex
line_regex: ^(?P<ts>\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(?P<level>[A-Z]+)\s+(?P<message>.*)$
field_map: {ts: ts_raw, level: level, message: message}
ts_field: ts
ts_formats: ['%m-%d %H:%M:%S']
multiline:
  start_regex: ^\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s
`
	d, err := descform.CompileText(descYAML)
	if err != nil {
		t.Fatal(err)
	}
	content := "broken line\n" + // 孤儿续行(前面没有可并入的事件)→ bad
		"09-21 10:00:00 INFO first\n" +
		"09-21 10:00:01 ERROR boom\n\tat a.b.C(C.java:1)\n\tat d.e.F(F.java:2)\n" +
		"09-21 10:00:02 INFO third\n"
	p := writeTemp(t, content)

	meta := newFakeMeta()
	events := &fakeEvents{}
	spec := Spec{
		CaseName: "c", Path: p, Kind: KindText, ParserLabel: "desc:t-log4j",
		Workers: 4, BatchRows: 3, ChunkBytes: 40, // 强制跨块
	}
	st, err := IngestTextFile(context.Background(), meta, events, spec,
		"utf-8", d.Parse, d.IsBlockStart)
	if err != nil {
		t.Fatalf("摄入失败: %v", err)
	}
	if st.Events != 3 || st.Bad != 1 {
		t.Fatalf("多行块账目: %+v", st)
	}
	// 堆栈块:raw 含续行全文,行号锚起始行(第 3 行,broken 占第 1 行)
	var block *EventRow
	for i := range events.rows {
		if events.rows[i].LineNo == 3 {
			block = &events.rows[i]
		}
	}
	if block == nil || !strings.Contains(block.Raw, "at d.e.F") {
		t.Fatalf("堆栈块留证: %+v", block)
	}
}
