// ActivitiesCache 解析器合成样本测试 + 内存纪律回归。
// 夹具全部合成(modernc 可写模式造库);真实案件样本绝不进测试。
package parsers

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// 全 want 列 DDL(列序 = acWantedCols 序,VALUES 用占位符按序插)。
const acDDL = `CREATE TABLE Activity (
	Id TEXT, AppId TEXT, AppActivityId TEXT, ActivityType INT, ActivityStatus INT,
	"Group" TEXT, StartTime DATETIME, EndTime DATETIME, LastModifiedTime DATETIME,
	LastModifiedOnClient DATETIME, ExpirationTime DATETIME, CreatedInCloud DATETIME,
	Payload BLOB, ClipboardPayload BLOB, PlatformDeviceId TEXT, IsLocalOnly INT,
	ETag INT)`

const acInsert = `INSERT INTO Activity VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

// acMakeDB 可写模式建合成 ActivitiesCache.db(仅测试造夹具;解析侧只读)。
func acMakeDB(t *testing.T, dir, ddl, insert string, rows [][]any) string {
	t.Helper()
	p := filepath.Join(dir, "ActivitiesCache.db")
	db, err := sql.Open("sqlite",
		p+"?_pragma=journal_mode(OFF)&_pragma=synchronous(OFF)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(ddl); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	if len(rows) > 0 {
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		stmt, err := tx.Prepare(insert)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if _, err := stmt.Exec(r...); err != nil {
				t.Fatalf("插行失败: %v", err)
			}
		}
		stmt.Close()
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// acRow 按 acDDL 列序拼一行(17 值)。
func acRow(id, appID string, atype, status any, group string,
	st, en, lm, lmc any, payload, clip any, localOnly any) []any {
	return []any{id, appID, "act-" + id, atype, status, group,
		st, en, lm, lmc, nil, nil, payload, clip, "dev", localOnly, 7}
}

func TestActivitiesCache_Fields(t *testing.T) {
	// 乱序插入,验证 ORDER BY StartTime(NULL 最前,100 次之)
	rows := [][]any{
		acRow("id-e", "", nil, 1, "grp", nil, 0, nil, nil,
			nil, nil, 0), // 无时间行;EndTime=0 → end_epoch nil;AppId 空 → appid_errors
		acRow("id-b", "not json{", 6, 1, "grp", 1600001000, 1600001100,
			1600001200, 1600001300, []byte{0xff, 0x00, 0x01},
			[]byte(`{"content":"clip text"}`), 1), // AppId 坏 JSON + payload opaque
		acRow("id-a", `[{"application":"  MyApp ","platform":"uap"},`+
			`{"application":"second","platform":"x"}]`, 5, 1, "grp",
			1600000000, 1600000100, 1600000200, 1600000300,
			[]byte(`{"displayText":"hello"}`), []byte(`[]`), 1), // 正常行
		acRow("id-d", `[{"application":"","platform":"uap"},{"platform":"x"}]`,
			6, 1, "grp", 100, nil, 1600003000, nil,
			nil, nil, 0), // StartTime 越窗 → bad_time,anchor 落 LM;AppId 全空不算错
		acRow("id-c", `[{"application":"AppC","platform":"uap"}]`, 5, 1, "grp",
			1600002000, nil, 1600002100, nil,
			[]byte(`{"a":1}`), nil, 1), // payload JSON 无文本字段 → 整 JSON 留证
	}
	p := acMakeDB(t, t.TempDir(), acDDL, acInsert, rows)
	stream, err := ActivitiesCacheParser{}.Records(p)
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, stream)
	if len(recs) != 6 { // 5 行级 + 1 summary
		t.Fatalf("记录数不符: %d", len(recs))
	}
	// 顺序:E(NULL) → D(100) → A → B → C
	if recs[0].Raw != "id-e" || recs[1].Raw != "id-d" || recs[2].Raw != "id-a" ||
		recs[3].Raw != "id-b" || recs[4].Raw != "id-c" {
		t.Fatalf("ORDER BY StartTime 顺序不符: %v %v %v %v %v",
			recs[0].Raw, recs[1].Raw, recs[2].Raw, recs[3].Raw, recs[4].Raw)
	}
	// 正常行 A 逐字段焊死
	a := recs[2]
	if a.Kind != model.KindEvent || a.Norm["event_type"] != "windows_timeline" ||
		a.Norm["source"] != "activitiescache" ||
		a.Norm["app"] != "MyApp" || a.Norm["app_platform"] != "uap" ||
		a.Norm["activity_type"] != int64(5) || a.Norm["group"] != "grp" ||
		a.Norm["app_activity_id"] != "act-id-a" ||
		a.Norm["is_local_only"] != int64(1) ||
		a.Norm["start_epoch"] != int64(1600000000) ||
		a.Norm["end_epoch"] != int64(1600000100) ||
		a.Norm["start_utc"] != "2020-09-13T12:26:40Z" ||
		a.Norm["end_utc"] != "2020-09-13T12:28:20Z" ||
		a.Norm["last_modified_utc"] != "2020-09-13T12:30:00Z" ||
		a.Norm["last_modified_on_client_utc"] != "2020-09-13T12:31:40Z" ||
		a.Norm["payload_format"] != "json" ||
		a.Norm["payload_len"] != int64(len(`{"displayText":"hello"}`)) ||
		a.Norm["payload_text"] != "hello" ||
		a.Norm["clipboard_format"] != "empty" || // "[]" → empty(树庭同款)
		a.Norm["clipboard_text"] != nil {
		t.Fatalf("正常行字段不符: %+v", a.Norm)
	}
	if a.TsUTCDirect == nil ||
		!a.TsUTCDirect.Equal(time.Unix(1600000000, 0).UTC()) {
		t.Fatalf("TsUTCDirect 不符: %v", a.TsUTCDirect)
	}
	// B:AppId 坏 JSON → appid_errors + app_id_raw 留证;payload opaque
	b := recs[3]
	if b.Norm["app"] != nil || b.Norm["app_id_raw"] != "not json{" ||
		b.Norm["payload_format"] != "opaque" ||
		b.Norm["payload_len"] != int64(3) || b.Norm["payload_text"] != nil ||
		b.Norm["clipboard_format"] != "json" ||
		b.Norm["clipboard_text"] != "clip text" {
		t.Fatalf("坏 AppId/opaque 行字段不符: %+v", b.Norm)
	}
	// D:StartTime 越窗 → start_utc nil,anchor=LastModifiedTime;AppId 全空非错误
	d := recs[1]
	if d.Norm["start_utc"] != nil || d.Norm["start_epoch"] != int64(100) ||
		d.Norm["last_modified_utc"] != "2020-09-13T13:16:40Z" ||
		d.Norm["app"] != nil {
		t.Fatalf("越窗时间行字段不符: %+v", d.Norm)
	}
	if d.TsUTCDirect == nil ||
		!d.TsUTCDirect.Equal(time.Unix(1600003000, 0).UTC()) {
		t.Fatalf("D 行 anchor 应落 LastModifiedTime: %v", d.TsUTCDirect)
	}
	if _, has := d.Norm["app_id_raw"]; has {
		t.Fatalf("JSON 合法全空 AppId 不应计错/留 raw: %+v", d.Norm)
	}
	// C:payload JSON 无文本字段 → 整 JSON 重排留证
	if recs[4].Norm["payload_format"] != "json" ||
		recs[4].Norm["payload_text"] != `{"a":1}` {
		t.Fatalf("payload fallback 不符: %+v", recs[4].Norm)
	}
	// E:无时间 → 无 anchor;EndTime=0 → end_epoch nil;AppId 空值 → 计错不留 raw
	e := recs[0]
	if e.TsUTCDirect != nil || e.Norm["end_epoch"] != nil ||
		e.Norm["start_epoch"] != nil || e.Norm["start_utc"] != nil {
		t.Fatalf("无时间行字段不符: %+v", e.Norm)
	}
	if _, has := e.Norm["app_id_raw"]; has {
		t.Fatalf("空 AppId 不应留 app_id_raw: %+v", e.Norm)
	}
	// summary 焊死
	s := recs[5].Norm["summary"].(map[string]any)
	if recs[5].Norm["event_type"] != "windows_timeline_summary" ||
		s["rows"] != int64(5) || s["emitted"] != int64(5) ||
		s["appid_errors"] != int64(2) || s["bad_time_rows"] != int64(1) ||
		s["no_time_rows"] != int64(1) || s["payload_json"] != int64(2) ||
		s["payload_opaque"] != int64(1) || s["clipboard_nonempty"] != int64(1) ||
		s["wal_replayed"] != false || s["wal_note"] == nil ||
		s["distinct_apps"] != int64(2) {
		t.Fatalf("summary 计数不符: %+v", s)
	}
	types := s["activity_types"].(map[string]int64)
	if types["5"] != 2 || types["6"] != 2 || types["None"] != 1 ||
		len(types) != 3 { // NULL ActivityType → "None" 键(Python str(None))
		t.Fatalf("activity_types 不符: %+v", types)
	}
	top := s["top_apps"].([]map[string]any)
	if len(top) != 2 || top[0]["app"] != "AppC" || top[0]["count"] != int64(1) ||
		top[1]["app"] != "MyApp" { // 并列按应用名字典序(树庭按插入序,已标差异)
		t.Fatalf("top_apps 不符: %+v", top)
	}
	tr := s["time_range_utc"].([]string)
	if tr[0] != "2020-09-13T12:26:40Z" || tr[1] != "2020-09-13T13:16:40Z" {
		t.Fatalf("time_range_utc 不符: %+v", tr)
	}
}

// decltype 探针:modernc 对 TEXT+DATETIME 声明列会无条件转 time.Time;
// 子查询剥 decltype 后应拿到原始字符串,按「非整数 → 不猜」处理
// (同时验证带空格/中文路径的 DSN 转义)。
func TestActivitiesCache_DecltypeProbe(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "空 dir")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rows := [][]any{
		acRow("id-t", `[{"application":"A","platform":"uap"}]`, 5, 1, "g",
			"2021-06-01 10:00:00", nil, 1600000000, nil, nil, nil, 1),
	}
	p := acMakeDB(t, dir, acDDL, acInsert, rows)
	recs := drainT(t, p)
	if len(recs) != 2 {
		t.Fatalf("记录数不符: %d", len(recs))
	}
	r := recs[0]
	if r.Norm["start_epoch"] != "2021-06-01 10:00:00" {
		t.Fatalf("TEXT 时间应原样留证(decltype 未剥净或被转 time.Time): %T %v",
			r.Norm["start_epoch"], r.Norm["start_epoch"])
	}
	if r.Norm["start_utc"] != nil { // 非整数 → 不猜
		t.Fatalf("TEXT 时间不应归一: %+v", r.Norm)
	}
	if r.TsUTCDirect == nil || !r.TsUTCDirect.Equal(time.Unix(1600000000, 0).UTC()) {
		t.Fatalf("anchor 应落 LastModifiedTime: %v", r.TsUTCDirect)
	}
	s := recs[1].Norm["summary"].(map[string]any)
	if s["bad_time_rows"] != int64(0) { // TEXT 非整数不计 bad_time(树庭同款)
		t.Fatalf("TEXT 时间不应计 bad_time_rows: %+v", s)
	}
}

func drainT(t *testing.T, path string) []model.Record {
	t.Helper()
	stream, err := ActivitiesCacheParser{}.Records(path)
	if err != nil {
		t.Fatal(err)
	}
	return drain(t, stream)
}

func TestActivitiesCache_Negative(t *testing.T) {
	// 非 SQLite 文件 → 文件级如实 failed
	if _, err := (ActivitiesCacheParser{}).Records(
		writeTemp(t, "ActivitiesCache.db", []byte("definitely not a sqlite db"))); err == nil {
		t.Fatal("非 SQLite 文件应文件级如实 failed")
	}
	// SQLite 但无 Activity 表 → failed 并列出实际表名
	dir := t.TempDir()
	dbp := filepath.Join(dir, "ActivitiesCache.db")
	db, err := sql.Open("sqlite", dbp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE SomethingElse (x INT)"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	_, err = ActivitiesCacheParser{}.Records(dbp)
	if err == nil {
		t.Fatal("无 Activity 表应如实 failed")
	}
	got := err.Error()
	if !strings.Contains(got, "SomethingElse") {
		t.Fatalf("错误信息应列实际表名: %v", err)
	}
	// 缺必备列 → failed
	p := acMakeDB(t, t.TempDir(),
		"CREATE TABLE Activity (Id TEXT, ActivityType INT, StartTime DATETIME)",
		"", nil)
	if _, err := (ActivitiesCacheParser{}).Records(p); err == nil {
		t.Fatal("缺必备列应如实 failed")
	}
	// 缺非必备列(无 ClipboardPayload)→ 降级 nil 正常解析
	p2 := acMakeDB(t, t.TempDir(),
		`CREATE TABLE Activity (Id TEXT, AppId TEXT, ActivityType INT,
			StartTime DATETIME, LastModifiedTime DATETIME)`,
		"INSERT INTO Activity VALUES (?,?,?,?,?)",
		[][]any{{"id-1", `[{"application":"A","platform":"uap"}]`, 5,
			1600000000, 1600000100}})
	recs := drainT(t, p2)
	if len(recs) != 2 || recs[0].Norm["clipboard_format"] != "empty" ||
		recs[0].Norm["group"] != nil || recs[0].Norm["end_epoch"] != nil {
		t.Fatalf("缺非必备列应降级 nil 正常解析: %+v", recs[0].Norm)
	}
	// 空 Activity 表(0 行)→ 仅 summary,rows=0,非错误
	p3 := acMakeDB(t, t.TempDir(), acDDL, acInsert, nil)
	recs3 := drainT(t, p3)
	if len(recs3) != 1 ||
		recs3[0].Norm["event_type"] != "windows_timeline_summary" {
		t.Fatalf("空表应仅产 summary: %+v", recs3)
	}
	s3 := recs3[0].Norm["summary"].(map[string]any)
	if s3["rows"] != int64(0) || s3["time_range_utc"] != nil ||
		s3["distinct_apps"] != int64(0) {
		t.Fatalf("空表 summary 不符: %+v", s3)
	}
}

// 内存纪律:大库(40 万行 × 256B opaque payload ≈ 110MB)流式解析,
// 堆增量 << 64MB;计数器键上限(65536)防灌爆。
func TestActivitiesCache_MemoryFlat(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过大输入内存用例")
	}
	const n = 400000
	payload := make([]byte, 256)
	for i := range payload {
		payload[i] = byte(i) // 非 UTF-8 → opaque
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "ActivitiesCache.db")
	db, err := sql.Open("sqlite",
		p+"?_pragma=journal_mode(OFF)&_pragma=synchronous(OFF)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(acDDL); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(acInsert)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		app := fmt.Sprintf(`[{"application":"App%d","platform":"uap"}]`, i%200)
		if _, err := stmt.Exec(fmt.Sprintf("id-%d", i), app,
			fmt.Sprintf("act-%d", i), i%8+1, 1, "grp",
			1600000000+i, nil, 1600000000+i, nil, nil, nil, payload, nil,
			"dev", 1, 7); err != nil {
			t.Fatal(err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	db.Close()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("合成库 %.1f MB,%d 行", float64(fi.Size())/(1<<20), n)

	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	stream, err := ActivitiesCacheParser{}.Records(p)
	if err != nil {
		t.Fatal(err)
	}
	var summary map[string]any
	var events int64
	for {
		rec, ok := stream.Next()
		if !ok {
			break
		}
		if rec.Norm["event_type"] == "windows_timeline_summary" {
			summary = rec.Norm["summary"].(map[string]any)
		} else {
			events++
		}
	}
	if err := stream.Err(); err != nil {
		t.Fatal(err)
	}
	stream.Close()
	runtime.GC()
	runtime.ReadMemStats(&m1)
	delta := int64(m1.HeapAlloc) - int64(m0.HeapAlloc)
	if delta > 64<<20 {
		t.Fatalf("%d 行输入堆增量 %d MB 超 64MB 纪律线(流式回归!)",
			n, delta>>20)
	}
	if summary["rows"] != int64(n) || events != int64(n) ||
		summary["payload_opaque"] != int64(n) || summary["distinct_apps"] != int64(200) {
		t.Fatalf("大库计数不符: rows=%v events=%d opaque=%v apps=%v",
			summary["rows"], events, summary["payload_opaque"],
			summary["distinct_apps"])
	}
	t.Logf("%d 行解析完成:堆增量 %.1f MB", n, float64(delta)/(1<<20))
}

// TestActivitiesCache_JSONScalarBlob payload 为 JSON 标量/空数组/坏 UTF-8 的
// 格式标注边界(树庭 _decode_blob 逐分支)。
func TestActivitiesCache_JSONScalarBlob(t *testing.T) {
	rows := [][]any{
		acRow("id-1", `[{"application":"A","platform":"uap"}]`, 1, 1, "g",
			1600000001, nil, nil, nil, []byte(`true`), nil, 1),
		acRow("id-2", `[{"application":"A","platform":"uap"}]`, 1, 1, "g",
			1600000002, nil, nil, nil, []byte(`"plain string"`), nil, 1),
		acRow("id-3", `[{"application":"A","platform":"uap"}]`, 1, 1, "g",
			1600000003, nil, nil, nil, []byte{0xfe, 0xfd}, nil, 1),
		acRow("id-4", `[{"application":"A","platform":"uap"}]`, 1, 1, "g",
			1600000004, nil, nil, nil, []byte(`[1,2]`), []byte(`  `), 1),
	}
	recs := drainT(t, acMakeDB(t, t.TempDir(), acDDL, acInsert, rows))
	if len(recs) != 5 {
		t.Fatalf("记录数不符: %d", len(recs))
	}
	if recs[0].Norm["payload_format"] != "json" ||
		recs[0].Norm["payload_text"] != "True" { // Python str(True)
		t.Fatalf("bool 标量不符: %+v", recs[0].Norm)
	}
	if recs[1].Norm["payload_format"] != "json" ||
		recs[1].Norm["payload_text"] != "plain string" {
		t.Fatalf("字符串标量不符: %+v", recs[1].Norm)
	}
	if recs[2].Norm["payload_format"] != "opaque" {
		t.Fatalf("坏 UTF-8 应 opaque: %+v", recs[2].Norm)
	}
	if recs[3].Norm["payload_format"] != "json" ||
		recs[3].Norm["payload_text"] != "[1,2]" ||
		recs[3].Norm["clipboard_format"] != "opaque" { // "  " 非 JSON → opaque
		t.Fatalf("数组/空白 payload 不符: %+v", recs[3].Norm)
	}
	s := recs[4].Norm["summary"].(map[string]any)
	if s["payload_json"] != int64(3) || s["payload_opaque"] != int64(1) ||
		s["no_time_rows"] != int64(0) || s["clipboard_nonempty"] != int64(0) {
		t.Fatalf("summary 不符: %+v", s)
	}
}
