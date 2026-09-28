// 浏览器 SQLite 解析器合成样本测试:正样本逐字段焊死 + 负样本(非 SQLite
// 头/缺必备表/缺必备列/坏时间越窗/坏 url)如实失败或计数,零静默;只读
// URI(mode=ro / immutable=1)语义焊死;大行数库内存纪律回归。
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

// buildSQLite 可写模式建合成库(modernc 普通路径 DSN),顺序执行 DDL/DML;
// rel 可含子目录(如 "Users/x/Browser/Edge/History",测浏览器家族标注)。
func buildSQLite(t *testing.T, rel string, stmts ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("建库执行失败 %q: %v", q, err)
		}
	}
	return p
}

// wk(unix 秒)→ Chromium WebKit µs since 1601。
func wk(sec int64) int64 { return (sec + 11644473600) * 1_000_000 }

// fx(us 时间戳测试用):(unix 秒)→ Firefox µs since 1970。
func fx(sec int64) int64 { return sec * 1_000_000 }

const chromiumDDL = `CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER)`

const visitsDDL = `CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER, visit_duration INTEGER)`

const downloadsDDL = `CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid TEXT, current_path TEXT, target_path TEXT, start_time INTEGER, end_time INTEGER, received_bytes INTEGER, total_bytes INTEGER, state INTEGER, danger_type INTEGER, tab_url TEXT, referrer TEXT, site_url TEXT, mime_type TEXT)`

const firefoxDDL = `CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, rev_host TEXT, visit_count INTEGER, typed INTEGER, hidden INTEGER, frecency INTEGER, last_visit_date INTEGER, guid TEXT)`

const firefoxVisitsDDL = `CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type INTEGER, from_visit INTEGER, session INTEGER)`

func summaryOf(t *testing.T, recs []model.Record) map[string]any {
	t.Helper()
	last := recs[len(recs)-1]
	if last.Norm["event_type"] != "browser_summary" {
		t.Fatalf("末条应为 browser_summary: %+v", last.Norm)
	}
	return last.Norm["summary"].(map[string]any)
}

// TestBrowserSQLite_ReadonlyURI 焊死选型前提:可写建库后 mode=ro 只读打开
// 可读、写入被 SQLITE_READONLY 拒;immutable 退化链可用(树庭
// _open_readonly 同语义);含中文/空格路径验证 URI 转义。
func TestBrowserSQLite_ReadonlyURI(t *testing.T) {
	p := buildSQLite(t, "样 本/Browser/Edge/History",
		`CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)`,
		`INSERT INTO t VALUES(1,'a')`,
	)
	db, mode, err := browserOpenSQLite(p)
	if err != nil {
		t.Fatalf("ro 打开失败: %v", err)
	}
	defer db.Close()
	if mode != "ro" {
		t.Fatalf("open_mode 应为 ro: %q", mode)
	}
	var n int64
	if err := db.QueryRow("SELECT COUNT(*) FROM t").Scan(&n); err != nil || n != 1 {
		t.Fatalf("ro 读取失败: n=%d err=%v", n, err)
	}
	if _, err := db.Exec("CREATE TABLE w(x)"); err == nil {
		t.Fatal("ro 模式写入应被拒(SQLITE_READONLY)")
	}
	// immutable 退化链(树庭 immutable_fallback 同语义)
	db2, err := sql.Open("sqlite", browserFileURI(p, "?mode=ro&immutable=1"))
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	if err := db2.Ping(); err != nil {
		t.Fatalf("immutable 只读打开失败: %v", err)
	}
	var m int64
	if err := db2.QueryRow("SELECT COUNT(*) FROM t").Scan(&m); err != nil || m != 1 {
		t.Fatalf("immutable 读取失败: m=%d err=%v", m, err)
	}
}

// TestBrowserChromium_Fields Chromium 三表全:visit 按 visit_time 排序产
// browser_history;urls 有而 visits 无 → url_entry;downloads →
// browser_download;browser 家族按路径 /browser/edge/ 判 edge。
func TestBrowserChromium_Fields(t *testing.T) {
	p := buildSQLite(t, "Users/x/Browser/Edge/History",
		chromiumDDL, visitsDDL, downloadsDDL,
		fmt.Sprintf(`INSERT INTO urls VALUES(1,'https://example.com/','Example',3,1,%d,0)`, wk(1600000000)),
		fmt.Sprintf(`INSERT INTO urls VALUES(2,'file:///C:/x.bin','',0,0,%d,0)`, wk(1600000100)),
		fmt.Sprintf(`INSERT INTO urls VALUES(3,'https://orphan.example.net/p','Orphan',1,0,%d,0)`, wk(1600000200)),
		// visits 故意乱序插,验证 ORDER BY visit_time;id=12 visit_time=0 坏时间
		fmt.Sprintf(`INSERT INTO visits VALUES(10,1,%d,0,16777217,5000)`, wk(1600000100)),
		fmt.Sprintf(`INSERT INTO visits VALUES(11,1,%d,0,1,3000)`, wk(1600000000)),
		`INSERT INTO visits VALUES(12,2,0,0,1,1000)`,
		fmt.Sprintf(`INSERT INTO downloads VALUES(7,'g-1','C:\dl\a.zip.crdownload','C:\dl\a.zip',%d,%d,100,200,1,0,'https://dl.example.org/a.zip','','https://dl.example.org/','application/zip')`,
			wk(1600000300), wk(1600000310)),
	)
	stream, err := BrowserChromiumHistoryParser{}.Records(p)
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, stream)
	if len(recs) != 6 { // 3 visit + 1 url_entry + 1 download + 1 summary
		t.Fatalf("记录数不符: %d", len(recs))
	}
	for i, r := range recs {
		if r.LineNo != i+1 || r.Kind != model.KindEvent {
			t.Fatalf("行号/类别不符: %+v", r)
		}
	}

	// recs[0]: visits:12(visit_time=0 → 坏时间,事件照出,时间不置)
	r0 := recs[0]
	if r0.Raw != "visits:12" || r0.Norm["record_type"] != "visit" ||
		r0.Norm["browser"] != "edge" || r0.Norm["source"] != "chromium_history" {
		t.Fatalf("visits:12 字段不符: %+v", r0.Norm)
	}
	if r0.Norm["visit_utc"] != nil || r0.TsUTCDirect != nil {
		t.Fatalf("坏时间应不置 visit_utc/TsUTCDirect: %+v", r0.Norm)
	}
	if r0.Norm["url"] != "file:///C:/x.bin" || r0.Norm["host"] != nil {
		t.Fatalf("file:// 应无 host(→bad_url): %+v", r0.Norm)
	}

	// recs[1]: visits:11(vt 最早的有效访问)
	r1 := recs[1]
	if r1.Raw != "visits:11" || r1.Norm["url"] != "https://example.com/" ||
		r1.Norm["title"] != "Example" || r1.Norm["host"] != "example.com" ||
		r1.Norm["transition"] != int64(1) ||
		r1.Norm["transition_core"] != int64(1) ||
		r1.Norm["visit_duration_us"] != int64(3000) ||
		r1.Norm["visit_time_raw"] != wk(1600000000) {
		t.Fatalf("visits:11 字段不符: %+v", r1.Norm)
	}
	if r1.Norm["visit_utc"] != "2020-09-13T12:26:40Z" {
		t.Fatalf("visit_utc 不符: %v", r1.Norm["visit_utc"])
	}
	if r1.TsUTCDirect == nil ||
		!r1.TsUTCDirect.Equal(time.Unix(1600000000, 0).UTC()) {
		t.Fatalf("TsUTCDirect 不符: %v", r1.TsUTCDirect)
	}

	// recs[2]: visits:10(transition 0x01000001 → core=1)
	r2 := recs[2]
	if r2.Raw != "visits:10" || r2.Norm["transition"] != int64(16777217) ||
		r2.Norm["transition_core"] != int64(1) ||
		r2.Norm["visit_utc"] != "2020-09-13T12:28:20Z" {
		t.Fatalf("visits:10 字段不符: %+v", r2.Norm)
	}

	// recs[3]: urls:3 残留条目(visits 无对应行)
	r3 := recs[3]
	if r3.Raw != "urls:3" || r3.Norm["record_type"] != "url_entry" ||
		r3.Norm["url"] != "https://orphan.example.net/p" ||
		r3.Norm["host"] != "orphan.example.net" ||
		r3.Norm["visit_count"] != int64(1) || r3.Norm["typed_count"] != int64(0) ||
		r3.Norm["hidden"] != int64(0) ||
		r3.Norm["last_visit_raw"] != wk(1600000200) ||
		r3.Norm["last_visit_utc"] != "2020-09-13T12:30:00Z" {
		t.Fatalf("urls:3 字段不符: %+v", r3.Norm)
	}
	if note, _ := r3.Norm["note"].(string); !strings.Contains(note, "visits 表无对应行") {
		t.Fatalf("url_entry note 不符: %v", r3.Norm["note"])
	}
	if r3.TsUTCDirect == nil ||
		!r3.TsUTCDirect.Equal(time.Unix(1600000200, 0).UTC()) {
		t.Fatalf("url_entry TsUTCDirect 不符: %v", r3.TsUTCDirect)
	}

	// recs[4]: downloads:7
	r4 := recs[4]
	if r4.Norm["event_type"] != "browser_download" || r4.Raw != "downloads:7" ||
		r4.Norm["guid"] != "g-1" ||
		r4.Norm["target_path"] != `C:\dl\a.zip` ||
		r4.Norm["current_path"] != `C:\dl\a.zip.crdownload` ||
		r4.Norm["tab_url"] != "https://dl.example.org/a.zip" ||
		r4.Norm["host"] != "dl.example.org" ||
		r4.Norm["received_bytes"] != int64(100) ||
		r4.Norm["total_bytes"] != int64(200) ||
		r4.Norm["state"] != int64(1) || r4.Norm["danger_type"] != int64(0) ||
		r4.Norm["mime_type"] != "application/zip" ||
		r4.Norm["start_raw"] != wk(1600000300) ||
		r4.Norm["start_utc"] != "2020-09-13T12:31:40Z" ||
		r4.Norm["end_utc"] != "2020-09-13T12:31:50Z" {
		t.Fatalf("downloads:7 字段不符: %+v", r4.Norm)
	}
	if r4.TsUTCDirect == nil ||
		!r4.TsUTCDirect.Equal(time.Unix(1600000300, 0).UTC()) {
		t.Fatalf("download TsUTCDirect 不符: %v", r4.TsUTCDirect)
	}

	// recs[5]: browser_summary(树庭字段集)
	sum := summaryOf(t, recs)
	if sum["source"] != "chromium_history" || sum["open_mode"] != "ro" ||
		sum["url_rows"] != int64(3) || sum["visit_rows"] != int64(3) ||
		sum["download_rows"] != int64(1) ||
		sum["emitted_history"] != int64(4) || sum["emitted_downloads"] != int64(1) ||
		sum["url_only_rows"] != int64(1) || sum["row_errors"] != int64(0) ||
		sum["bad_time_rows"] != int64(1) || sum["bad_url_rows"] != int64(1) ||
		sum["downloads_table"] != true {
		t.Fatalf("summary 不符: %+v", sum)
	}
	tr, _ := sum["time_range_utc"].([]string)
	if len(tr) != 2 || tr[0] != "2020-09-13T12:26:40Z" ||
		tr[1] != "2020-09-13T12:31:40Z" {
		t.Fatalf("time_range_utc 不符: %v", sum["time_range_utc"])
	}
}

// TestBrowserChromium_BadTimeWindow 坏时间谱系:0/负/NULL/越窗 → 时间不置
// + bad_time_rows 计数,事件照出;合理窗端点 [2004,2100] 含端点。
func TestBrowserChromium_BadTimeWindow(t *testing.T) {
	p := buildSQLite(t, "Users/x/Browser/Chrome/History",
		chromiumDDL, visitsDDL,
		fmt.Sprintf(`INSERT INTO urls VALUES(1,'https://a.example/',NULL,0,0,%d,0)`, wk(1600000000)),
		`INSERT INTO visits(id,url,visit_time) VALUES(1,1,NULL)`,
		`INSERT INTO visits(id,url,visit_time) VALUES(2,1,-5)`,
		`INSERT INTO visits(id,url,visit_time) VALUES(3,1,0)`,
		fmt.Sprintf(`INSERT INTO visits(id,url,visit_time) VALUES(4,1,%d)`, wk(951782400)),    // 2000-01-01 越窗
		fmt.Sprintf(`INSERT INTO visits(id,url,visit_time) VALUES(5,1,%d)`, wk(1072915200)),   // 2004-01-01 下界(含)
		fmt.Sprintf(`INSERT INTO visits(id,url,visit_time) VALUES(6,1,%d)`, wk(4102444800)+1), // 2100 越上界 1µs
		fmt.Sprintf(`INSERT INTO visits(id,url,visit_time) VALUES(7,1,%d)`, wk(4102444800)),   // 2100-01-01 上界(含)
	)
	stream, err := BrowserChromiumHistoryParser{}.Records(p)
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, stream)
	if len(recs) != 8 { // 7 visit + 1 summary
		t.Fatalf("记录数不符: %d", len(recs))
	}
	// ORDER BY visit_time:NULL 最前,其后 -5,0,2000,2004,2100,2100+1µs
	wantRaw := []string{"visits:1", "visits:2", "visits:3", "visits:4",
		"visits:5", "visits:7", "visits:6"}
	wantUTC := []any{nil, nil, nil, nil,
		"2004-01-01T00:00:00Z", "2100-01-01T00:00:00Z", nil}
	for i, r := range recs[:7] {
		if r.Raw != wantRaw[i] || r.Norm["event_type"] != "browser_history" {
			t.Fatalf("第 %d 条不符: %+v", i, r)
		}
		if r.Norm["visit_utc"] != wantUTC[i] {
			t.Fatalf("%s visit_utc 不符: got=%v want=%v", r.Raw,
				r.Norm["visit_utc"], wantUTC[i])
		}
		if (r.TsUTCDirect != nil) != (wantUTC[i] != nil) {
			t.Fatalf("%s TsUTCDirect 置位不符: %v", r.Raw, r.TsUTCDirect)
		}
	}
	sum := summaryOf(t, recs)
	if sum["bad_time_rows"] != int64(5) || sum["emitted_history"] != int64(7) {
		t.Fatalf("summary 不符: %+v", sum)
	}
	tr, _ := sum["time_range_utc"].([]string)
	if len(tr) != 2 || tr[0] != "2004-01-01T00:00:00Z" ||
		tr[1] != "2100-01-01T00:00:00Z" {
		t.Fatalf("time_range_utc 不符: %v", sum["time_range_utc"])
	}
	// browser 家族:路径含 /browser/chrome/
	if recs[0].Norm["browser"] != "chrome" {
		t.Fatalf("browser 应为 chrome: %v", recs[0].Norm["browser"])
	}
}

// TestBrowserChromium_NoDownloads 无 downloads 表:downloads_table=false
// 如实标,不算错。
func TestBrowserChromium_NoDownloads(t *testing.T) {
	p := buildSQLite(t, "Users/x/Browser/Edge/History",
		chromiumDDL, visitsDDL,
		fmt.Sprintf(`INSERT INTO urls VALUES(1,'https://a.example/','A',1,0,%d,0)`, wk(1600000000)),
		fmt.Sprintf(`INSERT INTO visits VALUES(1,1,%d,0,1,100)`, wk(1600000000)),
	)
	stream, err := BrowserChromiumHistoryParser{}.Records(p)
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, stream)
	sum := summaryOf(t, recs)
	if sum["downloads_table"] != false || sum["download_rows"] != int64(0) ||
		sum["emitted_downloads"] != int64(0) {
		t.Fatalf("无 downloads 表标注不符: %+v", sum)
	}
}

// TestBrowserChromium_SchemaFail 缺必备表/列 → 文件级如实 failed 并列出
// 实际表/列;非 SQLite 文件 → failed;路径无 /browser/{edge,chrome}/ →
// browser=unknown。
func TestBrowserChromium_SchemaFail(t *testing.T) {
	// urls 缺 last_visit_time
	p := buildSQLite(t, "h1/History",
		`CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT)`, visitsDDL)
	if _, err := (BrowserChromiumHistoryParser{}).Records(p); err == nil ||
		!strings.Contains(err.Error(), "urls 表缺必备列") {
		t.Fatalf("缺必备列应文件级 failed: %v", err)
	}
	// 无 visits 表
	p = buildSQLite(t, "h2/History", chromiumDDL)
	if _, err := (BrowserChromiumHistoryParser{}).Records(p); err == nil ||
		!strings.Contains(err.Error(), "无 visits 表") {
		t.Fatalf("缺 visits 表应文件级 failed: %v", err)
	}
	// 非 SQLite 文件
	if _, err := (BrowserChromiumHistoryParser{}).Records(
		writeTemp(t, "History", []byte("this is not a sqlite db at all...."))); err == nil ||
		!strings.Contains(err.Error(), "非 SQLite") {
		t.Fatalf("非 SQLite 头应文件级 failed: %v", err)
	}
	// 空文件 → 空库 → schema 校验如实 failed
	if _, err := (BrowserChromiumHistoryParser{}).Records(
		writeTemp(t, "History", nil)); err == nil {
		t.Fatal("空文件应文件级如实 failed(空库无 urls 表)")
	}
	// 路径无浏览器家族片段 → unknown
	p = buildSQLite(t, "somewhere/History",
		chromiumDDL, visitsDDL,
		fmt.Sprintf(`INSERT INTO urls VALUES(1,'https://a.example/','A',1,0,%d,0)`, wk(1600000000)),
		fmt.Sprintf(`INSERT INTO visits VALUES(1,1,%d,0,1,100)`, wk(1600000000)),
	)
	stream, err := BrowserChromiumHistoryParser{}.Records(p)
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, stream)
	if recs[0].Norm["browser"] != "unknown" {
		t.Fatalf("browser 应为 unknown: %v", recs[0].Norm["browser"])
	}
}

// TestBrowserFirefox_Fields Firefox 两表:visit/url_entry/summary 逐字段;
// µs since 1970;browser 固定 firefox;坏时间/坏 url 如实计数。
func TestBrowserFirefox_Fields(t *testing.T) {
	p := buildSQLite(t, "Profiles/abcd.default-release/places.sqlite",
		firefoxDDL, firefoxVisitsDDL,
		fmt.Sprintf(`INSERT INTO moz_places VALUES(1,'https://fx.example.com/','Fx','moc.elpmaxe.xf.',5,1,0,100,%d,'guid-1')`, fx(1600000000)),
		fmt.Sprintf(`INSERT INTO moz_places VALUES(2,'https://only.example.org/','Only','gro.elpmaxe.ylno.',2,0,0,50,%d,'guid-2')`, fx(1600000500)),
		`INSERT INTO moz_places VALUES(3,'','','',0,0,0,0,NULL,'guid-3')`,
		fmt.Sprintf(`INSERT INTO moz_historyvisits VALUES(20,1,%d,2,0,1)`, fx(1600000000)),
		`INSERT INTO moz_historyvisits VALUES(21,1,0,1,0,1)`,                               // 坏时间
		fmt.Sprintf(`INSERT INTO moz_historyvisits VALUES(22,3,%d,1,0,1)`, fx(1600000100)), // 空 url → bad_url
	)
	stream, err := BrowserFirefoxPlacesParser{}.Records(p)
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, stream)
	if len(recs) != 5 { // 3 visit + 1 url_entry + 1 summary
		t.Fatalf("记录数不符: %d", len(recs))
	}
	// ORDER BY visit_date:0(21) → 1600000000000000(20) → 1600000100000000(22)
	r0 := recs[0] // visits 21:坏时间
	if r0.Raw != "moz_historyvisits:21" || r0.Norm["source"] != "firefox_places" ||
		r0.Norm["browser"] != "firefox" || r0.Norm["record_type"] != "visit" ||
		r0.Norm["visit_utc"] != nil || r0.TsUTCDirect != nil ||
		r0.Norm["host"] != "fx.example.com" {
		t.Fatalf("visit 21 字段不符: %+v", r0.Norm)
	}
	r1 := recs[1] // visits 20:正常
	if r1.Raw != "moz_historyvisits:20" || r1.Norm["url"] != "https://fx.example.com/" ||
		r1.Norm["title"] != "Fx" || r1.Norm["visit_type"] != int64(2) ||
		r1.Norm["from_visit"] != int64(0) ||
		r1.Norm["visit_date_raw"] != fx(1600000000) ||
		r1.Norm["visit_utc"] != "2020-09-13T12:26:40Z" {
		t.Fatalf("visit 20 字段不符: %+v", r1.Norm)
	}
	if r1.TsUTCDirect == nil ||
		!r1.TsUTCDirect.Equal(time.Unix(1600000000, 0).UTC()) {
		t.Fatalf("visit 20 TsUTCDirect 不符: %v", r1.TsUTCDirect)
	}
	r2 := recs[2] // visits 22:空 url → bad_url,事件照出
	if r2.Raw != "moz_historyvisits:22" || r2.Norm["url"] != "" ||
		r2.Norm["host"] != nil || r2.Norm["visit_utc"] != "2020-09-13T12:28:20Z" {
		t.Fatalf("visit 22 字段不符: %+v", r2.Norm)
	}
	r3 := recs[3] // moz_places:2 残留条目
	if r3.Raw != "moz_places:2" || r3.Norm["record_type"] != "url_entry" ||
		r3.Norm["url"] != "https://only.example.org/" ||
		r3.Norm["host"] != "only.example.org" ||
		r3.Norm["guid"] != "guid-2" ||
		r3.Norm["visit_count"] != int64(2) || r3.Norm["typed"] != int64(0) ||
		r3.Norm["hidden"] != int64(0) || r3.Norm["frecency"] != int64(50) ||
		r3.Norm["last_visit_raw"] != fx(1600000500) ||
		r3.Norm["last_visit_utc"] != "2020-09-13T12:35:00Z" {
		t.Fatalf("moz_places:2 字段不符: %+v", r3.Norm)
	}
	if note, _ := r3.Norm["note"].(string); !strings.Contains(note, "moz_historyvisits 无对应行") {
		t.Fatalf("url_entry note 不符: %v", r3.Norm["note"])
	}
	sum := summaryOf(t, recs)
	if sum["source"] != "firefox_places" || sum["open_mode"] != "ro" ||
		sum["place_rows"] != int64(3) || sum["visit_rows"] != int64(3) ||
		sum["emitted_history"] != int64(4) || sum["url_only_rows"] != int64(1) ||
		sum["row_errors"] != int64(0) || sum["bad_time_rows"] != int64(1) ||
		sum["bad_url_rows"] != int64(1) {
		t.Fatalf("summary 不符: %+v", sum)
	}
	tr, _ := sum["time_range_utc"].([]string)
	if len(tr) != 2 || tr[0] != "2020-09-13T12:26:40Z" ||
		tr[1] != "2020-09-13T12:35:00Z" {
		t.Fatalf("time_range_utc 不符: %v", sum["time_range_utc"])
	}
}

// TestBrowserFirefox_SchemaFail 缺 moz_ 表/必备列 → 文件级如实 failed。
func TestBrowserFirefox_SchemaFail(t *testing.T) {
	p := buildSQLite(t, "p1/places.sqlite",
		`CREATE TABLE moz_places(id INTEGER PRIMARY KEY)`) // 缺 url 列
	if _, err := (BrowserFirefoxPlacesParser{}).Records(p); err == nil ||
		!strings.Contains(err.Error(), "moz_places 表缺必备列") {
		t.Fatalf("缺必备列应文件级 failed: %v", err)
	}
	p = buildSQLite(t, "p2/places.sqlite", chromiumDDL) // 无 moz_ 表
	if _, err := (BrowserFirefoxPlacesParser{}).Records(p); err == nil ||
		!strings.Contains(err.Error(), "无 moz_places 表") {
		t.Fatalf("缺 moz_places 表应文件级 failed: %v", err)
	}
}

// 内存纪律:30 万 urls + 30 万 visits 库,装载后(峰值驻留)与流式扫完后
// 堆增量均 <64MB(树庭同形态全量索引,此处验证上限保护下的真实驻留)。
func TestBrowserChromium_MemoryFlat(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过大输入内存用例")
	}
	const n = 300000
	p := buildSQLite(t, "big/History",
		chromiumDDL, visitsDDL,
		fmt.Sprintf(`WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<%d)
INSERT INTO urls(id,url,title,visit_count,typed_count,last_visit_time,hidden)
SELECT x,'https://h'||(x%%997)||'.example.com/p'||x,'t'||x,1,0,%d+x,0 FROM c`, n, wk(1600000000)),
		fmt.Sprintf(`WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<%d)
INSERT INTO visits(id,url,visit_time,from_visit,transition,visit_duration)
SELECT x,x,%d+x,0,1,100 FROM c`, n, wk(1600000000)),
	)

	var m0, m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	stream, err := BrowserChromiumHistoryParser{}.Records(p)
	if err != nil {
		t.Fatal(err)
	}
	// 峰值:urls 索引全量驻留(visit 反查需要)
	runtime.GC()
	runtime.ReadMemStats(&m1)
	var emitted int64
	var sum map[string]any
	for {
		rec, ok := stream.Next()
		if !ok {
			break
		}
		if rec.Norm["event_type"] == "browser_summary" {
			sum = rec.Norm["summary"].(map[string]any)
		} else {
			emitted++
		}
	}
	if err := stream.Err(); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	runtime.ReadMemStats(&m2)
	stream.Close()

	if sum == nil || sum["emitted_history"] != int64(n) ||
		sum["url_rows"] != int64(n) || sum["visit_rows"] != int64(n) ||
		sum["url_only_rows"] != int64(0) {
		t.Fatalf("大库计数不符: emitted=%d sum=%+v", emitted, sum)
	}
	peak := int64(m1.HeapAlloc) - int64(m0.HeapAlloc)
	after := int64(m2.HeapAlloc) - int64(m0.HeapAlloc)
	if peak > 64<<20 {
		t.Fatalf("urls 装载峰值堆增量 %d MB 超 64MB 纪律线", peak>>20)
	}
	if after > 64<<20 {
		t.Fatalf("流式扫完堆增量 %d MB 超 64MB 纪律线(流式回归!)", after>>20)
	}
	t.Logf("%d urls+visits:装载峰值 %.1f MB,扫完 %.1f MB,emitted=%d",
		n, float64(peak)/(1<<20), float64(after)/(1<<20), emitted)
}
