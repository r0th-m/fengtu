// 浏览器历史 SQLite 原生解析:Chromium History(urls/visits/downloads)+
// Firefox places.sqlite(moz_places/moz_historyvisits)。语义基准 = 树庭
// backend/app/parsers/browser_sqlite.py 中 parse_chromium_history /
// parse_firefox_places 两个 parser(金标准,逐字段对拍)。
//
// 选型:modernc.org/sqlite(纯 Go 移植版 SQLite,零 CGO,已 vendor
// v1.39.1)。驱动对 file: 前缀 DSN 原样透传查询串并以 SQLITE_OPEN_URI 打开,
// 故 mode=ro / immutable=1 是 SQLite 核原生 URI 语义(已读驱动源码确认,
// 并有合成测试焊死:可写建库后 ro 打开可读、写入被 SQLITE_READONLY 拒,
// immutable 退化链可用)。
//
// 格式契约(对公开 schema 写,不猜):
//   - Chromium History(Chrome/Edge 同 schema):urls(id/url/title/
//     visit_count/typed_count/last_visit_time/hidden)、visits(id/url→
//     urls.id/visit_time/transition/visit_duration)、downloads(guid/
//     current_path/target_path/start_time/end_time/received_bytes/
//     total_bytes/state/danger_type/tab_url/referrer/site_url/mime_type);
//   - Firefox places.sqlite:moz_places(id/url/title/rev_host/visit_count/
//     typed/hidden/frecency/last_visit_date/guid)、moz_historyvisits(id/
//     place_id/visit_date/visit_type/from_visit/session);
//   - 必备表/列缺失 → 文件级如实 failed 并列出实际表/列;downloads 表没有
//     → summary 里 downloads_table=false 如实标,不算错;
//   - 非 SQLite 文件(头 16 字节 != "SQLite format 3\x00")→ 文件级如实
//     failed;空文件 SQLite 视为空库 → schema 校验如实 failed(列出实际表)。
//
// 时间纪律(同树庭 §9.3):
//   - Chromium = WebKit µs since 1601-01-01 UTC;Firefox = µs since 1970;
//     原生 UTC → TsUTCDirect 直通 + Norm 里 *_utc ISO 字符串留证;
//   - 合理窗 [2004-01-01, 2100-01-01] 含端点(Firefox 1.0 发布于 2004,
//     统一下界;2100 后不猜);越窗/0/负/非整数 → 时间不置 +
//     bad_time_rows 计数,事件照出(ts 留 nil),不猜。
//
// 与树庭的口径差(如实):
//   - wal_residue 字段不落(树庭查金库 artifacts 表判 -wal 伴生 artifact,
//     丰图解析器只见单文件,无此上下文;-wal 存在与否由采集/摄取层负责);
//   - urls/moz_places 全量内存索引设上限 browserMaxURLRows(200 万行,
//     真实样本万级),超限部分不入索引、url_map_overflow_rows 如实计数
//     (树庭无上限,此为内存纪律加的结构性保护);
//   - 驻留索引的数值列只按 SQLite INTEGER(int64)接受:TEXT/REAL 混杂的
//     损坏单元格按 NULL 落(树庭原样透传)——正常库 INTEGER 亲和性下无差;
//   - Firefox 时间换算用整数除法(µs 精确);树庭是 v/1e6 浮点,µs 位可能
//     有 ±1 浮点舍入差(秒精度 *_utc 不受影响,TsUTCDirect 我们更准)。
//
// 流式纪律:visits/moz_historyvisits/downloads 走 rows.Next() 行级游标,
// 单条事件即产即放;仅 url 表(visit 外键反查需要)全量驻留,且 url_only
// 阶段结束即释放;连接数限 1,防并发连接放大内存。
package parsers

import (
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // 纯 Go SQLite 驱动(零 CGO;注册名 "sqlite")

	"github.com/ye-mengwen/fengtu/internal/model"
)

// browserMaxURLRows urls/moz_places 全量内存索引上限(结构上限,不是案件值)。
const browserMaxURLRows = 2_000_000

var (
	// 合理窗 [2004-01-01, 2100-01-01](树庭 _T_MIN/_T_MAX 同值)。
	browserTimeMin = time.Date(2004, 1, 1, 0, 0, 0, 0, time.UTC)
	browserTimeMax = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
)

// 列按树庭 *_WANT 固定序选取(只取实际存在的列;缺可选列 → 事件对应字段
// nil,诚实不猜)。
var (
	browserChromiumURLsWant = []string{"id", "url", "title", "visit_count",
		"typed_count", "last_visit_time", "hidden"}
	browserChromiumVisitsWant = []string{"id", "url", "visit_time", "from_visit",
		"transition", "visit_duration"}
	browserChromiumDownloadsWant = []string{"id", "guid", "current_path",
		"target_path", "start_time", "end_time", "received_bytes", "total_bytes",
		"state", "danger_type", "tab_url", "referrer", "site_url", "mime_type"}
	browserFirefoxPlacesWant = []string{"id", "url", "title", "rev_host",
		"visit_count", "typed", "hidden", "frecency", "last_visit_date", "guid"}
	browserFirefoxVisitsWant = []string{"id", "place_id", "visit_date",
		"visit_type", "from_visit", "session"}
)

// ---- 打开与 schema 判别 ----

// browserOpenSQLite 金库原件只读打开(树庭 _open_readonly 同链):先 mode=ro,
// 打不开退化 mode=ro&immutable=1(WAL 库无 shm 时 ro 拒开;immutable 明示
// 「无恢复无锁」语义,-wal 不重放),打开方式经返回值在 summary 如实标注。
func browserOpenSQLite(path string) (db *sql.DB, openMode string, err error) {
	if err := browserCheckHeader(path); err != nil {
		return nil, "", err
	}
	var lastErr error
	for _, cand := range []struct{ query, mode string }{
		{"?mode=ro", "ro"},
		{"?mode=ro&immutable=1", "immutable_fallback"},
	} {
		db, err := sql.Open("sqlite", browserFileURI(path, cand.query))
		if err != nil {
			lastErr = err
			continue
		}
		db.SetMaxOpenConns(1) // 行级游标串行,防并发连接放大内存
		if err := db.Ping(); err != nil {
			lastErr = err
			db.Close()
			continue
		}
		return db, cand.mode, nil
	}
	return nil, "", fmt.Errorf("SQLite 只读打开失败(ro 与 immutable 均拒): %w", lastErr)
}

// browserCheckHeader 打开期自查文件头(非 SQLite → 文件级如实 failed)。
// 空文件放行:SQLite 视零字节文件为空库,交由 schema 校验如实 failed。
func browserCheckHeader(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("打开失败: %w", err)
	}
	defer f.Close()
	var hdr [16]byte
	n, _ := io.ReadFull(f, hdr[:])
	if n == 0 {
		return nil // 空文件:不是「非 SQLite」,是空库
	}
	if n < len(hdr) || string(hdr[:]) != "SQLite format 3\x00" {
		return fmt.Errorf("非 SQLite 数据库文件(头 %d 字节与 \"SQLite format 3\\x00\" 不符)", n)
	}
	return nil
}

// browserFileURI 路径 → file: URI(树庭 quote(path.replace("\\","/"),
// safe="/:") 同口径:非保留字节百分号编码,"/" 与 ":" 保留)。
func browserFileURI(path, query string) string {
	var b strings.Builder
	b.WriteString("file:")
	for _, c := range []byte(filepath.ToSlash(path)) {
		switch {
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9':
			b.WriteByte(c)
		case c == '-' || c == '.' || c == '_' || c == '~' || c == '/' || c == ':':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	b.WriteString(query)
	return b.String()
}

// browserTables 实际表名集。
func browserTables(db *sql.DB) (map[string]bool, error) {
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

// browserCols 表的实际列名集。
func browserCols(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query(`PRAGMA table_info("` + table + `")`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int64
		var name, ctype string
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

// browserRequireCols 必备表/列判别;缺失 → error 列出实际表/列,不猜
// (树庭 _require 同口径)。返回实际列集。
func browserRequireCols(db *sql.DB, table string, required ...string) (map[string]bool, error) {
	tables, err := browserTables(db)
	if err != nil {
		return nil, fmt.Errorf("schema 读取失败: %w", err)
	}
	if !tables[table] {
		names := make([]string, 0, len(tables))
		for n := range tables {
			names = append(names, n)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("无 %s 表(实际表: %v;schema 变体未覆盖,如实 failed 不猜)",
			table, names)
	}
	cols, err := browserCols(db, table)
	if err != nil {
		return nil, fmt.Errorf("schema 读取失败(%s): %w", table, err)
	}
	var missing []string
	for _, r := range required {
		if !cols[r] {
			missing = append(missing, r)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("%s 表缺必备列 %v,不猜", table, missing)
	}
	return cols, nil
}

// browserSelect 构造只含实际存在列的 SELECT(want 固定序),返回行游标与
// 选中列名;orderBy 空串则不加 ORDER BY。
func browserSelect(db *sql.DB, table string, want []string, have map[string]bool,
	orderBy string) (*sql.Rows, []string, error) {
	var sel []string
	for _, c := range want {
		if have[c] {
			sel = append(sel, c)
		}
	}
	q := `SELECT "` + strings.Join(sel, `","`) + `" FROM "` + table + `"`
	if orderBy != "" {
		q += ` ORDER BY "` + orderBy + `"`
	}
	rows, err := db.Query(q)
	return rows, sel, err
}

// browserScanRow 一行 → map(列名 → 原值);Scan 失败 → error(调用方计
// row_errors,零静默)。
func browserScanRow(rows *sql.Rows, cols []string) (map[string]any, error) {
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		return nil, err
	}
	m := make(map[string]any, len(cols))
	for i, c := range cols {
		m[c] = vals[i]
	}
	return m, nil
}

// ---- 时间/host/数值换算 ----

// browserInt 单元格 → int64:INTEGER 直取;纯数字字符串同树庭
// _webkit_to_utc 的 str.isdigit() 分支接受;其它类型 → false(不猜)。
func browserInt(v any) (int64, bool) {
	switch t := v.(type) {
	case int64:
		return t, true
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0, false
		}
		for i := 0; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				return 0, false
			}
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// browserInWindow 合理窗判定 [2004,2100] 含端点(树庭 _T_MIN<=dt<=_T_MAX)。
func browserInWindow(t time.Time) (time.Time, bool) {
	if t.Before(browserTimeMin) || t.After(browserTimeMax) {
		return time.Time{}, false
	}
	return t, true
}

// browserWebkitToUTC Chromium/WebKit µs since 1601-01-01 UTC → UTC;
// 0/负/非整数/越窗 → false(不猜,调用方计 bad_time_rows)。
// 拆 sec/µs 再合成,避免大数直接 ×1000 溢出 int64。
func browserWebkitToUTC(v any) (time.Time, bool) {
	n, ok := browserInt(v)
	if !ok || n <= 0 {
		return time.Time{}, false
	}
	return browserInWindow(time.Unix(n/1_000_000-11644473600, n%1_000_000*1000).UTC())
}

// browserFxToUTC Firefox µs since 1970 → UTC(同窗口;整数除法,µs 精确)。
func browserFxToUTC(v any) (time.Time, bool) {
	n, ok := browserInt(v)
	if !ok || n <= 0 {
		return time.Time{}, false
	}
	return browserInWindow(time.Unix(n/1_000_000, n%1_000_000*1000).UTC())
}

// browserISO 合法时间 → RFC3339 秒精度字符串(树庭 _iso 同口径);非法 → nil。
func browserISO(t time.Time, ok bool) any {
	if !ok {
		return nil
	}
	return t.Format("2006-01-02T15:04:05Z")
}

// browserHostOf URL → 小写 hostname;非字符串/空/解不出/无 host(file://
// 等)→ ""(调用方计 bad_url_rows,树庭 _host_of 同口径返回 None)。
func browserHostOf(v any) string {
	s, ok := v.(string)
	if !ok || s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// browserHostVal host → Norm 值(空 → nil,树庭 None)。
func browserHostVal(h string) any {
	if h == "" {
		return nil
	}
	return h
}

// browserChromiumFamily 路径里的浏览器家族标注(树庭 _chromium_browser 同
// 逻辑:/browser/edge/ → edge,/browser/chrome/ → chrome,否则 unknown)。
func browserChromiumFamily(path string) string {
	p := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	if strings.Contains(p, "/browser/edge/") {
		return "edge"
	}
	if strings.Contains(p, "/browser/chrome/") {
		return "chrome"
	}
	return "unknown"
}

// ---- url 表驻留索引(visit 外键反查) ----
//
// 两阶段反查需 url 表全量驻留内存,故每源一个紧凑结构体(字符串/整数各就
// 各位 + ok 位掩码标 NULL;非 TEXT/INTEGER 的损坏单元格按 NULL 落,见文件
// 头口径差说明),装载器泛型化并先 COUNT(*) 预分配,免 map 倍增搬迁。

const (
	browserRowOKURL uint8 = 1 << iota
	browserRowOKTitle
	browserRowOKGUID
	// nums[i] 的有效位 = 1<<(3+i)
)

// chromiumURLRow urls 行驻留条目。
// nums: [0]visit_count [1]typed_count [2]last_visit_time [3]hidden
type chromiumURLRow struct {
	url, title string
	nums       [4]int64
	ok         uint8
	visited    bool
}

// firefoxPlaceRow moz_places 行驻留条目。
// nums: [0]visit_count [1]typed [2]hidden [3]frecency [4]last_visit_date
type firefoxPlaceRow struct {
	url, title, guid string
	nums             [5]int64
	ok               uint8
	visited          bool
}

func (r chromiumURLRow) urlVal() any {
	if r.ok&browserRowOKURL != 0 {
		return r.url
	}
	return nil
}

func (r chromiumURLRow) titleVal() any {
	if r.ok&browserRowOKTitle != 0 {
		return r.title
	}
	return nil
}

func (r firefoxPlaceRow) urlVal() any {
	if r.ok&browserRowOKURL != 0 {
		return r.url
	}
	return nil
}

func (r firefoxPlaceRow) titleVal() any {
	if r.ok&browserRowOKTitle != 0 {
		return r.title
	}
	return nil
}

func (r firefoxPlaceRow) guidVal() any {
	if r.ok&browserRowOKGUID != 0 {
		return r.guid
	}
	return nil
}

// numVal nums[i] → Norm 值(位未置 → nil,树庭 None)。
func (r chromiumURLRow) numVal(i int) any {
	if r.ok&(1<<(3+i)) != 0 {
		return r.nums[i]
	}
	return nil
}

func (r firefoxPlaceRow) numVal(i int) any {
	if r.ok&(1<<(3+i)) != 0 {
		return r.nums[i]
	}
	return nil
}

// timeVal nums[i] 存的时间原值 → UTC(位未置 → false;换算走传入的源纪元)。
func (r chromiumURLRow) timeVal(i int, toUTC func(any) (time.Time, bool)) (time.Time, bool) {
	if r.ok&(1<<(3+i)) == 0 {
		return time.Time{}, false
	}
	return toUTC(r.nums[i])
}

func (r firefoxPlaceRow) timeVal(i int, toUTC func(any) (time.Time, bool)) (time.Time, bool) {
	if r.ok&(1<<(3+i)) == 0 {
		return time.Time{}, false
	}
	return toUTC(r.nums[i])
}

// newChromiumURLRow urls 行 → 驻留索引条目。
func newChromiumURLRow(rec map[string]any) chromiumURLRow {
	var r chromiumURLRow
	if s, ok := rec["url"].(string); ok {
		r.url, r.ok = s, r.ok|browserRowOKURL
	}
	if s, ok := rec["title"].(string); ok {
		r.title, r.ok = s, r.ok|browserRowOKTitle
	}
	for i, c := range []string{"visit_count", "typed_count", "last_visit_time", "hidden"} {
		if n, ok := rec[c].(int64); ok {
			r.nums[i] = n
			r.ok |= 1 << (3 + i)
		}
	}
	return r
}

// newFirefoxPlaceRow moz_places 行 → 驻留索引条目。
func newFirefoxPlaceRow(rec map[string]any) firefoxPlaceRow {
	var r firefoxPlaceRow
	if s, ok := rec["url"].(string); ok {
		r.url, r.ok = s, r.ok|browserRowOKURL
	}
	if s, ok := rec["title"].(string); ok {
		r.title, r.ok = s, r.ok|browserRowOKTitle
	}
	if s, ok := rec["guid"].(string); ok {
		r.guid, r.ok = s, r.ok|browserRowOKGUID
	}
	for i, c := range []string{"visit_count", "typed", "hidden", "frecency",
		"last_visit_date"} {
		if n, ok := rec[c].(int64); ok {
			r.nums[i] = n
			r.ok |= 1 << (3 + i)
		}
	}
	return r
}

// browserStats 行计数与时间窗(树庭 summary 口径;两源共用)。
type browserStats struct {
	urlRows, visitRows, downloadRows int64
	emittedHist, emittedDL           int64
	urlOnly, rowErr                  int64
	badTime, badURL                  int64
	urlOverflow                      int64
	tMin, tMax                       time.Time
	hasTime                          bool
}

// track 合法时间进 time_range 窗口(树庭 _track 同语义)。
func (b *browserStats) track(t time.Time, ok bool) {
	if !ok {
		return
	}
	if !b.hasTime || t.Before(b.tMin) {
		b.tMin = t
	}
	if !b.hasTime || t.After(b.tMax) {
		b.tMax = t
	}
	b.hasTime = true
}

// timeRange time_range_utc 字段值(无合法时间 → nil,不猜)。
func (b *browserStats) timeRange() any {
	if !b.hasTime {
		return nil
	}
	return []string{
		b.tMin.Format("2006-01-02T15:04:05Z"),
		b.tMax.Format("2006-01-02T15:04:05Z"),
	}
}

// browserLoadURLRows url 表全量进 map(visit 外键反查);上限保护,超限
// 部分不入索引、urlOverflow 如实计数。order 保留扫描序(url_only 阶段
// 输出确定性,与树庭 dict 插入序同口径)。先 COUNT(*) 预分配,免 map
// 倍增搬迁的瞬时双倍驻留。
func browserLoadURLRows[T any](db *sql.DB, table string, want []string, have map[string]bool,
	mk func(map[string]any) T, st *browserStats) (map[int64]T, []int64, error) {
	var count int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM "` + table + `"`).Scan(&count); err != nil {
		return nil, nil, fmt.Errorf("SQLite 查询失败(%s 计数): %w", table, err)
	}
	if count > browserMaxURLRows {
		count = browserMaxURLRows
	}
	rows, sel, err := browserSelect(db, table, want, have, "")
	if err != nil {
		return nil, nil, fmt.Errorf("SQLite 查询失败(%s): %w", table, err)
	}
	defer rows.Close()
	m := make(map[int64]T, count)
	order := make([]int64, 0, count)
	for rows.Next() {
		st.urlRows++
		rec, err := browserScanRow(rows, sel)
		if err != nil {
			st.rowErr++
			continue
		}
		id, ok := rec["id"].(int64)
		if !ok {
			st.rowErr++
			continue
		}
		if len(m) >= browserMaxURLRows {
			st.urlOverflow++
			continue
		}
		if _, dup := m[id]; !dup {
			order = append(order, id)
		}
		m[id] = mk(rec)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("SQLite 查询失败(%s): %w", table, err)
	}
	return m, order, nil
}

// ==================== Chromium History ====================

// BrowserChromiumHistoryParser Chromium History(Chrome/Edge 同 schema)
// 解析器:urls 全量索引 → visits 流式扫(ORDER BY visit_time)产
// browser_history(record_type=visit)→ urls 有而 visits 无的残留条目补产
// browser_history(record_type=url_entry)→ downloads 流式扫产
// browser_download → 收尾 browser_summary。
type BrowserChromiumHistoryParser struct{}

type chromiumHistoryStream struct {
	db       *sql.DB
	browser  string
	openMode string
	urls     map[int64]chromiumURLRow
	urlOrder []int64
	stats    browserStats

	visits    *sql.Rows
	visitCols []string
	downloads *sql.Rows
	dlCols    []string
	dlHave    map[string]bool
	hasDL     bool

	phase  int // 0=visits 1=url_only 2=downloads 3=summary 4=done
	urlIdx int
	lineNo int
	err    error
}

// Records 打开 Chromium History:文件头/schema 校验与 urls 全量装载在打开期
// 完成(不合规 → 文件级如实 failed);visits/downloads 走行级游标流式产出。
func (BrowserChromiumHistoryParser) Records(path string) (Stream, error) {
	db, mode, err := browserOpenSQLite(path)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (Stream, error) {
		db.Close()
		return nil, err
	}
	uhave, err := browserRequireCols(db, "urls", "id", "url", "last_visit_time")
	if err != nil {
		return fail(err)
	}
	vhave, err := browserRequireCols(db, "visits", "id", "url", "visit_time")
	if err != nil {
		return fail(err)
	}
	tables, err := browserTables(db)
	if err != nil {
		return fail(fmt.Errorf("schema 读取失败: %w", err))
	}
	s := &chromiumHistoryStream{
		db: db, browser: browserChromiumFamily(path), openMode: mode,
		hasDL: tables["downloads"],
	}
	if s.hasDL {
		if s.dlHave, err = browserRequireCols(db, "downloads", "id", "start_time"); err != nil {
			return fail(err)
		}
	}
	if s.urls, s.urlOrder, err = browserLoadURLRows(db, "urls",
		browserChromiumURLsWant, uhave, newChromiumURLRow, &s.stats); err != nil {
		return fail(err)
	}
	s.visits, s.visitCols, err = browserSelect(db, "visits",
		browserChromiumVisitsWant, vhave, "visit_time")
	if err != nil {
		return fail(fmt.Errorf("SQLite 查询失败(visits): %w", err))
	}
	return s, nil
}

// Next 按 visits → url_only → downloads → summary 序产出。
func (s *chromiumHistoryStream) Next() (model.Record, bool) {
	for {
		switch s.phase {
		case 0: // visits 流式扫(ORDER BY visit_time)
			if s.visits.Next() {
				s.stats.visitRows++
				rec, err := browserScanRow(s.visits, s.visitCols)
				if err != nil {
					s.stats.rowErr++
					continue
				}
				if r, ok := s.visitRecord(rec); ok {
					s.lineNo++
					s.stats.emittedHist++
					r.LineNo = s.lineNo
					return r, true
				}
				continue // 行级坏已计 rowErr,零静默
			}
			if err := s.visits.Err(); err != nil {
				s.err = fmt.Errorf("SQLite 游标失败(visits): %w", err)
				s.phase = 4
				continue
			}
			s.visits.Close()
			s.visits = nil
			s.phase = 1
		case 1: // urls 有而 visits 无的残留条目(历史截断,树庭同款补产)
			if s.urlIdx < len(s.urlOrder) {
				id := s.urlOrder[s.urlIdx]
				s.urlIdx++
				u := s.urls[id]
				if u.visited {
					continue
				}
				s.stats.urlOnly++
				s.lineNo++
				s.stats.emittedHist++
				r := s.urlEntryRecord(id, u)
				r.LineNo = s.lineNo
				return r, true
			}
			// 索引使命完成即释放(内存纪律:downloads/summary 阶段不再占用)
			s.urls = nil
			s.urlOrder = nil
			if s.hasDL {
				var err error
				s.downloads, s.dlCols, err = browserSelect(s.db, "downloads",
					browserChromiumDownloadsWant, s.dlHave, "start_time")
				if err != nil {
					s.err = fmt.Errorf("SQLite 查询失败(downloads): %w", err)
					s.phase = 4
					continue
				}
			}
			s.phase = 2
		case 2: // downloads 流式扫(ORDER BY start_time)
			if s.hasDL {
				if s.downloads.Next() {
					s.stats.downloadRows++
					rec, err := browserScanRow(s.downloads, s.dlCols)
					if err != nil {
						s.stats.rowErr++
						continue
					}
					s.lineNo++
					s.stats.emittedDL++
					r := s.downloadRecord(rec)
					r.LineNo = s.lineNo
					return r, true
				}
				if err := s.downloads.Err(); err != nil {
					s.err = fmt.Errorf("SQLite 游标失败(downloads): %w", err)
					s.phase = 4
					continue
				}
				s.downloads.Close()
				s.downloads = nil
			}
			s.phase = 3
		case 3: // 收尾 browser_summary
			s.phase = 4
			s.lineNo++
			return s.summaryRecord(), true
		default:
			return model.Record{}, false
		}
	}
}

// visitRecord visits 行 → browser_history(record_type=visit);行级类型坏
// (transition 非整数非 NULL,树庭此处 TypeError)→ false 且已计 rowErr。
func (s *chromiumHistoryStream) visitRecord(rec map[string]any) (model.Record, bool) {
	// transition_core = (transition or 0) & 0xFF(树庭原式)
	var transCore int64
	switch t := rec["transition"].(type) {
	case nil:
	case int64:
		transCore = t & 0xFF
	default:
		s.stats.rowErr++
		return model.Record{}, false
	}
	var u chromiumURLRow
	if vid, ok := rec["url"].(int64); ok {
		if e, found := s.urls[vid]; found {
			e.visited = true
			s.urls[vid] = e
			u = e
		}
	}
	vt, vtOK := browserWebkitToUTC(rec["visit_time"])
	if !vtOK {
		s.stats.badTime++
	}
	s.stats.track(vt, vtOK)
	host := browserHostOf(u.urlVal())
	if host == "" {
		s.stats.badURL++
	}
	norm := map[string]any{
		"event_type":        "browser_history",
		"source":            "chromium_history",
		"record_type":       "visit",
		"browser":           s.browser,
		"url":               u.urlVal(),
		"title":             u.titleVal(),
		"host":              browserHostVal(host),
		"transition":        rec["transition"],
		"transition_core":   transCore,
		"visit_duration_us": rec["visit_duration"],
		"visit_time_raw":    rec["visit_time"],
		"visit_utc":         browserISO(vt, vtOK),
	}
	r := model.Record{Kind: model.KindEvent, Norm: norm,
		Raw: fmt.Sprintf("visits:%v", rec["id"])}
	if vtOK {
		r.TsUTCDirect = &vt
	}
	return r, true
}

// urlEntryRecord urls 残留条目 → browser_history(record_type=url_entry);
// 时间为 urls.last_visit_time(坏时间不计 bad_time,树庭同口径只 track)。
func (s *chromiumHistoryStream) urlEntryRecord(id int64, u chromiumURLRow) model.Record {
	lv, lvOK := u.timeVal(2, browserWebkitToUTC) // last_visit_time
	s.stats.track(lv, lvOK)
	host := browserHostOf(u.urlVal())
	norm := map[string]any{
		"event_type":     "browser_history",
		"source":         "chromium_history",
		"record_type":    "url_entry",
		"browser":        s.browser,
		"url":            u.urlVal(),
		"title":          u.titleVal(),
		"host":           browserHostVal(host),
		"visit_count":    u.numVal(0),
		"typed_count":    u.numVal(1),
		"hidden":         u.numVal(3),
		"last_visit_raw": u.numVal(2),
		"last_visit_utc": browserISO(lv, lvOK),
		"note":           "visits 表无对应行(历史截断残留),时间为 urls.last_visit_time",
	}
	r := model.Record{Kind: model.KindEvent, Norm: norm,
		Raw: fmt.Sprintf("urls:%d", id)}
	if lvOK {
		r.TsUTCDirect = &lv
	}
	return r
}

// downloadRecord downloads 行 → browser_download;host 取 tab_url 解不出再
// site_url(树庭 tab_url or site_url 同序)。downloads 不计 bad_url(树庭同)。
func (s *chromiumHistoryStream) downloadRecord(rec map[string]any) model.Record {
	st, stOK := browserWebkitToUTC(rec["start_time"])
	if !stOK {
		s.stats.badTime++
	}
	s.stats.track(st, stOK)
	en, enOK := browserWebkitToUTC(rec["end_time"])
	src := rec["tab_url"]
	if v, ok := src.(string); !ok || v == "" {
		src = rec["site_url"]
	}
	host := browserHostOf(src)
	norm := map[string]any{
		"event_type":     "browser_download",
		"source":         "chromium_history",
		"browser":        s.browser,
		"guid":           rec["guid"],
		"target_path":    rec["target_path"],
		"current_path":   rec["current_path"],
		"tab_url":        rec["tab_url"],
		"referrer":       rec["referrer"],
		"site_url":       rec["site_url"],
		"host":           browserHostVal(host),
		"received_bytes": rec["received_bytes"],
		"total_bytes":    rec["total_bytes"],
		"state":          rec["state"],
		"danger_type":    rec["danger_type"],
		"mime_type":      rec["mime_type"],
		"start_raw":      rec["start_time"],
		"start_utc":      browserISO(st, stOK),
		"end_utc":        browserISO(en, enOK),
	}
	r := model.Record{Kind: model.KindEvent, Norm: norm,
		Raw: fmt.Sprintf("downloads:%v", rec["id"])}
	if stOK {
		r.TsUTCDirect = &st
	}
	return r
}

// summaryRecord 收尾 browser_summary(树庭字段集,照抄口径;wal_residue
// 无金库上下文不落,见文件头口径差)。
func (s *chromiumHistoryStream) summaryRecord() model.Record {
	sum := map[string]any{
		"source":            "chromium_history",
		"open_mode":         s.openMode,
		"url_rows":          s.stats.urlRows,
		"visit_rows":        s.stats.visitRows,
		"download_rows":     s.stats.downloadRows,
		"emitted_history":   s.stats.emittedHist,
		"emitted_downloads": s.stats.emittedDL,
		"url_only_rows":     s.stats.urlOnly,
		"row_errors":        s.stats.rowErr,
		"bad_time_rows":     s.stats.badTime,
		"bad_url_rows":      s.stats.badURL,
		"downloads_table":   s.hasDL,
		"time_range_utc":    s.stats.timeRange(),
	}
	if s.stats.urlOverflow > 0 {
		sum["url_map_overflow_rows"] = s.stats.urlOverflow
		sum["note"] = fmt.Sprintf(
			"urls 行超内存索引上限 %d,超出部分未入索引(如实计数,不猜)",
			browserMaxURLRows)
	}
	return model.Record{LineNo: s.lineNo, Kind: model.KindEvent,
		Norm: map[string]any{"event_type": "browser_summary", "summary": sum},
		Raw:  "<browser_summary>"}
}

func (s *chromiumHistoryStream) Err() error { return s.err }

func (s *chromiumHistoryStream) Close() error {
	if s.visits != nil {
		s.visits.Close()
	}
	if s.downloads != nil {
		s.downloads.Close()
	}
	return s.db.Close()
}

// ==================== Firefox places.sqlite ====================

// BrowserFirefoxPlacesParser Firefox places.sqlite 解析器:moz_places 全量
// 索引 → moz_historyvisits 流式扫(ORDER BY visit_date)产 browser_history
// (record_type=visit)→ moz_places 有而 visits 无的条目补产
// browser_history(record_type=url_entry)→ 收尾 browser_summary。
// browser 固定 "firefox"(文件即家族标识,无需路径判别)。
type BrowserFirefoxPlacesParser struct{}

type firefoxPlacesStream struct {
	db       *sql.DB
	openMode string
	places   map[int64]firefoxPlaceRow
	order    []int64
	stats    browserStats

	visits    *sql.Rows
	visitCols []string

	phase  int // 0=visits 1=url_only 2=summary 3=done
	idx    int
	lineNo int
	err    error
}

// Records 打开 places.sqlite:文件头/schema 校验与 moz_places 全量装载在
// 打开期完成(不合规 → 文件级如实 failed);moz_historyvisits 行级游标流式。
func (BrowserFirefoxPlacesParser) Records(path string) (Stream, error) {
	db, mode, err := browserOpenSQLite(path)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (Stream, error) {
		db.Close()
		return nil, err
	}
	phave, err := browserRequireCols(db, "moz_places", "id", "url")
	if err != nil {
		return fail(err)
	}
	vhave, err := browserRequireCols(db, "moz_historyvisits", "id", "place_id",
		"visit_date")
	if err != nil {
		return fail(err)
	}
	s := &firefoxPlacesStream{db: db, openMode: mode}
	if s.places, s.order, err = browserLoadURLRows(db, "moz_places",
		browserFirefoxPlacesWant, phave, newFirefoxPlaceRow, &s.stats); err != nil {
		return fail(err)
	}
	s.visits, s.visitCols, err = browserSelect(db, "moz_historyvisits",
		browserFirefoxVisitsWant, vhave, "visit_date")
	if err != nil {
		return fail(fmt.Errorf("SQLite 查询失败(moz_historyvisits): %w", err))
	}
	return s, nil
}

// Next 按 visits → url_only → summary 序产出。
func (s *firefoxPlacesStream) Next() (model.Record, bool) {
	for {
		switch s.phase {
		case 0: // moz_historyvisits 流式扫(ORDER BY visit_date)
			if s.visits.Next() {
				s.stats.visitRows++
				rec, err := browserScanRow(s.visits, s.visitCols)
				if err != nil {
					s.stats.rowErr++
					continue
				}
				s.lineNo++
				s.stats.emittedHist++
				r := s.visitRecord(rec)
				r.LineNo = s.lineNo
				return r, true
			}
			if err := s.visits.Err(); err != nil {
				s.err = fmt.Errorf("SQLite 游标失败(moz_historyvisits): %w", err)
				s.phase = 3
				continue
			}
			s.visits.Close()
			s.visits = nil
			s.phase = 1
		case 1: // moz_places 有而 visits 无的条目(历史截断/仅书签引用)
			if s.idx < len(s.order) {
				id := s.order[s.idx]
				s.idx++
				p := s.places[id]
				if p.visited {
					continue
				}
				s.stats.urlOnly++
				s.lineNo++
				s.stats.emittedHist++
				r := s.urlEntryRecord(id, p)
				r.LineNo = s.lineNo
				return r, true
			}
			// 索引使命完成即释放(内存纪律)
			s.places = nil
			s.order = nil
			s.phase = 2
		case 2: // 收尾 browser_summary
			s.phase = 3
			s.lineNo++
			return s.summaryRecord(), true
		default:
			return model.Record{}, false
		}
	}
}

// visitRecord moz_historyvisits 行 → browser_history(record_type=visit)。
func (s *firefoxPlacesStream) visitRecord(rec map[string]any) model.Record {
	var p firefoxPlaceRow
	if pid, ok := rec["place_id"].(int64); ok {
		if e, found := s.places[pid]; found {
			e.visited = true
			s.places[pid] = e
			p = e
		}
	}
	vd, vdOK := browserFxToUTC(rec["visit_date"])
	if !vdOK {
		s.stats.badTime++
	}
	s.stats.track(vd, vdOK)
	host := browserHostOf(p.urlVal())
	if host == "" {
		s.stats.badURL++
	}
	norm := map[string]any{
		"event_type":     "browser_history",
		"source":         "firefox_places",
		"record_type":    "visit",
		"browser":        "firefox",
		"url":            p.urlVal(),
		"title":          p.titleVal(),
		"host":           browserHostVal(host),
		"visit_type":     rec["visit_type"],
		"from_visit":     rec["from_visit"],
		"visit_date_raw": rec["visit_date"],
		"visit_utc":      browserISO(vd, vdOK),
	}
	r := model.Record{Kind: model.KindEvent, Norm: norm,
		Raw: fmt.Sprintf("moz_historyvisits:%v", rec["id"])}
	if vdOK {
		r.TsUTCDirect = &vd
	}
	return r
}

// urlEntryRecord moz_places 残留条目 → browser_history(record_type=
// url_entry);时间为 moz_places.last_visit_date(坏时间只 track 不计数,
// 树庭同口径)。
func (s *firefoxPlacesStream) urlEntryRecord(id int64, p firefoxPlaceRow) model.Record {
	lv, lvOK := p.timeVal(4, browserFxToUTC) // last_visit_date
	s.stats.track(lv, lvOK)
	host := browserHostOf(p.urlVal())
	norm := map[string]any{
		"event_type":     "browser_history",
		"source":         "firefox_places",
		"record_type":    "url_entry",
		"browser":        "firefox",
		"url":            p.urlVal(),
		"title":          p.titleVal(),
		"host":           browserHostVal(host),
		"guid":           p.guidVal(),
		"visit_count":    p.numVal(0),
		"typed":          p.numVal(1),
		"hidden":         p.numVal(2),
		"frecency":       p.numVal(3),
		"last_visit_raw": p.numVal(4),
		"last_visit_utc": browserISO(lv, lvOK),
		"note": "moz_historyvisits 无对应行(历史截断/仅书签引用)," +
			"时间为 moz_places.last_visit_date",
	}
	r := model.Record{Kind: model.KindEvent, Norm: norm,
		Raw: fmt.Sprintf("moz_places:%d", id)}
	if lvOK {
		r.TsUTCDirect = &lv
	}
	return r
}

// summaryRecord 收尾 browser_summary(树庭 firefox_places 字段集,照抄口径)。
func (s *firefoxPlacesStream) summaryRecord() model.Record {
	sum := map[string]any{
		"source":          "firefox_places",
		"open_mode":       s.openMode,
		"place_rows":      s.stats.urlRows,
		"visit_rows":      s.stats.visitRows,
		"emitted_history": s.stats.emittedHist,
		"url_only_rows":   s.stats.urlOnly,
		"row_errors":      s.stats.rowErr,
		"bad_time_rows":   s.stats.badTime,
		"bad_url_rows":    s.stats.badURL,
		"time_range_utc":  s.stats.timeRange(),
	}
	if s.stats.urlOverflow > 0 {
		sum["url_map_overflow_rows"] = s.stats.urlOverflow
		sum["note"] = fmt.Sprintf(
			"moz_places 行超内存索引上限 %d,超出部分未入索引(如实计数,不猜)",
			browserMaxURLRows)
	}
	return model.Record{LineNo: s.lineNo, Kind: model.KindEvent,
		Norm: map[string]any{"event_type": "browser_summary", "summary": sum},
		Raw:  "<browser_summary>"}
}

func (s *firefoxPlacesStream) Err() error { return s.err }

func (s *firefoxPlacesStream) Close() error {
	if s.visits != nil {
		s.visits.Close()
	}
	return s.db.Close()
}
