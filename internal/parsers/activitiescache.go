// ActivitiesCache.db(Windows 时间线)原生解析:SQLite 只读流式行扫描 →
// 行级 windows_timeline 事件流 + 收尾 windows_timeline_summary。
// 语义基准 = 树庭 backend/app/parsers/win_activities.py(金标准,逐字段对拍)。
//
// 选型:已 vendor 的 modernc.org/sqlite(纯 Go,零 CGO)。DSN 走
// "file:<path>?mode=ro&immutable=1"——驱动带 SQLITE_OPEN_URI 整串交给
// sqlite3_open_v2,mode=ro/immutable=1 由 SQLite 原生 URI 解析生效;
// 打开期另自查 16 字节 "SQLite format 3\0" 头,坏库 → 文件级如实 failed。
//
// 格式契约(对真实 schema 写,不猜):
//   - Activity 表必备(无 → failed 并列出实际表名);必备列
//     {Id,AppId,ActivityType,StartTime,LastModifiedTime} 缺 → failed;
//     want 列集合照树庭 _WANTED_COLS,缺列降级 nil;
//   - 时间列声明 DATETIME 实测 typeof=integer = unix epoch 秒(UTC),
//     合理窗 [2018-01-01, 2100-01-01](Timeline 2018 才有),越窗/非整数 →
//     不猜 + bad_time_rows 计数;anchor = StartTime 或 LastModifiedTime,
//     合法则 TsUTCDirect 直通 + Norm *_utc ISO 留证;
//   - AppId TEXT 是 JSON 数组:application 非空的第一条为显示名 +
//     platform;解析失败 → appid_errors 计数 + app_id_raw 截 200 留证;
//     JSON 合法但全空 → 不算错;
//   - Payload/ClipboardPayload BLOB:空 → empty;UTF-8 JSON 可解 → json +
//     文本(displayText/description/content/appDisplayName 首个非空,否则
//     整 JSON 截 300);否则 opaque + 长度,不硬解。
//
// 与树庭的口径差(如实):
//   - WAL:树庭复制 .db+-wal 到临时目录重放;丰图采集包只读流式解析,
//     immutable=1 下 SQLite 本就不重放 WAL,summary 以 wal_replayed=false +
//     wal_note 如实标注(真实样本实测差异见汇报:有未 checkpoint WAL 的库
//     行数会少于树庭口径);
//   - 树庭 ts_raw 经 utc_to_local_ts_raw 回转本地;丰图 TsUTCDirect 原生
//     UTC 直通,语义等价且不再依赖时区声明;
//   - payload fallback 的 JSON 重排:Go 紧凑无空格 + 键按字典序;Python
//     json.dumps 默认 ", "/": " 分隔 + 保持插入序——仅在「JSON 合法但无
//     文本字段」的 fallback 文本上有格式差,语义等价;
//   - top_apps 并列时按应用名字典序定序(输出确定性);Python
//     Counter.most_common 并列按插入序——并列名次可能不同,计数一致;
//   - activity_types/apps 计数 map 设去重键上限(防恶意海量伪造键灌爆
//     内存,超上限入溢出桶如实计数;树庭 Counter 无上限)。
//
// 流式纪律:modernc 驱动 rows.Next 逐行 sqlite3_step,单条事件即产即放;
// ORDER BY StartTime 的排序由 SQLite sorter 承担(超内存阈值自动落临时
// 文件),解析进程堆增量与输入大小无关(大输入内存测试见
// activitiescache_test.go)。
//
// 实现注记:modernc 对「TEXT + decltype DATE/DATETIME/TIMESTAMP」的列会
// 无条件转 time.Time(sqlite.go rows.Next,INTEGER 的 intToTime 是 opt-in
// 默认关,无此问题);且实测 decltype 穿透子查询。因此主查询对每列套
// COALESCE(col,NULL)——函数表达式 decltype 必为 NULL,值与存储类原样
// 保留,TEXT 时间值拿到原始字符串,按「非整数 → 不猜」处理。
package parsers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// unix epoch 合理窗(秒):Timeline 随 Win10 1803(2018-04)出现,2100 后不猜
// (树庭 _EPOCH_MIN/_EPOCH_MAX 同值)。
const (
	acEpochMin = 1514764800 // 2018-01-01T00:00:00Z
	acEpochMax = 4102444800 // 2100-01-01T00:00:00Z
)

// 计数与截断上限(防过拟合:均为结构上限,不是案件值)。
const (
	acTopAppsN    = 10  // top_apps 呈现条数(树庭 most_common(10))
	acTextMax     = 300 // payload 文本截断(树庭 [:300])
	acAppIDRawMax = 200 // app_id_raw 留证截断(树庭 [:200])
)

// acSQLiteMagic SQLite 数据库文件头(16 字节)。
var acSQLiteMagic = []byte("SQLite format 3\x00")

// 必备列:缺任一 → 文件级如实 failed(树庭 _REQUIRED_COLS)。
var acRequiredCols = []string{"Id", "AppId", "ActivityType", "StartTime", "LastModifiedTime"}

// 读取列(树庭 _WANTED_COLS 顺序;缺列降级 nil,不 failed)。
var acWantedCols = []string{
	"Id", "AppId", "AppActivityId", "ActivityType", "ActivityStatus",
	"Group", "StartTime", "EndTime", "LastModifiedTime",
	"LastModifiedOnClient", "ExpirationTime", "CreatedInCloud",
	"Payload", "ClipboardPayload", "PlatformDeviceId", "IsLocalOnly", "ETag",
}

// ActivitiesCacheParser ActivitiesCache.db 解析器。
type ActivitiesCacheParser struct{}

// acStream 行流:rows.Next 逐行取,计数器与 treeyuan summary 同口径。
type acStream struct {
	db     *sql.DB
	rows   *sql.Rows
	sel    []string // 实际查询列(wanted ∩ 实际,顺序同 acWantedCols)
	lineNo int64    // 已产事件数(=已扫描行数,1 起;行号=事件序)

	rowsTotal, emitted                            int64
	appidErrors, badTimeRows, noTimeRows          int64
	payloadJSON, payloadOpaque, clipboardNonempty int64
	typeCounts                                    map[string]int64
	appCounts                                     map[string]int64
	typeOverflow, appOverflow                     int64
	tMin, tMax                                    time.Time
	hasRange                                      bool
	done, summaryEmitted                          bool
	err                                           error
}

// acDSN 拼只读 immutable URI;路径转正斜杠,URI 保留字(% ? # 空格)
// 百分号编码(SQLite URI 解析会解码)。
func acDSN(path string) string {
	p := strings.ReplaceAll(path, "\\", "/")
	var b strings.Builder
	b.WriteString("file:")
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '%':
			b.WriteString("%25")
		case '?':
			b.WriteString("%3F")
		case '#':
			b.WriteString("%23")
		case ' ':
			b.WriteString("%20")
		default:
			b.WriteByte(p[i])
		}
	}
	b.WriteString("?mode=ro&immutable=1")
	return b.String()
}

// Records 打开 ActivitiesCache.db:文件头/schema 校验在打开期完成
// (非 SQLite/无 Activity 表/缺必备列 → 文件级如实 failed)。
func (ActivitiesCacheParser) Records(path string) (Stream, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("activitiescache 打开失败: %w", err)
	}
	head := make([]byte, len(acSQLiteMagic))
	n, _ := f.ReadAt(head, 0)
	f.Close()
	if n < len(acSQLiteMagic) || string(head) != string(acSQLiteMagic) {
		return nil, fmt.Errorf("非 SQLite 文件(头 16 字节不符 \"SQLite format 3\")")
	}

	db, err := sql.Open("sqlite", acDSN(path))
	if err != nil {
		return nil, fmt.Errorf("activitiescache 打开失败: %w", err)
	}
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	fail := func(format string, args ...any) (Stream, error) {
		db.Close()
		return nil, fmt.Errorf(format, args...)
	}
	if err := db.PingContext(ctx); err != nil {
		return fail("SQLite 打开失败: %v", err)
	}

	// 表清单:无 Activity 表 → failed 并列出实际表名(不猜)。
	trows, err := db.QueryContext(ctx,
		"SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		return fail("SQLite 查询失败(表清单): %v", err)
	}
	var tables []string
	hasActivity := false
	for trows.Next() {
		var name string
		if err := trows.Scan(&name); err != nil {
			trows.Close()
			return fail("SQLite 查询失败(表清单): %v", err)
		}
		tables = append(tables, name)
		if name == "Activity" {
			hasActivity = true
		}
	}
	if err := trows.Err(); err != nil {
		trows.Close()
		return fail("SQLite 查询失败(表清单): %v", err)
	}
	trows.Close()
	if !hasActivity {
		sort.Strings(tables)
		return fail("无 Activity 表(实际表: %v;schema 变体未覆盖,如实 failed 不猜)",
			tables)
	}

	// Activity 列清单:缺必备列 → failed;want 列缺 → 该字段一律 nil。
	crows, err := db.QueryContext(ctx, "PRAGMA table_info(Activity)")
	if err != nil {
		return fail("SQLite 查询失败(列清单): %v", err)
	}
	cols := map[string]bool{}
	for crows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt any
		if err := crows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			crows.Close()
			return fail("SQLite 查询失败(列清单): %v", err)
		}
		cols[name] = true
	}
	if err := crows.Err(); err != nil {
		crows.Close()
		return fail("SQLite 查询失败(列清单): %v", err)
	}
	crows.Close()
	var missing []string
	for _, c := range acRequiredCols {
		if !cols[c] {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		return fail("Activity 表缺必备列 %v,不猜", missing)
	}
	var sel []string
	for _, c := range acWantedCols {
		if cols[c] {
			sel = append(sel, c)
		}
	}

	// 主查询:每列套 COALESCE(col,NULL) 剥 decltype(防驱动把 TEXT
	// DATETIME 转 time.Time;COALESCE 是函数表达式,decltype 必为 NULL,
	// 值与存储类原样保留),ORDER BY StartTime(树庭同序)。
	quoted := make([]string, len(sel))
	for i, c := range sel {
		quoted[i] = `COALESCE("` + c + `", NULL) AS "` + c + `"`
	}
	query := "SELECT " + strings.Join(quoted, ", ") +
		` FROM Activity ORDER BY "StartTime"`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return fail("SQLite 查询失败: %v", err)
	}
	return &acStream{db: db, rows: rows, sel: sel,
		typeCounts: map[string]int64{}, appCounts: map[string]int64{}}, nil
}

// Next 逐行产 windows_timeline;EOF 收尾产 windows_timeline_summary。
func (s *acStream) Next() (model.Record, bool) {
	if s.err != nil {
		return model.Record{}, false
	}
	if s.done {
		if !s.summaryEmitted {
			s.summaryEmitted = true
			return s.summaryRecord(), true
		}
		return model.Record{}, false
	}
	if !s.rows.Next() {
		if err := s.rows.Err(); err != nil {
			// 迭代中途损坏(页坏/IO 错):流级致命,如实暴露(树庭同款
			// ParseError,单文件 failed 不拖垮整包)。
			s.err = fmt.Errorf("SQLite 行迭代失败(第 %d 行后): %v", s.rowsTotal, err)
			return model.Record{}, false
		}
		s.done = true
		s.summaryEmitted = true
		return s.summaryRecord(), true
	}
	vals := make([]any, len(s.sel))
	dest := make([]any, len(s.sel))
	for i := range vals {
		dest[i] = &vals[i]
	}
	if err := s.rows.Scan(dest...); err != nil {
		s.err = fmt.Errorf("SQLite 行扫描失败(第 %d 行): %v", s.rowsTotal+1, err)
		return model.Record{}, false
	}
	s.rowsTotal++
	rec := make(map[string]any, len(s.sel))
	for i, c := range s.sel {
		rec[c] = vals[i]
	}
	return s.rowRecord(rec), true
}

// rowRecord 一行 → windows_timeline 事件(逐字段照树庭 data 集)。
func (s *acStream) rowRecord(rec map[string]any) model.Record {
	id := acPyStr(rec["Id"])
	locator := id
	if locator == "" {
		locator = fmt.Sprintf("row:%d", s.rowsTotal) // 树庭同款兜底
	}

	app, platform, appOK := acPickApp(rec["AppId"])
	if !appOK {
		s.appidErrors++
	}
	if app != "" {
		efuCount(s.appCounts, app, &s.appOverflow)
	}

	stV, enV := rec["StartTime"], rec["EndTime"]
	lmV, lmcV := rec["LastModifiedTime"], rec["LastModifiedOnClient"]
	st, stOK := acEpochToUTC(stV)
	en, enOK := acEpochToUTC(enV)
	lm, lmOK := acEpochToUTC(lmV)
	lmc, lmcOK := acEpochToUTC(lmcV)
	// bad_time:正整数但越窗(树庭:仅查 StartTime/EndTime/LastModifiedTime,
	// 每行至多计一次)。
	for _, v := range []any{stV, enV, lmV} {
		if n, isInt := v.(int64); isInt && n > 0 {
			if _, ok := acEpochToUTC(n); !ok {
				s.badTimeRows++
				break
			}
		}
	}
	var anchor *time.Time
	if stOK {
		anchor = &st
	} else if lmOK {
		anchor = &lm
	}
	if anchor == nil {
		s.noTimeRows++
	} else {
		if !s.hasRange || anchor.Before(s.tMin) {
			s.tMin = *anchor
		}
		if !s.hasRange || anchor.After(s.tMax) {
			s.tMax = *anchor
		}
		s.hasRange = true
	}

	pBlob := acBytes(rec["Payload"])
	pFmt, pText := acDecodeBlob(pBlob)
	switch pFmt {
	case "json":
		s.payloadJSON++
	case "opaque":
		s.payloadOpaque++
	}
	cBlob := acBytes(rec["ClipboardPayload"])
	cFmt, cText := acDecodeBlob(cBlob)
	if cFmt == "json" {
		s.clipboardNonempty++
	}

	efuCount(s.typeCounts, acPyStr(rec["ActivityType"]), &s.typeOverflow)

	norm := map[string]any{
		"event_type":                  "windows_timeline",
		"source":                      "activitiescache",
		"app":                         acNilIfEmpty(app),
		"app_platform":                platform,
		"activity_type":               rec["ActivityType"],
		"activity_status":             rec["ActivityStatus"],
		"group":                       rec["Group"],
		"app_activity_id":             rec["AppActivityId"],
		"is_local_only":               rec["IsLocalOnly"],
		"start_epoch":                 stV,
		"end_epoch":                   acOrNil(enV), // 树庭 `or None`:0/空 → nil
		"start_utc":                   acISO(st, stOK),
		"end_utc":                     acISO(en, enOK),
		"last_modified_utc":           acISO(lm, lmOK),
		"last_modified_on_client_utc": acISO(lmc, lmcOK),
		"payload_format":              pFmt,
		"payload_len":                 int64(len(pBlob)),
		"payload_text":                pText,
		"clipboard_format":            cFmt,
		"clipboard_text":              cText,
	}
	if !appOK && acTruthy(rec["AppId"]) {
		norm["app_id_raw"] = acTruncateRunes(acPyStr(rec["AppId"]), acAppIDRawMax)
	}
	s.emitted++
	return model.Record{LineNo: int(s.rowsTotal), Kind: model.KindEvent,
		Norm: norm, Raw: locator, TsUTCDirect: anchor}
}

// summaryRecord 收尾统计事件(字段照树庭 summary;wal_replayed 恒 false +
// wal_note 如实标注口径差)。
func (s *acStream) summaryRecord() model.Record {
	summary := map[string]any{
		"source":             "activitiescache",
		"rows":               s.rowsTotal,
		"emitted":            s.emitted,
		"appid_errors":       s.appidErrors,
		"bad_time_rows":      s.badTimeRows,
		"no_time_rows":       s.noTimeRows,
		"payload_json":       s.payloadJSON,
		"payload_opaque":     s.payloadOpaque,
		"clipboard_nonempty": s.clipboardNonempty,
		"wal_replayed":       false,
		"wal_note":           "WAL 伴生未重放(树庭复制重放;丰图只读 immutable,差异如实)",
		"activity_types":     s.typeCounts,
		"distinct_apps":      int64(len(s.appCounts)),
		"top_apps":           acTopApps(s.appCounts, acTopAppsN),
		"time_range_utc":     nil,
	}
	if s.hasRange {
		summary["time_range_utc"] = []string{
			s.tMin.Format("2006-01-02T15:04:05Z"),
			s.tMax.Format("2006-01-02T15:04:05Z")}
	}
	if s.typeOverflow > 0 {
		summary["activity_type_overflow_rows"] = s.typeOverflow
	}
	if s.appOverflow > 0 {
		summary["app_overflow_rows"] = s.appOverflow
	}
	return model.Record{LineNo: int(s.rowsTotal) + 1, Kind: model.KindEvent,
		Norm: map[string]any{"event_type": "windows_timeline_summary",
			"summary": summary},
		Raw: "<windows_timeline_summary>"}
}

// ---- 行内助手(树庭 _epoch_to_utc/_pick_app/_decode_blob 同语义) ----

// acEpochToUTC unix epoch 秒 → UTC;非整数(int64)/越窗 → false(不猜)。
// (SQLite 无 bool 存储类,Python 的 isinstance(v,bool) 排除天然满足。)
func acEpochToUTC(v any) (time.Time, bool) {
	n, ok := v.(int64)
	if !ok || n < acEpochMin || n > acEpochMax {
		return time.Time{}, false
	}
	return time.Unix(n, 0).UTC(), true
}

// acISO 合法时间 → RFC3339 UTC 字符串;非法 → nil(字段留 null,不猜)。
func acISO(t time.Time, ok bool) any {
	if !ok {
		return nil
	}
	return t.Format("2006-01-02T15:04:05Z")
}

// acPickApp AppId JSON 数组 → (显示名, platform, 解析是否成功)。
// application 非空的第一条为显示名;解析失败/非数组/空值 → ok=false;
// JSON 合法但全空 → ok=true 无显示名(不算错)。
func acPickApp(v any) (app string, platform any, ok bool) {
	b := acBytes(v)
	if len(b) == 0 {
		return "", nil, false
	}
	var entries any
	if err := json.Unmarshal(b, &entries); err != nil {
		return "", nil, false
	}
	list, isList := entries.([]any)
	if !isList {
		return "", nil, false
	}
	for _, e := range list {
		m, isMap := e.(map[string]any)
		if !isMap {
			continue
		}
		if a := strings.TrimSpace(acJSONScalarStr(m["application"])); a != "" {
			return a, m["platform"], true
		}
	}
	return "", nil, true
}

// acDecodeBlob BLOB → (格式标注, 文本或 nil):空 → empty;UTF-8 JSON 可解 →
// json + 文本(常见文本字段首个非空,否则整 JSON 重排截 300);否则 opaque。
func acDecodeBlob(b []byte) (string, any) {
	if len(b) == 0 {
		return "empty", nil
	}
	if !utf8.Valid(b) {
		return "opaque", nil
	}
	var obj any
	if err := json.Unmarshal(b, &obj); err != nil {
		return "opaque", nil
	}
	switch o := obj.(type) {
	case map[string]any:
		for _, k := range []string{"displayText", "description", "content",
			"appDisplayName"} {
			if txt, isStr := o[k].(string); isStr && strings.TrimSpace(txt) != "" {
				return "json", acTruncateRunes(txt, acTextMax)
			}
		}
		return "json", acTruncateRunes(acJSONDumps(o), acTextMax)
	case []any:
		if len(o) == 0 {
			return "empty", nil
		}
		return "json", acTruncateRunes(acJSONDumps(o), acTextMax)
	case string:
		return "json", acTruncateRunes(o, acTextMax)
	case nil:
		return "json", "None" // Python str(None)
	case bool:
		if o {
			return "json", "True" // Python str(True)
		}
		return "json", "False"
	default: // float64
		return "json", acTruncateRunes(acJSONScalarStr(o), acTextMax)
	}
}

// acBytes 值 → 字节串(TEXT/BLOB 统一;其余 → nil)。
func acBytes(v any) []byte {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		return []byte(x)
	case []byte:
		return x
	default:
		return nil
	}
}

// acPyStr Python str() 同语义:NULL → "None"(activity_types 键/locator 用),
// 整数/字符串原样,浮点整数化补 .0;[]byte 按 UTF-8 串处理(如实偏差:
// Python str(bytes) 是 repr,仅见病理输入)。
func acPyStr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return x
	case []byte:
		return string(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return acPyFloatStr(x)
	case bool:
		if x {
			return "True"
		}
		return "False"
	default:
		return fmt.Sprintf("%v", x)
	}
}

// acJSONScalarStr JSON 标量 → Python str() 同语义(AppId application 用)。
func acJSONScalarStr(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return acPyFloatStr(x)
	case bool:
		if x {
			return "True"
		}
		return "False"
	default:
		return fmt.Sprintf("%v", x)
	}
}

// acPyFloatStr Python str(float) 近似:整数值补 .0。
func acPyFloatStr(f float64) string {
	s := strconv.FormatFloat(f, 'g', -1, 64)
	if !strings.ContainsAny(s, ".eE") && !strings.ContainsAny(s, "infna") {
		s += ".0"
	}
	return s
}

// acTruthy Python 真值语义(end_epoch `or None`、app_id_raw 判空用)。
func acTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	case []byte:
		return len(x) > 0
	case int64:
		return x != 0
	case float64:
		return x != 0
	case bool:
		return x
	default:
		return true
	}
}

// acOrNil 假值 → nil(树庭 `rec.get("EndTime") or None`)。
func acOrNil(v any) any {
	if !acTruthy(v) {
		return nil
	}
	return v
}

// acNilIfEmpty 空串 → nil(app 无显示名时 Python 是 None)。
func acNilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// acTruncateRunes 按字符(rune)截断(Python [:n] 是码点语义,非字节)。
func acTruncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

// acJSONDumps 重排 JSON(payload fallback 留证;不转义 HTML,与树庭
// ensure_ascii=False 对齐;分隔符为 Go 紧凑式,差异已在文件头如实标注)。
func acJSONDumps(v any) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return ""
	}
	return strings.TrimRight(b.String(), "\n")
}

// acTopApps 应用计数 → [{app,count}...] 降序(并列按应用名字典序,输出
// 确定性;键名照树庭 {"app":..., "count":...})。
func acTopApps(m map[string]int64, n int) []map[string]any {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if n > 0 && len(keys) > n {
		keys = keys[:n]
	}
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]any{"app": k, "count": m[k]})
	}
	return out
}

// Err 流级致命错误;无错返回 nil。
func (s *acStream) Err() error { return s.err }

// Close 释放行迭代器与连接。
func (s *acStream) Close() error {
	err := s.rows.Close()
	if e := s.db.Close(); err == nil {
		err = e
	}
	return err
}
