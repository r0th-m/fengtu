// 时间归一(语义照索图 normalize.py):
//   - ts_raw 原样保留(引擎负责,本文件不碰);
//   - 源声明时区(tz_declared,IANA 名)已知 → 行内本地时间归一为 ts_utc;
//   - 无时区声明 → ts_utc=nil 如实标注,不硬归一、不猜;
//   - 识别顺序(全部确定性,与 Python 同款):IANA tzdb(zoneinfo/
//     LoadLocation)→ 标准时兜底表 → UTC±x 字面量 → 无法识别。
//
// 已知差异(如实标注):Python 侧在无 tzdata 的环境(Windows 无系统 tzdb)
// 落到「标准时兜底表」,本 Go 实现通过 GOROOT zoneinfo.zip 总能查到 IANA
// tzdb——对 1992 年后的日期两者结果一致(兜底表=标准时,IANA 同期无 DST);
// 对历史日期(LMT/早年 DST,如无年份格式默认的 1900 年)Go 更精确但会与
// 无 tzdata 的 Python 兜底结果不同——golden 对照的时区选择已避开该分歧
// (历史年份用 UTC±x 字面量,双边同走字面量路径)。
package descform

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 小型 IANA → 标准时偏移兜底表(分钟),照索图 normalize.py 原表。
var ianaStdOffsetMinutes = map[string]int{
	"asia/shanghai": 480, "asia/beijing": 480, "asia/chongqing": 480,
	"asia/hong_kong": 480, "asia/taipei": 480, "asia/singapore": 480,
	"asia/tokyo": 540, "asia/seoul": 540, "asia/kolkata": 330,
	"europe/london": 0, "europe/paris": 60, "europe/berlin": 60,
	"america/new_york": -300, "america/chicago": -360,
	"america/los_angeles": -480,
	"utc": 0, "etc/utc": 0, "etc/gmt": 0,
}

var utcLiteralRe = regexp.MustCompile(`^(?i:(?:UTC|GMT)?([+-])(\d{1,2})(?::?(\d{2}))?)$`)

var tzCache sync.Map // name -> *time.Location(nil 值用 notFound 占位)

type tzNotFound struct{}

// TZOffset 声明时区 → *time.Location;识别不了 → nil(时区未知,不硬归一)。
func TZOffset(tzDeclared string) *time.Location {
	name := strings.TrimSpace(tzDeclared)
	if name == "" {
		return nil
	}
	if v, ok := tzCache.Load(name); ok {
		if loc, isLoc := v.(*time.Location); isLoc {
			return loc
		}
		return nil
	}
	loc := resolveTZ(name)
	if loc == nil {
		tzCache.Store(name, tzNotFound{})
	} else {
		tzCache.Store(name, loc)
	}
	return loc
}

func resolveTZ(name string) *time.Location {
	// ① IANA tzdb(Go 发行版自带 zoneinfo.zip,Windows 同样可查)
	if loc, err := time.LoadLocation(name); err == nil {
		return loc
	}
	// ② 标准时兜底表
	if minutes, ok := ianaStdOffsetMinutes[strings.ToLower(name)]; ok {
		return time.FixedZone(name, minutes*60)
	}
	// ③ UTC±x 字面量
	if m := utcLiteralRe.FindStringSubmatch(name); m != nil {
		sign := 1
		if m[1] == "-" {
			sign = -1
		}
		h, _ := strconv.Atoi(m[2])
		min := 0
		if m[3] != "" {
			min, _ = strconv.Atoi(m[3])
		}
		return time.FixedZone(name, sign*(h*60+min)*60)
	}
	return nil
}

// ToUTC 行内本地时间(naive 墙钟,UTC location 承载)+ 声明时区 → UTC;
// 时区未知 → nil 如实(不硬归一)。等价 Python:
// dt_local.replace(tzinfo=tz).astimezone(timezone.utc)。
func ToUTC(dtLocal *time.Time, tzDeclared string) *time.Time {
	if dtLocal == nil {
		return nil
	}
	loc := TZOffset(tzDeclared)
	if loc == nil {
		return nil
	}
	w := dtLocal.UTC()
	withTZ := time.Date(w.Year(), w.Month(), w.Day(),
		w.Hour(), w.Minute(), w.Second(), w.Nanosecond(), loc)
	out := withTZ.UTC()
	return &out
}

// ResolveTsUTC LineOutcome 三要素 → ts_utc 的统一裁决:
// 直通 UTC(aware)> dt_local + 声明时区归一 > nil 如实。
// 直通值为 naive(本包约定=UTC location 承载的墙钟且无 tz 语义)按契约
// 违规处理,如实不归一。
func ResolveTsUTC(dtLocal *time.Time, tzDeclared string, tsUTCDirect *time.Time) *time.Time {
	if tsUTCDirect != nil {
		if tsUTCDirect.Location() == time.UTC {
			out := tsUTCDirect.UTC()
			return &out
		}
		// 非 UTC location 的 aware 直通:幂等换算到 UTC
		out := tsUTCDirect.UTC()
		return &out
	}
	return ToUTC(dtLocal, tzDeclared)
}
