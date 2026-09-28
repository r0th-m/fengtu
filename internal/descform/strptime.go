// strptime 风格时间解析(语义照 Python datetime.strptime)。
//
// 支持指令:%Y %y %m %d %H %I %M %S %f %b %B %p %z %Z %%。
// 与 Go time.Parse 的差异用「预校验正则 + 布局翻译」弥合:
//   - Python %f 是必填(1~6 位小数秒),Go 的 .999999 是可选——
//     预校验正则把 %f 定为必填,行为对齐;
//   - 格式无年份指令时 Python 默认年 1900(Go 默认年 0),解析后补正;
//   - 结果是 naive 本地时间的语义(墙钟),本包用 UTC location 承载墙钟,
//     时区归一由 normalize.go 按「源声明时区」完成——行内 %z 偏移与
//     索图一致只作解析依据,归一不猜用。
package descform

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// parsedTSFormat 是一个编译好的 strptime 格式串。
type parsedTSFormat struct {
	layouts  []string // 候选 Go 布局(%z 有多形态,逐个试)
	valRe    *regexp.Regexp
	hasYear  bool
	hasClock bool
}

// compileTSFormat 编译 strptime 格式串;未知指令如实报错(不带病解析)。
func compileTSFormat(format string) (*parsedTSFormat, error) {
	var layout strings.Builder
	var val strings.Builder
	val.WriteString("^")
	p := &parsedTSFormat{hasClock: false}
	i := 0
	for i < len(format) {
		c := format[i]
		if c != '%' {
			if c == ' ' || c == '\t' {
				// Python strptime:格式空白匹配输入 1+ 空白
				layout.WriteByte(' ')
				val.WriteString(`\s+`)
			} else {
				layout.WriteByte(c)
				val.WriteString(regexp.QuoteMeta(string(c)))
			}
			i++
			continue
		}
		if i+1 >= len(format) {
			return nil, fmt.Errorf("strptime 格式串以裸 %% 结尾: %q", format)
		}
		d := format[i+1]
		i += 2
		switch d {
		case '%':
			layout.WriteByte('%')
			val.WriteString("%")
		case 'Y':
			layout.WriteString("2006")
			val.WriteString(`\d{4}`)
			p.hasYear = true
		case 'y':
			layout.WriteString("06")
			val.WriteString(`\d{1,2}`)
			p.hasYear = true
		case 'm':
			layout.WriteString("01")
			val.WriteString(`\d{1,2}`)
		case 'd':
			layout.WriteString("02")
			val.WriteString(`\d{1,2}`)
		case 'H':
			layout.WriteString("15")
			val.WriteString(`\d{1,2}`)
			p.hasClock = true
		case 'I':
			layout.WriteString("03")
			val.WriteString(`\d{1,2}`)
			p.hasClock = true
		case 'M':
			layout.WriteString("04")
			val.WriteString(`\d{1,2}`)
			p.hasClock = true
		case 'S':
			layout.WriteString("05")
			val.WriteString(`\d{1,2}`)
			p.hasClock = true
		case 'f':
			// Go 小数秒必须紧跟秒位(.999999);只支持「秒. f」形态,
			// 其他位置(如独立 %f)超出 Go 布局能力,如实报错。
			l := layout.String()
			if !(strings.HasSuffix(l, "05.") || strings.HasSuffix(l, "05,")) {
				return nil, fmt.Errorf(
					"strptime 格式 %q: %%f 须紧跟 %%S. 或 %%S,(Go 布局能力边界)",
					format)
			}
			layout.WriteString("999999")
			val.WriteString(`\d{1,6}`)
			p.hasClock = true
		case 'b':
			layout.WriteString("Jan")
			val.WriteString(`[A-Za-z]+`)
		case 'B':
			layout.WriteString("January")
			val.WriteString(`[A-Za-z]+`)
		case 'p':
			layout.WriteString("PM")
			val.WriteString(`(?i)[AP]M`)
		case 'z':
			layout.WriteString("-0700")
			val.WriteString(`(Z|[+-]\d{2}:?\d{2})`)
		case 'Z':
			layout.WriteString("MST")
			val.WriteString(`[A-Za-z]+`)
		default:
			return nil, fmt.Errorf("strptime 格式 %q: 不支持的指令 %%%c", format, d)
		}
	}
	val.WriteString("$")
	re, err := regexp.Compile(val.String())
	if err != nil {
		return nil, fmt.Errorf("strptime 格式 %q 预校验正则编译失败: %v", format, err)
	}
	p.valRe = re
	// %z 的多形态:+0800 / +08:00 / Z ——逐个候选布局试(逐个格式试,
	// 全失败即坏行,与「ts_formats 逐个试」同款纪律)
	base := layout.String()
	p.layouts = []string{base}
	if strings.Contains(base, "-0700") {
		p.layouts = append(p.layouts,
			strings.ReplaceAll(base, "-0700", "-07:00"),
			strings.ReplaceAll(base, "-0700", "Z07:00"))
	}
	return p, nil
}

// parse 按格式解析 value → naive 墙钟(UTC location 承载);
// 缺省字段与 Python strptime 同款:年 1900、月 1、日 1、时分秒 0。
// 解析失败返回 error(调用方按坏行处理,零静默)。
func (p *parsedTSFormat) parse(value string) (time.Time, error) {
	if !p.valRe.MatchString(value) {
		return time.Time{}, fmt.Errorf("值不匹配格式")
	}
	var t time.Time
	var err error
	for _, layout := range p.layouts {
		t, err = time.Parse(layout, value)
		if err == nil {
			break
		}
	}
	if err != nil {
		return time.Time{}, err
	}
	// 行内 %z 解析出的偏移只作解析依据:剥离为 naive 墙钟语义
	// (归一只按源声明时区走,与索图 normalize.py 同款——
	// dt_local.replace(tzinfo=tz_declared) 会覆盖行内偏移,
	// 这里先对齐成「墙钟 + 无时区」)。
	if !p.hasYear {
		t = time.Date(1900, t.Month(), t.Day(),
			t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
	} else {
		t = time.Date(t.Year(), t.Month(), t.Day(),
			t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
	}
	return t, nil
}

// parseTimeAny 逐个格式试,全失败返回 error(与 Python 的
//「ts_formats 逐个试,全失败即坏行」同款)。
func parseTimeAny(value string, formats []*parsedTSFormat) (time.Time, bool) {
	for _, f := range formats {
		if t, err := f.parse(value); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
