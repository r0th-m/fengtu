// log_type 可选声明焊死(适用域路由键;未知品类拒载,不猜)。
package descform

import (
	"strings"
	"testing"
)

const logTypeBase = `
name: lt-demo
kind: regex
line_regex: '^(?P<ts>\d{4}-\d{2}-\d{2}) (?P<message>.*)$'
field_map:
  ts: ts_raw
  message: message
ts_field: ts
ts_formats:
  - '%Y-%m-%d'
`

func TestLogTypeDeclared(t *testing.T) {
	d, err := CompileText(logTypeBase + "log_type: app_log\n")
	if err != nil {
		t.Fatalf("合法 log_type 应过: %v", err)
	}
	if d.LogType != "app_log" {
		t.Fatalf("log_type 未透传: %q", d.LogType)
	}
}

func TestLogTypeAbsent(t *testing.T) {
	d, err := CompileText(logTypeBase)
	if err != nil {
		t.Fatalf("log_type 可选,缺省应过: %v", err)
	}
	if d.LogType != "" {
		t.Fatalf("缺省应为无品类: %q", d.LogType)
	}
}

func TestLogTypeUnknown(t *testing.T) {
	_, err := CompileText(logTypeBase + "log_type: made-up-type\n")
	if err == nil || !strings.Contains(err.Error(), "log_type") {
		t.Fatalf("未知品类应拒载: %v", err)
	}
}
