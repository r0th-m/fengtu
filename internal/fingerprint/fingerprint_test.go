// 指纹判定焊死(合成正负样本,对 spec 写,无案件值):
// nginx 全量样本高置信自动过 / 垃圾文本无可判定候选 / 头行加权公式 /
// desc 候选识别 / 门槛边界。
package fingerprint

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func nginxLines(n int) []string {
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf(
			`198.51.100.%d - - [01/Aug/2026:10:%02d:%02d +0000] "GET /p/%d HTTP/1.1" 200 %d "-" "Mozilla/5.0"`,
			i%250+1, i/60%60, i%60, i, 100+i%900))
	}
	return out
}

func testCands(t *testing.T) []Candidate {
	t.Helper()
	cands, err := LoadCandidates(t.TempDir()) // 空目录 = 仅内置 nginx
	if err != nil {
		t.Fatalf("候选装载失败: %v", err)
	}
	return cands
}

func TestDetectNginxAuto(t *testing.T) {
	res := Detect(nginxLines(100), testCands(t))
	if res == nil {
		t.Fatal("nginx 样本应可判定")
	}
	if res.FormatID != "builtin:nginx_combined" {
		t.Fatalf("判定格式错: %s", res.FormatID)
	}
	if res.Confidence < AutoThreshold {
		t.Fatalf("全量合法样本置信度应 ≥0.9: %.3f", res.Confidence)
	}
	if res.LogType != "web_access" {
		t.Fatalf("源品类错: %s", res.LogType)
	}
}

func TestDetectGarbageNoCandidate(t *testing.T) {
	var garbage []string
	for i := 0; i < 50; i++ {
		garbage = append(garbage, strings.Repeat("乱码不是日志 ", 5)+fmt.Sprint(i))
	}
	res := Detect(garbage, testCands(t))
	if res != nil && res.Confidence >= AutoThreshold {
		t.Fatalf("垃圾文本不应高置信: %+v", res)
	}
}

func TestHeadWeighting(t *testing.T) {
	// 头区(前 20 条非 skip)全合法,尾部全坏:
	// 头 20×2 权重 + 尾 30×1 → conf = 40/70 ≈ 0.571 < 0.9 → 不自动过
	lines := append(nginxLines(HeadLines), func() []string {
		var bad []string
		for i := 0; i < 30; i++ {
			bad = append(bad, "这不是 nginx 行 "+fmt.Sprint(i))
		}
		return bad
	}()...)
	res := Detect(lines, testCands(t))
	if res == nil {
		t.Fatal("头区全合法应有候选分")
	}
	want := float64(HeadWeight*HeadLines) / float64(HeadWeight*HeadLines+30)
	if res.Confidence < want-0.001 || res.Confidence > want+0.001 {
		t.Fatalf("头行加权公式不符: got %.4f want %.4f", res.Confidence, want)
	}
	if res.Confidence >= AutoThreshold {
		t.Fatalf("尾部 60%% 坏行不应自动过: %.3f", res.Confidence)
	}
}

func TestDescCandidate(t *testing.T) {
	dir := t.TempDir()
	desc := `
name: kv-demo
kind: regex
log_type: app_log
line_regex: '^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<level>\S+) (?P<message>.*)$'
field_map:
  ts: ts_raw
  level: level
  message: message
ts_field: ts
ts_formats:
  - '%Y-%m-%d %H:%M:%S'
status: enable
`
	if err := os.WriteFile(filepath.Join(dir, "kv-demo.yaml"), []byte(desc), 0o644); err != nil {
		t.Fatal(err)
	}
	cands, err := LoadCandidates(dir)
	if err != nil {
		t.Fatalf("候选装载失败: %v", err)
	}
	if len(cands) != 2 { // 内置 nginx + desc
		t.Fatalf("候选数: %d", len(cands))
	}
	var lines []string
	for i := 0; i < 30; i++ {
		lines = append(lines, fmt.Sprintf("2026-08-01 10:00:%02d INFO 第 %d 条应用日志", i%60, i))
	}
	res := Detect(lines, cands)
	if res == nil || res.FormatID != "desc:kv-demo" {
		t.Fatalf("desc 候选应胜出: %+v", res)
	}
	if res.LogType != "app_log" {
		t.Fatalf("desc 声明品类未透传: %s", res.LogType)
	}
	if res.Confidence < AutoThreshold {
		t.Fatalf("desc 全量合法样本置信度: %.3f", res.Confidence)
	}
}

func TestFindCandidate(t *testing.T) {
	cands := testCands(t)
	if FindCandidate(cands, "builtin:nginx_combined") == nil {
		t.Fatal("内置候选应可找")
	}
	if FindCandidate(cands, "desc:nope") != nil {
		t.Fatal("不存在候选应 nil")
	}
}

func TestEmptySample(t *testing.T) {
	if res := Detect(nil, testCands(t)); res != nil {
		t.Fatalf("空样本应无可判定候选: %+v", res)
	}
	// 全空行(skip 不参与判定)= 无可判定
	if res := Detect([]string{"", "  ", ""}, testCands(t)); res != nil {
		t.Fatalf("全空行样本应无可判定候选: %+v", res)
	}
}
