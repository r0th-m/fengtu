// 时间线(切片 8b)+ 检索源多选的契约测试。
package web

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/ye-mengwen/fengtu/internal/ingest"
)

// uploadTwo 造两源案件:a.log(nginx,声明时区 → ts 归一)+ b.log(无格式,
// 登记未解析)。返回 caseID/srcA/srcB;并直接往 fakeCH 补一条 b 源的
// 无时区事件(无时区事件不参与时间线桶,单列如实标——本测试的验证对象)。
func uploadTwo(t *testing.T, e *testEnv, caseName string) (string, string, string) {
	t.Helper()
	tid := e.uploadFileTZ(t, caseName, "a.log", []byte(nginxContent),
		"nginx_combined", "+0000")
	e.waitTask(t, tid)
	tid2 := e.uploadFile(t, caseName, "b.log",
		[]byte("10.9.9.9 - - [01/Aug/2026:10:00:09 +0000] \"GET /b HTTP/1.1\" 200 1 \"-\" \"sqlmap/2\"\n"), "")
	e.waitTask(t, tid2)
	_, out := e.do(t, "GET", "/api/cases", nil)
	var caseID string
	for _, c := range out["cases"].([]any) {
		cm := c.(map[string]any)
		if cm["name"] == caseName {
			caseID = cm["id"].(string)
		}
	}
	if caseID == "" {
		t.Fatalf("案件未建: %v", out)
	}
	_, out = e.do(t, "GET", "/api/cases/"+caseID, nil)
	var srcA, srcB string
	for _, s := range out["sources"].([]any) {
		sm := s.(map[string]any)
		if strings.HasSuffix(sm["path"].(string), "a.log") {
			srcA = sm["id"].(string)
		} else {
			srcB = sm["id"].(string)
		}
	}
	// b 源补一条无时区事件(模拟无时区格式解析产物)
	if err := e.ch.InsertEvents(context.Background(), []ingest.EventRow{{
		CaseID: caseID, SourceID: srcB, LineNo: 1, TS: nil,
		Kind: "event", Fields: "{}", Raw: "无时间戳的事件行",
	}}); err != nil {
		t.Fatalf("fakeCH 补事件失败: %v", err)
	}
	return caseID, srcA, srcB
}

// TestTimeline 时间线端点:小时桶密度(升序、只含有时区源)+ 无时区源单列;
// 未装配 Stats 面 503 如实;无此案件 404。
func TestTimeline(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	caseID, _, srcB := uploadTwo(t, e, "tl-case")

	code, out := e.do(t, "GET", "/api/cases/"+caseID+"/timeline", nil)
	if code != 200 {
		t.Fatalf("时间线失败: %d %v", code, out)
	}
	buckets, ok := out["buckets"].([]any)
	if !ok || len(buckets) == 0 {
		t.Fatalf("应有小时桶: %v", out)
	}
	b0 := buckets[0].(map[string]any)
	key := b0["key"].(string)
	if len(key) < 9 || strings.HasPrefix(key, "20") {
		t.Fatalf("桶 key 应为 Unix 秒(非 RFC3339): %v", b0)
	}
	if out["bucket_epoch_seconds"] != true {
		t.Fatalf("应声明桶 key 为 Unix 秒: %v", out)
	}
	// 升序
	for i := 1; i < len(buckets); i++ {
		prev := buckets[i-1].(map[string]any)["key"].(string)
		cur := buckets[i].(map[string]any)["key"].(string)
		if cur < prev {
			t.Fatalf("桶应升序: %v → %v", prev, cur)
		}
	}
	// 无时区源单列(b 源那条 ts=NULL 事件)
	notz, ok := out["notz_sources"].([]any)
	if !ok {
		t.Fatalf("无时区源清单应在(数组): %v", out)
	}
	found := false
	for _, s := range notz {
		if s.(map[string]any)["key"] == srcB {
			found = true
		}
	}
	if !found {
		t.Fatalf("无时区源 %s 应单列: %v", srcB, notz)
	}

	// 无此案件 404
	code, _ = e.do(t, "GET", "/api/cases/nope/timeline", nil)
	if code != http.StatusNotFound {
		t.Fatalf("无此案件应 404: %d", code)
	}
	// Stats 面未装配 503 如实
	e.srv.deps.Stats = nil
	code, _ = e.do(t, "GET", "/api/cases/"+caseID+"/timeline", nil)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("未装配应 503: %d", code)
	}
}

// TestSearchMultiSource 检索源多选(重复 source_id 参数 → SourceIDs 集合限定)。
func TestSearchMultiSource(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	caseID, srcA, srcB := uploadTwo(t, e, "ms-case")

	// 单源:只中 a.log 的 1 条
	code, out := e.do(t, "GET",
		"/api/query?case_id="+caseID+"&q=sqlmap&source_id="+srcA, nil)
	if code != 200 || len(out["events"].([]any)) != 1 {
		t.Fatalf("单源检索失败: %d %v", code, out)
	}
	// 源多选(a+b):a 的 1 条 + b 无时区那条不含 sqlmap → 仍 1 条;
	// 换词 「sqlmap」 在 b 原始行(未解析)不进 CH,改验集合限定语义:
	// 多选 vs 单选对同一词的结果差 = 集合限定生效
	code, out = e.do(t, "GET",
		"/api/query?case_id="+caseID+"&q=sqlmap&source_id="+srcA+"&source_id="+srcB, nil)
	if code != 200 || len(out["events"].([]any)) != 1 {
		t.Fatalf("多选(a+b)应中 1 条(b 无 sqlmap 事件): %d %v", code, out)
	}
	// 限定只 b:0 条(集合限定如实收窄)
	code, out = e.do(t, "GET",
		"/api/query?case_id="+caseID+"&q=sqlmap&source_id="+srcB, nil)
	if code != 200 || len(out["events"].([]any)) != 0 {
		t.Fatalf("限定 b 应 0 条: %d %v", code, out)
	}
	// 多选限定下查 b 的无时区事件词 → 中;只 a → 不中(集合限定方向性)
	code, out = e.do(t, "GET",
		"/api/query?case_id="+caseID+"&q=无时间戳&source_id="+srcA+"&source_id="+srcB, nil)
	if code != 200 || len(out["events"].([]any)) != 1 {
		t.Fatalf("多选应中 b 的无时区事件: %d %v", code, out)
	}
}
