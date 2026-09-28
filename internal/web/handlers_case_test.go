// 新建任务向导端点契约测试(交互改造,设计依据 fengtu-interaction-design.md §1):
// POST /api/cases——应急类型白名单/字段上限负样本、元数据落库回读、
// 目的预设播种 goal(引擎 nil 时如实 note 不杀主链路)、同名复用覆盖语义、
// 登录闸。
package web

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestCreateCaseEndpoint(t *testing.T) {
	e := newTestEnv(t)
	fi := newFakeIntent()
	e.srv.deps.Intent = fi
	e.login(t)

	// 未登录 401(登录闸;wizard 端点不在白名单)
	saved := e.cookie
	e.cookie = ""
	code, _ := e.do(t, "POST", "/api/cases", map[string]any{
		"name": "x", "incident_type": "ransomware"})
	if code != http.StatusUnauthorized {
		t.Fatalf("未登录应 401,得 %d", code)
	}
	e.cookie = saved

	// 正常创建:元数据落库 + 目的预设播种 goal
	code, out := e.do(t, "POST", "/api/cases", map[string]any{
		"name":          "勒索响应-演练",
		"incident_type": "ransomware",
		"background":    "发现经过:……\n影响面:……",
		"goals":         []string{"确认入侵入口", "确定影响范围", "  "}, // 空白跳过
	})
	if code != http.StatusCreated {
		t.Fatalf("创建应 201,得 %d: %v", code, out)
	}
	if out["goals_seeded"].(float64) != 2 {
		t.Fatalf("goals_seeded=%v,应=2", out["goals_seeded"])
	}
	c := out["case"].(map[string]any)
	if c["incident_type"] != "ransomware" || c["background"] == "" {
		t.Fatalf("元数据未回读: %v", c)
	}
	presets, isArr := c["goal_presets"].([]any)
	if !isArr || len(presets) != 2 {
		t.Fatalf("goal_presets 应为 2 条数组: %v", c["goal_presets"])
	}
	caseID := c["id"].(string)

	// GET 回读:元数据持久(列表与详情同口径)
	_, out = e.do(t, "GET", "/api/cases/"+caseID, nil)
	c2 := out["case"].(map[string]any)
	if c2["incident_type"] != "ransomware" {
		t.Fatalf("详情回读 incident_type 丢失: %v", c2)
	}
	_, out = e.do(t, "GET", "/api/cases", nil)
	found := false
	for _, x := range out["cases"].([]any) {
		m := x.(map[string]any)
		if m["id"] == caseID && m["incident_type"] == "ransomware" {
			found = true
		}
	}
	if !found {
		t.Fatal("列表回读元数据缺失")
	}

	// 审计留痕
	acts := map[string]bool{}
	entries, err := e.audit.AllAudit(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		acts[en.Action] = true
	}
	if !acts["case.create"] {
		t.Fatal("case.create 未进审计链")
	}

	// 同名复用:元数据按本次提交覆盖(与上传链 EnsureCase 同语义)
	code, out = e.do(t, "POST", "/api/cases", map[string]any{
		"name": "勒索响应-演练", "incident_type": "intrusion",
		"goals": []string{"攻击时间线"},
	})
	if code != http.StatusCreated {
		t.Fatalf("同名复用应 201,得 %d: %v", code, out)
	}
	if out["case"].(map[string]any)["id"].(string) != caseID {
		t.Fatal("同名应复用既有案件 id")
	}
	_, out = e.do(t, "GET", "/api/cases/"+caseID, nil)
	if out["case"].(map[string]any)["incident_type"] != "intrusion" {
		t.Fatal("同名复用元数据未覆盖")
	}
}

// TestCreateCaseRejects 负样本:名称空/超长、类型非法、背景超长、目的超限。
func TestCreateCaseRejects(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)

	bad := map[string]map[string]any{
		"名称空":   {"name": "  ", "incident_type": "ransomware"},
		"名称超长":  {"name": strings.Repeat("案", 129), "incident_type": "ransomware"},
		"类型非法":  {"name": "x", "incident_type": "crypto-miner"},
		"类型缺":   {"name": "x"},
		"背景超长":  {"name": "x", "incident_type": "other",
			"background": strings.Repeat("背", 4001)},
		"目的超数": {"name": "x", "incident_type": "other",
			"goals": func() []string {
				g := make([]string, 13)
				for i := range g {
					g[i] = fmt.Sprintf("目的%d", i)
				}
				return g
			}()},
		"目的单条超长": {"name": "x", "incident_type": "other",
			"goals": []string{strings.Repeat("目", 301)}},
	}
	for name, body := range bad {
		code, out := e.do(t, "POST", "/api/cases", body)
		if code != http.StatusBadRequest {
			t.Fatalf("%s:应 400,得 %d: %v", name, code, out)
		}
		if out["error"] == "" {
			t.Fatalf("%s:400 无错误文案", name)
		}
	}
	// 负样本不许落案(空清单可能为 null,如实兼容)
	_, out := e.do(t, "GET", "/api/cases", nil)
	if arr, _ := out["cases"].([]any); len(arr) != 0 {
		t.Fatalf("负样本泄漏落案: %v", out["cases"])
	}
}

// TestCreateCaseIntentDown 意图引擎未装配:元数据照落,如实 note,不 5xx。
func TestCreateCaseIntentDown(t *testing.T) {
	e := newTestEnv(t)
	e.login(t)
	code, out := e.do(t, "POST", "/api/cases", map[string]any{
		"name": "无引擎案", "incident_type": "data-leak",
		"goals": []string{"数据泄露面"},
	})
	if code != http.StatusCreated {
		t.Fatalf("引擎未装配创建应 201,得 %d: %v", code, out)
	}
	if out["goals_seeded"].(float64) != 0 {
		t.Fatalf("引擎未装配 goals_seeded 应=0,得 %v", out["goals_seeded"])
	}
	if !strings.Contains(fmt.Sprint(out["note"]), "意图链引擎未启用") {
		t.Fatalf("引擎未装配应如实 note: %v", out["note"])
	}
}
