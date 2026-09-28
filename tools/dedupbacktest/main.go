// dedupbacktest 派生去重闸(0.28.0-blackboard)的验收案回测(只读分析,
// 不动数据):拉取指定案件的意图图(登录后 GET /api/cases/{id}/intents),
// 按 created_at 回放历史——每条 AI 派生意图落库前,用与线上去重闸完全
// 相同的逻辑(internal/intent.CheckIntentDup,同包直链不复制实现)对当时
// 的比对集(非 parked 意图)判一次,统计「若黑板机制在场会拦下多少条」。
//
// 口径与限制(如实):
//   - 只评 created_by=ai 的意图(线上闸只闸 AI 派生;人工/模板播种不过闸);
//   - 比对集=创建时刻之前的全部非 parked 意图(当前仍 parked 的节点历史上
//     也未进过比对集,口径一致);
//   - created_at 序近似真实派生序(库内时序,非并发精确;报告如实标注)。
//
// 用法:
//
//	go run ./tools/dedupbacktest -base http://127.0.0.1:8200 \
//	  -case 57cdeafe-5697-4539-895d-5c5141365687 -user admin -pass <口令>
//	go run ./tools/dedupbacktest -file nodes.json   # 已保存的快照
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"sort"
	"time"

	"github.com/ye-mengwen/fengtu/internal/intent"
)

func main() {
	base := flag.String("base", "http://127.0.0.1:8200", "平台 base URL")
	caseID := flag.String("case", "", "案件 id")
	user := flag.String("user", "admin", "登录用户")
	pass := flag.String("pass", "", "登录密码(在线回测必填)")
	file := flag.String("file", "", "已有节点快照 JSON(免登录;{nodes:[...]} 或裸数组)")
	flag.Parse()
	if *file == "" && *pass == "" {
		fmt.Fprintln(os.Stderr, "在线回测必须给 -pass(或用 -file 走快照免登录)")
		os.Exit(2)
	}

	var nodes []*intent.Node
	var err error
	if *file != "" {
		nodes, err = loadFile(*file)
	} else {
		if *caseID == "" {
			fmt.Fprintln(os.Stderr, "缺 -case(或 -file)")
			os.Exit(2)
		}
		nodes, err = fetchNodes(*base, *user, *pass, *caseID)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "取节点失败:", err)
		os.Exit(1)
	}

	// 创建序回放(库内时序近似)
	sort.SliceStable(nodes, func(i, j int) bool {
		return nodes[i].CreatedAt.Before(nodes[j].CreatedAt)
	})

	var accepted []*intent.Node // 比对集:非 parked 意图(与线上 CheckIntentDup 口径一致)
	totalAI, blockedExact, blockedSimilar := 0, 0, 0
	type blockRec struct {
		text, hitText string
		score         float64
		exact         bool
	}
	var blocked []blockRec
	for _, n := range nodes {
		if n.Kind != intent.KindIntent {
			continue
		}
		if n.Status == intent.StatusParked {
			continue // parked 历史上不在比对集
		}
		if n.CreatedBy == intent.ByAI {
			totalAI++
			dv, score, hit := intent.CheckIntentDup(n.Text, accepted)
			if dv != intent.DupNone {
				rec := blockRec{text: n.Text, score: score, exact: dv == intent.DupExact}
				if hit != nil {
					rec.hitText = hit.Text
				}
				blocked = append(blocked, rec)
				if dv == intent.DupExact {
					blockedExact++
				} else {
					blockedSimilar++
				}
				continue // 被拦 → 转停车场 → 不进比对集
			}
		}
		accepted = append(accepted, n)
	}

	fmt.Printf("案件节点回放(创建序近似,只评 AI 派生,比对集=非 parked 意图):\n")
	fmt.Printf("  AI 派生意图总数: %d\n", totalAI)
	fmt.Printf("  若去重闸在场会拦下: %d 条(完全重复 %d + 高度相似 %d)\n",
		len(blocked), blockedExact, blockedSimilar)
	if totalAI > 0 {
		fmt.Printf("  拦截率: %.1f%%\n", float64(len(blocked))*100/float64(totalAI))
	}
	// 阈值扫描(证据面,不改口径):若阈值放宽到 0.7/0.6/0.5 会拦多少——
	// 供人评估阈值,线上仍按拍板值 0.85(保守优先,误拦代价低但噪声烦人)
	for _, th := range []float64{0.7, 0.6, 0.5} {
		var acc []*intent.Node
		n := 0
		for _, node := range nodes {
			if node.Kind != intent.KindIntent || node.Status == intent.StatusParked {
				continue
			}
			if node.CreatedBy == intent.ByAI {
				dv, score, _ := intent.CheckIntentDup(node.Text, acc)
				if dv == intent.DupExact || score >= th {
					n++
					continue
				}
			}
			acc = append(acc, node)
		}
		fmt.Printf("  [参考] 阈值 %.2f 时会拦: %d 条\n", th, n)
	}
	for i, b := range blocked {
		kind := "相似"
		if b.exact {
			kind = "重复"
		}
		fmt.Printf("  [%d] %s(score=%.2f) 被拦: %q ≈ 现存 %q\n",
			i+1, kind, b.score, b.text, b.hitText)
	}
}

func loadFile(path string) ([]*intent.Node, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Nodes []*intent.Node `json:"nodes"`
	}
	if err := json.Unmarshal(raw, &wrapper); err == nil && wrapper.Nodes != nil {
		return wrapper.Nodes, nil
	}
	var nodes []*intent.Node
	if err := json.Unmarshal(raw, &nodes); err != nil {
		return nil, err
	}
	return nodes, nil
}

func fetchNodes(base, user, pass, caseID string) ([]*intent.Node, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	cli := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	cred, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	resp, err := cli.Post(base+"/api/auth/login", "application/json", bytes.NewReader(cred))
	if err != nil {
		return nil, fmt.Errorf("登录请求失败: %w", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("登录失败: HTTP %d", resp.StatusCode)
	}
	resp, err = cli.Get(base + "/api/cases/" + caseID + "/intents")
	if err != nil {
		return nil, fmt.Errorf("意图图请求失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("意图图查询失败: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Nodes []*intent.Node `json:"nodes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Nodes, nil
}
