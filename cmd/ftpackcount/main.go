// ftpackcount —— 采集包走查计数(台架工具):按映射表路由整包,对每个
// route=native 的文件实跑解析器,按 event_type 计数;raw/desc/evtx 路由
// 只登记不解析。不依赖 CH/PG——用于「新增源全部 parsed + 事件数增量
// 如实记账」的无库验收(全管线重摄入要 CH/PG,台架无服务时以此替代)。
//
// 用法: ftpackcount <映射表.yaml> <Forensic_包根目录>
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ye-mengwen/fengtu/internal/ingest"
	"github.com/ye-mengwen/fengtu/internal/parsers"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "用法: ftpackcount <映射表.yaml> <包根目录>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "映射表读取失败:", err)
		os.Exit(1)
	}
	m, err := ingest.LoadArtifactMap(string(raw))
	if err != nil {
		fmt.Fprintln(os.Stderr, "映射表非法:", err)
		os.Exit(1)
	}
	root := os.Args[2]

	type routeKey struct{ route, parser, artifact string }
	routeCounts := map[routeKey]int{} // 文件数
	eventCounts := map[string]int64{} // event_type → 事件数
	var failures []string             // 文件级失败(如实列)
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		rule := m.Match(rel)
		if rule == nil {
			routeCounts[routeKey{"raw", "", "unmapped"}]++
			return nil
		}
		routeCounts[routeKey{string(rule.Route), rule.Parser, rule.Artifact}]++
		if rule.Route != ingest.RouteNative {
			return nil
		}
		parser, err := parsers.For(rule.Parser)
		if err != nil {
			failures = append(failures, rel+": "+err.Error())
			return nil
		}
		stream, err := parser.Records(p)
		if err != nil {
			failures = append(failures, rel+": "+err.Error())
			return nil
		}
		for {
			rec, ok := stream.Next()
			if !ok {
				break
			}
			et, _ := rec.Norm["event_type"].(string)
			if et == "" {
				et = "<" + rec.Kind + ">"
			}
			eventCounts[et]++
		}
		if err := stream.Err(); err != nil {
			failures = append(failures, rel+"(流): "+err.Error())
		}
		stream.Close()
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "走查失败:", err)
		os.Exit(1)
	}

	fmt.Println("== 路由分布(文件数) ==")
	keys := make([]routeKey, 0, len(routeCounts))
	for k := range routeCounts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].route != keys[j].route {
			return keys[i].route < keys[j].route
		}
		return keys[i].parser+keys[i].artifact < keys[j].parser+keys[j].artifact
	})
	for _, k := range keys {
		label := k.route
		if k.parser != "" {
			label += ":" + k.parser
		}
		fmt.Printf("  %-40s %6d  (%s)\n", label, routeCounts[k], k.artifact)
	}
	fmt.Println("== 事件计数(event_type) ==")
	ets := make([]string, 0, len(eventCounts))
	for et := range eventCounts {
		ets = append(ets, et)
	}
	sort.Strings(ets)
	var total int64
	for _, et := range ets {
		fmt.Printf("  %-40s %10d\n", et, eventCounts[et])
		total += eventCounts[et]
	}
	fmt.Printf("  %-40s %10d\n", "<合计>", total)
	fmt.Printf("== 文件级失败 %d 件 ==\n", len(failures))
	for _, f := range failures {
		fmt.Println("  " + strings.ReplaceAll(f, "\n", " "))
	}
}
