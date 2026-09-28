// ftmapwalk —— 采集包映射走查(台架工具,ftpackcount 姊妹件):按映射表
// 路由整包,逐文件打印 <route>/<parser>/<artifact>\t<包内相对路径>,
// 无命中打 UNMAPPED。不解析、不依赖 CH/PG——用于「采集项覆盖矩阵:
// 每个采集项要么 parsed 要么如实标 unmapped,不许静默漏」的逐文件台账。
//
// 用法: ftmapwalk <映射表.yaml> <Forensic_包根目录>
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/ye-mengwen/fengtu/internal/ingest"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "用法: ftmapwalk <映射表.yaml> <包根目录>")
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

	var lines []string
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		rule := m.Match(rel)
		if rule == nil {
			lines = append(lines, "UNMAPPED\t"+rel)
			return nil
		}
		lines = append(lines, fmt.Sprintf("%s/%s/%s\t%s", rule.Route, rule.Parser, rule.Artifact, rel))
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "走查失败:", err)
		os.Exit(1)
	}
	sort.Strings(lines)
	for _, l := range lines {
		fmt.Println(l)
	}
}
