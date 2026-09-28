// ftnativedump —— 树庭面原生解析器的 JSONL 导出(金标准对照 harness,
// 与 tools/parsers_golden.py 的参照输出逐条对拍;与 ftevtxdump 同款定位)。
//
// 用法: ftnativedump <hive|mft|pf|lnk|usn|efu|jumplist|chromium|firefox|
//
//	srum|activities|shimcache|sam|security|system> <file> [--max N]
//
// 输出:stdout JSONL,每行一条归一记录
// {line_no, kind, ts_utc, norm, reason?};--max 截断导出条数(对照大文件
// 前 N 条用;计数对照用全量)。
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/ye-mengwen/fengtu/internal/model"
	"github.com/ye-mengwen/fengtu/internal/parsers"
)

type dumpRow struct {
	LineNo int            `json:"line_no"`
	Kind   string         `json:"kind"`
	TsUTC  *string        `json:"ts_utc,omitempty"`
	Norm   map[string]any `json:"norm,omitempty"`
	Reason *string        `json:"reason,omitempty"`
	Raw    string         `json:"raw,omitempty"`
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr,
			"用法: ftnativedump <hive|mft|pf|lnk|usn|efu|jumplist|chromium|firefox|"+
				"srum|activities|shimcache|sam|security|system> <file> [--max N]")
		os.Exit(2)
	}
	name := map[string]string{
		"hive": "registry_hive", "mft": "mft", "pf": "prefetch",
		"lnk": "lnk", "usn": "usn_csv",
		// M3b
		"efu": "efu", "jumplist": "jumplist",
		"chromium": "browser_chromium_history", "firefox": "browser_firefox_places",
		"srum": "srum", "activities": "win_activities",
		"shimcache": "shimcache_hive", "sam": "sam_accounts",
		"security": "security_policy", "system": "system_hive",
	}[os.Args[1]]
	if name == "" {
		fmt.Fprintln(os.Stderr, "未知解析器: "+os.Args[1])
		os.Exit(2)
	}
	maxN := 0
	if len(os.Args) == 5 && os.Args[3] == "--max" {
		maxN, _ = strconv.Atoi(os.Args[4])
	}
	p, err := parsers.For(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	stream, err := p.Records(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "解析失败(如实): %v\n", err)
		os.Exit(1)
	}
	defer stream.Close()

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	n := 0
	for {
		rec, ok := stream.Next()
		if !ok {
			break
		}
		row := dumpRow{LineNo: rec.LineNo, Kind: rec.Kind,
			Norm: rec.Norm, Reason: rec.Reason}
		if rec.TsUTCDirect != nil {
			s := model.FormatUTC(*rec.TsUTCDirect)
			row.TsUTC = &s
		}
		if len(rec.Raw) > 300 {
			row.Raw = rec.Raw[:300] + "…"
		} else {
			row.Raw = rec.Raw
		}
		if err := enc.Encode(row); err != nil {
			fmt.Fprintf(os.Stderr, "编码失败: %v\n", err)
			os.Exit(1)
		}
		n++
		if maxN > 0 && n >= maxN {
			break
		}
	}
	if err := stream.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "流错误(如实): %v\n", err)
		os.Exit(1)
	}
}
