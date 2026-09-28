// ftparse —— 描述文件/内置格式的解析 CLI(性能台架 harness)。
//
// 用法:
//
//	ftparse --desc xxx.yaml [--format nginx_combined] [--tz Asia/Shanghai] <file>
//
// 输出:stdout JSONL,每行一条归一记录
// {line_no, kind, ts_raw, ts_utc, norm, raw, reason?, continuation_lines}。
// ts_utc 由「行内本地时间 + --tz 源声明时区」归一;不给 --tz → null 如实。
// 纯单机:无数据库、无网络依赖。
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"iter"
	"os"
	"runtime/pprof"

	"github.com/ye-mengwen/fengtu/internal/descform"
	"github.com/ye-mengwen/fengtu/internal/model"
)

func main() {
	descPath := flag.String("desc", "", "描述文件(YAML)路径")
	format := flag.String("format", "", "内置格式(目前: nginx_combined)")
	tz := flag.String("tz", "", "源声明时区(IANA 名或 UTC±x;缺省不归一)")
	cpuprofile := flag.String("cpuprofile", "", "CPU 剖面输出路径(台架定位用)")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"用法: ftparse --desc xxx.yaml [--format nginx_combined] [--tz 时区] <file>\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	if (*descPath == "") == (*format == "") {
		fmt.Fprintln(os.Stderr, "--desc 与 --format 须且只须给一个")
		os.Exit(2)
	}
	file := flag.Arg(0)

	// 性能剖面(台架定位用):--cpuprofile 与位置参数互斥校验后启用
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cpuprofile 创建失败: %v\n", err)
			os.Exit(1)
		}
		_ = pprof.StartCPUProfile(f)
		defer func() { pprof.StopCPUProfile(); f.Close() }()
	}

	var parse func(lines []string) iter.Seq[model.Record]
	encoding := "utf-8"

	if *format != "" {
		switch *format {
		case descform.NginxCombinedFormatID:
			parse = descform.ParseNginxCombined
		default:
			fmt.Fprintf(os.Stderr, "未知内置格式: %s\n", *format)
			os.Exit(2)
		}
	} else {
		text, err := os.ReadFile(*descPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "描述文件读取失败: %v\n", err)
			os.Exit(1)
		}
		d, err := descform.CompileText(string(text))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		encoding = d.Encoding
		parse = d.Parse
	}

	lines, err := descform.DecodeFile(file, encoding)
	if err != nil {
		fmt.Fprintf(os.Stderr, "源文件读取/解码失败: %v\n", err)
		os.Exit(1)
	}

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	var buf bytes.Buffer
	n := 0
	for rec := range parse(lines) {
		rec.TsUTC = descform.ResolveTsUTC(rec.DTLocal, *tz, rec.TsUTCDirect)
		buf.Reset()
		if err := rec.AppendJSONL(&buf); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		if _, err := out.Write(buf.Bytes()); err != nil {
			fmt.Fprintf(os.Stderr, "输出失败: %v\n", err)
			os.Exit(1)
		}
		n++
	}
}
