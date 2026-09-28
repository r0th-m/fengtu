// ftingest —— 摄入管线 CLI(台架与采集包摄入入口)。
//
// 子命令:
//
//	text     行式文本摄入(--format 内置 | --desc 描述文件,[--tz 源声明时区])
//	evtx     evtx 摄入(纯 Go 原生解析 Velocidex/evtx,薄接口可替换)
//	package  WinInfoSC 采集包整包摄入(--map 映射表 [--desc-dir])
//	register 原文登记不解析(其余类别)
//
// 库连接:--ch host:9000 + --ch-user/--ch-pass;--pg postgres://...。
// 可用环境变量 FENGTU_CH / FENGTU_CH_USER / FENGTU_CH_PASS / FENGTU_PG 兜底。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/ye-mengwen/fengtu/internal/ingest"
	"github.com/ye-mengwen/fengtu/internal/ingest/store"
)

type dbFlags struct {
	chAddr, chUser, chPass, chCompress, pgDSN string
	workers, batchRows, chunkMB               int
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	// 性能剖面(台架定位用):--cpuprofile 必须放子命令前,
	// 如 ftingest --cpuprofile x.pprof text ...
	args := os.Args[1:]
	if len(args) >= 2 && args[0] == "--cpuprofile" {
		f, err := os.Create(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "cpuprofile 创建失败: %v\n", err)
			os.Exit(1)
		}
		_ = pprof.StartCPUProfile(f)
		defer func() { pprof.StopCPUProfile(); f.Close() }()
		args = args[2:]
	}
	ctx := context.Background()
	var err error
	switch args[0] {
	case "text":
		err = cmdText(ctx, args[1:])
	case "evtx":
		err = cmdEVTX(ctx, args[1:])
	case "package":
		err = cmdPackage(ctx, args[1:])
	case "register":
		err = cmdRegister(ctx, args[1:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "失败: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `用法: ftingest <子命令> [参数]
  text     --case C (--format nginx_combined | --desc x.yaml) [--tz TZ] FILE
  evtx     --case C FILE...
  package  --case C --map m.yaml [--desc-dir D] DIR
  register --case C FILE...
公共: --ch host:9000 --ch-user U --ch-pass P --pg DSN [--workers N] [--batch-rows N] [--chunk-mb N]`)
}

func newDBFlagSet(name string, d *dbFlags) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.StringVar(&d.chAddr, "ch", os.Getenv("FENGTU_CH"), "ClickHouse native 地址 host:9000")
	fs.StringVar(&d.chUser, "ch-user", envOr("FENGTU_CH_USER", "fengtu"), "CH 用户")
	fs.StringVar(&d.chPass, "ch-pass", os.Getenv("FENGTU_CH_PASS"), "CH 口令")
	fs.StringVar(&d.chCompress, "ch-compress", envOr("FENGTU_CH_COMPRESS", "lz4"), "CH 传输压缩(lz4|none)")
	fs.StringVar(&d.pgDSN, "pg", os.Getenv("FENGTU_PG"), "PG DSN")
	fs.IntVar(&d.workers, "workers", runtime.NumCPU(), "解析 worker 数(默认 CPU 核数)")
	fs.IntVar(&d.batchRows, "batch-rows", 50000, "CH 批量插入行数阈值(§4.1 ≥5 万)")
	fs.IntVar(&d.chunkMB, "chunk-mb", 64, "文本分块目标 MB(§4.1 ≥64MB)")
	return fs
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// openStores 连库;withEvents=false 时只开 PG(register 子命令不碰 CH)。
func openStores(ctx context.Context, d dbFlags, withEvents bool) (*store.PG, *store.CH, func(), error) {
	meta, err := store.NewPG(ctx, d.pgDSN)
	if err != nil {
		return nil, nil, nil, err
	}
	if !withEvents {
		return meta, nil, func() { meta.Close() }, nil
	}
	events, err := store.NewCH(ctx, d.chAddr, d.chUser, d.chPass, d.chCompress)
	if err != nil {
		meta.Close()
		return nil, nil, nil, err
	}
	return meta, events, func() { meta.Close(); events.Close() }, nil
}

func baseSpec(d dbFlags, caseName string) ingest.Spec {
	return ingest.Spec{
		CaseName:   caseName,
		Workers:    d.workers,
		BatchRows:  d.batchRows,
		ChunkBytes: d.chunkMB << 20,
	}
}

func report(label string, st *ingest.Stats, elapsed time.Duration) {
	rate := float64(st.BytesIn) / elapsed.Seconds() / (1 << 20)
	fmt.Printf("%s: 记录=%d (event=%d bad=%d skip=%d) 字节=%d 耗时=%.1fs (%.0f MiB/s)\n",
		label, st.Total, st.Events, st.Bad, st.Skip, st.BytesIn,
		elapsed.Seconds(), rate)
}

func cmdText(ctx context.Context, args []string) error {
	var d dbFlags
	fs := newDBFlagSet("text", &d)
	caseName := fs.String("case", "", "案件名(必填)")
	descPath := fs.String("desc", "", "desc 描述文件路径")
	format := fs.String("format", "", "内置格式(nginx_combined)")
	tz := fs.String("tz", "", "源声明时区(缺省不归一,nil 如实)")
	_ = fs.Parse(args)
	if *caseName == "" || fs.NArg() != 1 || (*descPath == "") == (*format == "") {
		fs.Usage()
		return fmt.Errorf("参数不齐:需 --case + (--desc|--format 二选一) + 单文件")
	}

	var parse ingest.ParseFunc
	var encoding string
	var isBlockStart func(string) bool
	var label string
	var err error
	if *format != "" {
		parse, err = ingest.BuiltinParse(*format)
		encoding = "utf-8"
		isBlockStart = ingest.AlwaysBlockStart
		label = "builtin:" + *format
	} else {
		parse, encoding, isBlockStart, err = ingest.LoadDescParse(*descPath)
		label = "desc:" + *descPath
	}
	if err != nil {
		return err
	}

	meta, events, closeFn, err := openStores(ctx, d, true)
	if err != nil {
		return err
	}
	defer closeFn()

	spec := baseSpec(d, *caseName)
	spec.Path = fs.Arg(0)
	spec.Kind = ingest.KindText
	spec.ParserLabel = label
	spec.TZDeclared = *tz

	start := time.Now()
	st, err := ingest.IngestTextFile(ctx, meta, events, spec, encoding, parse, isBlockStart)
	if err != nil {
		return err
	}
	report(spec.Path, st, time.Since(start))
	return nil
}

func cmdEVTX(ctx context.Context, args []string) error {
	var d dbFlags
	fs := newDBFlagSet("evtx", &d)
	caseName := fs.String("case", "", "案件名(必填)")
	_ = fs.Parse(args)
	if *caseName == "" || fs.NArg() < 1 {
		fs.Usage()
		return fmt.Errorf("参数不齐:需 --case + 文件")
	}
	meta, events, closeFn, err := openStores(ctx, d, true)
	if err != nil {
		return err
	}
	defer closeFn()

	for _, p := range fs.Args() {
		spec := baseSpec(d, *caseName)
		spec.Path = p
		spec.Kind = ingest.KindEVTX
		spec.ParserLabel = "evtx_native:velocidex"
		start := time.Now()
		st, err := ingest.IngestEVTXFile(ctx, meta, events, spec, ingest.VelocidexParser{})
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		report(p, st, time.Since(start))
	}
	return nil
}

func cmdPackage(ctx context.Context, args []string) error {
	var d dbFlags
	fs := newDBFlagSet("package", &d)
	caseName := fs.String("case", "", "案件名(必填)")
	mapPath := fs.String("map", "", "WinInfoSC 映射表 YAML(必填)")
	descDir := fs.String("desc-dir", "configs/desc", "desc 描述文件目录")
	tz := fs.String("tz", "", "源声明时区(缺省不归一,nil 如实)")
	_ = fs.Parse(args)
	if *caseName == "" || *mapPath == "" || fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("参数不齐:需 --case --map + 采集包目录")
	}
	mapText, err := os.ReadFile(*mapPath)
	if err != nil {
		return fmt.Errorf("映射表读取失败: %w", err)
	}
	m, err := ingest.LoadArtifactMap(string(mapText))
	if err != nil {
		return err
	}
	meta, events, closeFn, err := openStores(ctx, d, true)
	if err != nil {
		return err
	}
	defer closeFn()

	spec := baseSpec(d, *caseName)
	spec.TZDeclared = *tz
	start := time.Now()
	rep, err := ingest.IngestPackage(ctx, meta, events, ingest.PackageSpec{
		CaseName: *caseName,
		Root:     fs.Arg(0),
		Map:      m,
		Evtx:     ingest.VelocidexParser{},
		DescDir:  *descDir,
		Spec:     spec,
	})
	elapsed := time.Since(start)
	fmt.Printf("包 %s: 文件=%d 事件=%d bad=%d skip=%d 耗时=%.1fs\n",
		fs.Arg(0), rep.Files, rep.Events, rep.Bad, rep.Skip, elapsed.Seconds())
	fmt.Printf("  路由分布: %v\n  artifact 分布(前 10): %s\n",
		rep.ByRoute, topArtifacts(rep.ByArtifact, 10))
	if len(rep.Unmapped) > 0 {
		fmt.Printf("  unmapped(兜底 raw) %d 个: %v\n", len(rep.Unmapped), rep.Unmapped)
	}
	if len(rep.Failures) > 0 {
		for _, f := range rep.Failures {
			fmt.Printf("  失败 %s: %s\n", f.RelPath, f.Err)
		}
	}
	return err
}

func topArtifacts(m map[string]int, n int) string {
	type kv struct {
		k string
		v int
	}
	pairs := make([]kv, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, kv{k, v})
	}
	for i := 0; i < len(pairs); i++ {
		for j := i + 1; j < len(pairs); j++ {
			if pairs[j].v > pairs[i].v {
				pairs[i], pairs[j] = pairs[j], pairs[i]
			}
		}
	}
	out := ""
	for i, p := range pairs {
		if i >= n {
			out += " ..."
			break
		}
		out += fmt.Sprintf(" %s=%d", p.k, p.v)
	}
	return out
}

func cmdRegister(ctx context.Context, args []string) error {
	var d dbFlags
	fs := newDBFlagSet("register", &d)
	caseName := fs.String("case", "", "案件名(必填)")
	_ = fs.Parse(args)
	if *caseName == "" || fs.NArg() < 1 {
		fs.Usage()
		return fmt.Errorf("参数不齐:需 --case + 文件")
	}
	meta, _, closeFn, err := openStores(ctx, d, false)
	if err != nil {
		return err
	}
	defer closeFn()
	for _, p := range fs.Args() {
		spec := baseSpec(d, *caseName)
		spec.Path = p
		spec.Kind = ingest.KindRaw
		if err := ingest.RegisterRawFile(ctx, meta, spec); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		fmt.Printf("%s: 已登记(raw)\n", p)
	}
	return nil
}
