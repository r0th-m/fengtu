// WinInfoSC 采集包整包摄入:结构识别(映射表)→ 逐文件路由 → 统一管线。
//
// 纪律:
//   - 根目录名不符合采集包规范 → 如实拒绝(不猜是不是包);
//   - 单文件失败不拖垮整包:记 failures 继续,最终报表如实列;
//   - 无规则命中的文件进 unmapped 清单(映射表覆盖度的诚实边界)。
package ingest

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ye-mengwen/fengtu/internal/descform"
	"github.com/ye-mengwen/fengtu/internal/parsers"
)

// FileFailure 单文件失败账。
type FileFailure struct {
	RelPath string
	Err     string
}

// PackageReport 整包摄入报表。
type PackageReport struct {
	Files      int
	Events     int64
	Bad        int64
	Skip       int64
	ByRoute    map[Route]int
	ByArtifact map[string]int
	Unmapped   []string
	Failures   []FileFailure
	Host       string // 主机键(host_regex 提取;空=未建模,如实)
	Package    string // 登记根名(同一主机二次采包可能带 #N 后缀)
}

// PackageSpec 整包摄入参数。
type PackageSpec struct {
	CaseName string
	Root     string // Forensic_<IP>_<主机名>/ 目录
	Map      *ArtifactMap
	Evtx     EvtxParser // evtx 原生解析器(route=evtx_native 用)
	DescDir  string     // desc 描述文件目录(route=desc 用)
	Spec     Spec       // 公共参数(Workers/BatchRows/ChunkBytes/TZDeclared)
	// DisplayRoot 登记根名(空=包根目录名;同一主机二次采包路径冲突时
	// 调用方给 #N 后缀的登记根名,主机键始终从真实包名提取)。
	DisplayRoot string
	// OnFile 单文件处理完回调(进度流用;nil = 不报)。
	// done 含失败文件(尽力而为原则,账在 failures)。
	OnFile func(done, total int, rel string)
}

// IngestPackage 整包摄入。返回报表;有失败文件时 err 非 nil(报表仍在)。
func IngestPackage(ctx context.Context, meta MetaStore, events EventStore,
	ps PackageSpec) (*PackageReport, error) {

	rootName := filepath.Base(filepath.Clean(ps.Root))
	if !ps.Map.IsPackageRoot(rootName) {
		return nil, fmt.Errorf("根目录 %q 不符合采集包命名规范(%s),不猜,拒绝摄入",
			rootName, ps.Map.PackageRootRegex)
	}
	displayRoot := ps.DisplayRoot
	if displayRoot == "" {
		displayRoot = rootName
	}
	host := ps.Map.HostOfPackage(rootName) // 主机键:从真实包名提取(空=未建模)

	// 0.32.0-linuxsc:包级时区自动推导。用户未指定 TZDeclared 时,读包内
	// _COLLECTION_TIME.txt 的「Timezone=<IANA>」行(LinuxSC 采集端恒定
	// 写入;WinInfoSC 同名文件是 w32tm 中文输出、无此键,不受影响)。
	// 仍识别不了 → 时区未知,ts 不归一(nil 如实,不猜)。
	if ps.Spec.TZDeclared == "" {
		if tz := packageTimezone(ps.Root); tz != "" {
			ps.Spec.TZDeclared = tz
		}
	}

	rep := &PackageReport{ByRoute: map[Route]int{}, ByArtifact: map[string]int{},
		Host: host, Package: displayRoot}

	// 先收集文件清单(排序,摄入顺序可复现)
	var files []string
	err := filepath.WalkDir(ps.Root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("采集包遍历失败: %w", err)
	}
	sort.Strings(files)

	for _, abs := range files {
		rel, err := filepath.Rel(ps.Root, abs)
		if err != nil {
			return rep, err
		}
		rel = filepath.ToSlash(rel)

		route := RouteRaw
		artifact := "unmapped"
		descName := ""
		nativeParser := ""
		logType := ""
		if rule := ps.Map.Match(rel); rule != nil {
			route = rule.Route
			artifact = rule.Artifact
			descName = rule.Desc
			nativeParser = rule.Parser
			logType = rule.LogType
		} else {
			rep.Unmapped = append(rep.Unmapped, rel)
		}
		rep.Files++
		rep.ByRoute[route]++
		rep.ByArtifact[artifact]++

		spec := ps.Spec
		spec.CaseName = ps.CaseName
		spec.Path = abs
		spec.DisplayPath = filepath.ToSlash(filepath.Join(displayRoot, rel))
		spec.ArtifactType = artifact
		spec.Host = host
		spec.Package = displayRoot

		var stats *Stats
		var ierr error
		switch route {
		case RouteEVTXNative:
			spec.Kind = KindEVTX
			spec.ParserLabel = "evtx_native:velocidex"
			spec.LogType = "windows_event_log" // evtx 原生路由品类(结构常量)
			stats, ierr = IngestEVTXFile(ctx, meta, events, spec, ps.Evtx)
		case RouteDesc:
			spec.Kind = KindText
			spec.ParserLabel = "desc:" + descName
			stats, ierr = ingestWithDesc(ctx, meta, events, spec, ps.DescDir, descName)
		case RouteNative: // M3:树庭面原生解析器(registry hive/MFT/PF/lnk/USN)
			p, perr := parsers.For(nativeParser)
			if perr != nil {
				ierr = perr // 映射表引用了未注册解析器:该文件如实 failed
				break
			}
			spec.Kind = KindNative
			spec.ParserLabel = "native:" + nativeParser
			spec.LogType = logType // 规则声明的源品类(如 usn_journal;空=无品类)
			stats, ierr = IngestNativeFile(ctx, meta, events, spec, p)
		default: // RouteRaw
			spec.Kind = KindRaw
			ierr = RegisterRawFile(ctx, meta, spec)
		}
		if ierr != nil {
			rep.Failures = append(rep.Failures, FileFailure{RelPath: rel, Err: ierr.Error()})
			continue
		}
		if stats != nil {
			rep.Events += stats.Events
			rep.Bad += stats.Bad
			rep.Skip += stats.Skip
		}
		if ps.OnFile != nil {
			ps.OnFile(rep.Files, len(files), rel)
		}
	}

	if len(rep.Failures) > 0 {
		return rep, fmt.Errorf("%d 个文件摄入失败(详见报表 failures)", len(rep.Failures))
	}
	return rep, nil
}

// ingestWithDesc 按映射表绑定的 desc 名加载描述文件并摄入。
func ingestWithDesc(ctx context.Context, meta MetaStore, events EventStore,
	spec Spec, descDir, descName string) (*Stats, error) {
	descPath := filepath.Join(descDir, descName+".yaml")
	text, err := os.ReadFile(descPath)
	if err != nil {
		return nil, fmt.Errorf("desc %q 读取失败(%s): %w", descName, descPath, err)
	}
	d, err := descform.CompileText(string(text))
	if err != nil {
		return nil, fmt.Errorf("desc %q 编译失败: %w", descName, err)
	}
	spec.LogType = d.LogType // desc 声明品类(空 = 无品类,如实)
	return IngestTextFile(ctx, meta, events, spec, d.Encoding, d.Parse, d.IsBlockStart)
}

// BuiltinParse 内置格式分发(内置格式无多行,isBlockStart 恒 true)。
func BuiltinParse(formatID string) (ParseFunc, error) {
	switch formatID {
	case descform.NginxCombinedFormatID:
		return descform.ParseNginxCombined, nil
	default:
		return nil, fmt.Errorf("未知内置格式: %s", formatID)
	}
}

// AlwaysBlockStart 无多行格式的恒真块起始判定。
func AlwaysBlockStart(string) bool { return true }

// LoadDescParse 加载 desc 文件 → (解析驱动, 编码, 块起始判定)。
func LoadDescParse(descPath string) (ParseFunc, string, func(string) bool, error) {
	text, err := os.ReadFile(descPath)
	if err != nil {
		return nil, "", nil, fmt.Errorf("描述文件读取失败: %w", err)
	}
	d, err := descform.CompileText(string(text))
	if err != nil {
		return nil, "", nil, err
	}
	return d.Parse, d.Encoding, d.IsBlockStart, nil
}

// LowerExt 小写扩展名(映射表测试与诊断用)。
func LowerExt(p string) string { return strings.ToLower(filepath.Ext(p)) }

// packageTimezone 读包根 _COLLECTION_TIME.txt 的 Timezone=<IANA> 行
// (0.32.0-linuxsc)。ASCII 键名,GBK 内容不碍。文件缺失/无此行 → 空串
// (调用方保持时区未知,不猜)。
func packageTimezone(root string) string {
	raw, err := os.ReadFile(filepath.Join(root, "_COLLECTION_TIME.txt"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimRight(line, "\r"), "Timezone="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
