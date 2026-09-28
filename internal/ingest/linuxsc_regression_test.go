// LinuxSC 五发行版真实样本回归(0.32.0-linuxsc)。
//
// 门控:FENGTU_LINUXSC_SAMPLES 指向「已解包的样本根目录的父目录」
// (其子目录 each = LinuxSC_<IP>_<主机名> 包根)。未设置 → Skip(日常
// go test 不依赖仓外样本;样本属证据材料,永不入库)。
//
// 口径(与汇报数字一致):
//   - 解析成功率 = events / (events + bad)(bad=坏行,skip=空行/表头
//     等结构行不计入分母——skip 是契约内分流,不是失败);
//   - failures(文件级失败)必须为零;
//   - unmapped 清单如实列出(映射表覆盖度的诚实边界)。
package ingest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestLinuxSCRealSamples(t *testing.T) {
	root := os.Getenv("FENGTU_LINUXSC_SAMPLES")
	if root == "" {
		t.Skip("FENGTU_LINUXSC_SAMPLES 未设置(真样本回归需仓外样本目录)")
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "configs", "wininfosc-map.yaml"))
	if err != nil {
		t.Fatalf("真实映射表不可读: %v", err)
	}
	m, err := LoadArtifactMap(string(raw))
	if err != nil {
		t.Fatalf("真实映射表非法: %v", err)
	}
	var pkgs []string
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			sub := filepath.Join(dir, e.Name())
			// 包根判定:名字合规 + 直接含 _COLLECTION_TIME.txt(采集契约
			// 文件)——防解包多套一层同名目录时认到外层。
			if m.IsPackageRoot(e.Name()) {
				if _, err := os.Stat(filepath.Join(sub, "_COLLECTION_TIME.txt")); err == nil {
					pkgs = append(pkgs, sub)
					continue
				}
			}
			if depth < 1 { // 容忍解包多套一层目录(tar 包内还有一层)
				walk(sub, depth+1)
			}
		}
	}
	walk(root, 0)
	sort.Strings(pkgs)
	if len(pkgs) == 0 {
		t.Fatalf("样本目录 %s 下无 LinuxSC 包根", root)
	}

	for _, pkgDir := range pkgs {
		name := filepath.Base(pkgDir)
		t.Run(name, func(t *testing.T) {
			meta := newFakeMeta()
			ev := &fakeEvents{}
			rep, err := IngestPackage(context.Background(), meta, ev, PackageSpec{
				CaseName: "regress-" + name,
				Root:     pkgDir,
				Map:      m,
				DescDir:  filepath.Join("..", "..", "configs", "desc"),
			})
			if err != nil && rep == nil {
				t.Fatalf("摄入失败: %v", err)
			}
			if len(rep.Failures) > 0 {
				t.Fatalf("文件级失败 %d 起(首例 %+v)", len(rep.Failures), rep.Failures[0])
			}
			den := rep.Events + rep.Bad
			rate := float64(1)
			if den > 0 {
				rate = float64(rep.Events) / float64(den)
			}
			t.Logf("包 %s: 文件 %d,事件 %d,坏行 %d,skip %d,解析成功率 %.2f%%",
				name, rep.Files, rep.Events, rep.Bad, rep.Skip, rate*100)
			var routeKeys []string
			for k := range rep.ByRoute {
				routeKeys = append(routeKeys, string(k))
			}
			sort.Strings(routeKeys)
			for _, k := range routeKeys {
				t.Logf("  route %s: %d 文件", k, rep.ByRoute[Route(k)])
			}
			if len(rep.Unmapped) > 0 {
				sort.Strings(rep.Unmapped)
				t.Logf("  unmapped %d 文件: %v", len(rep.Unmapped), rep.Unmapped)
			}
			// 硬闸:有事件的包解析成功率不低于 95%(逐发行版人工复核过
			// 剩余坏行的构成后才准下调——下调须写理由)。
			if den > 0 && rate < 0.95 {
				t.Fatalf("解析成功率 %.2f%% 低于 95%% 闸", rate*100)
			}
			fmt.Printf("[linuxsc-regress] %s files=%d events=%d bad=%d skip=%d rate=%.2f%% unmapped=%d\n",
				name, rep.Files, rep.Events, rep.Bad, rep.Skip, rate*100, len(rep.Unmapped))
		})
	}
}
