// zip 展开与 WinInfoSC 哈希清单校验。
//
// 展开语义(同索图,单层、不递归嵌套压缩包):
//   - 包模式:唯一顶层目录命中采集包命名规范(Forensic_<IP>_<主机名>,
//     判定函数由调用方注入——映射表是所有者)→ 整树安全展开,
//     _HASH_MANIFEST.txt 逐文件对账(契约失配 = 拒收;默认档
//     Mode=DEFAULT_NO_HASH 声明 = 采集时未哈希,无可对账条目,
//     如实记 NoHash 放行,完整性哈希由本平台入库时计算);
//   - 文件模式:每个非目录条目展成一个源;嵌套 .zip 跳过如实记。
//
// 安全与编码:
//   - 防 zip slip:逐条目校验解出路径必须落在目标目录内,越界整包拒绝;
//   - 条目名编码:UTF-8 标志位置位直取;未置位且非合法 UTF-8 → GBK
//     重解码(中文 Windows 压缩工具常态,索图 _decode_entry_name 同款);
//   - 清单文件编码:UTF-8 严格 → 回退 GBK(树庭 manifest.py 同款);
//     清单行 <sha256><空白><绝对路径>,绝对路径按「组件等于根目录名的
//     最后一段」相对化(防张冠李戴:别机清单混进来要喊出来)。
package ingress

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"

	"github.com/ye-mengwen/fengtu/internal/ingest"
)

// ExpandedFile 展成的一个文件源。
type ExpandedFile struct {
	Name   string // zip 内路径(正斜杠)
	Path   string // 解出后的磁盘绝对路径
	SHA256 string
	Size   int64
}

// ManifestReport 清单对账(语义照树庭:manifest_ok = 无 missing 且无
// mismatch;extra 为盘上多出文件——清单生成后新增,如实计数不判负)。
// NoHash:WinInfoSC 默认档(2026-09-26 起)采集时不逐文件哈希,清单只写
// 「Mode=DEFAULT_NO_HASH」声明——完整性哈希由本平台入库时计算,采集→入库
// 区间的保管责任归采集人;严格档(-Hash)清单维持逐文件 SHA256 + 根哈希。
type ManifestReport struct {
	Present  bool     `json:"present"`
	NoHash   bool     `json:"no_hash,omitempty"`
	Entries  int      `json:"entries"`
	OK       int      `json:"ok"`
	Missing  []string `json:"missing"`
	Mismatch []string `json:"mismatch"`
	Extra    int      `json:"extra"`
	BadLines int      `json:"bad_lines"`
}

// Pass manifest_ok 判定(树庭同款:missing==0 且 mismatch==0)。
// 默认档未哈希声明(NoHash)无可对账条目,如实放行——入库侧自行计算指纹。
func (r *ManifestReport) Pass() bool {
	return !r.Present || r.NoHash || (len(r.Missing) == 0 && len(r.Mismatch) == 0)
}

// Expanded 一次 zip 展开的产物。
type Expanded struct {
	Mode        string // "package" | "files"
	PackageRoot string // 包模式:解出的采集包根目录(磁盘绝对路径)
	PackageName string // 包模式:根目录名(Forensic_<IP>_<主机名>)
	Files       []ExpandedFile
	Skipped     []string // 跳过项(嵌套压缩包等),如实记
	Manifest    *ManifestReport
}

// decodeEntryName 还原 zip 条目名编码(见文件头注释)。
func decodeEntryName(f *zip.File) string {
	if f.Flags&(1<<11) != 0 { // UTF-8 标志位
		return f.Name
	}
	if utf8.ValidString(f.Name) {
		return f.Name
	}
	if s, err := simplifiedchinese.GBK.NewDecoder().String(f.Name); err == nil {
		return s
	}
	return f.Name
}

// decodeManifestText 清单文件文本解码(UTF-8 严格 → GBK 回退)。
func decodeManifestText(raw []byte) string {
	if utf8.Valid(raw) {
		return string(raw)
	}
	if s, err := simplifiedchinese.GBK.NewDecoder().Bytes(raw); err == nil {
		return string(s)
	}
	return string(raw)
}

// ExpandZip 安全展开 zip。isPackageRoot 判定采集包根目录名(映射表注入)。
func ExpandZip(zipPath, destDir string, isPackageRoot func(string) bool) (*Expanded, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("zip 打开失败: %w", err)
	}
	defer zr.Close()

	destReal, err := filepath.Abs(destDir)
	if err != nil {
		return nil, fmt.Errorf("展开目标路径解析失败: %w", err)
	}
	if err := os.MkdirAll(destReal, 0o755); err != nil {
		return nil, fmt.Errorf("展开目标目录创建失败: %w", err)
	}

	// 顶层组件统计(判包模式)
	topDirs := map[string]bool{}
	for _, f := range zr.File {
		name := decodeEntryName(f)
		comp := strings.Split(strings.Trim(name, "/"), "/")[0]
		if comp != "" {
			topDirs[comp] = true
		}
	}
	packageMode := false
	packageName := ""
	if len(topDirs) == 1 {
		for comp := range topDirs {
			if isPackageRoot(comp) {
				packageMode = true
				packageName = comp
			}
		}
	}

	exp := &Expanded{Mode: "files"}
	if packageMode {
		exp.Mode = "package"
		exp.PackageName = packageName
	}

	for _, f := range zr.File {
		name := decodeEntryName(f)
		if f.FileInfo().IsDir() {
			continue
		}
		// 防 zip slip:解出后的绝对路径必须落在目标目录内
		target := filepath.Join(destReal, filepath.FromSlash(name))
		targetAbs, err := filepath.Abs(target)
		if err != nil || targetAbs != destReal && !strings.HasPrefix(targetAbs, destReal+string(os.PathSeparator)) {
			return nil, fmt.Errorf("zip 条目越界(zip slip),整包拒绝: %q", name)
		}
		if !packageMode && strings.HasSuffix(strings.ToLower(name), ".zip") {
			exp.Skipped = append(exp.Skipped, name+"(嵌套压缩包不递归,跳过)")
			continue
		}
		if err := os.MkdirAll(filepath.Dir(targetAbs), 0o755); err != nil {
			return nil, fmt.Errorf("条目目录创建失败(%s): %w", name, err)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("条目打开失败(%s): %w", name, err)
		}
		out, err := os.Create(targetAbs)
		if err != nil {
			rc.Close()
			return nil, fmt.Errorf("条目写入失败(%s): %w", name, err)
		}
		h := sha256.New()
		size, err := io.Copy(io.MultiWriter(out, h), rc)
		rc.Close()
		if cerr := out.Close(); cerr != nil && err == nil {
			err = cerr
		}
		if err != nil {
			return nil, fmt.Errorf("条目解出失败(%s): %w", name, err)
		}
		exp.Files = append(exp.Files, ExpandedFile{
			Name: name, Path: targetAbs,
			SHA256: hex.EncodeToString(h.Sum(nil)), Size: size,
		})
	}

	if packageMode {
		exp.PackageRoot = filepath.Join(destReal, packageName)
		rep, err := VerifyManifest(exp.PackageRoot)
		if err != nil {
			return exp, err // 清单存在但不可读:如实上报,调用方判拒收
		}
		exp.Manifest = rep
	}
	return exp, nil
}

var manifestEntryRe = regexp.MustCompile(`^([0-9a-fA-F]{64})\s+(.+)$`)

// 清单头/噪声行(树庭 _NOISE_RE 同款纪律:已知噪声不计坏行)。
// Mode= 为档位声明行(默认档 DEFAULT_NO_HASH / 严格档无此行)。
var manifestNoiseRe = regexp.MustCompile(`^(Host=|Mode=|=+$|WinInfoSC|MANIFEST_ROOT_SHA256=)`)

// relativize 绝对路径 → 相对采集根(正斜杠);根名组件找不到 → 空串(坏行)。
func relativize(absPath, rootName string) string {
	parts := strings.FieldsFunc(strings.TrimSpace(absPath),
		func(r rune) bool { return r == '/' || r == '\\' })
	idx := -1
	for i, comp := range parts {
		if strings.EqualFold(comp, rootName) {
			idx = i
		}
	}
	if idx < 0 || idx == len(parts)-1 {
		return ""
	}
	return strings.Join(parts[idx+1:], "/")
}

// VerifyManifest 对账 <root>/_HASH_MANIFEST.txt(不存在 → Present=false)。
// 清单存在但不可读 → 错误(证据完整性无法对账,如实报,不静默放行)。
func VerifyManifest(root string) (*ManifestReport, error) {
	rep := &ManifestReport{}
	manifestPath := filepath.Join(root, "_HASH_MANIFEST.txt")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return rep, nil // 老包无清单:如实记 Present=false,不拦
		}
		return rep, fmt.Errorf("清单读取失败: %w", err)
	}
	rep.Present = true
	rootName := filepath.Base(root)

	entries := map[string]string{} // rel → sha256
	for _, line := range strings.Split(decodeManifestText(raw), "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "Mode=DEFAULT_NO_HASH" {
			// 默认档「采集时未哈希」声明:无条目可对账,如实记录放行
			rep.NoHash = true
			continue
		}
		m := manifestEntryRe.FindStringSubmatch(trimmed)
		if m == nil {
			// 默认档声明段的中/英说明行不计坏行(如实声明,非清单条目)
			if trimmed != "" && !rep.NoHash && !manifestNoiseRe.MatchString(trimmed) {
				rep.BadLines++
			}
			continue
		}
		rel := relativize(m[2], rootName)
		if rel == "" {
			rep.BadLines++
			continue
		}
		entries[rel] = strings.ToLower(m[1])
	}
	rep.Entries = len(entries)

	for rel, want := range entries {
		sum, _, err := ingest.HashFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			rep.Missing = append(rep.Missing, rel)
			continue
		}
		if sum != want {
			rep.Mismatch = append(rep.Mismatch, rel)
			continue
		}
		rep.OK++
	}
	// extra:盘上多出文件(清单生成后新增,如采集端足迹;如实计数不判负)
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if rel == "_HASH_MANIFEST.txt" {
			return nil
		}
		if _, listed := entries[rel]; !listed {
			rep.Extra++
		}
		return nil
	})
	sortStrings(rep.Missing)
	sortStrings(rep.Mismatch)
	return rep, nil
}

func sortStrings(ss []string) {
	for i := 0; i < len(ss); i++ {
		for j := i + 1; j < len(ss); j++ {
			if ss[j] < ss[i] {
				ss[i], ss[j] = ss[j], ss[i]
			}
		}
	}
}
