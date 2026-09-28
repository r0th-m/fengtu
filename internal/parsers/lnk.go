// .lnk 快捷方式原生解析(M3,MS-SHLLINK spec):语义逐字段移植树庭
// backend/app/parsers/jumplist.py 的 parse_lnk(金标准基准)。
//
// 格式契约(MS-SHLLINK):
//   - ShellLinkHeader 76 字节:签名+CLSID 固定 20 字节魔数,LinkFlags @0x14,
//     目标三时间 FILETIME @0x1C/0x24/0x2C(UTC 原生);
//   - 按 LinkFlags 跳 IDList(0x01),LinkInfo(0x02)取 LocalBasePath
//     (Unicode 优先,MBCS 兜底);StringData 按位取 Name/RelativePath/
//     WorkingDir/Arguments/IconLocation(IsUnicode 0x80 定宽窄);
//   - VolumeID(LinkInfo 内,VolumeIDAndLocalBasePath 0x01 时存在):
//     DriveType u32 @+4、DriveSerialNumber u32 @+8——**本切片在树庭基准
//     之上的补充**(MS-SHLLINK spec;树庭 parse_lnk 不产此两字段,
//     golden 对拍只覆盖树庭字段集);
//   - lnk 文件自身 mtime(最近打开时间)采集物不可得 → 快照型(ts 留 nil),
//     目标三时间进 fields 留证(树庭同款纪律,§9.3 不硬编时间轴);
//   - 结构不完整/签名不符 → bad 记录如实计数,不崩不猜。
package parsers

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// lnkMagic ShellLinkHeader 签名+CLSID(MS-SHLLINK 固定值)。
var lnkMagic = []byte{0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0,
	0xc0, 0, 0, 0, 0, 0, 0, 0x46}

// lnkDriveTypeLabels DriveType 枚举标签(MS-SHLLINK spec)。
var lnkDriveTypeLabels = map[uint32]string{
	0: "DRIVE_UNKNOWN", 1: "DRIVE_NO_ROOT_DIR", 2: "DRIVE_REMOVABLE",
	3: "DRIVE_FIXED", 4: "DRIVE_REMOTE", 5: "DRIVE_CDROM", 6: "DRIVE_RAMDISK",
}

// LnkParser .lnk 解析器(一文件一事件)。
type LnkParser struct{}

type lnkStream struct {
	rec  model.Record
	done bool
}

// lnkFields 解析结果(树庭字段 + VolumeID 补充)。
type lnkFields struct {
	target       string
	arguments    string
	workingDir   string
	createdFT    uint64
	modifiedFT   uint64
	accessedFT   uint64
	hasDriveType bool
	driveType    uint32
	volumeSerial uint32
}

// Records 读取并解析 .lnk(读取失败文件级如实;结构坏 → 流内 bad 记录)。
func (LnkParser) Records(path string) (Stream, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("lnk 读取失败: %w", err)
	}
	name := filepath.Base(path)
	f, err := parseLNK(data)
	if err != nil {
		reason := fmt.Sprintf("非 LNK 结构或截断: %v", err)
		return &lnkStream{rec: model.Record{LineNo: 1, Kind: model.KindBad,
			Reason: &reason, Raw: name}}, nil
	}
	norm := map[string]any{
		"event_type": "lnk_entry",
		"name":       name,
	}
	if f.target != "" {
		norm["target"] = f.target
	}
	if f.arguments != "" {
		norm["arguments"] = f.arguments
	}
	if f.workingDir != "" {
		norm["working_dir"] = f.workingDir
	}
	if s := FiletimeISO(f.createdFT); s != "" {
		norm["target_created"] = s
	}
	if s := FiletimeISO(f.modifiedFT); s != "" {
		norm["target_modified"] = s
	}
	if s := FiletimeISO(f.accessedFT); s != "" {
		norm["target_accessed"] = s
	}
	if f.hasDriveType {
		norm["drive_type"] = f.driveType
		norm["drive_type_label"] = lnkDriveTypeLabels[f.driveType]
		norm["volume_serial"] = fmt.Sprintf("%08X", f.volumeSerial)
	}
	norm["note"] = "lnk 自身 mtime(最近打开时间)采集物不可得,快照型 ts 留 nil;" +
		"目标三时间为 lnk 内 FILETIME(UTC);drive_type/volume_serial 为" +
		" MS-SHLLINK VolumeID 补充字段(树庭基准不产)"
	raw := name
	if f.target != "" {
		raw += " -> " + f.target
	}
	return &lnkStream{rec: model.Record{LineNo: 1, Kind: model.KindEvent,
		Norm: norm, Raw: raw}}, nil
}

// parseLNK LNK blob → 字段(树庭 parse_lnk 同语义;结构不完整返回错误)。
func parseLNK(d []byte) (*lnkFields, error) {
	if len(d) < 0x4C || !bytesHasPrefix(d, lnkMagic) {
		return nil, fmt.Errorf("签名/长度不符(前 %d 字节)", min(len(d), 0x4C))
	}
	flags := binary.LittleEndian.Uint32(d[0x14:])
	out := &lnkFields{
		createdFT:  binary.LittleEndian.Uint64(d[0x1C:]),
		modifiedFT: binary.LittleEndian.Uint64(d[0x24:]),
		accessedFT: binary.LittleEndian.Uint64(d[0x2C:]),
	}
	off := 0x4C
	if flags&0x01 != 0 { // HasLinkTargetIDList
		if off+2 > len(d) {
			return nil, fmt.Errorf("IDList 越界")
		}
		off += 2 + int(binary.LittleEndian.Uint16(d[off:]))
	}
	if flags&0x02 != 0 { // HasLinkInfo
		if off+0x1C > len(d) {
			return nil, fmt.Errorf("LinkInfo 越界")
		}
		liSize := int(binary.LittleEndian.Uint32(d[off:]))
		liHdr := int(binary.LittleEndian.Uint32(d[off+4:]))
		if liSize < 0x1C || off+liSize > len(d) {
			return nil, fmt.Errorf("LinkInfo 尺寸异常(%d)", liSize)
		}
		liFlags := binary.LittleEndian.Uint32(d[off+8:])
		if liFlags&0x01 != 0 { // VolumeIDAndLocalBasePath
			// VolumeID:DriveType/DriveSerialNumber(MS-SHLLINK 补充字段)
			if volOff := int(binary.LittleEndian.Uint32(d[off+0x0C:])); volOff > 0 &&
				volOff+0x0C <= liSize {
				out.hasDriveType = true
				out.driveType = binary.LittleEndian.Uint32(d[off+volOff+4:])
				out.volumeSerial = binary.LittleEndian.Uint32(d[off+volOff+8:])
			}
			if liHdr >= 0x24 { // Unicode 路径偏移可用
				if pOff := int(binary.LittleEndian.Uint32(d[off+0x1C:])); pOff > 0 &&
					pOff < liSize {
					out.target = cstr16(d[off+pOff : off+liSize])
				}
			}
			if out.target == "" {
				if pOff := int(binary.LittleEndian.Uint32(d[off+0x10:])); pOff > 0 &&
					pOff < liSize {
					out.target = cstrMBCS(d[off+pOff : off+liSize])
				}
			}
		}
		off += liSize
	}

	// StringData(Name/RelativePath/WorkingDir/Arguments/IconLocation)
	unicodeStr := flags&0x80 != 0 // IsUnicode
	for _, bit := range []struct {
		flag uint32
		key  int // 0=name 1=relative 2=working_dir 3=arguments 4=icon
	}{{0x04, 0}, {0x08, 1}, {0x10, 2}, {0x20, 3}, {0x40, 4}} {
		if flags&bit.flag == 0 {
			continue
		}
		if off+2 > len(d) {
			break
		}
		count := int(binary.LittleEndian.Uint16(d[off:]))
		off += 2
		n := count * 1
		if unicodeStr {
			n = count * 2
		}
		if off+n > len(d) {
			break
		}
		s := d[off : off+n]
		off += n
		var text string
		if unicodeStr {
			text = utf16le(s)
		} else {
			text = string(s) // MBCS 原样(树庭 mbcs decode;Go 侧字节直转,如实)
		}
		switch bit.key {
		case 2:
			out.workingDir = text
		case 3:
			out.arguments = text
		}
	}
	return out, nil
}

// cstrMBCS MBCS 字节串按首个 NUL 截断(树庭 mbcs decode 语义;
// 字节直转保持原值不猜编码——目标路径 ASCII 之外的字节如实留)。
func cstrMBCS(b []byte) string {
	if i := indexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func bytesHasPrefix(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := range prefix {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (s *lnkStream) Next() (model.Record, bool) {
	if s.done {
		return model.Record{}, false
	}
	s.done = true
	return s.rec, true
}

func (s *lnkStream) Err() error   { return nil }
func (s *lnkStream) Close() error { return nil }
