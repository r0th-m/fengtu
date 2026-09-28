// Prefetch(.pf)原生解析(M3):执行痕迹事件,语义逐字段移植树庭
// backend/app/parsers/prefetch.py(金标准基准;libscca《Windows Prefetch
// File (PF) format》spec)。
//
// 格式契约(file info 区自 0x54 起,以下均为文件绝对偏移):
//   - 文件头(全版本):0x00 版本(17/23/26/30/31)、0x04 "SCCA"、0x0C
//     文件大小、0x10 可执行名(UTF-16LE,60 字节)、0x4C 路径哈希;
//   - 0x58 引用文件数(file metrics 条目数,全版本);
//   - 运行次数/最近运行时间:V17 → 0x90 次数/0x78 单次 FILETIME;
//     V23 → 0x98/0x80;V26 → 0xD0/0x80 起 8 次;V30/V31 → 0xCC 非零则
//     次数在 0xC8 否则 0xD0(PECmd/Velociraptor 同款启发式),0x80 起 8 次;
//   - Win10+ 落盘 MAM 压缩:0x00 "MAM\x04" + 0x04 解压后大小 + 0x08 起
//     LZXPRESS-Huffman 单块;解压用 Velocidex go-prefetch 的纯 Go 实现
//     (Apache-2.0,零 CGO;不用其 Windows RtlDecompressBuffer 回调变体,
//     跨平台结果确定);
//   - 时间:FILETIME 原生 UTC → TsUTCDirect 直通(最近一次运行);
//   - 未知版本/解压失败/非 SCCA → 文件级如实 failed,不猜。
//
// 卷路径(volume_paths,本切片在树庭基准之上的补充,如实标注来源):
// go-prefetch 全结构解析(libscca spec)取 FilesAccessed 里的
// \VOLUME{...}\ 设备路径前缀去重;树庭 Python 基准不产此字段,
// golden 对拍只覆盖树庭字段集(见 tools/parsers_golden.py)。
package parsers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"

	pf "www.velocidex.com/golang/go-prefetch"

	"github.com/ye-mengwen/fengtu/internal/model"
)

var mamSig = []byte("MAM\x04")

// pfLayout 版本布局:运行次数偏移(0=V30/V31 启发式)/最近运行时间偏移/时间槽数。
type pfLayout struct {
	runOff   int
	timesOff int
	nSlots   int
}

var pfLayouts = map[uint32]pfLayout{
	17: {0x90, 0x78, 1},
	23: {0x98, 0x80, 1},
	26: {0xD0, 0x80, 8},
	30: {0, 0x80, 8}, // 0 = V30/V31 启发式(0xCC 非零 → 0xC8)
	31: {0, 0x80, 8},
}

const (
	pfMaxRunCount  = 10_000_000 // 计数合理性上限(超出视为结构错位)
	pfMaxMetrics   = 100_000
	pfMaxFileSize  = 64 << 20 // .pf 常态 ≤1MB;超限如实 failed(防垃圾内存)
	pfMamSizeSlack = 16       // MAM 声明大小与实测的对齐出入容忍(真机实测)
)

// PrefetchParser .pf 解析器(单文件单事件 + 收尾无,一文件一条记录)。
type PrefetchParser struct{}

// pfStream 单事件流(.pf 一文件一事,Next 一次后尽)。
type pfStream struct {
	rec  model.Record
	done bool
}

// Records 读取并解析 .pf(文件级失败如实:坏签名/未知版本/解压失败/截断)。
func (PrefetchParser) Records(path string) (Stream, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("pf 读取失败: %w", err)
	}
	if len(data) > pfMaxFileSize {
		return nil, fmt.Errorf("pf 尺寸 %d 超合理性上限 %d,不猜,如实 failed",
			len(data), pfMaxFileSize)
	}
	raw, compressed, note, err := pfDecompress(data)
	if err != nil {
		return nil, err
	}
	rec, err := pfParseRecord(raw, compressed, note)
	if err != nil {
		return nil, err
	}
	return &pfStream{rec: rec}, nil
}

// pfDecompress MAM 压缩壳 → SCCA 原始数据(树庭 _decompress 同语义)。
func pfDecompress(data []byte) (raw []byte, compressed bool, note string, err error) {
	if !bytes.HasPrefix(data, mamSig) {
		return data, false, "", nil
	}
	if len(data) < 8 {
		return nil, false, "", fmt.Errorf("MAM 头不足 8 字节(截断),如实 failed")
	}
	expected := int(binary.LittleEndian.Uint32(data[4:8]))
	out, derr := pf.LZXpressHuffmanDecompress(data[8:], expected)
	if derr != nil {
		return nil, false, "", fmt.Errorf(
			"MAM LZXPRESS-Huffman 解压失败(声明解压大小 %d): %v", expected, derr)
	}
	if len(out) < expected-pfMamSizeSlack {
		return nil, false, "", fmt.Errorf(
			"MAM 解压结果 %d 字节 << 声明 %d(截断/损坏),如实 failed",
			len(out), expected)
	}
	if len(out) != expected {
		note = fmt.Sprintf("MAM 声明解压大小 %d 与实测 %d 差 %d 字节"+
			"(对齐出入,SCCA 结构校验通过)", expected, len(out), len(out)-expected)
	}
	return out, true, note, nil
}

// pfParseRecord SCCA 数据 → 单条 prefetch_exec 事件(树庭 parse 同语义)。
func pfParseRecord(raw []byte, compressed bool, mamNote string) (model.Record, error) {
	if len(raw) < 0x54 || string(raw[4:8]) != "SCCA" {
		head := raw
		if len(head) > 8 {
			head = head[:8]
		}
		return model.Record{}, fmt.Errorf(
			"非 SCCA 结构(前 8 字节 %x,长度 %d),如实 failed", head, len(raw))
	}
	version := binary.LittleEndian.Uint32(raw[0:4])
	layout, ok := pfLayouts[version]
	if !ok {
		return model.Record{}, fmt.Errorf(
			"未支持的 Prefetch 版本 %d(已知 17/23/26/30/31),如实 failed 不猜", version)
	}

	name := strings.TrimSpace(cstr16(raw[0x10 : 0x10+60]))

	var runCount uint32
	if layout.runOff == 0 { // V30/V31:计数位置启发式
		if pfU32(raw, 0xCC) != 0 {
			runCount = pfU32(raw, 0xC8)
		} else {
			runCount = pfU32(raw, 0xD0)
		}
	} else {
		runCount = pfU32(raw, layout.runOff)
	}
	metricsCount := pfU32(raw, 0x58)
	declaredSize := pfU32(raw, 0x0C)

	var runTimes []time.Time
	for i := 0; i < layout.nSlots; i++ {
		off := layout.timesOff + i*8
		if off+8 > len(raw) {
			break
		}
		if t, ok := FiletimeToUTC(binary.LittleEndian.Uint64(raw[off:])); ok {
			runTimes = append(runTimes, t)
		}
	}

	var notes []string
	if mamNote != "" {
		notes = append(notes, mamNote)
	}
	var runCountOut any
	if runCount > pfMaxRunCount {
		notes = append(notes, fmt.Sprintf("运行次数字段异常(%d),不采信", runCount))
	} else {
		runCountOut = runCount
	}
	var metricsOut any
	if metricsCount > pfMaxMetrics {
		notes = append(notes, fmt.Sprintf("引用文件数字段异常(%d),不采信", metricsCount))
	} else {
		metricsOut = metricsCount
	}
	if declaredSize != 0 && absDiff(int(declaredSize), len(raw)) > 16 {
		notes = append(notes, fmt.Sprintf("头声明大小 %d 与实际 %d 不符",
			declaredSize, len(raw)))
	}
	if len(runTimes) == 0 {
		notes = append(notes, "无有效运行时间记录")
	}

	norm := map[string]any{
		"event_type":            "prefetch_exec",
		"exe_name":              name,
		"version":               version,
		"compressed":            compressed,
		"run_count":             runCountOut,
		"referenced_file_count": metricsOut,
	}
	if h := pfU32(raw, 0x4C); h != 0 {
		norm["prefetch_hash"] = fmt.Sprintf("%08X", h)
	}
	if len(runTimes) > 0 {
		norm["last_run_utc"] = runTimes[0].Format("2006-01-02T15:04:05Z")
		prev := []string{} // 树庭口径:空槽给 [] 不给 null
		for _, t := range runTimes[1:] {
			prev = append(prev, t.Format("2006-01-02T15:04:05Z"))
		}
		norm["previous_runs_utc"] = prev
	}

	// 卷路径(go-prefetch 全结构解析补充;失败不拖垮主字段,如实 note)
	vols, verr := pfVolumePaths(raw)
	if verr != nil {
		notes = append(notes, "卷路径补充解析失败(主字段不受影响): "+verr.Error())
	} else if len(vols) > 0 {
		norm["volume_paths"] = vols
	}

	if len(notes) > 0 {
		norm["parse_note"] = strings.Join(notes, ";") + "(如实标注,不猜)"
	}

	rec := model.Record{LineNo: 1, Kind: model.KindEvent, Norm: norm,
		Raw: "PREFETCH " + name}
	if len(runTimes) > 0 {
		rec.TsUTCDirect = &runTimes[0] // 最近一次运行,UTC 原生直通
	}
	return rec, nil
}

// pfVolumePaths 从 SCCA 数据提取卷设备路径前缀(go-prefetch 全结构解析;
// 树庭基准不产此字段,见文件头)。
func pfVolumePaths(raw []byte) ([]string, error) {
	info, err := pf.LoadPrefetch(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, fn := range info.FilesAccessed {
		up := strings.ToUpper(fn)
		if !strings.HasPrefix(up, `\VOLUME`) {
			continue
		}
		// 卷前缀 = 到第二个反斜杠(\VOLUME{guid}\...)
		rest := fn[1:]
		i := strings.IndexByte(rest, '\\')
		if i < 0 {
			continue
		}
		vol := fn[:i+1]
		if !seen[vol] {
			seen[vol] = true
			out = append(out, vol)
		}
	}
	return out, nil
}

func pfU32(b []byte, off int) uint32 {
	if off+4 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint32(b[off:])
}

func absDiff(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}

func (s *pfStream) Next() (model.Record, bool) {
	if s.done {
		return model.Record{}, false
	}
	s.done = true
	return s.rec, true
}

func (s *pfStream) Err() error   { return nil }
func (s *pfStream) Close() error { return nil }
