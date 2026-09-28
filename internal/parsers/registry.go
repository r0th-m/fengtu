// registry hive 原生解析(M3):SYSTEM/SAM/NTUSER/DEFAULT 等 regf 容器 →
// 通用键值对事件流。
//
// 选型:Velocidex regparser(www.velocidex.com/golang/regparser,
// Apache-2.0,纯 Go 零 CGO,Velociraptor 生产同款——与 evtx 选
// Velocidex/evtx 同一生态纪律),调用收在 HiveParser 后面,换实现只动本文件。
//
// 语义边界(如实):
//   - 本解析器是**通用键值遍历**(键路径/值名/类型/数据/键 last-write),
//     树庭 Python 侧 registry_hive.py 的语义解码(SAM F/V、Shimcache
//     二进制、SECURITY 政策三件半)是更上层的专题提取,移植排后续切片
//     ——通用遍历产出的事件字段对 regf spec 写,金标准对拍用
//     dissect.regf(树庭同款底层库)通用遍历做参照;
//   - 值数据渲染契约(与 tools/parsers_golden.py 参照侧逐字节对齐):
//     REG_SZ/EXPAND_SZ → UTF-16LE 字符串(去尾 NUL);REG_MULTI_SZ →
//     字符串数组;REG_DWORD(LE/BE)/REG_QWORD → 无符号整数;
//     其余类型(含 REG_BINARY)→ "hex:" 前缀小写十六进制(超 512 字节
//     截断,尺寸留 data_size,截断标 data_truncated=true);
//   - 键 last-write 是原生 UTC(FILETIME)→ TsUTCDirect 直通;
//   - 防坏结构:访问过的键 offset 集合防环,深度上限 64,单键/单值读取
//     失败计 bad 不中断,全部计数入收尾 registry_hive_summary。
package parsers

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"www.velocidex.com/golang/regparser"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// 渲染/遍历上限(防坏结构死循环与超大值灌库,均如实计数)。
const (
	hiveMaxDepth     = 64
	hiveHexRenderCap = 512
)

// HiveParser regf hive 通用键值遍历解析器。
type HiveParser struct{}

// hiveStream 遍历态(全部遍历在 Records 内完成——regparser 的 Subkeys/Values
// 是即时求值,遍历时随走随取;记录先入缓冲,Next 逐条放出。
// hive 值量级(万级)缓冲可接受;真超大 hive 由逐值渲染上限护住单条尺寸)。
type hiveStream struct {
	f    *os.File
	recs []model.Record
	pos  int
}

// Records 打开 hive 并全量遍历(regf 魔数不符/打不开 → 文件级失败,如实)。
func (HiveParser) Records(path string) (Stream, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("hive 打开失败: %w", err)
	}
	hive, err := regparser.NewRegistry(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("非 regf 结构或损坏(%s): %w", path, err)
	}
	s := &hiveStream{f: f}
	s.walk(hive)
	return s, nil
}

// walk 深度优先遍历全部键,逐值产 registry_value 事件 + 收尾 summary。
func (s *hiveStream) walk(hive *regparser.Registry) {
	root := hive.OpenKey("")
	if root == nil {
		reason := "根键读取失败(hive 结构异常)"
		s.recs = append(s.recs, model.Record{LineNo: 1, Kind: model.KindBad,
			Reason: &reason, Raw: "<hive root>"})
		return
	}
	var keys, values, bad, decodeNoted int
	depthCapped, cycled := 0, 0
	visited := map[int64]bool{}

	type frame struct {
		key   *regparser.CM_KEY_NODE
		path  string
		depth int
	}
	stack := []frame{{key: root, path: "", depth: 0}}
	for len(stack) > 0 {
		fr := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		keys++
		if visited[fr.key.Offset] {
			cycled++ // 坏结构回指:跳过计数(零静默)
			continue
		}
		visited[fr.key.Offset] = true

		var lwUTC *time.Time
		lwISO := ""
		if lw := fr.key.LastWriteTime(); lw != nil && !lw.Time.IsZero() {
			t := lw.Time.UTC()
			lwUTC = &t
			lwISO = t.Format("2006-01-02T15:04:05Z")
		}
		for _, v := range fr.key.Values() {
			values++
			rec := hiveValueRecord(len(s.recs)+1, fr.path, v, lwISO, lwUTC)
			if rec.Kind == model.KindBad {
				bad++
			} else if _, has := rec.Norm["value_decode_note"]; has {
				decodeNoted++ // 类型化解码失败降级 hex 的值(如实计数)
			}
			s.recs = append(s.recs, rec)
		}
		if fr.depth >= hiveMaxDepth {
			if len(fr.key.Subkeys()) > 0 {
				depthCapped += len(fr.key.Subkeys())
			}
			continue
		}
		for _, sk := range fr.key.Subkeys() {
			name := hiveKeyName(sk)
			p := name
			if fr.path != "" {
				p = fr.path + "\\" + name
			}
			stack = append(stack, frame{key: sk, path: p, depth: fr.depth + 1})
		}
	}
	summary := map[string]any{
		"keys_visited": keys, "values_emitted": values, "bad_values": bad,
		"values_decode_noted": decodeNoted,
		"cycle_skipped_keys":  cycled, "depth_capped_subkeys": depthCapped,
		"max_depth": hiveMaxDepth,
		"note": "通用键值遍历(regf spec,Velocidex regparser 纯 Go);键 last-write " +
			"为原生 UTC 直通 ts;专题语义解码(SAM F/V、Shimcache 二进制、SECURITY " +
			"政策)是上层提取,排后续切片",
	}
	s.recs = append(s.recs, model.Record{
		LineNo: len(s.recs) + 1, Kind: model.KindEvent,
		Norm: map[string]any{"event_type": "registry_hive_summary",
			"summary": summary},
		Raw: "<registry_hive_summary>",
	})
}

// hiveKeyName 键名解码:KEY_COMP_NAME(0x20)= ASCII 直读,否则 UTF-16LE。
// regparser 的 Name() 不做这个区分(金标准对拍实测:非 ASCII 键名
// 被它按字节直读成乱码);_Name() 未导出,故取 Name() 的字节再按 spec 解码。
func hiveKeyName(k *regparser.CM_KEY_NODE) string {
	raw := k.Name()
	if k.Flags()&0x20 != 0 {
		return raw
	}
	return utf16le([]byte(raw))
}

// hiveValueName 值名解码:VALUE_COMP_NAME(0x01)= ASCII 直读,否则
// UTF-16LE(同 hiveKeyName 的 regf spec 纪律;regparser ValueName() 不分)。
func hiveValueName(v *regparser.CM_KEY_VALUE) string {
	raw := v.ValueName()
	if raw == "" {
		return "(Default)"
	}
	if v.Flags()&0x01 != 0 {
		return raw
	}
	return utf16le([]byte(raw))
}

// hiveValueRecord 一个值 → registry_value 事件;解码异常(DWORD 尺寸不符
// 等真机常态)降级 hex + value_decode_note 如实标(不丢行,计数入 summary)。
func hiveValueRecord(lineNo int, keyPath string, v *regparser.CM_KEY_VALUE,
	lwISO string, lwUTC *time.Time) model.Record {

	name := hiveValueName(v)
	vtype := v.TypeString()
	raw := fmt.Sprintf("%s\\%s", keyPath, name)

	norm := map[string]any{
		"event_type": "registry_value",
		"key_path":   keyPath,
		"value_name": name,
		"value_type": vtype,
		"data_size":  v.DataSize(),
	}
	if lwISO != "" {
		norm["key_last_write_utc"] = lwISO
	}
	vd := v.ValueData()
	if vd == nil {
		reason := "值数据读取失败(regparser 返回空)"
		return model.Record{LineNo: lineNo, Kind: model.KindBad, Reason: &reason,
			Raw: raw}
	}
	if vd.Error != nil {
		// 类型化解码失败(如 DWORD 声明 8 字节):原始字节 hex 留证 + 如实标
		b := vd.Data
		if sz := v.DataSize(); int64(len(b)) > sz {
			b = b[:sz]
		}
		if len(b) > hiveHexRenderCap {
			b = b[:hiveHexRenderCap]
			norm["data_truncated"] = true
		}
		norm["data"] = "hex:" + hex.EncodeToString(b)
		norm["value_decode_note"] = fmt.Sprintf(
			"按 %s 解码失败(%v),原始字节 hex 留证不猜", vtype, vd.Error)
		raw += " = " + norm["data"].(string)
	} else {
		data, truncated := renderHiveValue(vd, v.DataSize())
		norm["data"] = data
		if truncated {
			norm["data_truncated"] = true
		}
		raw += " = " + renderRawShort(data)
	}

	rec := model.Record{LineNo: lineNo, Kind: model.KindEvent, Norm: norm, Raw: raw}
	rec.TsUTCDirect = lwUTC // 键 last-write,UTC 原生直通(无则 nil 如实)
	return rec
}

// renderHiveValue 值数据按类型渲染(渲染契约见文件头;截断如实标)。
// 注意 regparser 的两个实现怪癖(金标准对拍实测挖出,按 dissect 语义纠):
//   - inline 值(DataLength 高位标记)恒读 4 字节,声明尺寸 <4 时多读出
//     的尾部要按 DataSize 截掉;
//   - REG_SZ 的 String 不去尾 NUL,渲染契约去尾(与 dissect 一致)。
func renderHiveValue(vd *regparser.ValueData, size int64) (any, bool) {
	switch vd.Type {
	case regparser.REG_SZ, regparser.REG_EXPAND_SZ:
		return strings.TrimRight(vd.String, "\x00"), false
	case regparser.REG_MULTI_SZ:
		out := vd.MultiSz
		if out == nil {
			out = []string{} // 空 MULTI_SZ 给空数组不给 null(契约稳定)
		}
		return out, false
	case regparser.REG_DWORD, regparser.REG_DWORD_BIG_ENDIAN, regparser.REG_QWORD:
		return vd.Uint64, false
	default:
		b := vd.Data
		if int64(len(b)) > size { // inline 多读截掉(见上)
			b = b[:size]
		}
		truncated := false
		if len(b) > hiveHexRenderCap {
			b = b[:hiveHexRenderCap]
			truncated = true
		}
		return "hex:" + hex.EncodeToString(b), truncated
	}
}

// renderRawShort raw 列的短呈现(截 200 rune,全量在 fields.data)。
func renderRawShort(data any) string {
	s := fmt.Sprintf("%v", data)
	r := []rune(s)
	if len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return s
}

func (s *hiveStream) Next() (model.Record, bool) {
	if s.pos >= len(s.recs) {
		return model.Record{}, false
	}
	rec := s.recs[s.pos]
	s.pos++
	return rec, true
}

func (s *hiveStream) Err() error { return nil }

func (s *hiveStream) Close() error { return s.f.Close() }
