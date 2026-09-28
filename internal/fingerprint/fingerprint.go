// Package fingerprint 格式指纹判定(DESIGN §6.2 置信度第一面前验)。
//
// 语义(照 §6.2 + §6.3 拍板):
//   - 前验 = 抽样解析成功率 × 头行加权:候选解析器跑头部样本,
//     头区(前 HeadLines 条非 skip 行)按 HeadWeight 加权——头行往往
//     携带格式定义性结构(首行即格式门面),加权是声明的公式不是拍脑袋;
//   - ≥ AutoThreshold(0.9)→ 主链路自动按判定格式解析,判定结果与
//     置信度在源信息里可见可改(改判端点);< 0.9 → 该源挂「待确认」,
//     不阻塞其他源;
//   - 后验绊线(全量解析失败率 >5% → 判定降级存疑)在主链路侧落地
//     (需要全量解析账,不在本包);
//   - 候选集 = 内置格式(nginx_combined → web_access)+ desc 目录全部
//     描述文件(log_type 由 desc 可选声明,空 = 无品类)——候选是数据,
//     新增格式零代码。
package fingerprint

import (
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ye-mengwen/fengtu/internal/descform"
	"github.com/ye-mengwen/fengtu/internal/model"
)

const (
	// SampleLines 抽样行数(头部样本)。
	SampleLines = 200
	// HeadLines 头行加权区(前 N 条非 skip 行)。
	HeadLines = 20
	// HeadWeight 头区权重(其余行权重 1)。
	HeadWeight = 2
	// AutoThreshold 自动解析置信度门槛(DESIGN §6.2:≥0.9 自动过)。
	AutoThreshold = 0.9
	// PosteriorBadRate 后验绊线:全量解析失败率超过该值 → 判定降级存疑。
	PosteriorBadRate = 0.05
)

// ParseFunc 解析驱动(与 ingest.ParseFunc 同形,避免环依赖)。
type ParseFunc func(lines []string) iter.Seq[model.Record]

// Candidate 一个格式候选(数据,不是代码)。
type Candidate struct {
	FormatID string // builtin:<id> | desc:<name>
	LogType  string // 源品类(空 = 无品类)
	Encoding string
	Parse    ParseFunc
	// IsBlockStart 多行块起始判定(分块安全点;无多行格式恒 true)。
	IsBlockStart func(string) bool
}

func alwaysBlockStart(string) bool { return true }

// Result 指纹判定结果。
type Result struct {
	FormatID   string  `json:"format_id"`
	LogType    string  `json:"log_type"`
	Confidence float64 `json:"confidence"`
	Sampled    int     `json:"sampled"` // 参与判定的非 skip 行数
	Parsed     int     `json:"parsed"`  // 其中成 event 的行数
}

// LoadCandidates 装配候选集:内置 nginx_combined(最常用行式格式,序首)
// + descDir 全部 desc(文件名字典序,判定可复现)。
func LoadCandidates(descDir string) ([]Candidate, error) {
	cands := []Candidate{{
		FormatID:     "builtin:" + descform.NginxCombinedFormatID,
		LogType:      "web_access",
		Encoding:     "utf-8",
		Parse:        descform.ParseNginxCombined,
		IsBlockStart: alwaysBlockStart,
	}}
	entries, err := os.ReadDir(descDir)
	if err != nil {
		return nil, fmt.Errorf("desc 目录读取失败: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".yaml" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		text, err := os.ReadFile(filepath.Join(descDir, name))
		if err != nil {
			return nil, fmt.Errorf("desc 读取失败(%s): %w", name, err)
		}
		d, err := descform.CompileText(string(text))
		if err != nil {
			return nil, fmt.Errorf("desc 编译失败(%s): %w", name, err)
		}
		cands = append(cands, Candidate{
			FormatID: d.FormatID, LogType: d.LogType,
			Encoding: d.Encoding, Parse: d.Parse,
			IsBlockStart: d.IsBlockStart,
		})
	}
	return cands, nil
}

// FindCandidate 按 FormatID 找候选(改判端点校验用;无则 nil)。
func FindCandidate(cands []Candidate, formatID string) *Candidate {
	for i := range cands {
		if cands[i].FormatID == formatID {
			return &cands[i]
		}
	}
	return nil
}

// Detect 对样本(原始字节行,未解码)跑全部候选,返回置信度最高者;
// 无可判定候选(全部解析不了/样本空)返回 nil。
func Detect(sampleRawLines []string, cands []Candidate) *Result {
	var best *Result
	for _, cand := range cands {
		r := score(sampleRawLines, cand)
		if r == nil {
			continue
		}
		if best == nil || r.Confidence > best.Confidence {
			best = r
		}
	}
	return best
}

// score 单候选评分:按候选声明编码解码样本 → 解析 → 头行加权成功率。
// 解码失败/样本无有效行 → nil(该候选不适用,不算零分)。
func score(sampleRawLines []string, cand Candidate) *Result {
	text, err := descform.DecodeBytes(
		[]byte(strings.Join(sampleRawLines, "\n")), cand.Encoding)
	if err != nil {
		return nil
	}
	lines := descform.SplitLines(text)
	if len(lines) > SampleLines {
		lines = lines[:SampleLines]
	}
	headOK, headTotal, restOK, restTotal := 0, 0, 0, 0
	seen := 0
	for rec := range cand.Parse(lines) {
		if rec.Kind == model.KindSkip {
			continue // 空行/表头不参与判定(与摄入账 skip 同语义)
		}
		seen++
		ok := rec.Kind == model.KindEvent
		if seen <= HeadLines {
			headTotal++
			if ok {
				headOK++
			}
		} else {
			restTotal++
			if ok {
				restOK++
			}
		}
	}
	total := headTotal + restTotal
	if total == 0 {
		return nil
	}
	conf := float64(HeadWeight*headOK+restOK) / float64(HeadWeight*headTotal+restTotal)
	return &Result{
		FormatID: cand.FormatID, LogType: cand.LogType,
		Confidence: conf, Sampled: total, Parsed: headOK + restOK,
	}
}
