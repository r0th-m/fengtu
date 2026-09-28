// 派生去重闸(0.28.0-blackboard,黑板机制的机器侧一半):
//
// 实战验收暴露的问题:模板播种的意图与 AI 派生的意图语义重复(如「排查
// 计划任务持久化」vs「检查计划任务可疑项」),根因是 worker 看不到兄弟
// 分支在查什么。黑板(读侧,见 blackboard.go)让 worker 看得见;本闸在
// 写侧收口——AI 写回派生新意图时,与本案现存意图比对:
//
//   - 完全重复(归一化文本相同)→ 直接拦,转停车场(reason=dup_exact);
//   - 高度相似(关键词 Jaccard ≥ 0.85)→ 转停车场人裁(reason=
//     dup_similar),播报板播报「疑似重复,已入停车场」;
//   - 只闸 AI 派生(worker 写回路径 spawnChildren);人工手写意图/模板
//     播种不过闸(判断权归人,模板另有 template_key 幂等判重)。
//
// 保守优先:误拦代价低(进停车场人可捞回展开),放行代价是烧 token
// 重复排查。归一化/相似度是纯函数,不依赖 AI,零 token 消耗。
package intent

import (
	"strings"
	"unicode"
)

// 停车场转入原因(去重闸;019 迁移 CHECK 同口径)。
const (
	ParkReasonDupExact   = "dup_exact"   // 重复意图拦截(归一化完全相同)
	ParkReasonDupSimilar = "dup_similar" // 疑似重复(关键词 Jaccard 超阈),人裁
)

// DupJaccardThreshold 疑似重复阈值(关键词 Jaccard;保守档,宁拦勿放)。
const DupJaccardThreshold = 0.85

// DupVerdict 去重闸判定。
type DupVerdict int

const (
	DupNone    DupVerdict = iota // 放行:与现存意图不重复
	DupExact                     // 完全重复(归一化文本相同)
	DupSimilar                   // 高度相似(关键词 Jaccard ≥ 阈值)
)

// NormalizeIntentText 意图文本归一化(完全重复判据):小写 + 只留字母与
// 数字(标点/空白/符号全去)。中英文同口径(unicode 字母类)。
func NormalizeIntentText(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// IntentKeywords 意图关键词集(相似度判据):ASCII 字母数字词(≥2 字符,
// 单字符词噪声大不收)+ CJK 连续段的二字组(单字段收单字)。中文无空格
// 分词,二字组是零依赖的稳健近似;不追求语义,只拦「换皮重述」。
func IntentKeywords(s string) map[string]struct{} {
	out := map[string]struct{}{}
	s = strings.ToLower(s)
	var ascii strings.Builder
	var cjk []rune
	flushASCII := func() {
		if ascii.Len() >= 2 {
			out[ascii.String()] = struct{}{}
		}
		ascii.Reset()
	}
	flushCJK := func() {
		if len(cjk) == 1 {
			out[string(cjk[0])] = struct{}{}
		}
		for i := 0; i+1 < len(cjk); i++ {
			out[string(cjk[i:i+2])] = struct{}{}
		}
		cjk = cjk[:0]
	}
	for _, r := range s {
		switch {
		case r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r)):
			flushCJK()
			ascii.WriteRune(r)
		case unicode.Is(unicode.Han, r) || unicode.Is(unicode.Hiragana, r) ||
			unicode.Is(unicode.Katakana, r) || unicode.Is(unicode.Hangul, r):
			flushASCII()
			cjk = append(cjk, r)
		default: // 标点/空白/其他符号:分词边界
			flushASCII()
			flushCJK()
		}
	}
	flushASCII()
	flushCJK()
	return out
}

// KeywordJaccard 关键词集 Jaccard 相似度(|∩|/|∪|;双空集按 0,不比即不拦)。
func KeywordJaccard(a, b map[string]struct{}) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	inter := 0
	for k := range a {
		if _, ok := b[k]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

// CheckIntentDup 去重闸:候选意图文本 vs 本案现存意图(kind=intent 且非
// parked——parked 未展开不占比对,人裁展开时自然再进比对集)。返回判定、
// 最高相似度、命中节点(完全重复/最高相似的那条;DupNone 时 nil)。
func CheckIntentDup(text string, nodes []*Node) (DupVerdict, float64, *Node) {
	norm := NormalizeIntentText(text)
	if norm == "" {
		return DupNone, 0, nil
	}
	kw := IntentKeywords(text)
	best := 0.0
	var bestNode *Node
	for _, n := range nodes {
		if n.Kind != KindIntent || n.Status == StatusParked {
			continue
		}
		if NormalizeIntentText(n.Text) == norm {
			return DupExact, 1, n
		}
		if len(kw) == 0 {
			continue
		}
		if j := KeywordJaccard(kw, IntentKeywords(n.Text)); j > best {
			best = j
			bestNode = n
		}
	}
	if best >= DupJaccardThreshold && bestNode != nil {
		return DupSimilar, best, bestNode
	}
	return DupNone, best, nil
}
