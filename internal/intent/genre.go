// fact 体裁契约(M3,用户实测发现后立):worker 写回 fact 的 summary 必须
//
//	① 中文(引用日志原文/命令行除外——引用块不豁免「通篇英文」,
//	   合规结论必然带汉字,零汉字即违规);
//	② 只写「结论+锚点」,禁止过程叙述开头("我将/我先/I'll/I will/
//	   Let me" 类一律不合规)。
//
// 不合规 → 系统按现有契约校验器同档处理:降级 doubt 并如实记录
// (close_note + 过程流 + 审计),与「无锚点 supported 降级」并列。
package intent

import (
	"strings"
	"unicode"
)

// 过程叙述开头词表(开头即违规;小写比较,英文前缀含撇号变体)。
// 对 spec 写:表是数据,增删改本表即可,判定逻辑不动。
var genreProcessPrefixes = []string{
	// 中文过程叙述
	"我将", "我先", "我会", "我需要", "我打算", "我现在", "让我", "接下来我",
	"首先我", "下面我", "现在开始", "首先,我", "首先,让",
	// 英文过程叙述(小写比较)
	"i'll", "i will", "i am going", "i'm going", "let me", "let's",
	"i need to", "i have to", "first i", "first, i", "first, let",
	"now i", "next i", "i'd like", "i shall", "i start", "i will start",
	"to begin", "my plan", "step 1", "step1",
}

// factGenreViolation 体裁校验:返回违规原因(空串 = 合规)。
// 判据与例外(如实):
//   - 零汉字即违规——「引用日志原文/命令行除外」豁免的是引用内容,
//     不是整段;合规的「结论+锚点」必然有汉字结论;
//   - 过程叙述只查开头(修剪空白/引用符号后):开头即过程腔 = 在写过程
//     不在写结论;结论后面追述过程不由本闸拦(语义判断留给裁决人)。
func factGenreViolation(summary string) string {
	s := strings.TrimSpace(summary)
	if s == "" {
		return "" // 空 summary 由调用方既有逻辑处理,体裁闸不管
	}
	// ② 过程叙述开头(修剪常见引用/强调符号后比前缀)
	lead := strings.ToLower(strings.TrimLeft(s, "\"'`>*# 　"))
	for _, p := range genreProcessPrefixes {
		if strings.HasPrefix(lead, p) {
			return "过程叙述开头(命中前缀 " + p + "):fact 只写结论+锚点"
		}
	}
	// ① 中文要求:整段零汉字即违规
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return ""
		}
	}
	return "通篇无汉字:fact 必须中文(引用日志原文/命令行不免除结论的中文要求)"
}
