// 建案 KB 预勾选映射(0.30.0-report-ux 收口,原 0.20.0 起在前端
// taskWizard.KB_PRECHECK):应急类型 → applies_to 标签集;"*"=全勾哨兵。
//
// 单一数据源纪律:本表是唯一权威——前端新建向导经 GET /api/kb/precheck
// 取预勾选结果(不再自持映射表),API/脚本建案(POST /api/cases 不传
// kb_entries)也套本表。调映射只改本表,双端同时生效;前端若再长一张
// 本地表即违规(漂移由本表的单测 + web 契约测试焊死)。
//
// 语义与历史前端表逐字节等价(迁移对照,2026-09-26):
//   ransomware → execution/timeline/persistence/sample-recovery/entry-point
//   webshell   → execution/persistence
//   intrusion  → *(全勾)
//   data-leak  → persistence/timeline
//   other      → *(全勾)
package kb

// PrecheckAll 全勾哨兵(intrusion/other=全勾)。
const PrecheckAll = "*"

// PrecheckTags 应急类型 → 预勾选标签集(数据表,对 spec 写)。
var PrecheckTags = map[string][]string{
	"ransomware": {"execution", "timeline", "persistence", "sample-recovery", "entry-point"},
	"webshell":   {"execution", "persistence"},
	"intrusion":  {PrecheckAll},
	"data-leak":  {"persistence", "timeline"},
	"other":      {PrecheckAll},
}

// Preselect 按应急类型预勾选(返回条目 id 集):条目 applies_to 与该类型的
// 标签集有交集即勾,或映射为全勾;未知类型如实空集(不兜底全勾——判断权
// 归人,人手动勾)。保 entries 原序。
func Preselect(incidentType string, entries []*Entry) []string {
	rule, ok := PrecheckTags[incidentType]
	if !ok {
		return []string{}
	}
	all := len(rule) == 1 && rule[0] == PrecheckAll
	out := []string{}
	for _, e := range entries {
		if all {
			out = append(out, e.ID)
			continue
		}
		for _, t := range e.AppliesTo {
			match := false
			for _, r := range rule {
				if t == r {
					match = true
					break
				}
			}
			if match {
				out = append(out, e.ID)
				break
			}
		}
	}
	return out
}
