// Package query 单一检索层(DESIGN §4.2 纪律:一切事件检索走这一层,
// 永远只读——只产出 SELECT,CH 侧会话叠加只读约束)。
//
// 语义:
//   - q:全文词,对 raw 行做大小写不敏感子串匹配(全文秒级靠列存扫描,
//     3000 万行台架实测秒级);
//   - 字段条件 cond:fields JSON 内指定键,eq(精确)或 contains(包含,
//     大小写不敏感);字段名白名单校验防注入,值全部参数化;
//   - 时间窗 ts_from/ts_to 作用于 ts;无时区源 ts 为 NULL,SQL 比较
//     天然滤除——「无时区源如实不参与时间过滤」不靠特判,是语义本身;
//   - 行号锚点:每条结果带 source_id+line_no,回查原文由 vault 按
//     sources.sha256 定位(web 层组合);
//   - 结果不排序:按主键读取序(case_id, source_id, line_no)返回——
//     全库 ORDER BY ts 要排 3000 万行,亚秒预算内不做;ts 排序留给
//     后续热点列物化切片(如实标注)。
package query

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// CondOp 字段条件算子。
type CondOp string

const (
	OpEq       CondOp = "eq"       // 精确
	OpContains CondOp = "contains" // 包含(大小写不敏感)
)

// FieldCond 一条字段条件(多个条件 AND;Values 多值时字段内 OR——
// 检索 API 恒单值,规则引擎的「子串列表 OR」同语义下推 SQL)。
type FieldCond struct {
	Field  string
	Op     CondOp
	Values []string
}

// Params 检索参数。
type Params struct {
	CaseID   string
	Q        string      // 全文词(raw 子串,大小写不敏感)
	Conds    []FieldCond // 字段条件 AND
	TSFrom   *time.Time  // 时间窗(作用于 ts;NULL ts 源不参与,见包注释)
	TSTo     *time.Time
	SourceID string   // 可选:限定单源
	// SourceIDs 可选:限定源集合(切片七,意图主机范围:worker 会话按
	// 主机解析出的源 id 集;空=不限)。与 SourceID 并存时两者皆生效(AND)。
	SourceIDs []string
	Limit     int // 0 → 默认 100;上限 1000
	Offset    int
}

// Event 一行检索结果(含行号锚点)。
type Event struct {
	SourceID string     `json:"source_id"`
	LineNo   int        `json:"line_no"`
	TS       *time.Time `json:"ts"`
	Kind     string     `json:"kind"`
	Fields   string     `json:"fields"`
	Raw      string     `json:"raw"`
}

const (
	defaultLimit = 100
	maxLimit     = 1000
)

var fieldNameRe = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

func writePlaceholders(b *strings.Builder, n int) {
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("?")
	}
}

func anyStrings(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// maxSourceIDs 源集合限定的最大规模(单主机源数实测 <1000;上限是保险丝)。
const maxSourceIDs = 5000

// validate 参数校验(字段名白名单防注入;值一律走参数绑定)。
func (p *Params) validate() error {
	if p.CaseID == "" {
		return fmt.Errorf("case_id 必填")
	}
	if len(p.SourceIDs) > maxSourceIDs {
		return fmt.Errorf("源集合限定过大(≤%d 个): %d", maxSourceIDs, len(p.SourceIDs))
	}
	for _, sid := range p.SourceIDs {
		if sid == "" {
			return fmt.Errorf("源集合限定含空 source_id")
		}
	}
	for _, c := range p.Conds {
		if !fieldNameRe.MatchString(c.Field) {
			return fmt.Errorf("字段名非法(允许 [a-z0-9_]≤64): %q", c.Field)
		}
		switch c.Op {
		case OpEq, OpContains:
		default:
			return fmt.Errorf("未知算子: %q(允许 eq|contains)", c.Op)
		}
		if len(c.Values) == 0 {
			return fmt.Errorf("字段 %q 条件值为空", c.Field)
		}
		for _, v := range c.Values {
			if v == "" {
				return fmt.Errorf("字段 %q 条件值为空", c.Field)
			}
		}
	}
	if p.TSFrom != nil && p.TSTo != nil && p.TSFrom.After(*p.TSTo) {
		return fmt.Errorf("时间窗非法: ts_from 晚于 ts_to")
	}
	if p.Offset < 0 {
		return fmt.Errorf("offset 须 ≥0")
	}
	if p.Limit < 0 {
		return fmt.Errorf("limit 须 ≥0")
	}
	return nil
}

func (p *Params) limitOrDefault() int {
	if p.Limit <= 0 || p.Limit > maxLimit {
		if p.Limit > maxLimit {
			return maxLimit
		}
		return defaultLimit
	}
	return p.Limit
}

// whereClauses 生成 WHERE 片段与参数(检索与扫描共用)。
// kindFilter 空串 = 不过滤 kind;否则 kind = 该值(扫描只扫 event)。
func whereClauses(p Params, kindFilter string) (string, []any) {
	var args []any
	var b strings.Builder
	b.WriteString("case_id = ?")
	args = append(args, p.CaseID)
	if kindFilter != "" {
		b.WriteString(" AND kind = ?")
		args = append(args, kindFilter)
	}
	if p.SourceID != "" {
		b.WriteString(" AND source_id = ?")
		args = append(args, p.SourceID)
	}
	if len(p.SourceIDs) > 0 {
		b.WriteString(" AND source_id IN (")
		writePlaceholders(&b, len(p.SourceIDs))
		b.WriteString(")")
		args = append(args, anyStrings(p.SourceIDs)...)
	}
	if p.Q != "" {
		b.WriteString(" AND positionCaseInsensitive(raw, ?) > 0")
		args = append(args, p.Q)
	}
	for _, c := range p.Conds {
		if c.Field == "raw" {
			if c.Op == OpEq {
				if len(c.Values) == 1 {
					b.WriteString(" AND raw = ?")
				} else {
					b.WriteString(" AND raw IN (")
					writePlaceholders(&b, len(c.Values))
					b.WriteString(")")
				}
			} else {
				b.WriteString(" AND (")
				for i := range c.Values {
					if i > 0 {
						b.WriteString(" OR ")
					}
					b.WriteString("positionCaseInsensitive(raw, ?) > 0")
				}
				b.WriteString(")")
			}
			args = append(args, anyStrings(c.Values)...)
			continue
		}
		// 字段名过白名单后仍走参数绑定(JSONExtractString 第二参可参数化)
		if c.Op == OpEq {
			if len(c.Values) == 1 {
				b.WriteString(" AND JSONExtractString(fields, ?) = ?")
			} else {
				b.WriteString(" AND JSONExtractString(fields, ?) IN (")
				writePlaceholders(&b, len(c.Values))
				b.WriteString(")")
			}
			args = append(args, c.Field)
			args = append(args, anyStrings(c.Values)...)
		} else {
			b.WriteString(" AND (")
			for i, v := range c.Values {
				if i > 0 {
					b.WriteString(" OR ")
				}
				b.WriteString("positionCaseInsensitive(JSONExtractString(fields, ?), ?) > 0")
				// 每个 OR 分支一对(字段名, 值),与占位符一一对应
				args = append(args, c.Field, v)
			}
			b.WriteString(")")
		}
	}
	if p.TSFrom != nil {
		b.WriteString(" AND ts >= ?")
		args = append(args, p.TSFrom.UTC())
	}
	if p.TSTo != nil {
		b.WriteString(" AND ts <= ?")
		args = append(args, p.TSTo.UTC())
	}
	return b.String(), args
}

const selectCols = "SELECT source_id, line_no, ts, kind, fields, raw FROM fengtu.events"

// BuildSearchSQL 检索 SQL(只读 SELECT;主键序返回,不排序,见包注释)。
func BuildSearchSQL(p Params) (string, []any, error) {
	if err := p.validate(); err != nil {
		return "", nil, err
	}
	where, args := whereClauses(p, "")
	var b strings.Builder
	b.WriteString(selectCols)
	b.WriteString(" WHERE ")
	b.WriteString(where)
	b.WriteString(" ORDER BY source_id, line_no LIMIT ? OFFSET ?")
	args = append(args, p.limitOrDefault(), p.Offset)
	return b.String(), args, nil
}

// BuildScanSQL 扫描 SQL(规则引擎用:kind='event' 全量流式,无分页)。
func BuildScanSQL(p Params) (string, []any, error) {
	if err := p.validate(); err != nil {
		return "", nil, err
	}
	where, args := whereClauses(p, "event")
	var b strings.Builder
	b.WriteString(selectCols)
	b.WriteString(" WHERE ")
	b.WriteString(where)
	b.WriteString(" ORDER BY source_id, line_no")
	return b.String(), args, nil
}

// Querier 事件检索执行器(只读;store.CH 实现,单测 fake)。
type Querier interface {
	QueryEvents(ctx context.Context, sql string, args ...any) ([]Event, error)
	// StreamEvents 流式扫描(规则引擎扫全量,不驻留内存)。
	StreamEvents(ctx context.Context, sql string, args []any, fn func(Event) error) error
}

// Service 检索服务。
type Service struct {
	q Querier
}

// NewService 构造。
func NewService(q Querier) *Service { return &Service{q: q} }

// Search 检索(只读)。
func (s *Service) Search(ctx context.Context, p Params) ([]Event, error) {
	sql, args, err := BuildSearchSQL(p)
	if err != nil {
		return nil, err
	}
	return s.q.QueryEvents(ctx, sql, args...)
}

// StreamMatch 规则扫描流(只读;fn 返回错误即中止,如实上报)。
func (s *Service) StreamMatch(ctx context.Context, p Params, fn func(Event) error) error {
	sql, args, err := BuildScanSQL(p)
	if err != nil {
		return err
	}
	return s.q.StreamEvents(ctx, sql, args, fn)
}
