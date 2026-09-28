// Package review 待审区骨架(DESIGN §1「判断权归人」+ 索图 hits/scan_runs
// 语义移植):
//
//	扫描(规则引擎按 YAML spec 执行) → 命中候选(status 恒 pending)
//	→ 待审区 → 人裁决(accept/reject,留审计)。
//
// 纪律:
//   - 命中≠结论:一切机器产物是候选,hits 落库即 pending,detail 里
//     焊死声明文案;裁决是人,reviewed_by 锚真人;
//   - 规则是数据:YAML spec(id/title/severity/target/match/note/max_hits),
//     引擎按 spec 执行;match 语义:字段条件 AND、条件内值列表 OR、大小写
//     不敏感;键后缀 _contains=子串(裸键存量默认)、_prefix=前缀、
//     _eq=精确等值(后缀语义对齐树庭附录 A);去后缀后同一字段的多条件
//     之间取 OR(树庭同款),不同字段之间仍 AND;声明顺序保留(多字段
//     命中记第一个);
//   - 去重幂等:UNIQUE(source_id, line_no, rule_id),重跑 hits_new=0;
//   - 轮次:scan_runs.round_no 每案件递增, hits.round_no 记产出轮次;
//   - 预算帽:每规则每轮最多新增 max_hits 条(默认 500),超出如实记
//     truncated——防一条烂规则淹没待审区;
//   - 事件检索只走 query 单一检索层,本包零 SQL。
package review

import (
	"context"
	"errors"
	"time"

	"github.com/ye-mengwen/fengtu/internal/entity"
)

// Severity 允许值。
var severities = map[string]bool{"info": true, "low": true, "medium": true, "high": true}

// MatchFields 允许的匹配字段(对齐归一字段 + raw 整行兜底)。
//
// 0.22.0-treecourt-port 扩主机面(树庭附录 A 字段语义,对照表缺口的本质):
//   - web 面(存量):src_ip/user/method/path/query/status/referer/ua/xff;
//   - 主机统一面(树庭附录 A 语义):process_name/cmdline/parent_process/
//     image_path/target_path/reg_key/reg_value/task_name/service_name/
//     event_id/account/ip/domain/sha256/file_name——字段是规则可写的词表,
//     事件实际带不带该键由解析器决定(不带即该字段条件不成立,不猜);
//   - 丰图解析器现产出的主机字段(迁移规则实际锚的):event_type/channel/
//     computer/provider(evtx 原生)、exe_name(prefetch_exec)、key_path/
//     value_name/data(registry_value 等;evtx 的 data 是嵌套 EventData
//     对象,引擎侧串化后做子串匹配,见 engine.go fieldValue);
//   - raw 整行兜底。
var MatchFields = map[string]bool{
	// web 面(存量)
	"src_ip": true, "user": true, "method": true, "path": true,
	"query": true, "status": true, "referer": true, "ua": true,
	"xff": true, "raw": true,
	// 主机统一面(树庭附录 A 语义对齐)
	"process_name": true, "cmdline": true, "parent_process": true,
	"image_path": true, "target_path": true, "reg_key": true,
	"reg_value": true, "task_name": true, "service_name": true,
	"event_id": true, "account": true, "ip": true, "domain": true,
	"sha256": true, "file_name": true,
	// 丰图解析器现产出字段(evtx/prefetch/registry 原生键)
	"event_type": true, "channel": true, "computer": true, "provider": true,
	"exe_name": true, "key_path": true, "value_name": true, "data": true,
	// 0.25.0-datasource-unlock:PSHistory 命令历史(command,树庭附录 A
	// 锚字段;desc 双写 cmdline 见上)+ netstat 网络连接快照字段
	"command": true, "proto": true, "local_addr": true, "local_port": true,
	"remote_addr": true, "remote_port": true, "state": true, "pid": true,
	// 0.32.0-linuxsc:LinuxSC 采集包解析面(树庭 linux_* 规则迁移的锚字段;
	// 全部是解析器产出的事实字段,规则锚定才有意义,不锚不加):
	//   - 认证面:action(sshd accepted/failed/invalid_user/session_*)、
	//     unit(journal/syslog 单元=tag 同名语义)、source(源判别:
	//     auth_log 与 journal 双视角分流靠它,树庭靠 target=event_type,
	//     丰图 target 只有 any|entity,用源字段分流,语义等价如实注释);
	//   - 账户面:uid、empty_password(passwd 密码字段空串的派生标——
	//     引擎表达不了「等于空串」(子串须非空),解析器派生,如实);
	//   - 网络面:flags(conntrack [UNREPLIED] 等,空格串)、dport;
	//   - 持久化面:exec_start、has_exec、is_pam_exec、exports、risk_flags;
	//   - 文件/进程面:exe、name、type、nlink、path、kind(recovered_binary
	//     的 memfd|exe)、is_ioc(sshd 依赖 IOC 两档预筛直通)。
	"action": true, "unit": true, "source": true, "uid": true,
	"empty_password": true, "flags": true, "dport": true,
	"exec_start": true, "has_exec": true, "is_pam_exec": true,
	"exports": true, "risk_flags": true, "exe": true, "name": true,
	"type": true, "nlink": true, "kind": true, "is_ioc": true,
}

// EntityMatchFields target=entity 规则的匹配字段(实体表四列;
// 另有保留键 min_hosts——跨机聚合阈值,非标量字段条件)。
var EntityMatchFields = map[string]bool{
	"entity_type": true, "raw_value": true, "canonical_key": true,
	"qualifier": true,
}

// DefaultMaxHits 命中预算帽默认值(每规则每轮最多新增条数)。
const DefaultMaxHits = 500

// snippetMaxRunes 命中上下文截断长度。
const snippetMaxRunes = 240

// Disclaimer 焊死在每条候选 detail 里的判断权声明。
const Disclaimer = "命中≠结论:机器候选,判断权归人,需人工裁决"

// 比对算子(FieldMatch.Op 允许值)。
const (
	// OpContains 子串(大小写不敏感)——裸字段键的存量默认(索图子集语义)。
	MatchOpContains = "contains"
	// MatchOpPrefix 前缀(大小写不敏感),`_prefix` 后缀,对齐树庭附录 A。
	MatchOpPrefix = "prefix"
	// MatchOpEq 精确等值(大小写不敏感),`_eq` 后缀,对齐树庭裸键 eq 语义
	// (树庭裸键=eq;丰图裸键=contains 是存量兼容,差异如实注释)。
	MatchOpEq = "eq"
	// MatchOpEndsWith 尾匹配(大小写不敏感),`_endswith` 后缀,
	// 对齐树庭附录 A 同名算子(0.32.0-linuxsc)。
	MatchOpEndsWith = "endswith"
)

// FieldMatch 一个字段的匹配条件(声明顺序保留)。
type FieldMatch struct {
	Field string   `json:"field"` // 去后缀后的字段名
	Op    string   `json:"op"`    // contains|prefix|eq(见 MatchOp* 常量)
	Subs  []string `json:"subs"`  // 已预转小写
}

// Rule 一条签名规则(YAML 数据的编译态)。
type Rule struct {
	ID       string       `json:"id"`
	Title    string       `json:"title"`
	Severity string       `json:"severity"`
	Target   string       `json:"target"` // any | entity(0.25.0:实体层规则;web 等分类待 log_type 落地)
	Match    []FieldMatch `json:"match"`
	Note     string       `json:"note"`
	MaxHits  int          `json:"max_hits"`
	// MinHosts 跨机聚合阈值(target=entity 专属保留键,≥2;0=单机实体规则)。
	// 聚合只对 qualifier=global 的实体做(私网永不跨机,结构性闸)。
	MinHosts int `json:"min_hosts,omitempty"`
}

// Hit 一条候选命中。
type Hit struct {
	ID            string     `json:"id"`
	CaseID        string     `json:"case_id"`
	SourceID      string     `json:"source_id"`
	LineNo        int        `json:"line_no"`
	RuleID        string     `json:"rule_id"`
	Severity      string     `json:"severity"`
	MatchedField  string     `json:"matched_field"`
	MatchedValue  string     `json:"matched_value"`
	Snippet       string     `json:"snippet"`
	TsUTC         *time.Time `json:"ts_utc"`
	Status        string     `json:"status"`
	RoundNo       int        `json:"round_no"`
	EvidenceGrade string     `json:"evidence_grade"` // strong 强疑似|suspect 疑似|weak 弱信号(系统按证据结构算)
	DetailJSON    string     `json:"detail_json"`
	CreatedAt     time.Time  `json:"created_at"`
	ReviewedBy    string     `json:"reviewed_by,omitempty"`
	ReviewedAt    *time.Time `json:"reviewed_at,omitempty"`
	ReviewNote    string     `json:"review_note,omitempty"`
}

// ScanRun 一轮扫描台账。
type ScanRun struct {
	ID          string    `json:"id"`
	CaseID      string    `json:"case_id"`
	RoundNo     int       `json:"round_no"`
	RuleIDsJSON string    `json:"rule_ids_json"` // 空 = 全量
	Actor       string    `json:"actor"`
	SummaryJSON string    `json:"summary_json"`
	CreatedAt   time.Time `json:"created_at"`
}

// RuleSummary 单规则扫描账。
type RuleSummary struct {
	RuleID    string `json:"rule_id"`
	Scanned   int64  `json:"scanned"`   // 该规则条件流过的事件行数
	HitsNew   int    `json:"hits_new"`  // 本轮新增候选
	HitsDup   int    `json:"hits_dup"`  // 去重命中(此前已在待审区)
	Truncated int    `json:"truncated"` // 预算帽截断丢弃数
}

// OperatorSummary 单算子扫描账(适用域路由如实记:不匹配的源不实例化,
// 记「按域跳过」;未实现算子只注册不实例化,如实标)。
type OperatorSummary struct {
	OpID           string `json:"op_id"`
	Implemented    bool   `json:"implemented"`
	MatchedSources int    `json:"matched_sources"` // 适用域内实例化的源数
	SkippedDomain  int    `json:"skipped_domain"`  // 按域跳过的源数
	Findings       int    `json:"findings"`        // 算子产出命中数(落库前)
	HitsNew        int    `json:"hits_new"`
	HitsDup        int    `json:"hits_dup"`
	Truncated      int    `json:"truncated"`
	Note           string `json:"note,omitempty"`
}

// ScanSummary 一轮扫描总账。
type ScanSummary struct {
	RunID     string            `json:"run_id"`
	RoundNo   int               `json:"round_no"`
	Rules     []RuleSummary     `json:"rules"`
	Operators []OperatorSummary `json:"operators,omitempty"`
}

// ScanSource 扫描路由用的源投影(kind/log_type/artifact 决定适用域;
// host 供跨主机算子归并,切片七)。
type ScanSource struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	LogType      string `json:"log_type"`
	ArtifactType string `json:"artifact_type"`
	Host         string `json:"host"`
}

// RuleStat 一条规则/算子的裁决统计(近 90 天;接受率长期≈0 → 待复审)。
type RuleStat struct {
	RuleID         string   `json:"rule_id"`
	Candidates     int      `json:"candidates"` // 窗口内候选总数
	Accepted       int      `json:"accepted"`
	Rejected       int      `json:"rejected"`
	Pending        int      `json:"pending"`
	AcceptanceRate *float64 `json:"acceptance_rate"` // accepted/(accepted+rejected);无裁决为 null
	NeedsReview    bool     `json:"needs_review"`    // 裁决样本足够且接受率为 0 → 待复审退役闸
}

// NeedsReviewMinDecided 待复审闸的最小裁决样本(样本不足不判,防误杀新规则)。
const NeedsReviewMinDecided = 10

// HitFilter 待审区查询过滤。
type HitFilter struct {
	Status string // 空 = 全部;pending|accepted|rejected
	Round  int    // 0 = 全部轮次
	// SourceIDs 限定源集合(切片七,意图主机范围 worker 的 list_hits;
	// 空=不限)。
	SourceIDs []string
	Limit     int
	Offset    int
}

// Store 待审区存储(PG 实现在 internal/ingest/store)。
type Store interface {
	// CreateScanRun 开一轮(round = 该案 max+1,实现侧须事务内串行化)。
	CreateScanRun(ctx context.Context, caseID, actor, ruleIDsJSON string, now time.Time) (runID string, round int, err error)
	// InsertHit 落候选;inserted=false = 去重命中(唯一约束)。
	InsertHit(ctx context.Context, h Hit, now time.Time) (inserted bool, err error)
	FinishScanRun(ctx context.Context, runID, summaryJSON string) error
	ListHits(ctx context.Context, caseID string, f HitFilter) ([]Hit, error)
	GetHit(ctx context.Context, id string) (*Hit, error)
	// SetVerdict 人裁决(CAS:仅 status='pending' 的行可落库;
	// ok=false = 状态条件未命中——无此候选或已被他人裁决,区分由
	// 调用方回查行存在性,见 Engine.Verdict)。
	SetVerdict(ctx context.Context, id, actor, status, note string, now time.Time) (ok bool, err error)
	ListScanRuns(ctx context.Context, caseID string) ([]ScanRun, error)
	// ListSourcesForScan 适用域路由的源清单(kind text|evtx;raw 无事件不参与)。
	ListSourcesForScan(ctx context.Context, caseID string) ([]ScanSource, error)
	// RuleStatsRaw 按规则聚合窗口内候选/裁决计数(接受率与待复审闸在引擎算)。
	RuleStatsRaw(ctx context.Context, caseID string, since time.Time) ([]RuleStat, error)
}

// EntityLister 实体清单读取(target=entity 规则的扫描面;可选接口——
// Store 实现它即接入实体层,未实现时实体规则扫描如实报错,不静默跳过)。
type EntityLister interface {
	ListEntities(ctx context.Context, caseID string) ([]entity.Row, error)
}

// verdictStatuses 裁决终态(pending 是机器态,人只能给 accept/reject)。
var verdictStatuses = map[string]bool{"accepted": true, "rejected": true}

// ErrVerdictConflict 裁决冲突哨兵(M4 并发安全):裁决一次性——CAS 落空
// 且候选仍在 = 已被他人裁决,web 层映 409;errors.Is 可判。
// 行为变更(0.26.0-m4):此前对已 accepted/rejected 的候选再裁决是
// last-writer-wins 静默改判,现一律拒绝。
var ErrVerdictConflict = errors.New("该候选已被他人裁决")
