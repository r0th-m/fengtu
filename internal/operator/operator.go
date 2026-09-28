// Package operator 适用域算子(DESIGN §6.1 算子三层模型的确定性执行层)。
//
// 纪律:
//   - 注册表是 YAML 数据:每个算子声明 applicable_to(log_types/
//     artifact_kinds);扫描按源品类路由——不匹配的源不实例化,
//     任务账如实记「按域跳过」;
//   - implemented: false 的算子只注册不实现,清单里如实标「未实现」;
//     implemented: true 但代码无实现的注册表是谎话,装载即拒;
//   - 命中 detail 直给原始统计量(df/频次/cv/次数/窗口),不包装置信度
//     数字(§6.2 第二面);证据等级(强疑似/疑似/弱信号)由系统按证据
//     结构算出(Evidence → Grade),不由算子自评;
//   - 算子对 spec 写,不写具体案件值:阈值/状态码语义/模式清单全部
//     走 YAML params,任何案件值进测试判负;
//   - 执行只读:事件只经 query 单一检索层流入,本包零 SQL。
package operator

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ye-mengwen/fengtu/internal/query"
)

// Family 算子族(适用域第一层)。
var Families = map[string]bool{"web": true, "host": true, "cross": true}

// Evidence 证据结构(系统按它算档位,§6.2 第三面)。
type Evidence struct {
	IndependentPoints int      `json:"independent_points"`   // 独立证据点数
	ChainLinked       bool     `json:"chain_linked"`         // 证据点间链咬合
	StatisticalOnly   bool     `json:"statistical_only"`     // 仅统计依据
	Exclusions        []string `json:"exclusions,omitempty"` // 排除项声明(弱信号必须)
}

// 证据等级三档(§6.2:强疑似/疑似/弱信号)。
const (
	GradeStrong  = "strong"  // 强疑似
	GradeSuspect = "suspect" // 疑似
	GradeWeak    = "weak"    // 弱信号
)

// Grade 按证据结构算档位:
//
//	仅统计依据 → 弱信号(且必须声明排除项,否则结构不成立);
//	≥2 独立证据点 + 链咬合 → 强疑似;
//	其余(单点+上下文)→ 疑似。
//
// 签名族规则不走这里——引擎侧默认「疑似」如实标。
func Grade(ev Evidence) (string, error) {
	if ev.StatisticalOnly {
		if len(ev.Exclusions) == 0 {
			return "", fmt.Errorf("弱信号结构不成立:统计依据必须声明排除项(§6.2)")
		}
		return GradeWeak, nil
	}
	if ev.IndependentPoints >= 2 && ev.ChainLinked {
		return GradeStrong, nil
	}
	return GradeSuspect, nil
}

// ApplicableTo 适用域声明。
type ApplicableTo struct {
	LogTypes      []string `yaml:"log_types" json:"log_types"`
	ArtifactKinds []string `yaml:"artifact_kinds" json:"artifact_kinds"`
}

// Spec 一条算子注册(YAML 数据的编译态)。
type Spec struct {
	ID          string         `yaml:"id" json:"id"`
	Title       string         `yaml:"title" json:"title"`
	Family      string         `yaml:"family" json:"family"`
	Severity    string         `yaml:"severity" json:"severity"`
	Applicable  ApplicableTo   `yaml:"applicable_to" json:"applicable_to"`
	Params      map[string]any `yaml:"params" json:"params,omitempty"`
	Implemented bool           `yaml:"implemented" json:"implemented"`
	Note        string         `yaml:"note" json:"note"`
	MaxHits     int            `yaml:"max_hits" json:"max_hits"`

	// ExcludeKBTokens params.exclude_kb 引用的排除清单 token(小写,
	// 子串包含语义对齐索图 rules.py load_kb);LoadDir 装载期解析落盘
	// 文件填入,缺失/坏文件装载即拒(不静默)。
	ExcludeKBTokens []string `yaml:"-" json:"-"`
}

// Source 一个按适用域路由后的目标源。
type Source struct {
	ID           string
	Kind         string // text | evtx
	LogType      string
	ArtifactType string
	Host         string // 主机键(一案多包;跨主机算子归并键,空=未建模)
}

// Finding 一条算子命中(锚定到单源单行;detail 直给原始统计量)。
type Finding struct {
	SourceID     string
	LineNo       int
	TS           *time.Time
	MatchedField string
	MatchedValue string
	Snippet      string
	Detail       map[string]any
	Evidence     Evidence
}

// StreamFunc 按源流式取事件(由调用方经 query 单一检索层提供)。
type StreamFunc func(sourceID string, fn func(query.Event) error) error

// Impl 一个算子的代码实现(对一组已按适用域匹配的源执行)。
type Impl interface {
	Run(spec *Spec, srcs []Source, stream StreamFunc) ([]Finding, error)
}

// impls 已实现的算子 id → 实现(注册表 implemented:true 必须落在这里)。
var impls = map[string]Impl{
	"web-bruteforce-chain":      bruteForceChain{},
	"web-sequence-chain":        sequenceChain{},
	"web-beacon-periodicity":    beaconPeriodicity{},
	"web-ip-rate-spike":         ipRateSpike{},
	"web-key-divergence":        keyDivergence{},
	"web-cross-key-same-value":  crossKeySameValue{},
	"web-outlier":               sizeOutlier{},
	"host-auth-chain":           authChain{},
	"host-persistence-task":     persistenceTask{},
	"host-service-install":      serviceInstall{},
	"host-process-tree":         processTreeAnomaly{},
	"host-time-cluster":         timeCluster{},
	"host-credential-face":      credentialFace{},
	"cross-entity-multi-source": crossEntityMultiSource{},
	"cross-host-entity":         crossHostEntity{},
}

// Registry 算子注册表。
type Registry struct {
	specs map[string]*Spec
	order []string
}

var opIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// opKeys 注册表允许的顶层键(未知键拒载,防写错字被静默吞)。
var opKeys = map[string]bool{
	"id": true, "title": true, "family": true, "severity": true,
	"applicable_to": true, "params": true, "implemented": true,
	"note": true, "max_hits": true,
}

// LoadDir 扫描目录装载全部算子;implemented:true 无代码实现一律拒载。
func LoadDir(dir string) (*Registry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("算子目录读取失败: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".yaml" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, fmt.Errorf("算子目录 %s 无注册(.yaml)", dir)
	}
	reg := &Registry{specs: map[string]*Spec{}}
	for _, name := range names {
		text, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("算子读取失败(%s): %w", name, err)
		}
		spec, err := compile(name, string(text))
		if err != nil {
			return nil, err
		}
		if _, dup := reg.specs[spec.ID]; dup {
			return nil, fmt.Errorf("算子 id 冲突: %q(%s)", spec.ID, name)
		}
		// exclude_kb 引用:装载期解析排除清单文件(<算子目录>/../excludes/
		// <name>.yaml),缺失/坏结构装载即拒(与索图 load_stat_rules 同纪律:
		// KB 损坏加载即暴露,不静默)。
		if err := resolveExcludeKB(spec, filepath.Join(filepath.Dir(dir), "excludes")); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		reg.specs[spec.ID] = spec
		reg.order = append(reg.order, spec.ID)
	}
	return reg, nil
}

var excludeKBNameRe = regexp.MustCompile(`^[a-z0-9_]+$`)

// resolveExcludeKB 解析 spec params 里的 exclude_kb 引用并把 token 填到
// spec.ExcludeKBTokens;无引用则不动。排除清单是与算子 YAML 并列的人可
// 编辑数据文件:{id?, title?, note?, tokens: 非空字符串列表}。
func resolveExcludeKB(spec *Spec, excludesDir string) error {
	v, ok := spec.Params["exclude_kb"]
	if !ok {
		return nil
	}
	name, ok := v.(string)
	if !ok || !excludeKBNameRe.MatchString(name) {
		return fmt.Errorf("算子 %s 参数 exclude_kb 须为小写字母/数字/下划线的清单名", spec.ID)
	}
	path := filepath.Join(excludesDir, name+".yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("算子 %s 引用的排除清单 %s 读取失败: %w(引用的清单必须落盘)", spec.ID, name, err)
	}
	var doc struct {
		Tokens []string `yaml:"tokens"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("排除清单 %s YAML 解析失败: %w", name, err)
	}
	if len(doc.Tokens) == 0 {
		return fmt.Errorf("排除清单 %s tokens 须为非空字符串列表", name)
	}
	for _, tk := range doc.Tokens {
		tk = strings.TrimSpace(strings.ToLower(tk))
		if tk == "" {
			return fmt.Errorf("排除清单 %s 含空 token", name)
		}
		spec.ExcludeKBTokens = append(spec.ExcludeKBTokens, tk)
	}
	return nil
}

func compile(srcName, text string) (*Spec, error) {
	var raw map[string]any
	if err := yaml.Unmarshal([]byte(text), &raw); err != nil {
		return nil, fmt.Errorf("%s: 算子 YAML 解析失败: %w", srcName, err)
	}
	for k := range raw {
		if !opKeys[k] {
			return nil, fmt.Errorf("%s: 未知键 %q(允许: id/title/family/severity/applicable_to/params/implemented/note/max_hits)", srcName, k)
		}
	}
	var spec Spec
	if err := yaml.Unmarshal([]byte(text), &spec); err != nil {
		return nil, fmt.Errorf("%s: 算子结构解析失败: %w", srcName, err)
	}
	if !opIDRe.MatchString(spec.ID) {
		return nil, fmt.Errorf("%s: id 必填且形如 ^[a-z0-9][a-z0-9-]{0,63}$", srcName)
	}
	if !Families[spec.Family] {
		return nil, fmt.Errorf("%s: family 须为 web|host|cross: %q", srcName, spec.Family)
	}
	switch spec.Severity {
	case "info", "low", "medium", "high":
	default:
		return nil, fmt.Errorf("%s: severity 须为 info|low|medium|high", srcName)
	}
	if spec.Implemented {
		if _, ok := impls[spec.ID]; !ok {
			return nil, fmt.Errorf("%s: 声明 implemented:true 但代码无实现(注册表不许说谎)", srcName)
		}
	}
	if spec.MaxHits < 0 {
		return nil, fmt.Errorf("%s: max_hits 须 ≥0", srcName)
	}
	return &spec, nil
}

// Specs 全部已注册算子(装载序;含未实现,清单如实标)。
func (r *Registry) Specs() []*Spec {
	out := make([]*Spec, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.specs[id])
	}
	return out
}

// Impl 取算子实现(未实现/未知 → nil,false)。
func (r *Registry) Impl(id string) (Impl, bool) {
	impl, ok := impls[id]
	return impl, ok
}

// Match 源是否落在算子适用域(log_types 或 artifact_kinds 任一命中;
// 两边都空 = 全域,仅 cross 族该这么写)。
func (s *Spec) Match(src Source) bool {
	for _, lt := range s.Applicable.LogTypes {
		if src.LogType != "" && lt == src.LogType {
			return true
		}
	}
	for _, ak := range s.Applicable.ArtifactKinds {
		if src.ArtifactType != "" && ak == src.ArtifactType {
			return true
		}
	}
	return len(s.Applicable.LogTypes) == 0 && len(s.Applicable.ArtifactKinds) == 0
}
