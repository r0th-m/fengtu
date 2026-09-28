// Package kb 启发式知识库(0.19.0-heuristic-kb 起;0.20.0-case-kb 改为案件级
// 勾选;0.27.1-kb-simplify 起「全局启用」概念整体退役):应急排查 tradecraft
// 沉淀,回答「某个问题怎么找答案」,AI worker 在章节内自由调查时按「本案勾选」
// 注入参考(不再全量全局注入,prompt 变长每轮多付 token)。0.27.1 起:
// 注入 = 本案勾选(不再交集全局启用);kb_entries.enabled 列与 kb_builtin_state
// 表语义退役(存量数据原样保留,留待后续迁移清理,不再新建依赖);/system/kb
// 页纯管内容,启停只在建案/案内勾选。
//
// 铁律对位:
//   - 内容是数据:内置条目走 configs/kb/*.yaml(与 desc/rules/playbooks 同套
//     加载约定,启动装载即校验,坏文件拒启);用户条目走 PG kb_entries;
//   - 判断权归人:启发式不是证据也不是指令——注入措辞写死「是否采用由 AI
//     按当前证据判断,结论锚点仍只能锚采集物(source_id+line_no)」;
//   - 防过拟合:内置条目只写通用方法论(「怎么找」),严禁具体案件值;
//     内置条目内容不可改(人可另建用户条目沉淀)。
package kb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// 条目来源(与 API/注入段标徽同源)。
const (
	SourceBuiltin = "builtin"
	SourceUser    = "user"
)

// MaxInject 注入 worker system 的勾选条目上限(超出按更新时间截断,如实标注)。
const MaxInject = 20

// Entry 统一条目结构(内置 YAML 与用户 PG 行同一形态)。
type Entry struct {
	ID        string    `yaml:"id" json:"id"`
	Title     string    `yaml:"title" json:"title"`
	Content   string    `yaml:"content" json:"content"`
	AppliesTo []string  `yaml:"applies_to" json:"applies_to"`
	Source    string    `yaml:"-" json:"source"` // builtin|user(装载/落库时定)
	// Enabled 0.27.1 语义退役:不再参与注入与 API 呈现(注入=本案勾选);
	// 字段保留仅为承载存量数据(YAML enabled:false 解析 / kb_entries.enabled
	// 列扫描),JSON 不再输出,留待后续迁移清理。
	Enabled   bool      `yaml:"-" json:"-"`
	CreatedBy string    `yaml:"-" json:"created_by,omitempty"` // 用户条目记账(内置空)
	CreatedAt time.Time `yaml:"-" json:"created_at"`
	UpdatedAt time.Time `yaml:"-" json:"updated_at"`

	EnabledSet *bool `yaml:"enabled" json:"-"` // YAML 可显式 enabled:false(缺省=开)
}

// validate 条目结构校验(装载即校验;坏条目拒启,不带病上线)。
func validate(e *Entry) error {
	if strings.TrimSpace(e.ID) == "" {
		return fmt.Errorf("条目 id 必填")
	}
	if len(e.ID) > 128 {
		return fmt.Errorf("条目 %q id 过长(≤128 字符)", e.ID)
	}
	if strings.TrimSpace(e.Title) == "" {
		return fmt.Errorf("条目 %q title 必填", e.ID)
	}
	if utf8.RuneCountInString(e.Title) > 200 {
		return fmt.Errorf("条目 %q title 过长(≤200 字)", e.ID)
	}
	if strings.TrimSpace(e.Content) == "" {
		return fmt.Errorf("条目 %q content 必填", e.ID)
	}
	if utf8.RuneCountInString(e.Content) > 8000 {
		return fmt.Errorf("条目 %q content 过长(≤8000 字)", e.ID)
	}
	if len(e.AppliesTo) == 0 {
		return fmt.Errorf("条目 %q applies_to 至少一个场景标签", e.ID)
	}
	for _, t := range e.AppliesTo {
		if strings.TrimSpace(t) == "" || len(t) > 64 {
			return fmt.Errorf("条目 %q 场景标签非法: %q", e.ID, t)
		}
	}
	return nil
}

// LoadBuiltinDir 装载目录下全部内置条目(按文件名字典序;装载即校验)。
// 缺省 enabled=开(YAML 可显式 enabled:false 出厂即关);id 冲突拒装。
func LoadBuiltinDir(dir string) (map[string]*Entry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("知识库目录读取失败: %w", err)
	}
	out := map[string]*Entry{}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("知识库条目读取失败(%s): %w", name, err)
		}
		var e Entry
		if err := yaml.Unmarshal(raw, &e); err != nil {
			return nil, fmt.Errorf("知识库 YAML 解析失败(%s): %w", name, err)
		}
		if err := validate(&e); err != nil {
			return nil, fmt.Errorf("知识库条目校验失败(%s): %w", name, err)
		}
		if _, dup := out[e.ID]; dup {
			return nil, fmt.Errorf("知识库条目 id 冲突(%s): %q", name, e.ID)
		}
		e.Source = SourceBuiltin
		e.Enabled = e.EnabledSet == nil || *e.EnabledSet
		// 内置条目的「更新时间」= YAML 文件 mtime(内容是数据,如实;
		// 注入截断排序与 UI 呈现共用)。
		if fi, ferr := os.Stat(filepath.Join(dir, name)); ferr == nil {
			e.CreatedAt = fi.ModTime().UTC()
			e.UpdatedAt = fi.ModTime().UTC()
		}
		out[e.ID] = &e
	}
	return out, nil
}

// Store 用户条目 + 案件勾选的持久面(store.PG 实现;单测 fake)。
// 0.27.1:SetBuiltinKBState/ListBuiltinKBStates(kb_builtin_state 表)语义退役,
// 接口保留仅因 PG 实现/存量表暂不删,业务面不再调用,别再新建依赖。
type Store interface {
	// ListUserKB 用户条目清单(创建序)。
	ListUserKB(ctx context.Context) ([]*Entry, error)
	// CreateKB 用户条目落库(id/created_at/updated_at 回写)。
	CreateKB(ctx context.Context, e *Entry) error
	// UpdateKB 改用户条目(ok=false=无此条目)。
	UpdateKB(ctx context.Context, e *Entry) (bool, error)
	// DeleteKB 删用户条目(ok=false=无此条目;硬删,历史在审计链)。
	DeleteKB(ctx context.Context, id string) (bool, error)
	// SetBuiltinKBState 内置条目启用态覆写(upsert;enabled=false=禁用)。
	SetBuiltinKBState(ctx context.Context, id string, enabled bool) (time.Time, error)
	// ListBuiltinKBStates 内置条目禁用态清单(只列显式覆写过的)。
	ListBuiltinKBStates(ctx context.Context) (map[string]bool, error)
	// ListCaseKB 本案勾选的条目 id 集(0.20.0;无记录=空集,如实不注入)。
	ListCaseKB(ctx context.Context, caseID string) ([]string, error)
	// SetCaseKB 本案勾选集整体覆写(事务内清旧插新;返回勾选差集 added/removed,
	// 审计 kb.case_update 记账用)。
	SetCaseKB(ctx context.Context, caseID, actor string, ids []string) (added, removed []string, err error)
}

// Service 内置(YAML)+ 用户(PG)合一视图;内置禁用态存 PG 不删 YAML。
type Service struct {
	builtin map[string]*Entry
	store   Store
}

// NewService 装配(builtin 来自 LoadBuiltinDir;store 为 PG/fake)。
func NewService(builtin map[string]*Entry, st Store) *Service {
	return &Service{builtin: builtin, store: st}
}

// BuiltinCount 内置条目数(启动日志如实报)。
func (s *Service) BuiltinCount() int { return len(s.builtin) }

// Builtin 按 id 取内置条目(nil=无)。
func (s *Service) Builtin(id string) *Entry { return s.builtin[id] }

// List 合一清单(builtin 在前按 id 序,user 在后按创建序)。
// 0.27.1:不再叠 kb_builtin_state 覆写(enabled 语义退役,启用与否不再影响
// 任何消费面;存量覆写数据原样留在库里,不读不改)。
func (s *Service) List(ctx context.Context) ([]*Entry, error) {
	out := make([]*Entry, 0, len(s.builtin)+8)
	ids := make([]string, 0, len(s.builtin))
	for id := range s.builtin {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		cp := *s.builtin[id]
		out = append(out, &cp)
	}
	users, err := s.store.ListUserKB(ctx)
	if err != nil {
		return nil, fmt.Errorf("用户条目清单查询失败: %w", err)
	}
	for _, u := range users {
		u.Source = SourceUser
		out = append(out, u)
	}
	return out, nil
}

// Heuristics 全部条目池(按更新时间新→旧,不截断——截断是注入面的事,在
// HeuristicsForCase 交集之后做)。0.27.1:不再按 enabled 过滤(概念退役,
// 可选池=全部条目)。
func (s *Service) Heuristics(ctx context.Context) (entries []*Entry, err error) {
	all, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(all, func(i, j int) bool {
		return all[i].UpdatedAt.After(all[j].UpdatedAt)
	})
	return all, nil
}

// HeuristicsForCase AI 注入集(0.27.1-kb-simplify):本案勾选 ∩ 已知条目
// (builtin+user 全集,不再交集全局启用——enabled 语义退役),按更新时间
// 新→旧,超 MaxInject 截断。本案一条都没勾(含存量案件零勾选记录)= 空集,
// 如实不注入,不兜底全量。勾选里指向已删条目的死引用自然出局(交集已知集)。
func (s *Service) HeuristicsForCase(ctx context.Context, caseID string) (entries []*Entry, truncated int, err error) {
	sel, err := s.store.ListCaseKB(ctx, caseID)
	if err != nil {
		return nil, 0, fmt.Errorf("案件 KB 勾选查询失败: %w", err)
	}
	if len(sel) == 0 {
		return nil, 0, nil
	}
	en, err := s.Heuristics(ctx) // 全部条目池(未截断;截断在交集后做)
	if err != nil {
		return nil, 0, err
	}
	inSel := map[string]bool{}
	for _, id := range sel {
		inSel[id] = true
	}
	var out []*Entry
	for _, e := range en {
		if inSel[e.ID] {
			out = append(out, e)
		}
	}
	// truncated 如实=本案勾选但挤不进上限的条数
	if len(out) > MaxInject {
		return out[:MaxInject], len(out) - MaxInject, nil
	}
	return out, 0, nil
}

// CaseEntries 本案勾选的条目 id 集(web 案内管理/建案回显用)。
func (s *Service) CaseEntries(ctx context.Context, caseID string) ([]string, error) {
	return s.store.ListCaseKB(ctx, caseID)
}

// SetCaseEntries 本案勾选集整体覆写(人可增删,判断权归人):入参 id 必须是
// 已知条目(builtin 或 user),未知 id 拒写(400 由调用方映射);去重保序。
// 返回勾选差集(审计 kb.case_update 记账用)。勾选空集合法=本案不注入。
func (s *Service) SetCaseEntries(ctx context.Context, caseID, actor string, ids []string) (added, removed []string, err error) {
	all, err := s.List(ctx)
	if err != nil {
		return nil, nil, err
	}
	known := map[string]bool{}
	for _, e := range all {
		known[e.ID] = true
	}
	seen := map[string]bool{}
	clean := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		if !known[id] {
			return nil, nil, fmt.Errorf("未知知识库条目: %s", id)
		}
		seen[id] = true
		clean = append(clean, id)
	}
	return s.store.SetCaseKB(ctx, caseID, actor, clean)
}
