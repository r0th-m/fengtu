// playbook 意图模板(§6:playbook=预制的意图链模板,数据不是代码)。
// 模板 YAML 只含排查方法论(意图陈述+排查要点+派生关系),零具体案件值
// (防过拟合:案件上下文由 worker 工具返回,不进模板)。
package intent

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Template 一本 playbook 的意图链模板形态。
type Template struct {
	ID          string           `yaml:"id" json:"id"`
	Version     int              `yaml:"version" json:"version"`
	Title       string           `yaml:"title" json:"title"`
	Description string           `yaml:"description" json:"description"`
	OS          string           `yaml:"os" json:"os"`
	Goal        string           `yaml:"goal" json:"goal"` // goal 节点文本
	Intents     []TemplateIntent `yaml:"intents" json:"intents"`
}

// TemplateIntent 模板内一条意图(after=父意图 key,父完成才派生)。
type TemplateIntent struct {
	Key           string   `yaml:"key" json:"key"`
	Text          string   `yaml:"text" json:"text"`                   // 意图陈述(待验证的排查假设)
	Ask           string   `yaml:"ask" json:"ask"`                     // 排查要点(给 worker 的方法指引)
	Scope         string   `yaml:"scope" json:"scope"`                 // case|all(默认 case;all 过审批门)
	// HostScope 主机域(§3 修正稿):空=全案件;"each"=每台已建模主机各派
	// 一条(实例化时展开);"all"=显式全案件(等价空,如「横向移动」类);
	// 其余值=指定主机键。
	HostScope     string   `yaml:"host_scope" json:"host_scope,omitempty"`
	After         []string `yaml:"after" json:"after"`                 // 父意图 key 列表;空=根意图
	BudgetSeconds int      `yaml:"budget_seconds" json:"budget_seconds"` // 可选覆盖意图级预算
}

// LoadTemplatesDir 装载目录下全部模板(按文件名字典序;装载即校验)。
func LoadTemplatesDir(dir string) (map[string]*Template, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("模板目录读取失败: %w", err)
	}
	out := map[string]*Template{}
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
			return nil, fmt.Errorf("模板读取失败(%s): %w", name, err)
		}
		var t Template
		if err := yaml.Unmarshal(raw, &t); err != nil {
			return nil, fmt.Errorf("模板 YAML 解析失败(%s): %w", name, err)
		}
		if err := t.Validate(); err != nil {
			return nil, fmt.Errorf("模板校验失败(%s): %w", name, err)
		}
		if _, dup := out[t.ID]; dup {
			return nil, fmt.Errorf("模板 id 冲突(%s): %q", name, t.ID)
		}
		out[t.ID] = &t
	}
	return out, nil
}

// Validate 模板结构校验(key 唯一、after 引用存在、无环、深度 ≤MaxDepth)。
func (t *Template) Validate() error {
	if t.ID == "" || t.Goal == "" {
		return fmt.Errorf("模板 id/goal 必填")
	}
	if len(t.Intents) == 0 {
		return fmt.Errorf("模板至少一条意图")
	}
	byKey := map[string]*TemplateIntent{}
	for i := range t.Intents {
		ti := &t.Intents[i]
		if ti.Key == "" || ti.Text == "" {
			return fmt.Errorf("意图 key/text 必填(key=%q)", ti.Key)
		}
		if ti.Scope == "" {
			ti.Scope = ScopeCase
		}
		if ti.Scope != ScopeCase && ti.Scope != ScopeAll {
			return fmt.Errorf("意图 %s scope 非法: %q", ti.Key, ti.Scope)
		}
		if len(ti.HostScope) > 128 {
			return fmt.Errorf("意图 %s host_scope 过长(≤128 字符)", ti.Key)
		}
		if _, dup := byKey[ti.Key]; dup {
			return fmt.Errorf("意图 key 冲突: %q", ti.Key)
		}
		byKey[ti.Key] = ti
	}
	// 深度 = 最长 after 链(根=1);超 MaxDepth 或成环即拒装
	depthOf := map[string]int{}
	var depth func(key string, stack map[string]bool) (int, error)
	depth = func(key string, stack map[string]bool) (int, error) {
		if d, ok := depthOf[key]; ok {
			return d, nil
		}
		if stack[key] {
			return 0, fmt.Errorf("意图 after 成环: %s", key)
		}
		stack[key] = true
		ti := byKey[key]
		d := 1
		for _, p := range ti.After {
			if _, ok := byKey[p]; !ok {
				return 0, fmt.Errorf("意图 %s 的 after 引用未知 key: %q", key, p)
			}
			pd, err := depth(p, stack)
			if err != nil {
				return 0, err
			}
			if pd+1 > d {
				d = pd + 1
			}
		}
		delete(stack, key)
		depthOf[key] = d
		return d, nil
	}
	for k := range byKey {
		d, err := depth(k, map[string]bool{})
		if err != nil {
			return err
		}
		if d > MaxDepth {
			return fmt.Errorf("意图 %s 模板深度 %d 超上限(≤%d)", k, d, MaxDepth)
		}
	}
	return nil
}

// Roots 根意图(after 为空,装载序)。
func (t *Template) Roots() []*TemplateIntent {
	var out []*TemplateIntent
	for i := range t.Intents {
		if len(t.Intents[i].After) == 0 {
			out = append(out, &t.Intents[i])
		}
	}
	return out
}

// ChildrenOf 父 key 的直接子意图(声明序)。
func (t *Template) ChildrenOf(parentKey string) []*TemplateIntent {
	var out []*TemplateIntent
	for i := range t.Intents {
		for _, p := range t.Intents[i].After {
			if p == parentKey {
				out = append(out, &t.Intents[i])
				break
			}
		}
	}
	return out
}

// Find 按 key 取模板意图(nil=无)。
func (t *Template) Find(key string) *TemplateIntent {
	for i := range t.Intents {
		if t.Intents[i].Key == key {
			return &t.Intents[i]
		}
	}
	return nil
}
