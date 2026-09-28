// 规则 YAML 装载与校验(解析器对 spec 写:规则是数据,引擎按 spec 执行;
// 语义照索图签名规则子集——字段条件 AND、字段内子串 OR、大小写不敏感、
// 声明顺序保留;未知键一律报错,防规则写错字被静默吞掉)。
package review

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var ruleIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

var ruleKeys = map[string]bool{
	"id": true, "title": true, "severity": true, "target": true,
	"match": true, "note": true, "max_hits": true,
}

// splitFieldKey match 键 → (去后缀字段名, 比对算子)。
// 后缀语义对齐树庭附录 A:_contains=子串、_prefix=前缀、_eq=精确等值、
// _endswith=尾匹配(0.32.0-linuxsc 补:树庭 linux-exfil-shmtmp-archive 的
// name_endswith 依赖它——压缩包扩展名类判定尾匹配才准,contains 会把
// "x.zip.log" 误命中)(均大小写不敏感);裸键 = contains(索图子集存量语义,不变)。
func splitFieldKey(key string) (field, op string) {
	for _, s := range []struct {
		suffix string
		op     string
	}{
		{"_contains", MatchOpContains},
		{"_prefix", MatchOpPrefix},
		{"_endswith", MatchOpEndsWith},
		{"_eq", MatchOpEq},
	} {
		if strings.HasSuffix(key, s.suffix) {
			return key[:len(key)-len(s.suffix)], s.op
		}
	}
	return key, MatchOpContains
}

// CompileRule 编译一条规则 YAML(严格校验,错一处拒载)。
func CompileRule(srcName, text string) (*Rule, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, fmt.Errorf("%s: 规则 YAML 解析失败: %w", srcName, err)
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: 规则须为 YAML 映射", srcName)
	}
	root := doc.Content[0]

	scalar := func(key string) (string, bool) {
		for i := 0; i+1 < len(root.Content); i += 2 {
			if root.Content[i].Value == key {
				if root.Content[i+1].Kind != yaml.ScalarNode {
					return "", false
				}
				return root.Content[i+1].Value, true
			}
		}
		return "", false
	}
	node := func(key string) *yaml.Node {
		for i := 0; i+1 < len(root.Content); i += 2 {
			if root.Content[i].Value == key {
				return root.Content[i+1]
			}
		}
		return nil
	}

	var errs []string
	for i := 0; i+1 < len(root.Content); i += 2 {
		if !ruleKeys[root.Content[i].Value] {
			errs = append(errs, fmt.Sprintf("未知键 %q(允许: id/title/severity/target/match/note/max_hits)", root.Content[i].Value))
		}
	}

	r := &Rule{MaxHits: DefaultMaxHits}
	id, ok := scalar("id")
	if !ok || !ruleIDRe.MatchString(id) {
		errs = append(errs, "id 必填且形如 ^[a-z0-9][a-z0-9-]{0,63}$")
	}
	r.ID = id
	title, ok := scalar("title")
	if !ok || strings.TrimSpace(title) == "" {
		errs = append(errs, "title 必填")
	}
	r.Title = strings.TrimSpace(title)
	sev, ok := scalar("severity")
	if !ok || !severities[sev] {
		errs = append(errs, "severity 须为 info|low|medium|high 之一")
	}
	r.Severity = sev
	target, ok := scalar("target")
	if !ok {
		errs = append(errs, "target 必填")
	} else if target != "any" && target != "entity" {
		// entity = 实体层规则(0.25.0);web 等源分类依赖 log_type 落地;
		// 不支持即拒载,不静默忽略(不猜)
		errs = append(errs, fmt.Sprintf("target %q 未实现(仅 any|entity;源分类待 log_type 落地)", target))
	}
	r.Target = target
	if note, ok := scalar("note"); ok {
		r.Note = note
	}
	if mh, ok := scalar("max_hits"); ok {
		var n int
		if _, err := fmt.Sscanf(mh, "%d", &n); err != nil || n <= 0 {
			errs = append(errs, "max_hits 须为正整数")
		} else {
			r.MaxHits = n
		}
	}

	// match:映射,保序遍历(声明顺序 = 多字段命中记录顺序)。
	// 键 = 字段名[+_contains|+_prefix|+_eq];去后缀后同一字段允许多个条件
	// (条件间 OR,树庭附录 A 同款),不同字段之间 AND。
	//
	// target=entity(0.25.0 实体层):匹配字段限 EntityMatchFields(实体表
	// 四列),裸键语义对齐树庭附录 A = eq(事件规则裸键=contains 是索图
	// 子集存量,两套语义如实分流);保留键 min_hosts = 跨机聚合阈值
	// (标量整数 ≥2,给 = 跨机规则,缺省 0 = 单机实体规则)。
	mn := node("match")
	if mn == nil || mn.Kind != yaml.MappingNode || len(mn.Content) == 0 {
		errs = append(errs, "match 须为非空映射(字段条件 AND,字段内子串列表 OR)")
	} else {
		entityRule := target == "entity"
		seen := map[string]bool{}
		for i := 0; i+1 < len(mn.Content); i += 2 {
			key := mn.Content[i].Value
			vn := mn.Content[i+1]
			if entityRule && key == "min_hosts" {
				var n int
				if vn.Kind != yaml.ScalarNode {
					errs = append(errs, "match.min_hosts: 须为 ≥2 的整数标量")
					continue
				}
				if _, err := fmt.Sscanf(vn.Value, "%d", &n); err != nil || n < 2 {
					errs = append(errs, "match.min_hosts: 须为 ≥2 的整数标量")
					continue
				}
				r.MinHosts = n
				continue
			}
			field, op := splitFieldKey(key)
			if entityRule {
				if !EntityMatchFields[field] {
					errs = append(errs, fmt.Sprintf("match.%s: 未知实体匹配字段(允许: entity_type/raw_value/canonical_key/qualifier + 保留键 min_hosts)", key))
					continue
				}
				if key == field { // 裸键:树庭附录 A 语义 = eq
					op = MatchOpEq
				}
			} else if !MatchFields[field] {
				errs = append(errs, fmt.Sprintf("match.%s: 未知匹配字段", key))
				continue
			}
			if seen[key] {
				errs = append(errs, fmt.Sprintf("match.%s: 重复字段", key))
				continue
			}
			seen[key] = true
			if vn.Kind != yaml.SequenceNode || len(vn.Content) == 0 {
				errs = append(errs, fmt.Sprintf("match.%s: 须为非空子串列表(OR 语义)", key))
				continue
			}
			var subs []string
			bad := false
			for _, sn := range vn.Content {
				if sn.Kind != yaml.ScalarNode || sn.Value == "" {
					errs = append(errs, fmt.Sprintf("match.%s: 子串须为非空标量", key))
					bad = true
					break
				}
				subs = append(subs, strings.ToLower(sn.Value))
			}
			if !bad {
				r.Match = append(r.Match, FieldMatch{Field: field, Op: op, Subs: subs})
			}
		}
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("%s: %s", srcName, strings.Join(errs, "; "))
	}
	return r, nil
}

// LoadRulesDir 扫描目录装载全部规则;重复 id 一律报错(治理:冲突检测)。
func LoadRulesDir(dir string) ([]*Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("规则目录读取失败: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".yaml" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	seen := map[string]string{}
	var rules []*Rule
	for _, name := range names {
		text, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("规则读取失败(%s): %w", name, err)
		}
		r, err := CompileRule(name, string(text))
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[r.ID]; dup {
			return nil, fmt.Errorf("规则 id 冲突: %q 同时见于 %s 与 %s", r.ID, prev, name)
		}
		seen[r.ID] = name
		rules = append(rules, r)
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("规则目录 %s 无规则(.yaml)", dir)
	}
	return rules, nil
}
