// 运行中操控(交互改造切片三,设计依据 fengtu-interaction-design.md §3):
//   - AddHint 补充线索(ARTEX add_hint 照抄:hint 节点挂图,worker 下轮可见
//     ——注入 system 段;hint 不可派发,不 Wake,零 AI 消耗);
//   - 操作约束 CRUD(ARTEX set_constraints 应急映射:「不得触碰的生产系统
//     清单/只读原则/时间窗」;人增人删,机器不自动抽取,增删进审计哈希链)。
package intent

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"
)

// 入参上限(防呆不是防攻:同源已登录用户)。
const (
	hintTextMaxRunes       = 500
	constraintTextMaxRunes = 300
	constraintMaxPerCase   = 20
)

// AddHint 补充线索:hint 节点挂图(人提出),可挂父节点(缺省锚首 goal,
// 无 goal 则孤儿——布局上 hint 孤儿留最左);worker system 下轮起注入
// 「人工线索」段(见 systemExtra)。不 Wake:hint 不可派发,播种零 AI 消耗。
func (e *Engine) AddHint(ctx context.Context, caseID, actor, text, parentID string) (*Node, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, fmt.Errorf("线索内容必填")
	}
	if utf8.RuneCountInString(text) > hintTextMaxRunes {
		return nil, fmt.Errorf("线索内容过长(≤%d 字)", hintTextMaxRunes)
	}
	depth := 0
	if parentID != "" {
		p, err := e.deps.Store.GetNode(ctx, parentID)
		if err != nil {
			return nil, err
		}
		if p == nil || p.CaseID != caseID {
			return nil, fmt.Errorf("父节点不存在(或不属本案件): %s", parentID)
		}
		depth = p.Depth + 1
		if depth > MaxDepth {
			depth = MaxDepth // hint 不派生,深度只是布局参考,截断不拒
		}
	} else {
		// 缺省锚首 goal(与 SeedRules 同锚),图上有血缘不孤儿
		nodes, err := e.deps.Store.ListNodes(ctx, caseID)
		if err != nil {
			return nil, err
		}
		for _, n := range nodes {
			if n.Kind == KindGoal {
				parentID = n.ID
				depth = 1
				break
			}
		}
	}
	// hint 不执行:status=closed(不占用 open 队列/不计待执行),卡片不显示
	// 状态徽标(前端按 kind=hint 抑制)。
	hint := &Node{CaseID: caseID, Kind: KindHint, Text: text, Status: StatusClosed,
		CreatedBy: ByHuman, Scope: ScopeCase, ParentID: parentID, Depth: depth,
		BudgetSeconds: e.deps.BudgetSeconds}
	if err := ValidateNode(hint); err != nil {
		return nil, err
	}
	if err := e.deps.Store.CreateNode(ctx, hint); err != nil {
		return nil, err
	}
	e.emitNodeAdded(hint)
	if parentID != "" {
		ed := &Edge{CaseID: caseID, FromID: parentID, ToID: hint.ID, Kind: EdgeDerivedFrom}
		if err := e.deps.Store.CreateEdge(ctx, ed); err != nil {
			return hint, err
		}
		e.emitEdgeAdded(ed)
	}
	_, _, _ = e.deps.Audit.AppendAudit(ctx, caseID, actor, "intent.add_hint",
		hint.ID, map[string]any{"text": text, "parent": parentID})
	return hint, nil
}

// AddConstraint 新增案件级操作约束(人定;注入 worker system,对之后认领的
// 意图生效;进审计)。同案同文本幂等(返回既有,不重复落库不重复审计)。
func (e *Engine) AddConstraint(ctx context.Context, caseID, actor, text string) (*Constraint, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, fmt.Errorf("约束内容必填")
	}
	if utf8.RuneCountInString(text) > constraintTextMaxRunes {
		return nil, fmt.Errorf("约束内容过长(≤%d 字)", constraintTextMaxRunes)
	}
	cs, err := e.deps.Store.ListConstraints(ctx, caseID)
	if err != nil {
		return nil, err
	}
	for _, c := range cs {
		if c.Text == text {
			return c, nil // 幂等:同文本不重复落
		}
	}
	if len(cs) >= constraintMaxPerCase {
		return nil, fmt.Errorf("约束条数超上限(≤%d 条/案件)", constraintMaxPerCase)
	}
	c := &Constraint{CaseID: caseID, Text: text, CreatedBy: actor}
	if err := e.deps.Store.AddConstraint(ctx, c); err != nil {
		return nil, err
	}
	_, _, _ = e.deps.Audit.AppendAudit(ctx, caseID, actor, "intent.constraint.add",
		c.ID, map[string]any{"text": text})
	return c, nil
}

// RemoveConstraint 删除约束(无此约束如实报错;硬删,历史在审计链)。
func (e *Engine) RemoveConstraint(ctx context.Context, caseID, id, actor string) error {
	ok, err := e.deps.Store.DeleteConstraint(ctx, caseID, id)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("无此约束: %s", id)
	}
	_, _, _ = e.deps.Audit.AppendAudit(ctx, caseID, actor, "intent.constraint.remove",
		id, nil)
	return nil
}

// Constraints 案件约束清单(API 呈现;创建序)。
func (e *Engine) Constraints(ctx context.Context, caseID string) ([]*Constraint, error) {
	return e.deps.Store.ListConstraints(ctx, caseID)
}
