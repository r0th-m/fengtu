// 0.27.0 案件封存/迁移(M4)存储面:证据锚点导出读取 + 意图节点全列落库。
// 导出读面(join sources 带 sha256/path,跨实例重映射不靠旧 id);导入写面
// (SealInsertNode 全列保真,状态改写与 id 重映射在 web 层做完再落)。
package store

import (
	"context"
	"fmt"

	"github.com/ye-mengwen/fengtu/internal/intent"
)

// SealAnchor 证据锚点导出/导入行(evidence_anchors join sources;
// SourceSHA256/SourcePath 是跨实例重映射键——旧 source_id 在目标实例
// 无意义,按内容哈希+路径找新源)。CaseID 不随包(json 忽略),fake 过滤用。
type SealAnchor struct {
	CaseID       string `json:"-"`
	NodeID       string `json:"node_id"`                 // 导出=旧节点 id;导入侧重映射后落新 id
	SourceID     string `json:"source_id,omitempty"`     // 可空(纯 hit 关联/探索语义)
	SourceSHA256 string `json:"source_sha256,omitempty"` // 重映射主键(join sources;源已删则空)
	SourcePath   string `json:"source_path,omitempty"`   // 同 sha256 多路径时的消歧键
	LineNo       int    `json:"line_no,omitempty"`
	HitID        string `json:"hit_id,omitempty"` // 导出原样留痕;导入一律置空(hits 不随包)
	Kind         string `json:"kind"`             // evidence|explored
	Note         string `json:"note,omitempty"`
}

// ListSealAnchors 案件证据锚点全量(导出用;创建序,带源 sha256/path)。
func (p *PG) ListSealAnchors(ctx context.Context, caseID string) ([]SealAnchor, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT ea.case_id::text, ea.node_id::text,
			COALESCE(ea.source_id::text, ''), COALESCE(s.sha256, ''),
			COALESCE(s.path, ''), COALESCE(ea.line_no, 0),
			COALESCE(ea.hit_id::text, ''), ea.kind, ea.note
		FROM evidence_anchors ea
		LEFT JOIN sources s ON s.id = ea.source_id
		WHERE ea.case_id = $1
		ORDER BY ea.created_at, ea.id`, caseID)
	if err != nil {
		return nil, fmt.Errorf("证据锚点查询失败: %w", err)
	}
	defer rows.Close()
	out := []SealAnchor{}
	for rows.Next() {
		var a SealAnchor
		if err := rows.Scan(&a.CaseID, &a.NodeID, &a.SourceID, &a.SourceSHA256,
			&a.SourcePath, &a.LineNo, &a.HitID, &a.Kind, &a.Note); err != nil {
			return nil, fmt.Errorf("证据锚点行解析失败: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SealInsertNode 迁移意图节点全列落库(导入专用):id 由库生成并回写
// (旧 id→新 id 映射由调用方建),created_at/started_at/finished_at 原样
// 保留(历史事实不改写);session_id 恒 NULL(AI 会话不随包);
// parent_id 调用方已重映射。状态改写(running/awaiting_approval→stopped)
// 在 web 层做完再调,本函数不偷偷改任何字段。
func (p *PG) SealInsertNode(ctx context.Context, n *intent.Node) error {
	var createdAt any
	if !n.CreatedAt.IsZero() {
		createdAt = n.CreatedAt
	}
	err := p.pool.QueryRow(ctx, `
		INSERT INTO intent_nodes
			(case_id, kind, text, status, created_by, rule_id, template_id,
			 template_key, scope, host_scope, parent_id, depth, evidence,
			 result_text, close_note, session_id, budget_seconds,
			 started_at, finished_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NULL,$16,$17,$18,
		        COALESCE($19, now()))
		RETURNING id`,
		n.CaseID, n.Kind, n.Text, n.Status, n.CreatedBy, n.RuleID, n.TemplateID,
		n.TemplateKey, n.Scope, n.HostScope, nilIfEmpty(n.ParentID), n.Depth,
		marshalAnchors(n.Evidence), n.ResultText, n.CloseNote, n.BudgetSeconds,
		n.StartedAt, n.FinishedAt, createdAt).
		Scan(&n.ID)
	if err != nil {
		return fmt.Errorf("迁移意图节点落库失败: %w", err)
	}
	return nil
}
