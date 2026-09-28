// 全局只读聚合(切片十,ARTEX dashboard/审批记录页的应急映射):
// GlobalStats 仪表盘总览统计;ListAwaitingIntents 跨案件待批意图
// (审批记录全局页的待处理区)。全部纯读,不落账。
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/ye-mengwen/fengtu/internal/intent"
)

// ActivityDay 一天的审计链活动条数(仪表盘「近 N 天活动」柱)。
type ActivityDay struct {
	Day   string `json:"day"` // YYYY-MM-DD(UTC 日界,如实标注)
	Count int64  `json:"count"`
}

// GlobalStats 平台总览(计数口径与工作台一致:候选=hits 全状态,
// 待裁决=status='pending';待批=intent_nodes awaiting_approval)。
// 011 起:默认不含已归档案件(cases/sources/candidates/pending 全口径;
// 归档数单列 ArchivedCases 如实标注)。
type GlobalStats struct {
	Cases             int64          `json:"cases"`
	Sources           int64          `json:"sources"`
	Candidates        int64          `json:"candidates"`
	PendingCandidates int64          `json:"pending_candidates"`
	PendingApprovals  int64          `json:"pending_approvals"`
	LLMRecords        int64          `json:"llm_records"`    // 录制账总条数
	ArchivedCases     int64          `json:"archived_cases"` // 已归档案件数(不计入上列口径)
	Activity          []ActivityDay  `json:"activity"`       // 近 7 天审计链日条数(升序)
}

// GlobalStats 平台总览聚合(只读 SQL;活动窗焊死 7 天)。
// 归档口径(011):活跃案件 = archived_at IS NULL;源/候选/待裁决/待批
// 均经 case 归属过滤,归档案的量不进默认口径(ArchivedCases 单列如实)。
func (p *PG) GlobalStats(ctx context.Context) (*GlobalStats, error) {
	var s GlobalStats
	err := p.pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM cases WHERE archived_at IS NULL),
			(SELECT count(*) FROM sources s JOIN cases c ON c.id = s.case_id
				WHERE c.archived_at IS NULL),
			(SELECT count(*) FROM hits h JOIN cases c ON c.id = h.case_id
				WHERE c.archived_at IS NULL),
			(SELECT count(*) FROM hits h JOIN cases c ON c.id = h.case_id
				WHERE h.status = 'pending' AND c.archived_at IS NULL),
			(SELECT count(*) FROM intent_nodes n JOIN cases c ON c.id = n.case_id
				WHERE n.status = 'awaiting_approval' AND c.archived_at IS NULL),
			(SELECT count(*) FROM llm_records),
			(SELECT count(*) FROM cases WHERE archived_at IS NOT NULL)`).Scan(
		&s.Cases, &s.Sources, &s.Candidates, &s.PendingCandidates,
		&s.PendingApprovals, &s.LLMRecords, &s.ArchivedCases)
	if err != nil {
		return nil, fmt.Errorf("总览统计聚合失败: %w", err)
	}

	rows, err := p.pool.Query(ctx, `
		SELECT to_char(date_trunc('day', ts AT TIME ZONE 'UTC'), 'YYYY-MM-DD'), count(*)
		FROM audit_chain
		WHERE ts >= now() - interval '7 days'
		GROUP BY 1 ORDER BY 1`)
	if err != nil {
		return nil, fmt.Errorf("活动按日聚合失败: %w", err)
	}
	defer rows.Close()
	s.Activity = []ActivityDay{}
	for rows.Next() {
		var d ActivityDay
		if err := rows.Scan(&d.Day, &d.Count); err != nil {
			return nil, fmt.Errorf("活动日行解析失败: %w", err)
		}
		s.Activity = append(s.Activity, d)
	}
	return &s, rows.Err()
}

// ListAwaitingIntents 跨案件待批意图(审批记录全局页待处理区;
// 创建序升序,最久等待在前)。011 起排除已归档案件(归档案停派,
// 待批挂起不挡活跃案件的审批视野)。
func (p *PG) ListAwaitingIntents(ctx context.Context) ([]*intent.Node, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT `+intentNodeCols+` FROM intent_nodes
		WHERE status = 'awaiting_approval'
			AND case_id IN (SELECT id FROM cases WHERE archived_at IS NULL)
		ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("待批意图清单查询失败: %w", err)
	}
	defer rows.Close()
	out := []*intent.Node{}
	for rows.Next() {
		n, err := scanIntentNode(rows)
		if err != nil {
			return nil, fmt.Errorf("待批意图行解析失败: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// WorkspaceFile 工作空间文件条目(原件金库=已登记源;导出件=exports 目录)。
type WorkspaceFile struct {
	Area      string    `json:"area"` // vault=案件上传原件金库 | exports=导出件
	Name      string    `json:"name"` // vault=源登记路径;exports=相对路径
	CaseID    string    `json:"case_id,omitempty"`
	CaseName  string    `json:"case_name,omitempty"`
	SHA256    string    `json:"sha256,omitempty"` // vault 原件的证据链哈希
	SizeBytes int64     `json:"size_bytes"`
	ModTime   time.Time `json:"mod_time"`
}

// ListWorkspaceSources 原件金库视图:全部已登记源(哈希/大小/案件锚来自
// 摄入账,与金库实体一一对应——金库只读,本查询就是文件清单的账)。
func (p *PG) ListWorkspaceSources(ctx context.Context, limit int) ([]WorkspaceFile, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	rows, err := p.pool.Query(ctx, `
		SELECT s.path, s.sha256, s.size_bytes, s.created_at,
			s.case_id::text, c.name
		FROM sources s JOIN cases c ON c.id = s.case_id
		ORDER BY s.created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("工作空间原件清单查询失败: %w", err)
	}
	defer rows.Close()
	out := []WorkspaceFile{}
	for rows.Next() {
		var f WorkspaceFile
		if err := rows.Scan(&f.Name, &f.SHA256, &f.SizeBytes, &f.ModTime,
			&f.CaseID, &f.CaseName); err != nil {
			return nil, fmt.Errorf("工作空间原件行解析失败: %w", err)
		}
		f.Area = "vault"
		out = append(out, f)
	}
	return out, rows.Err()
}
