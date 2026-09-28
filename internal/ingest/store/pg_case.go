// 案件生命周期(0.18.0-case-lifecycle):改名 / 归档 / 删除的 PG 面。
//
// 纪律:
//   - 归档是软状态(cases.archived_at),不解文件不动证据,解归档即恢复;
//   - 删除是硬删级联(判断权归人:人逐字输名确认才走到这里),一案事务
//     内按外键依赖序清空全部元数据;审计链不动(全局哈希链,011 迁移已
//     解除案件外键,被删案件的审计条目原样保留为历史账,链零影响);
//   - vault 原件按内容寻址(sha256),同哈希可能被其他案件源引用——
//     删案只清「全库再无引用」的原件,引用仍在的如实留着(证据链不断)。
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// RenameCase 案件改名(ok=false=无此案件;重名撞 UNIQUE 如实报错)。
func (p *PG) RenameCase(ctx context.Context, id, name string) (bool, error) {
	tag, err := p.pool.Exec(ctx,
		"UPDATE cases SET name = $2 WHERE id = $1", id, name)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return false, fmt.Errorf("任务名已被占用: %s", name)
		}
		return false, fmt.Errorf("案件改名失败: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// SetCaseArchived 归档/解归档(archived=true 落归档时刻,false 清空;
// ok=false=无此案件)。幂等:重复归档刷新时刻如实(每次操作都进审计)。
func (p *PG) SetCaseArchived(ctx context.Context, id string, archived bool) (bool, error) {
	var tag pgconn.CommandTag
	var err error
	if archived {
		tag, err = p.pool.Exec(ctx,
			"UPDATE cases SET archived_at = now() WHERE id = $1", id)
	} else {
		tag, err = p.pool.Exec(ctx,
			"UPDATE cases SET archived_at = NULL WHERE id = $1", id)
	}
	if err != nil {
		return false, fmt.Errorf("案件归档状态写入失败: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// CaseArchived 案件是否已归档(意图引擎派发闸;无此案件按未归档如实,
// 案件已被删时 NextRunnable 自然空,不派)。
func (p *PG) CaseArchived(ctx context.Context, caseID string) (bool, error) {
	var archived bool
	err := p.pool.QueryRow(ctx,
		"SELECT archived_at IS NOT NULL FROM cases WHERE id = $1", caseID).
		Scan(&archived)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("案件归档状态查询失败: %w", err)
	}
	return archived, nil
}

// CaseInFlight 案件在跑工作账(删除前置闸):摄入任务 running 数 +
// 意图节点 running 数。二者任一非零 = 有在跑工作,删案应 409 如实拒。
func (p *PG) CaseInFlight(ctx context.Context, caseID string) (jobs, intents int64, err error) {
	err = p.pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM ingest_jobs WHERE case_id = $1 AND status = 'running'),
			(SELECT count(*) FROM intent_nodes WHERE case_id = $1 AND status = 'running')`,
		caseID).Scan(&jobs, &intents)
	if err != nil {
		return 0, 0, fmt.Errorf("案件在跑工作查询失败: %w", err)
	}
	return jobs, intents, nil
}

// CountSourcesByHash 全库引用该 sha256 的源数(vault 原件级联删除闸:
// 删案后仍 >0 = 其他案件还指着这份证据,原件如实保留)。
func (p *PG) CountSourcesByHash(ctx context.Context, sha256 string) (int64, error) {
	var n int64
	if err := p.pool.QueryRow(ctx,
		"SELECT count(*) FROM sources WHERE sha256 = $1", sha256).Scan(&n); err != nil {
		return 0, fmt.Errorf("哈希引用计数失败: %w", err)
	}
	return n, nil
}

// CaseDeleteReport 删除级联账(各表删除行数,如实回填响应与审计)。
type CaseDeleteReport struct {
	Sources         int64            `json:"sources"`
	Hits            int64            `json:"hits"`
	ScanRuns        int64            `json:"scan_runs"`
	IngestJobs      int64            `json:"ingest_jobs"`
	IntentNodes     int64            `json:"intent_nodes"`
	IntentEdges     int64            `json:"intent_edges"`
	IntentEvents    int64            `json:"intent_events"`
	EvidenceAnchors int64            `json:"evidence_anchors"`
	AISessions      int64            `json:"ai_sessions"`
	LLMRecords      int64            `json:"llm_records"`
	Constraints     int64            `json:"constraints"`
	CaseKBEntries   int64            `json:"case_kb_entries"`
	Parking         int64            `json:"parking"`  // 停车场条目(014;挂 cases+intent_nodes)
	Entities        int64            `json:"entities"` // 实体锚点(015;挂 sources,须先于 sources 删)
	CaseReports     int64            `json:"case_reports"` // 研判报告版本账(021;挂 cases)
	Tables          map[string]int64 `json:"-"`        // 内部明细
}

// DeleteCase 案件元数据级联硬删(单事务,按外键依赖序)。
// 前置闸(在跑工作 409/名匹配复核)与审计落账在 web 层;本函数只清 PG。
// audit_chain 不动:全局哈希链断不得,011 迁移已解除其案件外键,
// 被删案件的审计条目原样保留(case_id 为悬空 UUID 文本,取舍见迁移注释)。
// CH 事件与磁盘(vault 原件/workspace/<case_id>)由调用方在 PG 删完后清。
func (p *PG) DeleteCase(ctx context.Context, caseID string) (*CaseDeleteReport, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("删除事务开启失败: %w", err)
	}
	defer tx.Rollback(ctx)

	rep := &CaseDeleteReport{Tables: map[string]int64{}}
	// 外键依赖序:先子表后父表(intent_parking 挂 cases+intent_nodes;
	// evidence_anchors/intent_events 挂 intent_nodes,intent_edges 同理;
	// ingest_jobs/hits 挂 sources;entities.source_id 挂 sources 且无
	// ON DELETE CASCADE(015 迁移),漏删会在删 sources 时 FK 报错——
	// M4 实锤补登)。
	steps := []struct {
		table string
		sql   string
		out   *int64
	}{
		{"case_reports", "DELETE FROM case_reports WHERE case_id = $1", &rep.CaseReports},
		{"intent_parking", "DELETE FROM intent_parking WHERE case_id = $1", &rep.Parking},
		{"intent_events", "DELETE FROM intent_events WHERE case_id = $1", &rep.IntentEvents},
		{"evidence_anchors", "DELETE FROM evidence_anchors WHERE case_id = $1", &rep.EvidenceAnchors},
		{"intent_edges", "DELETE FROM intent_edges WHERE case_id = $1", &rep.IntentEdges},
		{"intent_nodes", "DELETE FROM intent_nodes WHERE case_id = $1", &rep.IntentNodes},
		{"llm_records", "DELETE FROM llm_records WHERE case_id = $1", &rep.LLMRecords},
		{"ai_sessions", "DELETE FROM ai_sessions WHERE case_id = $1", &rep.AISessions},
		{"case_constraints", "DELETE FROM case_constraints WHERE case_id = $1", &rep.Constraints},
		{"case_kb_entries", "DELETE FROM case_kb_entries WHERE case_id = $1", &rep.CaseKBEntries},
		{"scan_runs", "DELETE FROM scan_runs WHERE case_id = $1", &rep.ScanRuns},
		{"hits", "DELETE FROM hits WHERE case_id = $1", &rep.Hits},
		{"ingest_jobs", "DELETE FROM ingest_jobs WHERE case_id = $1", &rep.IngestJobs},
		{"entities", "DELETE FROM entities WHERE case_id = $1", &rep.Entities},
		{"sources", "DELETE FROM sources WHERE case_id = $1", &rep.Sources},
	}
	for _, st := range steps {
		tag, err := tx.Exec(ctx, st.sql, caseID)
		if err != nil {
			return nil, fmt.Errorf("级联删除失败(%s): %w", st.table, err)
		}
		*st.out = tag.RowsAffected()
		rep.Tables[st.table] = tag.RowsAffected()
	}
	tag, err := tx.Exec(ctx, "DELETE FROM cases WHERE id = $1", caseID)
	if err != nil {
		return nil, fmt.Errorf("案件行删除失败: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, fmt.Errorf("无此案件: %s", caseID)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("删除事务提交失败: %w", err)
	}
	return rep, nil
}

// caseArchivedCol 案件归档列(011 迁移;查询投影统一带)。
const caseArchivedCol = `, c.archived_at`
