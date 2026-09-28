// 指纹判定与解析状态面(切片四:一键分析主链路的幂等依据——
// 「已解析过的源跳过」由 ingest_jobs 最新账判定;判定结果人可见可改)。
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// 判定状态机(migrations/003_slice4.sql CHECK 同款,写侧代码层也把一道)。
var detectStatuses = map[string]bool{
	"none": true, "auto": true, "pending_confirm": true,
	"overridden": true, "suspect": true,
}

// Detection 一次指纹判定/人改判的落库内容。
type Detection struct {
	Format     string   // builtin:<id> | desc:<name>(可空:仅改状态)
	Confidence *float64 // 前验置信度(人改判保留原值留痕)
	Status     string   // detect_status 状态机值
	LogType    string   // 源品类(可空:不改变)
}

// JobState 源最近一次摄入任务账(幂等/后验绊线依据)。
type JobState struct {
	Status    string `json:"status"`
	Parser    string `json:"parser"`
	RowsTotal int64  `json:"rows_total"`
	RowsEvent int64  `json:"rows_event"`
	RowsBad   int64  `json:"rows_bad"`
	RowsSkip  int64  `json:"rows_skip"`
}

// LatestJob 源最近一次摄入任务账(无则 nil,nil)。
func (p *PG) LatestJob(ctx context.Context, sourceID string) (*JobState, error) {
	var j JobState
	err := p.pool.QueryRow(ctx, `
		SELECT status, COALESCE(parser, ''), rows_total, rows_event, rows_bad, rows_skip
		FROM ingest_jobs WHERE source_id = $1
		ORDER BY started_at DESC LIMIT 1`, sourceID).
		Scan(&j.Status, &j.Parser, &j.RowsTotal, &j.RowsEvent, &j.RowsBad, &j.RowsSkip)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("摄入任务账查询失败: %w", err)
	}
	return &j, nil
}

// SetDetection 落指纹判定/人改判(状态机值代码层先校验,非法即拒)。
func (p *PG) SetDetection(ctx context.Context, sourceID string, d Detection) error {
	if !detectStatuses[d.Status] {
		return fmt.Errorf("detect_status 非法: %q", d.Status)
	}
	if d.Format == "" && d.Status != "pending_confirm" && d.Status != "none" {
		return fmt.Errorf("判定格式不能为空(状态 %s)", d.Status)
	}
	tag, err := p.pool.Exec(ctx, `
		UPDATE sources SET detect_format = $2, detect_confidence = $3,
			detect_status = $4, log_type = $5
		WHERE id = $1`,
		sourceID, nilIfEmpty(d.Format), d.Confidence, d.Status, nilIfEmpty(d.LogType))
	if err != nil {
		return fmt.Errorf("判定落库失败: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("无此源: %s", sourceID)
	}
	return nil
}

// MarkParsedText 文本源解析成功后 kind 由 raw(registered_unparsed)提升为
// text——金库行号回查/适用域路由都以 kind=text 为准。
func (p *PG) MarkParsedText(ctx context.Context, sourceID string) error {
	if _, err := p.pool.Exec(ctx,
		"UPDATE sources SET kind = 'text' WHERE id = $1 AND kind = 'raw'",
		sourceID); err != nil {
		return fmt.Errorf("源类别提升失败: %w", err)
	}
	return nil
}

// SourceState 源 + 最近任务账(内容树/主链路汇总用)。
type SourceState struct {
	Source
	Job *JobState `json:"job,omitempty"`
}

// ListSourcesWithJobs 案件源清单联最近任务账(每源一行,窗口函数取最新)。
func (p *PG) ListSourcesWithJobs(ctx context.Context, caseID string) ([]SourceState, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT `+sourceCols+`,
			j.status, COALESCE(j.parser, ''), j.rows_total, j.rows_event,
			j.rows_bad, j.rows_skip
		FROM sources s
		LEFT JOIN LATERAL (
			SELECT status, parser, rows_total, rows_event, rows_bad, rows_skip
			FROM ingest_jobs ij WHERE ij.source_id = s.id
			ORDER BY ij.started_at DESC LIMIT 1
		) j ON true
		WHERE s.case_id = $1 ORDER BY s.created_at, s.id`, caseID)
	if err != nil {
		return nil, fmt.Errorf("源联任务账查询失败: %w", err)
	}
	defer rows.Close()
	var out []SourceState
	for rows.Next() {
		var st SourceState
		var jStatus *string
		var jParser string
		var jTotal, jEvent, jBad, jSkip *int64
		err := rows.Scan(&st.ID, &st.CaseID, &st.Path, &st.SHA256, &st.SizeBytes,
			&st.Kind, &st.ArtifactType, &st.LogType, &st.Host, &st.Package,
			&st.DetectFormat, &st.DetectConfidence, &st.DetectStatus, &st.CreatedAt,
			&jStatus, &jParser, &jTotal, &jEvent, &jBad, &jSkip)
		if err != nil {
			return nil, fmt.Errorf("源联任务账行解析失败: %w", err)
		}
		if jStatus != nil {
			st.Job = &JobState{Status: *jStatus, Parser: jParser,
				RowsTotal: deref(jTotal), RowsEvent: deref(jEvent),
				RowsBad: deref(jBad), RowsSkip: deref(jSkip)}
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func deref(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}
