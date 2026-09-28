// web 层的案件/源查询面(PG 只读查询;摄入登记走 pipeline 的 MetaStore)。
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Case 案件(含源计数;切片 8a 起含候选计数——工作台卡片墙用,
// hits 表窗口外全量计数,口径在字段注释焊死)。
// 交互改造(新建任务向导)起含应急元数据三字段(007 迁移;
// 空串/空数组=旧案件未经向导填写,如实不回填)。
type Case struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	Sources   int       `json:"sources"`
	// Candidates 命中候选总数(hits 表全状态计数;命中≠结论)。
	Candidates int `json:"candidates"`
	// PendingCandidates 待裁决候选数(status=pending,需人工接受/排除)。
	PendingCandidates int `json:"pending_candidates"`
	// IncidentType 应急类型(ransomware|webshell|intrusion|data-leak|other)。
	IncidentType string `json:"incident_type"`
	// Background 应急背景自由文本(向导模板回填的产物落此)。
	Background string `json:"background"`
	// GoalPresets 应急目的预设(预设勾选+自由补充的最终文本;创建时
	// 同步播种为意图图 goal 节点,本列是元数据账)。
	GoalPresets []string `json:"goal_presets"`
	// ArchivedAt 归档时刻(011 迁移;nil=活跃)。归档=列表默认隐藏/
	// 停派新意图/禁起新分析,页面照常只读可看,解归档即恢复。
	ArchivedAt *time.Time `json:"archived_at"`
}

// CaseProfile 案件应急元数据(新建任务向导落库,007 迁移)。
type CaseProfile struct {
	IncidentType string
	Background   string
	GoalPresets  []string
}

// SetCaseProfile 写案件应急元数据(覆盖语义;无此案件如实报错)。
func (p *PG) SetCaseProfile(ctx context.Context, caseID string, prof CaseProfile) error {
	presets := prof.GoalPresets
	if presets == nil {
		presets = []string{} // 不落 NULL/空串,JSONB 数组语义焊死
	}
	tag, err := p.pool.Exec(ctx, `
		UPDATE cases SET incident_type = $2, background = $3, goal_presets = $4
		WHERE id = $1`, caseID, prof.IncidentType, prof.Background, presets)
	if err != nil {
		return fmt.Errorf("案件元数据写入失败: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("无此案件: %s", caseID)
	}
	return nil
}

// Source 源(含证据链锚点 sha256——金库回查的寻址键;含指纹判定四列,
// 切片四起——判定结果与置信度人可见可改,DESIGN §6.2 第一面)。
type Source struct {
	ID               string    `json:"id"`
	CaseID           string    `json:"case_id"`
	Path             string    `json:"path"`
	SHA256           string    `json:"sha256"`
	SizeBytes        int64     `json:"size_bytes"`
	Kind             string    `json:"kind"`
	ArtifactType     string    `json:"artifact_type"`
	LogType          string    `json:"log_type"`
	Host             string    `json:"host"`    // 主机键(一案多包;空=未建模)
	Package          string    `json:"package"` // 采集包登记根名(空=散件)
	DetectFormat     string    `json:"detect_format"`
	DetectConfidence *float64  `json:"detect_confidence"`
	DetectStatus     string    `json:"detect_status"`
	CreatedAt        time.Time `json:"created_at"`
}

const sourceCols = `id, case_id, path, sha256, size_bytes, kind, artifact_type,
	COALESCE(log_type, ''), host, package, COALESCE(detect_format, ''),
	detect_confidence, detect_status, created_at`

func scanSource(row interface{ Scan(...any) error }) (*Source, error) {
	var s Source
	err := row.Scan(&s.ID, &s.CaseID, &s.Path, &s.SHA256, &s.SizeBytes,
		&s.Kind, &s.ArtifactType, &s.LogType, &s.Host, &s.Package,
		&s.DetectFormat, &s.DetectConfidence, &s.DetectStatus, &s.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// caseCounts 案件计数投影列(源数 + 候选总数 + 待裁决数;候选口径:
// hits 表全量/全状态,pending 子集单列——工作台卡片用,判断权归人可视化)。
const caseCounts = `
		(SELECT count(*) FROM sources s WHERE s.case_id = c.id),
		(SELECT count(*) FROM hits h WHERE h.case_id = c.id),
		(SELECT count(*) FROM hits h WHERE h.case_id = c.id AND h.status = 'pending')`

// caseMetaCols 案件应急元数据列(007 迁移;新建任务向导三字段)+ 归档列(011)。
const caseMetaCols = `, c.incident_type, c.background, c.goal_presets, c.archived_at`

// scanCase 案件行解析(计数投影 + 应急元数据 + 归档时刻;goal_presets JSONB → []string)。
func scanCase(row interface{ Scan(...any) error }) (*Case, error) {
	var c Case
	var presets []byte
	err := row.Scan(&c.ID, &c.Name, &c.CreatedAt, &c.Sources,
		&c.Candidates, &c.PendingCandidates, &c.IncidentType, &c.Background,
		&presets, &c.ArchivedAt)
	if err != nil {
		return nil, err
	}
	if len(presets) > 0 {
		if err := json.Unmarshal(presets, &c.GoalPresets); err != nil {
			return nil, fmt.Errorf("案件目的预设 JSON 解析失败: %w", err)
		}
	}
	if c.GoalPresets == nil {
		c.GoalPresets = []string{} // 零预设返回 [],不返回 null
	}
	return &c, nil
}

// ListCases 案件清单(含源/候选计数 + 应急元数据)。
func (p *PG) ListCases(ctx context.Context) ([]Case, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT c.id, c.name, c.created_at,`+caseCounts+caseMetaCols+`
		FROM cases c ORDER BY c.created_at`)
	if err != nil {
		return nil, fmt.Errorf("案件查询失败: %w", err)
	}
	defer rows.Close()
	var out []Case
	for rows.Next() {
		c, err := scanCase(rows)
		if err != nil {
			return nil, fmt.Errorf("案件行解析失败: %w", err)
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// GetCase 按 id 取案件(无则 nil,nil)。
func (p *PG) GetCase(ctx context.Context, id string) (*Case, error) {
	c, err := scanCase(p.pool.QueryRow(ctx, `
		SELECT c.id, c.name, c.created_at,`+caseCounts+caseMetaCols+`
		FROM cases c WHERE c.id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("案件查询失败: %w", err)
	}
	return c, nil
}

// ListSources 案件源清单(登记序)。
func (p *PG) ListSources(ctx context.Context, caseID string) ([]Source, error) {
	rows, err := p.pool.Query(ctx,
		"SELECT "+sourceCols+" FROM sources WHERE case_id = $1 ORDER BY created_at, id",
		caseID)
	if err != nil {
		return nil, fmt.Errorf("源查询失败: %w", err)
	}
	defer rows.Close()
	var out []Source
	for rows.Next() {
		s, err := scanSource(rows)
		if err != nil {
			return nil, fmt.Errorf("源行解析失败: %w", err)
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// GetSource 按 id 取源(无则 nil,nil;行号锚点回查的 sha256 寻址来源)。
func (p *PG) GetSource(ctx context.Context, id string) (*Source, error) {
	s, err := scanSource(p.pool.QueryRow(ctx,
		"SELECT "+sourceCols+" FROM sources WHERE id = $1", id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("源查询失败: %w", err)
	}
	return s, nil
}

// ListPackages 案件已登记的采集包根名清单(一案多包:同名包二次摄入
// 时调用方据此给登记根名加 #N 后缀,路径唯一约束不撞车)。
func (p *PG) ListPackages(ctx context.Context, caseID string) ([]string, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT DISTINCT package FROM sources
		WHERE case_id = $1 AND package <> '' ORDER BY package`, caseID)
	if err != nil {
		return nil, fmt.Errorf("包清单查询失败: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("包清单行解析失败: %w", err)
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// ListHosts 案件已建模主机键清单(意图模板 host_scope=each 的实例化域)。
func (p *PG) ListHosts(ctx context.Context, caseID string) ([]string, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT DISTINCT host FROM sources
		WHERE case_id = $1 AND host <> '' ORDER BY host`, caseID)
	if err != nil {
		return nil, fmt.Errorf("主机清单查询失败: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("主机清单行解析失败: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
