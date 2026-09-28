// HTTP server 装配:路由 + 登录闸中间件 + JSON 助手。
package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ye-mengwen/fengtu/internal/audit"
	"github.com/ye-mengwen/fengtu/internal/auth"
	"github.com/ye-mengwen/fengtu/internal/fingerprint"
	"github.com/ye-mengwen/fengtu/internal/ingest"
	"github.com/ye-mengwen/fengtu/internal/ingest/store"
	"github.com/ye-mengwen/fengtu/internal/ingress"
	"github.com/ye-mengwen/fengtu/internal/intent"
	"github.com/ye-mengwen/fengtu/internal/logbuf"
	"github.com/ye-mengwen/fengtu/internal/operator"
	"github.com/ye-mengwen/fengtu/internal/query"
	"github.com/ye-mengwen/fengtu/internal/review"
	"github.com/ye-mengwen/fengtu/internal/vault"
	"github.com/ye-mengwen/fengtu/internal/webui"
)

// MetaFace web 层需要的 PG 元数据面(store.PG 实现;含摄入登记面)。
type MetaFace interface {
	ingest.MetaStore
	ListCases(ctx context.Context) ([]store.Case, error)
	GetCase(ctx context.Context, id string) (*store.Case, error)
	ListSources(ctx context.Context, caseID string) ([]store.Source, error)
	GetSource(ctx context.Context, id string) (*store.Source, error)
	// 切片四:一键分析主链路(幂等/判定/内容树)。
	LatestJob(ctx context.Context, sourceID string) (*store.JobState, error)
	SetDetection(ctx context.Context, sourceID string, d store.Detection) error
	ListSourcesWithJobs(ctx context.Context, caseID string) ([]store.SourceState, error)
	MarkParsedText(ctx context.Context, sourceID string) error
	// 切片七:一案多包(包登记根名清单,同名包二次摄入 #N 后缀用)。
	ListPackages(ctx context.Context, caseID string) ([]string, error)
	// 交互改造·新建任务向导:案件应急元数据(类型/背景/目的预设)写入。
	SetCaseProfile(ctx context.Context, caseID string, prof store.CaseProfile) error
	// 切片十(ARTEX 布局全量复刻):平台页只读聚合面。
	GlobalStats(ctx context.Context) (*store.GlobalStats, error)
	ListAwaitingIntents(ctx context.Context) ([]*intent.Node, error)
	// CountPendingParking 全局停车场待处置条数(0.24.0;侧边栏计数)。
	CountPendingParking(ctx context.Context) (int64, error)
	ListLLMRecords(ctx context.Context, caseID string, limit, offset int) ([]store.LLMRecord, int64, error)
	GetLLMRecord(ctx context.Context, id string) (*store.LLMRecord, error)
	// 0.18.0 案件生命周期:改名/归档/删除级联/在跑闸/哈希引用计数。
	RenameCase(ctx context.Context, id, name string) (bool, error)
	SetCaseArchived(ctx context.Context, id string, archived bool) (bool, error)
	CaseArchived(ctx context.Context, caseID string) (bool, error)
	CaseInFlight(ctx context.Context, caseID string) (jobs, intents int64, err error)
	DeleteCase(ctx context.Context, caseID string) (*store.CaseDeleteReport, error)
	CountSourcesByHash(ctx context.Context, sha256 string) (int64, error)
	// 0.27.0 案件封存/迁移(M4):导出读取面 + 导入写回面。
	// ListSealAnchors 证据锚点全量(带源 sha256/path,跨实例重映射键)。
	ListSealAnchors(ctx context.Context, caseID string) ([]store.SealAnchor, error)
	// 意图图读写(节点/边;实现复用 intent.Store 既有面,SealInsertNode
	// 为导入全列落库新增,id 由库生成回写)。
	ListNodes(ctx context.Context, caseID string) ([]*intent.Node, error)
	ListEdges(ctx context.Context, caseID string) ([]*intent.Edge, error)
	SealInsertNode(ctx context.Context, n *intent.Node) error
	CreateEdge(ctx context.Context, e *intent.Edge) error
	AddAnchors(ctx context.Context, caseID, nodeID, kind string, anchors []intent.Anchor) error
	// EnsureNewCase 永远建新案(名撞加「(导入)」后缀;与 EnsureCase
	// 归并语义相反,并发导入不串案)。
	EnsureNewCase(ctx context.Context, baseName string) (id, name string, err error)
	// 0.31.0 研判报告(AI 生成)版本账:同案多次生成,版本递增保留历史;
	// content 存 LLM 产出原文,读侧按元数据拼报告头/截断标注。
	InsertCaseReport(ctx context.Context, r *store.CaseReport) error
	ListCaseReports(ctx context.Context, caseID, kind string) ([]store.CaseReport, error)
	GetCaseReport(ctx context.Context, caseID, kind string, version int) (*store.CaseReport, error)
}

// AuditFace 审计链追加/查询面(store.PG 实现)。
type AuditFace interface {
	AppendAudit(ctx context.Context, caseID, actor, action, scope string, detail any) (int64, string, error)
	ListAudit(ctx context.Context, caseID string, limit int) ([]audit.Entry, error)
	AllAudit(ctx context.Context) ([]audit.Entry, error)
}

// EventsAdminFace 事件库管理面(store.CH 实现;切片七重解析通路 +
// 0.18.0 案件删除级联)。
type EventsAdminFace interface {
	// DeleteEventsForSource 删除一个源的全部事件(重解析「先删后插」的删;
	// 实现须同步落地,删完才允许重解析)。
	DeleteEventsForSource(ctx context.Context, caseID, sourceID string) error
	// DeleteEventsForCase 删除一个案件的全部事件(案件删除级联;同步落地)。
	DeleteEventsForCase(ctx context.Context, caseID string) error
	// CountEventsForCase 案件事件总数(删除前的审计快照)。
	CountEventsForCase(ctx context.Context, caseID string) (int64, error)
}

// Deps server 依赖(全部接口化,httptest 用 fake 打全链)。
type Deps struct {
	Auth         *auth.Service
	Meta         MetaFace
	Audit        AuditFace
	Vault        *vault.Vault
	Ingress      *ingress.Manager
	Query        *query.Service
	// Stats 事件聚合执行面(store.CH 实现;切片 8b 时间线端点用;
	// nil = 时间线不可用,端点如实 503)。
	Stats        query.StatsQuerier
	Review       *review.Engine
	Events       ingest.EventStore // 摄入任务的 CH 写入面
	// EventsAdmin 事件库管理面(切片七重解析通路:改判后删旧事件;
	// nil = 重解析不可用,端点如实 503)。
	EventsAdmin  EventsAdminFace
	ArtifactMap  *ingest.ArtifactMap
	DescDir      string
	StagingDir   string                  // zip 展开暂存(任务内创建/清理)
	Candidates   []fingerprint.Candidate // 指纹候选集(内置 + desc 目录)
	Operators    *operator.Registry      // 算子注册表(nil = 不跑算子)
	AI           AIFace                  // AI 会话服务(nil = AI 未启用,端点 503)
	Intent       IntentFace              // 意图链引擎(nil = 未启用,端点 503)
	// KB 启发式知识库(0.19.0;nil = 未启用,端点 503 如实)。
	KB KBFace
	// DataDir 数据根(工作空间文件管理器根 <dir>/workspace;空=工作空间端点
	// 503 如实)。
	DataDir string
	// Logs 平台运行日志环形账(logbuf.Buffer;nil = 日志页 503 如实)。
	Logs         *logbuf.Buffer
	Version      string
	CookieSecure bool
}

// Server HTTP server。
type Server struct {
	deps  Deps
	tasks *TaskManager
	mux   *http.ServeMux
}

// NewServer 装配路由。
func NewServer(d Deps) *Server {
	s := &Server{deps: d, tasks: NewTaskManager(), mux: http.NewServeMux()}

	// 公开端点(登录闸外)
	s.mux.HandleFunc("GET /api/health", s.health)
	s.mux.HandleFunc("POST /api/auth/setup", s.authSetup)
	s.mux.HandleFunc("POST /api/auth/login", s.authLogin)

	// 会话端点(登录闸内)
	s.mux.HandleFunc("POST /api/auth/logout", s.authLogout)
	s.mux.HandleFunc("GET /api/auth/me", s.authMe)
	// 本人改密(任何登录用户;验旧口令)
	s.mux.HandleFunc("POST /api/auth/password", s.changeMyPassword)

	// 0.26.0-m4-multiuser:用户管理(admin 闸;operator 一律 403)
	s.mux.HandleFunc("GET /api/users", s.requireAdmin(s.listUsers))
	s.mux.HandleFunc("POST /api/users", s.requireAdmin(s.createUser))
	s.mux.HandleFunc("PATCH /api/users/{id}", s.requireAdmin(s.patchUser))
	s.mux.HandleFunc("POST /api/users/{id}/password", s.requireAdmin(s.resetUserPassword))
	s.mux.HandleFunc("DELETE /api/users/{id}", s.requireAdmin(s.deleteUser))

	s.mux.HandleFunc("GET /api/cases", s.listCases)
	s.mux.HandleFunc("POST /api/cases", s.createCase)
	s.mux.HandleFunc("GET /api/cases/{id}", s.getCase)
	// 0.18.0 案件生命周期:改名 / 归档·解归档 / 删除(双确认在 handler 内)
	s.mux.HandleFunc("PATCH /api/cases/{id}", s.renameCase)
	s.mux.HandleFunc("POST /api/cases/{id}/archive", s.archiveCase)
	s.mux.HandleFunc("POST /api/cases/{id}/unarchive", s.unarchiveCase)
	s.mux.HandleFunc("DELETE /api/cases/{id}", s.deleteCase)
	// 0.27.0 案件封存/迁移(M4):导出单 zip / 导入重建(全角色,登录即可;
	// 判断权归人——导入永远建新案,不并案不覆盖)
	s.mux.HandleFunc("GET /api/cases/{id}/export", s.exportCase)
	s.mux.HandleFunc("POST /api/cases/import", s.importCase)

	s.mux.HandleFunc("POST /api/uploads", s.uploadInit)
	s.mux.HandleFunc("GET /api/uploads/{id}", s.uploadStatus)
	s.mux.HandleFunc("PUT /api/uploads/{id}/chunks/{index}", s.uploadChunk)
	s.mux.HandleFunc("POST /api/uploads/{id}/complete", s.uploadComplete)

	s.mux.HandleFunc("GET /api/tasks", s.listTasks)
	s.mux.HandleFunc("GET /api/tasks/{id}", s.getTask)
	s.mux.HandleFunc("GET /api/tasks/{id}/events", s.taskEvents)

	s.mux.HandleFunc("GET /api/query", s.search)
	s.mux.HandleFunc("GET /api/sources/{id}/lines", s.sourceLines)
	s.mux.HandleFunc("GET /api/cases/{id}/timeline", s.timeline)

	s.mux.HandleFunc("GET /api/rules", s.listRules)
	s.mux.HandleFunc("GET /api/operators", s.listOperators)
	s.mux.HandleFunc("POST /api/cases/{id}/scans", s.startScan)
	s.mux.HandleFunc("GET /api/cases/{id}/scans", s.listScans)
	s.mux.HandleFunc("GET /api/cases/{id}/hits", s.listHits)
	s.mux.HandleFunc("POST /api/hits/{id}/verdict", s.verdict)
	s.mux.HandleFunc("POST /api/hits/batch-verdict", s.batchVerdict) // 0.29.0 批量裁决

	// 切片四:一键分析主链路 + 判定改判 + 内容树 + 规则统计(§6.1~§6.3)
	s.mux.HandleFunc("POST /api/cases/{id}/analyze", s.startAnalyze)
	s.mux.HandleFunc("POST /api/sources/{id}/detect", s.overrideDetect)
	s.mux.HandleFunc("GET /api/cases/{id}/artifact-tree", s.artifactTree)
	s.mux.HandleFunc("GET /api/cases/{id}/rules/stats", s.ruleStats)

	// 切片五:AI 沟通区(§7;AI nil 时 503 如实,外发闸关 403 如实)
	s.mux.HandleFunc("GET /api/ai/settings", s.aiSettingsGet)
	// 系统配置写 = admin 专属(0.26.0 角色闸;GET 设置/AI 会话全角色)
	s.mux.HandleFunc("PUT /api/ai/settings", s.requireAdmin(s.aiSettingsPut))
	s.mux.HandleFunc("POST /api/ai/settings/test-proxy", s.requireAdmin(s.aiTestProxy))   // 切片十一:代理自测
	s.mux.HandleFunc("POST /api/ai/settings/test-search", s.requireAdmin(s.aiTestSearch)) // 切片十一:搜索自测
	s.mux.HandleFunc("GET /api/ai/settings/presets", s.aiPresetsGet)                      // 0.27.0:厂商预设表
	s.mux.HandleFunc("POST /api/ai/settings/fetch-models", s.requireAdmin(s.aiFetchModels)) // 0.27.0:拉模型清单
	s.mux.HandleFunc("POST /api/ai/sessions", s.aiCreateSession)
	s.mux.HandleFunc("GET /api/cases/{id}/ai/sessions", s.aiListSessions)
	s.mux.HandleFunc("GET /api/ai/sessions/{id}", s.aiGetSession)
	s.mux.HandleFunc("POST /api/ai/sessions/{id}/messages", s.aiPostMessage)
	s.mux.HandleFunc("POST /api/ai/sessions/{id}/abort", s.aiAbort)

	// 切片六:意图链(§6/§6.4;引擎 nil 时 503 如实)
	s.mux.HandleFunc("GET /api/playbooks", s.listPlaybooks)
	s.mux.HandleFunc("GET /api/cases/{id}/intents", s.listIntents)
	s.mux.HandleFunc("GET /api/cases/{id}/intents/events", s.intentEvents)
	s.mux.HandleFunc("GET /api/cases/{id}/activity", s.caseActivity) // 0.23.0 播报板轮询兜底
	// 0.24.0-convergence:停车场(L2)+ 预算可观测(L1)
	s.mux.HandleFunc("GET /api/cases/{id}/parking", s.caseParking)
	s.mux.HandleFunc("POST /api/parking/{id}/deploy", s.parkingDeploy)
	s.mux.HandleFunc("POST /api/parking/{id}/dismiss", s.parkingDismiss)
	s.mux.HandleFunc("POST /api/parking/batch", s.parkingBatch) // 0.29.0 批量处置
	s.mux.HandleFunc("GET /api/cases/{id}/budget", s.caseBudget)
	s.mux.HandleFunc("GET /api/cases/{id}/blackboard", s.caseBlackboard) // 0.28.0 案件黑板
	s.mux.HandleFunc("POST /api/cases/{id}/intents", s.createIntent)
	s.mux.HandleFunc("GET /api/cases/{id}/coverage", s.coverage)
	// 交互改造切片三:报告 tab(模板化骨架,不走 LLM)
	s.mux.HandleFunc("GET /api/cases/{id}/report", s.report)
	// 0.31.0 研判报告(形态二,LLM 生成,opt-in 烧 token):生成(归档案
	// 409 同纪律)/版本清单/版本详情(内容含动态拼的报告头)。
	s.mux.HandleFunc("POST /api/cases/{id}/report/narrative", s.narrativeGenerate)
	s.mux.HandleFunc("GET /api/cases/{id}/report/narrative", s.narrativeList)
	s.mux.HandleFunc("GET /api/cases/{id}/report/narrative/{version}", s.narrativeGet)
	s.mux.HandleFunc("GET /api/intents/{id}", s.getIntent)
	s.mux.HandleFunc("POST /api/intents/{id}/approve", s.approveIntent)
	s.mux.HandleFunc("POST /api/intents/{id}/stop", s.stopIntent)
	// 交互改造切片三:运行中操控(设计 §3)——steer 纠偏 / add_hint 线索 /
	// 操作约束 CRUD
	s.mux.HandleFunc("POST /api/intents/{id}/steer", s.steerIntent)
	s.mux.HandleFunc("POST /api/cases/{id}/hints", s.addHint)
	s.mux.HandleFunc("GET /api/cases/{id}/constraints", s.listConstraints)
	s.mux.HandleFunc("POST /api/cases/{id}/constraints", s.addConstraint)
	s.mux.HandleFunc("DELETE /api/cases/{id}/constraints/{cid}", s.deleteConstraint)

	s.mux.HandleFunc("GET /api/audit/chain", s.auditChain)
	s.mux.HandleFunc("GET /api/audit/verify", s.auditVerify)

	// 切片十(ARTEX 布局全量复刻):仪表盘/LLM 录制/工作空间/日志/全局审批
	s.mux.HandleFunc("GET /api/stats/overview", s.statsOverview)
	s.mux.HandleFunc("GET /api/llm/records", s.llmRecordsList)
	s.mux.HandleFunc("GET /api/llm/records/{id}", s.llmRecordGet)
	// 切片十一:工作空间文件管理器(ARTEX workspace 复刻;根=DataDir/workspace,
	// 与 vault 金库物理隔离;写操作进审计,路径逃逸负样本焊死)
	// 切片十三:按案件隔离——/api/cases/{id}/workspace/* 是案件工作区
	// (workspace/<case_id>/,AI 只读工具同域);旧全局端点降级为「未分配」
	// 遗留区(兼容旧数据),案件目录在全局区清单滤除、首段命中案件 id 400。
	s.mux.HandleFunc("GET /api/workspace/list", s.wsList)
	s.mux.HandleFunc("GET /api/workspace/file", s.wsFile)
	s.mux.HandleFunc("GET /api/workspace/download", s.wsDownload)
	s.mux.HandleFunc("POST /api/workspace/upload", s.wsUpload)
	s.mux.HandleFunc("POST /api/workspace/mkdir", s.wsMkdir)
	s.mux.HandleFunc("PUT /api/workspace/file", s.wsWrite)
	s.mux.HandleFunc("DELETE /api/workspace/entry", s.wsDelete)
	s.mux.HandleFunc("GET /api/cases/{id}/workspace/list", s.wsList)
	s.mux.HandleFunc("GET /api/cases/{id}/workspace/file", s.wsFile)
	s.mux.HandleFunc("GET /api/cases/{id}/workspace/download", s.wsDownload)
	s.mux.HandleFunc("POST /api/cases/{id}/workspace/upload", s.wsUpload)
	s.mux.HandleFunc("POST /api/cases/{id}/workspace/mkdir", s.wsMkdir)
	s.mux.HandleFunc("PUT /api/cases/{id}/workspace/file", s.wsWrite)
	s.mux.HandleFunc("DELETE /api/cases/{id}/workspace/entry", s.wsDelete)
	s.mux.HandleFunc("GET /api/logs", s.logsTail)
	s.mux.HandleFunc("GET /api/approvals", s.approvalsGlobal)

	// 0.19.0 启发式知识库:合一清单 + 用户条目 CRUD + 内置条目启停
	// (全局 KB 写 = admin 专属(0.26.0 角色闸);GET 与案件级勾选全角色)
	s.mux.HandleFunc("GET /api/kb", s.listKB)
	// 0.30.0:建案预勾选(单一数据源在 kb.PrecheckTags;前端向导也走这里)
	s.mux.HandleFunc("GET /api/kb/precheck", s.precheckKB)
	s.mux.HandleFunc("POST /api/kb", s.requireAdmin(s.createKB))
	s.mux.HandleFunc("PUT /api/kb/{id}", s.requireAdmin(s.updateKB))
	s.mux.HandleFunc("DELETE /api/kb/{id}", s.requireAdmin(s.deleteKB))
	// 0.20.0 案件级 KB 勾选:本案勾选视图 + 整体覆写(审计 kb.case_update)
	s.mux.HandleFunc("GET /api/cases/{id}/kb", s.getCaseKB)
	s.mux.HandleFunc("PUT /api/cases/{id}/kb", s.putCaseKB)
	return s
}

// Handler 登录闸中间件 + 路由:/api/ 走 API mux,其余 GET 走内嵌前端
// (切片 8a,go:embed 单二进制;SPA 回退在 webui.Handler)。
func (s *Server) Handler() http.Handler {
	static := webui.Handler()
	return s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			s.mux.ServeHTTP(w, r)
			return
		}
		static.ServeHTTP(w, r)
	}))
}

const sessionCookie = "fengtu_session"

// publicPaths 登录闸外端点。
func publicPath(p string) bool {
	return p == "/api/health" || p == "/api/auth/setup" || p == "/api/auth/login"
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") || publicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie(sessionCookie)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "未登录")
			return
		}
		user, err := s.deps.Auth.Authenticate(r.Context(), cookie.Value)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "会话校验失败: "+err.Error())
			return
		}
		if user == nil {
			writeErr(w, http.StatusUnauthorized, "会话无效或已过期")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(
			r.Context(), userKey{}, user)))
	})
}

type userKey struct{}

func userFrom(ctx context.Context) *auth.User {
	u, _ := ctx.Value(userKey{}).(*auth.User)
	return u
}

// requireAdmin 角色闸(0.26.0-m4-multiuser):非 admin 一律 403「需要管理员
// 权限」。包在用户管理/系统配置写/全局 KB 写端点上;案件操作全角色放开。
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := userFrom(r.Context())
		if u == nil || u.Role != auth.RoleAdmin {
			writeErr(w, http.StatusForbidden, "需要管理员权限")
			return
		}
		next.ServeHTTP(w, r)
	}
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: s.deps.CookieSecure, MaxAge: maxAge,
	})
}

// ---- JSON 助手 ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体 JSON 解析失败: "+err.Error())
		return false
	}
	return true
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"ok": "true", "version": s.deps.Version,
	})
}
