// 后端 API 返回的模型(与 Go struct json tag 对齐,字段只取前端用到的)。

export interface CaseInfo {
  id: string;
  name: string;
  created_at: string;
  sources: number;
  candidates?: number; // 切片 8a:命中候选总数(hits 表计数)
  pending_candidates?: number; // 待裁决数(status=pending)
  incident_type?: string; // 应急类型(向导落库;空=旧案件未填)
  background?: string; // 应急背景
  goal_presets?: string[]; // 应急目的预设(落库文本)
  archived_at?: string | null; // 归档时刻(0.18.0;null/缺=活跃)
}

export interface SourceInfo {
  id: string;
  case_id: string;
  path: string;
  sha256: string;
  size_bytes: number;
  kind: string;
  artifact_type: string;
  log_type: string;
  host: string;
  package: string;
  detect_format: string;
  detect_confidence: number | null;
  detect_status: string;
}

export interface Task {
  id: string;
  kind: string; // ingest | scan | analyze | parse
  status: string; // running | done | failed
  progress: string;
  detail?: unknown;
  err?: string;
  created_at: string;
  finished_at?: string | null;
}

export interface Hit {
  id: string;
  case_id: string;
  source_id: string;
  line_no: number;
  rule_id: string;
  severity: string; // info|low|medium|high
  matched_field: string;
  matched_value: string;
  snippet: string;
  ts_utc: string | null;
  status: string; // pending|accepted|rejected
  round_no: number;
  evidence_grade: string; // strong 强疑似|suspect 疑似|weak 弱信号
  created_at: string;
  reviewed_by?: string;
  review_note?: string;
}

export interface TreeNode {
  name: string;
  path: string;
  type: "dir" | "source";
  children?: TreeNode[];
  source_id?: string;
  kind?: string;
  artifact_type?: string;
  log_type?: string;
  size_bytes?: number;
  lines?: number;
  status?: string;
  detect_format?: string;
  detect_confidence?: number | null;
}

export interface RuleInfo {
  id: string;
  title: string;
  severity: string;
}

export interface OperatorInfo {
  id: string;
  title: string;
  implemented: boolean;
}

export interface AuditEntry {
  Seq: number;
  CaseID: string;
  TS: string;
  Actor: string;
  Action: string;
  Scope: string;
  DetailJSON: string;
}

export interface AISession {
  id: string;
  case_id: string;
}

export interface SourceLine {
  no: number;
  text: string;
}

// QueryEvent 检索层事件(非文本源的事件视图用;raw=CH 原文列)。
export interface QueryEvent {
  source_id: string;
  line_no: number;
  ts: string | null;
  kind: string;
  fields: string;
  raw: string;
}

// NavAnchor 锚点跳转目标(候选卡/聊天 chip → 内容树对应源+行)。
// seq 单调递增,重复跳同一锚也触发。
export interface NavAnchor {
  sourceId: string;
  lineNo: number;
  seq: number;
}

// ---- 报告(交互改造切片三;0.30.0-report-ux 可读性重构:结论先行/攻击时间线/
// 分章结论/证据附录;GET /api/cases/{id}/report,模板化不走 LLM) ----

export interface ReportFinding {
  id: string;
  rule_id: string;
  severity: string;
  evidence_grade: string;
  snippet: string;
  ts_utc: string | null;
  reviewed_by: string;
  reviewed_at?: string;
  source_id: string;
  line_no: number;
  host: string; // 空=未建模散件(如实)
  source_path: string;
  source_sha256: string;
}

export interface ReportFactAnchor {
  source_id?: string;
  line_no?: number;
  hit_id?: string;
  note?: string;
  host?: string;
  source_path?: string;
  source_sha256?: string;
}

export interface ReportFact {
  id: string; // 血缘子图锚(按 id 回溯)
  text: string;
  evidence: ReportFactAnchor[];
}

// ReportChapter 分章结论(0.30.0):goal 章+机器评估态+章内 supported 账+结论清单。
export interface ReportChapter {
  goal_id: string;
  goal_text: string;
  status: string; // goal 机器评估态(原样;STATUS_LABEL 映射呈现)
  intents_total: number;
  intents_supported: number;
  facts: ReportFact[];
}

// ReportTimelineItem 攻击时间线一条(仅锚点可解析出事件时间的发现/结论)。
export interface ReportTimelineItem {
  ts_utc: string;
  kind: string; // finding|fact
  text: string; // 一句话(后端已截断)
  fact_id?: string; // kind=fact 时的血缘回溯锚
  host: string;
  source_id: string;
  source_path: string;
  line_no: number;
  source_sha256: string;
}

// ReportEvidenceItem 证据附录一行(锚点去重:源+行;refs=被引次数)。
export interface ReportEvidenceItem {
  host: string;
  source_id: string;
  source_path: string;
  line_no: number;
  source_sha256: string;
  refs: number;
}

export interface ReportData {
  case_id: string;
  case_name: string;
  incident_type: string;
  background: string;
  generated_at: string;
  hosts: string[]; // 已建模主机键清单(空=未建模散件,如实)
  window_from: string | null; // 时间窗(结论先行;null=无 ts 可解析,如实)
  window_to: string | null;
  chapters: ReportChapter[]; // 分章结论(核心判断清单同源)
  orphan_facts: ReportFact[]; // 归属不上任何章的结论(如实单列)
  findings: ReportFinding[]; // 人裁决 accepted,严重度降序
  timeline: ReportTimelineItem[];
  timeline_total: number;
  timeline_truncated: boolean; // 超 50 条截断(如实)
  evidence: ReportEvidenceItem[]; // 附录:锚点去重清单
  evidence_truncated: boolean;
  hits_pending: number;
  hits_accepted: number;
  hits_rejected: number;
  findings_truncated: boolean;
  sources_total: number;
  sources_explored: number;
  intent_ready: boolean; // false=意图引擎未装配,章节/覆盖区段缺失(如实)
  advice: string[]; // 模板建议,需人核
}

// ---- 研判报告(形态二,0.31.0-narrative-report):AI 生成初稿(定论归人),
// 版本递增保留历史;生成 opt-in(明示消耗 token 二次确认) ----

export interface CaseReportMeta {
  id: string;
  case_id: string;
  kind: string; // narrative
  version: number;
  tokens_in: number;
  tokens_out: number;
  truncated: boolean; // token 预算熔断截断(如实)
  created_by: string;
  created_at: string;
}

// CaseConstraint 案件级操作约束(交互改造切片三,设计 §3 set_constraints
// 应急映射;人增人删,注入 worker system 最高优先,增删进审计链)。
export interface CaseConstraint {
  id: string;
  case_id: string;
  text: string;
  created_by: string;
  created_at: string;
}

// ---- 平台页(切片十,ARTEX dashboard/llm-records/workspace/logs/approvals
// 应急映射;与后端 handlers_platform.go 返回形状对齐) ----

export interface OverviewStats {
  cases: number;
  sources: number;
  candidates: number; // 命中≠结论:机器候选
  pending_candidates: number; // 待裁决(判断权归人入口)
  pending_approvals: number; // 待审批意图
  llm_records: number;
  activity: { day: string; count: number }[]; // 近 7 天审计链日条数(UTC)
}

export interface CaseStatusBuckets {
  pending: number;
  reviewed: number;
  ingested: number;
  empty: number;
}

export interface LLMRecord {
  id: string;
  session_id: string;
  case_id: string;
  kind: string; // chat|intent
  model: string;
  status: string; // ok|error
  err?: string;
  tokens_in: number;
  tokens_out: number;
  duration_ms: number;
  prompt?: string; // 仅 record_mode=full 期间录制
  response?: string;
  created_at: string;
}

// ---- 工作空间文件管理器(切片十一,ARTEX workspace 复刻;
// 与后端 handlers_workspace.go 返回形状对齐) ----

export interface WorkspaceEntry {
  name: string;
  path: string; // 相对工作区根的 slash 路径
  dir: boolean;
  size: number;
  mtime: number; // Unix 毫秒
}

export interface WorkspaceFileView {
  name: string;
  path: string;
  size: number;
  mtime: number;
  binary: boolean; // 内容嗅探判定(NUL/控制字符比例),如实不回内容
  too_large: boolean; // >8MB 如实不回内容,只给下载
  content?: string;
}

export interface LogEntry {
  seq: number;
  ts: string;
  line: string;
}

export interface ApprovalPendingItem {
  id: string;
  case_id: string;
  case_name: string;
  text: string;
  created_by: string;
  scope: string;
  host_scope?: string;
  created_at: string;
}

export interface ApprovalHistoryItem {
  seq: number;
  ts: string;
  actor: string;
  action: string; // intent.approve|intent.reject|intent.stop
  case_id: string;
  case_name: string;
  text: string;
}

// AISettings AI 平台设置(/api/ai/settings;api_key 永不回显,只有 key_source)。
export interface AISettings {
  provider: string;
  protocol: string; // openai-compatible|anthropic|ollama(0.27.0)
  base_url: string;
  model: string;
  key_source: string; // env|pg|none(未配置)
  outbound_enabled: boolean;
  budget_tokens: number;
  max_tokens: number;
  rate_per_second: number;
  record_mode: string; // off|metadata|full(LLM 录制档位,默认 metadata)
  agent_concurrency: number; // 意图 worker 全局并发上限(默认 4,010 迁移)
  intent_fanout_limit: number; // 每意图派生扇出上限(默认 5,014 迁移)
  intent_chapter_limit: number; // 每章自动派生意图上限(默认 30)
  intent_case_limit: number; // 每案自动派生意图上限(默认 200)
  global_proxy: string; // 全局出口代理(http/https/socks5,空=直连)
  web_search_enabled: boolean;
  web_search_backend: string; // ddgs|brave-free|tavily
  search_key_set: boolean; // 搜索后端 key 只报有/无,永不回显
}

// ProbeResult 联通性自测回执(test-proxy/test-search;ok=false 时 detail 是失败原文)。
export interface ProbeResult {
  ok: boolean;
  detail: string;
  target?: string;
  backend?: string;
}

// AIProviderPreset 厂商预设(0.27.0;/api/ai/settings/presets,数据驱动)。
export interface AIProviderPreset {
  id: string;
  name: string;
  protocol: string; // openai-compatible|anthropic|ollama
  base_url: string; // 默认端点(可改);custom 为空
  needs_key: boolean; // ollama 本地免 key
  note: string;
}

// FetchModelsResult 模型清单拉取回执(fetch-models;永远 200,
// ok=false 时 detail 是失败原文,不猜)。
export interface FetchModelsResult {
  ok: boolean;
  models: string[];
  detail: string;
  target?: string;
  protocol: string;
}

// KBEntry 启发式知识库条目(0.19.0;builtin=configs/kb YAML 内置,
// user=PG kb_entries 用户沉淀;合一清单标 source)。0.27.1-kb-simplify:
// enabled 字段下线(启停概念退役,条目生效以案件勾选为准,后端不再输出)。
export interface KBEntry {
  id: string;
  title: string;
  content: string;
  applies_to: string[];
  source: "builtin" | "user";
  created_by?: string;
  created_at: string;
  updated_at: string;
}

// UserInfo 用户管理条目(M4;GET /api/users,仅 admin;与 Go json tag 对齐)。
// locked_until=登录连败锁定到点(RFC3339,null=未锁定)。
export interface UserInfo {
  id: string;
  username: string;
  role: string; // admin|operator
  disabled: boolean;
  failed_attempts: number;
  locked_until: string | null;
  created_at: string;
}
