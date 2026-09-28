// 新建任务向导纯逻辑(交互改造,设计依据 fengtu-interaction-design.md §1):
// 应急类型枚举/背景模板/目的预设都是**数据**(对 spec 写:增删改本表即可,
// 判定逻辑不动;零具体案件值,防过拟合)。字段上限与后端 createCase 同值
// (后端是权威校验,这里只做提交前拦截,双端漂移由契约测试焊死)。

import type { UploadStage } from "./uploadFlow";

// ---- 应急类型(固定枚举;与后端 incidentTypes 白名单同表) ----

export interface BgTemplate {
  id: string;
  label: string;
  text: string; // 选模板回填背景 textarea(照抄 ARTEX TaskTemplateControls 机制)
}

export interface IncidentType {
  id: string; // 落库值(后端白名单)
  label: string;
  hint: string;
  templates: BgTemplate[];
  recommendedGoals: string[]; // 该类型的目的预设默认勾选(预设 id)
}

// 背景四段骨架(设计 §1:发现经过/影响面/已知 IOC/时间窗)。
function bgSkeleton(focus: string): string {
  return `【发现经过】${focus}\n【影响面】\n【已知 IOC】\n【时间窗】\n`;
}

export const INCIDENT_TYPES: IncidentType[] = [
  {
    id: "ransomware",
    label: "勒索响应",
    hint: "文件被加密/勒索信,需还原加密窗口与进入路径",
    templates: [
      { id: "discovery", label: "标准勒索接报", text: bgSkeleton("何时由谁发现加密/勒索信,首例机器") },
    ],
    recommendedGoals: ["impact-scope", "persistence", "timeline"],
  },
  {
    id: "webshell",
    label: "WebShell 排查",
    hint: "网站目录发现可疑脚本,需定位上传入口与后续动作",
    templates: [
      { id: "discovery", label: "标准 WebShell 接报", text: bgSkeleton("谁扫到/何文件,站点与中间件") },
    ],
    recommendedGoals: ["entry-point", "persistence", "timeline"],
  },
  {
    id: "intrusion",
    label: "入侵排查",
    hint: "告警或异常登录触发,需确认是否真进来、进来做了什么",
    templates: [
      { id: "discovery", label: "标准入侵接报", text: bgSkeleton("触发告警/异常现象,首见时间") },
    ],
    recommendedGoals: ["entry-point", "impact-scope", "persistence", "timeline"],
  },
  {
    id: "data-leak",
    label: "数据泄露",
    hint: "疑似数据外发,需界定泄露面与通道",
    templates: [
      { id: "discovery", label: "标准泄露接报", text: bgSkeleton("何处发现疑似泄露数据,涉及哪些库表/目录") },
    ],
    recommendedGoals: ["exfil-surface", "impact-scope", "timeline"],
  },
  {
    id: "other",
    label: "其他",
    hint: "不在上列的应急场景",
    templates: [
      { id: "discovery", label: "通用接报", text: bgSkeleton("") },
    ],
    recommendedGoals: [],
  },
];

export function incidentTypeById(id: string): IncidentType | undefined {
  return INCIDENT_TYPES.find((t) => t.id === id);
}

// ---- 应急目的预设(复选+自由补充;落库即多条 goal 节点,预设优先) ----

export interface GoalPreset {
  id: string;
  label: string; // 落库/播种文本(后端不再翻译,原样落 goal 节点)
}

export const GOAL_PRESETS: GoalPreset[] = [
  { id: "entry-point", label: "确认入侵入口" },
  { id: "impact-scope", label: "确定影响范围" },
  { id: "persistence", label: "找驻留点(持久化)" },
  { id: "exfil-surface", label: "数据泄露面" },
  { id: "timeline", label: "攻击时间线" },
];

// ---- 案件级 KB 勾选(0.20.0-case-kb) ----
// 0.30.0-report-ux:预勾选映射表收口到后端 kb.PrecheckTags(单一数据源),
// 前端经 GET /api/kb/precheck?incident_type=x 取勾选集,不再自持映射——
// 此前双端各一张表,API/脚本建案不传 kb_entries 时后端零勾选裸奔(验收
// 缺口)。本地 KB_PRECHECK/preselectKB 已退役,别再加回来。

// ---- 一键分析 playbook 建议(0.26.1-analyze-button):按应急类型预选模板 ----
// 映射是数据表;建议值只是下拉框默认选中,人可改,判断权归人。
export const PLAYBOOK_SUGGEST: Record<string, string> = {
  ransomware: "ransomware-triage",
  webshell: "linux-webshell-chain",
  intrusion: "host-triage",
  "data-leak": "data-exfil",
  other: "general-triage",
};

export function suggestPlaybook(incidentType?: string): string {
  return (incidentType && PLAYBOOK_SUGGEST[incidentType]) || "general-triage";
}

// ---- 字段上限(与后端 createCase 同值,契约测试焊死) ----

export const LIMITS = {
  nameMaxRunes: 128,
  backgroundMaxRunes: 4000,
  goalsMaxCount: 12,
  goalTextMaxRunes: 300,
} as const;

// collectGoals 勾选的预设 id + 自由补充 → 最终落库文本数组
// (预设 id → label 翻译;去重保序;空白剔除;超上限如实报错文本,null=合法)。
export function collectGoals(
  checkedIds: string[],
  customs: string[],
): { goals?: string[]; error?: string } {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const id of checkedIds) {
    const p = GOAL_PRESETS.find((g) => g.id === id);
    if (!p) return { error: `未知目的预设: ${id}` };
    if (!seen.has(p.label)) {
      seen.add(p.label);
      out.push(p.label);
    }
  }
  for (const c of customs) {
    const t = c.trim();
    if (!t) continue; // 空白条目如实跳过
    if (t.length > LIMITS.goalTextMaxRunes) {
      return { error: `应急目的单条过长(≤${LIMITS.goalTextMaxRunes} 字)` };
    }
    if (!seen.has(t)) {
      seen.add(t);
      out.push(t);
    }
  }
  if (out.length > LIMITS.goalsMaxCount) {
    return { error: `应急目的条数超上限(≤${LIMITS.goalsMaxCount} 条)` };
  }
  return { goals: out };
}

export interface CreateInput {
  name: string;
  incidentType: string;
  background: string;
  goals: string[]; // collectGoals 产物
}

// validateCreate 提交前校验(返回错误文案,null=可提交;与后端同规则)。
export function validateCreate(input: CreateInput): string | null {
  if (!input.name.trim()) return "任务名称必填";
  if (input.name.trim().length > LIMITS.nameMaxRunes) {
    return `任务名称过长(≤${LIMITS.nameMaxRunes} 字)`;
  }
  if (!incidentTypeById(input.incidentType)) return "请选择应急类型";
  if (input.background.length > LIMITS.backgroundMaxRunes) {
    return `应急背景过长(≤${LIMITS.backgroundMaxRunes} 字)`;
  }
  return null;
}

// anyLocalBusy 上传中禁提交(设计 §1):本地阶段(校验/会话/上传中)未完成
// 时不许创建;进入服务端摄入(ingesting)后不阻塞——摄入账在任务页可见。
export function anyLocalBusy(stages: UploadStage[]): boolean {
  return stages.some((s) => s === "hashing" || s === "init" || s === "uploading");
}

// anyFailed 有失败卡片(提示重试或移除,不阻塞提交——失败包未摄入,如实)。
export function anyFailed(stages: UploadStage[]): boolean {
  return stages.some((s) => s === "failed");
}
