// 停车场(0.24.0-convergence L2)模型与呈现助手(纯函数,可测)。
// 数据源:GET /api/cases/{id}/parking(条目)+ GET /api/cases/{id}/budget(预算)。
// 语义:超闸/AI 登记的未展开线索;展开/丢弃永远人批(AI 收官评估只建议)。

// ParkingEntry 停车场一条(与后端 intent.ParkingEntry 对齐)。
export interface ParkingEntry {
  id: string;
  case_id: string;
  node_id: string; // 对应图上 parked 灰色虚线节点
  text: string; // 线索摘要
  source_node_id?: string; // 来源意图
  suggest_goal_id?: string; // 归属建议:章(goal 节点);空=建议新开章
  suggest_label?: string; // 归属建议人读标签
  reason: string; // budget_fanout|budget_chapter|budget_case|park_lead
  verdict?: string; // 收官评估建议 deploy|dismiss(空=未评估;AI 只建议)
  verdict_reason?: string;
  status: string; // parked|deployed|dismissed
  created_by: string;
  created_at: string;
  decided_at?: string | null;
  decided_by?: string;
}

// BudgetStatus 案件预算消耗(与后端 intent.BudgetStatus 对齐)。
export interface BudgetStatus {
  limits: { fanout: number; chapter: number; case: number };
  case_intents: number; // 案内自动派生意图数(不含 parked)
  chapters: { goal_id: string; title: string; intents: number; limit: number }[];
  parked: number; // 待处置条数
}

// PARK_REASON_LABEL 转入原因如实中文标。
export const PARK_REASON_LABEL: Record<string, string> = {
  budget_fanout: "扇出超闸",
  budget_chapter: "章预算超闸",
  budget_case: "案件预算超闸",
  park_lead: "AI 章外线索申请",
  dup_exact: "重复意图拦截", // 0.28.0 去重闸:归一化完全相同
  dup_similar: "疑似重复(待人裁)", // 0.28.0 去重闸:关键词 Jaccard ≥ 0.85
};

// PARKING_STATUS_LABEL 处置状态标。
export const PARKING_STATUS_LABEL: Record<string, string> = {
  parked: "待处置",
  deployed: "已展开",
  dismissed: "已丢弃",
};

// splitParking 待处置/已处置分区(各自保持创建序;已处置=留痕区)。
export function splitParking(items: ParkingEntry[]): {
  parked: ParkingEntry[];
  decided: ParkingEntry[];
} {
  const parked: ParkingEntry[] = [];
  const decided: ParkingEntry[] = [];
  for (const it of items || []) {
    if (it.status === "parked") parked.push(it);
    else decided.push(it);
  }
  return { parked, decided };
}

// suggestText 归属建议呈现(新开章/章名;空如实标「未给建议」)。
export function suggestText(p: ParkingEntry): string {
  if (p.suggest_label) return p.suggest_label;
  if (p.suggest_goal_id) return "(章已删除,仅剩 id)"; // 如实:快照缺, goal 不在
  return "建议新开章";
}
