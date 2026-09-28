// 案件黑板(0.28.0-blackboard)模型(与后端 intent.Blackboard 对齐)。
// 数据源:GET /api/cases/{id}/blackboard——与 worker systemExtra 注入同一份
// 派生逻辑(后端 buildBlackboard),前端不另算。只读视图:人在这里一眼看到
// 「AI 现在知道什么」;操作(展开/丢弃停车场)仍走停车场 tab 人批。

export interface BlackboardAnchor {
  source_id?: string;
  line_no?: number;
  hit_id?: string;
  note?: string;
}

export interface BlackboardFact {
  node_id: string;
  text: string;
  anchors: BlackboardAnchor[];
}

export interface BlackboardDoubt {
  node_id: string;
  intent: string;
  summary: string;
}

export interface BlackboardIntent {
  node_id: string;
  text: string;
  status: string; // open|running|awaiting_approval|supported|denied|doubt|closed...
}

export interface BlackboardParking {
  id: string;
  node_id: string;
  text: string;
  reason: string; // budget_*|park_lead|dup_exact|dup_similar
  suggest_label?: string;
  created_at: string;
}

export interface Blackboard {
  case_id: string;
  facts: BlackboardFact[];
  facts_total: number;
  doubts: BlackboardDoubt[];
  doubts_total: number;
  intents: BlackboardIntent[];
  intents_total: number;
  parking: BlackboardParking[];
  parking_total: number;
}
