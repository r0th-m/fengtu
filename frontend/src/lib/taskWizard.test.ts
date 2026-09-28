// 新建任务向导纯逻辑测试(数据表 + 校验/收集函数;负样本焊死上限与枚举)。
import { describe, expect, it } from "vitest";
import {
  anyFailed,
  anyLocalBusy,
  collectGoals,
  GOAL_PRESETS,
  INCIDENT_TYPES,
  incidentTypeById,
  LIMITS,
  validateCreate,
} from "./taskWizard";

describe("应急类型/目的预设数据表", () => {
  it("五类枚举,id 唯一;每类至少一个背景模板", () => {
    expect(INCIDENT_TYPES.map((t) => t.id)).toEqual([
      "ransomware", "webshell", "intrusion", "data-leak", "other",
    ]);
    for (const t of INCIDENT_TYPES) {
      expect(t.templates.length).toBeGreaterThan(0);
      expect(t.templates[0].text).toContain("【发现经过】");
      expect(t.templates[0].text).toContain("【时间窗】");
    }
  });

  it("推荐勾选必须引用存在的预设 id(防数据表悬空引用)", () => {
    const ids = new Set(GOAL_PRESETS.map((g) => g.id));
    for (const t of INCIDENT_TYPES) {
      for (const g of t.recommendedGoals) {
        expect(ids.has(g), `${t.id} 推荐了不存在的预设 ${g}`).toBe(true);
      }
    }
  });

  it("预设 label 非空且唯一(落库去重键=文本)", () => {
    const labels = GOAL_PRESETS.map((g) => g.label);
    expect(new Set(labels).size).toBe(labels.length);
    for (const l of labels) expect(l.trim()).not.toBe("");
  });
});

describe("collectGoals", () => {
  it("预设 id → label,保序去重,空白自由补充剔除", () => {
    const r = collectGoals(["entry-point", "timeline"], [" 自定义目的 ", "", "确认入侵入口"]);
    expect(r.error).toBeUndefined();
    expect(r.goals).toEqual(["确认入侵入口", "攻击时间线", "自定义目的"]);
  });

  it("未知预设 id 如实报错", () => {
    expect(collectGoals(["ghost"], []).error).toContain("未知目的预设");
  });

  it("负样本:自由补充单条超长", () => {
    const r = collectGoals([], ["目".repeat(LIMITS.goalTextMaxRunes + 1)]);
    expect(r.error).toContain("过长");
  });

  it("负样本:总数超上限", () => {
    const customs = Array.from({ length: LIMITS.goalsMaxCount }, (_, i) => `目的${i}`);
    const r = collectGoals(["entry-point"], customs);
    expect(r.error).toContain("超上限");
  });

  it("空选=空数组(合法,目的可后补)", () => {
    expect(collectGoals([], []).goals).toEqual([]);
  });
});

describe("validateCreate", () => {
  const ok = {
    name: "演练案", incidentType: "ransomware", background: "背景", goals: ["确认入侵入口"],
  };
  it("合法输入放行", () => {
    expect(validateCreate(ok)).toBeNull();
  });
  it("负样本:名称空/超长、类型非法", () => {
    expect(validateCreate({ ...ok, name: "  " })).toContain("必填");
    expect(validateCreate({ ...ok, name: "案".repeat(LIMITS.nameMaxRunes + 1) })).toContain("过长");
    expect(validateCreate({ ...ok, incidentType: "ghost" })).toContain("应急类型");
  });
  it("负样本:背景超长", () => {
    expect(validateCreate({ ...ok, background: "背".repeat(LIMITS.backgroundMaxRunes + 1) })).toContain("过长");
  });
});

describe("上传门禁", () => {
  it("本地阶段(校验/会话/上传中)禁提交", () => {
    expect(anyLocalBusy(["hashing"])).toBe(true);
    expect(anyLocalBusy(["init"])).toBe(true);
    expect(anyLocalBusy(["uploading"])).toBe(true);
  });
  it("服务端摄入中不阻塞提交;完成/失败/空闲不阻塞", () => {
    expect(anyLocalBusy(["ingesting"])).toBe(false);
    expect(anyLocalBusy(["done", "failed", "idle"])).toBe(false);
  });
  it("失败卡片可识别(提示重试/移除)", () => {
    expect(anyFailed(["done", "failed"])).toBe(true);
    expect(anyFailed(["done", "ingesting"])).toBe(false);
  });
});

describe("incidentTypeById", () => {
  it("命中/未命中", () => {
    expect(incidentTypeById("webshell")?.label).toBe("WebShell 排查");
    expect(incidentTypeById("ghost")).toBeUndefined();
  });
});

// ---- 案件级 KB 预勾选已收口后端(0.30.0;GET /api/kb/precheck,
// 映射表 kb.PrecheckTags 单一数据源) ----

// ---- 一键分析 playbook 建议(0.26.1-analyze-button):按应急类型预选模板 ----

import { suggestPlaybook, PLAYBOOK_SUGGEST } from "./taskWizard";

describe("playbook 建议映射(类型→模板,数据表)", () => {
  it("五类应急类型都有建议(防数据表缺类)", () => {
    for (const t of ["ransomware", "webshell", "intrusion", "data-leak", "other"]) {
      expect(PLAYBOOK_SUGGEST[t], `类型 ${t} 缺 playbook 建议`).toBeTruthy();
    }
  });

  it("勒索→ransomware-triage;未知/空→general-triage 兜底", () => {
    expect(suggestPlaybook("ransomware")).toBe("ransomware-triage");
    expect(suggestPlaybook("webshell")).toBe("linux-webshell-chain");
    expect(suggestPlaybook("ghost")).toBe("general-triage");
    expect(suggestPlaybook(undefined)).toBe("general-triage");
  });
});
