// 新建应急任务向导(交互改造切片一,设计依据 fengtu-interaction-design.md §1):
// 一步页内分区块(不学多步 wizard——单页够用,多步拖慢应急):
//   ① 任务名称 ② 应急类型(固定枚举单选) ③ 应急背景(模板下拉回填)
//   ④ 采集包多包上传卡(每包一张状态卡:文件名/大小/SHA256/状态,
//     复用 POST /api/uploads 上传链,选中即传、可多次追加、上传中禁提交)
//   ⑤ 应急目的预设(复选+自由补充,落库即 goal 节点)
//   ⑥ 知识库条目勾选(0.20.0 起本案生效=勾选;0.27.1 起可选池=全部条目,
//     启停概念退役;按应急类型预勾选,支持全选/全不选)
// 创建后跳转案件页(设计 §1:应急场景用户下一步一定是看任务)。
import { ChangeEvent, DragEvent, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, putChunk } from "../lib/api";
import { hashFile } from "../lib/sha256";
import { UploadDeps, UploadFlow, UploadState } from "../lib/uploadFlow";
import {
  anyFailed,
  anyLocalBusy,
  collectGoals,
  GOAL_PRESETS,
  INCIDENT_TYPES,
  incidentTypeById,
  validateCreate,
} from "../lib/taskWizard";
import { watchTask } from "../lib/watch";
import type { CaseInfo, KBEntry } from "../lib/types";
import Tip from "../components/Tip";

const STAGE_LABEL: Record<string, string> = {
  hashing: "校验",
  init: "会话",
  uploading: "上传",
  ingesting: "摄入",
  done: "完成",
  failed: "失败",
};

interface PackItem {
  key: string;
  file: File;
  state: UploadState;
}

function fmtSize(n: number): string {
  if (n >= 1 << 30) return (n / (1 << 30)).toFixed(2) + " GiB";
  if (n >= 1 << 20) return (n / (1 << 20)).toFixed(1) + " MiB";
  if (n >= 1024) return (n / 1024).toFixed(1) + " KiB";
  return n + " B";
}

export default function NewCasePage() {
  const nav = useNavigate();
  const [name, setName] = useState("");
  const [incidentType, setIncidentType] = useState("intrusion");
  const [background, setBackground] = useState("");
  const [items, setItems] = useState<PackItem[]>([]);
  const [checkedGoals, setCheckedGoals] = useState<string[]>(
    incidentTypeById("intrusion")?.recommendedGoals ?? [],
  );
  const [customGoals, setCustomGoals] = useState<string[]>([]);
  const [customInput, setCustomInput] = useState("");
  // 案件级 KB 勾选(0.20.0):按应急类型预勾选,人可增删;
  // 0.27.1 起可选池=全部条目(启停概念退役)
  const [kbPool, setKbPool] = useState<KBEntry[]>([]);
  const [checkedKB, setCheckedKB] = useState<string[]>([]);
  const [kbErr, setKbErr] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [submitErr, setSubmitErr] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const flowsRef = useRef(new Map<string, UploadFlow>());
  const seqRef = useRef(0);

  // 任务名锁定:已有包卡片后改名会把后续包挂到别的案件,锁死并如实提示
  const nameLocked = items.length > 0;
  const stages = items.map((it) => it.state.stage);
  const localBusy = anyLocalBusy(stages);
  const failedCount = items.filter((it) => it.state.stage === "failed").length;

  // KB 可选池装载(0.27.1 起=全部条目,不再按 enabled 过滤);
  // 预勾选走后端端点(0.30.0:映射表单一数据源在 kb.PrecheckTags,
  // 前端不再自持表——API/脚本建案也套同一张表)
  useEffect(() => {
    api
      .get<{ entries: KBEntry[] }>("/api/kb")
      .then((d) => setKbPool(d.entries || []))
      .catch((e) => setKbErr(e instanceof Error ? e.message : String(e)));
    applyPrecheck("intrusion");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 预勾选序号闸:快速连切类型时慢响应不得覆盖新选择(如实以最新一次为准)
  const precheckSeq = useRef(0);
  function applyPrecheck(typeId: string) {
    const seq = ++precheckSeq.current;
    api
      .get<{ selected: string[] }>(
        `/api/kb/precheck?incident_type=${encodeURIComponent(typeId)}`)
      .then((d) => {
        if (seq === precheckSeq.current) setCheckedKB(d.selected || []);
      })
      .catch((e) => {
        if (seq !== precheckSeq.current) return;
        // 预勾选装载失败如实清空+提示,人手动勾(不兜底全勾,判断权归人)
        setCheckedKB([]);
        setKbErr("预勾选装载失败,已清空勾选,请手动勾选: " +
          (e instanceof Error ? e.message : String(e)));
      });
  }

  // 上传链依赖(复用 hero 同一条 POST /api/uploads 链;案件名在
  // flow.start(file, caseName) 显式传入——多包挂同一任务,不靠文件名推)
  const deps = useMemo<UploadDeps>(
    () => ({
      hashFile,
      initUpload: (body) =>
        api.post("/api/uploads", body) as Promise<{ upload_id: string; chunk_size: number }>,
      putChunk: (id, idx, buf) => putChunk(`/api/uploads/${id}/chunks/${idx}`, buf),
      completeUpload: (id) =>
        api.post(`/api/uploads/${id}/complete`) as Promise<{ task_id: string }>,
      watchTask,
      findCaseIdByName: async (n) => {
        const d = await api.get<{ cases: CaseInfo[] }>("/api/cases");
        return d.cases.find((c) => c.name === n)?.id ?? null;
      },
    }),
    [],
  );

  function addFiles(files: File[]) {
    if (files.length === 0) return;
    // 任务名空 → 从首个包文件名取(去扩展名,与 hero 同规则),随后锁定
    let effective = name.trim();
    if (!effective) {
      effective = UploadFlow.caseNameFromFile(files[0].name);
      setName(effective);
    }
    const next: PackItem[] = [];
    for (const f of files) {
      seqRef.current += 1;
      const key = `pack-${seqRef.current}`;
      const flow = new UploadFlow(deps, (s) => {
        setItems((prev) =>
          prev.map((it) => (it.key === key ? { ...it, state: s } : it)),
        );
      });
      flowsRef.current.set(key, flow);
      next.push({ key, file: f, state: { ...flow.state, fileName: f.name } });
    }
    setItems((prev) => [...prev, ...next]);
    // 包卡选中即传(设计 §1 照抄 UX:创建页内直接传、可多次追加)
    for (const it of next) {
      void flowsRef.current.get(it.key)!.start(it.file, effective);
    }
  }

  function retryItem(key: string) {
    const flow = flowsRef.current.get(key);
    const item = items.find((it) => it.key === key);
    if (!flow || !item) return;
    flow.reset();
    void flow.start(item.file, name.trim());
  }

  function removeItem(key: string) {
    // 仅失败卡片可移除;已摄入的包不会因移除卡片而退出案件(如实,不假装回收)
    const item = items.find((it) => it.key === key);
    if (!item || item.state.stage !== "failed") return;
    flowsRef.current.delete(key);
    setItems((prev) => prev.filter((it) => it.key !== key));
  }

  function onTypeChange(id: string) {
    setIncidentType(id);
    // 类型驱动目的预设推荐(设计 §1:类型驱动默认排查目标预设);
    // 换类型即重套推荐——用户手动勾选以最近一次类型为准,如实不记忆
    setCheckedGoals(incidentTypeById(id)?.recommendedGoals ?? []);
    // KB 预勾选同理(0.30.0 起走后端 /api/kb/precheck,映射表单一数据源)
    applyPrecheck(id);
  }

  function addCustomGoal() {
    const t = customInput.trim();
    if (!t) return;
    setCustomGoals((prev) => [...prev, t]);
    setCustomInput("");
  }

  async function submit() {
    setSubmitErr("");
    const { goals, error } = collectGoals(checkedGoals, customGoals);
    if (error) {
      setSubmitErr(error);
      return;
    }
    const verr = validateCreate({
      name, incidentType, background, goals: goals ?? [],
    });
    if (verr) {
      setSubmitErr(verr);
      return;
    }
    setSubmitting(true);
    try {
      const d = await api.post<{ case: CaseInfo; goals_seeded: number; note?: string }>(
        "/api/cases",
        { name: name.trim(), incident_type: incidentType, background, goals: goals ?? [],
          kb_entries: checkedKB },
      );
      // 创建即跳任务页(设计 §1 照抄 ARTEX 修正项:创建完成直接跳转)
      nav(`/cases/${d.case.id}`);
    } catch (e) {
      setSubmitErr(e instanceof Error ? e.message : String(e));
      setSubmitting(false);
    }
  }

  const tpls = incidentTypeById(incidentType)?.templates ?? [];

  return (
    <div className="min-h-full">
      {/* 页头(切片四:TopBar 退役,壳层 AppShell 接管;页内标题照抄 ARTEX 页头形态) */}
      <main className="max-w-3xl mx-auto px-5 py-6 space-y-5">
        <div>
          <h1 className="text-base font-semibold">新建应急任务</h1>
          <p className="text-xs text-mute mt-0.5">
            应急类型 / 背景 / 采集包 / 目的预设——创建即跳案件页,摄入与分析后台跟进
          </p>
        </div>
        {/* ① 任务名称 */}
        <section className="rounded-card bg-white shadow-card p-5">
          <SectionHead n={1} title="任务名称" tip="案件容器名;与上传链 EnsureCase 同名复用——已在跑的包挂在本案,改名会把后续包挂到别的案件,故加包后锁定" />
          <input
            value={name}
            disabled={nameLocked}
            onChange={(e) => setName(e.target.value)}
            placeholder="如:勒索响应-财务服务器(留空则从首个采集包文件名取)"
            className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm
              focus:outline-none focus:ring-2 focus:ring-brand/40 disabled:bg-slate-50 disabled:text-mute"
          />
          {nameLocked && (
            <div className="mt-1.5 text-[11px] text-mute">
              已挂采集包,名称锁定——改名会把后续包挂到别的案件(同名复用按名称归并)
            </div>
          )}
        </section>

        {/* ② 应急类型 */}
        <section className="rounded-card bg-white shadow-card p-5">
          <SectionHead n={2} title="应急类型" tip="固定枚举;类型驱动目的预设的默认勾选(换类型重套推荐)" />
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
            {INCIDENT_TYPES.map((t) => (
              <Tip key={t.id} text={t.hint}>
                <button
                  onClick={() => onTypeChange(t.id)}
                  className={`w-full rounded-xl px-2 py-2.5 text-sm font-medium ring-1 transition-colors ${
                    incidentType === t.id
                      ? "bg-brand text-white ring-brand shadow-sm"
                      : "bg-white text-ink ring-slate-200 hover:bg-brand-light/50"
                  }`}
                >
                  {t.label}
                </button>
              </Tip>
            ))}
          </div>
        </section>

        {/* ③ 应急背景 */}
        <section className="rounded-card bg-white shadow-card p-5">
          <div className="flex items-center justify-between mb-2">
            <SectionHead n={3} title="应急背景" tip="自由文本;选模板回填四段骨架(发现经过/影响面/已知 IOC/时间窗)——照抄 ARTEX 选模板回填机制" />
            <select
              defaultValue=""
              onChange={(e: ChangeEvent<HTMLSelectElement>) => {
                const t = tpls.find((x) => x.id === e.target.value);
                if (t) setBackground(t.text);
                e.target.value = "";
              }}
              className="rounded-lg border border-slate-200 px-2 py-1 text-xs text-mute
                focus:outline-none focus:ring-2 focus:ring-brand/40"
            >
              <option value="" disabled>
                选模板回填…
              </option>
              {tpls.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.label}
                </option>
              ))}
            </select>
          </div>
          <textarea
            value={background}
            onChange={(e) => setBackground(e.target.value)}
            rows={5}
            placeholder="发现经过、影响面、已知 IOC、时间窗……(可选模板一键回填骨架)"
            className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm leading-relaxed
              focus:outline-none focus:ring-2 focus:ring-brand/40"
          />
        </section>

        {/* ④ 采集包上传 */}
        <section className="rounded-card bg-white shadow-card p-5">
          <SectionHead
            n={4}
            title="采集包"
            tip="一次任务可挂多个采集包(zip);选中即传、可多次追加;每包进摄取队列,状态卡全程可见(零黑盒转圈);上传中禁提交"
          />
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e: DragEvent) => {
              e.preventDefault();
              setDragOver(false);
              addFiles(Array.from(e.dataTransfer.files || []));
            }}
            className={`rounded-xl border-2 border-dashed px-4 py-6 text-center transition-colors ${
              dragOver ? "border-brand bg-brand-light/40" : "border-brand/30"
            }`}
          >
            <input
              ref={inputRef}
              type="file"
              multiple
              className="hidden"
              onChange={(e) => {
                addFiles(Array.from(e.target.files || []));
                e.target.value = "";
              }}
            />
            <div className="text-sm text-ink">拖入采集包(zip),可多个</div>
            <div className="mt-1 text-[11px] text-mute">
              WinInfoSC 包 / 日志 zip / 单文件;选中即开始上传,上传中不可提交任务
            </div>
            <button
              onClick={() => inputRef.current?.click()}
              className="mt-3 rounded-lg bg-brand-light text-brand text-xs font-medium px-4 py-1.5
                hover:bg-brand hover:text-white transition-colors"
            >
              添加采集包
            </button>
          </div>
          {items.length > 0 && (
            <ul className="mt-3 space-y-2">
              {items.map((it) => (
                <PackCard
                  key={it.key}
                  item={it}
                  onRetry={() => retryItem(it.key)}
                  onRemove={() => removeItem(it.key)}
                />
              ))}
            </ul>
          )}
          {failedCount > 0 && (
            <div className="mt-2 text-[11px] text-amber-700">
              {failedCount} 个包失败(未摄入,不阻塞创建)——可重试或移除后重新添加
            </div>
          )}
        </section>

        {/* ⑤ 应急目的 */}
        <section className="rounded-card bg-white shadow-card p-5">
          <SectionHead
            n={5}
            title="应急目的"
            tip="预设复选+自由补充;落库即意图图 goal 节点(goal 先行,引擎后动;此处不触发 AI 分析)"
          />
          <div className="flex flex-wrap gap-2">
            {GOAL_PRESETS.map((g) => {
              const on = checkedGoals.includes(g.id);
              return (
                <button
                  key={g.id}
                  onClick={() =>
                    setCheckedGoals((prev) =>
                      on ? prev.filter((x) => x !== g.id) : [...prev, g.id],
                    )
                  }
                  className={`rounded-full px-3 py-1.5 text-xs font-medium ring-1 transition-colors ${
                    on
                      ? "bg-brand text-white ring-brand"
                      : "bg-white text-ink ring-slate-200 hover:bg-brand-light/50"
                  }`}
                >
                  {g.label}
                </button>
              );
            })}
          </div>
          {customGoals.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-2">
              {customGoals.map((g, i) => (
                <span
                  key={`${g}-${i}`}
                  className="rounded-full bg-brand-light text-brand px-3 py-1.5 text-xs
                    inline-flex items-center gap-1.5"
                >
                  {g}
                  <button
                    className="text-brand/60 hover:text-brand"
                    onClick={() => setCustomGoals((prev) => prev.filter((_, j) => j !== i))}
                  >
                    ×
                  </button>
                </span>
              ))}
            </div>
          )}
          <div className="mt-2.5 flex gap-2">
            <input
              value={customInput}
              onChange={(e) => setCustomInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  addCustomGoal();
                }
              }}
              placeholder="自由补充目的,回车添加"
              className="flex-1 rounded-lg border border-slate-200 px-3 py-1.5 text-xs
                focus:outline-none focus:ring-2 focus:ring-brand/40"
            />
            <button
              onClick={addCustomGoal}
              className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs text-mute hover:text-ink"
            >
              添加
            </button>
          </div>
        </section>

        {/* ⑥ 知识库勾选(0.27.1:本案生效=勾选;可选池=全部条目;全选/全不选) */}
        <section className="rounded-card bg-white shadow-card p-5" data-testid="kb-section">
          <div className="flex items-center justify-between mb-2.5">
            <SectionHead
              n={6}
              title="知识库条目"
              tip="本案勾选的启发式条目才注入 AI worker 参考段(省 token,不再全量全局注入);按应急类型预勾选,人可增删/全选/全不选;一条不勾=本案不注入,案内可再改"
            />
            <div className="flex gap-2 shrink-0">
              <button
                onClick={() => setCheckedKB(kbPool.map((e) => e.id))}
                disabled={kbPool.length === 0}
                className="rounded-lg border border-slate-200 px-2.5 py-1 text-[11px] text-mute
                  hover:text-ink disabled:opacity-40"
                data-testid="kb-select-all"
              >
                全选
              </button>
              <button
                onClick={() => setCheckedKB([])}
                disabled={checkedKB.length === 0}
                className="rounded-lg border border-slate-200 px-2.5 py-1 text-[11px] text-mute
                  hover:text-ink disabled:opacity-40"
                data-testid="kb-select-none"
              >
                全不选
              </button>
            </div>
          </div>
          {kbErr && (
            <div className="mb-2 rounded-lg bg-amber-50 text-amber-700 text-xs px-3 py-2">
              知识库清单装载失败(不阻塞建案,勾选为空): {kbErr}
            </div>
          )}
          {kbPool.length === 0 && !kbErr ? (
            <div className="text-xs text-mute" data-testid="kb-empty">
              暂无知识库条目(可在「系统 → 知识库」新建);本案将不注入启发式参考
            </div>
          ) : (
            <div className="space-y-1.5" data-testid="kb-options">
              {kbPool.map((en) => {
                const on = checkedKB.includes(en.id);
                return (
                  <label
                    key={en.id}
                    className={`flex items-center gap-2.5 rounded-lg border px-3 py-2 cursor-pointer
                      transition-colors ${on ? "border-brand/50 bg-brand-light/40" : "border-slate-200 hover:bg-slate-50"}`}
                    data-testid={`kb-opt-${en.id}`}
                  >
                    <input
                      type="checkbox"
                      checked={on}
                      onChange={() =>
                        setCheckedKB((prev) =>
                          on ? prev.filter((x) => x !== en.id) : [...prev, en.id],
                        )
                      }
                      className="accent-brand"
                      data-testid={`kb-check-${en.id}`}
                    />
                    <span className="text-xs font-medium text-ink">{en.title}</span>
                    <span
                      className={`rounded-full px-1.5 py-0.5 text-[10px] font-medium
                        ${en.source === "builtin" ? "bg-slate-100 text-slate-600" : "bg-brand-light text-brand"}`}
                    >
                      {en.source === "builtin" ? "内置" : "用户"}
                    </span>
                    <span className="ml-auto flex gap-1">
                      {en.applies_to.map((t) => (
                        <span
                          key={t}
                          className="rounded-full bg-slate-50 border border-slate-200 px-1.5 py-0.5
                            text-[10px] text-slate-500"
                        >
                          {t}
                        </span>
                      ))}
                    </span>
                  </label>
                );
              })}
            </div>
          )}
          <div className="mt-2 text-[11px] text-mute" data-testid="kb-hint">
            已勾 {checkedKB.length} / {kbPool.length} 条 · 勾选即生效(0.27.1 起
            不再有全局启停,知识库页只管条目内容);一条不勾=本案不注入,案内可再改
          </div>
        </section>

        {/* 提交 */}
        {submitErr && (
          <div className="rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2" data-testid="wizard-error">
            {submitErr}
          </div>
        )}
        <button
          data-testid="wizard-submit"
          disabled={submitting || localBusy}
          onClick={() => void submit()}
          className="w-full rounded-xl bg-brand text-white text-sm font-medium py-3
            hover:bg-brand-dark transition-colors shadow-lift
            disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {submitting
            ? "创建中…"
            : localBusy
              ? "采集包上传中,稍后提交…"
              : "创建任务并进入任务页"}
        </button>
        <div className="text-center text-[11px] text-mute pb-6">
          创建后目的预设即落为意图图 goal 节点;AI 排查在任务页按需发起(判断权归人)
        </div>
      </main>
    </div>
  );
}

function SectionHead({ n, title, tip }: { n: number; title: string; tip: string }) {
  return (
    <div className="flex items-center gap-2 mb-2.5">
      <span className="inline-flex items-center justify-center w-5 h-5 rounded-full bg-brand-light text-brand text-[11px] font-semibold">
        {n}
      </span>
      <h2 className="text-sm font-semibold">{title}</h2>
      <Tip text={tip}>
        <span className="text-mute text-xs cursor-help">?</span>
      </Tip>
    </div>
  );
}

// PackCard 采集包状态卡(设计 §1:文件名/大小/SHA256/解析状态,每包一张)。
function PackCard({
  item,
  onRetry,
  onRemove,
}: {
  item: PackItem;
  onRetry: () => void;
  onRemove: () => void;
}) {
  const s = item.state;
  const failed = s.stage === "failed";
  return (
    <li className="rounded-xl ring-1 ring-slate-200 px-3 py-2.5" data-testid="pack-card">
      <div className="flex items-center gap-2">
        <span
          className={`inline-block w-1.5 h-1.5 rounded-full shrink-0 ${
            s.stage === "done"
              ? "bg-brand"
              : failed
                ? "bg-red-500"
                : "bg-amber-400 animate-pulse"
          }`}
        />
        <span className="text-xs font-medium truncate" title={s.fileName}>
          {s.fileName}
        </span>
        <span className="text-[11px] text-mute shrink-0">{fmtSize(item.file.size)}</span>
        <span
          className={`ml-auto shrink-0 rounded-full px-2 py-0.5 text-[11px] ring-1 ${
            failed
              ? "bg-red-50 text-red-700 ring-red-200"
              : s.stage === "done"
                ? "bg-brand-light text-brand ring-brand/20"
                : "bg-slate-50 text-slate-600 ring-slate-200"
          }`}
        >
          {STAGE_LABEL[s.stage] || s.stage}
        </span>
        {failed && (
          <>
            <button className="shrink-0 text-[11px] text-brand underline" onClick={onRetry}>
              重试
            </button>
            <button className="shrink-0 text-[11px] text-mute underline" onClick={onRemove}>
              移除
            </button>
          </>
        )}
      </div>
      {s.sha256 && (
        <div className="mt-1 text-[10px] text-mute font-mono truncate" title={s.sha256}>
          SHA256 {s.sha256}
        </div>
      )}
      {(s.stage === "hashing" || s.stage === "uploading") && (
        <div className="mt-1.5 h-1 rounded-full bg-slate-100 overflow-hidden">
          <div
            className="h-full rounded-full bg-brand transition-all duration-300"
            style={{ width: `${Math.max(s.percent, 4)}%` }}
          />
        </div>
      )}
      <div className={`mt-1 text-[11px] ${failed ? "text-red-600" : "text-mute"}`}>
        {failed ? s.error : s.progress || "排队中"}
      </div>
    </li>
  );
}
