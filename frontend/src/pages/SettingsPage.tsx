// 系统配置页(ARTEX system/settings 多卡瀑布形态):
// 卡 1:AI 厂商设置(0.27.0:厂商预设表联动 base_url/协议 + 拉取模型下拉;
//       api_key 密文永不回显/外发开关/预算);
// 卡 2:Agent 并发上限(切片十一:意图引擎 worker 全局限流,超限排队如实);
// 卡 3:全局代理(切片十一:LLM 请求+联网搜索出站,留空=直连,带联通性自测);
// 卡 4:联网搜索(切片十一:web_search 工具开关+后端+key 密文,带自测);
// 卡 5:LLM 录制档位(record_mode:off|metadata|full);
// 卡 6:版本信息(/api/health 只读);卡 7:常规项占位(自动更新,如实标未启用)。
// AI 未装配(503)时如实显示,不装。
import { useEffect, useState } from "react";
import {
  Brain,
  CheckCircle2,
  Download,
  Gauge,
  Globe,
  Info,
  Radio,
  Search,
  Settings2,
  Zap,
} from "lucide-react";
import { api } from "../lib/api";
import type { AIProviderPreset, AISettings, FetchModelsResult, ProbeResult } from "../lib/types";

function Card({
  icon: Icon,
  title,
  desc,
  children,
}: {
  icon: typeof Brain;
  title: string;
  desc: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-card bg-white shadow-card p-4 mb-4 break-inside-avoid">
      <div className="flex items-center gap-1.5 text-sm font-semibold text-ink">
        <Icon className="w-4 h-4 text-mute" />
        {title}
      </div>
      <div className="text-[11px] text-mute mt-0.5 mb-3">{desc}</div>
      {children}
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block mb-2.5">
      <span className="block text-[11px] text-mute mb-1">{label}</span>
      {children}
    </label>
  );
}

const inputCls = `w-full h-8 rounded-lg border border-slate-200 bg-white px-2.5 text-xs
  focus:outline-none focus:ring-2 focus:ring-brand/40`;

const btnCls = `rounded-lg bg-brand text-white text-xs font-medium px-3.5 py-1.5
  hover:bg-brand-dark transition-colors disabled:opacity-50`;

const btnGhostCls = `rounded-lg border border-slate-200 bg-white text-xs px-3 py-1.5
  text-slate-600 hover:bg-slate-50 transition-colors disabled:opacity-50`;

// ProbeLine 自测回执行(ok 绿/fail 红,原文如实)。
function ProbeLine({ r }: { r: ProbeResult }) {
  return (
    <div
      className={`mt-2 rounded-lg text-xs px-3 py-2 ${
        r.ok ? "bg-emerald-50 text-emerald-700" : "bg-red-50 text-red-700"
      }`}
    >
      {r.ok ? "联通正常" : "自测失败"}:{r.detail}
      {r.target ? <span className="text-mute">(目标 {r.target})</span> : null}
    </div>
  );
}

export default function SettingsPage() {
  const [s, setS] = useState<AISettings | null>(null);
  const [aiDown, setAiDown] = useState("");
  const [version, setVersion] = useState("");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [saving, setSaving] = useState(false);
  // 切片十一:并发/代理/搜索卡的本地编辑态(从设置回填)
  const [conc, setConc] = useState("4");
  const [proxy, setProxy] = useState("");
  const [searchKey, setSearchKey] = useState("");
  // 0.24.0:意图链预算三闸(扇出/章/案;超闸转停车场,人批才展开)
  const [fanout, setFanout] = useState("5");
  const [chapterLim, setChapterLim] = useState("30");
  const [caseLim, setCaseLim] = useState("200");
  const [proxyProbe, setProxyProbe] = useState<ProbeResult | null>(null);
  const [searchProbe, setSearchProbe] = useState<ProbeResult | null>(null);
  const [probing, setProbing] = useState(false);
  // 0.27.0:厂商预设表 + 模型清单拉取(预设拉不到=空表,按「自定义」降级,不装死)
  const [presets, setPresets] = useState<AIProviderPreset[]>([]);
  const [models, setModels] = useState<string[]>([]);
  const [fetchRes, setFetchRes] = useState<FetchModelsResult | null>(null);
  const [fetching, setFetching] = useState(false);

  useEffect(() => {
    api.get<{ settings: AISettings }>("/api/ai/settings")
      .then((d) => setS(d.settings))
      .catch((e) => setAiDown(e instanceof Error ? e.message : String(e)));
    api.get<{ presets: AIProviderPreset[] }>("/api/ai/settings/presets")
      .then((d) => setPresets(d.presets ?? []))
      .catch(() => setPresets([])); // 老后端无此端点:降级自定义,如实
    api.get<{ version?: string }>("/api/health")
      .then((h) => setVersion(h.version ?? ""))
      .catch(() => {});
  }, []);

  // 设置到达/刷新后回填本地编辑态(搜索 key 永不回显,不回填)
  useEffect(() => {
    if (s) {
      setConc(String(s.agent_concurrency || 4));
      setProxy(s.global_proxy ?? "");
      setFanout(String(s.intent_fanout_limit || 5));
      setChapterLim(String(s.intent_chapter_limit || 30));
      setCaseLim(String(s.intent_case_limit || 200));
    }
  }, [s]);

  const save = async (patch: Record<string, unknown>) => {
    setSaving(true);
    setMsg("");
    setErr("");
    try {
      await api.put("/api/ai/settings", patch);
      const d = await api.get<{ settings: AISettings }>("/api/ai/settings");
      setS(d.settings);
      setMsg("已保存");
      setApiKey("");
      setSearchKey("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  // 自测:表单值直测(先测后存);失败也是 200 + {ok:false},如实呈现
  const testProxy = async () => {
    setProbing(true);
    setProxyProbe(null);
    try {
      setProxyProbe(await api.post<ProbeResult>("/api/ai/settings/test-proxy",
        { global_proxy: proxy.trim() }));
    } catch (e) {
      setProxyProbe({ ok: false, detail: e instanceof Error ? e.message : String(e) });
    } finally {
      setProbing(false);
    }
  };

  const testSearch = async () => {
    if (!s) return;
    setProbing(true);
    setSearchProbe(null);
    try {
      setSearchProbe(await api.post<ProbeResult>("/api/ai/settings/test-search", {
        web_search_backend: s.web_search_backend,
        // key 留空=后端回退已存密文(key 永不回显,同 ARTEX 口径)
        ...(searchKey ? { search_api_key: searchKey } : {}),
      }));
    } catch (e) {
      setSearchProbe({ ok: false, detail: e instanceof Error ? e.message : String(e) });
    } finally {
      setProbing(false);
    }
  };

  const needsSearchKey = s != null && s.web_search_backend !== "ddgs";

  // ---- 0.27.0:厂商预设联动 ----
  // provider 对不上预设 id 的存量配置按「自定义」呈现(向后兼容,不改存量值)
  const activePreset = s ? presets.find((p) => p.id === s.provider) : undefined;
  const presetId = activePreset ? activePreset.id : "custom";

  // 选预设:自动填 base_url/协议;custom 保留用户已填的 base_url
  const onPreset = (id: string) => {
    if (!s) return;
    const p = presets.find((x) => x.id === id);
    if (!p) return;
    setS({
      ...s,
      provider: p.id,
      base_url: p.base_url || s.base_url,
      protocol: p.protocol,
    });
    setModels([]);
    setFetchRes(null);
  };

  // 拉取模型:表单值直测(key 留空=后端回退已存密文);失败给原始错误,不猜
  const fetchModels = async () => {
    if (!s) return;
    setFetching(true);
    setFetchRes(null);
    try {
      const r = await api.post<FetchModelsResult>("/api/ai/settings/fetch-models", {
        base_url: s.base_url,
        protocol: s.protocol || "openai-compatible",
        ...(apiKey ? { api_key: apiKey } : {}),
      });
      setFetchRes(r);
      if (r.ok) setModels(r.models);
    } catch (e) {
      setFetchRes({
        ok: false, models: [], protocol: s.protocol || "openai-compatible",
        detail: e instanceof Error ? e.message : String(e),
      });
    } finally {
      setFetching(false);
    }
  };

  return (
    <div className="max-w-[1100px] mx-auto" data-testid="settings-page">
      <div className="mb-4">
        <h1 className="text-xl font-semibold tracking-tight flex items-center gap-2">
          <Settings2 className="w-5 h-5 text-mute" />
          系统配置
        </h1>
        <p className="text-sm text-mute">全局运行时开关(改动即生效;api_key 只存密文永不回显)</p>
      </div>

      {/* 多列瀑布(照抄 ARTEX:columns 防等高撑满) */}
      <div className="columns-1 lg:columns-2">
        <Card
          icon={Brain}
          title="AI 厂商设置"
          desc="选厂商预设自动填 base_url/协议,填 key 后可拉取可用模型;环境变量 FENGTU_AI_* 优先于本设置;外发开关关=一切 AI 端点 403"
        >
          {aiDown ? (
            <div className="rounded-lg bg-amber-50 text-amber-700 text-xs px-3 py-2"
              data-testid="ai-unavailable">
              AI 未启用:{aiDown}
            </div>
          ) : !s ? (
            <div className="text-xs text-mute">加载中…</div>
          ) : (
            <>
              <div className="grid grid-cols-2 gap-2">
                <Field label="厂商">
                  <select
                    value={presetId}
                    onChange={(e) => onPreset(e.target.value)}
                    data-testid="ai-provider"
                    className="h-8 w-full rounded-lg border border-slate-200 bg-white px-2 text-xs text-slate-700"
                  >
                    {presets.map((p) => (
                      <option key={p.id} value={p.id}>{p.name}</option>
                    ))}
                    {!activePreset && <option value="custom">自定义</option>}
                  </select>
                </Field>
                <Field label="协议">
                  <select
                    value={s.protocol || "openai-compatible"}
                    onChange={(e) => setS({ ...s, protocol: e.target.value })}
                    disabled={presetId !== "custom"}
                    data-testid="ai-protocol"
                    className="h-8 w-full rounded-lg border border-slate-200 bg-white px-2 text-xs text-slate-700 disabled:bg-slate-50 disabled:text-slate-500"
                  >
                    <option value="openai-compatible">openai-compatible</option>
                    <option value="anthropic">anthropic</option>
                    <option value="ollama">ollama</option>
                  </select>
                </Field>
              </div>
              {(activePreset || presetId === "custom") && (
                <div className="text-[11px] text-mute -mt-1.5 mb-2.5" data-testid="ai-preset-note">
                  {activePreset
                    ? `${activePreset.note}${activePreset.needs_key ? "" : ";免 API key"}`
                    : "provider 对不上预设,按自定义呈现(存量配置不受影响)"}
                </div>
              )}
              <Field label="Base URL">
                <input className={inputCls} value={s.base_url}
                  onChange={(e) => setS({ ...s, base_url: e.target.value })}
                  data-testid="ai-base-url" />
              </Field>
              <Field label={
                activePreset && !activePreset.needs_key
                  ? "API Key(本档免 key)"
                  : `API Key(当前:${s.key_source};留空=不动)`
              }>
                <input className={inputCls} type="password" value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder="输入即覆盖(只存 AES-GCM 密文)"
                  data-testid="ai-api-key" />
              </Field>
              <Field label="模型(可手输,也可先拉取再选)">
                <input className={inputCls} value={s.model} list="ai-model-options"
                  onChange={(e) => setS({ ...s, model: e.target.value })}
                  data-testid="ai-model" />
                <datalist id="ai-model-options" data-testid="ai-model-list">
                  {models.map((m) => <option key={m} value={m} />)}
                </datalist>
              </Field>
              <div className="flex items-center gap-2 mb-3">
                <button
                  disabled={fetching || !s.base_url}
                  onClick={() => void fetchModels()}
                  data-testid="ai-fetch-models"
                  className={btnGhostCls}
                >
                  {fetching ? "拉取中…" : "拉取模型(GET models,免费不调对话)"}
                </button>
                {fetchRes && (
                  <span
                    className={`text-xs ${fetchRes.ok ? "text-emerald-600" : "text-red-600"}`}
                    data-testid="ai-fetch-result"
                  >
                    {fetchRes.ok ? fetchRes.detail : `拉取失败:${fetchRes.detail}`}
                  </span>
                )}
              </div>
              <div className="grid grid-cols-2 gap-2">
                <Field label="会话 token 预算">
                  <input className={inputCls} type="number" value={s.budget_tokens}
                    onChange={(e) => setS({ ...s, budget_tokens: Number(e.target.value) })}
                    data-testid="ai-budget" />
                </Field>
                <Field label="单回复 token 上限">
                  <input className={inputCls} type="number" value={s.max_tokens}
                    onChange={(e) => setS({ ...s, max_tokens: Number(e.target.value) })} />
                </Field>
              </div>
              <label className="flex items-center gap-2 text-xs text-slate-700 mb-3">
                <input type="checkbox" checked={s.outbound_enabled}
                  onChange={(e) => setS({ ...s, outbound_enabled: e.target.checked })}
                  data-testid="ai-outbound" />
                AI 外发总开关(关=任何厂商调用前 403)
              </label>
              <button
                disabled={saving}
                onClick={() =>
                  void save({
                    provider: s.provider, protocol: s.protocol || "openai-compatible",
                    base_url: s.base_url, model: s.model,
                    outbound_enabled: s.outbound_enabled,
                    session_budget_tokens: s.budget_tokens, max_tokens: s.max_tokens,
                    ...(apiKey ? { api_key: apiKey } : {}),
                  })
                }
                data-testid="ai-save"
                className={btnCls}
              >
                保存 AI 设置
              </button>
            </>
          )}
          {msg && (
            <span className="ml-2 text-xs text-emerald-600 inline-flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" />{msg}
            </span>
          )}
          {err && (
            <div className="mt-2 rounded-lg bg-red-50 text-red-700 text-xs px-3 py-2">{err}</div>
          )}
        </Card>

        <Card
          icon={Zap}
          title="Agent 并发上限"
          desc="意图引擎派发 worker 的全局并发上限(默认 4)。超上限的意图排队等位,过程流如实记「排队中(并发上限 N)」;调低不追回在跑 worker,对之后的派发生效"
        >
          {s ? (
            <>
              <Field label="同时在跑的 worker 上限">
                <input className={inputCls} type="number" min={1} value={conc}
                  onChange={(e) => setConc(e.target.value)}
                  data-testid="agent-concurrency" />
              </Field>
              <button
                disabled={saving}
                onClick={() => void save({ agent_concurrency: Number(conc) })}
                data-testid="agent-concurrency-save"
                className={btnCls}
              >
                保存并发上限
              </button>
            </>
          ) : (
            <div className="text-xs text-mute">
              {aiDown ? "AI 未启用,并发上限不可用(如实)" : "加载中…"}
            </div>
          )}
        </Card>

        <Card
          icon={Gauge}
          title="意图链预算闸"
          desc="三层收敛的 L1(0.24.0):防应急意图链发散爆炸的硬闸——扇出(每条意图一次写回最多派生几条)/章(每册 playbook 章内自动派生上限)/案(每案自动派生总数上限)。超闸的新派生不进图,转停车场等人批;只闸自动派生,人工手写意图/线索不受限。改即对之后派生即时生效,不追回在跑"
        >
          {s ? (
            <>
              <div className="grid grid-cols-3 gap-2">
                <Field label="扇出上限/意图">
                  <input className={inputCls} type="number" min={1} value={fanout}
                    onChange={(e) => setFanout(e.target.value)}
                    data-testid="intent-fanout" />
                </Field>
                <Field label="章意图上限">
                  <input className={inputCls} type="number" min={1} value={chapterLim}
                    onChange={(e) => setChapterLim(e.target.value)}
                    data-testid="intent-chapter-limit" />
                </Field>
                <Field label="案意图总上限">
                  <input className={inputCls} type="number" min={1} value={caseLim}
                    onChange={(e) => setCaseLim(e.target.value)}
                    data-testid="intent-case-limit" />
                </Field>
              </div>
              <button
                disabled={saving}
                onClick={() =>
                  void save({
                    intent_fanout_limit: Number(fanout),
                    intent_chapter_limit: Number(chapterLim),
                    intent_case_limit: Number(caseLim),
                  })
                }
                data-testid="intent-limits-save"
                className={btnCls}
              >
                保存预算闸
              </button>
            </>
          ) : (
            <div className="text-xs text-mute">
              {aiDown ? "AI 未启用,预算闸不可用(如实)" : "加载中…"}
            </div>
          )}
        </Card>

        <Card
          icon={Globe}
          title="全局代理"
          desc="LLM 厂商请求与联网搜索的出站代理(http/https/socks5,可带 user:pass);留空=直连。改配置对之后开始的会话生效"
        >
          {s ? (
            <>
              <Field label="代理 URL(空=直连)">
                <input className={inputCls} value={proxy}
                  onChange={(e) => setProxy(e.target.value)}
                  placeholder="如 http://127.0.0.1:7890 或 socks5://127.0.0.1:1080"
                  data-testid="global-proxy" />
              </Field>
              <div className="flex items-center gap-2">
                <button
                  disabled={saving}
                  onClick={() => void save({ global_proxy: proxy.trim() })}
                  data-testid="global-proxy-save"
                  className={btnCls}
                >
                  保存代理
                </button>
                <button
                  disabled={probing}
                  onClick={() => void testProxy()}
                  data-testid="global-proxy-test"
                  className={btnGhostCls}
                >
                  {probing ? "测试中…" : "测试(表单值直测,经代理 HEAD 当前 base_url)"}
                </button>
              </div>
              {proxyProbe && <ProbeLine r={proxyProbe} />}
            </>
          ) : (
            <div className="text-xs text-mute">
              {aiDown ? "AI 未启用,代理配置不可用(如实)" : "加载中…"}
            </div>
          )}
        </Card>

        <Card
          icon={Search}
          title="联网搜索"
          desc="应急场景查较新的威胁报告/IOC 披露。开关开 且 外发总开关开 才给 AI 挂 web_search 工具(带 key 后端缺 key 如实不挂)。证据链纪律:搜索结果是参考不是证据——网页内容不能当锚点,结论锚点仍只能锚案件采集物(source_id+行号)"
        >
          {s ? (
            <>
              <label className="flex items-center gap-2 text-xs text-slate-700 mb-2.5">
                <input type="checkbox" checked={s.web_search_enabled}
                  onChange={(e) => setS({ ...s, web_search_enabled: e.target.checked })}
                  data-testid="web-search-enabled" />
                启用联网搜索(web_search 工具)
              </label>
              <div className="grid grid-cols-2 gap-2">
                <Field label="搜索后端">
                  <select
                    value={s.web_search_backend}
                    onChange={(e) => setS({ ...s, web_search_backend: e.target.value })}
                    data-testid="web-search-backend"
                    className="h-8 w-full rounded-lg border border-slate-200 bg-white px-2 text-xs text-slate-700"
                  >
                    <option value="ddgs">DuckDuckGo(ddgs,免 key)</option>
                    <option value="brave-free">Brave Search API(需 key)</option>
                    <option value="tavily">Tavily(需 key)</option>
                  </select>
                </Field>
                {needsSearchKey && (
                  <Field label={`搜索 API Key(${s.search_key_set ? "已设置" : "未设置"};留空=不动)`}>
                    <input className={inputCls} type="password" value={searchKey}
                      onChange={(e) => setSearchKey(e.target.value)}
                      placeholder="输入即覆盖(只存 AES-GCM 密文)"
                      data-testid="search-api-key" />
                  </Field>
                )}
              </div>
              <div className="flex items-center gap-2">
                <button
                  disabled={saving}
                  onClick={() =>
                    void save({
                      web_search_enabled: s.web_search_enabled,
                      web_search_backend: s.web_search_backend,
                      ...(searchKey ? { search_api_key: searchKey } : {}),
                    })
                  }
                  data-testid="web-search-save"
                  className={btnCls}
                >
                  保存搜索设置
                </button>
                <button
                  disabled={probing}
                  onClick={() => void testSearch()}
                  data-testid="web-search-test"
                  className={btnGhostCls}
                >
                  {probing ? "测试中…" : "测试(真发一次查询,走全局代理)"}
                </button>
              </div>
              {searchProbe && <ProbeLine r={searchProbe} />}
            </>
          ) : (
            <div className="text-xs text-mute">
              {aiDown ? "AI 未启用,搜索配置不可用(如实)" : "加载中…"}
            </div>
          )}
        </Card>

        <Card
          icon={Radio}
          title="LLM 录制"
          desc="每次厂商调用的台账;默认只记元数据(时间/模型/token/耗时/锚点),全文是 opt-in"
        >
          {s ? (
            <div className="flex items-center gap-2">
              <select
                value={s.record_mode}
                onChange={(e) => void save({ record_mode: e.target.value })}
                data-testid="record-mode-setting"
                className="h-8 rounded-lg border border-slate-200 bg-white px-2 text-xs text-slate-700"
              >
                <option value="off">关闭(不录)</option>
                <option value="metadata">元数据(默认)</option>
                <option value="full">全文 opt-in(prompt/response,截断 8000 字符)</option>
              </select>
              <span className="text-[11px] text-mute">改动即生效(下次调用起)</span>
            </div>
          ) : (
            <div className="text-xs text-mute">
              {aiDown ? "AI 未启用,档位不可用(如实)" : "加载中…"}
            </div>
          )}
        </Card>

        <Card icon={Info} title="版本信息" desc="只读(来自 /api/health)">
          <div className="flex items-center gap-2 text-xs">
            <span className="rounded-md bg-slate-100 px-2 py-1 font-mono" data-testid="settings-version">
              {version || "未知"}
            </span>
            <span className="text-mute">单二进制 embed 前端;升级=换二进制重启</span>
          </div>
        </Card>

        <Card
          icon={Download}
          title="常规项(未启用,如实占位)"
          desc="ARTEX 有而丰图后端无对应语义——陈列仅为布局对齐,不装能用"
        >
          <div className="space-y-2 text-xs text-slate-500">
            <div className="flex items-center gap-2 rounded-lg border border-dashed border-slate-200 px-3 py-2">
              <Download className="w-3.5 h-3.5 text-slate-400" />
              自动更新
              <span className="ml-auto rounded bg-slate-100 px-1.5 py-px text-[10px] text-mute">
                未启用
              </span>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}
