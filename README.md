<div align="center">

# 丰图（FengTu）

**面向应急响应的服务端分析平台——意图链驱动，人裁决，证据链不可断**

采集包上传 → 解析入库 → 意图链 AI 排查 → 人裁决 → 出报告

[快速开始](#快速开始docker-compose推荐) · [功能地图](#功能地图截图) · [硬件配置](#硬件配置推荐) · [安全声明](#安全声明与免责声明请先读我)

</div>

丰图是**本地优先、人主导**的应急分析平台：外勤采集包（WinInfoSC / LinuxSC）
上传后，解析管线把行式日志与 Windows 取证产物（evtx/registry/MFT/Prefetch/
lnk/USN/EFU/JumpList/浏览器/SRUM 等）归一入库，规则引擎与适用域算子跑出
候选，意图链 AI 沿 playbook 逐册排查——**一切机器产物都是候选，收官定论归人**。

## 亮点

- **意图链驱动排查**——playbook 14 册模板播种「目标 → 意图 → 事实/发现」
  血缘图，planner 派发 + worker 执行（单意图单 AI 会话、只读工具集）；
  人随时手写意图进图、行内停止/纠偏。
- **黑板机制**——每个 worker 开工注入同一份案件黑板（兄弟分支在查什么、
  已确认什么、什么存疑、停车场有什么），多分支并行不重复劳动、不撞车。
- **收敛三闸 + 停车场**——扇出/章/案三层预算闸硬核收敛，防意图链发散爆炸；
  超闸线索不丢，进停车场记账，展开/丢弃永远人批。
- **证据链不可断**——原件进只读金库（SHA256 内容寻址），每条判断锚定
  「主机 + 源 + 行号 + SHA256」，操作全进审计哈希链。
- **人在环**——规则命中、算子发现、AI 结论一律进待审区；AI/规则派生的
  批量意图过审批门，人批准才运行；全站禁「确认」类措辞。
- **双报告形态**——结构化报告模板化生成、零 LLM、血缘可回溯；
  研判报告（AI 初稿）opt-in 单独计 token，两账分立，收官定论归人。
- **多用户与零外联默认**——admin/operator 两档角色 + 登录锁定；
  数据不出机、无遥测，AI 外发是唯一数据出口且默认关闭。
- **两代实战项目的算子族融合**——日志级（索图：速率突刺/周期信标/
  复合键离群/稀有值跨键/多步链）与主机级（树庭：认证链/持久化/进程
  伪装/凭据面）两套在真实案件里打磨过的算子族，在丰图合并为一套
  15 个适用域算子（web/host/cross 三域），数值口径与 Python 原版
  逐案对拍一致——确定性计算不经过 AI、可复算、零幻觉。

## 安全声明与免责声明（请先读我）

**合理地怀疑一切——包括本工具的输出。**

- **本工具仅用于获得授权的安全分析、应急响应与取证场景。** 使用者须确保
  对分析对象拥有合法授权；作者不对任何滥用行为承担责任。
- **规则、统计、算子、AI 的一切产出都是「候选」**，不构成对任何主体的
  最终定性结论。平台不为你的研判背书——背书的是人。任何由本工具辅助
  得出的结论，在采信前都应回到原始证据独立复核。
- **数据不出机**：全部数据（案件库/金库/账号）存于运行数据目录，无遥测、
  无回传。AI 外发是唯一的数据出口，且默认关闭：需人工开闸并配置 key；
  key 只存 AES-GCM 密文或走环境变量，永不入库明文。
- **取证完整性是纪律不是功能**：原件只读金库 + SHA256 校验 + 审计哈希链
  能证明「平台没改过数据」，但不能证明「数据本身是真的」——采集与移交
  链路的可信度仍由人负责。
- 本软件按「现状」提供，无任何明示或默示担保（详见 LICENSE）。安全工具
  自身也是攻击面：请按 docs/DEPLOY.md 的绑定与口令纪律部署，
  默认口令/占位口令必须更换。

## 硬件配置推荐

按实测数据给（非推算）：

| 场景 | 配置 | 实测锚点 |
|---|---|---|
| 最小可用（小案件/试用） | 4C / 8G / SSD | 4C VM 跑通 1943 源、220 万事件的勒索案全链 |
| 推荐（日常应急） | 8C / 16G / NVMe | 解析与扫描吃 CPU 核数，核多线性提速 |
| 舒适（大案件/多案并行） | 16C / 16G+ / NVMe | 16C VPS 实测 1.5G 采集包摄入 335 秒、零坏行 |

- 磁盘按案件量估：单案约「采集包大小 × 3」（金库原件 + 事件库 + 索引），
  100G 约容 20 个中型案件；归档/删除策略见 docs/USAGE.md。
- ClickHouse 内存上限默认 8G（compose 里可调），大案扫描防 OOM。
- 带宽只影响上传：25Mbps 传 1.5G 采集包约 8 分钟，分析过程不吃带宽。

## 三条铁律

1. **判断权归人**——规则命中、算子发现、AI 结论一律进待审区等人裁决；
   全站禁「确认」类措辞。
2. **证据链不可断**——原件进金库只读（SHA256 内容寻址），每条判断锚定
   「主机 + 源 + 行号 + SHA256」，操作全进审计哈希链。
3. **如实不装死**——查不到、没覆盖、预算耗尽、数据缺失，一律如实标注，
   零静默、不硬编结论。

## 架构（一张图）

```
采集端(独立项目): WinInfoSC.bat / LinuxSC.sh —— 外勤采集,打 zip 回传
        │  HTTPS 分块上传 + 断点续传 + SHA256 对账
        ▼
┌─ fengtu server(Go 单二进制,前端 embed 内置,零外部静态依赖) ──────────┐
│  ingress  上传接入/校验/登记                                           │
│  ingest   解析管线(行式日志走 desc YAML 描述;evtx/hive/MFT/Prefetch/  │
│           lnk/USN/EFU/JumpList/浏览器/SRUM 等走 Go 原生解析器)         │
│  review   规则引擎(configs/rules YAML)+ 适用域算子(configs/operators) │
│  intent   意图链引擎:planner 派发 + worker 执行(单意图单 AI 会话,     │
│           只读工具集),playbook = 意图链模板(configs/playbooks)         │
│  agentloop AI 薄壳:外发闸/预算熔断/审计锚点                            │
│  kb       启发式知识库(configs/kb 内置 + 用户条目,按案件勾选注入)      │
│  web      HTTP API(net/http)+ 内嵌前端(React/Vite 构建产物 go:embed)  │
└────────────────────────────────────────────────────────────────────────┘
        │                │                    │
        ▼                ▼                    ▼
  PostgreSQL 16    ClickHouse 25.x      data/ 目录(本地盘)
  案件/用户/审计链  事件/实体(列存)      vault/  原件金库(只读)
                                      tmp/    上传暂存
                                      workspace/ 案件工作区
```

## 快速开始（Docker Compose，推荐）

依赖：Docker（29.x 实测）+ compose v2。一栈三服务：丰图单二进制
（前端 embed 进镜像）+ PostgreSQL 16 + ClickHouse 25.8。

```bash
# 1) 配环境(口令三处同串:POSTGRES_PASSWORD=FENGTU_PG 口令段;
#    CLICKHOUSE_PASSWORD=FENGTU_CH_PASS;端口绑定缺省 127.0.0.1=仅本机)
cp .env.example .env && chmod 600 .env && $EDITOR .env

# 2) 构建并起栈(Go 依赖走 vendor/ 内嵌,构建期零外网拉取;
#    国内加速可加 --build-arg NPM_REGISTRY=https://registry.npmmirror.com)
docker compose build
docker compose up -d

# 3) 首启建管理员:浏览器打开 http://127.0.0.1:8200 按引导创建
#    (只能建一次;口令 ≥8 位且含字母+数字)
```

完整环境变量表、systemd 裸机部署、升级与备份见 `docs/DEPLOY.md`。

## 功能地图（截图）

> 以下截图全部摄于**全合成演示实例**：案件名 `demo-*`、主机 `DEMO-WIN01`/
> `demo-lnx01`、IP 均为 RFC5737 文档段（203.0.113.x / 198.51.100.x），
> 不含任何真实案件数据。演示实例 AI 外发闸保持关闭（零 token 消耗），
> 故审批/停车场页呈现的是如实空态。

### 总览

登录与首启引导——首次部署一次性创建管理员，此后只剩登录门（失败锁定进审计）。

![登录页](docs/screenshots/01-login.png)

仪表盘——案件/数据源/候选/待裁决/待审批全局一屏，近 7 天活动与案件状态分布。

![仪表盘](docs/screenshots/02-dashboard.png)

任务列表——案件台账：类型、状态、源/候选/待裁决计数，右侧是审计链实时流水。

![任务列表](docs/screenshots/03-tasks.png)

新建应急任务向导——类型/背景模板/多包上传/目的预设/知识库勾选，创建即跳案件页。

![新建任务向导](docs/screenshots/04-new-case.png)

全局发现——跨案件候选汇总，按严重度/状态/案件过滤，逐条挂证据等级。

![全局发现](docs/screenshots/18-findings.png)

### 案件工作台

探索链路——意图链血缘图逐帧生长（目标/意图/事实/发现/线索五型五色），
右栏播报板实时态势流，支持手写意图进图与行内停止/纠偏。

![探索链路与播报板](docs/screenshots/05-case-graph.png)

候选发现——规则/算子命中逐条锚定「源 + 行号」，接受/排除由人裁决
（并发 CAS 防撞），命中≠结论。

![候选发现](docs/screenshots/06-candidates.png)

内容树——采集包目录树 + 原文回查（行号锚点），候选卡/对话锚点一键跳原文。

![内容树](docs/screenshots/07-tree.png)

检索——全文词 + 字段条件 + 时间窗 + 源多选，3000 万行实测亚秒~秒级。

![检索](docs/screenshots/08-search.png)

时间线——全源按小时聚合密度；无时区源单列、如实不参与时间窗过滤。

![时间线](docs/screenshots/09-timeline.png)

### 收敛与人审

审批门——AI/规则派生的批量执行意图创建即挂起，人批准才运行；
批准/拒绝全进审计哈希链（截图为零 AI 演示实例的如实空态）。

![审批](docs/screenshots/10-approvals.png)

停车场——预算闸拦下的派生线索记账待处置，三闸额度账本一目了然，
展开/丢弃永远人批（截图同为零 AI 演示空态）。

![停车场](docs/screenshots/11-parking.png)

黑板——案件实时状态四段只读视图（已确认事实/存疑发现/在意意图/停车场），
每个 worker 开工注入的同一份。

![黑板](docs/screenshots/12-blackboard.png)

报告——结构化报告模板化生成、不走 LLM：结论先行 + 分章排查结论 +
血缘回溯 + Markdown 下载；收官定论归人。

![结构化报告](docs/screenshots/13-report.png)

### 协作与管理

工作空间——按案件隔离的补充材料管理器（文本在线编辑、写操作进审计），
与原件金库物理隔离，AI 会话只读可见。

![工作空间](docs/screenshots/14-workspace.png)

知识库——内置 32 条启发式方法论 + 用户条目，按案件勾选注入 AI，
不兜底全量。

![知识库](docs/screenshots/15-kb.png)

系统配置——AI 外发总开关默认关（关=一切厂商调用 403）、key 只存
AES-GCM 密文永不回显、预算闸/并发上限/代理/联网搜索集中管理。

![系统配置](docs/screenshots/16-settings.png)

用户管理——admin/operator 两档角色，登录锁定与后端自伤保护。

![用户管理](docs/screenshots/17-users.png)

### 覆盖与状态（文字版）

| 功能 | 状态 | 入口 |
|---|---|---|
| 新建任务向导（类型/背景/多包上传/目的预设/KB 勾选） | ✅ | 侧边栏「新建应急任务」 |
| 上传接入（分块/断点续传/哈希对账/采集清单校验） | ✅ | 向导内上传卡 |
| 解析管线（desc 行式 + Windows 12 类原生解析器 + LinuxSC 采集包） | ✅（Windows 覆盖明细见 docs/coverage-matrix.md） | 上传后自动 |
| 意图链排查（planner/worker + playbook 14 册模板） | ✅ | 案件页「探索链路」tab |
| 播报板（实时态势流，行内停止/纠偏） | ✅（历史不回放，重启即空，如实） | 案件页右栏 |
| 审批门（AI/规则派生的批量意图过人批） | ✅ | 案件页「审批」tab |
| 停车场（预算闸拦下的派生线索，人批展开/丢弃） | ✅ | 案件页「停车场」tab |
| 候选发现 + 裁决（接受/排除，并发 CAS 409） | ✅ | 案件页「候选发现」tab |
| 内容树（采集项目录树 + 原文回查 + 格式改判） | ✅ | 案件页「内容树」tab |
| 检索（全文/字段条件/时间窗/源多选） | ✅（3000 万行实测亚秒~秒级） | 案件页「检索」tab |
| 时间线（小时桶密度 + 无时区源单列） | ✅ | 案件页「时间线」tab |
| 工作空间（按案件隔离的文件管理器，AI 可读） | ✅ | 案件页「工作区」tab |
| 知识库（内置条目 + 用户条目，按案件勾选注入 AI） | ✅ | 案件页「知识库」tab |
| 操作约束（人工红线，注入 worker，fail-closed） | ✅ | 案件页「约束」tab |
| 规则/算子（签名规则 + 适用域算子，YAML 数据文件人可换） | ✅（盘点见 docs/operator-inventory.md） | 扫描随一键分析 |
| 报告（模板化骨架 + 血缘子图 + markdown 下载） | ✅（不走 LLM；收官定论归人） | 案件页「报告」tab |
| 多用户（admin/operator 两档 + 登录锁定） | ✅（案件无行级隔离，团队共享口径） | /system/users |
| 封存导出/导入（单 zip，跨实例迁移，哈希逐文件对账） | ✅ | 案件页头「导出封存包」 |
| AI 外发（DeepSeek 默认，OpenAI 线格式可换） | ⚠️ 默认关（外发闸），需人工开闸+配 key | /system/settings |

已知边界（如实）：

- 重启后卡 running 的意图不自动回收（worker 随进程死）；播报板/任务台账是
  进程内存态，重启即空（结果数据不受影响）。
- 意图图是 SVG 逐帧渲染，数百节点以上的大案未实测。
- LinuxSC 部分采集面（init.d/xdg-autostart/轮转压缩包等）暂按原文登记
  可检索、未字段化（暂缓项清单见 docs/operator-inventory.md），随版本扩展。

## 配置要点

- **口令三处同串**：`POSTGRES_PASSWORD` = `FENGTU_PG` 口令段；
  `CLICKHOUSE_PASSWORD` = `FENGTU_CH_PASS`；占位口令必须更换。
- **绑定纪律**：丰图 web 口缺省只绑 `127.0.0.1`（`FENGTU_BIND_IP` 控制）；
  要给团队访问走内网 IP 或 TLS 反代，反代后 `FENGTU_COOKIE_SECURE=true`。
- **AI 外发默认关**：不配 key 时 AI 端点 503/外发闸 403，其余功能不受影响；
  开闸在 `/system/settings`，key 只存 AES-GCM 密文或走环境变量。
- **内存保险丝**：ClickHouse 侧 `deploy/ch-limits.xml`（缺省 8GB，
  按机型自调）与应用层会话级 4GB 保险丝叠加。
- 全量 24 个 `FENGTU_*` 环境变量见 `cmd/fengtu/main.go` 头部注释与
  `docs/DEPLOY.md`。

## 从源码构建

依赖：Go ≥ 1.26、Node.js 18+（仅前端构建需要，产物 embed 进二进制）。

```bash
cd frontend && npm install && npm run build && cd ..
go build -o bin/fengtu ./cmd/fengtu
./bin/fengtu        # 缺省监听 127.0.0.1:8200;启动自动跑 PG 迁移,失败拒启
```

## 测试

```bash
go vet ./... && go test ./...      # 后端(含 golden 金标准对照,不碰真库)
cd frontend && npm test            # 前端 vitest(上传流状态机/裁决交互等)
```

纪律：解析器对 spec 写不对值写；代码与测试中不得出现任何具体案件数据值
（防过拟合负样本测试焊死）；金标准由独立的 Python 参照引擎生成、离线对照。

## 文档索引

- `DESIGN.md` —— 平台设计书（定位/选型/意图链/性能军令状/里程碑）
- `docs/DEPLOY.md` —— 从零部署手册（依赖/env 全表/systemd/升级/备份/排障）
- `docs/USAGE.md` —— 用户操作手册（登录到出报告全链路）
- `docs/EXTEND.md` —— 配置扩展手册（desc/rules/operators/playbooks/kb 怎么加自己的）
- `docs/coverage-matrix.md` —— WinInfoSC 采集项解析覆盖矩阵
- `docs/operator-inventory.md` —— 算子/规则盘点对照表

## 特别鸣谢

- **[ARTEX](https://github.com/Autumn-27/ARTEX)** —— 意图链交互与布局
  设计灵感来源：探索链路图、播报板、黑板、收敛三闸等交互形态均受
  ARTEX 启发（后端语义与数据模型为丰图独立实现）。
- `testdata/parsers/NTUSER.DAT` 来自 velocidex/regparser（Apache-2.0）；
  金标准对照基准由同作者的索图（SuoTu）Python 引擎生成。

## License

[Apache License 2.0](./LICENSE)（Copyright 2026 ye-mengwen）。
二次开发请保留版权声明并显著标注改动。
