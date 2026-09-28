# EXTEND.md —— 配置扩展手册：怎么加一条自己的

> `configs/` 下的一切都是**数据不是代码**：新增日志格式/规则/算子参数/
> playbook/知识库条目，都只改 YAML，不改 Go。共同纪律：
>
> - **装载即校验**：任何文件写错（未知键/坏正则/非法引用），server 启动
>   直接拒启并打出全部问题——改完配置先本地起一次或跑 `go test ./...`
>   （仓内有真实配置目录的焊死测试），别直接上台。
> - **防过拟合**：配置里只写结构特征/通用特征，**永不出现具体案件值**
>   （真实 IP/主机名/家族名）——测试闸会拦。
> - 各目录可用环境变量换路径（`FENGTU_DESC_DIR` 等，见 DEPLOY.md §2）；
>   部署 = 把 configs 同步到部署根，`FENGTU_DATA_DIR` 之外的存量案件
>   数据不受影响，重启生效。

## 1. `configs/desc/` —— 行式日志描述文件（新增日志格式零代码）

一个文件描述一种行式日志格式。字段白名单（写别的键 = 拒载）：

```yaml
name: my-app-log            # 必填,小写+中划线(^[a-z0-9]+(-[a-z0-9]+)*$)
title: 我的应用日志          # 必填,人读名
kind: regex                 # regex | json | csv
log_type: app_log           # 可选,源品类(词表见下);不声明=无品类
encoding: utf-8             # utf-8 | gbk
line_regex: '^(?P<ts>...)'  # kind=regex 必填;命名捕获组
field_map:                  # 捕获组 → 归一字段(归一字段有词表,见下)
  ts: ts_raw                # ts_raw 是保留映射:行内时间不进归一字段
  level: level
  message: message
ts_field: ts                # 时间来源组
ts_formats:                 # 逐个试的时间格式(Go 参考时间/strftime 风格)
- '%Y-%m-%d %H:%M:%S'
ts_optional: true           # 快照型源(无时间戳)显式声明,ts 恒空如实,不伪造
multiline:                  # 可选,多行块合并(堆栈等)
  start_regex: '^\d{4}-'    # 块起始行模式
  max_continuation_lines: 2000
  max_block_bytes: 1000000
status: enable              # draft(草稿) | review | enable
note: 口径与已知差异写这里,不猜
```

- 归一字段词表（field_map 的值）：web 族 `src_ip/method/path/query/status/
  bytes/ua/referer`，审计族 `actor/action/object/result/detail`，通用
  `level/logger/message/exception`，主机族 `command/cmdline`；词表外字段
  不丢——自动落 extras。
- 源品类词表（log_type）：`web_access / app_log / audit_log /
  windows_event_log / usn_journal / generic / command_history /
  net_connection`。品类决定哪些算子会打上来（适用域路由）。**新增品类**
  要先在 `internal/descform/spec.go` 的 LogTypes 加词表（这是数据性质
  的一行代码改动）。
- 时间格式里无年份的（如 log4j 简写日期）归一落 1900 年，如实不猜；
  时区未知就 nil，事件 ts 落空、不参与时间窗——这是语义不是缺陷。

**加一条**：仿照 `configs/desc/pshistory.yaml`（最简单的 regex 样例）或
`tomcat-catalina.yaml`（多行块样例）写一个文件丢进目录，重启。先用
`cmd/ftparse` 离线验证：`ftparse --desc configs/desc/my-app-log.yaml sample.log`。

## 2. `configs/rules/` —— 签名规则（确定性扫描，零 token）

```yaml
id: my-rule                 # ^[a-z0-9][a-z0-9-]{0,63}$,全目录唯一
title: 规则人读名
severity: high              # info | low | medium | high
target: any                 # 事件规则只有 any;另有 entity(见下)
match:                      # 字段条件:不同字段之间 AND,同字段多值 OR
  channel: ["Security"]
  event_id_eq: ["1102"]     # 后缀语义:_contains 子串 / _prefix 前缀 / _eq 精确等值
  data: ["vssadmin", "delete shadows"]  # 裸键 = contains(存量语义,大小写不敏感)
max_hits: 500               # 可选,预算帽,超出记 truncated 不落库
note: 判定要点与口径写这里;末尾习惯带「命中≠结论」
```

- **可用字段**（MatchFields，36 个）：web 面 `src_ip/user/method/path/
  query/status/referer/ua/xff/raw`；主机统一面 `process_name/cmdline/
  parent_process/image_path/target_path/reg_key/reg_value/task_name/
  service_name/event_id/account/ip/domain/sha256/file_name`；解析器原生键
  `event_type/channel/computer/provider/exe_name/key_path/value_name/
  data`；命令历史/连接快照 `command/proto/local_addr/local_port/
  remote_addr/remote_port/state/pid`。词表外字段 = 拒载。
- **evtx 嵌套**：`data` 是 EventData 嵌套对象，串化后参与子串匹配
  （宽筛严判同源，VM 实测对齐）。
- **实体规则**（target: entity，跨机/单机实体匹配，0.25.0 起）：

```yaml
target: entity
match:
  entity_type: [ip]         # 实体表字段:entity_type/raw_value/canonical_key/qualifier
  qualifier: [global]
  min_hosts: 2              # 保留键:跨机聚合阈值(≥2 台主机才命中)
```

实体规则裸键 = 精确等值（与事件规则裸键 contains 不同，注意）。
- **加一条**：仿 `configs/rules/scanner-ua.yaml`（web 签名）/
  `ransom-security-log-cleared.yaml`（evtx 面）/ `xhost-shared-public-ip.yaml`
  （实体面）。加完跑 `go test ./internal/review/`（真实目录焊死测试会
  逐条装载你的新规则）。命中以 pending 落待审区，人裁决——规则不产生结论。

## 3. `configs/operators/` —— 统计算子注册表

算子是「机器决定怎么算」的参数化统计原语（爆破链/信标/突刺/离群/分化/
序列链/认证链/驻留链/进程树/时间簇/凭据面/跨实体），实现写死在 Go，
**YAML 只能调参与声明适用域，不能发明新算法**（新算法 = 代码工作）。

```yaml
id: web-bruteforce-chain    # 必须与已注册实现同名;implemented: true 而
title: Web 爆破链            # 无代码实现 = 注册表说谎,装载即拒
family: web                 # web | host | cross
severity: high
applicable_to:              # 适用域:按源品类路由,不匹配源不实例化(零消耗)
  log_types: [web_access]
params:                     # 全部可调参数在这里,阈值/窗口/排除清单
  fail_threshold: 10
  window_seconds: 600
  fail_status: ["401", "403"]
  success_status: ["200"]
  # exclude_kb: common_uas  # 可选:引用 configs/excludes/<名>.yaml(去扩展名)
implemented: true
max_hits: 500
note: 判定要点(命中时随 detail 返回给人)
```

**加一条自己的**：实际是「调一档自己的参数」——复制现有算子文件改
params（比如把爆破阈值改严），**id 不能乱起**：必须是 Go 侧已注册的
实现名（`internal/operator/operator.go` impls 表，现有 15 个）。
排除清单引用见 §6。

## 4. `configs/playbooks/` —— 意图链模板（playbook = 预制排查思路）

```yaml
id: my-playbook
version: 1
title: 我的排查手册
description: 这本册子回答什么问题
os: windows                 # windows | linux 等标签
goal: 收官目标文本(种成意图图 goal 节点)
intents:
  - key: first_step         # key 全册唯一
    text: 意图陈述(一个待验证的排查假设)
    ask: 给 worker 的方法指引:查什么、怎么交叉印证、缺数据如实报
    host_scope: each        # each=每台主机各派一条;all=显式全案(过审批门);缺省=全案
    # after: [other_key]    # 父意图 key 列表;空=根意图,父完成才长出
    # scope: all            # 显式批量意图(过审批门)
    # budget_seconds: 300   # 可选,覆盖意图级 wall-clock 预算
```

- 装载即校验：key 唯一 / after 引用存在 / 无环 / 深度 ≤5，违反拒启。
- 写法纪律：蒸馏「怎么查」的思路，零具体案件值；数据缺失的通道要求
  worker 如实报「未覆盖」，不硬编。
- **加一册**：仿 `general-triage.yaml`（结构最全的注释样例）。实例化
  幂等（同册重复播种不重复长）。

## 5. `configs/kb/` —— 启发式知识库内置条目

```yaml
id: my-heuristic            # 全目录唯一(与用户条目同池,冲突拒装)
title: 条目人读名
applies_to: [execution, timeline]   # 场景标签(自由文本;常用五面:
                                    # execution/sample-recovery/timeline/
                                    # persistence/entry-point)
content: >-
  【机制】...【怎么找】...【注意】...   # 写法纪律:回答「怎么找答案」,
                                        # 不是模板步骤,零案件值
# enabled: false            # 可选,内置条目默认启用;禁用态也可在页面上改(存 PG)
```

- 生效机制：内置条目启用 = 进各案可选池；**案件实际生效以建案/案内勾选
  为准**（0.20.0 起案件级勾选，不再全量注入）。注入 AI worker 时带口径
  声明「参考不是证据，锚点仍只能锚采集物」。
- **加一条**：文件丢进目录重启即可；也可在「系统 → 知识库」页建用户条目
  （存 PG，admin 写）。内置条目页面只能启停不能改——要改内容就改 YAML。
- 每破一个案子沉淀一条「下次怎么找」是这套机制的 design intent。

## 6. `configs/excludes/` —— 排除清单（宁漏勿冤）

```yaml
id: common_uas              # 文件名去 .yaml 即引用名
title: 清单人读名
tokens:                     # 值小写化后子串包含(实测语义,不是前缀匹配)
  - googlebot
  - curl/
note: 排除只缩小聚簇,不产生命中;新 token 人审后追加
```

- **被引用方式**：算子 YAML 的 params 里写 `exclude_kb: common_uas`。
  装载期解析，缺文件/坏结构 = 算子注册表拒载（不静默）。
- 与算子内 `exclude_value_patterns`（正则）并行，任一命中即排除。

## 7. `configs/wininfosc-map.yaml` —— 采集包结构映射表

新增采集项/新采集端（如 LinuxSC）只改这一个文件：

```yaml
package_root_regex: ^Forensic_[^_/]+_[^/]+$     # 包根规范(识别「这是一个采集包」)
host_regex: ^Forensic_(?P<host>[^_/]+)_[^/]+$   # 主机键提取(命名捕获组 host 必须有,缺组拒载)
rules:                          # 首条命中即停;含 / 匹配包内相对路径,否则只匹配文件名
  - match: Windows_logs/*.evtx
    artifact: windows_event_log # 采集物类别
    route: evtx_native          # evtx 原生路由
  - match: usn_journal_*.csv    # 注意顺序:特例要写在 *.csv 兜底之前
    artifact: usn_journal
    route: native               # native = Go 原生解析器
    parser: usn_csv             # native 必须给 parser(词表见 internal/parsers 注册表)
    log_type: usn_journal       # 可选,接算子适用域
  # 无命中 → 兜底 raw + artifact=unmapped(如实计数不静默;扩展覆盖=加规则,不是改代码)
```

- 纪律：规则只写「采集包规范的结构特征」（目录名/文件名模式），出现具体
  主机名/IP 即判负（防过拟合测试焊死）。新增 native parser 是代码工作
  （`internal/parsers/`，金标准对拍纪律见 `golden/gen_golden.py` 头部说明）。
