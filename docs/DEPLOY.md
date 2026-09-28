# DEPLOY.md —— 丰图从零部署手册

> 以 `cmd/fengtu/main.go`（环境变量权威出处）、根 `Dockerfile` +
> `docker-compose.yml`（主部署形态）、`deploy/schema/` 为准。
> 当前版本 0.32.1-case-distilled。

## 0. Docker 部署（主部署形态 · DESIGN §12 拍板）

一栈三服务：丰图单二进制（前端 embed 进镜像）+ PostgreSQL 16 +
ClickHouse 25.8。以下命令在云主机（docker 29.1.3 + compose v2）
实测通过。

```bash
# 1) 配环境(口令三处同串:POSTGRES_PASSWORD=FENGTU_PG 口令段;
#    CLICKHOUSE_PASSWORD=FENGTU_CH_PASS;端口绑定缺省 127.0.0.1 不动)
cp .env.example .env && chmod 600 .env && $EDITOR .env

# 2) 构建(国内加速可加 --build-arg NPM_REGISTRY=https://registry.npmmirror.com;
#    Go 依赖走 vendor/ 内嵌,构建期零外网拉取)
docker compose build

# 3) 起栈(PG/CH 健康后才起丰图;schema 首启自动初始化,迁移幂等)
docker compose up -d
```

验证：

```bash
docker compose ps                              # 三服务全 (healthy)
curl http://127.0.0.1:8200/api/health          # {"ok":"true","version":"0.32.1-case-distilled"}
docker compose logs fengtu | head              # 启动行:规则 68/算子 15/playbook 14/KB 32
```

首启引导同手动部署：浏览器开 `http://127.0.0.1:8200`（或 SSH 端口转发
`ssh -L 8200:127.0.0.1:8200 ...`）建首个管理员，或
`curl -X POST http://127.0.0.1:8200/api/auth/setup -H 'Content-Type: application/json' -d '{"username":"admin","password":"..."}'`。

端口纪律（§9，公网机尤其）：

- 丰图 web 口由 `.env` 的 `FENGTU_BIND_IP` 控制宿主绑定，**缺省
  127.0.0.1 仅本机**；要暴露给团队改成内网 IP，公网必须反代 TLS +
  `FENGTU_COOKIE_SECURE=true`。
- PG 5432 / CH 9000·8123 **不对宿主暴露任何端口**，只在 compose 内部
  网络互通；排障用 `docker exec fengtu-pg psql -U fengtu` /
  `docker exec fengtu-ch clickhouse-client --user fengtu --password ...`。

内存纪律：CH 挂载 `deploy/ch-limits.xml`（server 级
`max_memory_usage=8GB`，16GB 机型参考值，约为物理内存一半），与应用层
会话级 4GB 保险丝（§4.2）叠加；换机型改该文件后 `compose up -d` 生效。

数据三卷：`fengtu_pg_data`（元数据/审计链）、`fengtu_ch_data`（事件列存）、
`fengtu_fengtu_data`（/app/data：vault 原件+暂存+AI transcript+工作区）。
备份口径与 §6 相同，容器名换成 `fengtu-pg`/`fengtu-ch`。

升级 = 改代码后 `docker compose build && docker compose up -d`（镜像重
建、容器换新；迁移随启动幂等补齐，纪律同 §5）。回滚 = 旧镜像 tag 重新
`up -d`。

手动部署（systemd + 裸二进制）保留为备选形态，见下文 §3/§4。

## 1. 依赖与规格

| 组件 | 版本 | 说明 |
|---|---|---|
| PostgreSQL | 16（compose 镜像 `postgres:16`） | 案件/用户/审计链/意图图/待审区 |
| ClickHouse | 25.8（compose 镜像 `clickhouse/clickhouse-server:25.8`） | 事件/实体列存，native 协议 9000 + HTTP 8123 |
| Go | ≥ 1.26（go.mod 声明 1.26.4） | 仅构建需要 |
| Node.js | 18+ | 仅前端构建需要（产物 embed 进二进制，运行时不需要） |
| Docker | 29.x 实测 | PG/CH 的推荐运行形态（DESIGN §12 已拍板 compose 为主部署形态） |

规格建议（以台架实测为锚，不外推）：

- 台架基线：4 vCPU / 15GB 内存跑过 5000 万行事件全表 + 36 万行/秒级摄入
  （894MB nginx 摄入 19.0s，性能军令状台架实测）。
- 内存：≥ 8GB 起步；CH 是内存大户，检索侧有会话级
  `max_memory_usage=4GB` 保险丝（DESIGN §4.2）。
- 磁盘：三块叠加——`data/vault/`（原件全量，与采集包总量 1:1）、
  ClickHouse 数据卷（归一事件+原文 raw，与日志文本量同量级，列存有压缩）、
  PG 数据卷（元数据，相对小）。预留公式：采集包总量 ×3 起步，按案件留存
  策略加码。
- 端口纪律：PG 5432 / CH 9000·8123 **只绑内网地址**（compose 的
  `${FENGTU_BIND_IP}`，缺省 127.0.0.1），不裸绑 0.0.0.0；丰图 web 口
  8200 供用户访问。公网部署必须反代 TLS + `FENGTU_COOKIE_SECURE=true`
  （DESIGN §9）。

## 2. 环境变量全表

出处：`cmd/fengtu/main.go` 头部注释 + 装配代码。标 **必填** 的无默认值，
缺了启动直接失败（拒启是纪律，不带病上线）。

### 数据库与监听

| 变量 | 缺省 | 必填 | 说明 |
|---|---|---|---|
| `FENGTU_PG` | 无 | **是** | PG DSN，形如 `postgres://user:pass@host:5432/fengtu` |
| `FENGTU_CH` | 无 | **是** | ClickHouse native 地址，形如 `host:9000` |
| `FENGTU_CH_USER` | `fengtu` | 否 | CH 用户 |
| `FENGTU_CH_PASS` | 无 | **是** | CH 口令 |
| `FENGTU_CH_COMPRESS` | `lz4` | 否 | CH 传输压缩；内网带宽充足可置 `none` 省 CPU（台架 bench 姿态） |
| `FENGTU_LISTEN` | `127.0.0.1:8200` | 否 | web 绑定地址；要给别人访问就显式绑内网 IP 或反代 |

### 数据与配置目录

| 变量 | 缺省 | 必填 | 说明 |
|---|---|---|---|
| `FENGTU_DATA_DIR` | `./data` | 否 | 数据根；金库 `<dir>/vault`、暂存 `<dir>/tmp`、AI transcript `<dir>/ai`、工作区 `<dir>/workspace` |
| `FENGTU_MAP` | `configs/wininfosc-map.yaml` | 否 | 采集包结构映射表（读取失败拒启） |
| `FENGTU_DESC_DIR` | `configs/desc` | 否 | 行式日志 desc 描述文件目录（装载失败拒启） |
| `FENGTU_RULES_DIR` | `configs/rules` | 否 | 签名规则目录（装载失败拒启） |
| `FENGTU_OPERATORS_DIR` | `configs/operators` | 否 | 算子注册表目录（装载失败拒启） |
| `FENGTU_PLAYBOOKS_DIR` | `configs/playbooks` | 否 | playbook 意图模板目录（装载失败拒启） |
| `FENGTU_KB_DIR` | `configs/kb` | 否 | 启发式知识库内置条目目录（装载失败拒启） |

注意：缺省值都是**相对路径**，务必设 `WorkingDirectory`（systemd）或在
部署根目录启动，并把 `configs/` 整套同步到该目录（台架布局
`/opt/fengtu/{bin,configs,data}`）。

### 会话与安全

| 变量 | 缺省 | 必填 | 说明 |
|---|---|---|---|
| `FENGTU_COOKIE_SECURE` | `false` | 否 | 会话 cookie Secure 位；内网明文可 false，反代 TLS 时**必须** `true` |

### AI 层（全部可选；不配 = AI 端点 503/外发闸关 403，如实，不影响其余功能）

| 变量 | 缺省 | 必填 | 说明 |
|---|---|---|---|
| `FENGTU_AI_API_KEY` | 无 | 否 | 厂商 key；走 env 永不落库。也可在「系统配置」页存（PG 里只存 AES-GCM 密文） |
| `FENGTU_AI_SECRET` | 无 | 条件 | 平台设置存 key 时的 AES-GCM master key（不入库）；**用了设置页存 key 就必须固定此值**，换了/丢了旧密文解不开（如实报「无法解密」） |
| `FENGTU_AI_BASE_URL` | `https://api.deepseek.com/v1` | 否 | OpenAI 线格式端点 |
| `FENGTU_AI_MODEL` | `deepseek-chat` | 否 | 模型名 |
| `FENGTU_AI_PROVIDER` | `deepseek` | 否 | 厂商标签 |
| `FENGTU_AI_OUTBOUND` | 关 | 否 | AI 外发总开关（`true`/`1`）；关 = AI 端点 403 如实，一个字节不出机 |
| `FENGTU_AI_BUDGET_TOKENS` | `200000` | 否 | 人工聊天会话 token 预算，超即熔断如实 |
| `FENGTU_AI_MAX_TOKENS` | `4096` | 否 | 厂商级单回复 token 上限 |
| `FENGTU_INTENT_BUDGET_SECONDS` | `600` | 否 | 单意图 wall-clock 预算；耗尽 → `closed_exhausted` 如实（不是失败，已得照写回） |
| `FENGTU_INTENT_TOKEN_BUDGET` | `1000000` | 否 | 意图 worker 会话 token 预算（保险丝不是性能声明；0.21 起默认 1M——**main.go 头注仍写 100000，是过期注释，以代码为准**） |

优先级：**环境变量 > PG 平台设置（系统配置页）> 内置 DeepSeek 默认档**。
另外「系统配置」页还有不写 env 的运行时档位：worker 全局并发（默认 4）、
意图链派生三闸（扇出 5 / 章 30 / 案 200）、全局代理、联网搜索
（ddgs/brave-free/tavily）、LLM 录制档位（off/metadata/full）。

## 3. 从零部署

```bash
# 1) 起数据库(schema 由 entrypoint initdb 在空卷首启时执行一次)
cd deploy && FENGTU_BIND_IP=<本机内网IP> docker compose up -d

# 2) 准备部署根
mkdir -p /opt/fengtu/{bin,data}
# 把仓内 configs/ 整个目录复制到 /opt/fengtu/configs
# (desc/rules/operators/playbooks/kb/excludes + wininfosc-map.yaml)

# 3) 构建并安放二进制(前端必须先构建,否则 web 只出占位页)
cd frontend && npm install && npm run build && cd ..
go build -o /opt/fengtu/bin/fengtu ./cmd/fengtu

# 4) 写 env 文件 /etc/fengtu/fengtu.env(权限 0600,含口令与 AI key)
#    然后 systemd 拉起(见下节)

# 5) 验证
curl http://127.0.0.1:8200/api/health   # {"ok":"true","version":"0.26.0-m4-multiuser"}
```

首启：浏览器开 `http://<主机>:8200`，引导页建首个管理员（后端把关只能
一次，复跑 403）。等价 API：`POST /api/auth/setup`。

**首次启动做了什么**（main.go 启动顺序，任何一步失败都拒启）：连 PG →
跑 schema 迁移（幂等，见 §5）→ 连 CH → 开金库/暂存目录 → 装载映射表/
规则/算子/desc/playbook/KB → 监听。启动日志会打印
「规则 N 条, 算子 N 个, playbook N 册, 知识库内置条目 N 条」——数字与
`configs/` 目录对不上就是配置没同步全。

## 4. systemd unit 样例

```ini
# /etc/systemd/system/fengtu.service
[Unit]
Description=FengTu IR analysis platform
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/fengtu
EnvironmentFile=/etc/fengtu/fengtu.env
ExecStart=/opt/fengtu/bin/fengtu
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

`/etc/fengtu/fengtu.env` 样例（**LF 行尾、0600**，CRLF 会污染变量值，
踩坑在案）：

```bash
FENGTU_LISTEN=<服务器内网IP>:8200
FENGTU_PG=postgres://fengtu:<口令>@<数据库主机>:5432/fengtu
FENGTU_CH=<数据库主机>:9000
FENGTU_CH_USER=fengtu
FENGTU_CH_PASS=<口令>
FENGTU_DATA_DIR=/opt/fengtu/data
FENGTU_AI_API_KEY=<厂商key,也可留空走设置页>
FENGTU_AI_SECRET=<随机 32 字节 base64,设置页存 key 必填且不可再换>
```

```bash
systemctl daemon-reload && systemctl enable --now fengtu
journalctl -u fengtu -f
```

## 5. 升级流程

升级 = 换二进制 + 同步 configs，**迁移自动跑，不需要手工执行 SQL**：

1. 本机构建新版本二进制，传 `/opt/fengtu/bin/fengtu.new`；
   `md5sum` 两端对账一致后 `mv fengtu.new fengtu`（直接覆盖运行中二进制
   会 ETXTBSY，踩坑在案）。
2. 同步 `configs/` 增量（rules/operators/playbooks/kb/desc 新增文件、
   wininfosc-map.yaml 变更）。启动时配置装载失败会拒启——先把旧进程留住
   再停。
3. `systemctl restart fengtu`。
4. 验证：`curl /api/health` 版本号变更；启动日志各配置计数正确；
   `docker exec fengtu-postgres psql -U fengtu -c 'SELECT * FROM schema_migrations ORDER BY version'` 应记账到最新序号（当前 **017**）。

迁移纪律（开发侧已焊死，运维只需知道）：`deploy/schema/pg/*.sql` 与二进制
内嵌迁移逐字节一致（migrate_test 防漂移）；已应用过的序号自动跳过；
docker initdb 只在空卷首启跑，存量库全靠 server 启动时 Migrate 补齐。
当前最新迁移序号 017（`017_case_seal.sql`）。

## 6. 备份

三块数据，口径分开：

```bash
# PG(元数据/审计链/意图图/待审区)——必须备,审计链在这
docker exec fengtu-postgres pg_dump -U fengtu fengtu | gzip > fengtu-pg-$(date +%F).sql.gz

# ClickHouse(事件/实体)——派生数据,理论上可由 vault 原件重建,
# 但重建要重跑摄入;建议照备
docker exec fengtu-clickhouse clickhouse-client --user fengtu --password <口令> \
  -q "BACKUP TABLE fengtu.events TO Disk('backups','events-$(date +%F).zip')"
#   (或用 clickhouse-backup 工具;至少把 /var/lib/clickhouse 卷做快照)

# data/ 目录(证据本体+工作区+AI transcript)——必须备,vault 是原件
rsync -a /opt/fengtu/data/ /backup/fengtu-data-$(date +%F)/
```

恢复优先级：先 PG + data/（含 vault 原件），CH 丢了可用
`cmd/ftingest` 从 vault 重建（解析器对 spec 写，重跑确定）。
另外单案件粒度的跨实例迁移用平台自带「封存导出/导入」（案件页头
「导出封存包」，单 zip 含原件+哈希清单，见 USAGE.md）。

## 7. 故障排查速查

### 白屏 / 页面打不开

1. `curl http://<host>:8200/api/health`——不通 = 进程没起，看
   `journalctl -u fengtu`；通了但页面白：
2. 直开/刷新深层路径白屏（如 /cases/xxx）：曾有的 `base:"./"` 相对基线
   坑已在 8b 修掉（`base:"/"`）；若现形，多半是前端没构建——根路径只出
   占位页 = 没跑 `npm run build` 就 `go build` 了，回 §3 第 3 步。
3. 浏览器 F12 看资产 404 / MIME 报错，按 2 处理。

### 502（反代后）

1. 反代 upstream 指的地址与 `FENGTU_LISTEN` 是否一致；
2. `journalctl -u fengtu` 看进程是否反复重启（配置装载失败/迁移失败会
   拒启，日志第一屏就是原因）；
3. SSE 长连接（任务进度/意图图/聊天）经反代需关缓冲：
   nginx 侧 `proxy_buffering off; proxy_read_timeout 3600s;`。

### 迁移失败（启动日志「schema 迁移失败」）

1. 日志里有具体 SQL 错误原文，先看原文；
2. 查已应用序号：`docker exec fengtu-postgres psql -U fengtu -c 'SELECT version FROM schema_migrations ORDER BY version'`（当前应到 017）；
3. 常见根因：手工改过库导致与迁移假设冲突；跨版本跳级部署一般无碍
   （迁移幂等逐号补）。**不要手工改表迁就**，带着序号和错误原文找开发。

### 意图链不动（图不长/意图卡 open）

按顺序查：

1. **AI 外发闸没开**：系统配置页「AI 厂商设置」外发开关默认关，关了
   worker 发不出请求。开闸 + 配 key（env 或设置页二选一）。
2. **AI key 无效/余额尽**：AI 装配失败意图端点 503 如实；厂商 402/401
   会如实落 close_note。设置页「测试」按钮直连自测。
3. **归档中**：归档案 planner 停派（analyze/手写意图 409 如实）——
   任务列表「已归档」筛选确认，解归档即恢复。
4. **等审批**：AI/规则派生的 scope=all 批量意图挂 awaiting_approval，
   铃铛/审批 tab 红点计数，批了才派发。
5. **并发排队**：worker 全局并发上限（默认 4，系统配置页可调）满了会
   排队，过程流如实记「排队中(并发上限 N)」。
6. **预算耗尽**：closed_exhausted（wall-clock，默认 600s/
   `FENGTU_INTENT_BUDGET_SECONDS`）或 token 熔断（close_note 如实标
   「会话 token 预算熔断」）——都不是失败，已得结论照写回。
7. **重启残留**：进程重启后在跑的意图卡 running 不自动回收（已知边界），
   新意图照常派发；残留节点可人工 stop。

### 摄入失败 / 上传被拒

1. 哈希对账不过 = 422 拒收（审计 `upload.rejected`）——重传，网络层
   问题；WinInfoSC 包清单失配 = 证据完整性存疑拒收，看任务失败原文。
2. evtx 跨百日大分区量曾撞 CH `max_partitions_per_insert_block`——
   已在代码会话级放到 10000（store/ch.go），若现形看 CH 容器日志。
3. 任务详情/「系统 → 日志」页有失败原文；持久账在 PG `ingest_jobs`。

## 8. 性能台架（可选）

`deploy/bench.sh`（DESIGN §4.3 军令状执行器，在部署机上跑）：

```bash
/opt/fengtu/deploy/bench.sh          # 全流程(摄入+扫描)
/opt/fengtu/deploy/bench.sh clean    # 清空 bench 数据(TRUNCATE 全表,含采集包案件——顺序敏感,先 bench 后业务数据)
```

注意 bench.sh 里的台架口令/地址是台架专用，换环境先改脚本头部 env 段。
