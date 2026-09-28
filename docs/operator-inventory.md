# 算子盘点对照表(丰图 × 索图 × 树庭)

> 只读调研产出,2026-09-25。三仓基线(均为同作者项目,仓内相对路径):
> - **丰图**(Go):算子注册点 `internal/operator/operator.go` impls 表;签名规则引擎 `internal/review/`;配置 `configs/{operators,rules,playbooks,kb}/`
> - **索图**(Python FastAPI):引擎 `backend/app/rules.py`;规则 `backend/rules/{builtin,stats}/`;KB `backend/kb/`
> - **树庭**(Python):引擎 `backend/app/rules.py`(附录 A schema);规则 `backend/rules/builtin/`;手册 `backend/playbooks/`;KB `backend/kb/`

---

## 1. 丰图现有清单(基准列)

### 1.1 算子(14 个,全部 implemented:true;注册表 `internal/operator/operator.go:117`)

| 算子 id | 族 | 功能 | 关键参数 |
|---|---|---|---|
| web-bruteforce-chain | web | 同 src_ip 失败×N → 窗口内成功(401/403→200) | fail_threshold=10, window_seconds=600, window_lines=2000, 状态码可配 |
| web-beacon-periodicity | web | 同键请求间隔 CV 三闸信标 | min_samples=12, min_span_seconds=3600, max_cv=0.15 |
| web-ip-rate-spike | web | 单 IP 时间桶计数 z 检突刺 | bucket_seconds=60, z_threshold=5.0, min_bucket_count=100 |
| web-key-divergence | web | 同 src_ip 单维度(ua)distinct 计数发散 | key_field, dimension=ua, min_distinct=50 |
| web-cross-key-same-value | web | 稀有值跨多键复现(max_df + 正则排除) | value_field=ua, min_keys=3, max_df=5, exclude_value_patterns |
| web-outlier | web | 同键 bytes 偏离中位数 | key_field=path, ratio=3.0, min_samples=10 |
| host-auth-chain | host | 4625×N → 4624 爆破成功链 | fail_threshold=10, window_seconds=600 |
| host-persistence-task | host | 4698/4702 任务名实不符(良性名×可疑执行体) | benign/suspicious 正则清单 |
| host-service-install | host | 7045 两翼:全量 + 映像落可写目录 | writable_dir_patterns |
| host-process-tree | host | 4688 相似名×异常位置(lookalike 系统进程) | lookalike_targets, system_dirs |
| host-time-cluster | host | 窗口内海量写/改名(USN reason_bits) | window_seconds=300, min_events=100, ext_exclude |
| host-credential-face | host | SAM/SECURITY 访问(4656/4663)+ 4648 显式凭据 | sam_object_patterns, 进程白名单 |
| cross-entity-multi-source | cross | 公网 IP 同值 ≥2 源 | min_sources=2, ip_fields 按 log_type |
| cross-host-entity | cross | 公网 IP 同值 ≥2 主机 | min_hosts=2, ip_fields 按 log_type |

### 1.2 签名规则引擎与规则文件

- 引擎 `internal/review/rule.go`:索图签名规则子集——字段条件 AND、字段内子串 OR、大小写不敏感;match 字段白名单(`review.go:44`)含 web 面 10 + 主机统一面 15 + 解析器产出 8 + 0.25.0 新增(command/netstat 八字段);`target` 接受 `any|entity`(0.25.0 实体层;web 等分类仍待 log_type 落地)。
- 规则文件 39 条(0.21.0 索图系 11 + 0.22.0 树庭系 12 + 0.25.0 数据源解锁 16)。
- playbook 2 册:`general-triage`、`ransomware-triage`(意图链模板,蒸馏自树庭手册)。
- KB 25 条(0.21.0 及以前 11 + 0.22.0 树庭族级 11 + 0.25.0 数据源解锁族级 3)。
- **无 sigma/yara 引擎,无主机 artifact 签名 target,无 exclude_kb 引用机制。**

---

## 2. 索图算子清单 + 丰图对照

### 2.1 统计算子族(`backend/app/rules.py:67` STAT_OPERATORS,runner 表 :796)

| 算子 | 功能(一句话) | 输入字段 | 配置参数 | 规则例 | 丰图对照 | 移植难度 |
|---|---|---|---|---|---|---|
| same_key_divergence | 同复合键组内按分化维度分桶,metric 均值 max/min 超阈 | key_fields=[path,src_ip,ua], diverge_field=method, metric=bytes/status | min_group_events, diverge_ratio | method-bytes-divergence.yaml | **部分**:web-key-divergence 仅单 key_field + distinct 计数,无复合键、无 metric 比值 | 需写 Go(小:扩参数支持多字段键 + bytes/status 均值比) |
| cross_key_same_value | 稀有值(value 全局频次<阈)出现在 ≥N 个不同键 | value_field=ua, key_fields=[src_ip] | min_keys, max_value_freq, **exclude_kb**(KB 文件前缀排除) | rare-ua-cross-ip.yaml | **有**:web-cross-key-same-value(max_df + 正则排除替代 KB 引用) | 已迁;exclude_kb 引用机制若要对齐需小改 |
| rate_spike | 键内时间桶计数 z-score 突刺(空桶不补零) | key_fields=[src_ip] | bucket_seconds, zscore, min_bucket_count | ip-rate-spike.yaml | **有**:web-ip-rate-spike(另加 min_buckets 闸) | 已迁 |
| size_outlier | 同复合键(path+method+status)对中位数双向离群,拎少数派 | key_fields 多字段, metric=bytes | min_group_events, deviate_ratio, max_outliers | path-size-outlier.yaml | **部分**:web-outlier 单 key_field,无 method/status 复合键 | 需写 Go(小:多字段键 + max_outliers) |
| sequence | 通用多步链:同键 steps 序列,窗口内末步达成,首步需达最低次数 | key_fields=[src_ip,path], steps=[{field,in}] | window_seconds, **min_first_step_count** | auth-bruteforce-success.yaml | **部分**:web-bruteforce-chain 是爆破特化(状态码可配但键语义固定,无 path 复合键、无任意 steps) | 爆破场景已覆盖;通用 sequence 引擎需写 Go(中) |
| periodicity | 同键相邻间隔 CV 低于阈 + 样本/跨度双闸 | key_fields=[src_ip,path] | min_events, max_cv, min_span_seconds | periodic-beacon.yaml | **有**:web-beacon-periodicity | 已迁 |
| cross_source_entity(内置,非 YAML) | 公网实体(qualifier=global)跨 ≥2 源联动 | 实体表 | — | 内置常量 | **有**:cross-entity-multi-source | 已迁 |

### 2.2 签名规则(11 条,`backend/rules/builtin/`)

| 规则 id | 功能 | 丰图 | 难度 | 研判思路(KB 素材) |
|---|---|---|---|---|
| scanner-ua | 扫描器默认 UA 指纹 | 有(已迁) | — | 工具默认 UA 是自我标识,命中只说明「自称」,严重级不上调 |
| abnormal-method | 异常 HTTP 方法(PUT/DELETE/TRACE 等) | 无 | 纯配置 | 业务白名单外的方法动词是攻击面探测的第一筛子 |
| cmd-exec-params | 命令执行参数特征(cmd=/exec=/system() 等) | 无 | 纯配置 | 参数位出现 shell 元字符/解释器名是 RCE 探测直接信号 |
| path-traversal | 路径穿越/敏感系统文件(../、/etc/passwd、boot.ini) | 无 | 纯配置 | 穿越序列与已知敏感文件路径同现,几乎无业务正当理由 |
| sensitive-path | 敏感路径探测(后台/备份/配置文件) | 无 | 纯配置 | 对管理后台/备份文件的批量 GET 是前置踩点 |
| sqli-time-based | 时间盲注特征(sleep/benchmark) | 无 | 纯配置 | 查询串含延时函数 = 盲注探测,误报面小 |
| sqli-union-select | UNION SELECT 特征 | 无 | 纯配置 | union select 组合在业务参数中无合法形态 |
| waf-checker-ua | 云防线/安全服务检查器 UA(归因提示) | 无 | 纯配置 | 安全厂商巡检 UA 命中是「对方也在看你」的归因旁证 |
| webshell-filename | 已知 webshell 文件名访问 | 无 | 纯配置 | 对已知马名的成功响应 = 马已落地的高疑信号 |
| xss-javascript-protocol | javascript: 伪协议 | 无 | 纯配置 | 伪协议进反射参数是 XSS 探测签名 |
| xss-script-handler | script 标签/事件处理器 | 无 | 纯配置 | 标签+on* 处理器组合是 XSS 载荷骨架 |

> 迁移注意:丰图引擎 `target` 仅支持 `any`,索图这 10 条原作 `target: web`——直接拷会被拒载;要么写 `any`(scanner-ua 已这么干),要么等 log_type 落地。

---

## 3. 树庭清单 + 丰图对照

### 3.1 规则(63 条 builtin;引擎为附录 A 签名匹配:字段 AND/list OR、`_contains`/`_prefix` 后缀、cross_host 用 qualifier+min_hosts)

**Windows 数据外泄(6)**

| 规则 id | 功能 | 丰图 | 难度 | 研判思路 |
|---|---|---|---|---|
| exfil-archive-create-cmdline | PSHistory 出现打包命令(7z/rar a) | **有**(0.25.0 PSHistory 事件化) | — | 拿走数据前先打包,命令行历史是第一现场 |
| exfil-encrypted-archive-cmdline | 带口令压缩(-p) | **有**(0.25.0) | — | 加密压缩=防 DLP/防事后读包,外泄意图升级信号 |
| exfil-upload-tool-cmdline | rclone/curl 上传命令 | **有**(0.25.0) | — | 合法同步工具被挪用是最常见外泄通道 |
| exfil-compression-tool-prefetch | 压缩工具执行痕迹 | **有**(0.22.0 已迁) | — | 命令行可清,Prefetch 执行痕难清,互为印证 |
| exfil-cloud-storage-domain | 网盘/传输服务域名实体 | **有**(0.25.0 实体层) | — | 与网盘域名建联≠外泄,但给时间窗提供锚点 |
| exfil-transfer-port-outbound | FTP/TFTP 等传输端口外联 | **有**(0.25.0 netstat 事件化) | — | 稀有传输协议端口外联在服务器角色上天然可疑 |

**Windows 横向移动(7)**

| 规则 id | 功能 | 丰图 | 难度 | 研判思路 |
|---|---|---|---|---|
| lateral-service-installed | 7045 新服务安装 | **部分**(host-service-install 覆盖事件面) | 已覆盖 EVTX 侧 | 7045 是 psexec/远控落点的系统级铁证,先看映像路径与创建账户 |
| lateral-service-writable-dir | 7045 映像落可写目录 | **有**(host-service-install 可写目录翼) | — | 合法服务不落 AppData/Temp,落即强信号 |
| lateral-remote-task-created | 4698 计划任务创建 | **部分**(host-persistence-task 含 4698/4702) | 已覆盖 | at/schtasks 远程建任务是横向经典通道,先查创建人 |
| lateral-admin-port-connection | 445/3389/5985 已建立连接 | **有**(0.25.0 netstat 事件化) | — | 服务器间管理端口互联先问「这台该不该管别人」 |
| lateral-recon-cmdline | net use/net view 侦察命令 | **有**(0.25.0 PSHistory 事件化) | — | 侦察命令簇是横向前的踩点,成簇出现才升级 |
| lateral-remote-exec-tool-prefetch | psexec 等工具执行痕 | **有**(0.22.0 已迁) | — | 远程执行工具在本机的 Prefetch 留痕与 7045 互证 |

**Windows 勒索(4)+ 驻留/签名面(5)+ 远控(2)**

| 规则 id | 功能 | 丰图 | 难度 | 研判思路 |
|---|---|---|---|---|
| ransom-shadow-delete-cmdline | 4688 删影/关恢复命令 | **有**(0.22.0 已迁,EVTX 面) | — | 动手前先断恢复后路,删影是勒索最强前置信号 |
| ransom-shadow-delete-pshistory | PSHistory 删影命令 | **有**(0.25.0 PSHistory 事件化) | — | 同上,PSHistory 是 4688 被清后的备份视角 |
| ransom-shadow-tool-prefetch | vssadmin/wbadmin 执行痕 | **有**(0.22.0 已迁) | — | 工具本身合法,与加密时间簇咬合才定性 |
| ransom-security-log-cleared | 1102 安全日志清除 | **有**(0.22.0 已迁) | — | 清日志=反取证实锤候选,必查清除者与前后窗口 |
| suspicious-run-key-non-system-dir | Run 键指向可写/用户目录 | **有**(0.22.0 已迁) | — | 驻留位+非系统位置双条件,误报面小 |
| suspicious-scheduled-task-user-dir | 任务指向临时/用户目录 | **部分**(host-persistence-task 的 suspicious_exec_patterns) | 已覆盖事件面;采集 XML 面暂缓(等专题面) | 任务名可以伪装,执行体路径骗不了人 |
| unsigned-persistence-binary | 驻留项二进制签名非 Valid | 无 | 暂缓(等签名面:签名校验数据源) | 驻留位 × 未过签两个弱信号咬合成强信号 |
| unsigned-binary-writable-path | 未签二进制落可写目录 | 无 | 暂缓(等签名面) | 同上,位置维度版 |
| native-messaging-host-writable-path | NMH 清单位可写目录 | 无 | 暂缓(等专题面:NMH 清单解析) | 浏览器扩展通道驻留,冷门但查到的都是干货 |
| browser-extension-forcelist | 策略强制安装扩展 | **有**(0.22.0 已迁) | — | 用户无法卸载的扩展=企业管控或被滥用,先核对管控基线 |
| winrat-anydesk-presence / winrat-sunlogin-presence | AnyDesk/向日葵痕迹 | 无 | 暂缓(等专题面:RemoteAccess 痕迹解析) | 合法远控在应急里先问「谁装的、谁在连」,不先定性 |

**Linux(26,0.32.0-linuxsc 已解锁 24 条;linux-lateral-internal-ssh-conn
此前已解锁;linux-ransom-note-deepscan 仍暂缓——它锚的是 Strata 采集端
deepscan 文件清单面,LinuxSC 无此产物,等 Strata 接入)**

| 规则 id | 功能 | 丰图 | 难度 | 研判思路 |
|---|---|---|---|---|
| linux-sshd-accepted-authlog / -journal | SSH 登录成功待审 | **有**(0.32.0;authlog/journal 双面,source/unit 分流替代树庭 target) | — | 暴破背景下每一条 accepted 都要回溯同 IP 失败史 |
| linux-lateral-root-accepted-authlog / -journal | root 远程登录成功 | **有**(0.32.0) | — | root 直登成功=高疑,先核堡垒机/运维白名单 |
| linux-lateral-internal-ssh-conn | 主动向内网 SSH 出站 | **有**(0.25.0 net_connection 面;0.32.0 起 ss/netstat_tuanp/conntrack 三面同规则自动覆盖) | — | 服务器主动连内网 SSH=跳板候选,服务器不该发起 |
| linux-lateral-tunnel-tool-cmdline | frp/autossh 等隧道工具 | **有**(0.32.0 ps 面) | — | 隧道工具在无运维理由的主机上即反连通道 |
| linux-conntrack-unreplied-out | SYN_SENT+UNREPLIED 出站 | **有**(0.32.0 conntrack 面) | — | 发出去没人理的连接是 C2 死了/被墙的残影 |
| linux-uid0-account | 非 root 的 UID 0 | **有**(0.32.0 passwd 面) | — | root 之外的 UID 0 就是后门,无合法形态 |
| linux-empty-password-account | 空密码账户 | **有**(0.32.0;引擎表达不了「等于空串」,解析器派生 empty_password 承载) | — | 空密码字段=无口令可登录,直接入侵面 |
| linux-cron-suspicious-exec | cron 指向临时目录/远程拉取 | **有**(0.32.0 cron 四面:逐用户汇总/系统/cron.d+anacron+spool) | — | 持久化老三样里 cron 最常被忘查 |
| linux-systemd-suspicious-path | 单元 ExecStart 指向可写目录 | **有**(0.32.0 systemd 单元+drop-in 面) | — | 合法服务不从 /tmp 启动 |
| linux-udev-exec-shm | udev 规则执行 /dev/shm | **有**(0.32.0 udev 面) | — | udev 触发+内存文件系统=高隐蔽持久化,基本无合法形态 |
| linux-pam-exec-hook | pam_exec 钩子 | **有**(0.32.0 pam.d 面) | — | 认证流程挂外部命令=凭据窃取/后门通道 |
| linux-ld-preload-export | shell 配置导出 LD_PRELOAD | **有**(0.32.0 shell 配置面) | — | 预载劫持是用户态 rootkit 的入门级手法 |
| linux-ssh-suspicious-authkey | authorized_keys 结构风险(弱钥/强制命令) | **有**(0.32.0;含 RSA/DSA 位数解算,SSH wire format 纯 Go 解析) | — | 公钥本身合法,弱钥/不可归因注释才指向被种key |
| linux-memfd-recovered-binary | memfd 内存马回收 | **有**(0.32.0 RecoveredBinaries 面;树庭注的 Strata 是另一采集端,LinuxSC 同样产 memfd 回收) | — | 不落盘的二进制=内存马,回收到样本即实锤候选 |
| linux-ebury-libns2 / -sshd-lib | Ebury IOC(libns2/异常 libkeyutils) | **有**(0.32.0;IOC 两档预筛在解析器,规则直通 is_ioc) | — | 硬 IOC 命中即高危,特案规则可低频保留 |
| linux-miner-known-tool-cmdline / -stratum-cmdline / -pool-port-conntrack / -proc-exe-writable | 挖矿四视角(进程名/stratum 地址/矿池端口/exe 落可写目录) | **有**(0.32.0) | — | 挖矿判定走多视角互证:名单命中+协议+端口+位置 |
| linux-exfil-archive-cmdline / -copy-cmdline / -upload-cmdline / -shmtmp-archive | 打包/scp/上传命令 + shm/tmp 压缩包 | **有**(0.32.0;shmtmp 扩展名用新增 _endswith 算子) | — | 与 Windows 外泄同理:先打包后传,shm 里的压缩包是 staging 区 |
| linux-ransom-note-deepscan | 勒索信文件名特征(Strata deepscan 清单) | 无 | **仍暂缓**(Strata 采集端 deepscan 面,LinuxSC 无此产物) | 勒索信文件名是公开 IOC 面,命中即锚定加密窗口 |
| linux-ransom-note-shmtmp | 勒索信文件名特征(shm/tmp 快照) | **有**(0.32.0) | — | 同上,shm/tmp 快照面 |
| linux-ransom-deleted-held-file | 已删除仍被持有文件(lsof +L1) | **有**(0.32.0) | — | 就地加密的残影:原文件删了句柄还开着 |
| linux-ransom-destructive-cmdline | 拆 LVM/删快照命令 | **有**(0.32.0 ps 面) | — | 与 Windows 删影同思路:先断恢复后路 |

**Windows 挖矿(5,跨平台同族)**

| 规则 id | 功能 | 丰图 | 难度 | 研判思路 |
|---|---|---|---|---|
| miner-pool-domain-entity / -pool-port-outbound / -stratum-url-cmdline / -tool-flags-cmdline | 矿池域名/矿池端口/stratum URL/矿工参数 | **有**(0.25.0:实体层 1 + netstat 1 + PSHistory 2) | — | 同 Linux:多视角互证,单条命中只算弱信号 |
| miner-known-tool-process / miner-service-writable-dir | 矿工进程名/服务落可写目录 | **有**(0.22.0:miner-known-tool-prefetch 走 Prefetch 面 + miner-service-writable-dir 走注册表面) | — | 进程面(process_exec)暂缓,等签名面进程列表数据源 |

**跨主机(3)**

| 规则 id | 功能 | 丰图 | 难度 | 研判思路 |
|---|---|---|---|---|
| xhost-shared-public-ip | 公网 IP 跨 ≥2 主机 | **有**(算子 cross-host-entity + 0.25.0 签名规则双路) | — | 私网永不跨机防假联动;多机共同外联才有意义 |
| xhost-shared-account-sid | 同一 SID 跨多机 | **有**(算子 account_sid 型 + 0.25.0 实体层签名规则) | — | SID 克隆=整机克隆或账户复制,跨机同 SID 值得问 |
| xhost-shared-file-hash | 同一 sha256 跨多机 | **有**(算子 file_sha256 型 + 0.25.0 实体层签名规则) | — | 同一样本多机落=已扩散,直接圈波及面 |

> 0.25.0-datasource-unlock 解锁小计(16 条):PSHistory 事件化 7
> (exfil-archive-create/-encrypted-archive/-upload-tool-cmdline、
> lateral-recon-cmdline、ransom-shadow-delete-pshistory、
> miner-stratum-url/-tool-flags-cmdline)+ netstat 事件化 4
> (exfil-transfer-port-outbound、lateral-admin-port-connection、
> linux-lateral-internal-ssh-conn、miner-pool-port-outbound)+ 实体层 5
> (exfil-cloud-storage-domain、miner-pool-domain-entity、xhost 三条)。
> 剩余暂缓分类:Linux 仅剩 linux-ransom-note-deepscan **等 Strata**
> (0.32.0-linuxsc 已解锁 28 条);unsigned-*/winrat/unsigned-*/winrat/
> native-messaging-host 等 5 条**等签名面/专题面**(签名校验、
> RemoteAccess 痕迹、NMH 清单、任务 XML);Sigma/YARA 5 条**等引擎**
> (外接优先);suspicious-scheduled-task-user-dir 任务 XML 面**等专题面**。

**Sigma(3)/YARA(2)**:`certutil-download`、`process-from-user-dir`、`ps-encoded-command`;`ps-download-cradle.yar`、`webshell-common.yar` — 丰图**无对应引擎**,需写 Go 或外接工具,优先级低。

### 3.2 Playbook(14 册 vs 丰图 2 册)

| 手册 id | 内容 | 丰图对照 | 难度 |
|---|---|---|---|
| general-triage | 通用主机排查 14 步 | **有**(已蒸馏为意图树) | — |
| windows-ransomware | 勒索专项 13 步 | **有**(ransomware-triage 意图树) | — |
| host-triage | 主机排查 11 步(发现链:后续步消费前序发现) | 无 | 纯配置(蒸馏为意图树) |
| lateral-movement | 横向移动 8 步 | 无 | 纯配置 |
| data-exfil / linux-exfil | 数据外泄 7 步(Win/Linux) | 无 | 纯配置 |
| miner / linux-miner | 挖矿 7 步 | 无 | 纯配置 |
| ransomware-precursor | 勒索前置 7 步(删影→可疑进程→批量加密→note) | 无(部分思想在 ransomware-triage) | 纯配置 |
| masq-hunt | 冒名驻留 8 步(名字像→位置不对→持久化→活着→外联印证→正品对账) | 无(host-process-tree 只覆盖一步) | 纯配置;方法论语义已被丰图算子部分吸收 |
| linux-triage / linux-lateral / linux-ransomware / linux-webshell-chain | Linux 四册(含 webshell 三级链:Web 入口→驻留→/tmp 改名 bash 波次→C2) | 无 | 纯配置,但依赖 LinuxSC 数据源接入 |

### 3.3 确定性分析模块(规则/手册之外的资产)

树庭除规则/手册外还有几个确定性分析模块,丰图侧若要继续对齐可留意:`backend/app/efu_anomaly.py`(EFU 扩展名突发,≈host-time-cluster 的采集面版本)、`backend/app/cred_exposure.py`(凭据暴露面,≈host-credential-face)、`backend/app/strata_verdict.py`(Linux Strata verdict→待审命中)、`backend/app/smb_auth.py`、`backend/app/rdp_ledger.py`。

---

## 4. 缺口汇总与移植优先级

依据=应急场景使用频率(实战应急中 Web 攻击面排查 > Windows 主机入侵 > Linux 入侵 > 特案 IOC)。

### 高(先搬)

| 项 | 来源 | 理由 | 工作量 |
|---|---|---|---|
| 索图 10 条 Web 签名规则 | 索图 builtin | Web 日志应急每案必跑;引擎语义已兼容,拷贝改 `target: any` 即可 | 纯配置,半天 |
| size_outlier 复合键增强(path+method+status) | 索图 | 「同路径响应尺寸找叛徒」是 webshell/0day 狩猎高频手法,丰图 web-outlier 单键粒度不够 | 需写 Go,小 |
| same_key_divergence 复合键 + bytes 均值比 | 索图 | 同 IP 同 UA 同路径跨方法长度分化是 0day 实案沉淀,丰图 web-key-divergence 只有 distinct 计数 | 需写 Go,小 |
| 树庭横向/勒索/驻留签名族(若丰图接 WinInfoSC 包) | 树庭 | 7045/4698 事件面丰图算子已覆盖,但 PSHistory/Prefetch/Run 键/签名面是主机应急主力数据源 | 需新数据源+match 字段扩展,中 |

### 中

| 项 | 来源 | 理由 | 工作量 |
|---|---|---|---|
| 通用 sequence 引擎(steps/window/min_first_step_count) | 索图 | 爆破链已特化覆盖,通用链(如 扫描→打点→利用)在新案型才有价值 | 需写 Go,中 |
| xhost-shared-account-sid / -file-hash | 树庭 | 波及面圈定在一案多包场景高频;cross-host-entity 扩实体类型即可 | 需写 Go,小 |
| 树庭 12 册 playbook 蒸馏 | 树庭 | 意图树机制已验证(general/ransomware 两册),剩下是内容工作 | 纯配置,每册 1-2 天 |
| exclude_kb 引用机制(值排除走 KB 文件) | 索图 | 稀有值聚簇的误报压制要靠人可编辑的 KB,正则清单硬编码在算子 YAML 里不利于运营 | 需写 Go,小 |
| Linux 规则族(26 条) | 树庭 | 依赖 LinuxSC/Strata 数据源接入;接入后签名规则是纯配置 | 需新数据源,中 |

### 低

| 项 | 来源 | 理由 | 工作量 |
|---|---|---|---|
| Ebury/特案 IOC 规则 | 树庭 | 特案专用,平时低频;作为 IOC 库沉淀即可 | 纯配置 |
| winrat presence 两条 | 树庭 | 远控痕迹在通用排查 playbook 里已引导人查,规则化增益小 | 需新数据源 |
| sigma/yara 引擎 | 树庭 | 3+2 条存量,外接成熟工具比自研引擎划算 | 需写 Go,大 |

---

## 5. 附:三层模型差异一句话

索图 = 签名规则(字段子串) + 6 统计/时序算子(通用参数化);树庭 = 附录 A 签名匹配(单机/跨机,锚定 artifact target) + playbook 发现链;丰图已把两者合并为「签名规则(索图子集) + 14 个适用域算子(web/host/cross) + 意图树 playbook」,缺口的本质是:**主机 artifact 签名 target 未进丰图 review 引擎 + 索图算子的复合键/通用 sequence 粒度未迁**。
