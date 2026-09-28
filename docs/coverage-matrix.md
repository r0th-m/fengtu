# WinInfoSC 采集项覆盖矩阵(丰图 v2 验收)

> 2026-09-23 综合实战验收切片·任务一。
> 采集项全清单从采集端脚本反推:`WinInfoSC.bat`(792 行,GBK/CRLF)。
> 映射口径:`configs/wininfosc-map.yaml`(首条命中即停;无命中→兜底 raw +
> artifact=unmapped,如实计数不静默)。
>
> 状态口径:
> - **parsed**:native 路由,专用解析器出结构化事件(事件数实测,见文末台账);
> - **raw**:登记入库(文本类行进全文索引可检索;二进制类登记留证不索引);
> - **unmapped**:无规则命中,兜底 raw + artifact=unmapped(文本仍可全文检索,
>   二进制仅登记)——覆盖缺口全部如实列在「unmapped 清单」节;
> - **—**:该包未采集到此项(采集版本差异/条件采集未触发/系统无此物)。
>
> 三包(真实案件采集物,标识已脱敏):`E:`=采集包 P1(Windows 主机,13 类采集项);
> `Y:`=采集包 P2(Windows 主机,16 类,含 SAM/SECURITY 专题);
> `A:`=采集包 P3(早期采集脚本产物,无四契约文件,hash 校验放宽如实标;
> 含 .venv/ 与 analysis/ 异物)。
> 逐文件路由台账:`go run ./cmd/ftmapwalk configs/wininfosc-map.yaml <包根>`
> (本切片新增台架工具);解析实测:`go run ./cmd/ftpackcount ...`。

## 1. 契约与元信息

| 采集项(bat 段落) | 产出 | 丰图路由/解析器 | E | Y | A |
|---|---|---|---|---|---|
| 采集时刻+时区(w32tm/tzutil) | `_COLLECTION_TIME.txt` | raw / collection_meta | raw | raw | — |
| 失败命令日志(:fail) | `_COLLECT_ERRORS.log` | raw / collection_errors | raw | raw | — |
| 完整性清单 | `_HASH_MANIFEST.txt`(严格档 `-Hash`:逐文件 SHA256+根哈希;默认档:「采集时未哈希」声明,平台入库时计算) | raw / hash_manifest | raw | raw | —(二开无,校验放宽如实标) |
| 采集足迹(:fp) | `_COLLECT_FOOTPRINT.txt` | `*.txt` → raw / text_snapshot | — | — | —(三包均为足迹特性前采集) |

## 2. 易失态快照(易失序优先段)

| 采集项 | 产出 | 路由/解析器 | E | Y | A |
|---|---|---|---|---|---|
| 进程快照 tasklist /V | `tasklist_process.csv` | raw / csv_snapshot | raw | raw | raw |
| 服务宿主 tasklist /SVC | `tasklist_services.csv` | raw / csv_snapshot | raw | raw | raw |
| 网络连接 netstat -abon | `netstat.txt` | **native / netstat → parsed**(0.25.0) | parsed | parsed | — |
| 已建立连接 | `netstat_established.txt` | **native / netstat → parsed**(0.25.0) | parsed | parsed | — |
| DNS 缓存 | `dns_cache.txt` | raw / text_snapshot | raw | raw | raw |
| ARP 表 | `arp_a.txt` | raw / text_snapshot | raw | raw | raw |
| NetBIOS 缓存 | `nbtstat_cache.txt` | raw / text_snapshot | raw | raw | raw |
| SMB 会话/共享连接 | `net_session.txt` / `net_use.txt` | raw / text_snapshot | raw | raw | raw |
| USN 变更日志 fsutil | `usn_journal_C.csv` | **native / usn_csv → parsed** | parsed(253,960 usn_change) | parsed(373,363) | — |
| $MFT(可选 RawCopy) | `MFT.bin` | **native / mft → parsed** | parsed(169,422 mft_entry+500 timestomp 候选) | parsed(1,525,107+500) | — |
| Everything 全盘清单 | `everything.efu` | **native / efu → parsed** | parsed(296,470 行) | parsed(2,219,400 行) | parsed(169,923 行,0 失败) |
| 环境变量 set | `Enviromment_var.txt` | raw / text_snapshot | raw | raw | raw |

## 3. 注册表快照(reg export 文本)

全部走 `REG_*.txt` → raw / registry_query(文本全文可检索;语义化键值证据
由 hive 二进制原生解析承担,见 §7)。bat 导出全集 44 个键:

- 基础 11 键:Shimcache / UserAssit / IFEO / CurrentVersionRun / BHO /
  ShellExecuteHooks / CurrentControlSet_Services / ControlSet001_Services /
  ControlSet002_Services / RunMRU / RecentDocs
- 持久化 6 键:Winlogon / AppInitDLLs / SessionManager / LSA /
  COM_Hijack_HKCU / HKCU_Run
- USB/网络/RDP 7 键:USBSTOR / USB / MountPoints2 / RDPServers / RDPDefault /
  NetworkProfiles / NetworkSignatures
- Defender 2 键:DefenderExclusions / DefenderPolicy
- 驻留面扩展 18 键:ContextMenuHandlers×3 / ShellExtensions×2 / Shellex×4 /
  NativeMessaging×7 / 浏览器扩展策略×6 / FileExts(collect_ext.ps1 另产
  `signatures.csv` + `REG_Shellex_ClassesAll.txt`)
- 其它:MuiCache / UserSettings(bam) / Recall_WindowsAI×2

| 包 | 实采 | 状态 |
|---|---|---|
| E | 24 键(无 ControlSet002/USBSTOR/RDP/驻留面扩展/Recall) | 全 raw / registry_query |
| Y | 25 键(E 集 + USBSTOR) | 全 raw / registry_query |
| A | 10 键(二开旧版子集) | 全 raw / registry_query |

驻留面扩展 18 键与 RDPServers/RDPDefault、Recall 键三包均未采到(采集版本差),
非解析缺口。`Navicat.reg`(HKCU PremiumSoft)三包皆无,`*.reg` → raw 兜底。

## 4. 事件日志

| 采集项 | 产出 | 路由/解析器 | E | Y | A |
|---|---|---|---|---|---|
| winevt 全量日志 | `Windows_logs/*.evtx` | **evtx_native(sidecar)→ parsed** | parsed(167 通道) | parsed(417) | parsed(108) |
| evtx 容量快照 | `evtx_sizes.txt` / `evtx_channel_stats.txt` | raw / text_snapshot | — | — | —(特性后采集,三包均早于该特性) |

## 5. NT6 目录采集件

| 采集项 | 产出 | 路由/解析器 | E | Y | A |
|---|---|---|---|---|---|
| JumpList 自动目标 | `JumpList/*.automaticDestinations-ms` | **native / jumplist → parsed** | parsed(13 件 45 条目) | parsed(177 件 510 条目) | — |
| 杀软日志(有则采) | `360log/` `QAXlog/` | `*.log` → raw | — | — | — |
| 计划任务文件 | `Tasks/{System32,SysWOW64}/*`(XML 无扩展名) | **unmapped 兜底 raw**(文本可全文检索) | unmapped(231) | unmapped(261) | unmapped(60+) |
| certutil 下载缓存 | `Virus/certutil/*` | **unmapped 兜底 raw**(二进制为主) | unmapped(30) | unmapped(596) | unmapped(14,含勒索后缀文件与勒索信,见验收文档) |
| ScreenOn 电源诊断 | `ScreenOn/*.etl` | **unmapped**(ETL 二进制) | unmapped(6) | unmapped | — |
| Temp 目录 | `Temp/*` | 按扩展名分流(.txt/.log raw;exe/tmp/db.ses 等 unmapped) | 混合 | 混合 | — |
| 最近访问 | `Recent/*.lnk` | **native / lnk → parsed** | parsed(3) | parsed(2) | —(目录空) |
| Amcache | `Amcache.hve` | (路由缺口:.hve 无规则,见 §8) | — | — | —(三包均未采到) |
| RDP 位图缓存 | `RDPBitmapCache/*` | `*.bin` → raw / binary_artifact;*.rdp → unmapped | — | —(目录空) | — |
| 时间线 | `ActivitiesCache*/**/ActivitiesCache.db` | **native / win_activities → parsed** | parsed(2 库 4 行) | parsed(2 库 1,868 行) | — |
| 时间线伴生 | `*.cdp/.sst/.cdpresource/.db-shm/.db-wal` | unmapped(WAL 不重放,已如实标) | unmapped | unmapped | — |
| PowerShell 历史 | `PSHistory/ConsoleHost_history.txt` | **desc / pshistory → parsed**(0.25.0;快照型 ts 恒 nil) | — | parsed | — |
| 启动目录 | `Startup/{CurrentUser,Global}/*` | `.lnk` → native parsed;其余 unmapped | parsed/U 混合 | 同左 | — |
| ShellBags(当前用户) | `ShellBags_CurrentUser/UsrClass.dat` | **native / registry_hive → parsed** | parsed | parsed | — |
| Defender 检测历史 | `DefenderHistory/*` | (空目录) | — | —(空) | — |
| SSH 密钥 | `SSH/{CurrentUser,Global}/*` | **unmapped**(密钥材料只登记,设计上不解析) | — | unmapped(2) | — |
| Win11 Recall | `Recall_CurrentUser/` + REG_Recall_* | (未实采,非 Win11 24H2) | — | — | — |
| 远控痕迹 | `RemoteAccess/{AnyDesk,TeamViewer,ToDesk,Sunlogin_Oray,...}` | `.txt/.log` → raw;`.trace/.conf/.cache/.png` 等 **unmapped** | — | 混合(181 件,AnyDesk/Sunlogin 实证) | — |

## 6. 系统状态与安全面

| 采集项 | 产出 | 路由 | E | Y | A |
|---|---|---|---|---|---|
| hosts / ipconfig /all / systeminfo / route print | 同名 .txt | raw / text_snapshot | raw | raw | raw |
| 账户:net user / net user Administrator / net localgroup(×2)/ Get-LocalUser | `net_user*.txt` / `net_localgroup*.txt` / `net_user_all.txt` | raw / text_snapshot | raw(net_user_all —) | raw(同左) | raw(同左) |
| 凭据管理器 cmdkey /l | `cmdkey.txt` | raw / text_snapshot | raw | raw | raw |
| 防火墙规则/端口代理 | `netsh_firewall_all.txt` / `netsh_portproxy_all.txt` | raw / text_snapshot | raw | raw | raw |
| 全量注册表导出 regedit /e | `regedit.reg` | raw / registry_export | raw | raw | raw(291MB,全文索引) |
| 隐藏文件/字体目录 | `dir_system32_hide.txt` / `dir_fonts.txt` | raw / text_snapshot | raw | raw | raw |
| Wi-Fi 历史+明文导出 | `wifi_profiles.txt` / `WiFiProfiles/*.xml` | txt → raw;**xml 无规则 → unmapped** | raw(导出未触发) | raw(同左) | — |
| 防火墙/Netlogon 日志 | `pfirewall.log` / `netlogon.log(.bak)` | `*.log` → raw;.bak unmapped | — | — | — |
| 审计策略 auditpol | `auditpol.txt` | raw / text_snapshot | raw | raw | — |
| 凭据保险箱 vaultcmd | `vault_creds.txt` | raw / text_snapshot | raw | raw | — |
| 驱动列表 | `driverquery.csv` | raw / csv_snapshot | raw | raw | — |
| 卷影副本 vssadmin | `vss_shadows.txt` | raw / text_snapshot | raw | raw | — |
| BITS 作业 | `bits_jobs.txt` | raw / text_snapshot | raw | raw | — |
| 回收站清单 | `recycle_bin_list.txt` | raw / text_snapshot | raw | raw | — |
| IIS 日志 | `IIS_Logs/*.log` | raw / log_snapshot | — | — | — |
| WMI 持久化订阅 | `WMI_Subscription/*.txt` ×3 | raw / text_snapshot | raw | raw | — |
| 计划任务查询 | `schtasks.txt` | raw / text_snapshot | raw | raw | raw |
| WMIC 快照(进程/账户/登录/补丁) | `WMIC_*.html/.txt` | raw / wmic_snapshot | raw(4) | raw(4) | raw(3) |
| wmic 兜底产物 | `tasklist_process.txt` / `query_user_logon.txt` / `qfe_from_systeminfo.txt` | raw / text_snapshot | (未触发) | (未触发) | (未触发) |

## 7. 注册表 hive 与 ESE 二进制

| 采集项 | 产出 | 路由/解析器 | E | Y | A |
|---|---|---|---|---|---|
| SOFTWARE hive | `SOFTWARE` | **native / registry_hive → parsed**(通用 kv) | parsed | parsed | — |
| SYSTEM hive | `SYSTEM` | **native / system_hive → parsed**(复合:通用遍历+Shimcache 专题) | parsed(Shimcache 261) | parsed(Shimcache 1,024) | — |
| SAM hive | `SAM` | **native / sam_accounts → parsed** | — | parsed(4 账户) | — |
| SECURITY hive | `SECURITY` | **native / security_policy → parsed**(域/审计策略/权限) | — | parsed(58) | — |
| SRUM | `SRUDB.dat` | **native / srum → parsed** | parsed(345) | parsed(251,691) | — |
| Windows 搜索索引 | `Windows.edb` | **unmapped(.edb 无规则=解析缺口)** | — | — | —(三包均未采到) |
| UAL(Server SKU) | `UAL/*.mdb` | **unmapped(.mdb 无规则=解析缺口)** | — | — | — |
| IE/Edge WebCache | `Users/*/Browser/IE/WebCacheV01.dat` | `*.dat` → raw / binary_artifact(ESE 未解析=缺口) | — | — | — |

## 8. 逐用户采集(Users/<U>/,多用户遍历段)

| 采集项 | 路由/解析器 | E | Y | A |
|---|---|---|---|---|
| PSHistory / Startup / SSH / Recall / RDPBitmapCache | 同 §5 同名项 | 按存在性同 §5 | 同左 | —(二开无逐用户段) |
| 浏览器 Chromium 历史 | `History` → **native / browser_chromium_history → parsed** | parsed(Edge,空库如实 0) | parsed(Edge 31 urls/9 visits/10 downloads) | — |
| 浏览器 Firefox 历史 | `places.sqlite` → **native / browser_firefox_places → parsed** | — | parsed(4,609/5,490) | — |
| 浏览器 Cookies / Login Data / Downloads | **unmapped**(无扩展名;树庭三 parser 未移植,已记账) | unmapped | unmapped | — |
| Firefox profile 其余件(jsonlz4/xpi/sqlite/png 等) | **unmapped**(采集端整目录拷,分析端设计口径只取 places.sqlite) | — | unmapped(741 件大头) | — |
| UsrClass.dat ShellBags | **native / registry_hive → parsed** | parsed | parsed | — |
| 逐用户 REG 导出 9 键 | raw / registry_query | raw | raw | — |
| CredStore(NetSarang/MobaXterm/WinSCP.ini) | **unmapped**(凭据材料只登记,设计上不解析) | — | unmapped | — |
| 逐用户远控(AnyDesk/TeamViewer/ToDesk/RustDesk/SunloginClient/Oray) | 同 §5 远控行 | — | 混合 | — |

## 9. 包内异物(非采集项,如实标注)

| 物 | 包 | 处置 |
|---|---|---|
| `.venv/`(Python 虚拟环境,1,689 文件) | A | unmapped 兜底登记;非采集项,属采集环境污染 |
| `analysis/`(前人应急工作产物:sec_pass1.py/out/) | A | unmapped 兜底登记;人工作品非证据源 |
| `应急响应报告_*.md`(人写结论报告) | A | **摄入前按考题纪律排除**(摄入脚本 EXCLUDE 清单),不进平台 |
| 勒索加密后缀文件(3 件) | A | unmapped 兜底登记(二进制;EFU 已索引其路径) |

## 10. unmapped 清单(按价值排序)

### 解析器缺口(值得补,按价值降序)

1. **计划任务 XML**(Tasks/{System32,SysWOW64},无扩展名,三包合计 550+ 件)——
   驻留排查核心源;当前靠 raw 兜底全文检索能搜到文本,但无结构化
   (Action/Trigger/作者)提取,`host-persistence-task` 算子吃不到。
   建议:映射表加 `Tasks/**` 目录规则 + 任务 XML 解析器。
2. **ESE 三件套**:`Windows.edb`(搜索索引)/ `UAL/*.mdb`(Server 用户访问
   日志)/ `WebCacheV01.dat`(IE 浏览器)——go-ese 依赖已在(SRUM 实证),
   缺解析器与路由;UAL 对 Server 入口面价值高。
3. **certutil 下载缓存**(Virus/certutil,三包合计 640 件)——下载取证直接
   证据;MetaData 为文本可先行解析,Content 为内容体。
4. **Amcache.hve 路由**:hive 解析器已有,只差 `.hve` 映射规则(零解析器
   成本;当前三包未采到,采集端确认后即补)。
5. **浏览器 Cookies / Login Data / Downloads**(树庭有三 parser 未移植,
   M3b 已记账;Login Data 涉凭据材料,移植需过敏感面评审)。
6. **RemoteAccess 各厂商日志**(.trace/.conf/.cache)——远控通道考题直接
   相关;格式厂商各异,宜按厂商逐个做解析器,当前文本件(.txt/.log)
   已 raw 可检索。

### 设计上的不解析(登记留证即可)

- SSH 密钥材料 / CredStore 凭据材料(敏感面,只登记不展开);
- ScreenOn `.etl` / RDP 位图缓存 `.bmc`(二进制取证格式,价值/成本比低);
- Temp/Startup 内二进制与 desktop.ini 等;ActivitiesCache 伴生 .cdp/.sst
  /WAL(WAL 不重放已在解析器如实标注);
- Firefox profile 非 places 件(采集端整目录留证,分析端设计口径只取
  places.sqlite);
- 包内异物(.venv/analysis/,§9)。

## 11. 解析实测台账(ftpackcount,无库走查,0 文件级失败)

| 包 | native 路由文件 | 结构化事件合计 | 文件级失败 |
|---|---|---|---|
| E(P1) | 13 类(efu/mft/prefetch/lnk/usn/jumplist/srum/activities/hive×3/浏览器/… ) | 1,199,885 | 0 |
| Y(P2) | 16 类(含 SAM/SECURITY 专题) | 5,232,975 | 0 |
| A(P3) | efu(早期版包无 hive/MFT/Prefetch 等) | 169,924(efu) | 0 |

A 包全管线(验收二进制,含 PG/CH):files=1,942,
events=2,220,448(=2,050,524 evtx/raw + 169,924 efu),bad=0,skip=0,
failures=0,unmapped=1,782(其中 .venv 异物 1,689 件)。全量实战验收
台账为内部存档,未随本仓公开。
