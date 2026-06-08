# DARPA 攻击评估基准文件

## 说明

- 这份文件用于后续 DARPA 数据集 ATT&CK 检测实验的统一评估输入。
- 评估粒度是 `host + attack_window`。
- 主评估口径以 `confirmed` 窗口和 `confirmed_techniques` 为准。
- `attempted_failed` 单独统计，不纳入主成功 recall/precision 分母。

## 来源

- 官方攻击报告: `TC_Ground_Truth_Report_E3_Update.pdf`
- 官方攻击报告路径: `D:\download\TC_Ground_Truth_Report_E3_Update.pdf`
- 严格映射文件: `D:\download\ALL_HOSTS_ATTCK_STRICT_MAPPING.md`
- 宽松映射文件: `D:\download\ALL_HOSTS_ATTACK_ATTCK_MAPPING.md`
- 推荐 GT 时间偏移:
  - `TRACE`: `240` 分钟

## CADETS

| Window ID | 时间 | 状态 | 攻击摘要 | Confirmed Tactics | Confirmed Techniques | Attempted Techniques | 来源页码 |
|---|---|---|---|---|---|---|---|
| CADETS_20180406_1121_1208_01 | 2018-04-06 11:21:00 - 2018-04-06 12:08:00 | confirmed | “exploiting Nginx”；`HTTP post`；loaderDrakon 连接 operator console；`putfile libdrakon`；`ps`；`inject /var/log/devc 809`；CADETS 崩溃。 | INITIAL_ACCESS, COMMAND_AND_CONTROL, DISCOVERY | T1190, T1071.001, T1105, T1057 | T1055 | 3,4 |
| CADETS_20180411_1508_1515_02 | 2018-04-11 15:08:00 - 2018-04-11 15:15:00 | confirmed | 再次利用 Nginx malformed HTTP request；`throw http payload`；`putfile libdrakon`；`inject /tmp/grain 802`；CADETS crashed。 | INITIAL_ACCESS, COMMAND_AND_CONTROL | T1190, T1071.001, T1105 | T1055 | 16,17 |
| CADETS_20180412_1400_1438_03 | 2018-04-12 14:00:00 - 2018-04-12 14:38:00 | confirmed | Nginx exploit 后 Drakon implant 连接 HTTP operator console；多次 `putfile microapt`；micro APT 连接 C2；`APT>scan` 多个 128.55.12.* 目标端口范围。 | INITIAL_ACCESS, COMMAND_AND_CONTROL, DISCOVERY, DEFENSE_EVASION | T1190, T1071.001, T1105, T1046, T1070.004 |  | 23,24,25 |
| CADETS_20180413_0904_0915_04 | 2018-04-13 09:04:00 - 2018-04-13 09:15:00 | confirmed | 重新利用 Nginx HTTP request；Drakon 在 Nginx 内存中运行并 C2 回连；`putfile drakon`、`putfile libdrakon`；`whoami`、`ps`；多次 `inject` 到 sshd PID 20691。 | INITIAL_ACCESS, COMMAND_AND_CONTROL, DISCOVERY | T1190, T1071.001, T1105, T1033, T1057 | T1055 | 26,27,28 |

## CLEARSCOPE

| Window ID | 时间 | 状态 | 攻击摘要 | Confirmed Tactics | Confirmed Techniques | Attempted Techniques | 来源页码 |
|---|---|---|---|---|---|---|---|
| CLEARSCOPE_20180406_1440_1517_01 | 2018-04-06 14:40:00 - 2018-04-06 15:17:00 | confirmed | 钓鱼邮件发送给 Bob；链接到 `www.nasa.ng`；用户点击链接；输入姓名、邮箱、密码；结果发送到 `www.foo1.com`。 | INITIAL_ACCESS, EXECUTION | T1566.002, T1204.001 |  | 32,33 |
| CLEARSCOPE_20180411_1355_1447_02 | 2018-04-11 13:55:00 - 2018-04-11 14:47:00 | confirmed | Android Firefox 访问 `www.mit.gov.jo`；获得 shell；`putfile drakon`；`elevate shared_files`；Drakon 回连；`cat hosts`；`getfile fb-schedule`；`putfile libdrakon`；`inject failed`。 | INITIAL_ACCESS, EXECUTION, COMMAND_AND_CONTROL, DISCOVERY, COLLECTION | T1189, T1203, T1071.001, T1105, T1016, T1005 | T1055 | 13,14,15 |
| CLEARSCOPE_20180412_1519_1524_03 | 2018-04-12 15:19:00 - 2018-04-12 15:24:00 | confirmed | 使用遗留 Drakon root 连接；`whoami`；`putfile libdrakon`；`inject failed`；`put shared_lib`；`elevate worked`；连接保持打开。 | DISCOVERY, COMMAND_AND_CONTROL, DEFENSE_EVASION | T1033, T1105, T1071.001, T1070.004 | T1055 | 15,16 |

## FAROS

| Window ID | 时间 | 状态 | 攻击摘要 | Confirmed Tactics | Confirmed Techniques | Attempted Techniques | 来源页码 |
|---|---|---|---|---|---|---|---|
| FAROS_20180411_1100_1100_01 | 2018-04-11 11:00:00 | insufficient | 表中 FAROS 对应 Drakon，但 Description 为 `N/A`。 |  |  |  | 2 |
| FAROS_20180409_1338_1338_02 | 2018-04-09 13:38:00 | insufficient | FiveDirections 攻击上下文中出现 “Failed to load e-mail client on FAROS”。 |  |  |  | 34,35 |

## FIVEDIRECTIONS

| Window ID | 时间 | 状态 | 攻击摘要 | Confirmed Tactics | Confirmed Techniques | Attempted Techniques | 来源页码 |
|---|---|---|---|---|---|---|---|
| FIVEDIRECTIONS_20180409_1319_1542_01 | 2018-04-09 13:19:00 - 2018-04-09 15:42:00 | confirmed | 发送 Excel 宏附件；PowerShell 命令下载 `update.ps1` 并执行；FiveDirections 上宏未自动执行，后来手动运行 PowerShell 后得到连接；执行 `tasklist`、读取 hosts 和多个本地文档；删除 `BoviaBenefitsOE.xlsm`。 | INITIAL_ACCESS, EXECUTION, COMMAND_AND_CONTROL, DISCOVERY, COLLECTION, DEFENSE_EVASION | T1566.001, T1059.001, T1105, T1095, T1057, T1016, T1005, T1070.004 |  | 34,35,36 |
| FIVEDIRECTIONS_20180411_1000_1040_02 | 2018-04-11 10:00:00 - 2018-04-11 10:40:00 | confirmed | Firefox 访问 `www.cnpc.com.cn`，多次崩溃后连接成功；netrecon；`hostname`；`cat` / `getfile` 多个 rtf/docx/xlsx 文件；报告说明 exfil 多个文件。 | INITIAL_ACCESS, EXECUTION, COMMAND_AND_CONTROL, DISCOVERY, COLLECTION, EXFILTRATION | T1189, T1203, T1071.001, T1082, T1005, T1041 |  | 10,11,12 |
| FIVEDIRECTIONS_20180412_1113_1114_03 | 2018-04-12 11:13:00 - 2018-04-12 11:14:00 | attempted_failed | malicious pass manager browser extension 尝试；loaderDrakon / Drakon dropper 失败；Drakon 崩溃；`hJauWl01 file downloaded to disk`。 |  |  | T1203, T1105 | 19,20 |

## TA5.2

| Window ID | 时间 | 状态 | 攻击摘要 | Confirmed Tactics | Confirmed Techniques | Attempted Techniques | 来源页码 |
|---|---|---|---|---|---|---|---|
| TA5.2_20180409_1419_1420_01 | 2018-04-09 14:19:00 - 2018-04-09 14:20:00 | confirmed | `BoviaBenefitsOE.xlsm` 附件；用户打开表格后宏运行 PowerShell；下载 `update.ps1`；powercat 回连。 | INITIAL_ACCESS, EXECUTION, COMMAND_AND_CONTROL, DEFENSE_EVASION | T1566.001, T1204.002, T1059.001, T1105, T1095, T1070.004 |  | 33,34 |
| TA5.2_20180410_1400_1400_02 | 2018-04-10 14:00:00 | confirmed | 用户打开钓鱼邮件；点击链接；连接 `www.nasa.ng`；输入凭证并提交到 `www.foo1.com`。 | INITIAL_ACCESS, EXECUTION | T1566.002, T1204.001 |  | 38,39 |
| TA5.2_20180411_1043_1054_03 | 2018-04-11 10:43:00 - 2018-04-11 10:54:00 | confirmed | Firefox 访问恶意链路并连接；运行 netrecon；`cat` 多个本地文件；`getfile` 文档；`cat hosts/networks/services`；`nrtcp`。 | INITIAL_ACCESS, EXECUTION, COMMAND_AND_CONTROL, DISCOVERY, COLLECTION, EXFILTRATION | T1189, T1203, T1071.001, T1016, T1005, T1041 |  | 12,13 |
| TA5.2_20180412_1008_1046_04 | 2018-04-12 10:08:00 - 2018-04-12 10:46:00 | attempted_failed | browser extension / dropper 尝试；no callback；10:43 写入文件但未回连；Drakon 崩溃；文件留在磁盘。 |  |  | T1203, T1105 | 18,19 |

## THEIA

| Window ID | 时间 | 状态 | 攻击摘要 | Confirmed Tactics | Confirmed Techniques | Attempted Techniques | 来源页码 |
|---|---|---|---|---|---|---|---|
| THEIA_20180410_1341_1455_01 | 2018-04-10 13:41:00 - 2018-04-10 14:55:00 | confirmed | 通过 Firefox 54.0.1 和恶意网站攻击；14:31 `www.gatech.edu` 获得 shell；`putfile clean`；`elevate clean`；`connect back`；再次 re-exploit 并写入 profile/xdev。 | INITIAL_ACCESS, EXECUTION, COMMAND_AND_CONTROL | T1189, T1203, T1071.001, T1105 |  | 7,8,9 |
| THEIA_20180410_1342_1342_02 | 2018-04-10 13:42:00 | confirmed | THEIA 打开钓鱼邮件；点击链接；连接 `www.nasa.ng`；输入凭证并提交到 `www.foo1.com`。 | INITIAL_ACCESS, EXECUTION | T1566.002, T1204.001 |  | 37,38 |
| THEIA_20180412_1244_1326_03 | 2018-04-12 12:44:00 - 2018-04-12 13:26:00 | confirmed | browser extension 攻击；`whoami`；`ps`；多次 `inject` 到 sshd 失败；`putfile microapt`；micro APT C2；大量 `APT>scan`；`rm mail`。 | EXECUTION, DISCOVERY, COMMAND_AND_CONTROL, DEFENSE_EVASION | T1203, T1033, T1057, T1105, T1071.001, T1046, T1070.004 | T1055 | 20,21,22 |
| THEIA_20180413_1350_1404_04 | 2018-04-13 13:50:00 - 2018-04-13 14:04:00 | attempted_failed | 恶意可执行附件 `tcexec`；用户下载并运行；因缺少依赖失败。 |  |  | T1566.001, T1204.002 | 39,40 |

## TRACE

| Window ID | 时间 | 状态 | 攻击摘要 | Confirmed Tactics | Confirmed Techniques | Attempted Techniques | 来源页码 |
|---|---|---|---|---|---|---|---|
| TRACE_20180410_0946_1109_01 | 2018-04-10 09:46:00 - 2018-04-10 11:09:00 | confirmed | 通过 `www.allstate.com` 恶意广告/网站利用 Firefox 54.0.1；10:49 收到 OC2 连接；`putfile drakon`；`elevate drakon`；`putfile libdrakon` 到 `/var/log/xtmp`。 | INITIAL_ACCESS, EXECUTION, COMMAND_AND_CONTROL | T1189, T1203, T1071.001, T1105 |  | 5,6,7 |
| TRACE_20180410_1228_1230_02 | 2018-04-10 12:28:00 - 2018-04-10 12:30:00 | confirmed | TRACE 打开 phishing email；点击链接；连接 `www.nasa.ng`；输入凭证并提交；连接 `www.foo1.com`。 | INITIAL_ACCESS, EXECUTION | T1566.002, T1204.001 |  | 36,37 |
| TRACE_20180412_1336_1336_03 | 2018-04-12 13:36:00 | attempted_failed | 尝试通过 malicious pass manager browser extension 攻击；Firefox 访问恶意站点后挂起；未收到 operator console 连接。 |  |  | T1203 | 22,23 |
| TRACE_20180413_1243_1253_04 | 2018-04-13 12:43:00 - 2018-04-13 12:53:00 | confirmed | 浏览 `allstate.com` 后得到 shell；`ps`；`execfile /tmp/ztmp`；micro APT callback；micro portscan；`rm /tmp/ztmp`；netrecon 地址 8064。 | EXECUTION, COMMAND_AND_CONTROL, DISCOVERY, DEFENSE_EVASION | T1203, T1071.001, T1057, T1105, T1046, T1070.004 |  | 28,29,30 |
| TRACE_20180413_1350_1428_05 | 2018-04-13 13:50:00 - 2018-04-13 14:28:00 | confirmed | 发送恶意可执行附件；用户下载/运行 `tcexec` 但失败；随后发送 micro APT；用户打开带附件邮件后 micro APT 自动执行、C2 回连并 portscan。 | INITIAL_ACCESS, EXECUTION, COMMAND_AND_CONTROL, DISCOVERY | T1566.001, T1204.002, T1105, T1071.001, T1046 |  | 40,41,42 |

## Technique 到 Tactic 对照

| Technique | Tactics |
|---|---|
| T1005 | COLLECTION |
| T1016 | DISCOVERY |
| T1033 | DISCOVERY |
| T1041 | EXFILTRATION |
| T1046 | DISCOVERY |
| T1055 | DEFENSE_EVASION, PRIVILEGE_ESCALATION |
| T1057 | DISCOVERY |
| T1059.001 | EXECUTION |
| T1070.004 | DEFENSE_EVASION |
| T1071.001 | COMMAND_AND_CONTROL |
| T1082 | DISCOVERY |
| T1095 | COMMAND_AND_CONTROL |
| T1105 | COMMAND_AND_CONTROL |
| T1189 | INITIAL_ACCESS |
| T1190 | INITIAL_ACCESS |
| T1203 | EXECUTION |
| T1204.001 | EXECUTION |
| T1204.002 | EXECUTION |
| T1210 | LATERAL_MOVEMENT |
| T1566.001 | INITIAL_ACCESS |
| T1566.002 | INITIAL_ACCESS |
