from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[2]
REPORT_MD_PATH = Path(
    r"D:\dataji\TC_Ground_Truth_Report_E3_Update_md\TC_Ground_Truth_Report_E3_Update.md"
)
LEGACY_GT_PATH = REPO_ROOT / "docs" / "darpa_attack_eval_ground_truth_2026-05-26.json"
OUTPUT_JSON_PATH = REPO_ROOT / "docs" / "darpa_attack_eval_ground_truth_e3_report_enriched_20260618.json"
OUTPUT_MD_PATH = REPO_ROOT / "docs" / "darpa_attack_eval_ground_truth_e3_report_enriched_20260618.md"

TARGET_HOSTS = {"TRACE", "CADETS", "THEIA", "FIVEDIRECTIONS"}
HOST_ALIASES = {
    "TRACE": "TRACE",
    "CADETS": "CADETS",
    "THEIA": "THEIA",
    "FIVEDIRECTIONS": "FIVEDIRECTIONS",
    "FIVEDIRECTIONS": "FIVEDIRECTIONS",
    "FIVEDIRECTIONS WINDOWS": "FIVEDIRECTIONS",
    "FIVEDIRECTIONS –": "FIVEDIRECTIONS",
    "FIVEDIRECTIONS -": "FIVEDIRECTIONS",
    "FIVEDIRECTIONS/WINDOWS": "FIVEDIRECTIONS",
    "FIVEDIRECTIONS WINDOWS 10": "FIVEDIRECTIONS",
    "FIVEDIRECTIONS WINDOWS 10 X64": "FIVEDIRECTIONS",
    "FIVEDIRECTIONS WINDOWS X64": "FIVEDIRECTIONS",
    "FIVEDIRECTIONS WINDOWS HOST": "FIVEDIRECTIONS",
    "FIVEDIRECTIONS WINDOWS HOSTS": "FIVEDIRECTIONS",
    "FIVEDIRECTIONS": "FIVEDIRECTIONS",
    "FiveDirections".upper(): "FIVEDIRECTIONS",
}

TACTIC_TO_LABEL = {
    "INITIAL_ACCESS": "初始进入",
    "EXECUTION": "执行",
    "PRIVILEGE_ESCALATION": "提权",
    "COMMAND_AND_CONTROL": "命令控制",
    "DISCOVERY": "侦察发现",
    "CREDENTIAL_ACCESS": "凭证获取",
    "COLLECTION": "数据收集",
    "EXFILTRATION": "数据外传",
    "DEFENSE_EVASION": "防御规避",
}

TECHNIQUE_TO_TACTICS_REFERENCE = {
    "T1190": ["INITIAL_ACCESS"],
    "T1189": ["INITIAL_ACCESS"],
    "T1203": ["EXECUTION"],
    "T1071.001": ["COMMAND_AND_CONTROL"],
    "T1105": ["COMMAND_AND_CONTROL"],
    "T1057": ["DISCOVERY"],
    "T1046": ["DISCOVERY"],
    "T1033": ["DISCOVERY"],
    "T1055": ["DEFENSE_EVASION", "PRIVILEGE_ESCALATION"],
    "T1566.002": ["INITIAL_ACCESS"],
    "T1204.001": ["EXECUTION"],
    "T1566.001": ["INITIAL_ACCESS"],
    "T1204.002": ["EXECUTION"],
    "T1059.001": ["EXECUTION"],
    "T1070.004": ["DEFENSE_EVASION"],
    "T1005": ["COLLECTION"],
    "T1041": ["EXFILTRATION"],
}


@dataclass(frozen=True)
class LineRecord:
    line_no: int
    text: str


@dataclass
class Subsection:
    subsection_id: str
    title: str
    level: int
    start_line: int
    end_line: int
    body_lines: list[LineRecord]
    synthetic: bool = False


@dataclass
class Section:
    section_id: str
    heading: str
    title: str
    host: str
    start_line: int
    end_line: int
    date_token: str
    time_token: str
    report_pages: list[int]
    subsections: list[Subsection]


def _selector(*contains_any: str, subsection_contains: str = "", evidence_type: str = "") -> dict[str, str | list[str]]:
    return {
        "contains_any": list(contains_any),
        "subsection_contains": subsection_contains,
        "evidence_type": evidence_type,
    }


SECTION_SPECS: dict[str, dict[str, Any]] = {
    "3.1": {
        "status": "confirmed",
        "time_precision": "minute_window",
        "start_time": "2018-04-06T11:21:00",
        "end_time": "2018-04-06T12:08:00",
        "attack_summary": "CADETS 上的 Nginx 被成功利用，drakon/operator console 回连建立，攻击者提权运行 netrecon 并尝试向 sshd 注入 libdrakon，最终 CADETS 崩溃。",
        "notes": "窗口只把成功攻击链记为 confirmed；失败的 sshd 注入除保留在 behavior_chain 外，也上升为 attempted DEFENSE_EVASION。",
        "behaviors": [
            {
                "behavior_id": "exploit_delivery",
                "action": "exploit_delivery",
                "judgment": "confirmed",
                "why": "报告正文与 Event Log 都明确写到第二次 Nginx exploit 成功。",
                "selectors": [_selector("second attempt succeeded", "Successful, connect back", "HTTP post sent, exploit worked")],
            },
            {
                "behavior_id": "c2_callback",
                "action": "c2_callback",
                "judgment": "confirmed",
                "why": "loaderDrakon/operator console 回连在正文、Event Log 和连接交互中都有明确记录。",
                "selectors": [_selector("loaderDrakon connected to an operator console shell", "connect back", "nginx: connection to 200.36.109.214:80", "vUgefal: connection to 139.123.0.113:80")],
            },
            {
                "behavior_id": "payload_elevate",
                "action": "payload_elevate",
                "judgment": "confirmed",
                "why": "正文写明下载文件后被提升为 root 新进程，交互里也有 elevate。",
                "selectors": [_selector("elevated as a new process running as root", "11:33 elevate", "elevate /tmp/vUgefal")],
            },
            {
                "behavior_id": "network_scan",
                "action": "scan",
                "judgment": "confirmed",
                "why": "Event Log 里的 nrinfo/nrtcp 与正文里的 netrecon 共同支撑网络侦察行为。",
                "selectors": [_selector("11:38 nrinfo", "11:39 nrtcp", "11:42 nrtcp", "netrecon module failed", "F2>nrtcp 61.167.39.128 80")],
            },
            {
                "behavior_id": "module_transfer",
                "action": "payload_write",
                "judgment": "confirmed",
                "why": "Event Log 和文件交互均明确记录了 libdrakon 落盘到 /var/log/devc。",
                "selectors": [_selector("putfile ./deploy/archive/libdrakon", "/var/log/devc")],
            },
            {
                "behavior_id": "inject_attempt",
                "action": "inject_attempt",
                "judgment": "attempted",
                "why": "报告明确记录了向 sshd 注入 libdrakon 的尝试，但失败并导致 CADETS 崩溃。",
                "selectors": [_selector("inject /var/log/devc", "inject foo 123", "no injection", "kernel panic")],
            },
            {
                "behavior_id": "process_discovery",
                "action": "process_discovery",
                "judgment": "confirmed",
                "why": "Event Log 中有显式 ps。",
                "selectors": [_selector("12:04 ps")],
            },
        ],
        "tactic_rationales": [
            {
                "tactic": "INITIAL_ACCESS",
                "judgment": "confirmed",
                "why": "Nginx exploit 成功并进入目标主机，是窗口的进入起点。",
                "behavior_ids": ["exploit_delivery"],
            },
            {
                "tactic": "EXECUTION",
                "judgment": "confirmed",
                "why": "攻击者把 drakon/netrecon 相关载荷落盘并提权运行。",
                "behavior_ids": ["payload_elevate", "module_transfer"],
            },
            {
                "tactic": "PRIVILEGE_ESCALATION",
                "judgment": "confirmed",
                "why": "正文明确写到新进程以 root 权限运行。",
                "behavior_ids": ["payload_elevate"],
            },
            {
                "tactic": "COMMAND_AND_CONTROL",
                "judgment": "confirmed",
                "why": "drakon/operator console 回连在多处证据中被直接描述。",
                "behavior_ids": ["c2_callback"],
            },
            {
                "tactic": "DISCOVERY",
                "judgment": "confirmed",
                "why": "攻击者执行 nrinfo/nrtcp 与 ps，对网络和进程做侦察。",
                "behavior_ids": ["network_scan", "process_discovery"],
            },
            {
                "tactic": "DEFENSE_EVASION",
                "judgment": "attempted",
                "why": "报告明确记录了向 sshd 注入 libdrakon 的尝试，但最终失败并导致主机崩溃。",
                "behavior_ids": ["inject_attempt"],
            },
        ],
        "technique_rationales": [
            {
                "technique_id": "T1190",
                "judgment": "confirmed",
                "why": "报告明确写明利用 Nginx 公网服务发起 exploit。",
                "behavior_ids": ["exploit_delivery"],
            },
            {
                "technique_id": "T1071.001",
                "judgment": "confirmed",
                "why": "drakon/operator console 使用 web/HTTP 风格回连进行控制。",
                "behavior_ids": ["c2_callback"],
            },
            {
                "technique_id": "T1105",
                "judgment": "confirmed",
                "why": "攻击者把 drakon/libdrakon/netrecon 等组件传入主机使用。",
                "behavior_ids": ["module_transfer"],
            },
            {
                "technique_id": "T1046",
                "judgment": "confirmed",
                "why": "nrtcp/netrecon 明确对应网络服务侦察。",
                "behavior_ids": ["network_scan"],
            },
            {
                "technique_id": "T1057",
                "judgment": "confirmed",
                "why": "Event Log 中有直接的 ps 进程枚举。",
                "behavior_ids": ["process_discovery"],
            },
            {
                "technique_id": "T1055",
                "judgment": "attempted",
                "why": "libdrakon 被用于对 sshd 进程做 inject 尝试，但最终失败。",
                "behavior_ids": ["inject_attempt"],
            },
        ],
    },
    "3.2": {
        "status": "confirmed",
        "time_precision": "minute_window",
        "start_time": "2018-04-10T09:46:00",
        "end_time": "2018-04-10T11:09:00",
        "attack_summary": "TRACE 通过恶意网站/广告利用 Firefox，drakon 在内存中获得 shell，随后把 drakon/libdrakon 落盘并提权为 root 进程，留下开放连接。",
        "notes": "窗口保留多次 Firefox crash 作为 exploit 失败重试背景，但 confirmed tactics 只统计最终成功形成的攻击行为。",
        "behaviors": [
            {
                "behavior_id": "driveby_exploit",
                "action": "exploit_delivery",
                "judgment": "confirmed",
                "why": "正文写明通过 www.allstate.com 恶意广告/网站成功利用 Firefox。",
                "selectors": [_selector("exploiting Firefox 54.0.1", "www.allstate.com", "10:49 Received 2 connections to the OC2")],
            },
            {
                "behavior_id": "c2_callback",
                "action": "c2_callback",
                "judgment": "confirmed",
                "why": "正文写明 drakon 在 Firefox 内存中回连 operator console，Event Log 也记录了收到 OC2 连接。",
                "selectors": [_selector("connection out to the attacker operator console", "Received 2 connections to the OC2", "cache: connection to 180.156.107.146")],
            },
            {
                "behavior_id": "payload_write",
                "action": "payload_write",
                "judgment": "confirmed",
                "why": "putfile 明确把 drakon 和 libdrakon 写到目标磁盘。",
                "selectors": [_selector("putfile ./deploy/archive/drakon.linux.x64", "putfile ./deploy/archive/libdrakon", "/home/admin/cache", "xtmp")],
            },
            {
                "behavior_id": "payload_elevate",
                "action": "payload_elevate",
                "judgment": "confirmed",
                "why": "正文与交互都明确写明 drakon 从磁盘以 root 身份执行。",
                "selectors": [_selector("using a privilege escalated execution capability", "10:51 elevate drakon", "elevate /home/admin/cache")],
            },
        ],
        "tactic_rationales": [
            {"tactic": "INITIAL_ACCESS", "judgment": "confirmed", "why": "恶意网站 exploit 成功形成 TRACE 的初始进入。", "behavior_ids": ["driveby_exploit"]},
            {"tactic": "EXECUTION", "judgment": "confirmed", "why": "drakon 被写盘后再次执行，形成显式载荷执行。", "behavior_ids": ["payload_write", "payload_elevate"]},
            {"tactic": "PRIVILEGE_ESCALATION", "judgment": "confirmed", "why": "正文明确写到新 drakon 进程以 root 运行。", "behavior_ids": ["payload_elevate"]},
            {"tactic": "COMMAND_AND_CONTROL", "judgment": "confirmed", "why": "operator console/OC2 回连在正文、Event Log、连接交互三处共同支撑。", "behavior_ids": ["c2_callback"]},
        ],
        "technique_rationales": [
            {"technique_id": "T1189", "judgment": "confirmed", "why": "通过恶意网站/广告触发 Firefox exploit。", "behavior_ids": ["driveby_exploit"]},
            {"technique_id": "T1071.001", "judgment": "confirmed", "why": "攻击者通过 web/HTTP 风格连接维持 drakon/operator console 通信。", "behavior_ids": ["c2_callback"]},
            {"technique_id": "T1105", "judgment": "confirmed", "why": "putfile 明确把 drakon/libdrakon 传入目标主机。", "behavior_ids": ["payload_write"]},
        ],
    },
    "3.3": {
        "status": "confirmed",
        "time_precision": "minute_window",
        "start_time": "2018-04-10T13:41:00",
        "end_time": "2018-04-10T14:55:00",
        "attack_summary": "THEIA 通过恶意网站 exploit Firefox，drakon 两次获得 shell，并把 clean/profile/xdev 等载荷写盘、提权、回连，最后又留下可后续触发的盘上落地物。",
        "notes": "09:58 的主机重启说明被保留在证据里，但时间窗按真正的攻击交互阶段取 13:41-14:55；rm clean / rm profile 作为原文明确给出的清理动作，上升为 confirmed DEFENSE_EVASION。",
        "behaviors": [
            {
                "behavior_id": "driveby_exploit",
                "action": "exploit_delivery",
                "judgment": "confirmed",
                "why": "报告正文与 Event Log 都明确写明 THEIA 通过 www.gatech.edu 重新 exploit 成功。",
                "selectors": [_selector("www.gatech.edu", "14:31 Shell from THEIA", "14:55 re-exploit gatech.edu")],
            },
            {
                "behavior_id": "c2_callback",
                "action": "c2_callback",
                "judgment": "confirmed",
                "why": "drakon/operator console 的 shell 与 connect back 记录齐全。",
                "selectors": [_selector("connection out to the attacker operator console", "14:35 connect back", "profile: connection to 161.116.88.72:80")],
            },
            {
                "behavior_id": "payload_write",
                "action": "payload_write",
                "judgment": "confirmed",
                "why": "putfile clean/profile/xdev 直接记录了落地载荷与后续待用文件。",
                "selectors": [_selector("putfile clean", "putfile profile", "putfile /var/log/xdev", "putfile ./deploy/archive/libdrakon")],
            },
            {
                "behavior_id": "payload_elevate",
                "action": "payload_elevate",
                "judgment": "confirmed",
                "why": "正文写明 drakon 以 root 运行，交互里也有 elevate clean/profile。",
                "selectors": [_selector("run the new process as root", "elevate clean", "elevate /home/admin/profile", "elevate /home/admin/clean")],
            },
            {
                "behavior_id": "network_scan",
                "action": "scan",
                "judgment": "confirmed",
                "why": "连接交互中出现 L2>nrtcp，说明使用 netrecon 做网络探测。",
                "selectors": [_selector("L2>nrtcp 7.149.198.40 80", "netrecon (www.gatech.edu)")],
            },
            {
                "behavior_id": "cleanup_delete",
                "action": "file_delete",
                "judgment": "confirmed",
                "why": "交互里明确写出 rm clean 与 rm profile，属于成功完成的落地物清理。",
                "selectors": [_selector("rm clean", "rm profile")],
            },
        ],
        "tactic_rationales": [
            {"tactic": "INITIAL_ACCESS", "judgment": "confirmed", "why": "Firefox 恶意网站 exploit 成功进入 THEIA。", "behavior_ids": ["driveby_exploit"]},
            {"tactic": "EXECUTION", "judgment": "confirmed", "why": "drakon/libdrakon 被写盘并执行。", "behavior_ids": ["payload_write", "payload_elevate"]},
            {"tactic": "PRIVILEGE_ESCALATION", "judgment": "confirmed", "why": "正文明确写明新的 drakon 进程以 root 身份运行。", "behavior_ids": ["payload_elevate"]},
            {"tactic": "COMMAND_AND_CONTROL", "judgment": "confirmed", "why": "shell、connect back 与 profile 对外连接共同表明已形成 C2。", "behavior_ids": ["c2_callback"]},
            {"tactic": "DISCOVERY", "judgment": "confirmed", "why": "nrtcp/netrecon 对网络接口与可达性做侦察。", "behavior_ids": ["network_scan"]},
            {"tactic": "DEFENSE_EVASION", "judgment": "confirmed", "why": "rm clean 与 rm profile 是原文直接给出的删除清理动作。", "behavior_ids": ["cleanup_delete"]},
        ],
        "technique_rationales": [
            {"technique_id": "T1189", "judgment": "confirmed", "why": "恶意网站导致 Firefox exploit。", "behavior_ids": ["driveby_exploit"]},
            {"technique_id": "T1071.001", "judgment": "confirmed", "why": "operator console 与 drakon 的通信走 web/HTTP 风格地址。", "behavior_ids": ["c2_callback"]},
            {"technique_id": "T1105", "judgment": "confirmed", "why": "putfile 明确把 drakon/libdrakon 组件写入目标。", "behavior_ids": ["payload_write"]},
            {"technique_id": "T1046", "judgment": "confirmed", "why": "nrtcp/netrecon 对目标网络进行侦察。", "behavior_ids": ["network_scan"]},
            {"technique_id": "T1070.004", "judgment": "confirmed", "why": "rm clean 与 rm profile 是显式文件删除清理。", "behavior_ids": ["cleanup_delete"]},
        ],
    },
    "3.4": {
        "status": "confirmed",
        "time_precision": "minute_window",
        "start_time": "2018-04-11T10:00:00",
        "end_time": "2018-04-11T10:40:00",
        "attack_summary": "FiveDirections 通过 Firefox 恶意网站 exploit 获得 drakon 会话，执行 netrecon，对主机与网络做侦察，并读取/取回多个本地文档，报告正文明确说明已外传多个文件。",
        "notes": "该节同时包含显式 file read/getfile 与正文里的 exfil 描述，因此 COLLECTION 和 EXFILTRATION 都保留。",
        "behaviors": [
            {"behavior_id": "driveby_exploit", "action": "exploit_delivery", "judgment": "confirmed", "why": "正文与 Event Log 都明确写到通过 www.cnpc.com.cn exploit Firefox 成功建立连接。", "selectors": [_selector("www.cnpc.com.cn", "1009 Firefox connect", "exploit www.cnpc.com.cn 179.252.65.246:80")]},
            {"behavior_id": "c2_callback", "action": "c2_callback", "judgment": "confirmed", "why": "正文写到 drakon 在 Firefox 内存中并连接 operator console，连接交互也有 Firefox 到 loaderDrakon 的外联。", "selectors": [_selector("connected out to the operator console for C2", "firefox: connection to 156.78.147.114:80", "firefox: connection to 16.54.116.146:80")]},
            {"behavior_id": "network_scan", "action": "scan", "judgment": "confirmed", "why": "Event Log 中的 netrecon exfil / nrudp 与正文里的 recon interfaces 明确表明侦察行为。", "selectors": [_selector("netrecon exfil 193.189.212.26:80", "nrudp 27.56.56.211 80", "loaded the netrecon module to recon the network interfaces", "hostname")]},
            {"behavior_id": "file_collect", "action": "file_read", "judgment": "confirmed", "why": "Interactions 里有 cat/getfile 多个本地文档和 hosts 文件。", "selectors": [_selector("W1>cat trains.rtf", "W1>cat malicious.rtf", "W1>getfile Missledefence.doc", "W1>getfile Covert.xlsx", "W1>cat hosts")]},
            {"behavior_id": "data_exfil", "action": "data_exfil", "judgment": "confirmed", "why": "正文直接写明 exfil'ed multiple files from the target。", "selectors": [_selector("The attacker exfil'ed multiple files from the target", "exfil'ed multiple files from the target", "netrecon exfil 193.189.212.26:80")]},
        ],
        "tactic_rationales": [
            {"tactic": "INITIAL_ACCESS", "judgment": "confirmed", "why": "恶意网站 exploit 成功后建立 drakon 会话。", "behavior_ids": ["driveby_exploit"]},
            {"tactic": "EXECUTION", "judgment": "confirmed", "why": "drakon/netrecon 在目标主机上运行并继续执行后续命令。", "behavior_ids": ["driveby_exploit", "network_scan"]},
            {"tactic": "COMMAND_AND_CONTROL", "judgment": "confirmed", "why": "drakon/operator console 与 Firefox 到 shellcode/loaderDrakon 的外联共同支撑 C2。", "behavior_ids": ["c2_callback"]},
            {"tactic": "DISCOVERY", "judgment": "confirmed", "why": "hostname、hosts 读取与 netrecon/nrudp 都是侦察行为。", "behavior_ids": ["network_scan", "file_collect"]},
            {"tactic": "COLLECTION", "judgment": "confirmed", "why": "本地敏感文档被 cat/getfile 读取与抓取。", "behavior_ids": ["file_collect"]},
            {"tactic": "EXFILTRATION", "judgment": "confirmed", "why": "正文直接声明 exfil 多个文件。", "behavior_ids": ["data_exfil"]},
        ],
        "technique_rationales": [
            {"technique_id": "T1189", "judgment": "confirmed", "why": "通过浏览恶意站点触发 Firefox exploit。", "behavior_ids": ["driveby_exploit"]},
            {"technique_id": "T1071.001", "judgment": "confirmed", "why": "drakon 会话与相关对外连接走 web 风格地址。", "behavior_ids": ["c2_callback"]},
            {"technique_id": "T1046", "judgment": "confirmed", "why": "netrecon/nrudp 对网络服务与接口做侦察。", "behavior_ids": ["network_scan"]},
            {"technique_id": "T1005", "judgment": "confirmed", "why": "cat/getfile 明确访问本地文档与配置文件。", "behavior_ids": ["file_collect"]},
            {"technique_id": "T1041", "judgment": "confirmed", "why": "正文直接写明文件被 exfil 到攻击方。", "behavior_ids": ["data_exfil"]},
        ],
    },
    "3.8": {
        "status": "confirmed",
        "time_precision": "minute_window",
        "start_time": "2018-04-11T15:08:00",
        "end_time": "2018-04-11T15:15:00",
        "attack_summary": "CADETS 再次通过 Nginx malformed HTTP request 成功拿到 drakon in-memory shell，并把 libdrakon 落盘后尝试注入 sshd，最终再次导致主机崩溃。",
        "notes": "这一节成功确认了 exploit、shell/C2 和载荷落盘；失败的 inject 既保留在行为链，也上升为 attempted DEFENSE_EVASION。",
        "behaviors": [
            {"behavior_id": "exploit_delivery", "action": "exploit_delivery", "judgment": "confirmed", "why": "正文明确写到 Nginx exploit 第一次即成功。", "selectors": [_selector("once again exploiting Nginx", "This time, the exploit worked on the first attempt", "15:08 throw http payload")]},
            {"behavior_id": "c2_callback", "action": "c2_callback", "judgment": "confirmed", "why": "正文写到 drakon implant running in memory of Nginx with a shell connected via HTTP to the operator console。", "selectors": [_selector("shell connected via HTTP to the operator console", "nginx: connection to 155.162.39.48:80")]},
            {"behavior_id": "module_transfer", "action": "payload_write", "judgment": "confirmed", "why": "libdrakon 被 putfile 到 grain。", "selectors": [_selector("putfile ./deploy/archive/libdrakon", "grain")]},
            {"behavior_id": "inject_attempt", "action": "inject_attempt", "judgment": "attempted", "why": "grain 被用于 inject /tmp/grain 802，但失败并造成 kernel panic。", "selectors": [_selector("inject /tmp/grain 802", "kernel panic", "cadets crashed")]},
        ],
        "tactic_rationales": [
            {"tactic": "INITIAL_ACCESS", "judgment": "confirmed", "why": "Nginx exploit 成功进入 CADETS。", "behavior_ids": ["exploit_delivery"]},
            {"tactic": "EXECUTION", "judgment": "confirmed", "why": "drakon 在 nginx 内存中运行，libdrakon 也被写盘准备执行/注入。", "behavior_ids": ["exploit_delivery", "module_transfer"]},
            {"tactic": "COMMAND_AND_CONTROL", "judgment": "confirmed", "why": "operator console shell 已被成功建立。", "behavior_ids": ["c2_callback"]},
            {"tactic": "DEFENSE_EVASION", "judgment": "attempted", "why": "grain 被用于向 sshd 注入，但最终失败并造成 kernel panic。", "behavior_ids": ["inject_attempt"]},
        ],
        "technique_rationales": [
            {"technique_id": "T1190", "judgment": "confirmed", "why": "Nginx 公网服务被利用。", "behavior_ids": ["exploit_delivery"]},
            {"technique_id": "T1071.001", "judgment": "confirmed", "why": "shell 通过 HTTP/operator console 连接。", "behavior_ids": ["c2_callback"]},
            {"technique_id": "T1105", "judgment": "confirmed", "why": "libdrakon 作为注入载荷被传入目标。", "behavior_ids": ["module_transfer"]},
            {"technique_id": "T1055", "judgment": "attempted", "why": "grain 被明确用于对 sshd 进程做 inject 尝试，但最终失败。", "behavior_ids": ["inject_attempt"]},
        ],
    },
    "3.10": {
        "status": "attempted_failed",
        "time_precision": "minute_window",
        "start_time": "2018-04-12T11:13:00",
        "end_time": "2018-04-12T11:14:00",
        "attack_summary": "FiveDirections 上的恶意浏览器扩展攻击失败：loaderDrakon 与 drakon dropper 都没有成功运行，但可执行文件被写到了磁盘上。",
        "notes": "该节只保留 attempted 结论；报告明确说 drakon 没有成功运行、connect out 或 self delete。",
        "behaviors": [
            {"behavior_id": "browser_extension_attempt", "action": "exploit_delivery", "judgment": "attempted", "why": "浏览器扩展攻击被实际触发，但没有得到有效 shell。", "selectors": [_selector("loaderdrakon browser extension (fail)", "drakon dropper browser extension (fail)", "unable to load drakon into the browser extension's memory")]},
            {"behavior_id": "payload_write", "action": "payload_write", "judgment": "attempted", "why": "hJauWl01 文件被下载到磁盘，但后续执行失败。", "selectors": [_selector("hJauWl01 file downloaded to disk")]},
            {"behavior_id": "payload_crash", "action": "payload_crash", "judgment": "attempted", "why": "报告明确写到 drakon implant executable is crashing。", "selectors": [_selector("drakon implant executable is crashing", "drakon did not successfully run, connect out, or self delete")]},
        ],
        "tactic_rationales": [
            {"tactic": "INITIAL_ACCESS", "judgment": "attempted", "why": "攻击者尝试用恶意浏览器扩展重新进入主机，但未形成有效控制。", "behavior_ids": ["browser_extension_attempt"]},
            {"tactic": "EXECUTION", "judgment": "attempted", "why": "落地文件与 dropper 尝试执行，但因崩溃而失败。", "behavior_ids": ["browser_extension_attempt", "payload_write", "payload_crash"]},
        ],
        "technique_rationales": [
            {"technique_id": "T1203", "judgment": "attempted", "why": "报告明确写到通过恶意浏览器扩展触发 exploit/dropper，但最终失败。", "behavior_ids": ["browser_extension_attempt"]},
        ],
    },
    "3.11": {
        "status": "confirmed",
        "time_precision": "minute_window",
        "start_time": "2018-04-12T12:44:00",
        "end_time": "2018-04-12T13:26:00",
        "attack_summary": "THEIA 上的恶意浏览器扩展攻击通过写盘方式转成成功链：drakon 与 micro apt 分别落盘、注入尝试失败、micro 提权并回连，随后进行大规模端口扫描并删除 mail 落地物。",
        "notes": "窗口同时记录了 failed injection 与 successful micro path；confirmed tactics 统计成功链，failed injection 额外上升为 attempted DEFENSE_EVASION。",
        "behaviors": [
            {"behavior_id": "browser_extension_exploit", "action": "exploit_delivery", "judgment": "confirmed", "why": "浏览器扩展路径虽然没能把 drakon 留在内存里，但成功把后续载荷链推到了磁盘执行阶段。", "selectors": [_selector("www.gatech.edu loaderDrakon browser ext", "www.gatech.edu drakon browser ext", "writing the drakon implant executable to disk on the target upon exploiting the browser extension")]},
            {"behavior_id": "payload_write", "action": "payload_write", "judgment": "confirmed", "why": "xdev/wdev/memtrace.so/mail 等文件均被明确写入。", "selectors": [_selector("putfile /tmp/memtrace.so", "putfile ./deploy/archive/microapt", "putfile ./deploy/archive/libdrakon", "L2>putfile ./deploy/archive/microapt.linux.x64_149.52.198.23 mail")]},
            {"behavior_id": "payload_elevate", "action": "payload_elevate", "judgment": "confirmed", "why": "正文明确写到 micro apt 被提升为 root 新进程，Event Log 也有 elevate /var/log/mail。", "selectors": [_selector("elevating it as a new process with root privileges", "1317 elevate /var/log/mail", "L2>elevate /var/log/mail")]},
            {"behavior_id": "c2_callback", "action": "c2_callback", "judgment": "confirmed", "why": "gtcache/drakon 与 micro listener 的连接都被明确记录。", "selectors": [_selector("1317 c2 connection", "gtcache: connection to 146.153.68.151", "THEIA micro", "Micro apt connected out to the micro C2 listener")]},
            {"behavior_id": "network_scan", "action": "scan", "judgment": "confirmed", "why": "APT>scan 列出了多个目标与端口范围。", "selectors": [_selector("APT>scan 128.55.12.73", "APT>scan 128.55.12.141", "APT>scan 128.55.12.110", "perform a portscan of the known hosts")]},
            {"behavior_id": "cleanup_delete", "action": "file_delete", "judgment": "confirmed", "why": "xdev/wdev/mail 等临时或载荷相关文件都被删除。", "selectors": [_selector("1326 rm mail", "L3>rm xdev", "L2>rm xdev", "L2>rm wdev", "L2>rm mail")]},
            {"behavior_id": "inject_attempt", "action": "inject_attempt", "judgment": "attempted", "why": "多次向 sshd 注入 xdev/wdev/memtrace.so 失败。", "selectors": [_selector("inject /var/log/xdev 1226", "inject /var/log/wdev 1226", "inject /tmp/memtrace.so", "failed, sshd crash")]},
            {"behavior_id": "identity_discovery", "action": "identity_discovery", "judgment": "confirmed", "why": "Event Log 中有 whoami。", "selectors": [_selector("1251 whoami")]},
            {"behavior_id": "process_discovery", "action": "process_discovery", "judgment": "confirmed", "why": "Event Log 中有 ps 与 sshd PID。", "selectors": [_selector("1251 ps", "root (sshd)")]},
        ],
        "tactic_rationales": [
            {"tactic": "INITIAL_ACCESS", "judgment": "confirmed", "why": "浏览器扩展 exploit 成功把攻击推进到盘上落地与后续控制。", "behavior_ids": ["browser_extension_exploit"]},
            {"tactic": "EXECUTION", "judgment": "confirmed", "why": "drakon/micro 载荷被写盘并继续执行。", "behavior_ids": ["payload_write", "payload_elevate"]},
            {"tactic": "PRIVILEGE_ESCALATION", "judgment": "confirmed", "why": "micro apt 被明确提升为 root 权限进程。", "behavior_ids": ["payload_elevate"]},
            {"tactic": "COMMAND_AND_CONTROL", "judgment": "confirmed", "why": "gtcache/drakon 与 micro listener 的外连共同说明已形成控制通道。", "behavior_ids": ["c2_callback"]},
            {"tactic": "DISCOVERY", "judgment": "confirmed", "why": "whoami、ps 和多批次 APT>scan 同时覆盖身份、进程和网络侦察。", "behavior_ids": ["identity_discovery", "process_discovery", "network_scan"]},
            {"tactic": "DEFENSE_EVASION", "judgment": "confirmed", "why": "mail/xdev/wdev 等落地物被删除，属于明确的痕迹清理/落地物清理。", "behavior_ids": ["cleanup_delete"]},
            {"tactic": "DEFENSE_EVASION", "judgment": "attempted", "why": "多次向 sshd 注入 xdev/wdev/memtrace.so 的尝试都失败了。", "behavior_ids": ["inject_attempt"]},
        ],
        "technique_rationales": [
            {"technique_id": "T1203", "judgment": "confirmed", "why": "恶意浏览器扩展 exploit 是窗口的进入方式。", "behavior_ids": ["browser_extension_exploit"]},
            {"technique_id": "T1071.001", "judgment": "confirmed", "why": "gtcache/drakon 与 micro listener 通过 web 风格地址建立控制通信。", "behavior_ids": ["c2_callback"]},
            {"technique_id": "T1105", "judgment": "confirmed", "why": "microapt/libdrakon 等模块被写盘导入目标。", "behavior_ids": ["payload_write"]},
            {"technique_id": "T1046", "judgment": "confirmed", "why": "APT>scan 明确对应网络服务侦察。", "behavior_ids": ["network_scan"]},
            {"technique_id": "T1033", "judgment": "confirmed", "why": "whoami 明确对应身份发现。", "behavior_ids": ["identity_discovery"]},
            {"technique_id": "T1057", "judgment": "confirmed", "why": "ps 与 sshd PID 枚举明确对应进程发现。", "behavior_ids": ["process_discovery"]},
            {"technique_id": "T1070.004", "judgment": "confirmed", "why": "rm mail/xdev/wdev 是明确的文件删除清理。", "behavior_ids": ["cleanup_delete"]},
            {"technique_id": "T1055", "judgment": "attempted", "why": "xdev/wdev/memtrace.so 被多次用于向 sshd 注入，但都失败。", "behavior_ids": ["inject_attempt"]},
        ],
    },
    "3.12": {
        "status": "attempted_failed",
        "time_precision": "minute_window",
        "start_time": "2018-04-12T13:36:00",
        "end_time": "2018-04-12T13:36:00",
        "attack_summary": "TRACE 上的恶意浏览器扩展攻击在 exploit 阶段就卡死，没有收到 operator console 回连。",
        "notes": "这一节只有 attempted 结论；没有稳定的 C2、落地执行或后续链条。",
        "behaviors": [
            {"behavior_id": "browser_extension_attempt", "action": "exploit_delivery", "judgment": "attempted", "why": "报告明确写到尝试利用恶意浏览器扩展，但 Firefox 立刻挂起。", "selectors": [_selector("www.allstate.com drakon browser extension", "Firefox seems to hang", "never received a connection back to the operator console")]},
        ],
        "tactic_rationales": [
            {"tactic": "INITIAL_ACCESS", "judgment": "attempted", "why": "攻击者实际触发了浏览器扩展 exploit 尝试，但未获得控制。", "behavior_ids": ["browser_extension_attempt"]},
            {"tactic": "EXECUTION", "judgment": "attempted", "why": "浏览器扩展路径尝试执行恶意逻辑，但在挂起后失败。", "behavior_ids": ["browser_extension_attempt"]},
        ],
        "technique_rationales": [
            {"technique_id": "T1203", "judgment": "attempted", "why": "报告明确写到通过恶意浏览器扩展尝试 exploit。", "behavior_ids": ["browser_extension_attempt"]},
        ],
    },
    "3.13": {
        "status": "confirmed",
        "time_precision": "minute_window",
        "start_time": "2018-04-12T14:00:00",
        "end_time": "2018-04-12T14:38:00",
        "attack_summary": "CADETS 上再次成功利用 Nginx，drakon/XIM 与 micro 两条链并行推进：多次传入 drakon/libdrakon/microapt，最终 XIM 提权成功、micro 落盘执行并回连，再对多个内网地址做端口扫描，同时清理若干临时文件。",
        "notes": "这一节是 CADETS 里最完整的成功链之一；除成功的 drakon 提权外，也保留 micro 等多次失败的提权尝试为 attempted PRIVILEGE_ESCALATION。",
        "behaviors": [
            {"behavior_id": "exploit_delivery", "action": "exploit_delivery", "judgment": "confirmed", "why": "Nginx malformed HTTP request exploit 再次成功。", "selectors": [_selector("once again exploiting Nginx", "1400 http_post shell F1", "exploit: connection on port 80 from 25.159.96.207")]},
            {"behavior_id": "payload_write", "action": "payload_write", "judgment": "confirmed", "why": "tmux-1002/minions/font/XIM/netlog/sendmail/main/test 等载荷均被 putfile 到磁盘。", "selectors": [_selector("putfile ./deploy/archive/microapt", "putfile ./deploy/archive/libdrakon", "putfile ./deploy/archive/drakon", "tmux-1002", "sendmail", "test")]},
            {"behavior_id": "payload_elevate", "action": "payload_elevate", "judgment": "confirmed", "why": "正文写到 drakon 成功以 root 运行，交互里也有 F1>elevate /tmp/XIM 成功。", "selectors": [_selector("able to elevate the drakon implant", "F1>elevate /tmp/XIM", "1069:- F1>elevate /tmp/XIM")]},
            {"behavior_id": "payload_execute", "action": "payload_execute", "judgment": "confirmed", "why": "micro 通过 execfile /tmp/test 被直接执行。", "selectors": [_selector("execfile /tmp/test", "F2>execfile /tmp/test")]},
            {"behavior_id": "c2_callback", "action": "c2_callback", "judgment": "confirmed", "why": "XIM 与 sendmail(micro) 都形成了对外回连。", "selectors": [_selector("XIM: connection to 53.158.101.118:80", "sendmail: connection to 192.113.144.28:80", "connected out to the micro apt listener for C2")]},
            {"behavior_id": "network_scan", "action": "scan", "judgment": "confirmed", "why": "sendmail(Micro APT) 交互里有连续的 APT>scan 记录。", "selectors": [_selector("APT>scan 128.55.12.166", "APT>scan 128.55.12.67", "APT>scan 128.55.12.1", "perform network recon using port scans")]},
            {"behavior_id": "cleanup_delete", "action": "file_delete", "judgment": "confirmed",
                "why": "grain/vUGefai/tmux-1002/minion/XIM/netlog/sendmail/main/test 等文件有多次 rm 清理。",
                "selectors": [_selector("F1>rm grain", "F1>rm vUGefai", "F1>rm tmux-1002", "F2>rm minion", "F2>rm XIM", "F2>rm netlog", "F2>rm sendmail", "F2>rm main", "F2>rm test")]},
            {"behavior_id": "payload_elevate_attempt", "action": "payload_elevate", "judgment": "attempted",
                "why": "micro 相关载荷存在多次 failed elevate，说明窗口内确有失败的提权尝试。",
                "selectors": [_selector("tried to elevate it. This was unsuccessful multiple times", "elevate /tmp/tmux-1002 (failed)", "elevate /tmp/minions (failed)", "elevate /var/log/netlog (failed)", "elevate /var/log/sendmail (failed)", "elevate /tmp/test (failed)")]},
        ],
        "tactic_rationales": [
            {"tactic": "INITIAL_ACCESS", "judgment": "confirmed", "why": "Nginx exploit 成功开启后续链。", "behavior_ids": ["exploit_delivery"]},
            {"tactic": "EXECUTION", "judgment": "confirmed", "why": "drakon/micro 载荷被写盘并执行。", "behavior_ids": ["payload_write", "payload_execute"]},
            {"tactic": "PRIVILEGE_ESCALATION", "judgment": "confirmed", "why": "drakon(XIM) 被成功 elevate 到 root。", "behavior_ids": ["payload_elevate"]},
            {"tactic": "COMMAND_AND_CONTROL", "judgment": "confirmed", "why": "XIM 与 micro sendmail 都形成了对外 C2 连接。", "behavior_ids": ["c2_callback"]},
            {"tactic": "DISCOVERY", "judgment": "confirmed", "why": "Micro APT 针对多个目标和端口做扫描。", "behavior_ids": ["network_scan"]},
            {"tactic": "DEFENSE_EVASION", "judgment": "confirmed", "why": "大量临时/载荷文件被删除，属于显式清理行为。", "behavior_ids": ["cleanup_delete"]},
            {"tactic": "PRIVILEGE_ESCALATION", "judgment": "attempted", "why": "micro 相关载荷有多次 failed elevate，属于窗口内明确发生但未成功的提权尝试。", "behavior_ids": ["payload_elevate_attempt"]},
        ],
        "technique_rationales": [
            {"technique_id": "T1190", "judgment": "confirmed", "why": "Nginx exploit 是整个窗口的进入方式。", "behavior_ids": ["exploit_delivery"]},
            {"technique_id": "T1071.001", "judgment": "confirmed", "why": "XIM 与 micro listener 的通信都走 web 风格外联。", "behavior_ids": ["c2_callback"]},
            {"technique_id": "T1105", "judgment": "confirmed", "why": "drakon/libdrakon/microapt 等载荷均被 putfile 进目标。", "behavior_ids": ["payload_write"]},
            {"technique_id": "T1046", "judgment": "confirmed", "why": "APT>scan 直接对应网络服务侦察。", "behavior_ids": ["network_scan"]},
            {"technique_id": "T1070.004", "judgment": "confirmed", "why": "rm 多个落地文件是明确的删除清理。", "behavior_ids": ["cleanup_delete"]},
        ],
    },
    "3.14": {
        "status": "confirmed",
        "time_precision": "minute_window",
        "start_time": "2018-04-13T09:04:00",
        "end_time": "2018-04-13T09:15:00",
        "attack_summary": "CADETS 上重新连回旧 shell 后，再次通过 Nginx exploit 生成新的 drakon in-memory 会话，把 drakon 与 libdrakon 落盘、提权为 root 进程、再次回连，并对 sshd 做多次注入尝试。",
        "notes": "窗口中 inject 仍失败，但 whoami/ps、落盘、提权和第二条 C2 都是明确成功行为；失败的 inject 额外上升为 attempted DEFENSE_EVASION。",
        "behaviors": [
            {"behavior_id": "reconnect_old_shell", "action": "c2_callback", "judgment": "confirmed", "why": "Event Log 开头明确写到 reconnect to open connection。", "selectors": [_selector("09:04 reconnect to open connection")]},
            {"behavior_id": "identity_discovery", "action": "identity_discovery", "judgment": "confirmed", "why": "Event Log 中直接执行 whoami。", "selectors": [_selector("09:04 whoami", "09:12 whoami")]},
            {"behavior_id": "process_discovery", "action": "process_discovery", "judgment": "confirmed", "why": "Event Log 中多次 ps，并明确给出 sshd PID 20691。", "selectors": [_selector("09:13 ps", "root 20691", "09:14 ps")]},
            {"behavior_id": "exploit_delivery", "action": "exploit_delivery", "judgment": "confirmed", "why": "报告正文和 Event Log 都写明重新用 HTTP 请求 exploit Nginx 成功。", "selectors": [_selector("Re-exploited Nginx", "09:07 http post nc -s 25.159.96.207 128.55.12.73 80", "09:07 shell F1")]},
            {"behavior_id": "payload_write", "action": "payload_write", "judgment": "confirmed", "why": "drakon 与 libdrakon 被 putfile 到 pEja72mA / eWq10bVcx，再复制成 memhelp.so/eraseme/done.so。", "selectors": [_selector("putfile ./deploy/archive/drakon.freebsd.x64", "putfile ./deploy/archive/libdrakon", "cp eWq10bVcx memhelp.so", "cp memhelp.so eraseme", "cp eraseme done.so")]},
            {"behavior_id": "payload_elevate", "action": "payload_elevate", "judgment": "confirmed", "why": "正文写明 drakon executable was ran from disk as root，Event Log 中也有 elevate pEja72mA。", "selectors": [_selector("resulting in a new drakon process with root privileges", "09:12 elevate pEja72mA", "F1>elevate /tmp/pEja72mA")]},
            {"behavior_id": "c2_callback", "action": "c2_callback", "judgment": "confirmed", "why": "新的 root drakon 进程再次连接 operator console，连接交互中也有 pEja72mA 外联。", "selectors": [_selector("new connection to the operator console", "09:12 connection F2", "09:12 console F2", "pEja72mA: connection to 53.158.101.118:80")]},
            {"behavior_id": "inject_attempt", "action": "inject_attempt", "judgment": "attempted", "why": "F2 使用 memhelp.so/eraseme/done.so 对 sshd 20691 做多次 inject，但仍失败。", "selectors": [_selector("09:15 inject", "inject /tmp/memhelp.so 20691", "inject eraseme 20691", "inject /tmp/done.so 20691")]},
        ],
        "tactic_rationales": [
            {"tactic": "INITIAL_ACCESS", "judgment": "confirmed", "why": "重新 exploit Nginx 形成新的进入链。", "behavior_ids": ["exploit_delivery"]},
            {"tactic": "EXECUTION", "judgment": "confirmed", "why": "drakon/libdrakon 从磁盘运行与复制，形成盘上执行链。", "behavior_ids": ["payload_write", "payload_elevate"]},
            {"tactic": "PRIVILEGE_ESCALATION", "judgment": "confirmed", "why": "新的 drakon 进程以 root 权限运行。", "behavior_ids": ["payload_elevate"]},
            {"tactic": "COMMAND_AND_CONTROL", "judgment": "confirmed", "why": "旧 shell reconnect 与新的 root drakon/operator console 连接都已形成。", "behavior_ids": ["reconnect_old_shell", "c2_callback"]},
            {"tactic": "DISCOVERY", "judgment": "confirmed", "why": "whoami 和 ps/sshd PID 枚举共同支撑身份与进程侦察。", "behavior_ids": ["identity_discovery", "process_discovery"]},
            {"tactic": "DEFENSE_EVASION", "judgment": "attempted", "why": "root drakon 针对 sshd 的多次 inject 都失败了。", "behavior_ids": ["inject_attempt"]},
        ],
        "technique_rationales": [
            {"technique_id": "T1190", "judgment": "confirmed", "why": "Nginx 再次被 exploit。", "behavior_ids": ["exploit_delivery"]},
            {"technique_id": "T1071.001", "judgment": "confirmed", "why": "旧 shell 与新的 drakon/operator console 使用 web 风格外联。", "behavior_ids": ["reconnect_old_shell", "c2_callback"]},
            {"technique_id": "T1105", "judgment": "confirmed", "why": "drakon 与 libdrakon 被传入并落盘复制。", "behavior_ids": ["payload_write"]},
            {"technique_id": "T1033", "judgment": "confirmed", "why": "whoami 明确对应身份发现。", "behavior_ids": ["identity_discovery"]},
            {"technique_id": "T1057", "judgment": "confirmed", "why": "ps 与 sshd PID 对应进程发现。", "behavior_ids": ["process_discovery"]},
            {"technique_id": "T1055", "judgment": "attempted", "why": "memhelp.so / eraseme / done.so 被用于对 sshd 的 inject 尝试，但都失败。", "behavior_ids": ["inject_attempt"]},
        ],
    },
    "3.15": {
        "status": "confirmed",
        "time_precision": "minute_window",
        "start_time": "2018-04-13T12:43:00",
        "end_time": "2018-04-13T12:53:00",
        "attack_summary": "TRACE 利用恶意密码管理器扩展把 drakon 写盘，再转而落盘/执行 micro apt；micro 成功回连并做端口扫描，同时删除 /tmp/ztmp 临时文件，提权与向 sshd 注入的尝试都未能稳定成功。",
        "notes": "窗口保留了 failed privilege escalation 与 failed injection 背景；confirmed tactics 只统计已经成功形成的执行、C2、扫描与清理，失败的提权/注入则记入 attempted tactics。",
        "behaviors": [
            {"behavior_id": "browser_extension_exploit", "action": "exploit_delivery", "judgment": "confirmed", "why": "报告正文明确写到 continued attack against TRACE via malicious pass manager browser extension。", "selectors": [_selector("malicious pass manager browser extension", "1243 browse to allstate.com", "1243 shell L1")]},
            {"behavior_id": "process_discovery", "action": "process_discovery", "judgment": "confirmed", "why": "Event Log 中有 ps 与 sshd PID。", "selectors": [_selector("1243 ps", "root (sshd)")]},
            {"behavior_id": "payload_write", "action": "payload_write", "judgment": "confirmed", "why": "正文明确说把 drakon executable 写到磁盘，又写入 micro apt。", "selectors": [_selector("writing the drakon implant executable to disk", "1246 ztmp", "used the browser extension to write the drakon implant executable to disk", "writing micro apt to disk")]},
            {"behavior_id": "payload_elevate", "action": "payload_elevate", "judgment": "attempted", "why": "Event Log 中出现 elevate ztmp，但正文明确说明 micro 无法完成提权。", "selectors": [_selector("1246 elevate ztmp", "We were unable to elevate micro")]},
            {"behavior_id": "inject_attempt", "action": "inject_attempt", "judgment": "attempted", "why": "评论中明确写到尝试把 staged file 注入 sshd 进程内存，但最终失败。", "selectors": [_selector("process injection failing", "load the file staged on disk into sshd process memory but could not do so")]},
            {"behavior_id": "payload_execute", "action": "payload_execute", "judgment": "confirmed", "why": "Event Log 中有 execfile，正文也写到 executed it from disk。", "selectors": [_selector("1247 execfile", "executed it", "We settled for writing micro apt to disk and executing it")]},
            {"behavior_id": "c2_callback", "action": "c2_callback", "judgment": "confirmed", "why": "micro callback 明确形成了对外控制连接。", "selectors": [_selector("1248 micro callback", "Micro apt connected out to the micro C2 listener")]},
            {"behavior_id": "network_scan", "action": "scan", "judgment": "confirmed", "why": "Event Log 中有 micro portscan 与 netrecon 8064。", "selectors": [_selector("1248 micro portscan", "1253 netrecon 8064", "used micro apt to perform a portscan")]},
            {"behavior_id": "cleanup_delete", "action": "file_delete", "judgment": "confirmed", "why": "ztmp 在执行后被显式删除。", "selectors": [_selector("1251 rm /tmp/ztmp")]},
        ],
        "tactic_rationales": [
            {"tactic": "INITIAL_ACCESS", "judgment": "confirmed", "why": "恶意浏览器扩展 exploit 成功恢复了 TRACE 上的攻击链。", "behavior_ids": ["browser_extension_exploit"]},
            {"tactic": "EXECUTION", "judgment": "confirmed", "why": "drakon/micro 由盘上链被继续执行。", "behavior_ids": ["payload_write", "payload_execute"]},
            {"tactic": "COMMAND_AND_CONTROL", "judgment": "confirmed", "why": "micro callback 是明确的控制连接。", "behavior_ids": ["c2_callback"]},
            {"tactic": "DISCOVERY", "judgment": "confirmed", "why": "ps/sshd PID 与 micro portscan/netrecon 共同支撑侦察行为。", "behavior_ids": ["process_discovery", "network_scan"]},
            {"tactic": "DEFENSE_EVASION", "judgment": "confirmed", "why": "rm /tmp/ztmp 是明确的落地物清理。", "behavior_ids": ["cleanup_delete"]},
            {"tactic": "PRIVILEGE_ESCALATION", "judgment": "attempted", "why": "窗口内出现 elevate ztmp，且正文明确说明 micro 最终无法提权成功。", "behavior_ids": ["payload_elevate"]},
            {"tactic": "DEFENSE_EVASION", "judgment": "attempted", "why": "评论中明确写到尝试把 staged file 注入 sshd 进程内存，但最终失败。", "behavior_ids": ["inject_attempt"]},
        ],
        "technique_rationales": [
            {"technique_id": "T1203", "judgment": "confirmed", "why": "通过恶意浏览器扩展重新 exploit TRACE。", "behavior_ids": ["browser_extension_exploit"]},
            {"technique_id": "T1071.001", "judgment": "confirmed", "why": "micro listener 回连通过 web 风格地址建立。", "behavior_ids": ["c2_callback"]},
            {"technique_id": "T1046", "judgment": "confirmed", "why": "micro portscan/netrecon 对网络服务做侦察。", "behavior_ids": ["network_scan"]},
            {"technique_id": "T1057", "judgment": "confirmed", "why": "ps/sshd PID 明确对应进程发现。", "behavior_ids": ["process_discovery"]},
            {"technique_id": "T1070.004", "judgment": "confirmed", "why": "rm /tmp/ztmp 是显式文件删除。", "behavior_ids": ["cleanup_delete"]},
            {"technique_id": "T1055", "judgment": "attempted", "why": "评论中明确写到尝试把 staged file 注入 sshd 进程内存，但最终失败。", "behavior_ids": ["inject_attempt"]},
        ],
    },
    "4.1": {
        "status": "insufficient",
        "time_precision": "coarse_summary",
        "start_time": "2018-04-06T15:00:00",
        "end_time": "2018-04-06T15:00:00",
        "attack_summary": "该节描述的是攻击者借助 CADETS 上的 postfix 邮件服务器发送多批 phishing 邮件；报告明确说明这不是对 CADETS 的直接攻陷，而是 CADETS 作为邮件基础设施被间接使用。",
        "notes": "保留该窗口是为了后续把邮件投递行为与其他 host 的 phishing 行为对齐，但不把它当成 CADETS 成功被攻陷的攻击窗口。",
        "behaviors": [
            {"behavior_id": "mail_delivery", "action": "service_connection", "judgment": "confirmed", "why": "Event Log 和 Connections 都明确写到从外部 IP 连接 CADETS 的 25 端口发送钓鱼邮件。", "selectors": [_selector("Connection from 62.83.155.175 on port 25", "Sent e-mail to bob@bovia", "Phishing email to everyone@bovia.com", "connecting to the postfix server hosted on CADETS")]},
        ],
        "tactic_rationales": [],
        "technique_rationales": [],
    },
    "4.4": {
        "status": "confirmed",
        "time_precision": "minute_window",
        "start_time": "2018-04-09T13:19:00",
        "end_time": "2018-04-09T15:42:00",
        "attack_summary": "FiveDirections 上的 Excel 宏钓鱼最终通过手工执行 PowerShell 成功：下载并执行 update.ps1，建立远程 shell，随后读取 hosts 与多份本地文档，并删除恶意表格附件。",
        "notes": "自动宏执行失败被保留在证据中，但窗口总体是 confirmed，因为手工 PowerShell 执行后攻击链成功建立。",
        "behaviors": [
            {"behavior_id": "phishing_attachment", "action": "attachment_delivery", "judgment": "confirmed", "why": "报告明确写到发送了带编码 PowerShell 宏的 Excel 附件。", "selectors": [_selector("spreadsheet attachment with an encoded powershell command", "Prepared BoviaBenefitsOE.xlsm attachment", "Send e-mail from Bob to Charles")]},
            {"behavior_id": "powershell_execute", "action": "payload_execute", "judgment": "confirmed", "why": "Event Log 明确写到手工运行 powershell -encodedCommand 并收到连接。", "selectors": [_selector("15:07 Manually ran powershell command and got connection back", "powershell -nop -ep bypass -encodedCommand", "downloaded a powershell script and executed it")]},
            {"behavior_id": "c2_callback", "action": "c2_callback", "judgment": "confirmed", "why": "正文写到 resulting in a new connection out for a remote command shell。", "selectors": [_selector("resulting in a new connection out for a remote command shell", "got connection back", "Connect out to 208.75.117.5 to download update.ps1")]},
            {"behavior_id": "file_collect", "action": "file_read", "judgment": "confirmed", "why": "Interactions 明确列出 hosts 与多份 rtf 文档读取。", "selectors": [_selector("type C:\\windows\\system32\\drivers\\etc\\hosts", "type Document.rtf", "type MissleAlert.rtf", "type trains.rtf")]},
            {"behavior_id": "cleanup_delete", "action": "file_delete", "judgment": "confirmed", "why": "恶意表格附件被显式删除。", "selectors": [_selector("del BoviaBenefitsOE.xlsm")]},
        ],
        "tactic_rationales": [
            {"tactic": "INITIAL_ACCESS", "judgment": "confirmed", "why": "钓鱼邮件附件把攻击入口送达了目标用户。", "behavior_ids": ["phishing_attachment"]},
            {"tactic": "EXECUTION", "judgment": "confirmed", "why": "PowerShell 编码命令与 update.ps1 被手工执行。", "behavior_ids": ["powershell_execute"]},
            {"tactic": "COMMAND_AND_CONTROL", "judgment": "confirmed", "why": "PowerShell/update.ps1 建立了回连 shell。", "behavior_ids": ["c2_callback"]},
            {"tactic": "DISCOVERY", "judgment": "confirmed", "why": "hosts 文件被读取，用于环境侦察。", "behavior_ids": ["file_collect"]},
            {"tactic": "COLLECTION", "judgment": "confirmed", "why": "多个本地文档被显式读取。", "behavior_ids": ["file_collect"]},
            {"tactic": "DEFENSE_EVASION", "judgment": "confirmed", "why": "恶意附件 BoviaBenefitsOE.xlsm 被删除。", "behavior_ids": ["cleanup_delete"]},
        ],
        "technique_rationales": [
            {"technique_id": "T1566.001", "judgment": "confirmed", "why": "报告明确写到钓鱼邮件携带恶意 Excel 附件。", "behavior_ids": ["phishing_attachment"]},
            {"technique_id": "T1204.002", "judgment": "confirmed", "why": "用户侧实际执行了恶意文件/命令链。", "behavior_ids": ["phishing_attachment", "powershell_execute"]},
            {"technique_id": "T1059.001", "judgment": "confirmed", "why": "PowerShell 命令被直接执行。", "behavior_ids": ["powershell_execute"]},
            {"technique_id": "T1005", "judgment": "confirmed", "why": "本地 hosts 和多份文档被直接读取。", "behavior_ids": ["file_collect"]},
            {"technique_id": "T1070.004", "judgment": "confirmed", "why": "恶意表格附件被删除。", "behavior_ids": ["cleanup_delete"]},
        ],
    },
    "4.5": {
        "status": "confirmed",
        "time_precision": "minute_window",
        "start_time": "2018-04-10T12:28:00",
        "end_time": "2018-04-10T12:30:00",
        "attack_summary": "TRACE 用户收到冒充 Bob 的钓鱼邮件，打开邮件、点击链接、访问 www.nasa.ng、输入并提交凭证，结果被送往 www.foo1.com。",
        "notes": "该节主要保留 phishing link 与 credential submission 两条主证据，不把它扩展成后续驻留或 C2。", 
        "behaviors": [
            {"behavior_id": "phishing_link", "action": "exploit_delivery", "judgment": "confirmed", "why": "报告明确写到发送 phishing e-mail，并让用户点击恶意链接。", "selectors": [_selector("12:28 Phishing email to everyone@bovia.com", "12:30 TRACE open email", "click the link", "phishing e-mail included a link")]},
            {"behavior_id": "credential_submit", "action": "credential_submit", "judgment": "confirmed", "why": "用户访问 www.nasa.ng 后输入并提交 name/e-mail/password，结果发往 foo1。", "selectors": [_selector("enter creds and submit", "Connect to www.nasa.ng", "Connect to www.foo1.com", "The results were sent back to www.foo1.com")]},
        ],
        "tactic_rationales": [
            {"tactic": "INITIAL_ACCESS", "judgment": "confirmed", "why": "钓鱼邮件与恶意链接构成了明确的进入方式。", "behavior_ids": ["phishing_link"]},
            {"tactic": "EXECUTION", "judgment": "confirmed", "why": "用户实际点击并执行了恶意链接带来的交互。", "behavior_ids": ["phishing_link"]},
            {"tactic": "CREDENTIAL_ACCESS", "judgment": "confirmed", "why": "报告明确写到用户输入并提交了凭证。", "behavior_ids": ["credential_submit"]},
        ],
        "technique_rationales": [
            {"technique_id": "T1566.002", "judgment": "confirmed", "why": "报告明确写到 phishing e-mail with link。", "behavior_ids": ["phishing_link"]},
            {"technique_id": "T1204.001", "judgment": "confirmed", "why": "用户点击恶意链接并继续在钓鱼站点交互。", "behavior_ids": ["phishing_link"]},
        ],
    },
    "4.6": {
        "status": "confirmed",
        "time_precision": "minute_window",
        "start_time": "2018-04-10T12:28:00",
        "end_time": "2018-04-10T13:42:00",
        "attack_summary": "THEIA 用户收到冒充 Bob 的钓鱼邮件，打开邮件、点击链接、访问 www.nasa.ng、输入并提交凭证，结果发往 www.foo1.com。",
        "notes": "与 TRACE 的 4.5 相同，这一节只保留 phishing link 与 credential submission，不扩展成驻留/C2。", 
        "behaviors": [
            {"behavior_id": "phishing_link", "action": "exploit_delivery", "judgment": "confirmed", "why": "报告明确写到发送 phishing e-mail，并让用户点击恶意链接。", "selectors": [_selector("12:28 Phishing email to everyone@bovia.com", "13:42 THEIA open email", "click the link", "phishing e-mail included a link")]},
            {"behavior_id": "credential_submit", "action": "credential_submit", "judgment": "confirmed", "why": "用户访问 www.nasa.ng 后输入并提交凭证，结果发往 foo1。", "selectors": [_selector("enter creds and submit", "Connect to www.nasa.ng", "Connect to www.foo1.com", "The results were sent back to www.foo1.com")]},
        ],
        "tactic_rationales": [
            {"tactic": "INITIAL_ACCESS", "judgment": "confirmed", "why": "钓鱼邮件与恶意链接构成了明确的进入方式。", "behavior_ids": ["phishing_link"]},
            {"tactic": "EXECUTION", "judgment": "confirmed", "why": "用户实际点击并执行了恶意链接带来的交互。", "behavior_ids": ["phishing_link"]},
            {"tactic": "CREDENTIAL_ACCESS", "judgment": "confirmed", "why": "报告明确写到用户输入并提交了凭证。", "behavior_ids": ["credential_submit"]},
        ],
        "technique_rationales": [
            {"technique_id": "T1566.002", "judgment": "confirmed", "why": "报告明确写到 phishing e-mail with link。", "behavior_ids": ["phishing_link"]},
            {"technique_id": "T1204.001", "judgment": "confirmed", "why": "用户点击恶意链接并继续在钓鱼站点交互。", "behavior_ids": ["phishing_link"]},
        ],
    },
    "4.8": {
        "status": "attempted_failed",
        "time_precision": "minute_window",
        "start_time": "2018-04-13T13:50:00",
        "end_time": "2018-04-13T14:04:00",
        "attack_summary": "THEIA 上的恶意可执行附件 tcexec 被用户下载并运行，但因缺少依赖而失败，没有形成后续驻留或回连。",
        "notes": "该节是标准的 attempted_failed：有投递、有打开执行，但没有形成成功链。",
        "behaviors": [
            {"behavior_id": "phishing_attachment", "action": "attachment_open", "judgment": "attempted", "why": "恶意可执行附件 tcexec 被发送、打开并运行。", "selectors": [_selector("13:50 from bob to everyone tcexec", "Open tcexec, run it", "manual download tcexec to desktop", "tcexec file downloaded to disk from e-mail")]},
            {"behavior_id": "payload_crash", "action": "payload_crash", "judgment": "attempted", "why": "报告明确写到 failed missing library。", "selectors": [_selector("14:04 failed missing library", "failed to execute because of missing dependencies")]},
        ],
        "tactic_rationales": [
            {"tactic": "INITIAL_ACCESS", "judgment": "attempted", "why": "钓鱼附件被送达并打开，但没有形成成功控制。", "behavior_ids": ["phishing_attachment"]},
            {"tactic": "EXECUTION", "judgment": "attempted", "why": "用户执行了恶意可执行文件，但因依赖缺失而失败。", "behavior_ids": ["phishing_attachment", "payload_crash"]},
        ],
        "technique_rationales": [
            {"technique_id": "T1566.001", "judgment": "attempted", "why": "报告明确写到通过恶意可执行附件投递。", "behavior_ids": ["phishing_attachment"]},
            {"technique_id": "T1204.002", "judgment": "attempted", "why": "用户实际打开并运行了恶意附件。", "behavior_ids": ["phishing_attachment"]},
        ],
    },
    "4.9": {
        "status": "confirmed",
        "time_precision": "minute_window",
        "start_time": "2018-04-13T13:50:00",
        "end_time": "2018-04-13T14:28:00",
        "attack_summary": "TRACE 上的第一封恶意 tcexec 附件邮件失败，第二封把 micro apt 伪装成 tcexec 后成功：用户打开邮件后 micro 自动执行并回连，随后进行端口扫描，shell 命令尝试失败；同时 pine backdoor 写出了 tcexfil 本地数据文件。",
        "notes": "窗口同时保留 first attachment failed 与 second micro succeeded 两段；由于报告明确说明 tcexfil 用于写出 stolen e-mail data，因此 COLLECTION 也计入 confirmed。",
        "behaviors": [
            {"behavior_id": "phishing_attachment", "action": "attachment_open", "judgment": "confirmed", "why": "两次邮件附件投递都在 Event Log 中有直接记录，第二次 micro-as-tcexec 成功形成自动执行链。", "selectors": [_selector("13:50 from bob to everyone tcexec", "14:15 sent micro as tcexec", "14:20 open email with attachment")]},
            {"behavior_id": "payload_write", "action": "payload_write", "judgment": "confirmed", "why": "tcexec、tcexfil、Micro APT 文件都落到了磁盘。", "selectors": [_selector("tcexec file downloaded to disk", "tcexfil file written to tmp directory", "Micro APT File downloaded to disk")]},
            {"behavior_id": "email_data_collect", "action": "file_collect", "judgment": "confirmed", "why": "评论明确说明漏洞版 pine 会把 stolen e-mail data 写到 tcexfil，而交互中也确实出现了 tcexfil 落地。", "selectors": [_selector("write stolen e-mail data to a file called tcexfil", "tcexfil file written to tmp directory")]},
            {"behavior_id": "payload_execute", "action": "payload_execute", "judgment": "confirmed", "why": "第二次邮件打开后 micro apt 自动执行成新进程。", "selectors": [_selector("When the user opened the e-mail, micro apt automatically executed as a new process", "14:20 got connection micro apt")]},
            {"behavior_id": "c2_callback", "action": "c2_callback", "judgment": "confirmed", "why": "Micro APT C2 与 eth0:951 TRACE micro 地址共同支撑控制连接。", "selectors": [_selector("Micro APT C2", "TRACE micro", "got connection micro apt", "connection out to the micro apt listener")]},
            {"behavior_id": "network_scan", "action": "scan", "judgment": "confirmed", "why": "Event Log 中有 micro apt portscan。", "selectors": [_selector("14:22 portscan from micro apt", "ran a portscan of the target network hosts")]},
            {"behavior_id": "shell_attempt", "action": "shell_attempt", "judgment": "attempted", "why": "micro apt shell cmd try 1/2/3 均失败。", "selectors": [_selector("micro apt shell cmd try 1", "micro apt shell cmd try 2", "micro apt shell cmd try 3")]},
        ],
        "tactic_rationales": [
            {"tactic": "INITIAL_ACCESS", "judgment": "confirmed", "why": "恶意可执行附件被送达并在第二轮形成真正的自动执行入口。", "behavior_ids": ["phishing_attachment"]},
            {"tactic": "EXECUTION", "judgment": "confirmed", "why": "micro apt 作为附件被自动执行为新进程。", "behavior_ids": ["payload_write", "payload_execute"]},
            {"tactic": "COMMAND_AND_CONTROL", "judgment": "confirmed", "why": "Micro APT C2 连接被直接记录。", "behavior_ids": ["c2_callback"]},
            {"tactic": "DISCOVERY", "judgment": "confirmed", "why": "micro apt 对目标网络主机发起端口扫描。", "behavior_ids": ["network_scan"]},
            {"tactic": "COLLECTION", "judgment": "confirmed", "why": "报告明确说明 pine backdoor 会把 stolen e-mail data 写到 tcexfil，而交互中记录了 tcexfil 文件已写出。", "behavior_ids": ["email_data_collect"]},
        ],
        "technique_rationales": [
            {"technique_id": "T1566.001", "judgment": "confirmed", "why": "报告明确写到通过恶意可执行附件发送 tcexec/micro。", "behavior_ids": ["phishing_attachment"]},
            {"technique_id": "T1204.002", "judgment": "confirmed", "why": "用户打开邮件后附件被执行。", "behavior_ids": ["phishing_attachment", "payload_execute"]},
            {"technique_id": "T1071.001", "judgment": "confirmed", "why": "Micro APT listener/C2 通过 web 风格地址建立。", "behavior_ids": ["c2_callback"]},
            {"technique_id": "T1046", "judgment": "confirmed", "why": "portscan 明确对应网络服务侦察。", "behavior_ids": ["network_scan"]},
            {"technique_id": "T1005", "judgment": "confirmed", "why": "tcexfil 的语义被正文明确说明为 stolen e-mail data 的本地落地文件。", "behavior_ids": ["email_data_collect"]},
        ],
    },
    "4.10": {
        "status": "insufficient",
        "time_precision": "coarse_summary",
        "start_time": "2018-04-13T15:00:00",
        "end_time": "2018-04-13T15:00:00",
        "attack_summary": "该节明确写明攻击者没有把恶意可执行附件用于 FiveDirections Windows 主机，因此这里只保留“未实施/跳过”的报告事实，不输出攻击战术结论。",
        "notes": "保留该窗口是为了说明 E3 报告里这一节存在，但它不应被当成 FiveDirections 上实际发生的成功或失败攻击窗口。",
        "behaviors": [],
        "tactic_rationales": [],
        "technique_rationales": [],
    },
}


def _load_lines(path: Path) -> list[LineRecord]:
    return [LineRecord(idx, line.rstrip("\n")) for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)]


def _normalize_host(text: str) -> str:
    upper = text.upper().replace("–", "-")
    if "FIVEDIRECTIONS" in upper:
        return "FIVEDIRECTIONS"
    for key, value in HOST_ALIASES.items():
        if key in upper:
            return value
    for host in TARGET_HOSTS:
        if host in upper:
            return host
    return ""


def _parse_report_pages(lines: list[LineRecord]) -> dict[str, int]:
    pages: dict[str, int] = {}
    toc_pattern = re.compile(r"^\s*(\d+\.\d+)\s+.+?\.{3,}\s+(\d+)\s*$")
    for record in lines:
        match = toc_pattern.match(record.text)
        if not match:
            continue
        section_id, page = match.groups()
        pages[section_id] = int(page)
    return pages


def _build_page_spans(section_order: list[str], start_pages: dict[str, int]) -> dict[str, list[int]]:
    output: dict[str, list[int]] = {}
    for idx, section_id in enumerate(section_order):
        start = start_pages.get(section_id)
        if start is None:
            continue
        next_start = None
        for next_section in section_order[idx + 1 :]:
            if next_section in start_pages:
                next_start = start_pages[next_section]
                break
        if next_start is None or next_start <= start:
            output[section_id] = [start]
            continue
        output[section_id] = list(range(start, next_start))
    return output


def _split_subsections(section_id: str, section_lines: list[LineRecord], section_end_line: int) -> list[Subsection]:
    headings: list[tuple[int, str, str, int]] = []
    for idx, record in enumerate(section_lines):
        if record.text.startswith("#### "):
            raw = record.text[5:].strip()
            headings.append((idx, raw, raw, 4))
        elif record.text.startswith("##### "):
            raw = record.text[6:].strip()
            headings.append((idx, raw, raw, 5))
    subsections: list[Subsection] = []
    if headings:
        lead_body = [line for line in section_lines[: headings[0][0]] if line.text.strip()]
        if lead_body:
            subsections.append(
                Subsection(
                    subsection_id=f"{section_id}.lead",
                    title="Section Lead",
                    level=4,
                    start_line=lead_body[0].line_no,
                    end_line=lead_body[-1].line_no,
                    body_lines=lead_body,
                    synthetic=True,
                )
            )
    else:
        body = [line for line in section_lines if line.text.strip()]
        if body:
            return [
                Subsection(
                    subsection_id=f"{section_id}.lead",
                    title="Section Lead",
                    level=4,
                    start_line=body[0].line_no,
                    end_line=body[-1].line_no,
                    body_lines=body,
                    synthetic=True,
                )
            ]
        return []
    for idx, (offset, raw_id_title, title, level) in enumerate(headings):
        body_start_offset = offset + 1
        body_end_offset = headings[idx + 1][0] if idx + 1 < len(headings) else len(section_lines)
        body_lines = section_lines[body_start_offset:body_end_offset]
        header_match = re.match(r"^(\d+\.\d+(?:\.\d+)*)\s+(.*)$", raw_id_title)
        if header_match:
            subsection_id, clean_title = header_match.groups()
        else:
            subsection_id, clean_title = f"{section_id}.x{idx+1}", raw_id_title
        end_line = body_lines[-1].line_no if body_lines else section_end_line
        subsections.append(
            Subsection(
                subsection_id=subsection_id,
                title=clean_title.strip(),
                level=level,
                start_line=section_lines[offset].line_no,
                end_line=end_line,
                body_lines=body_lines,
            )
        )
    return subsections


def _explode_pseudo_subsections(subsection: Subsection) -> list[Subsection]:
    pseudo_pattern = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s*(Files|Processes|Connections)\s*$", re.IGNORECASE)
    matches: list[tuple[int, str, str]] = []
    for idx, record in enumerate(subsection.body_lines):
        match = pseudo_pattern.match(record.text.strip())
        if match:
            pseudo_id, title = match.groups()
            matches.append((idx, pseudo_id, title.title()))
    if not matches:
        return [subsection]
    exploded: list[Subsection] = []
    for idx, (offset, pseudo_id, title) in enumerate(matches):
        body_start = offset + 1
        body_end = matches[idx + 1][0] if idx + 1 < len(matches) else len(subsection.body_lines)
        body_lines = subsection.body_lines[body_start:body_end]
        if not body_lines:
            continue
        exploded.append(
            Subsection(
                subsection_id=pseudo_id,
                title=title,
                level=subsection.level + 1,
                start_line=subsection.body_lines[offset].line_no,
                end_line=body_lines[-1].line_no,
                body_lines=body_lines,
                synthetic=True,
            )
        )
    return exploded or [subsection]


def _parse_sections(lines: list[LineRecord], start_pages: dict[str, int]) -> dict[str, Section]:
    top_headers: list[tuple[int, str, str]] = []
    top_pattern = re.compile(r"^###\s+(\d+\.\d+)\s+(.*)$")
    for idx, record in enumerate(lines):
        match = top_pattern.match(record.text)
        if match:
            top_headers.append((idx, match.group(1), match.group(2).strip()))
    order = [section_id for _, section_id, _ in top_headers]
    page_spans = _build_page_spans(order, start_pages)
    sections: dict[str, Section] = {}
    for idx, (offset, section_id, heading_title) in enumerate(top_headers):
        next_offset = top_headers[idx + 1][0] if idx + 1 < len(top_headers) else len(lines)
        content = lines[offset + 1 : next_offset]
        host = _normalize_host(heading_title)
        if host not in TARGET_HOSTS:
            continue
        header_match = re.search(r"(?P<date>\d{8})(?:\s+(?P<time>\d{4}))?\s+", heading_title)
        date_token = header_match.group("date") if header_match else ""
        time_token = header_match.group("time") if header_match and header_match.group("time") else ""
        subsections = _split_subsections(section_id, content, lines[next_offset - 1].line_no if next_offset > offset + 1 else lines[offset].line_no)
        sections[section_id] = Section(
            section_id=section_id,
            heading=heading_title,
            title=heading_title,
            host=host,
            start_line=lines[offset].line_no,
            end_line=lines[next_offset - 1].line_no if next_offset > offset else lines[offset].line_no,
            date_token=date_token,
            time_token=time_token,
            report_pages=page_spans.get(section_id, []),
            subsections=subsections,
        )
    return sections


def _section_leaf_subsections(section: Section) -> list[Subsection]:
    output: list[Subsection] = []
    for subsection in section.subsections:
        output.extend(_explode_pseudo_subsections(subsection))
    return output


def _classify_evidence_type(title: str) -> str:
    title_upper = title.upper()
    if "EVENT LOG" in title_upper:
        return "event_log"
    if "ADDRESSES" in title_upper:
        return "address"
    if "FILES" in title_upper:
        return "interaction_file"
    if "PROCESSES" in title_upper:
        return "interaction_process"
    if "CONNECTIONS" in title_upper:
        return "interaction_connection"
    return "narrative_comment"


def _iter_blocks(subsection: Subsection, evidence_type: str) -> Iterable[tuple[int, int, str]]:
    lines = subsection.body_lines
    if evidence_type == "narrative_comment":
        current: list[LineRecord] = []
        for record in lines:
            text = record.text.rstrip()
            if not text.strip():
                if current:
                    merged = " ".join(item.text.strip() for item in current)
                    yield current[0].line_no, current[-1].line_no, merged
                    current = []
                continue
            if text.startswith("!["):
                continue
            current.append(record)
        if current:
            merged = " ".join(item.text.strip() for item in current)
            yield current[0].line_no, current[-1].line_no, merged
        return
    current: list[LineRecord] = []
    bullet_pattern = re.compile(r"^\s*[-*]\s+")
    for record in lines:
        text = record.text.rstrip()
        if not text.strip():
            if current:
                merged = " ".join(item.text.strip() for item in current)
                yield current[0].line_no, current[-1].line_no, merged
                current = []
            continue
        if text.startswith("!["):
            continue
        if bullet_pattern.match(text):
            if current:
                merged = " ".join(item.text.strip() for item in current)
                yield current[0].line_no, current[-1].line_no, merged
            current = [LineRecord(record.line_no, bullet_pattern.sub("", text, count=1))]
            continue
        if current:
            current.append(LineRecord(record.line_no, text.strip()))
        else:
            current = [LineRecord(record.line_no, text.strip())]
    if current:
        merged = " ".join(item.text.strip() for item in current)
        yield current[0].line_no, current[-1].line_no, merged


def _dedupe_dict_items(items: list[dict[str, Any]], *, key_fields: list[str]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    output: list[dict[str, Any]] = []
    for item in items:
        key = tuple(item.get(field) for field in key_fields)
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def _extract_observables(raw_text: str) -> list[dict[str, str]]:
    observables: list[dict[str, str]] = []
    text = raw_text.strip()
    if not text:
        return observables
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+(?:\.[A-Za-z]{2,})?\b")
    domain_pattern = re.compile(r"\b(?:www\.)?[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:\.[A-Za-z]{2,})?\b")
    ip_port_pattern = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}:\d+\b")
    windows_path_pattern = re.compile(r"\b[A-Za-z]:\\[^\s>]+(?:\\[^\s>]+)*")
    linux_path_pattern = re.compile(r"(?<!\w)/(?:[A-Za-z0-9._-]+/?)+")
    pid_pattern = re.compile(r"\bPID\s+(\d+)\b|\broot\s+(\d{2,6})\b")
    attachment_pattern = re.compile(r"\b(?:BoviaBenefitsOE\.xlsm|tcexec|update\.ps1|micro apt|microapt)\b", re.IGNORECASE)
    process_tokens = [
        "nginx",
        "firefox",
        "sshd",
        "sendmail",
        "powershell",
        "drakon",
        "loaderdrakon",
        "micro",
        "netrecon",
        "pine",
        "postfix",
    ]
    command_tokens = [
        "putfile",
        "elevate",
        "execfile",
        "inject",
        "powershell",
        "taskkill",
        "whoami",
        "ps",
        "cat ",
        "getfile",
        "python -m",
        "nc -l",
        "click the link",
        "enter creds",
    ]
    for match in email_pattern.finditer(text):
        observables.append({"observable_type": "user", "value": match.group(0), "raw_fragment": match.group(0)})
    for match in ip_port_pattern.finditer(text):
        observables.append({"observable_type": "ip_port", "value": match.group(0), "raw_fragment": match.group(0)})
    for match in windows_path_pattern.finditer(text):
        observables.append({"observable_type": "file_path", "value": match.group(0), "raw_fragment": match.group(0)})
    for match in linux_path_pattern.finditer(text):
        value = match.group(0)
        if value in {"/F", "/PID"}:
            continue
        observables.append({"observable_type": "file_path", "value": value, "raw_fragment": value})
    for match in domain_pattern.finditer(text):
        value = match.group(0)
        if value.lower().endswith((".so", ".ps1", ".rtf", ".doc", ".docx", ".xlsx", ".xlsm")):
            continue
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value):
            continue
        observables.append({"observable_type": "domain", "value": value, "raw_fragment": value})
    for match in pid_pattern.finditer(text):
        value = match.group(1) or match.group(2)
        if value:
            observables.append({"observable_type": "pid", "value": value, "raw_fragment": value})
    lower = text.lower()
    for token in process_tokens:
        if token in lower:
            observables.append({"observable_type": "process_name", "value": token, "raw_fragment": token})
    for token in command_tokens:
        if token in lower:
            observables.append({"observable_type": "command", "value": text, "raw_fragment": token})
            break
    for token in ("CADETS", "TRACE", "THEIA", "FiveDirections"):
        if token.lower() in lower:
            observables.append({"observable_type": "host", "value": token.upper() if token != "FiveDirections" else "FIVEDIRECTIONS", "raw_fragment": token})
    for match in attachment_pattern.finditer(text):
        observables.append({"observable_type": "email_artifact", "value": match.group(0), "raw_fragment": match.group(0)})
    return _dedupe_dict_items(observables, key_fields=["observable_type", "value"])


def _extract_time_text(raw_text: str) -> str:
    patterns = [
        re.compile(r"\b(\d{1,2}[:.]\d{2})\b"),
        re.compile(r"^\s*(\d{4})\b"),
    ]
    for pattern in patterns:
        match = pattern.search(raw_text)
        if match:
            return match.group(1)
    return ""


def _normalize_clock(value: str) -> str:
    value = value.strip()
    if re.fullmatch(r"\d{4}", value):
        return f"{value[:2]}:{value[2:]}"
    if re.fullmatch(r"\d{1,2}\.\d{2}", value):
        left, right = value.split(".", 1)
        return f"{int(left):02d}:{right}"
    if re.fullmatch(r"\d{1,2}:\d{2}", value):
        left, right = value.split(":", 1)
        return f"{int(left):02d}:{right}"
    return ""


def _resolve_line_date(section: Section, subsection: Subsection) -> str:
    subsection_match = re.search(r"(\d{8})", subsection.title)
    if subsection_match:
        return subsection_match.group(1)
    return section.date_token


def _to_timestamp_iso(date_token: str, time_text: str) -> str:
    if not date_token or not time_text:
        return ""
    clock = _normalize_clock(time_text)
    if not clock:
        return ""
    return f"{date_token[:4]}-{date_token[4:6]}-{date_token[6:8]}T{clock}:00"


def _build_section_evidence(section: Section) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    evidence_items: list[dict[str, Any]] = []
    source_subsections: list[dict[str, Any]] = []
    leaf_subsections = _section_leaf_subsections(section)
    for subsection in leaf_subsections:
        body_text = "\n".join(line.text for line in subsection.body_lines if line.text.strip() and not line.text.startswith("!["))
        source_subsections.append(
            {
                "subsection_id": subsection.subsection_id,
                "title": subsection.title,
                "line_span": {"start": subsection.start_line, "end": subsection.end_line},
                "body_text": body_text.strip(),
            }
        )
        evidence_type = _classify_evidence_type(subsection.title)
        for block_start, block_end, raw_text in _iter_blocks(subsection, evidence_type):
            if not raw_text.strip():
                continue
            evidence_id = f"{section.section_id.replace('.', '_')}_e{len(evidence_items)+1:03d}"
            time_text = _extract_time_text(raw_text)
            timestamp_iso = _to_timestamp_iso(_resolve_line_date(section, subsection), time_text)
            evidence_items.append(
                {
                    "evidence_id": evidence_id,
                    "source_subsection": f"{subsection.subsection_id} {subsection.title}",
                    "source_subsection_id": subsection.subsection_id,
                    "source_line_numbers": {"start": block_start, "end": block_end},
                    "raw_text": raw_text.strip(),
                    "time_text": time_text,
                    "timestamp_iso": timestamp_iso,
                    "evidence_type": evidence_type,
                    "observables": _extract_observables(raw_text),
                }
            )
    return evidence_items, source_subsections


def _normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


def _match_selector(evidence: dict[str, Any], selector: dict[str, Any]) -> bool:
    subsection_contains = str(selector.get("subsection_contains", "")).strip().lower()
    evidence_type = str(selector.get("evidence_type", "")).strip().lower()
    if subsection_contains and subsection_contains not in str(evidence.get("source_subsection", "")).lower():
        return False
    if evidence_type and evidence_type != str(evidence.get("evidence_type", "")).lower():
        return False
    contains_any = [str(item).strip().lower() for item in selector.get("contains_any", []) if str(item).strip()]
    if not contains_any:
        return True
    raw_text = _normalize_text(str(evidence.get("raw_text", "")))
    return any(fragment in raw_text for fragment in contains_any)


def _resolve_behavior_chain(
    section_spec: dict[str, Any], evidence_items: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    evidence_by_id = {item["evidence_id"]: item for item in evidence_items}
    behavior_outputs: list[dict[str, Any]] = []
    behavior_evidence_map: dict[str, list[str]] = {}
    for behavior in section_spec.get("behaviors", []):
        matched_ids: list[str] = []
        for selector in behavior.get("selectors", []):
            for evidence in evidence_items:
                evidence_id = evidence["evidence_id"]
                if evidence_id in matched_ids:
                    continue
                if _match_selector(evidence, selector):
                    matched_ids.append(evidence_id)
        if not matched_ids:
            raise RuntimeError(
                f"Behavior {behavior['behavior_id']} in section has no evidence match: {section_spec.get('attack_summary', '')}"
            )
        behavior_evidence_map[behavior["behavior_id"]] = matched_ids
        behavior_outputs.append(
            {
                "behavior_id": behavior["behavior_id"],
                "action": behavior["action"],
                "judgment": behavior["judgment"],
                "why": behavior["why"],
                "evidence_ids": matched_ids,
            }
        )
        for evidence_id in matched_ids:
            if evidence_id not in evidence_by_id:
                raise RuntimeError(f"Missing evidence {evidence_id}")
    return behavior_outputs, behavior_evidence_map


def _resolve_rationales(
    items: list[dict[str, Any]], behavior_evidence_map: dict[str, list[str]], *, field_name: str
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for item in items:
        evidence_ids: list[str] = []
        for behavior_id in item.get("behavior_ids", []):
            evidence_ids.extend(behavior_evidence_map.get(behavior_id, []))
        evidence_ids = list(dict.fromkeys(evidence_ids))
        if not evidence_ids:
            raise RuntimeError(f"Rationale {item} has no evidence_ids")
        payload = {
            field_name: item[field_name],
            "judgment": item["judgment"],
            "why": item["why"],
            "evidence_ids": evidence_ids,
            "behavior_ids": list(item.get("behavior_ids", [])),
        }
        output.append(payload)
    return output


def _build_explicit_observables(evidence_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    aggregate: dict[tuple[str, str], dict[str, Any]] = {}
    for evidence in evidence_items:
        for observable in evidence.get("observables", []):
            key = (observable["observable_type"], observable["value"])
            entry = aggregate.setdefault(
                key,
                {
                    "observable_type": observable["observable_type"],
                    "value": observable["value"],
                    "raw_fragments": [],
                    "evidence_ids": [],
                },
            )
            if observable["raw_fragment"] not in entry["raw_fragments"]:
                entry["raw_fragments"].append(observable["raw_fragment"])
            if evidence["evidence_id"] not in entry["evidence_ids"]:
                entry["evidence_ids"].append(evidence["evidence_id"])
    return list(aggregate.values())


def _load_legacy_window_ids(path: Path) -> dict[tuple[str, str], str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    mapping: dict[tuple[str, str], str] = {}
    for item in payload.get("windows", []):
        source_ref = str(item.get("source_ref", ""))
        match = re.search(r"(\d+\.\d+)", source_ref)
        if not match:
            continue
        host = str(item.get("host", "")).strip().upper()
        mapping[(host, match.group(1))] = str(item.get("window_id", ""))
    return mapping


def _next_window_id(host: str, date_token: str, start_time: str, end_time: str, used_ids: set[str]) -> str:
    host_upper = host.upper()
    prefix = f"{host_upper}_{date_token}_{start_time.replace(':', '')}_{end_time.replace(':', '')}"
    host_suffix_pattern = re.compile(rf"^{re.escape(host_upper)}_\d{{8}}_\d{{4}}_\d{{4}}_(\d{{2}})$")
    suffixes = [
        int(match.group(1))
        for window_id in used_ids
        if (match := host_suffix_pattern.match(window_id))
    ]
    suffix = (max(suffixes) + 1) if suffixes else 1
    while True:
        candidate = f"{prefix}_{suffix:02d}"
        if candidate not in used_ids:
            used_ids.add(candidate)
            return candidate
        suffix += 1


def _build_window_payload(
    section: Section,
    section_spec: dict[str, Any],
    evidence_items: list[dict[str, Any]],
    source_subsections: list[dict[str, Any]],
    behavior_chain: list[dict[str, Any]],
    tactic_rationales: list[dict[str, Any]],
    technique_rationales: list[dict[str, Any]],
    legacy_window_ids: dict[tuple[str, str], str],
    used_window_ids: set[str],
) -> dict[str, Any]:
    start_time = section_spec["start_time"]
    end_time = section_spec["end_time"]
    window_id = legacy_window_ids.get((section.host, section.section_id))
    if not window_id:
        window_id = _next_window_id(
            section.host,
            section.date_token,
            start_time.split("T", 1)[1][:5],
            end_time.split("T", 1)[1][:5],
            used_window_ids,
        )
    else:
        used_window_ids.add(window_id)
    confirmed_tactics = [
        item["tactic"] for item in tactic_rationales if item["judgment"] == "confirmed"
    ]
    attempted_tactics = [
        item["tactic"] for item in tactic_rationales if item["judgment"] == "attempted"
    ]
    confirmed_techniques = [
        item["technique_id"] for item in technique_rationales if item["judgment"] == "confirmed"
    ]
    attempted_techniques = [
        item["technique_id"] for item in technique_rationales if item["judgment"] == "attempted"
    ]
    return {
        "window_id": window_id,
        "host": section.host,
        "source_doc": REPORT_MD_PATH.name,
        "source_ref": f"Section {section.section_id} / Markdown lines {section.start_line}-{section.end_line}",
        "status": section_spec["status"],
        "time_precision": section_spec["time_precision"],
        "start_time": start_time,
        "end_time": end_time,
        "confirmed_techniques": confirmed_techniques,
        "attempted_techniques": attempted_techniques,
        "confirmed_tactics": confirmed_tactics,
        "attempted_tactics": attempted_tactics,
        "coarse_chain_tags": list(dict.fromkeys(item["action"] for item in behavior_chain)),
        "notes": section_spec["notes"],
        "broad_techniques": [],
        "attack_summary": section_spec["attack_summary"],
        "source_report_pages": list(section.report_pages),
        "report_section_id": section.section_id,
        "report_section_title": section.title,
        "source_markdown_path": str(REPORT_MD_PATH),
        "source_markdown_line_span": {"start": section.start_line, "end": section.end_line},
        "source_subsections": source_subsections,
        "tactic_rationales": tactic_rationales,
        "technique_rationales": technique_rationales,
        "evidence_items": evidence_items,
        "explicit_observables": _build_explicit_observables(evidence_items),
        "behavior_chain": behavior_chain,
    }


def _build_host_summary(windows: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for host in sorted(TARGET_HOSTS):
        host_windows = [item for item in windows if item["host"] == host]
        confirmed_windows = [item for item in host_windows if item["status"] == "confirmed"]
        attempted_windows = [item for item in host_windows if item["status"] == "attempted_failed"]
        insufficient_windows = [item for item in host_windows if item["status"] == "insufficient"]
        confirmed_techniques = sorted(
            {technique for item in host_windows for technique in item.get("confirmed_techniques", [])}
        )
        attempted_techniques = sorted(
            {technique for item in host_windows for technique in item.get("attempted_techniques", [])}
        )
        confirmed_tactics = sorted(
            {tactic for item in host_windows for tactic in item.get("confirmed_tactics", [])}
        )
        attempted_tactics = sorted(
            {tactic for item in host_windows for tactic in item.get("attempted_tactics", [])}
        )
        summary[host] = {
            "window_count": len(host_windows),
            "confirmed_window_count": len(confirmed_windows),
            "attempted_window_count": len(attempted_windows),
            "insufficient_window_count": len(insufficient_windows),
            "confirmed_technique_union": confirmed_techniques,
            "attempted_technique_union": attempted_techniques,
            "confirmed_tactic_union": confirmed_tactics,
            "attempted_tactic_union": attempted_tactics,
        }
    return summary


def _build_technique_to_tactics(windows: list[dict[str, Any]]) -> dict[str, list[str]]:
    used = sorted(
        {
            technique
            for item in windows
            for technique in item.get("confirmed_techniques", []) + item.get("attempted_techniques", [])
        }
    )
    return {
        technique: list(TECHNIQUE_TO_TACTICS_REFERENCE.get(technique, []))
        for technique in used
    }


def _render_markdown(windows: list[dict[str, Any]], host_summary: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# E3 报告驱动的富证据 GT（2026-06-18）")
    lines.append("")
    lines.append("## 生成说明")
    lines.append("")
    lines.append(f"- 主事实来源：`{REPORT_MD_PATH}`")
    lines.append(f"- 旧 GT 只用于复用已有 `window_id` 命名：`{LEGACY_GT_PATH}`")
    lines.append("- 覆盖 host：`TRACE`、`CADETS`、`THEIA`、`FIVEDIRECTIONS`")
    lines.append("- 战术与 technique 都按报告原文保守判定；证据不足时保留为空，不做补全。")
    lines.append("- `recommended_gt_time_offset_minutes_by_host` 在新 JSON 中故意留空，因为 E3 报告本身没有给出 host 级时间偏移建议。")
    lines.append("")
    lines.append("## Host Summary")
    lines.append("")
    lines.append("| Host | Window Count | Confirmed | Attempted Failed | Insufficient | Confirmed Tactics | Attempted Tactics |")
    lines.append("| --- | ---: | ---: | ---: | ---: | --- | --- |")
    for host in sorted(host_summary):
        item = host_summary[host]
        lines.append(
            f"| {host} | {item['window_count']} | {item['confirmed_window_count']} | "
            f"{item['attempted_window_count']} | {item['insufficient_window_count']} | "
            f"{', '.join(item['confirmed_tactic_union']) or '-'} | {', '.join(item['attempted_tactic_union']) or '-'} |"
        )
    for host in sorted({window["host"] for window in windows}):
        lines.append("")
        lines.append(f"## {host}")
        lines.append("")
        host_windows = [item for item in windows if item["host"] == host]
        for window in host_windows:
            lines.append(f"### {window['window_id']} / Section {window['report_section_id']}")
            lines.append("")
            lines.append(f"- 标题：`{window['report_section_title']}`")
            lines.append(f"- 状态：`{window['status']}`")
            lines.append(f"- 时间精度：`{window['time_precision']}`")
            lines.append(f"- 时间窗：`{window['start_time']}` -> `{window['end_time']}`")
            lines.append(f"- Markdown 行号：`{window['source_markdown_line_span']['start']}-{window['source_markdown_line_span']['end']}`")
            lines.append(f"- 报告页：`{', '.join(str(page) for page in window.get('source_report_pages', [])) or '-'}`")
            lines.append(f"- 攻击概述：{window['attack_summary']}")
            lines.append(f"- 备注：{window['notes']}")
            lines.append("")
            lines.append("#### 战术判定")
            lines.append("")
            lines.append("| Tactic | Judgment | 含义 | Why | Evidence IDs |")
            lines.append("| --- | --- | --- | --- | --- |")
            for rationale in window.get("tactic_rationales", []):
                lines.append(
                    f"| {rationale['tactic']} | {rationale['judgment']} | "
                    f"{TACTIC_TO_LABEL.get(rationale['tactic'], '')} | "
                    f"{rationale['why'].replace('|', '\\|')} | "
                    f"{', '.join(rationale['evidence_ids'])} |"
                )
            if not window.get("tactic_rationales"):
                lines.append("| - | - | - | 该节不输出战术结论。 | - |")
            lines.append("")
            lines.append("#### Technique 判定")
            lines.append("")
            lines.append("| Technique | Judgment | Why | Evidence IDs |")
            lines.append("| --- | --- | --- | --- |")
            for rationale in window.get("technique_rationales", []):
                lines.append(
                    f"| {rationale['technique_id']} | {rationale['judgment']} | "
                    f"{rationale['why'].replace('|', '\\|')} | {', '.join(rationale['evidence_ids'])} |"
                )
            if not window.get("technique_rationales"):
                lines.append("| - | - | 该节不输出 technique 结论。 | - |")
            lines.append("")
            lines.append("#### Behavior Chain")
            lines.append("")
            lines.append("| Behavior ID | Action | Judgment | Why | Evidence IDs |")
            lines.append("| --- | --- | --- | --- | --- |")
            for behavior in window.get("behavior_chain", []):
                lines.append(
                    f"| {behavior['behavior_id']} | {behavior['action']} | {behavior['judgment']} | "
                    f"{behavior['why'].replace('|', '\\|')} | {', '.join(behavior['evidence_ids'])} |"
                )
            if not window.get("behavior_chain"):
                lines.append("| - | - | - | 该节没有可稳定抽象的攻击行为链项。 | - |")
            lines.append("")
            lines.append("#### 显式观测")
            lines.append("")
            for observable in window.get("explicit_observables", []):
                fragments = "; ".join(observable.get("raw_fragments", []))
                evidence_ids = ", ".join(observable.get("evidence_ids", []))
                lines.append(
                    f"- `{observable['observable_type']}` / `{observable['value']}`"
                    f"  Evidence: `{evidence_ids}`"
                    f"  Raw: {fragments}"
                )
            if not window.get("explicit_observables"):
                lines.append("- 无。")
            lines.append("")
            lines.append("#### 原始子节摘录")
            lines.append("")
            for subsection in window.get("source_subsections", []):
                lines.append(
                    f"- `{subsection['subsection_id']}` {subsection['title']} "
                    f"(lines {subsection['line_span']['start']}-{subsection['line_span']['end']})"
                )
                if subsection.get("body_text"):
                    lines.append("")
                    for raw_line in subsection["body_text"].splitlines():
                        lines.append(f"  > {raw_line}")
                    lines.append("")
            lines.append("#### 证据条目")
            lines.append("")
            for evidence in window.get("evidence_items", []):
                lines.append(
                    f"1. `{evidence['evidence_id']}` | `{evidence['evidence_type']}` | "
                    f"`{evidence['source_subsection']}` | "
                    f"lines `{evidence['source_line_numbers']['start']}-{evidence['source_line_numbers']['end']}`"
                )
                lines.append(f"   - Raw: {evidence['raw_text']}")
                lines.append(f"   - Time: `{evidence.get('time_text') or '-'}` / `{evidence.get('timestamp_iso') or '-'}`")
                if evidence.get("observables"):
                    lines.append(
                        "   - Observables: "
                        + "; ".join(
                            f"{item['observable_type']}={item['value']}"
                            for item in evidence.get("observables", [])
                        )
                    )
                else:
                    lines.append("   - Observables: -")
            lines.append("")
    return "\n".join(lines) + "\n"


def _validate_payload(payload: dict[str, Any]) -> None:
    windows = payload.get("windows", [])
    hosts = {window.get("host") for window in windows}
    if hosts - TARGET_HOSTS:
        raise RuntimeError(f"Unexpected hosts in payload: {sorted(hosts - TARGET_HOSTS)}")
    summary = payload.get("host_summary", {})
    for host, host_summary in summary.items():
        host_windows = [window for window in windows if window.get("host") == host]
        if host_summary.get("window_count") != len(host_windows):
            raise RuntimeError(f"Host summary mismatch for {host}")
    evidence_ids = {
        evidence["evidence_id"]
        for window in windows
        for evidence in window.get("evidence_items", [])
    }
    for window in windows:
        if not (1 <= window["source_markdown_line_span"]["start"] <= window["source_markdown_line_span"]["end"]):
            raise RuntimeError(f"Bad line span for {window['window_id']}")
        for rationale in window.get("tactic_rationales", []) + window.get("technique_rationales", []):
            if not rationale.get("evidence_ids"):
                raise RuntimeError(f"Rationale without evidence ids in {window['window_id']}")
            if any(evidence_id not in evidence_ids for evidence_id in rationale["evidence_ids"]):
                raise RuntimeError(f"Rationale references missing evidence ids in {window['window_id']}")
        for behavior in window.get("behavior_chain", []):
            if not behavior.get("evidence_ids"):
                raise RuntimeError(f"Behavior without evidence ids in {window['window_id']}")
            if any(evidence_id not in evidence_ids for evidence_id in behavior["evidence_ids"]):
                raise RuntimeError(f"Behavior references missing evidence ids in {window['window_id']}")


def main() -> None:
    lines = _load_lines(REPORT_MD_PATH)
    start_pages = _parse_report_pages(lines)
    sections = _parse_sections(lines, start_pages)
    legacy_window_ids = _load_legacy_window_ids(LEGACY_GT_PATH)
    used_window_ids: set[str] = set()
    windows: list[dict[str, Any]] = []
    for section_id, section_spec in SECTION_SPECS.items():
        section = sections.get(section_id)
        if section is None:
            raise RuntimeError(f"Missing section {section_id} in report parse")
        evidence_items, source_subsections = _build_section_evidence(section)
        behavior_chain, behavior_evidence_map = _resolve_behavior_chain(section_spec, evidence_items)
        tactic_rationales = _resolve_rationales(
            section_spec.get("tactic_rationales", []),
            behavior_evidence_map,
            field_name="tactic",
        )
        technique_rationales = _resolve_rationales(
            section_spec.get("technique_rationales", []),
            behavior_evidence_map,
            field_name="technique_id",
        )
        windows.append(
            _build_window_payload(
                section,
                section_spec,
                evidence_items,
                source_subsections,
                behavior_chain,
                tactic_rationales,
                technique_rationales,
                legacy_window_ids,
                used_window_ids,
            )
        )
    windows.sort(key=lambda item: (item["host"], item["start_time"], item["window_id"]))
    host_summary = _build_host_summary(windows)
    payload = {
        "schema_version": "darpa_attack_eval_gt.v1",
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_documents": {
            "primary_attack_report_name": REPORT_MD_PATH.name,
            "primary_attack_report_path": str(REPORT_MD_PATH),
            "legacy_window_id_reference_path": str(LEGACY_GT_PATH),
            "derivation_notes": (
                "Facts were extracted strictly from the E3 markdown report. "
                "The legacy GT JSON was consulted only to reuse existing window_id names for overlapping sections."
            ),
        },
        "recommended_gt_time_offset_minutes_by_host": {},
        "host_summary": host_summary,
        "technique_to_tactics": _build_technique_to_tactics(windows),
        "windows": windows,
    }
    _validate_payload(payload)
    OUTPUT_JSON_PATH.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    OUTPUT_MD_PATH.write_text(_render_markdown(windows, host_summary), encoding="utf-8")
    print(f"Wrote {OUTPUT_JSON_PATH}")
    print(f"Wrote {OUTPUT_MD_PATH}")


if __name__ == "__main__":
    main()
