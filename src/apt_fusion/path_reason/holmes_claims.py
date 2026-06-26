from __future__ import annotations

from collections import Counter
from datetime import timedelta
from typing import Any, Dict, Iterable, List

from .chain_semantics import (
    collect_staged_object_keys,
    collect_payload_elevate_event_ids,
    collect_precursor_event_ids,
    collect_staged_chmod_event_ids,
    collect_staged_exec_event_ids,
    is_placeholder_object_key,
    is_system_service_object_key,
    item_timestamp,
    normalize_semantic_text,
    staged_object_keys_from_bridge_edges,
)

HOLMES_TTP_CATALOG: dict[str, dict[str, Any]] = {
    "untrusted_read": {
        "apt_stage": "Initial Compromise",
        "statement": "A process received or read untrusted external content that can seed compromise.",
        "query_terms": ("untrusted read", "remote content", "initial compromise"),
        "tactic_ids": ("TA0001",),
        "technique_ids": (),
        "allow_tactics": ("TA0001",),
    },
    "make_mem_exec": {
        "apt_stage": "Initial Compromise",
        "statement": "A process made memory executable after handling untrusted input.",
        "query_terms": ("memory execution", "mprotect", "reflective loading"),
        "tactic_ids": ("TA0002",),
        "technique_ids": (),
        "allow_tactics": ("TA0002",),
    },
    "make_file_exec": {
        "apt_stage": "Initial Compromise",
        "statement": "A suspicious file was made executable after staging from attacker-controlled content.",
        "query_terms": ("make file executable", "chmod executable", "staged executable"),
        "tactic_ids": ("TA0002",),
        "technique_ids": (),
        "allow_tactics": ("TA0002",),
    },
    "untrusted_file_exec": {
        "apt_stage": "Initial Compromise",
        "statement": "A dropped or untrusted file was executed.",
        "query_terms": ("untrusted file exec", "dropped file execution", "payload execution"),
        "tactic_ids": ("TA0002", "TA0011"),
        "technique_ids": ("T1105",),
        "allow_tactics": ("TA0002", "TA0011"),
    },
    "attachment_user_exec": {
        "apt_stage": "Initial Compromise",
        "statement": "A user-facing attachment or staged object was opened or executed.",
        "query_terms": ("attachment execution", "user execution", "malicious attachment"),
        "tactic_ids": ("TA0001", "TA0002"),
        "technique_ids": ("T1566.001", "T1566.002", "T1204.002"),
        "allow_tactics": ("TA0001", "TA0002"),
    },
    "shell_exec": {
        "apt_stage": "Establish Foothold",
        "statement": "A shell or interpreter executed attacker-controlled commands.",
        "query_terms": ("shell execution", "command interpreter", "bash exec"),
        "tactic_ids": ("TA0002",),
        "technique_ids": ("T1059",),
        "allow_tactics": ("TA0002",),
    },
    "cnc_communication": {
        "apt_stage": "Establish Foothold",
        "statement": "A compromised process communicated repeatedly with an external endpoint consistent with C2.",
        "query_terms": ("command and control", "web protocols", "beacon"),
        "tactic_ids": ("TA0011",),
        "technique_ids": ("T1071.001",),
        "allow_tactics": ("TA0011",),
    },
    "sudo_exec": {
        "apt_stage": "Privilege Escalation",
        "statement": "A privileged execution path used sudo or a superuser helper after compromise.",
        "query_terms": ("sudo exec", "privilege escalation"),
        "tactic_ids": ("TA0004",),
        "technique_ids": (),
        "allow_tactics": ("TA0004",),
    },
    "switch_su": {
        "apt_stage": "Privilege Escalation",
        "statement": "A process switched identity to a higher-privilege user.",
        "query_terms": ("switch user", "setuid", "su"),
        "tactic_ids": ("TA0004",),
        "technique_ids": (),
        "allow_tactics": ("TA0004",),
    },
    "payload_elevate": {
        "apt_stage": "Privilege Escalation",
        "statement": "A staged attacker payload was explicitly elevated or re-launched with higher privileges.",
        "query_terms": ("payload elevate", "elevate payload", "root payload execution"),
        "tactic_ids": ("TA0004",),
        "technique_ids": (),
        "allow_tactics": ("TA0004",),
    },
    "credential_submit": {
        "apt_stage": "Internal Recon",
        "statement": "A browser- or mail-mediated interaction submitted credentials or other user-entered secrets to an external site.",
        "query_terms": ("credential submit", "phishing form", "browser credential post"),
        "tactic_ids": ("TA0006",),
        "technique_ids": (),
        "allow_tactics": ("TA0006",),
    },
    "sensitive_read": {
        "apt_stage": "Internal Recon",
        "statement": "A process read credential, history, or other sensitive local artifacts.",
        "query_terms": ("sensitive read", "credential access", "data from local system"),
        "tactic_ids": ("TA0006", "TA0009"),
        "technique_ids": ("T1552.003", "T1005"),
        "allow_tactics": ("TA0006", "TA0009"),
    },
    "sensitive_command": {
        "apt_stage": "Internal Recon",
        "statement": "A process executed host- or network-enumeration commands.",
        "query_terms": ("system information discovery", "host discovery", "enumeration"),
        "tactic_ids": ("TA0007",),
        "technique_ids": (),
        "allow_tactics": ("TA0007",),
    },
    "network_service_discovery": {
        "apt_stage": "Internal Recon",
        "statement": "The path shows bursty or multi-host connection activity consistent with service discovery or scanning.",
        "query_terms": ("network service discovery", "port scan", "service scan"),
        "tactic_ids": ("TA0007",),
        "technique_ids": ("T1046",),
        "allow_tactics": ("TA0007",),
    },
    "send_internal": {
        "apt_stage": "Move Laterally",
        "statement": "A process initiated suspicious internal connections consistent with lateral movement.",
        "query_terms": ("internal connection", "lateral movement", "remote service"),
        "tactic_ids": ("TA0008",),
        "technique_ids": (),
        "allow_tactics": ("TA0008",),
    },
    "sensitive_leak": {
        "apt_stage": "Complete Mission",
        "statement": "Sensitive local data was followed by outbound transfer to an external endpoint.",
        "query_terms": ("data exfiltration", "sensitive leak", "outbound transfer"),
        "tactic_ids": ("TA0010", "TA0011"),
        "technique_ids": ("T1041",),
        "allow_tactics": ("TA0010", "TA0011"),
    },
    "clear_logs": {
        "apt_stage": "Cleanup Tracks",
        "statement": "The path removed or modified log artifacts consistent with defense evasion.",
        "query_terms": ("clear logs", "artifact cleanup", "file deletion"),
        "tactic_ids": ("TA0005",),
        "technique_ids": ("T1070.004",),
        "allow_tactics": ("TA0005",),
    },
    "sensitive_temp_rm": {
        "apt_stage": "Cleanup Tracks",
        "statement": "Temporary artifacts tied to sensitive collection were deleted after use.",
        "query_terms": ("temporary file cleanup", "artifact cleanup", "file deletion"),
        "tactic_ids": ("TA0005",),
        "technique_ids": ("T1070.004",),
        "allow_tactics": ("TA0005",),
    },
    "untrusted_file_rm": {
        "apt_stage": "Cleanup Tracks",
        "statement": "A suspicious staged or downloaded object was deleted after execution.",
        "query_terms": ("malware cleanup", "file deletion", "remove dropped file"),
        "tactic_ids": ("TA0005",),
        "technique_ids": ("T1070.004",),
        "allow_tactics": ("TA0005",),
    },
    "interpreter_precursor_chain": {
        "apt_stage": "Establish Foothold",
        "statement": "A short-lived interpreter precursor chain staged and launched attacker tooling.",
        "query_terms": ("interpreter precursor", "command-not-found", "bash python chmod"),
        "tactic_ids": ("TA0002", "TA0001"),
        "technique_ids": ("T1059",),
        "allow_tactics": ("TA0002", "TA0001"),
    },
}

HOLMES_STAGE_ORDER = {
    "Initial Compromise": 0,
    "Establish Foothold": 1,
    "Privilege Escalation": 2,
    "Internal Recon": 3,
    "Move Laterally": 4,
    "Complete Mission": 5,
    "Cleanup Tracks": 6,
}

HOLMES_ALLOW_TACTICS = {
    key: set(value.get("allow_tactics", ()))
    for key, value in HOLMES_TTP_CATALOG.items()
}
HOLMES_ATTACK_PRIORS = {
    key: {
        "tactics": set(value.get("tactic_ids", ())),
        "techniques": set(value.get("technique_ids", ())),
    }
    for key, value in HOLMES_TTP_CATALOG.items()
}
HOLMES_QUERY_TERMS = {
    key: tuple(value.get("query_terms", (key.replace("_", " "),)))
    for key, value in HOLMES_TTP_CATALOG.items()
}

_RECON_COMMAND_MARKERS = ("whoami", "hostname", "uname", "ifconfig", "ip addr", "netstat", "ss ", "ps ", "id ")
_ATTACHMENT_MARKERS = ("tcexec", "pine", "rimapd", "attachment", "mail")
_BROWSER_PROCESS_MARKERS = ("firefox", "chrome", "chromium", "edge", "safari", "thunderbird", "outlook", "mail", "fluxbox")
_CREDENTIAL_SUBMIT_MAX_RECV_EVENTS = 80
_CREDENTIAL_SUBMIT_MAX_DURATION_SECONDS = 150.0
_SENSITIVE_STRONG_LABELS = {"B_READ_CRED", "B_READ_HISTORY"}
_SENSITIVE_WEAK_LABELS = {"B_READ_BUSINESS", "B_MASS_FILE_ACCESS"}
_STRONG_EXEC_FAMILY_TAGS = {
    "short_lived_precursor",
    "attachment_or_tcexec_exec",
    "initial_or_drop_exec",
}
_STRONG_EXEC_LABELS = {
    "A_BRIDGED_BY_SUSPICIOUS_OBJECT",
    "B_EXEC_SUSPECT_WRITTEN",
    "B_EXEC_DOWNLOADED",
    "B_EXEC_UPLOADED",
    "B_EXEC_TEMP",
    "B_SHELL_SPAWN",
    "B_SCRIPT_EXEC",
}
_DELETE_EVENT_TYPES = {"DELETE", "UNLINK", "RENAME"}
_LOG_PATH_MARKERS = ("/var/log/", ".log", "lastlog", "wtmp", "btmp", "utmp", "messages", "secure")
_TEMP_CLEANUP_MARKERS = ("/tmp/", "/var/tmp/", "/dev/shm/", "ztmp", "gtcache")
_STAGED_OBJECT_ROLE_LABELS = {"O_SUSPECT_WRITTEN_EXECUTABLE", "O_FILE_DOWNLOADED", "O_FILE_UPLOADED", "O_FILE_TEMP"}


def _normalize_text(value: Any) -> str:
    return " ".join(str(value or "").strip().split()).lower()


def _unique_event_ids(values: Iterable[str]) -> list[str]:
    output: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text not in output:
            output.append(text)
    return output


def _timeline_by_id(dossier: dict[str, Any]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for item in dossier.get("evidence_timeline", []) or []:
        if isinstance(item, dict):
            event_id = str(item.get("event_id", "")).strip()
            if event_id:
                output[event_id] = item
    return output


def _timeline_items_for_predicate(
    dossier: dict[str, Any],
    predicate,
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for item in dossier.get("evidence_timeline", []) or []:
        if isinstance(item, dict) and predicate(item):
            output.append(item)
    return output


def _timeline_items_for_labels(dossier: dict[str, Any], labels: set[str]) -> list[dict[str, Any]]:
    return _timeline_items_for_predicate(
        dossier,
        lambda item: bool(
            {
                str(value).strip()
                for value in item.get("labels_triggered", []) or []
                if str(value).strip()
            }.intersection(labels)
        ),
    )


def _event_ids_from_items(items: list[dict[str, Any]], limit: int = 8) -> list[str]:
    output: list[str] = []
    for item in items:
        event_id = str(item.get("event_id", "")).strip()
        if event_id and event_id not in output:
            output.append(event_id)
        if len(output) >= limit:
            break
    return output


def _core_process_labels(dossier: dict[str, Any]) -> set[str]:
    output: set[str] = set()
    for item in dossier.get("core_processes", []) or []:
        if not isinstance(item, dict):
            continue
        for label in item.get("labels", []) or []:
            text = str(label).strip()
            if text:
                output.add(text)
    return output


def _dossier_family_tags(dossier: dict[str, Any]) -> set[str]:
    return {
        str(value).strip()
        for value in dossier.get("family_tags", []) or []
        if str(value).strip()
    }


def _text_blob(dossier: dict[str, Any]) -> str:
    parts: list[str] = []
    for item in dossier.get("evidence_timeline", []) or []:
        if isinstance(item, dict):
            parts.extend(
                [
                    str(item.get("description", "")).strip(),
                    str(item.get("object_key", "")).strip(),
                    str(item.get("object_class", "")).strip(),
                ]
            )
    for edge in dossier.get("bridge_edges", []) or []:
        if isinstance(edge, dict):
            parts.extend(
                [
                    str(edge.get("object_key", "")).strip(),
                    str(edge.get("reason", "")).strip(),
                    " ".join(str(value).strip() for value in edge.get("object_labels", []) or [] if str(value).strip()),
                ]
            )
    parts.extend(str(value).strip() for value in dossier.get("support_object_keys", []) or [] if str(value).strip())
    for key in (
        "network_support_summary",
        "object_lineage_summary",
        "service_context_summary",
        "sensitive_object_summary",
        "cleanup_object_summary",
        "summary",
    ):
        text = str(dossier.get(key, "")).strip()
        if text:
            parts.append(text)
    return " ".join(part for part in parts if part).lower()


def _core_process_names(dossier: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for item in dossier.get("core_processes", []) or []:
        if not isinstance(item, dict):
            continue
        for key in ("name", "process_name", "exe", "process_exe"):
            text = _normalize_text(item.get(key, ""))
            if text:
                names.add(text)
    return names


def _timeline_item_labels(item: dict[str, Any]) -> set[str]:
    return {str(value).strip() for value in item.get("labels_triggered", []) or [] if str(value).strip()}


def _timeline_item_process_guid(item: dict[str, Any]) -> str:
    return str(item.get("process_guid", "")).strip()


def _timeline_item_object_key(item: dict[str, Any]) -> str:
    return str(item.get("object_key", "")).strip()


def _timeline_item_event_type(item: dict[str, Any]) -> str:
    return str(item.get("event_type", "")).strip().upper()


def _timeline_item_object_class(item: dict[str, Any]) -> str:
    return str(item.get("object_class", "")).strip().lower()


def _timeline_item_object_labels(item: dict[str, Any]) -> set[str]:
    return {str(value).strip() for value in item.get("object_labels", []) or [] if str(value).strip()}


def _event_items_by_ids(timeline_by_id: dict[str, dict[str, Any]], event_ids: Iterable[str]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for event_id in event_ids:
        item = timeline_by_id.get(str(event_id).strip())
        if isinstance(item, dict):
            output.append(item)
    return output


def _non_service_sensitive_ids(timeline_by_id: dict[str, dict[str, Any]], event_ids: Iterable[str]) -> list[str]:
    output: list[str] = []
    for item in _event_items_by_ids(timeline_by_id, event_ids):
        event_id = str(item.get("event_id", "")).strip()
        object_key = _timeline_item_object_key(item)
        if event_id and object_key and not is_system_service_object_key(object_key):
            output.append(event_id)
    return _unique_event_ids(output)


def _has_staged_exec_lineage(
    *,
    staged_object_keys: set[str],
    staged_chmod_ids: list[str],
    staged_exec_ids: list[str],
    bridge_exec_ids: list[str],
) -> bool:
    return bool(staged_object_keys or staged_chmod_ids or staged_exec_ids or bridge_exec_ids)


def _flatten_ordered_pairs(pairs: list[tuple[str, str]]) -> list[str]:
    output: list[str] = []
    for earlier_id, later_id in pairs:
        if earlier_id and earlier_id not in output:
            output.append(earlier_id)
        if later_id and later_id not in output:
            output.append(later_id)
    return output


def _ordered_signal_pairs_within_window(
    dossier: dict[str, Any],
    earlier_ids: Iterable[str],
    later_ids: Iterable[str],
    *,
    max_minutes: int,
) -> list[tuple[str, str]]:
    positions = _timeline_position_by_id(dossier)
    timeline_by_id = _timeline_by_id(dossier)
    output: list[tuple[str, str]] = []
    for earlier_id in _unique_event_ids(earlier_ids):
        earlier_item = timeline_by_id.get(earlier_id)
        if not isinstance(earlier_item, dict):
            continue
        earlier_pos = positions.get(earlier_id)
        earlier_ts = item_timestamp(earlier_item)
        for later_id in _unique_event_ids(later_ids):
            later_item = timeline_by_id.get(later_id)
            if not isinstance(later_item, dict):
                continue
            later_pos = positions.get(later_id)
            if earlier_pos is None or later_pos is None or earlier_pos >= later_pos:
                continue
            later_ts = item_timestamp(later_item)
            if earlier_ts is not None and later_ts is not None:
                delta = later_ts - earlier_ts
                if delta < timedelta(0) or delta > timedelta(minutes=max_minutes):
                    continue
            output.append((earlier_id, later_id))
    return output


def _pairs_share_process(
    timeline_by_id: dict[str, dict[str, Any]],
    pairs: list[tuple[str, str]],
) -> bool:
    for earlier_id, later_id in pairs:
        earlier_item = timeline_by_id.get(earlier_id)
        later_item = timeline_by_id.get(later_id)
        if not isinstance(earlier_item, dict) or not isinstance(later_item, dict):
            continue
        earlier_process = _timeline_item_process_guid(earlier_item)
        later_process = _timeline_item_process_guid(later_item)
        if earlier_process and earlier_process == later_process:
            return True
    return False


def _has_lineage_or_bridge_support(dossier: dict[str, Any]) -> bool:
    if str(dossier.get("object_lineage_summary", "")).strip():
        return True
    if any(str(value).strip() for value in dossier.get("support_relations", []) or []):
        return True
    return any(isinstance(edge, dict) for edge in dossier.get("bridge_edges", []) or [])


def _is_log_cleanup_item(item: dict[str, Any]) -> bool:
    labels = _timeline_item_labels(item).union(_timeline_item_object_labels(item))
    if "B_DELETE_LOG" in labels or "O_LOG_ARTIFACT" in labels:
        return True
    if _timeline_item_object_class(item) == "log_file":
        return True
    object_key = _normalize_text(item.get("object_key", ""))
    return bool(object_key and any(marker in object_key for marker in _LOG_PATH_MARKERS))


def _cleanup_event_ids(
    dossier: dict[str, Any],
    *,
    strong_exec_context: bool,
    staged_object_keys: set[str],
) -> tuple[list[str], list[str]]:
    if not strong_exec_context:
        return [], []
    log_cleanup_ids: list[str] = []
    staged_cleanup_ids: list[str] = []
    timeline_by_id = _timeline_by_id(dossier)
    staged_cleanup_keys = collect_staged_object_keys(
        timeline_by_id.values(),
        suspicious_object_keys=staged_object_keys,
    )
    for item in timeline_by_id.values():
        event_id = str(item.get("event_id", "")).strip()
        if not event_id or _timeline_item_event_type(item) not in _DELETE_EVENT_TYPES:
            continue
        object_key = _normalize_text(item.get("object_key", ""))
        if not object_key or is_placeholder_object_key(object_key):
            continue
        if _is_log_cleanup_item(item):
            log_cleanup_ids.append(event_id)
            continue
        staged_object_like = bool(_timeline_item_object_labels(item).intersection(_STAGED_OBJECT_ROLE_LABELS))
        temp_cleanup_like = any(marker in object_key for marker in _TEMP_CLEANUP_MARKERS)
        if (object_key in staged_cleanup_keys or staged_object_like or temp_cleanup_like) and not is_system_service_object_key(object_key):
            staged_cleanup_ids.append(event_id)
    return _unique_event_ids(log_cleanup_ids), _unique_event_ids(staged_cleanup_ids)


def _bridge_exec_event_ids(dossier: dict[str, Any]) -> list[str]:
    output: list[str] = []
    for edge in dossier.get("bridge_edges", []) or []:
        if not isinstance(edge, dict):
            continue
        labels = {str(value).strip() for value in edge.get("object_labels", []) or [] if str(value).strip()}
        if not labels.intersection({"O_SUSPECT_WRITTEN_EXECUTABLE", "O_FILE_DOWNLOADED", "O_FILE_UPLOADED", "O_FILE_TEMP"}):
            continue
        for key in ("write_event_id", "read_or_exec_event_id"):
            event_id = str(edge.get(key, "")).strip()
            if event_id and event_id not in output:
                output.append(event_id)
    return output


def _timeline_position_by_id(dossier: dict[str, Any]) -> dict[str, int]:
    positions: dict[str, int] = {}
    for index, item in enumerate(dossier.get("evidence_timeline", []) or []):
        if not isinstance(item, dict):
            continue
        event_id = str(item.get("event_id", "")).strip()
        if event_id and event_id not in positions:
            positions[event_id] = index
    return positions


def _has_ordered_signal_flow(dossier: dict[str, Any], earlier_ids: list[str], later_ids: list[str]) -> bool:
    positions = _timeline_position_by_id(dossier)
    earlier_positions = [positions[event_id] for event_id in earlier_ids if event_id in positions]
    later_positions = [positions[event_id] for event_id in later_ids if event_id in positions]
    return bool(earlier_positions and later_positions and any(src < dst for src in earlier_positions for dst in later_positions))


def _has_strong_exec_context(
    dossier: dict[str, Any],
    *,
    labels: set[str],
    exec_ids: list[str],
    bridge_exec_ids: list[str],
    attachment_ids: list[str],
    shell_exec_ids: list[str],
    precursor_ids: list[str],
) -> bool:
    family_tags = _dossier_family_tags(dossier)
    if bridge_exec_ids or attachment_ids or shell_exec_ids or precursor_ids:
        return True
    if labels.intersection(_STRONG_EXEC_LABELS):
        return True
    if family_tags.intersection(_STRONG_EXEC_FAMILY_TAGS):
        return True
    return bool(exec_ids and family_tags.intersection({"callback_c2", "cleanup_delete", *tuple(_STRONG_EXEC_FAMILY_TAGS)}))


def _is_browser_mail_context(dossier: dict[str, Any], blob: str) -> bool:
    family_tags = _dossier_family_tags(dossier)
    if "mail_browser_context_tail" in family_tags:
        return True
    process_names = _core_process_names(dossier)
    return any(any(marker in name for marker in _BROWSER_PROCESS_MARKERS) for name in process_names) or "browser" in blob


def _is_browser_only_context(dossier: dict[str, Any], blob: str) -> bool:
    if not _is_browser_mail_context(dossier, blob):
        return False
    process_names = _core_process_names(dossier)
    if not process_names:
        return False
    return all(any(marker in name for marker in _BROWSER_PROCESS_MARKERS) for name in process_names)


def _timeline_span_seconds(dossier: dict[str, Any]) -> float | None:
    values: list[Any] = []
    for item in dossier.get("evidence_timeline", []) or []:
        if not isinstance(item, dict):
            continue
        value = item_timestamp(item)
        if value is not None:
            values.append(value)
    if len(values) < 2:
        return None
    return max(0.0, float((max(values) - min(values)).total_seconds()))


def _network_support_counts(dossier: dict[str, Any]) -> dict[str, int]:
    summary = str(dossier.get("network_support_summary", "")).strip()
    if not summary:
        return {}
    output: dict[str, int] = {}
    for chunk in summary.split(";"):
        part = chunk.strip()
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip()
        value = value.strip()
        if not key or not value:
            continue
        try:
            output[key] = int(value)
        except ValueError:
            continue
    return output


def _candidate_precursor_ids(dossier: dict[str, Any], blob: str) -> list[str]:
    items = [item for item in dossier.get("evidence_timeline", []) or [] if isinstance(item, dict)]
    if not items:
        return []
    suspicious_object_keys = staged_object_keys_from_bridge_edges(dossier.get("bridge_edges", []) or [])
    provided_ids = _unique_event_ids(str(value).strip() for value in dossier.get("precursor_event_ids", []) or [])
    if provided_ids:
        item_by_id = {str(item.get("event_id", "")).strip(): item for item in items if str(item.get("event_id", "")).strip()}
        provided_items = [item_by_id[event_id] for event_id in provided_ids if event_id in item_by_id]
        return collect_precursor_event_ids(provided_items, suspicious_object_keys=suspicious_object_keys, limit=8)
    return collect_precursor_event_ids(items, suspicious_object_keys=suspicious_object_keys, limit=8)


def build_holmes_claim_graph(dossier: dict[str, Any]) -> dict[str, Any]:
    timeline_by_id = _timeline_by_id(dossier)
    labels = _core_process_labels(dossier)
    blob = _text_blob(dossier)

    external_recv_ids = _event_ids_from_items(
        _timeline_items_for_predicate(
            dossier,
            lambda item: "B_EXTERNAL_RECV" in _timeline_item_labels(item)
            or (_timeline_item_object_class(item) == "external_ip" and _timeline_item_event_type(item) == "RECV"),
        )
    )
    external_send_ids = _event_ids_from_items(
        _timeline_items_for_predicate(
            dossier,
            lambda item: "B_EXTERNAL_SEND" in _timeline_item_labels(item)
            or (_timeline_item_object_class(item) == "external_ip" and _timeline_item_event_type(item) == "SEND"),
        )
    )
    lateral_ids = _event_ids_from_items(_timeline_items_for_labels(dossier, {"B_LATERAL_CONNECT"}))
    exec_ids = _event_ids_from_items(
        _timeline_items_for_labels(dossier, {"B_EXEC_SUSPECT_WRITTEN", "B_EXEC_DOWNLOADED", "B_EXEC_UPLOADED", "B_EXEC_TEMP"})
    )
    strong_sensitive_ids = _event_ids_from_items(
        _timeline_items_for_predicate(
            dossier,
            lambda item: _timeline_item_event_type(item) == "READ"
            and bool(_timeline_item_labels(item).intersection(_SENSITIVE_STRONG_LABELS)),
        )
    )
    weak_sensitive_ids = _event_ids_from_items(
        _timeline_items_for_predicate(
            dossier,
            lambda item: _timeline_item_event_type(item) == "READ"
            and bool(_timeline_item_labels(item).intersection(_SENSITIVE_WEAK_LABELS)),
        )
    )
    recon_command_ids = _event_ids_from_items(
        _timeline_items_for_predicate(
            dossier,
            lambda item: any(marker in _normalize_text(item.get("description", "")) for marker in _RECON_COMMAND_MARKERS),
        )
    )
    scan_ids = _event_ids_from_items(
        _timeline_items_for_predicate(
            dossier,
            lambda item: "B_LATERAL_CONNECT" in {str(value).strip() for value in item.get("labels_triggered", []) or [] if str(value).strip()}
            or ("connect" == str(item.get("event_type", "")).strip().lower() and str(item.get("object_class", "")).strip().lower() in {"external_ip", "internal_ip"}),
        )
    )
    internal_send_ids = _event_ids_from_items(
        _timeline_items_for_predicate(
            dossier,
            lambda item: str(item.get("object_class", "")).strip().lower() == "internal_ip"
            and str(item.get("event_type", "")).strip().upper() in {"CONNECT", "SEND", "RECV"},
        )
    )
    mem_exec_ids = _event_ids_from_items(
        _timeline_items_for_predicate(
            dossier,
            lambda item: any(term in _normalize_text(item.get("description", "")) for term in ("mprotect", "mem exec", "mprotect_exec", "virtualalloc")),
        )
    )
    attachment_ids = _event_ids_from_items(
        _timeline_items_for_predicate(
            dossier,
            lambda item: any(marker in _normalize_text(item.get("description", "")) or marker in _normalize_text(item.get("object_key", "")) for marker in _ATTACHMENT_MARKERS),
        )
    )
    precursor_ids = _candidate_precursor_ids(dossier, blob)
    bridge_exec_ids = _bridge_exec_event_ids(dossier)
    temp_remove_ids = _event_ids_from_items(
        _timeline_items_for_predicate(
            dossier,
            lambda item: str(item.get("event_type", "")).strip().upper() in _DELETE_EVENT_TYPES
            and any(token in _normalize_text(item.get("object_key", "")) for token in ("/tmp/", "temp", "gtcache", "ztmp")),
        )
    )
    shell_exec_ids = _event_ids_from_items(
        _timeline_items_for_predicate(
            dossier,
            lambda item: any(marker in _normalize_text(item.get("description", "")) for marker in ("bash", "sh ", "python", "perl", "php", "tcexec", "command-not-found")),
        )
    )
    strong_exec_context = _has_strong_exec_context(
        dossier,
        labels=labels,
        exec_ids=exec_ids,
        bridge_exec_ids=bridge_exec_ids,
        attachment_ids=attachment_ids,
        shell_exec_ids=shell_exec_ids,
        precursor_ids=precursor_ids,
    )
    sudo_ids = _event_ids_from_items(
        _timeline_items_for_predicate(
            dossier,
            lambda item: "sudo" in _normalize_text(item.get("description", "")),
        )
    )
    su_ids = _event_ids_from_items(
        _timeline_items_for_predicate(
            dossier,
            lambda item: any(term in _normalize_text(item.get("description", "")) for term in (" setuid", " su ", "switch user")),
        )
    )
    browser_only_context = _is_browser_only_context(dossier, blob)
    browser_mail_context = _is_browser_mail_context(dossier, blob)
    explicit_callback_context = bool(
        shell_exec_ids
        or precursor_ids
        or attachment_ids
        or (bridge_exec_ids and not browser_only_context)
    )

    claims: list[dict[str, Any]] = []
    claim_ids_by_atom: dict[str, str] = {}
    created_ids: list[str] = []
    stage_counter: Counter[str] = Counter()

    def add_claim(atom: str, event_ids: list[str], confidence: float, support_signals: list[str], *, claim_source: str = "holmes_rule") -> None:
        if atom not in HOLMES_TTP_CATALOG:
            return
        dedup_ids = _unique_event_ids(event_ids)[:8]
        if not dedup_ids:
            return
        stage = str(HOLMES_TTP_CATALOG[atom]["apt_stage"])
        stage_counter[stage] += 1
        claim_id = f"{atom}_{stage_counter[stage]}"
        claim_ids_by_atom[atom] = claim_id
        created_ids.append(claim_id)
        claims.append(
            {
                "claim_id": claim_id,
                "behavior_type": atom,
                "statement": str(HOLMES_TTP_CATALOG[atom]["statement"]),
                "evidence_event_ids": dedup_ids,
                "confidence": round(float(confidence), 3),
                "apt_stage": stage,
                "prerequisite_claim_ids": [],
                "claim_source": claim_source,
                "support_signals": [signal for signal in support_signals if signal],
            }
        )

    if external_recv_ids:
        add_claim("untrusted_read", external_recv_ids, 0.74, ["external_recv"])
    staged_object_keys = staged_object_keys_from_bridge_edges(dossier.get("bridge_edges", []) or [])
    staged_chmod_ids = collect_staged_chmod_event_ids(
        dossier.get("evidence_timeline", []) or [],
        suspicious_object_keys=staged_object_keys,
        limit=8,
    )
    staged_exec_ids = collect_staged_exec_event_ids(
        dossier.get("evidence_timeline", []) or [],
        suspicious_object_keys=staged_object_keys,
        limit=8,
    )
    staged_lineage = _has_staged_exec_lineage(
        staged_object_keys=staged_object_keys,
        staged_chmod_ids=staged_chmod_ids,
        staged_exec_ids=staged_exec_ids,
        bridge_exec_ids=bridge_exec_ids,
    )
    weak_sensitive_non_service_ids = _non_service_sensitive_ids(timeline_by_id, weak_sensitive_ids)
    raw_discovery_signal = bool(len(scan_ids) >= 2 or (scan_ids and lateral_ids))
    raw_log_cleanup_ids, raw_staged_cleanup_ids = _cleanup_event_ids(
        dossier,
        strong_exec_context=strong_exec_context,
        staged_object_keys=staged_object_keys,
    )
    if mem_exec_ids and (external_recv_ids or precursor_ids):
        add_claim("make_mem_exec", mem_exec_ids + external_recv_ids + precursor_ids, 0.77, ["mem_exec", "precursor_dependency"])
    if staged_chmod_ids:
        add_claim("make_file_exec", staged_chmod_ids + staged_exec_ids + bridge_exec_ids, 0.78, ["chmod_exec", "staged_object"])
    if bridge_exec_ids:
        add_claim("untrusted_file_exec", bridge_exec_ids + external_recv_ids, 0.84, ["bridge_exec", "staged_object"])
    if attachment_ids:
        add_claim("attachment_user_exec", attachment_ids + bridge_exec_ids, 0.82, ["attachment_markers"])
    if shell_exec_ids:
        add_claim("shell_exec", shell_exec_ids + precursor_ids[:4], 0.78, ["interpreter_exec"])
    credential_submit_pairs = _ordered_signal_pairs_within_window(
        dossier,
        external_recv_ids,
        external_send_ids,
        max_minutes=10,
    )
    network_support_counts = _network_support_counts(dossier)
    credential_submit_recv_total = network_support_counts.get("external_recv", len(external_recv_ids))
    credential_submit_span_seconds = _timeline_span_seconds(dossier)
    credential_submit_short_burst = credential_submit_recv_total <= _CREDENTIAL_SUBMIT_MAX_RECV_EVENTS and (
        credential_submit_span_seconds is None
        or credential_submit_span_seconds <= _CREDENTIAL_SUBMIT_MAX_DURATION_SECONDS
    )
    if (
        browser_mail_context
        and browser_only_context
        and credential_submit_pairs
        and not explicit_callback_context
        and credential_submit_short_burst
    ):
        add_claim("credential_submit", _flatten_ordered_pairs(credential_submit_pairs), 0.77, ["browser_form_submit"])
    if external_send_ids and strong_exec_context and (not browser_only_context or explicit_callback_context):
        add_claim("cnc_communication", external_send_ids + external_recv_ids, 0.8, ["external_c2"])
    if sudo_ids:
        add_claim("sudo_exec", sudo_ids, 0.8, ["sudo"])
    if su_ids:
        add_claim("switch_su", su_ids, 0.8, ["identity_switch"])
    payload_elevate_ids = collect_payload_elevate_event_ids(
        dossier.get("evidence_timeline", []) or [],
        suspicious_object_keys=staged_object_keys,
        limit=8,
    )
    if payload_elevate_ids and strong_exec_context:
        add_claim("payload_elevate", payload_elevate_ids + bridge_exec_ids[:2], 0.81, ["payload_elevate"])
    sensitive_read_ids: list[str] = []
    sensitive_read_signals: list[str] = []
    if strong_sensitive_ids and strong_exec_context:
        sensitive_read_ids.extend(strong_sensitive_ids)
        sensitive_read_signals.append("sensitive_strong_read")
    weak_sensitive_support = bool(
        raw_discovery_signal
        or raw_log_cleanup_ids
        or raw_staged_cleanup_ids
        or staged_lineage
        or (external_send_ids and strong_exec_context and (not browser_only_context or explicit_callback_context))
    )
    if weak_sensitive_non_service_ids and strong_exec_context and weak_sensitive_support:
        sensitive_read_ids.extend(weak_sensitive_non_service_ids)
        sensitive_read_signals.append("sensitive_weak_read")
    sensitive_read_ids = _unique_event_ids(sensitive_read_ids)
    if sensitive_read_ids:
        add_claim("sensitive_read", sensitive_read_ids, 0.82, sensitive_read_signals or ["sensitive_local_read"])
    if recon_command_ids:
        add_claim("sensitive_command", recon_command_ids, 0.78, ["recon_commands"])
    if raw_discovery_signal:
        add_claim("network_service_discovery", scan_ids + lateral_ids, 0.82, ["scan_burst"])
    if internal_send_ids:
        add_claim("send_internal", internal_send_ids, 0.76, ["internal_connect"])
    leak_pairs = _ordered_signal_pairs_within_window(
        dossier,
        sensitive_read_ids,
        external_send_ids,
        max_minutes=10,
    )
    if leak_pairs and strong_exec_context and (
        _pairs_share_process(timeline_by_id, leak_pairs) or _has_lineage_or_bridge_support(dossier)
    ):
        add_claim("sensitive_leak", _flatten_ordered_pairs(leak_pairs), 0.83, ["sensitive_plus_external_send"])
    log_cleanup_ids, staged_cleanup_ids = raw_log_cleanup_ids, raw_staged_cleanup_ids
    clear_logs_ids = _unique_event_ids(log_cleanup_ids + staged_cleanup_ids)
    clear_logs_signals: list[str] = []
    if log_cleanup_ids:
        clear_logs_signals.append("log_cleanup")
    if staged_cleanup_ids:
        clear_logs_signals.append("staged_cleanup")
    if clear_logs_ids:
        add_claim("clear_logs", clear_logs_ids, 0.82, clear_logs_signals or ["log_cleanup"])
    if temp_remove_ids and sensitive_read_ids:
        add_claim("sensitive_temp_rm", temp_remove_ids + sensitive_read_ids, 0.78, ["temp_cleanup_after_collection"])
    if temp_remove_ids and bridge_exec_ids:
        add_claim("untrusted_file_rm", temp_remove_ids + bridge_exec_ids, 0.76, ["cleanup_staged_object"])
    if precursor_ids:
        add_claim("interpreter_precursor_chain", precursor_ids, 0.8, ["precursor_markers"], claim_source="holmes_precursor_rule")

    prerequisite_map = {
        "make_mem_exec": ("untrusted_read",),
        "make_file_exec": ("untrusted_read",),
        "untrusted_file_exec": ("untrusted_read", "make_file_exec", "attachment_user_exec"),
        "attachment_user_exec": ("untrusted_read",),
        "shell_exec": ("untrusted_file_exec", "attachment_user_exec", "interpreter_precursor_chain"),
        "cnc_communication": ("untrusted_file_exec", "attachment_user_exec", "shell_exec", "interpreter_precursor_chain"),
        "sudo_exec": ("shell_exec",),
        "switch_su": ("shell_exec",),
        "payload_elevate": ("untrusted_file_exec", "make_file_exec", "attachment_user_exec", "shell_exec"),
        "credential_submit": ("untrusted_read",),
        "sensitive_read": ("untrusted_file_exec", "shell_exec", "interpreter_precursor_chain"),
        "sensitive_command": ("untrusted_file_exec", "shell_exec", "interpreter_precursor_chain"),
        "network_service_discovery": ("shell_exec", "cnc_communication", "attachment_user_exec"),
        "send_internal": ("shell_exec", "cnc_communication"),
        "sensitive_leak": ("sensitive_read", "cnc_communication"),
        "clear_logs": ("shell_exec", "cnc_communication"),
        "sensitive_temp_rm": ("sensitive_read",),
        "untrusted_file_rm": ("untrusted_file_exec",),
        "interpreter_precursor_chain": ("attachment_user_exec", "make_file_exec", "untrusted_read"),
    }
    for claim in claims:
        atom = str(claim.get("behavior_type", "")).strip()
        prerequisites = [
            claim_ids_by_atom[dependency]
            for dependency in prerequisite_map.get(atom, ())
            if dependency in claim_ids_by_atom
        ]
        claim["prerequisite_claim_ids"] = prerequisites

    claims.sort(
        key=lambda item: (
            HOLMES_STAGE_ORDER.get(str(item.get("apt_stage", "")), 99),
            -float(item.get("confidence", 0.0) or 0.0),
            str(item.get("claim_id", "")),
        )
    )
    for index, claim in enumerate(claims, start=1):
        claim["graph_order"] = index

    edges = [
        {"src_claim_id": prereq, "dst_claim_id": claim["claim_id"], "relation": "prerequisite"}
        for claim in claims
        for prereq in claim.get("prerequisite_claim_ids", [])
    ]
    diagnostics = {
        "matched_atoms": [str(claim.get("behavior_type", "")) for claim in claims],
        "stage_counts": dict(Counter(str(claim.get("apt_stage", "")) for claim in claims)),
        "missing_expected_atoms": [
            atom
            for atom in ("network_service_discovery", "clear_logs", "attachment_user_exec", "interpreter_precursor_chain")
            if atom not in claim_ids_by_atom
        ],
    }
    return {"claims": claims, "edges": edges, "diagnostics": diagnostics, "atom_catalog_version": "holmes_ttp_v1"}
