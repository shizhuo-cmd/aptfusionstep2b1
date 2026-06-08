from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Iterable, List


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
_PRECURSOR_MARKERS = ("tcexec", "command-not-found", "/dev/pts/3", "python3", "chmod", "bash")


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
    for key in ("network_support_summary", "object_lineage_summary", "summary"):
        text = str(dossier.get(key, "")).strip()
        if text:
            parts.append(text)
    return " ".join(part for part in parts if part).lower()


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


def _candidate_precursor_ids(dossier: dict[str, Any], blob: str) -> list[str]:
    provided = _unique_event_ids(str(value).strip() for value in dossier.get("precursor_event_ids", []) or [])
    if provided:
        return provided[:8]
    if not any(marker in blob for marker in _PRECURSOR_MARKERS):
        return []
    items = _timeline_items_for_predicate(
        dossier,
        lambda item: any(marker in _normalize_text(item.get("description", "")) or marker in _normalize_text(item.get("object_key", "")) for marker in _PRECURSOR_MARKERS),
    )
    return _event_ids_from_items(items)


def build_holmes_claim_graph(dossier: dict[str, Any]) -> dict[str, Any]:
    timeline_by_id = _timeline_by_id(dossier)
    labels = _core_process_labels(dossier)
    blob = _text_blob(dossier)

    external_recv_ids = _event_ids_from_items(_timeline_items_for_labels(dossier, {"B_EXTERNAL_RECV"}))
    external_send_ids = _event_ids_from_items(_timeline_items_for_labels(dossier, {"B_EXTERNAL_SEND"}))
    lateral_ids = _event_ids_from_items(_timeline_items_for_labels(dossier, {"B_LATERAL_CONNECT"}))
    exec_ids = _event_ids_from_items(
        _timeline_items_for_labels(dossier, {"B_EXEC_SUSPECT_WRITTEN", "B_EXEC_DOWNLOADED", "B_EXEC_UPLOADED", "B_EXEC_TEMP"})
    )
    sensitive_ids = _event_ids_from_items(
        _timeline_items_for_labels(dossier, {"B_READ_CRED", "B_READ_HISTORY", "B_READ_BUSINESS", "B_MASS_FILE_ACCESS"})
    )
    history_ids = _event_ids_from_items(_timeline_items_for_labels(dossier, {"B_READ_HISTORY"}))
    business_ids = _event_ids_from_items(_timeline_items_for_labels(dossier, {"B_READ_BUSINESS", "B_MASS_FILE_ACCESS"}))
    persistence_ids = _event_ids_from_items(_timeline_items_for_labels(dossier, {"B_WRITE_PERSISTENCE", "B_WRITE_PRIV_CONFIG"}))
    log_delete_ids = _event_ids_from_items(
        _timeline_items_for_predicate(
            dossier,
            lambda item: "B_DELETE_LOG" in {str(value).strip() for value in item.get("labels_triggered", []) or [] if str(value).strip()}
            or ("log" in _normalize_text(item.get("object_key", "")) and str(item.get("event_type", "")).strip().upper() in {"DELETE", "UNLINK", "RENAME"}),
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
    chmod_ids = _event_ids_from_items(
        _timeline_items_for_predicate(
            dossier,
            lambda item: str(item.get("event_type", "")).strip().upper() in {"CHMOD", "MODIFY_FILE_ATTRIBUTES"}
            or "chmod" in _normalize_text(item.get("description", "")),
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
            lambda item: str(item.get("event_type", "")).strip().upper() in {"DELETE", "UNLINK", "RENAME"}
            and any(token in _normalize_text(item.get("object_key", "")) for token in ("/tmp/", "temp", "gtcache", "ztmp")),
        )
    )
    shell_exec_ids = _event_ids_from_items(
        _timeline_items_for_predicate(
            dossier,
            lambda item: any(marker in _normalize_text(item.get("description", "")) for marker in ("bash", "sh ", "python", "perl", "php", "tcexec", "command-not-found")),
        )
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
    if mem_exec_ids and (external_recv_ids or precursor_ids):
        add_claim("make_mem_exec", mem_exec_ids + external_recv_ids + precursor_ids, 0.77, ["mem_exec", "precursor_dependency"])
    if chmod_ids and (external_recv_ids or bridge_exec_ids or precursor_ids):
        add_claim("make_file_exec", chmod_ids + bridge_exec_ids + precursor_ids, 0.78, ["chmod_exec", "staged_object"])
    if bridge_exec_ids:
        add_claim("untrusted_file_exec", bridge_exec_ids + external_recv_ids, 0.84, ["bridge_exec", "staged_object"])
    if attachment_ids:
        add_claim("attachment_user_exec", attachment_ids + bridge_exec_ids, 0.82, ["attachment_markers"])
    if shell_exec_ids:
        add_claim("shell_exec", shell_exec_ids + precursor_ids[:4], 0.78, ["interpreter_exec"])
    if external_send_ids or (external_recv_ids and "network_support_summary" in dossier):
        add_claim("cnc_communication", external_send_ids + external_recv_ids, 0.8, ["external_c2"])
    if sudo_ids:
        add_claim("sudo_exec", sudo_ids, 0.8, ["sudo"])
    if su_ids:
        add_claim("switch_su", su_ids, 0.8, ["identity_switch"])
    if sensitive_ids or history_ids or business_ids:
        add_claim("sensitive_read", sensitive_ids + history_ids + business_ids, 0.82, ["sensitive_local_read"])
    if recon_command_ids:
        add_claim("sensitive_command", recon_command_ids, 0.78, ["recon_commands"])
    if len(scan_ids) >= 2 or (scan_ids and lateral_ids):
        add_claim("network_service_discovery", scan_ids + lateral_ids, 0.82, ["scan_burst"])
    if internal_send_ids:
        add_claim("send_internal", internal_send_ids, 0.76, ["internal_connect"])
    if external_send_ids and (sensitive_ids or business_ids or history_ids):
        add_claim("sensitive_leak", external_send_ids + sensitive_ids + business_ids + history_ids, 0.83, ["sensitive_plus_external_send"])
    if log_delete_ids:
        add_claim("clear_logs", log_delete_ids, 0.82, ["log_cleanup"])
    if temp_remove_ids and (sensitive_ids or business_ids or history_ids):
        add_claim("sensitive_temp_rm", temp_remove_ids + sensitive_ids + business_ids + history_ids, 0.78, ["temp_cleanup_after_collection"])
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
        "sensitive_read": ("untrusted_file_exec", "shell_exec", "cnc_communication", "interpreter_precursor_chain"),
        "sensitive_command": ("untrusted_file_exec", "shell_exec", "cnc_communication", "interpreter_precursor_chain"),
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
