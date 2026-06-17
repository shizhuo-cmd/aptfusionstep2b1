from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

from .attack_kb import (
    load_attack_kb,
    resolve_tactic_name,
    resolve_technique_name,
    retrieve_attack_candidates,
    technique_supports_tactic,
)
from .holmes_claims import (
    HOLMES_ALLOW_TACTICS,
    HOLMES_TTP_CATALOG,
    build_holmes_claim_graph,
)
from ..common import ensure_dir, load_json, save_json
from ..config import FusionConfig
from .llm_io import _call_ollama_json, _llm_input_record

_TACTIC_ID_PATTERN = re.compile(r"^TA\d{4}$", re.IGNORECASE)
_TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(?:[./]\d{3})?$", re.IGNORECASE)
_FLOW_OBJECT_KEY_PATTERN = re.compile(
    r"(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<src_port>\d{1,5})->(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<dst_port>\d{1,5})"
)
_GENERIC_CLAIM_MARKERS = (
    "series of system calls",
    "may indicate a potential threat",
    "malicious object",
    "not fully understood",
)
_PATH_BEHAVIOR_ALIGNMENT_PRIORS = {
    "download_and_exec": {"tactic_id": "TA0011", "technique_id": "T1105"},
    "credential_read": {"tactic_id": "TA0006", "technique_id": ""},
    "business_data_access": {"tactic_id": "TA0009", "technique_id": "T1005"},
    "persistence_change": {"tactic_id": "TA0003", "technique_id": ""},
    "log_deletion": {"tactic_id": "TA0005", "technique_id": "T1070.004"},
    "remote_send": {"tactic_id": "TA0011", "technique_id": ""},
    "lateral_connect": {"tactic_id": "TA0008", "technique_id": ""},
    "remote_service_entry": {"tactic_id": "TA0001", "technique_id": ""},
    "execution_chain": {"tactic_id": "TA0002", "technique_id": ""},
}
_PATH_BEHAVIOR_ALIGNMENT_PRIORS.update(
    {
        key: {
            "tactic_id": str(value.get("tactic_ids", ("",))[0] if value.get("tactic_ids") else ""),
            "technique_id": str(value.get("technique_ids", ("",))[0] if value.get("technique_ids") else ""),
        }
        for key, value in HOLMES_TTP_CATALOG.items()
    }
)
_TACTIC_NAME_BY_ID = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
}
_TECHNIQUE_NAME_BY_ID = {
    "T1105": "Ingress Tool Transfer",
    "T1071.001": "Web Protocols",
    "T1070.004": "File Deletion",
    "T1005": "Data from Local System",
    "T1552.003": "Shell History",
    "T1046": "Network Service Discovery",
    "T1041": "Exfiltration Over C2 Channel",
    "T1059": "Command and Scripting Interpreter",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1204.002": "Malicious File",
}
_WEB_C2_PORTS = {"80", "443", "8080", "8443"}
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
_BEHAVIOR_TACTIC_ALLOWLIST = {
    "download_and_exec": {"TA0011", "TA0002"},
    "credential_read": {"TA0006", "TA0009"},
    "business_data_access": {"TA0009", "TA0010"},
    "persistence_change": {"TA0003", "TA0005"},
    "log_deletion": {"TA0005"},
    "remote_send": {"TA0011", "TA0010"},
    "lateral_connect": {"TA0008"},
    "remote_service_entry": {"TA0001"},
    "execution_chain": {"TA0002"},
}
_BEHAVIOR_TACTIC_ALLOWLIST.update(HOLMES_ALLOW_TACTICS)


def _candidate_dir(cfg: FusionConfig) -> Path:
    return cfg.module5_paths_dir / "candidate_paths"


def _summary_path(cfg: FusionConfig) -> Path:
    return cfg.module6_reason_dir / "summary.json"


def _reports_dir(cfg: FusionConfig) -> Path:
    return cfg.module6_reason_dir / "reports"


def _dossiers_dir(cfg: FusionConfig) -> Path:
    return cfg.module6_reason_dir / "dossiers"


def _markdown_dir(cfg: FusionConfig) -> Path:
    return cfg.module6_reason_dir / "markdown"


def _llm_inputs_dir(cfg: FusionConfig) -> Path:
    return cfg.module6_reason_dir / "llm_inputs"


def _claim_graphs_dir(cfg: FusionConfig) -> Path:
    return cfg.module6_reason_dir / "claim_graphs"


def _report_index_path(cfg: FusionConfig) -> Path:
    return cfg.module6_reason_dir / "report_index.json"


def _claim_attack_priors_enabled(cfg: FusionConfig) -> bool:
    return str(getattr(cfg, "claim_attack_prior_mode", "full")).strip().lower() != "disabled"


def _attack_mapping_scope(cfg: FusionConfig) -> str:
    return str(getattr(cfg, "attack_mapping_scope", "full")).strip().lower() or "full"


def _tactic_mapping_mode(cfg: FusionConfig) -> str:
    return str(getattr(cfg, "tactic_mapping_mode", "llm")).strip().lower() or "llm"


def _tactics_only_enabled(cfg: FusionConfig) -> bool:
    return _attack_mapping_scope(cfg) == "tactics_only"


def _deterministic_tactic_mapping_enabled(cfg: FusionConfig) -> bool:
    return _tactics_only_enabled(cfg) and _tactic_mapping_mode(cfg) == "deterministic"


def _system_prompt() -> str:
    return (
        "You are an advanced persistent threat analyst. Use only the supplied candidate attack path dossier. "
        "Treat bridge edges, explicit behavior labels, and labeled network/file events as the strongest evidence. "
        "Do not summarize benign library loads, generic OPEN/CLOSE noise, or vague system-call sequences as attack behavior. "
        "Return strict JSON only. Every claim or ATT&CK mapping must trace back to event IDs or claim IDs already present in the dossier."
    )


def _extract_schema() -> Dict[str, Any]:
    return {
        "summary": "short factual summary string",
        "claims": [
            {
                "claim_id": "string",
                "behavior_type": "|".join(sorted(HOLMES_TTP_CATALOG)),
                "statement": "string",
                "evidence_event_ids": ["event_id"],
                "confidence": 0.0,
            }
        ],
        "iocs": [
            {
                "type": "ip|domain|url|path|process|port|other",
                "value": "string",
                "evidence_event_ids": ["event_id"],
                "confidence": 0.0,
            }
        ],
        "gaps": ["string"],
    }


def _mapping_schema() -> Dict[str, Any]:
    return {
        "attack_mappings": [
            {
                "tactic_id": "TA0000 or empty string",
                "tactic": "string",
                "technique_id": "T0000 or empty string",
                "technique": "string or empty string",
                "evidence_claim_ids": ["claim_id"],
                "confidence": 0.0,
                "gaps": ["string"],
            }
        ],
        "gaps": ["string"],
    }


def _schema_json(schema: Dict[str, Any]) -> str:
    return json.dumps(schema, ensure_ascii=False, separators=(",", ":"))


def _truncate_text(text: str, limit: int = 160) -> str:
    cleaned = " ".join(str(text or "").strip().split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: max(0, limit - 3)].rstrip() + "..."


def _csv(values: list[str], limit: int | None = None) -> str:
    items = [str(value).strip() for value in values if str(value).strip()]
    if limit is not None:
        items = items[:limit]
    return ",".join(items)


def _sorted_unique(values: list[str]) -> list[str]:
    output: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text not in output:
            output.append(text)
    return output


def _compact_process_line(process: dict[str, Any]) -> str:
    guid = str(process.get("process_guid", "")).strip()
    name = str(process.get("name", "")).strip() or guid
    labels = _csv([str(value) for value in process.get("labels", [])], limit=8)
    parts = [name]
    if guid:
        parts.append(f"id={guid}")
    if labels:
        parts.append(f"labels={labels}")
    return " | ".join(parts)


def _compact_bridge_line(edge: dict[str, Any]) -> str:
    src = str(edge.get("src", "")).strip()
    dst = str(edge.get("dst", "")).strip()
    object_key = _truncate_text(str(edge.get("object_key", "")).strip(), 96)
    object_labels = _csv([str(value) for value in edge.get("object_labels", [])], limit=6)
    write_event_id = str(edge.get("write_event_id", "")).strip()
    read_event_id = str(edge.get("read_or_exec_event_id", "")).strip()
    reason = _truncate_text(str(edge.get("reason", "")).strip(), 72)
    parts = [f"{src}->{dst}"]
    if object_key:
        parts.append(f"via={object_key}")
    if object_labels:
        parts.append(f"labels={object_labels}")
    if write_event_id or read_event_id:
        parts.append(f"ev={write_event_id}/{read_event_id}".strip("/"))
    if reason:
        parts.append(f"why={reason}")
    return " | ".join(parts)


def _compact_timeline_line(item: dict[str, Any]) -> str:
    timestamp = str(item.get("timestamp", "")).strip()
    event_id = str(item.get("event_id", "")).strip()
    event_type = str(item.get("event_type", "")).strip().upper()
    object_class = str(item.get("object_class", "")).strip()
    object_key = _truncate_text(str(item.get("object_key", "")).strip(), 92)
    labels = _csv([str(value) for value in item.get("labels_triggered", [])], limit=8)
    description = _truncate_text(str(item.get("description", "")).strip(), 128)
    parts = []
    if timestamp:
        parts.append(timestamp)
    if event_id:
        parts.append(f"id={event_id}")
    if event_type:
        parts.append(event_type)
    if object_class:
        parts.append(f"obj={object_class}")
    if object_key:
        parts.append(object_key)
    if labels:
        parts.append(f"labels={labels}")
    if description:
        parts.append(f"desc={description}")
    return " | ".join(parts)


def _render_compact_path_dossier(dossier: dict[str, Any]) -> str:
    lines = [
        "PATH",
        (
            f"id={dossier.get('path_id', '')} task={dossier.get('task_id', '')} "
            f"type={dossier.get('path_type', '')} risk={dossier.get('risk_level', '')}:{float(dossier.get('risk_score', 0.0) or 0.0):.2f} "
            f"stages={_csv([str(value) for value in dossier.get('stage_coverage', [])], limit=8)}"
        ).strip(),
    ]
    summary = _truncate_text(str(dossier.get("summary", "")).strip(), 180)
    if summary:
        lines.append(f"summary={summary}")
    support_lines: list[str] = []
    chain_kind = str(dossier.get("chain_kind", "")).strip()
    if chain_kind:
        support_lines.append(f"- chain_kind={chain_kind}")
    family_tags = [
        str(value).strip()
        for value in dossier.get("family_tags", []) or []
        if str(value).strip()
    ]
    if family_tags:
        support_lines.append(f"- family_tags={_csv(family_tags, limit=8)}")
    context_ids = [
        str(value).strip()
        for value in dossier.get("context_ids", []) or []
        if str(value).strip()
    ]
    if context_ids:
        support_lines.append(f"- contexts={_csv(context_ids, limit=6)}")
    support_object_keys = [
        _truncate_text(str(value).strip(), 80)
        for value in dossier.get("support_object_keys", []) or []
        if str(value).strip()
    ]
    if support_object_keys:
        support_lines.append(f"- support_objects={_csv(support_object_keys, limit=8)}")
    support_relations = [
        _truncate_text(str(value).strip(), 120)
        for value in dossier.get("support_relations", []) or []
        if str(value).strip()
    ]
    if support_relations:
        support_lines.append("- support_relations")
        for relation in support_relations[:8]:
            support_lines.append(f"  - {relation}")
    support_event_ids = [
        str(value).strip()
        for value in dossier.get("support_event_ids", []) or []
        if str(value).strip()
    ]
    if support_event_ids:
        support_lines.append(f"- support_events={_csv(support_event_ids, limit=10)}")
    if support_lines:
        lines.append("SUPPORT")
        lines.extend(support_lines)
    precursor_event_ids = [
        str(value).strip()
        for value in dossier.get("precursor_event_ids", []) or []
        if str(value).strip()
    ]
    if precursor_event_ids:
        lines.append("PRECURSOR")
        lines.append(f"- events={_csv(precursor_event_ids, limit=10)}")
    followup_event_ids = [
        str(value).strip()
        for value in dossier.get("followup_event_ids", []) or []
        if str(value).strip()
    ]
    if followup_event_ids:
        lines.append("FOLLOWUP")
        lines.append(f"- events={_csv(followup_event_ids, limit=10)}")
    network_support_summary = _truncate_text(str(dossier.get("network_support_summary", "")).strip(), 180)
    if network_support_summary:
        lines.append("NETWORK_SUPPORT")
        lines.append(f"- {network_support_summary}")
    object_lineage_summary = _truncate_text(str(dossier.get("object_lineage_summary", "")).strip(), 180)
    if object_lineage_summary:
        lines.append("OBJECT_LINEAGE")
        lines.append(f"- {object_lineage_summary}")
    lines.append("PROCESSES")
    processes = dossier.get("core_processes", []) or []
    if processes:
        for process in processes:
            if isinstance(process, dict):
                lines.append(f"- {_compact_process_line(process)}")
    else:
        lines.append("- none")
    lines.append("BRIDGES")
    bridges = dossier.get("bridge_edges", []) or []
    if bridges:
        for edge in bridges:
            if isinstance(edge, dict):
                lines.append(f"- {_compact_bridge_line(edge)}")
    else:
        lines.append("- none")
    lines.append("TIMELINE")
    timeline = dossier.get("evidence_timeline", []) or []
    if timeline:
        for item in timeline:
            if isinstance(item, dict):
                lines.append(f"- {_compact_timeline_line(item)}")
    else:
        lines.append("- none")
    warnings = [str(value).strip() for value in dossier.get("warnings", []) if str(value).strip()]
    if warnings:
        lines.append("WARNINGS")
        for warning in warnings[:8]:
            lines.append(f"- {_truncate_text(warning, 144)}")
    missed_truth_like_hints = [
        str(value).strip()
        for value in dossier.get("missed_truth_like_hints", []) or []
        if str(value).strip()
    ]
    if missed_truth_like_hints:
        lines.append("FAMILY_GAPS")
        for hint in missed_truth_like_hints[:8]:
            lines.append(f"- {_truncate_text(hint, 144)}")
    return "\n".join(lines).strip()


def _compact_claim_line(claim: dict[str, Any]) -> str:
    claim_id = str(claim.get("claim_id", "")).strip()
    behavior_type = str(claim.get("behavior_type", "")).strip()
    apt_stage = str(claim.get("apt_stage", "")).strip()
    claim_source = str(claim.get("claim_source", "")).strip()
    confidence = float(claim.get("confidence", 0.0) or 0.0)
    evidence_event_ids = _csv([str(value) for value in claim.get("evidence_event_ids", [])], limit=8)
    prerequisite_ids = _csv([str(value) for value in claim.get("prerequisite_claim_ids", [])], limit=6)
    support_signals = _csv([str(value) for value in claim.get("support_signals", [])], limit=6)
    statement = _truncate_text(str(claim.get("statement", "")).strip(), 180)
    parts = [claim_id, behavior_type, f"conf={confidence:.2f}"]
    if apt_stage:
        parts.append(f"stage={apt_stage}")
    if claim_source:
        parts.append(f"src={claim_source}")
    if evidence_event_ids:
        parts.append(f"ev={evidence_event_ids}")
    if prerequisite_ids:
        parts.append(f"pre={prerequisite_ids}")
    if support_signals:
        parts.append(f"signals={support_signals}")
    if statement:
        parts.append(statement)
    return " | ".join(part for part in parts if part.strip())


def _compact_candidate_line(item: dict[str, Any]) -> str:
    external_id = str(item.get("external_id", "")).strip().upper()
    name = str(item.get("name", "")).strip()
    score = float(item.get("score", 0.0) or 0.0)
    tactic_ids = _csv([str(value) for value in item.get("tactic_ids", [])], limit=5)
    matched_terms = _csv([str(value) for value in item.get("matched_terms", [])], limit=6)
    parts = [external_id or name, name if external_id else "", f"score={score:.2f}"]
    if tactic_ids:
        parts.append(f"tactics={tactic_ids}")
    if matched_terms:
        parts.append(f"terms={matched_terms}")
    return " | ".join(part for part in parts if part.strip())


def _render_compact_mapping_context(context: dict[str, Any]) -> str:
    attack_mapping_scope = str(context.get("attack_mapping_scope", "full")).strip().lower() or "full"
    tactics_only = attack_mapping_scope == "tactics_only"
    lines = [_render_compact_path_dossier(context.get("path_dossier", {}))]
    claim_graph = context.get("claim_graph", {}) or {}
    lines.append("CLAIMS")
    claims = context.get("claims", []) or []
    if claims:
        for claim in claims:
            if isinstance(claim, dict):
                lines.append(f"- {_compact_claim_line(claim)}")
    else:
        lines.append("- none")
    graph_edges = [item for item in claim_graph.get("edges", []) if isinstance(item, dict)]
    if graph_edges:
        lines.append("CAUSAL_RELATIONS")
        for edge in graph_edges[:16]:
            src_claim_id = str(edge.get("src_claim_id", "")).strip()
            dst_claim_id = str(edge.get("dst_claim_id", "")).strip()
            relation = str(edge.get("relation", "")).strip() or "prerequisite"
            if src_claim_id and dst_claim_id:
                lines.append(f"- {src_claim_id} -> {dst_claim_id} [{relation}]")
    diagnostics = claim_graph.get("diagnostics", {}) or {}
    matched_atoms = [str(value).strip() for value in diagnostics.get("matched_atoms", []) if str(value).strip()]
    if matched_atoms:
        lines.append("MATCHED_TTP_ATOMS")
        lines.append(f"- {_csv(matched_atoms, limit=16)}")
    missing_atoms = [str(value).strip() for value in diagnostics.get("missing_expected_atoms", []) if str(value).strip()]
    if missing_atoms:
        lines.append("MISSING_TTP_ATOMS")
        lines.append(f"- {_csv(missing_atoms, limit=12)}")
    raw_hints = context.get("claim_attack_hints", {}) or {}
    hint_rows: list[dict[str, Any]] = []
    if isinstance(raw_hints, dict):
        for claim_id in sorted(str(key).strip() for key in raw_hints if str(key).strip()):
            hint = raw_hints.get(claim_id, {})
            if not isinstance(hint, dict):
                continue
            hint_rows.append({"claim_id": claim_id, **hint})
    elif isinstance(raw_hints, list):
        for item in raw_hints:
            if isinstance(item, dict):
                hint_rows.append(item)
    if hint_rows:
        lines.append("CLAIM_HINTS")
        def _hint_sort_key(item: dict[str, Any]) -> tuple[str, str]:
            claim_id = str(item.get("claim_id", "")).strip()
            behavior = str(item.get("behavior_type", "")).strip()
            return (claim_id, behavior)

        for hint in sorted(hint_rows, key=_hint_sort_key):
            claim_id = str(hint.get("claim_id", "")).strip()
            tactic_id = str(hint.get("tactic_id", "")).strip().upper()
            technique_id = str(hint.get("technique_id", "")).strip().upper()
            behavior = str(hint.get("behavior_type", "")).strip()
            preferred_tactic_id = str(hint.get("preferred_tactic_id", "")).strip().upper()
            preferred_technique_id = str(hint.get("preferred_technique_id", "")).strip().upper()
            allowed_tactic_ids = _csv(
                [str(value).strip().upper() for value in hint.get("allowed_tactic_ids", []) if str(value).strip()],
                limit=8,
            )
            parts = [claim_id]
            if behavior:
                parts.append(f"behavior={behavior}")
            if tactic_id:
                parts.append(f"tactic={tactic_id}")
            if technique_id:
                parts.append(f"technique={technique_id}")
            if preferred_tactic_id:
                parts.append(f"prefer_tactic={preferred_tactic_id}")
            if preferred_technique_id:
                parts.append(f"prefer_technique={preferred_technique_id}")
            if allowed_tactic_ids:
                parts.append(f"allow_tactics={allowed_tactic_ids}")
            lines.append(f"- {' | '.join(parts)}")
    attack_candidates = context.get("attack_candidates", {}) or {}
    lines.append("TACTIC_CANDIDATES")
    tactics = [item for item in attack_candidates.get("tactics", []) if isinstance(item, dict)]
    if tactics:
        for item in tactics[:10]:
            lines.append(f"- {_compact_candidate_line(item)}")
    else:
        lines.append("- none")
    if not tactics_only:
        lines.append("TECHNIQUE_CANDIDATES")
        techniques = [item for item in attack_candidates.get("techniques", []) if isinstance(item, dict)]
        if techniques:
            for item in techniques[:14]:
                lines.append(f"- {_compact_candidate_line(item)}")
        else:
            lines.append("- none")
    return "\n".join(line for line in lines if line.strip()).strip()


def _user_prompt_extract(dossier: dict[str, Any]) -> str:
    claim_graph = build_holmes_claim_graph(dossier)
    candidate_claim_lines = []
    for claim in claim_graph.get("claims", []) or []:
        if isinstance(claim, dict):
            candidate_claim_lines.append(f"- {_compact_claim_line(claim)}")
    if not candidate_claim_lines:
        candidate_claim_lines.append("- none")
    return (
        "Analyze the reasoning unit below and return JSON matching the shape exactly.\n\n"
        f"JSON shape:\n{_schema_json(_extract_schema())}\n\n"
        "Rules:\n"
        "- Use only evidence from the dossier.\n"
        "- Focus on the attack-relevant semantics of the reasoning unit rather than unrelated host context.\n"
        "- The claim list must only confirm, refine, or omit the pre-matched Holmes-style TTP atoms shown below.\n"
        "- Do not invent new claim IDs or new behavior_type values.\n"
        "- Preserve the provided evidence_event_ids unless the dossier clearly shows they are unsupported.\n"
        "- Prefer concise factual statements that explain why the TTP atom matched.\n"
        "- Use bridge edges, support relations, and labeled network/file events before generic chronology.\n"
        "- Do not write generic claims such as 'a series of system calls may indicate a threat'.\n"
        "- If no candidate atom is supported, return an empty claims list and explain the gap.\n"
        "- Confidence must be between 0 and 1.\n\n"
        f"Reasoning unit:\n{_render_compact_path_dossier(dossier)}\n\n"
        f"PREMATCHED_TTP_ATOMS:\n{chr(10).join(candidate_claim_lines)}"
    )


def _user_prompt_map(
    context: dict[str, Any],
    *,
    include_claim_attack_hints: bool = True,
) -> str:
    attack_mapping_scope = str(context.get("attack_mapping_scope", "full")).strip().lower() or "full"
    tactics_only = attack_mapping_scope == "tactics_only"
    rules = [
        "- Use only the provided claims, timeline, and ATT&CK candidates.",
        "- Treat the claims as pre-matched Holmes-style TTP atoms and preserve their causal ordering.",
        "- Map each claim independently and do not reuse a technique from one behavior type for an unrelated claim.",
        "- Choose only from the provided ATT&CK candidate IDs and names.",
        "- Choose the best-supported tactic first.",
        "- Prefer ATT&CK IDs from the candidate list when possible.",
    ]
    if tactics_only:
        rules.append("- This run is tactic-only: leave technique_id and technique empty for every mapping.")
    else:
        rules.append("- Then choose the best-supported technique.")
        rules.append("- If tactic support exists but technique support is weak, leave technique empty.")
    if include_claim_attack_hints:
        rules.append("- Treat claim_attack_hints as soft priors that reflect behavior semantics, not as proof by themselves.")
    rules.extend(
        [
            "- Do not map a generic execution-chain claim to injection, COM, hollowing, or hijacking unless the claim explicitly supports those semantics.",
            "- Prefer Discovery for network_service_discovery and sensitive_command claims unless stronger evidence indicates another tactic.",
            "- Prefer Defense Evasion for clear_logs, sensitive_temp_rm, and untrusted_file_rm claims.",
            "- Prefer Initial Access plus Execution for attachment_user_exec when the claim reflects opening or executing a staged attachment-like object.",
            "- For credential reads with no stronger evidence, tactic-only Credential Access is safer than a wrong technique.",
            "- Confidence must be between 0 and 1.",
        ]
    )
    return (
        "Map the validated claims below to MITRE ATT&CK and return JSON matching the shape exactly.\n\n"
        f"JSON shape:\n{_schema_json(_mapping_schema())}\n\n"
        f"Rules:\n{chr(10).join(rules)}\n\n"
        f"Context:\n{_render_compact_mapping_context(context)}"
    )


def _normalize_attack_name(value: str) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _dossier_event_ids(dossier: dict[str, Any]) -> set[str]:
    event_ids = {
        str(item.get("event_id", "")).strip()
        for item in dossier.get("evidence_timeline", []) or []
        if isinstance(item, dict) and str(item.get("event_id", "")).strip()
    }
    for edge in dossier.get("bridge_edges", []) or []:
        if not isinstance(edge, dict):
            continue
        for key in ("write_event_id", "read_or_exec_event_id"):
            value = str(edge.get(key, "")).strip()
            if value:
                event_ids.add(value)
    return event_ids


def _dossier_timeline_by_event_id(dossier: dict[str, Any]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for item in dossier.get("evidence_timeline", []) or []:
        if not isinstance(item, dict):
            continue
        event_id = str(item.get("event_id", "")).strip()
        if event_id:
            output[event_id] = item
    return output


def _claim_timeline_items(dossier: dict[str, Any], claim: dict[str, Any]) -> list[dict[str, Any]]:
    timeline_by_id = _dossier_timeline_by_event_id(dossier)
    output: list[dict[str, Any]] = []
    for event_id in claim.get("evidence_event_ids", []) or []:
        normalized_id = str(event_id).strip()
        if normalized_id and normalized_id in timeline_by_id:
            output.append(timeline_by_id[normalized_id])
    return output


def _dossier_family_tags(dossier: dict[str, Any]) -> set[str]:
    return {
        str(value).strip()
        for value in dossier.get("family_tags", []) or []
        if str(value).strip()
    }


def _dossier_core_process_labels(dossier: dict[str, Any]) -> set[str]:
    labels: set[str] = set()
    for process in dossier.get("core_processes", []) or []:
        if not isinstance(process, dict):
            continue
        for value in process.get("labels", []) or []:
            text = str(value).strip()
            if text:
                labels.add(text)
    return labels


def _timeline_position_by_event_id(dossier: dict[str, Any]) -> dict[str, int]:
    positions: dict[str, int] = {}
    for index, item in enumerate(dossier.get("evidence_timeline", []) or []):
        if not isinstance(item, dict):
            continue
        event_id = str(item.get("event_id", "")).strip()
        if event_id and event_id not in positions:
            positions[event_id] = index
    return positions


def _dossier_has_ordered_signal_flow(dossier: dict[str, Any], earlier_ids: list[str], later_ids: list[str]) -> bool:
    positions = _timeline_position_by_event_id(dossier)
    earlier_positions = [positions[event_id] for event_id in earlier_ids if event_id in positions]
    later_positions = [positions[event_id] for event_id in later_ids if event_id in positions]
    return bool(earlier_positions and later_positions and any(src < dst for src in earlier_positions for dst in later_positions))


def _dossier_has_strong_exec_context(dossier: dict[str, Any], labels: set[str]) -> bool:
    family_tags = _dossier_family_tags(dossier)
    core_labels = _dossier_core_process_labels(dossier)
    if labels.intersection(_STRONG_EXEC_LABELS):
        return True
    if core_labels.intersection(_STRONG_EXEC_LABELS):
        return True
    return bool(family_tags.intersection(_STRONG_EXEC_FAMILY_TAGS))


def _remote_ports_from_items(items: list[dict[str, Any]]) -> list[str]:
    ports: list[str] = []
    for item in items:
        object_key = str(item.get("object_key", "")).strip()
        match = _FLOW_OBJECT_KEY_PATTERN.search(object_key)
        if match is None:
            continue
        port = str(match.group("dst_port")).strip()
        if port:
            ports.append(port)
    return ports


def _dynamic_behavior_prior_for_claim(dossier: dict[str, Any], claim: dict[str, Any]) -> dict[str, str] | None:
    behavior = str(claim.get("behavior_type", "")).strip().lower()
    if not behavior:
        return None
    prior = dict(_PATH_BEHAVIOR_ALIGNMENT_PRIORS.get(behavior, {}))
    if not prior:
        return None
    if behavior == "remote_send":
        items = _claim_timeline_items(dossier, claim)
        ports = _remote_ports_from_items(items)
        if len(items) >= 3 and sum(1 for port in ports if port in _WEB_C2_PORTS) >= 2:
            prior["tactic_id"] = "TA0011"
            prior["technique_id"] = "T1071.001"
    return prior


def _claim_has_required_signal(claim: dict[str, Any], dossier: dict[str, Any]) -> bool:
    behavior = str(claim.get("behavior_type", "")).strip().lower()
    if behavior and behavior not in HOLMES_TTP_CATALOG:
        return False
    evidence_ids = [str(value).strip() for value in claim.get("evidence_event_ids", []) if str(value).strip()]
    if not evidence_ids:
        return False
    timeline_by_id = _dossier_timeline_by_event_id(dossier)
    events = [timeline_by_id[event_id] for event_id in evidence_ids if event_id in timeline_by_id]
    labels = {
        str(label).strip()
        for event in events
        for label in event.get("labels_triggered", []) or []
        if str(label).strip()
    }
    object_classes = {
        str(event.get("object_class", "")).strip().lower()
        for event in events
        if str(event.get("object_class", "")).strip()
    }
    event_types = {
        str(event.get("event_type", "")).strip().upper()
        for event in events
        if str(event.get("event_type", "")).strip()
    }
    bridge_ids = set(_bridge_event_ids_for_exec(dossier))
    strong_exec_context = _dossier_has_strong_exec_context(dossier, labels)
    statement_blob = " ".join(
        [
            str(claim.get("statement", "")).strip().lower(),
            " ".join(str(event.get("description", "")).strip().lower() for event in events),
            " ".join(str(event.get("object_key", "")).strip().lower() for event in events),
        ]
    )
    if behavior == "untrusted_read":
        return "B_EXTERNAL_RECV" in labels or (
            "external_ip" in object_classes and any(event_type in {"RECV", "CONNECT"} for event_type in event_types)
        )
    if behavior == "make_mem_exec":
        return any(term in statement_blob for term in ("mprotect", "mem exec", "virtualalloc"))
    if behavior == "make_file_exec":
        return any(term in statement_blob for term in ("chmod", "executable", "staged object")) or any(
            event_type in {"CHMOD", "MODIFY_FILE_ATTRIBUTES"} for event_type in event_types
        )
    if behavior in {"untrusted_file_exec", "attachment_user_exec"}:
        return bool(labels.intersection({"B_EXEC_SUSPECT_WRITTEN", "B_EXEC_DOWNLOADED", "B_EXEC_UPLOADED", "B_EXEC_TEMP"})) or any(event_id in bridge_ids for event_id in evidence_ids)
    if behavior in {"shell_exec", "interpreter_precursor_chain"}:
        return any(term in statement_blob for term in ("bash", "shell", "python", "perl", "php", "tcexec", "command-not-found"))
    if behavior == "cnc_communication":
        return strong_exec_context and (("B_EXTERNAL_SEND" in labels or "B_EXTERNAL_RECV" in labels) or (
            "external_ip" in object_classes and any(event_type in {"SEND", "CONNECT", "RECV"} for event_type in event_types)
        ))
    if behavior == "sudo_exec":
        return "sudo" in statement_blob
    if behavior == "switch_su":
        return any(term in statement_blob for term in ("setuid", " su ", "switch user"))
    if behavior == "sensitive_read":
        return strong_exec_context and bool(labels.intersection({"B_READ_CRED", "B_READ_HISTORY", "B_READ_BUSINESS", "B_MASS_FILE_ACCESS"}))
    if behavior == "sensitive_command":
        return any(
            term in statement_blob for term in ("whoami", "hostname", "netstat", "ifconfig", "uname", "system information", "enumeration")
        )
    if behavior == "network_service_discovery":
        return "B_LATERAL_CONNECT" in labels or any(term in statement_blob for term in ("scan", "discovery", "connect burst", "service discovery"))
    if behavior == "send_internal":
        return "internal_ip" in object_classes or "B_LATERAL_CONNECT" in labels
    if behavior == "sensitive_leak":
        return strong_exec_context and ("B_EXTERNAL_SEND" in labels or "external_ip" in object_classes) and bool(
            labels.intersection({"B_READ_CRED", "B_READ_HISTORY", "B_READ_BUSINESS", "B_MASS_FILE_ACCESS"})
        ) and _dossier_has_ordered_signal_flow(
            dossier,
            [
                str(value).strip()
                for value in claim.get("evidence_event_ids", [])
                if str(value).strip() and str(value).strip() not in {str(event.get("event_id", "")).strip() for event in events if "B_EXTERNAL_SEND" in {str(label).strip() for label in event.get("labels_triggered", []) or [] if str(label).strip()}}
            ],
            [
                str(event.get("event_id", "")).strip()
                for event in events
                if "B_EXTERNAL_SEND" in {str(label).strip() for label in event.get("labels_triggered", []) or [] if str(label).strip()}
            ],
        )
    if behavior in {"clear_logs", "sensitive_temp_rm", "untrusted_file_rm"}:
        return "B_DELETE_LOG" in labels or any(event_type in {"DELETE", "UNLINK", "RENAME"} for event_type in event_types)
    return bool(evidence_ids)


def _claim_is_generic(claim: dict[str, Any]) -> bool:
    statement = str(claim.get("statement", "")).strip().lower()
    return any(marker in statement for marker in _GENERIC_CLAIM_MARKERS)


def _validate_claims(raw_claims: list[dict[str, Any]], dossier: dict[str, Any]) -> list[dict[str, Any]]:
    valid_event_ids = _dossier_event_ids(dossier)
    cleaned: list[dict[str, Any]] = []
    for item in raw_claims:
        if not isinstance(item, dict):
            continue
        claim_id = str(item.get("claim_id", "")).strip()
        statement = str(item.get("statement", "")).strip()
        if not claim_id or not statement:
            continue
        evidence_event_ids = [
            str(value).strip()
            for value in item.get("evidence_event_ids", [])
            if str(value).strip() and str(value).strip() in valid_event_ids
        ]
        if not evidence_event_ids:
            continue
        claim = {
            "claim_id": claim_id,
            "behavior_type": str(item.get("behavior_type", "other")).strip() or "other",
            "statement": statement,
            "evidence_event_ids": evidence_event_ids,
            "confidence": _clip_confidence(item.get("confidence")),
            "apt_stage": str(item.get("apt_stage", "")).strip(),
            "prerequisite_claim_ids": [
                str(value).strip()
                for value in item.get("prerequisite_claim_ids", [])
                if str(value).strip()
            ],
            "claim_source": str(item.get("claim_source", "llm_confirmation")).strip() or "llm_confirmation",
            "support_signals": [
                str(value).strip()
                for value in item.get("support_signals", [])
                if str(value).strip()
            ],
        }
        if _claim_is_generic(claim):
            continue
        if not _claim_has_required_signal(claim, dossier):
            continue
        cleaned.append(claim)
    return cleaned


def _validate_iocs(raw_iocs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cleaned: list[dict[str, Any]] = []
    for item in raw_iocs:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value", "")).strip()
        if not value:
            continue
        cleaned.append(
            {
                "type": str(item.get("type", "other")).strip() or "other",
                "value": value,
                "evidence_event_ids": [str(value).strip() for value in item.get("evidence_event_ids", []) if str(value).strip()],
                "confidence": _clip_confidence(item.get("confidence")),
            }
        )
    return cleaned


def _timeline_items_for_label(dossier: dict[str, Any], target_labels: set[str]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for item in dossier.get("evidence_timeline", []) or []:
        if not isinstance(item, dict):
            continue
        labels = {str(value).strip() for value in item.get("labels_triggered", []) or [] if str(value).strip()}
        if labels.intersection(target_labels):
            output.append(item)
    return output


def _event_ids_from_items(items: list[dict[str, Any]], limit: int = 6) -> list[str]:
    output: list[str] = []
    for item in items:
        event_id = str(item.get("event_id", "")).strip()
        if event_id and event_id not in output:
            output.append(event_id)
        if len(output) >= limit:
            break
    return output


def _unique_event_ids(values: list[str]) -> list[str]:
    output: list[str] = []
    for value in values:
        event_id = str(value).strip()
        if event_id and event_id not in output:
            output.append(event_id)
    return output


def _core_label_set(dossier: dict[str, Any]) -> set[str]:
    labels: set[str] = set()
    for item in dossier.get("core_processes", []) or []:
        if not isinstance(item, dict):
            continue
        for label in item.get("labels", []) or []:
            text = str(label).strip()
            if text:
                labels.add(text)
    return labels


def _bridge_event_ids_for_exec(dossier: dict[str, Any]) -> list[str]:
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
    return output[:6]


def _fallback_claims(dossier: dict[str, Any], claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    claim_graph = build_holmes_claim_graph(dossier)
    return _merge_claims(claims, [dict(item) for item in claim_graph.get("claims", []) if isinstance(item, dict)])


def _merge_claims(primary: list[dict[str, Any]], fallback: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = [dict(item) for item in fallback if isinstance(item, dict)]
    by_claim_id = {
        str(item.get("claim_id", "")).strip(): index
        for index, item in enumerate(merged)
        if str(item.get("claim_id", "")).strip()
    }
    by_behavior = {
        str(item.get("behavior_type", "other")).strip().lower(): index
        for index, item in enumerate(merged)
        if str(item.get("behavior_type", "")).strip()
    }
    for claim in primary:
        if not isinstance(claim, dict):
            continue
        claim_id = str(claim.get("claim_id", "")).strip()
        behavior = str(claim.get("behavior_type", "other")).strip().lower()
        existing_idx = by_claim_id.get(claim_id)
        if existing_idx is None:
            existing_idx = by_behavior.get(behavior)
        if existing_idx is None:
            patched = dict(claim)
            if not patched.get("claim_source"):
                patched["claim_source"] = "llm_confirmation"
            merged.append(patched)
            continue
        existing = dict(merged[existing_idx])
        existing["statement"] = str(claim.get("statement", "")).strip() or existing.get("statement", "")
        existing["confidence"] = max(
            float(existing.get("confidence", 0.0) or 0.0),
            float(claim.get("confidence", 0.0) or 0.0),
        )
        llm_ids = [str(value).strip() for value in claim.get("evidence_event_ids", []) if str(value).strip()]
        if llm_ids:
            existing["evidence_event_ids"] = _unique_event_ids(llm_ids + list(existing.get("evidence_event_ids", [])))[:8]
        existing["claim_source"] = "holmes_rule+llm_confirmation"
        merged[existing_idx] = existing
    return merged


def _candidate_dict_from_kb(item: Any, score: float, matched_term: str) -> dict[str, Any]:
    return {
        "candidate_id": str(getattr(item, "candidate_id", "")).strip(),
        "external_id": str(getattr(item, "external_id", "")).strip().upper(),
        "name": str(getattr(item, "name", "")).strip(),
        "description": str(getattr(item, "description", "")).strip(),
        "attack_url": str(getattr(item, "attack_url", "")).strip(),
        "tactics": list(getattr(item, "tactics", ()) or ()),
        "tactic_ids": list(getattr(item, "tactic_ids", ()) or ()),
        "score": float(score),
        "matched_terms": [matched_term],
        "object_type": str(getattr(item, "object_type", "")).strip(),
    }


def _behavior_prior_hints_for_claims(
    cfg: FusionConfig,
    dossier: dict[str, Any],
    claims: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    kb = load_attack_kb(cfg)
    tactic_kb = {
        str(item.external_id).strip().upper(): item
        for item in kb.get("tactics", [])
        if str(item.external_id).strip()
    }
    technique_kb = {
        str(item.external_id).strip().upper(): item
        for item in kb.get("techniques", [])
        if str(item.external_id).strip()
    }
    output: list[dict[str, Any]] = []
    for claim in claims:
        claim_id = str(claim.get("claim_id", "")).strip()
        behavior = str(claim.get("behavior_type", "")).strip().lower()
        if not claim_id or not behavior:
            continue
        prior = _dynamic_behavior_prior_for_claim(dossier, claim) or {}
        allow_tactic_ids = sorted(_BEHAVIOR_TACTIC_ALLOWLIST.get(behavior, set()))
        preferred_tactic_id = str(prior.get("tactic_id", "")).strip().upper()
        preferred_technique_id = str(prior.get("technique_id", "")).strip().upper().replace("/", ".")
        output.append(
            {
                "claim_id": claim_id,
                "behavior_type": behavior,
                "allowed_tactic_ids": allow_tactic_ids,
                "allowed_tactic_names": [
                    str(tactic_kb[tactic_id].name).strip() if tactic_id in tactic_kb else _TACTIC_NAME_BY_ID.get(tactic_id, "")
                    for tactic_id in allow_tactic_ids
                ],
                "preferred_tactic_id": preferred_tactic_id,
                "preferred_tactic_name": (
                    str(tactic_kb[preferred_tactic_id].name).strip()
                    if preferred_tactic_id in tactic_kb
                    else _TACTIC_NAME_BY_ID.get(preferred_tactic_id, "")
                ),
                "preferred_technique_id": preferred_technique_id,
                "preferred_technique_name": (
                    str(technique_kb[preferred_technique_id].name).strip()
                    if preferred_technique_id in technique_kb
                    else _TECHNIQUE_NAME_BY_ID.get(preferred_technique_id, "")
                ),
            }
        )
    return output


def _augment_attack_candidates_with_behavior_priors(
    cfg: FusionConfig,
    dossier: dict[str, Any],
    attack_candidates: dict[str, Any],
    claims: list[dict[str, Any]],
) -> dict[str, Any]:
    if not _claim_attack_priors_enabled(cfg):
        return attack_candidates
    tactics = [item for item in attack_candidates.get("tactics", []) if isinstance(item, dict)]
    techniques = [item for item in attack_candidates.get("techniques", []) if isinstance(item, dict)]
    tactic_ids = {str(item.get("external_id", "")).strip().upper() for item in tactics if str(item.get("external_id", "")).strip()}
    technique_ids = {
        str(item.get("external_id", "")).strip().upper().replace("/", ".")
        for item in techniques
        if str(item.get("external_id", "")).strip()
    }
    kb = load_attack_kb(cfg)
    tactic_kb = {
        str(item.external_id).strip().upper(): item
        for item in kb.get("tactics", [])
        if str(item.external_id).strip()
    }
    technique_kb = {
        str(item.external_id).strip().upper(): item
        for item in kb.get("techniques", [])
        if str(item.external_id).strip()
    }
    injected_tactics: list[dict[str, Any]] = []
    injected_techniques: list[dict[str, Any]] = []
    seen_injected_tactics: set[str] = set()
    seen_injected_techniques: set[str] = set()

    for claim in claims:
        behavior = str(claim.get("behavior_type", "")).strip().lower()
        if not behavior:
            continue
        for tactic_id in sorted(_BEHAVIOR_TACTIC_ALLOWLIST.get(behavior, set())):
            normalized_id = tactic_id.strip().upper()
            if not normalized_id or normalized_id in tactic_ids or normalized_id in seen_injected_tactics:
                continue
            item = tactic_kb.get(normalized_id)
            if item is None:
                continue
            injected_tactics.append(_candidate_dict_from_kb(item, score=0.98, matched_term="behavior_allowlist"))
            seen_injected_tactics.add(normalized_id)

        prior = _dynamic_behavior_prior_for_claim(dossier, claim) or {}
        technique_id = str(prior.get("technique_id", "")).strip().upper().replace("/", ".")
        if technique_id and technique_id not in technique_ids and technique_id not in seen_injected_techniques:
            item = technique_kb.get(technique_id)
            if item is None:
                continue
            injected_techniques.append(_candidate_dict_from_kb(item, score=1.02, matched_term="behavior_prior"))
            seen_injected_techniques.add(technique_id)

    return {
        **attack_candidates,
        "tactics": injected_tactics + tactics,
        "techniques": injected_techniques + techniques,
    }


def _filter_attack_candidates_for_scope(cfg: FusionConfig, attack_candidates: dict[str, Any]) -> dict[str, Any]:
    if not _tactics_only_enabled(cfg):
        return attack_candidates
    return {
        **attack_candidates,
        "techniques": [],
    }


def _deterministic_tactic_mappings(
    cfg: FusionConfig,
    claims: list[dict[str, Any]],
    attack_candidates: dict[str, Any],
) -> list[dict[str, Any]]:
    tactic_by_id = {
        str(item.get("external_id", "")).strip().upper(): item
        for item in attack_candidates.get("tactics", []) or []
        if isinstance(item, dict) and str(item.get("external_id", "")).strip()
    }
    mappings: list[dict[str, Any]] = []
    for claim in claims:
        claim_id = str(claim.get("claim_id", "")).strip()
        behavior = str(claim.get("behavior_type", "")).strip().lower()
        if not claim_id or not behavior:
            continue
        tactic_ids = list(HOLMES_TTP_CATALOG.get(behavior, {}).get("tactic_ids", ()) or ())
        if not tactic_ids:
            preferred_tactic_id = str(_PATH_BEHAVIOR_ALIGNMENT_PRIORS.get(behavior, {}).get("tactic_id", "")).strip().upper()
            if preferred_tactic_id:
                tactic_ids = [preferred_tactic_id]
        for tactic_id in _sorted_unique([str(value).strip().upper() for value in tactic_ids if str(value).strip()]):
            tactic_choice = tactic_by_id.get(tactic_id, {"external_id": tactic_id, "name": _TACTIC_NAME_BY_ID.get(tactic_id, "")})
            mappings.append(
                {
                    "tactic_id": str(tactic_choice.get("external_id", "")).strip().upper(),
                    "tactic": str(tactic_choice.get("name", "")).strip() or _TACTIC_NAME_BY_ID.get(tactic_id, ""),
                    "technique_id": "",
                    "technique": "",
                    "evidence_claim_ids": [claim_id],
                    "confidence": max(0.72, _clip_confidence(claim.get("confidence"))),
                    "gaps": [],
                }
            )
    dedup: dict[tuple[str, tuple[str, ...]], dict[str, Any]] = {}
    for item in mappings:
        key = (
            str(item.get("tactic_id", "")).strip().upper(),
            tuple(sorted(str(value).strip() for value in item.get("evidence_claim_ids", []) if str(value).strip())),
        )
        if key not in dedup or float(item.get("confidence", 0.0) or 0.0) > float(dedup[key].get("confidence", 0.0) or 0.0):
            dedup[key] = item
    return list(dedup.values())


def _empty_mapping_validation_summary() -> dict[str, Any]:
    return {
        "raw_mapping_count": 0,
        "kept_mapping_count": 0,
        "raw_evidence_id_count": 0,
        "raw_claim_id_ref_count": 0,
        "raw_event_id_ref_count": 0,
        "raw_unknown_id_ref_count": 0,
        "mappings_with_claim_id_refs_count": 0,
        "mappings_with_event_id_refs_count": 0,
        "mappings_with_unknown_id_refs_count": 0,
        "normalized_event_id_claim_ref_count": 0,
        "mappings_normalized_to_empty_count": 0,
        "mappings_dropped_after_claim_support_filter_count": 0,
    }


def _normalize_mapping_evidence_claim_ids(
    raw_values: Any,
    *,
    claim_ids: set[str],
    event_id_to_claim_ids: dict[str, list[str]],
) -> tuple[list[str], dict[str, Any]]:
    normalized: list[str] = []
    seen: set[str] = set()
    detail = {
        "raw_value_count": 0,
        "raw_claim_id_ref_count": 0,
        "raw_event_id_ref_count": 0,
        "raw_unknown_id_ref_count": 0,
        "normalized_event_id_claim_ref_count": 0,
    }
    for value in raw_values or []:
        text = str(value).strip()
        if not text:
            continue
        detail["raw_value_count"] += 1
        if text in claim_ids:
            detail["raw_claim_id_ref_count"] += 1
            if text not in seen:
                normalized.append(text)
                seen.add(text)
            continue
        mapped_claim_ids = event_id_to_claim_ids.get(text, [])
        if mapped_claim_ids:
            detail["raw_event_id_ref_count"] += 1
            for claim_id in mapped_claim_ids:
                if claim_id not in seen:
                    normalized.append(claim_id)
                    seen.add(claim_id)
                    detail["normalized_event_id_claim_ref_count"] += 1
            continue
        detail["raw_unknown_id_ref_count"] += 1
    return normalized, detail


def _claim_supports_mapping(
    dossier: dict[str, Any],
    claim: dict[str, Any],
    tactic_choice: dict[str, Any] | None,
    technique_choice: dict[str, Any] | None,
    *,
    enforce_behavior_priors: bool = True,
) -> bool:
    behavior = str(claim.get("behavior_type", "")).strip().lower()
    if not enforce_behavior_priors or not behavior or behavior == "other":
        return True
    allow_tactics = _BEHAVIOR_TACTIC_ALLOWLIST.get(behavior, set())
    tactic_id = str((tactic_choice or {}).get("external_id", "")).strip().upper()
    technique_tactic_ids = {
        str(value).strip().upper()
        for value in (technique_choice or {}).get("tactic_ids", []) or []
        if str(value).strip()
    }
    if allow_tactics:
        if tactic_id and tactic_id not in allow_tactics:
            return False
        if not tactic_id and technique_tactic_ids and not technique_tactic_ids.intersection(allow_tactics):
            return False
    prior = _dynamic_behavior_prior_for_claim(dossier, claim) or {}
    prior_technique_id = str(prior.get("technique_id", "")).strip().upper().replace("/", ".")
    technique_id = str((technique_choice or {}).get("external_id", "")).strip().upper().replace("/", ".")
    if prior_technique_id and technique_id and technique_id != prior_technique_id:
        return False
    return True


def _validate_mappings(
    cfg: FusionConfig,
    dossier: dict[str, Any],
    raw_mappings: list[dict[str, Any]],
    attack_candidates: dict[str, Any],
    claims: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    tactics_only = _tactics_only_enabled(cfg)
    claim_by_id = {
        str(item.get("claim_id", "")).strip(): item
        for item in claims
        if isinstance(item, dict) and str(item.get("claim_id", "")).strip()
    }
    claim_ids = {
        str(item.get("claim_id", "")).strip()
        for item in claims
        if isinstance(item, dict) and str(item.get("claim_id", "")).strip()
    }
    event_id_to_claim_ids: dict[str, list[str]] = {}
    for item in claims:
        if not isinstance(item, dict):
            continue
        claim_id = str(item.get("claim_id", "")).strip()
        if not claim_id:
            continue
        for value in item.get("evidence_event_ids", []) or []:
            event_id = str(value).strip()
            if not event_id:
                continue
            refs = event_id_to_claim_ids.setdefault(event_id, [])
            if claim_id not in refs:
                refs.append(claim_id)
    candidate_tactics = [
        item for item in attack_candidates.get("tactics", []) if isinstance(item, dict)
    ]
    candidate_techniques = [
        item for item in attack_candidates.get("techniques", []) if isinstance(item, dict)
    ]
    tactic_by_id = {
        str(item.get("external_id", "")).strip().upper(): item
        for item in candidate_tactics
        if str(item.get("external_id", "")).strip()
    }
    tactic_by_name = {
        _normalize_attack_name(str(item.get("name", ""))): item
        for item in candidate_tactics
        if str(item.get("name", "")).strip()
    }
    technique_by_id = {
        str(item.get("external_id", "")).strip().upper().replace("/", "."): item
        for item in candidate_techniques
        if str(item.get("external_id", "")).strip()
    }
    technique_by_name = {
        _normalize_attack_name(str(item.get("name", ""))): item
        for item in candidate_techniques
        if str(item.get("name", "")).strip()
    }
    cleaned: list[dict[str, Any]] = []
    validation_summary = _empty_mapping_validation_summary()
    enforce_behavior_priors = _claim_attack_priors_enabled(cfg)
    for item in raw_mappings:
        if not isinstance(item, dict):
            continue
        validation_summary["raw_mapping_count"] += 1
        evidence_claim_ids, normalization_detail = _normalize_mapping_evidence_claim_ids(
            item.get("evidence_claim_ids", []),
            claim_ids=claim_ids,
            event_id_to_claim_ids=event_id_to_claim_ids,
        )
        validation_summary["raw_evidence_id_count"] += int(normalization_detail["raw_value_count"])
        validation_summary["raw_claim_id_ref_count"] += int(normalization_detail["raw_claim_id_ref_count"])
        validation_summary["raw_event_id_ref_count"] += int(normalization_detail["raw_event_id_ref_count"])
        validation_summary["raw_unknown_id_ref_count"] += int(normalization_detail["raw_unknown_id_ref_count"])
        validation_summary["normalized_event_id_claim_ref_count"] += int(
            normalization_detail["normalized_event_id_claim_ref_count"]
        )
        if int(normalization_detail["raw_claim_id_ref_count"]) > 0:
            validation_summary["mappings_with_claim_id_refs_count"] += 1
        if int(normalization_detail["raw_event_id_ref_count"]) > 0:
            validation_summary["mappings_with_event_id_refs_count"] += 1
        if int(normalization_detail["raw_unknown_id_ref_count"]) > 0:
            validation_summary["mappings_with_unknown_id_refs_count"] += 1
        if not evidence_claim_ids:
            if int(normalization_detail["raw_value_count"]) > 0:
                validation_summary["mappings_normalized_to_empty_count"] += 1
            continue
        tactic_id = str(item.get("tactic_id", "")).strip().upper()
        tactic_name = str(item.get("tactic", "")).strip()
        technique_id = str(item.get("technique_id", "")).strip().upper().replace("/", ".")
        technique_name = str(item.get("technique", "")).strip()
        if not tactic_id and not tactic_name and not technique_id and not technique_name:
            continue

        if tactic_id and not _TACTIC_ID_PATTERN.match(tactic_id):
            tactic_id = ""
        if technique_id and not _TECHNIQUE_ID_PATTERN.match(technique_id):
            technique_id = ""

        tactic_choice = tactic_by_id.get(tactic_id) if tactic_id else None
        if tactic_choice is None and tactic_name:
            tactic_choice = tactic_by_name.get(_normalize_attack_name(tactic_name))
        technique_choice = technique_by_id.get(technique_id) if technique_id else None
        if technique_choice is None and technique_name:
            technique_choice = technique_by_name.get(_normalize_attack_name(technique_name))
        if tactic_choice is None and technique_choice is not None:
            for candidate_tactic_id in technique_choice.get("tactic_ids", []) or []:
                candidate_tactic = tactic_by_id.get(str(candidate_tactic_id).strip().upper())
                if candidate_tactic is not None:
                    tactic_choice = candidate_tactic
                    break
            if tactic_choice is None:
                for tactic_label in technique_choice.get("tactics", []) or []:
                    tactic_choice = tactic_by_name.get(_normalize_attack_name(str(tactic_label)))
                    if tactic_choice is not None:
                        break
        if tactics_only:
            technique_choice = None
            technique_id = ""
            technique_name = ""
        if tactic_choice is None and technique_choice is None:
            continue
        tactic = None
        technique = None
        if tactic_choice is not None and technique_choice is not None:
            tactic = resolve_tactic_name(cfg, str(tactic_choice.get("name", "")).strip())
            technique = resolve_technique_name(cfg, str(technique_choice.get("name", "")).strip())
            technique_tactic_ids = {
                str(value).strip().upper()
                for value in technique_choice.get("tactic_ids", []) or []
                if str(value).strip()
            }
            if str(tactic_choice.get("external_id", "")).strip().upper() not in technique_tactic_ids:
                if tactic is not None and technique is not None and not technique_supports_tactic(technique, tactic):
                    continue
        filtered_claim_ids = [
            claim_id
            for claim_id in evidence_claim_ids
            if claim_id in claim_by_id
            and _claim_supports_mapping(
                dossier,
                claim_by_id[claim_id],
                tactic_choice,
                technique_choice,
                enforce_behavior_priors=enforce_behavior_priors,
            )
        ]
        if not filtered_claim_ids:
            validation_summary["mappings_dropped_after_claim_support_filter_count"] += 1
            continue
        cleaned.append(
            {
                "tactic_id": str((tactic_choice or {}).get("external_id", "")).strip().upper(),
                "tactic": str((tactic_choice or {}).get("name", "")).strip() or (tactic.name if tactic else ""),
                "technique_id": "" if tactics_only else str((technique_choice or {}).get("external_id", "")).strip().upper(),
                "technique": "" if tactics_only else (str((technique_choice or {}).get("name", "")).strip() or (technique.name if technique else "")),
                "evidence_claim_ids": filtered_claim_ids,
                "confidence": _clip_confidence(item.get("confidence")),
                "gaps": [str(value).strip() for value in item.get("gaps", []) if str(value).strip()],
            }
        )
        validation_summary["kept_mapping_count"] += 1
    dedup: dict[tuple[str, str, tuple[str, ...]], dict[str, Any]] = {}
    for item in cleaned:
        key = (
            item["tactic_id"],
            item["technique_id"],
            tuple(sorted(str(value).strip() for value in item.get("evidence_claim_ids", []) if str(value).strip())),
        )
        if key not in dedup or float(item["confidence"]) > float(dedup[key]["confidence"]):
            dedup[key] = item
    validation_summary["kept_mapping_count"] = len(dedup)
    return list(dedup.values()), validation_summary


def _clip_confidence(value: Any) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def _behavior_prior_mapping_for_claim(
    dossier: dict[str, Any],
    claim: dict[str, Any],
    attack_candidates: dict[str, Any],
) -> dict[str, Any] | None:
    prior = _dynamic_behavior_prior_for_claim(dossier, claim)
    if prior is None:
        return None
    tactic_id = str(prior.get("tactic_id", "")).strip().upper()
    technique_id = str(prior.get("technique_id", "")).strip().upper()
    tactic_choice = None
    technique_choice = None
    for item in attack_candidates.get("tactics", []) or []:
        if isinstance(item, dict) and str(item.get("external_id", "")).strip().upper() == tactic_id:
            tactic_choice = item
            break
    if technique_id:
        for item in attack_candidates.get("techniques", []) or []:
            if isinstance(item, dict) and str(item.get("external_id", "")).strip().upper() == technique_id:
                technique_choice = item
                break
    if tactic_choice is None and technique_choice is None:
        return None
    return {
        "tactic_id": str((tactic_choice or {}).get("external_id", "")).strip().upper(),
        "tactic": str((tactic_choice or {}).get("name", "")).strip(),
        "technique_id": str((technique_choice or {}).get("external_id", "")).strip().upper(),
        "technique": str((technique_choice or {}).get("name", "")).strip(),
        "evidence_claim_ids": [str(claim.get("claim_id", "")).strip()],
        "confidence": max(0.72, _clip_confidence(claim.get("confidence"),)),
        "gaps": [],
    }


def _apply_behavior_prior_mappings(
    cfg: FusionConfig,
    dossier: dict[str, Any],
    claims: list[dict[str, Any]],
    attack_candidates: dict[str, Any],
    mappings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not _claim_attack_priors_enabled(cfg):
        return mappings
    prior_by_claim: dict[str, dict[str, Any]] = {}
    for claim in claims:
        claim_id = str(claim.get("claim_id", "")).strip()
        if not claim_id:
            continue
        prior = _behavior_prior_mapping_for_claim(dossier, claim, attack_candidates)
        if prior is not None:
            prior_by_claim[claim_id] = prior
    if not prior_by_claim:
        return mappings

    filtered: list[dict[str, Any]] = []
    for mapping in mappings:
        claim_ids = [str(item).strip() for item in mapping.get("evidence_claim_ids", []) if str(item).strip()]
        if not claim_ids:
            filtered.append(mapping)
            continue
        suppress = False
        for claim_id in claim_ids:
            prior = prior_by_claim.get(claim_id)
            if prior is None:
                continue
            prior_tactic = str(prior.get("tactic_id", "")).strip().upper()
            prior_technique = str(prior.get("technique_id", "")).strip().upper()
            mapping_tactic = str(mapping.get("tactic_id", "")).strip().upper()
            mapping_technique = str(mapping.get("technique_id", "")).strip().upper()
            if prior_tactic and mapping_tactic and prior_tactic != mapping_tactic:
                suppress = True
                break
            if prior_technique:
                if mapping_technique and mapping_technique != prior_technique:
                    suppress = True
                    break
            elif mapping_technique and str(claim_id).strip() in prior_by_claim:
                suppress = True
                break
        if not suppress:
            filtered.append(mapping)

    seen = {
        (
            str(item.get("tactic_id", "")).strip().upper(),
            str(item.get("technique_id", "")).strip().upper(),
            tuple(sorted(str(value).strip() for value in item.get("evidence_claim_ids", []) if str(value).strip())),
        )
        for item in filtered
    }
    for prior in prior_by_claim.values():
        key = (
            str(prior.get("tactic_id", "")).strip().upper(),
            str(prior.get("technique_id", "")).strip().upper(),
            tuple(sorted(str(value).strip() for value in prior.get("evidence_claim_ids", []) if str(value).strip())),
        )
        if key in seen:
            continue
        filtered.append(prior)
        seen.add(key)
    return filtered


def _synthetic_bundle_for_attack_kb(dossier: dict[str, Any]) -> dict[str, Any]:
    synthetic_events: list[dict[str, Any]] = []
    for item in dossier.get("evidence_timeline", []):
        description = str(item.get("description", "")).strip()
        labels = ", ".join(str(value).strip() for value in item.get("labels_triggered", []) or [] if str(value).strip())
        synthetic_events.append(
            {
                "action": "PATH_EVENT",
                "description": f"{description} labels={labels}".strip(),
                "subject_attr": "",
                "object_attr": " ".join(
                    str(item.get(key, "")).strip()
                    for key in ("object_key", "object_class")
                    if str(item.get(key, "")).strip()
                ),
            }
        )
    for process in dossier.get("core_processes", []):
        if not isinstance(process, dict):
            continue
        name = str(process.get("name", "")).strip()
        labels = " ".join(str(value).strip() for value in process.get("labels", []) or [] if str(value).strip())
        if name or labels:
            synthetic_events.append(
                {
                    "action": "PROCESS_LABELS",
                    "description": f"{name} {labels}".strip(),
                    "subject_attr": name,
                    "object_attr": labels,
                }
            )
    for edge in dossier.get("bridge_edges", []):
        if not isinstance(edge, dict):
            continue
        synthetic_events.append(
            {
                "action": "BRIDGE_EDGE",
                "description": f"{edge.get('reason', '')} via {edge.get('object_key', '')}".strip(),
                "subject_attr": "",
                "object_attr": " ".join(
                    [
                        str(edge.get("object_key", "")).strip(),
                        " ".join(str(value).strip() for value in edge.get("object_labels", []) or [] if str(value).strip()),
                    ]
                ).strip(),
            }
        )
    return {
        "events": synthetic_events,
        "episodes": [
            {
                "description": " ".join(
                    [
                        str(item.get("description", "")).strip(),
                        " ".join(str(value).strip() for value in item.get("labels_triggered", []) or [] if str(value).strip()),
                    ]
                ).strip(),
            }
            for item in dossier.get("evidence_timeline", [])
        ],
        "ioc_candidates": {
            "processes": [str(item.get("name", "")).strip() for item in dossier.get("core_processes", []) if str(item.get("name", "")).strip()],
            "paths": [str(item.get("object_key", "")).strip() for item in dossier.get("bridge_edges", []) if str(item.get("object_key", "")).strip()],
            "ips": [
                token
                for item in dossier.get("evidence_timeline", [])
                for token in [str(item.get("object_key", "")).split("->")[-1].split(":")[0].strip()]
                if "." in token and token.count(".") == 3
            ],
        },
    }


def _render_claim_graph_markdown(claim_graph: dict[str, Any]) -> str:
    claims = [item for item in claim_graph.get("claims", []) if isinstance(item, dict)]
    edges = [item for item in claim_graph.get("edges", []) if isinstance(item, dict)]
    diagnostics = claim_graph.get("diagnostics", {}) or {}
    lines = ["# Claim Graph", ""]
    lines.append("## Claims")
    if claims:
        for claim in claims:
            lines.append(f"- {_compact_claim_line(claim)}")
    else:
        lines.append("- none")
    lines.extend(["", "## Edges"])
    if edges:
        for edge in edges:
            src_claim_id = str(edge.get("src_claim_id", "")).strip()
            dst_claim_id = str(edge.get("dst_claim_id", "")).strip()
            relation = str(edge.get("relation", "")).strip() or "prerequisite"
            if src_claim_id and dst_claim_id:
                lines.append(f"- `{src_claim_id}` -> `{dst_claim_id}` [{relation}]")
    else:
        lines.append("- none")
    lines.extend(["", "## Diagnostics"])
    matched_atoms = [str(value).strip() for value in diagnostics.get("matched_atoms", []) if str(value).strip()]
    lines.append(f"- matched_atoms: `{_csv(matched_atoms, limit=24) or 'none'}`")
    missing_atoms = [str(value).strip() for value in diagnostics.get("missing_expected_atoms", []) if str(value).strip()]
    lines.append(f"- missing_expected_atoms: `{_csv(missing_atoms, limit=16) or 'none'}`")
    return "\n".join(lines).strip() + "\n"


def run_module6_reason(cfg: FusionConfig) -> Dict[str, str]:
    ensure_dir(cfg.module6_reason_dir)
    for folder in [_reports_dir(cfg), _dossiers_dir(cfg), _markdown_dir(cfg), _llm_inputs_dir(cfg), _claim_graphs_dir(cfg)]:
        ensure_dir(folder)
    candidate_files = sorted(_candidate_dir(cfg).glob("*.json"))
    report_index: list[dict[str, Any]] = []
    report_count = 0
    for path in candidate_files:
        payload = load_json(path)
        if not isinstance(payload, list):
            continue
        for item in payload[: int(cfg.reason_top_paths_per_task)]:
            if not isinstance(item, dict):
                continue
            dossier = item.get("dossier", {})
            if not isinstance(dossier, dict):
                continue
            task_id = str(dossier.get("task_id", "")).strip()
            path_id = str(dossier.get("path_id", "")).strip()
            if not task_id or not path_id:
                continue
            extract_system_prompt = _system_prompt()
            extract_user_prompt = _user_prompt_extract(dossier)
            raw_extract = _call_ollama_json(cfg, extract_system_prompt, extract_user_prompt)
            claim_graph = build_holmes_claim_graph(dossier)
            claims = _fallback_claims(dossier, _validate_claims(list(raw_extract.get("claims", [])), dossier))
            claim_graph = {
                **claim_graph,
                "claims": claims,
                "edges": [item for item in claim_graph.get("edges", []) if isinstance(item, dict)],
            }
            iocs = _validate_iocs(list(raw_extract.get("iocs", [])))
            attack_candidates = retrieve_attack_candidates(cfg, _synthetic_bundle_for_attack_kb(dossier), claims)
            if _claim_attack_priors_enabled(cfg):
                attack_candidates = _augment_attack_candidates_with_behavior_priors(cfg, dossier, attack_candidates, claims)
                claim_attack_hints = _behavior_prior_hints_for_claims(cfg, dossier, claims)
            else:
                claim_attack_hints = []
            attack_candidates = _filter_attack_candidates_for_scope(cfg, attack_candidates)
            mapping_context = {
                "path_dossier": dossier,
                "claims": claims,
                "claim_graph": claim_graph,
                "claim_attack_hints": claim_attack_hints,
                "attack_candidates": attack_candidates,
                "attack_mapping_scope": _attack_mapping_scope(cfg),
            }
            mapping_system_prompt = _system_prompt()
            mapping_user_prompt = ""
            if _deterministic_tactic_mapping_enabled(cfg):
                raw_mapping = {
                    "attack_mappings": [],
                    "gaps": ["deterministic tactic mapping derived from Holmes-style claims"],
                }
                mappings = _deterministic_tactic_mappings(cfg, claims, attack_candidates)
                mapping_validation_summary = _empty_mapping_validation_summary()
            else:
                mapping_user_prompt = _user_prompt_map(
                    mapping_context,
                    include_claim_attack_hints=_claim_attack_priors_enabled(cfg),
                )
                raw_mapping = _call_ollama_json(cfg, mapping_system_prompt, mapping_user_prompt)
                mappings, mapping_validation_summary = _validate_mappings(
                    cfg,
                    dossier,
                    list(raw_mapping.get("attack_mappings", [])),
                    attack_candidates,
                    claims,
                )
                mappings = _apply_behavior_prior_mappings(cfg, dossier, claims, attack_candidates, mappings)
            report = {
                "task_id": task_id,
                "path_id": path_id,
                "path_type": dossier.get("path_type", ""),
                "risk_level": dossier.get("risk_level", ""),
                "risk_score": dossier.get("risk_score", 0.0),
                "stage_coverage": dossier.get("stage_coverage", []),
                "family_tags": dossier.get("family_tags", []),
                "summary": str(raw_extract.get("summary", "")).strip() or str(dossier.get("summary", "")).strip(),
                "claims": claims,
                "claim_graph": claim_graph,
                "extracted_behaviors": claims,
                "iocs": iocs,
                "attack_candidates": attack_candidates,
                "attack_mappings": mappings,
                "attack_mapping_scope": _attack_mapping_scope(cfg),
                "tactic_mapping_mode": _tactic_mapping_mode(cfg),
                "mapping_validation_summary": mapping_validation_summary,
                "gaps": [
                    *[str(value).strip() for value in raw_extract.get("gaps", []) if str(value).strip()],
                    *[str(value).strip() for value in raw_mapping.get("gaps", []) if str(value).strip()],
                ],
                "source_candidate_paths_path": str(path),
                "evidence_support_rate": _evidence_support_rate(claims, mappings),
            }
            llm_inputs = {
                "extract": _llm_input_record(
                    cfg,
                    stage="path_extract",
                    system_prompt=extract_system_prompt,
                    user_prompt=extract_user_prompt,
                    context=dossier,
                    response=raw_extract,
                ),
                "mapping": _llm_input_record(
                    cfg,
                    stage="path_mapping",
                    system_prompt=mapping_system_prompt,
                    user_prompt=mapping_user_prompt,
                    context=mapping_context,
                    response=raw_mapping,
                ),
            }
            llm_inputs["mapping"]["validation_summary"] = mapping_validation_summary
            slug = _slugify(path_id)
            dossier_path = _dossiers_dir(cfg) / f"{slug}.json"
            report_path = _reports_dir(cfg) / f"{slug}.report.json"
            markdown_path = _markdown_dir(cfg) / f"{slug}.md"
            llm_input_path = _llm_inputs_dir(cfg) / f"{slug}.input.json"
            claim_graph_path = _claim_graphs_dir(cfg) / f"{slug}.claim_graph.json"
            claim_graph_markdown_path = _claim_graphs_dir(cfg) / f"{slug}.claim_graph.md"
            save_json(dossier_path, dossier)
            save_json(report_path, report)
            markdown_path.write_text(_render_markdown(report), encoding="utf-8")
            save_json(llm_input_path, llm_inputs)
            save_json(claim_graph_path, claim_graph)
            claim_graph_markdown_path.write_text(_render_claim_graph_markdown(claim_graph), encoding="utf-8")
            report_index.append(
                {
                    "task_id": task_id,
                    "path_id": path_id,
                    "report_path": str(report_path),
                    "dossier_path": str(dossier_path),
                    "markdown_path": str(markdown_path),
                    "llm_input_path": str(llm_input_path),
                    "claim_graph_path": str(claim_graph_path),
                }
            )
            report_count += 1
    save_json(_report_index_path(cfg), report_index)
    save_json(
        _summary_path(cfg),
        {
            "report_count": report_count,
            "claim_attack_prior_mode": cfg.claim_attack_prior_mode,
            "attack_mapping_scope": _attack_mapping_scope(cfg),
            "tactic_mapping_mode": _tactic_mapping_mode(cfg),
            "candidate_file_count": len(candidate_files),
            "reports_dir": str(_reports_dir(cfg)),
            "dossiers_dir": str(_dossiers_dir(cfg)),
            "markdown_dir": str(_markdown_dir(cfg)),
            "llm_inputs_dir": str(_llm_inputs_dir(cfg)),
            "claim_graphs_dir": str(_claim_graphs_dir(cfg)),
        },
    )
    return {
        "summary": str(_summary_path(cfg)),
        "report_index": str(_report_index_path(cfg)),
        "reports_dir": str(_reports_dir(cfg)),
        "dossiers_dir": str(_dossiers_dir(cfg)),
        "markdown_dir": str(_markdown_dir(cfg)),
        "llm_inputs_dir": str(_llm_inputs_dir(cfg)),
        "claim_graphs_dir": str(_claim_graphs_dir(cfg)),
    }


def _slugify(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in str(value)).strip("_") or "path"


def _evidence_support_rate(claims: list[dict[str, Any]], mappings: list[dict[str, Any]]) -> float:
    if not claims and not mappings:
        return 0.0
    claim_score = sum(1 for claim in claims if claim.get("evidence_event_ids")) / max(1, len(claims))
    mapping_score = sum(1 for mapping in mappings if mapping.get("evidence_claim_ids")) / max(1, len(mappings) or 1)
    return float((claim_score + mapping_score) / 2.0)


def _render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# {report.get('path_id', '')}",
        "",
        f"- task_id: `{report.get('task_id', '')}`",
        f"- path_type: `{report.get('path_type', '')}`",
        f"- risk_level: `{report.get('risk_level', '')}`",
        f"- risk_score: `{float(report.get('risk_score', 0.0)):.2f}`",
        f"- evidence_support_rate: `{float(report.get('evidence_support_rate', 0.0)):.3f}`",
        "",
        "## Summary",
        str(report.get("summary", "")).strip(),
        "",
        "## Claims",
    ]
    for claim in report.get("claims", []):
        lines.append(
            f"- `{claim.get('claim_id', '')}` {claim.get('behavior_type', '')} ({claim.get('apt_stage', '')}): {claim.get('statement', '')} "
            f"[events={', '.join(claim.get('evidence_event_ids', []))}; pre={', '.join(claim.get('prerequisite_claim_ids', []))}; confidence={float(claim.get('confidence', 0.0)):.2f}]"
        )
    lines.extend(["", "## Claim Graph"])
    claim_graph = report.get("claim_graph", {}) or {}
    graph_edges = [item for item in claim_graph.get("edges", []) if isinstance(item, dict)]
    if graph_edges:
        for edge in graph_edges:
            lines.append(
                f"- `{edge.get('src_claim_id', '')}` -> `{edge.get('dst_claim_id', '')}` [{edge.get('relation', 'prerequisite')}]"
            )
    else:
        lines.append("- no claim dependencies")
    lines.extend(["", "## ATT&CK Mappings"])
    mappings = report.get("attack_mappings", [])
    if mappings:
        for mapping in mappings:
            lines.append(
                f"- `{mapping.get('tactic_id', '')}` {mapping.get('tactic', '')} | "
                f"`{mapping.get('technique_id', '')}` {mapping.get('technique', '')} "
                f"[claims={', '.join(mapping.get('evidence_claim_ids', []))}; confidence={float(mapping.get('confidence', 0.0)):.2f}]"
            )
    else:
        lines.append("- no supported ATT&CK mappings")
    return "\n".join(lines).strip() + "\n"

