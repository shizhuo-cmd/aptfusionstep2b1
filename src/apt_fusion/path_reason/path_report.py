from __future__ import annotations

from typing import Any

from ..config import FusionConfig
from .chain_semantics import is_placeholder_object_key, is_system_service_object_key, is_temp_exec_path, normalize_semantic_text
from .path_schemas import CandidatePath, ObjectState, ProcessState


_HIGH_SIGNAL_EVENT_TYPES = {"EXEC", "CONNECT", "SEND", "RECV", "WRITE", "CREATE", "READ", "DELETE", "RENAME", "CHMOD", "CHOWN"}
_PAYLOAD_FOLLOWUP_EVENT_TYPES = {"CLONE"}
_HIGH_SIGNAL_OBJECT_CLASSES = {
    "temp_file",
    "external_ip",
    "internal_ip",
    "credential_file",
    "history_file",
    "business_file",
    "persistence_file",
    "privilege_file",
    "log_file",
}
_SERVICE_PROCESS_NAMES = {
    "cron",
    "cleanup",
    "cupsd",
    "dbus-daemon",
    "login",
    "master",
    "pickup",
    "postfix",
    "qmgr",
    "rpcbind",
    "smtpd",
    "sshd",
    "systemd",
}
_DELETE_EVENT_TYPES = {"DELETE", "UNLINK", "RENAME"}
_STRONG_SENSITIVE_OBJECT_LABELS = {"O_CREDENTIAL", "O_HISTORY", "O_SENSITIVE_STRONG"}
_WEAK_SENSITIVE_OBJECT_LABELS = {"O_BUSINESS_DATA", "O_SENSITIVE_WEAK"}
_STAGED_OBJECT_LABELS = {"O_FILE_TEMP", "O_FILE_DOWNLOADED", "O_FILE_UPLOADED", "O_SUSPECT_WRITTEN_EXECUTABLE", "O_STAGED_EXEC_SOURCE"}
_LOG_PATH_MARKERS = ("/var/log/", ".log", "lastlog", "wtmp", "btmp", "utmp", "messages", "secure")


def _event_labels(event: dict[str, Any]) -> list[str]:
    output: list[str] = []
    for key in ("labels_triggered", "path_labels_triggered"):
        for value in event.get(key, []) or []:
            text = str(value).strip()
            if text and text not in output:
                output.append(text)
    return output


def _event_priority(event: dict[str, Any], bridge_event_ids: set[str]) -> tuple[int, int]:
    event_id = str(event.get("event_id", "")).strip()
    event_type = str(event.get("event_type", "")).strip().upper()
    object_class = str(event.get("object_class", "")).strip().lower()
    object_key = str(event.get("object_key", "")).strip().lower()
    labels = _event_labels(event)
    score = 0
    if event_id in bridge_event_ids:
        score += 100
    if labels:
        score += 40 + 12 * len(labels)
        if any(label.startswith("B_") for label in labels):
            score += 20
    if event_type in _HIGH_SIGNAL_EVENT_TYPES:
        score += 8
    if object_class in _HIGH_SIGNAL_OBJECT_CLASSES:
        score += 8
    if any(marker in object_key for marker in ("/tmp/", "/var/tmp/", "/dev/shm/")):
        score += 10
    if "->" in object_key or object_class in {"external_ip", "internal_ip"}:
        score += 6
    if _is_payload_followup_event(event):
        score += 24
    return score, int(event.get("order_index", 0) or 0)


def _path_has_staged_bridge(path: CandidatePath) -> bool:
    for edge in path.bridge_edges:
        labels = {str(value).strip() for value in edge.object_labels if str(value).strip()}
        if labels.intersection(_STAGED_OBJECT_LABELS):
            return True
    return False


def _is_payload_followup_event(event: dict[str, Any]) -> bool:
    event_type = str(event.get("event_type", "")).strip().upper()
    if event_type not in _PAYLOAD_FOLLOWUP_EVENT_TYPES:
        return False
    object_class = str(event.get("object_class", "")).strip().lower()
    if object_class != "process":
        return False
    object_key = normalize_semantic_text(event.get("object_key"))
    if not object_key or is_temp_exec_path(object_key) or is_system_service_object_key(object_key):
        return False
    return object_key.startswith("/")


def _select_timeline_events(
    events: list[dict[str, Any]],
    path: CandidatePath,
    max_items: int,
) -> list[dict[str, Any]]:
    if len(events) <= max_items:
        return sorted(events, key=lambda item: int(item.get("order_index", 0) or 0))
    bridge_event_ids = {
        str(edge.write_event_id).strip()
        for edge in path.bridge_edges
        if str(edge.write_event_id).strip()
    }.union(
        {
            str(edge.read_or_exec_event_id).strip()
            for edge in path.bridge_edges
            if str(edge.read_or_exec_event_id).strip()
        }
    )
    pinned_event_ids = {
        str(event_id).strip()
        for event_id in (
            list(path.precursor_event_ids)
            + list(path.followup_event_ids)
        )
        if str(event_id).strip()
    }
    ranked = sorted(
        events,
        key=lambda item: (
            -_event_priority(item, bridge_event_ids)[0],
            _event_priority(item, bridge_event_ids)[1],
        ),
    )
    chosen: dict[str, dict[str, Any]] = {}
    pinned_events = sorted(
        [
            event
            for event in events
            if str(event.get("event_id", "")).strip() in pinned_event_ids
        ],
        key=lambda item: int(item.get("order_index", 0) or 0),
    )
    for event in pinned_events:
        event_id = str(event.get("event_id", "")).strip()
        if event_id:
            chosen[event_id] = event
    if _path_has_staged_bridge(path):
        followup_events = [
            event
            for event in ranked
            if _is_payload_followup_event(event)
        ]
        for event in followup_events[:1]:
            event_id = str(event.get("event_id", "")).strip()
            if event_id:
                chosen[event_id] = event
    for event in ranked:
        event_id = str(event.get("event_id", "")).strip()
        if not event_id:
            continue
        chosen[event_id] = event
        if len(chosen) >= max_items:
            break
    for extra in (events[0], events[-1]):
        event_id = str(extra.get("event_id", "")).strip()
        if event_id and event_id not in chosen and len(chosen) < max_items:
            chosen[event_id] = extra
    return sorted(chosen.values(), key=lambda item: int(item.get("order_index", 0) or 0))


def _object_state_lookup(object_states: dict[str, ObjectState]) -> dict[str, ObjectState]:
    lookup: dict[str, ObjectState] = {}
    for key, state in object_states.items():
        text = str(key).strip().lower()
        if text and text not in lookup:
            lookup[text] = state
    return lookup


def _object_state_for_key(object_key: Any, object_lookup: dict[str, ObjectState]) -> ObjectState | None:
    text = str(object_key or "").strip().lower()
    if not text:
        return None
    return object_lookup.get(text)


def _service_like_process_names(path: CandidatePath, process_states: dict[str, ProcessState]) -> list[str]:
    output: list[str] = []
    for guid in path.process_chain:
        state = process_states.get(guid)
        if state is None:
            continue
        name = str(state.process_name or "").strip().lower()
        if not name:
            continue
        if name in _SERVICE_PROCESS_NAMES or (name.endswith("d") and len(name) >= 4):
            if name not in output:
                output.append(name)
    return output


def _object_label_set(event: dict[str, Any], object_lookup: dict[str, ObjectState]) -> set[str]:
    labels = {str(value).strip() for value in event.get("object_labels", []) or [] if str(value).strip()}
    state = _object_state_for_key(event.get("object_key"), object_lookup)
    if state is not None:
        labels.update(str(value).strip() for value in state.labels if str(value).strip())
    return labels


def _format_summary_values(values: list[str], *, limit: int = 4) -> str:
    output: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in output:
            output.append(text)
        if len(output) >= limit:
            break
    return ", ".join(output)


def _is_log_artifact(event: dict[str, Any], object_lookup: dict[str, ObjectState]) -> bool:
    labels = _object_label_set(event, object_lookup)
    if "B_DELETE_LOG" in {str(value).strip() for value in event.get("labels_triggered", []) or [] if str(value).strip()}:
        return True
    object_class = str(event.get("object_class", "")).strip().lower()
    if object_class == "log_file":
        return True
    object_key = str(event.get("object_key", "")).strip().lower()
    if not object_key:
        return False
    return any(marker in object_key for marker in _LOG_PATH_MARKERS) or "O_LOG_ARTIFACT" in labels


def _build_service_context_summary(
    path: CandidatePath,
    process_states: dict[str, ProcessState],
    events: list[dict[str, Any]],
    object_lookup: dict[str, ObjectState],
) -> str:
    service_processes = _service_like_process_names(path, process_states)
    system_objects: list[str] = []
    for event in events:
        object_key = str(event.get("object_key", "")).strip()
        if object_key and is_system_service_object_key(object_key) and object_key not in system_objects:
            system_objects.append(object_key)
    parts: list[str] = []
    if service_processes:
        parts.append(f"service_processes={_format_summary_values(service_processes)}")
    if system_objects:
        parts.append(f"system_objects={_format_summary_values(system_objects)}")
    if not parts:
        return ""
    return "; ".join(parts)


def _build_sensitive_object_summary(events: list[dict[str, Any]], object_lookup: dict[str, ObjectState]) -> str:
    strong_objects: list[str] = []
    weak_objects: list[str] = []
    weak_system_objects: list[str] = []
    for event in events:
        labels = _object_label_set(event, object_lookup)
        event_labels = {str(value).strip() for value in event.get("labels_triggered", []) or [] if str(value).strip()}
        object_key = str(event.get("object_key", "")).strip()
        object_class = str(event.get("object_class", "")).strip().lower()
        if not object_key:
            continue
        is_strong = bool(labels.intersection(_STRONG_SENSITIVE_OBJECT_LABELS)) or object_class in {"credential_file", "history_file"} or bool(
            event_labels.intersection({"B_READ_CRED", "B_READ_HISTORY"})
        )
        is_weak = bool(labels.intersection(_WEAK_SENSITIVE_OBJECT_LABELS)) or object_class == "business_file" or bool(
            event_labels.intersection({"B_READ_BUSINESS", "B_MASS_FILE_ACCESS"})
        )
        if is_strong and object_key not in strong_objects:
            strong_objects.append(object_key)
            continue
        if is_weak:
            target = weak_system_objects if is_system_service_object_key(object_key) else weak_objects
            if object_key not in target:
                target.append(object_key)
    parts: list[str] = []
    if strong_objects:
        parts.append(f"strong={_format_summary_values(strong_objects)}")
    if weak_objects:
        parts.append(f"weak={_format_summary_values(weak_objects)}")
    if weak_system_objects:
        parts.append(f"weak_system={_format_summary_values(weak_system_objects)}")
    return "; ".join(parts)


def _build_cleanup_object_summary(events: list[dict[str, Any]], object_lookup: dict[str, ObjectState]) -> str:
    log_cleanup: list[str] = []
    staged_cleanup: list[str] = []
    for event in events:
        event_type = str(event.get("event_type", "")).strip().upper()
        if event_type not in _DELETE_EVENT_TYPES:
            continue
        object_key = str(event.get("object_key", "")).strip()
        if not object_key or is_placeholder_object_key(object_key):
            continue
        labels = _object_label_set(event, object_lookup)
        if _is_log_artifact(event, object_lookup):
            if object_key not in log_cleanup:
                log_cleanup.append(object_key)
            continue
        if is_temp_exec_path(object_key) or labels.intersection(_STAGED_OBJECT_LABELS):
            if object_key not in staged_cleanup:
                staged_cleanup.append(object_key)
    parts: list[str] = []
    if log_cleanup:
        parts.append(f"log_cleanup={_format_summary_values(log_cleanup)}")
    if staged_cleanup:
        parts.append(f"staged_cleanup={_format_summary_values(staged_cleanup)}")
    return "; ".join(parts)


def build_path_dossier(
    cfg: FusionConfig,
    path: CandidatePath,
    process_states: dict[str, ProcessState],
    object_states: dict[str, ObjectState],
    retained_events: list[dict[str, Any]],
) -> dict[str, Any]:
    path_process_set = set(path.process_chain)
    bridge_event_ids = {edge.write_event_id for edge in path.bridge_edges}.union(
        {edge.read_or_exec_event_id for edge in path.bridge_edges}
    )
    path_context_event_ids = {
        str(event_id).strip()
        for event_id in (
            list(path.support_event_ids)
            + list(path.precursor_event_ids)
            + list(path.followup_event_ids)
        )
        if str(event_id).strip()
    }
    object_lookup = _object_state_lookup(object_states)
    events = [
        event
        for event in retained_events
        if str(event.get("process_guid", "")).strip() in path_process_set
        or str(event.get("event_id", "")).strip() in bridge_event_ids
        or str(event.get("event_id", "")).strip() in path_context_event_ids
    ]
    events.sort(key=lambda item: int(item.get("order_index", 0) or 0))
    timeline = []
    selected_events = _select_timeline_events(events, path, int(cfg.reason_max_timeline_items_per_path))
    for event in selected_events:
        timeline.append(
            {
                "timestamp": event.get("timestamp"),
                "event_id": event.get("event_id"),
                "description": event.get("description"),
                "event_type": event.get("event_type"),
                "object_key": event.get("object_key"),
                "object_class": event.get("object_class"),
                "object_labels": sorted(_object_label_set(event, object_lookup)),
                "process_guid": event.get("process_guid"),
                "process_name": event.get("process_name"),
                "labels_triggered": _event_labels(event),
                "raw_log_id": event.get("raw_log_id"),
                "order_index": event.get("order_index"),
            }
        )
    dossier = {
        "task_id": path.task_id,
        "path_id": path.path_id,
        "path_type": path.path_type,
        "risk_level": path.risk_level,
        "risk_score": path.risk_score,
        "stage_coverage": list(path.stage_coverage),
        "chain_kind": path.chain_kind,
        "context_ids": list(path.context_ids),
        "support_event_ids": list(path.support_event_ids),
        "support_object_keys": list(path.support_object_keys),
        "support_relations": list(path.support_relations),
        "family_tags": list(path.family_tags),
        "precursor_event_ids": list(path.precursor_event_ids),
        "followup_event_ids": list(path.followup_event_ids),
        "network_support_summary": path.network_support_summary,
        "object_lineage_summary": path.object_lineage_summary,
        "service_context_summary": _build_service_context_summary(path, process_states, events, object_lookup),
        "sensitive_object_summary": _build_sensitive_object_summary(events, object_lookup),
        "cleanup_object_summary": _build_cleanup_object_summary(events, object_lookup),
        "holmes_matched_atoms": list(path.holmes_matched_atoms),
        "missed_truth_like_hints": list(path.missed_truth_like_hints),
        "process_envelope_time_range": {
            "start": path.time_range[0].isoformat() if path.time_range[0] is not None else None,
            "end": path.time_range[1].isoformat() if path.time_range[1] is not None else None,
        },
        "core_processes": [
            {
                "process_guid": guid,
                "name": process_states[guid].process_name if guid in process_states else guid,
                "labels": sorted(process_states[guid].all_labels()) if guid in process_states else [],
            }
            for guid in path.process_chain
        ],
        "bridge_edges": [
            {
                "src": edge.src_process_guid,
                "dst": edge.dst_process_guid,
                "object_key": edge.object_key,
                "object_labels": sorted(edge.object_labels),
                "write_event_id": edge.write_event_id,
                "read_or_exec_event_id": edge.read_or_exec_event_id,
                "confidence": edge.confidence,
                "reason": edge.reason,
            }
            for edge in path.bridge_edges[: int(cfg.reason_max_bridge_edges_per_path)]
        ],
        "evidence_timeline": timeline,
        "warnings": list(path.warnings),
        "summary": path.summary,
    }
    return dossier


def render_candidate_path_markdown(dossier: dict[str, Any]) -> str:
    lines = [
        f"# {dossier.get('path_id', '')}",
        "",
        f"- task_id: `{dossier.get('task_id', '')}`",
        f"- path_type: `{dossier.get('path_type', '')}`",
        f"- risk_level: `{dossier.get('risk_level', '')}`",
        f"- risk_score: `{float(dossier.get('risk_score', 0.0)):.2f}`",
        f"- stage_coverage: `{', '.join(dossier.get('stage_coverage', []))}`",
        f"- process_envelope_time_range: `{(dossier.get('process_envelope_time_range', {}) or {}).get('start')}` -> `{(dossier.get('process_envelope_time_range', {}) or {}).get('end')}`",
        "",
        "## Core Processes",
    ]
    for process in dossier.get("core_processes", []):
        lines.append(
            f"- `{process.get('process_guid', '')}` {process.get('name', '')} | labels={', '.join(process.get('labels', []))}"
        )
    lines.extend(["", "## Bridge Edges"])
    bridge_edges = dossier.get("bridge_edges", [])
    if bridge_edges:
        for edge in bridge_edges:
            lines.append(
                f"- `{edge.get('src', '')}` -> `{edge.get('dst', '')}` via `{edge.get('object_key', '')}` "
                f"(labels={', '.join(edge.get('object_labels', []))}; confidence={float(edge.get('confidence', 0.0)):.2f})"
            )
    else:
        lines.append("- none")
    support_present = bool(
        dossier.get("chain_kind")
        or dossier.get("context_ids")
        or dossier.get("support_object_keys")
        or dossier.get("support_relations")
    )
    if support_present:
        lines.extend(["", "## Support"])
        if dossier.get("chain_kind"):
            lines.append(f"- chain_kind: `{dossier.get('chain_kind', '')}`")
        family_tags = dossier.get("family_tags", [])
        if family_tags:
            lines.append(f"- family_tags: `{', '.join(family_tags)}`")
        context_ids = dossier.get("context_ids", [])
        if context_ids:
            lines.append(f"- context_ids: `{', '.join(context_ids)}`")
        support_object_keys = dossier.get("support_object_keys", [])
        if support_object_keys:
            lines.append(f"- support_object_keys: `{', '.join(support_object_keys)}`")
        holmes_matched_atoms = dossier.get("holmes_matched_atoms", [])
        if holmes_matched_atoms:
            lines.append(f"- holmes_matched_atoms: `{', '.join(holmes_matched_atoms)}`")
    precursor_event_ids = dossier.get("precursor_event_ids", [])
    if precursor_event_ids:
        lines.extend(["", "## PRECURSOR", f"- event_ids: `{', '.join(precursor_event_ids)}`"])
    followup_event_ids = dossier.get("followup_event_ids", [])
    if followup_event_ids:
        lines.extend(["", "## FOLLOWUP", f"- event_ids: `{', '.join(followup_event_ids)}`"])
    network_support_summary = str(dossier.get("network_support_summary", "")).strip()
    if network_support_summary:
        lines.extend(["", "## NETWORK_SUPPORT", f"- {network_support_summary}"])
    object_lineage_summary = str(dossier.get("object_lineage_summary", "")).strip()
    if object_lineage_summary:
        lines.extend(["", "## OBJECT_LINEAGE", f"- {object_lineage_summary}"])
    service_context_summary = str(dossier.get("service_context_summary", "")).strip()
    if service_context_summary:
        lines.extend(["", "## SERVICE_CONTEXT", f"- {service_context_summary}"])
    sensitive_object_summary = str(dossier.get("sensitive_object_summary", "")).strip()
    if sensitive_object_summary:
        lines.extend(["", "## SENSITIVE_OBJECTS", f"- {sensitive_object_summary}"])
    cleanup_object_summary = str(dossier.get("cleanup_object_summary", "")).strip()
    if cleanup_object_summary:
        lines.extend(["", "## CLEANUP_OBJECTS", f"- {cleanup_object_summary}"])
    missed_truth_like_hints = dossier.get("missed_truth_like_hints", [])
    if missed_truth_like_hints:
        lines.extend(["", "## FAMILY_GAPS"])
        for hint in missed_truth_like_hints:
            lines.append(f"- {hint}")
    if support_present:
        support_relations = dossier.get("support_relations", [])
        if support_relations:
            lines.append("- support_relations:")
            for relation in support_relations:
                lines.append(f"  - {relation}")
    lines.extend(["", "## Timeline"])
    for item in dossier.get("evidence_timeline", []):
        lines.append(
            f"- `{item.get('timestamp', '')}` {item.get('description', '')} "
            f"[labels={', '.join(item.get('labels_triggered', []))}; raw_log_id={item.get('raw_log_id', '')}]"
        )
    warnings = dossier.get("warnings", [])
    if warnings:
        lines.extend(["", "## Warnings"])
        for warning in warnings:
            lines.append(f"- {warning}")
    return "\n".join(lines).strip() + "\n"

