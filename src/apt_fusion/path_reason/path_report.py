from __future__ import annotations

from typing import Any

from ..config import FusionConfig
from .path_schemas import CandidatePath, ObjectState, ProcessState


_HIGH_SIGNAL_EVENT_TYPES = {"EXEC", "CONNECT", "SEND", "RECV", "WRITE", "CREATE", "READ", "DELETE", "RENAME", "CHMOD", "CHOWN"}
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
    return score, int(event.get("order_index", 0) or 0)


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
    ranked = sorted(
        events,
        key=lambda item: (
            -_event_priority(item, bridge_event_ids)[0],
            _event_priority(item, bridge_event_ids)[1],
        ),
    )
    chosen: dict[str, dict[str, Any]] = {}
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
    events = [
        event
        for event in retained_events
        if str(event.get("process_guid", "")).strip() in path_process_set
        or str(event.get("event_id", "")).strip() in bridge_event_ids
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
                "labels_triggered": _event_labels(event),
                "raw_log_id": event.get("raw_log_id"),
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
        context_ids = dossier.get("context_ids", [])
        if context_ids:
            lines.append(f"- context_ids: `{', '.join(context_ids)}`")
        support_object_keys = dossier.get("support_object_keys", [])
        if support_object_keys:
            lines.append(f"- support_object_keys: `{', '.join(support_object_keys)}`")
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

