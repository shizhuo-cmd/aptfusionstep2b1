from __future__ import annotations

from pathlib import Path
import copy
from typing import Any, Dict

from .bridge_builder import build_bridge_edges
from .label_provenance import is_provenance_key_label, load_label_provenance_records
from ..common import ensure_dir, load_json, load_jsonl, save_json
from ..config import FusionConfig
from .module4_semantic_compact import (
    _summary_path as _module4_summary_path,
    _task_index_path as _module4_task_index_path,
)
from .path_labeler import apply_full_path_labels
from .path_propagator import propagate_status_labels
from .path_report import build_path_dossier, render_candidate_path_markdown
from .path_rules import load_path_rules
from .path_schemas import CandidatePath, LabelProvenanceRecord, ObjectState, ObjectVersion, ProcessState, TaskPrior, parse_datetime
from .path_scoring import score_candidate_paths
from .path_search import search_candidate_paths


def _summary_path(cfg: FusionConfig) -> Path:
    return cfg.module5_paths_dir / "summary.json"


def _process_summary_path(cfg: FusionConfig) -> Path:
    return cfg.module5_paths_dir / "process_summary.json"


def _object_summary_path(cfg: FusionConfig) -> Path:
    return cfg.module5_paths_dir / "object_summary.json"


def _bridge_dir(cfg: FusionConfig) -> Path:
    return cfg.module5_paths_dir / "bridge_edges"


def _candidate_dir(cfg: FusionConfig) -> Path:
    return cfg.module5_paths_dir / "candidate_paths"


def _compact_index(cfg: FusionConfig) -> list[dict[str, Any]]:
    path = _module4_task_index_path(cfg)
    if not path.exists():
        raise FileNotFoundError(f"module4 compact task index not found: {path}. Run module4_compact first.")
    payload = load_json(path)
    return payload if isinstance(payload, list) else []


def _load_priors(cfg: FusionConfig) -> dict[str, TaskPrior]:
    path = cfg.module3_evidence_dir / "priors_by_task.json"
    if not path.exists():
        return {}
    payload = load_json(path)
    if not isinstance(payload, dict):
        return {}
    priors = {task_id: TaskPrior.from_dict(dict(value)) for task_id, value in payload.items() if isinstance(value, dict)}
    return _enrich_priors_from_module1(cfg, priors)


def _enrich_priors_from_module1(cfg: FusionConfig, priors: dict[str, TaskPrior]) -> dict[str, TaskPrior]:
    if not priors:
        return priors
    if all(prior.task_root_id or prior.boundary_node_ids for prior in priors.values()):
        return priors
    graph_path = cfg.module1_dir / "tapas_native_graphs.pt"
    if not graph_path.exists():
        return priors
    try:
        import torch

        bundle = torch.load(graph_path, map_location="cpu", weights_only=False)
    except Exception:
        return priors
    if not isinstance(bundle, dict):
        return priors
    meta_by_task = {
        str(meta.get("task_id", "")).strip(): meta
        for meta in bundle.get("selected_graph_metas", []) or []
        if isinstance(meta, dict) and str(meta.get("task_id", "")).strip()
    }
    for task_id, prior in priors.items():
        meta = meta_by_task.get(task_id)
        if meta is None:
            continue
        if not prior.task_root_id:
            prior.task_root_id = str(meta.get("task_root_id", "")).strip()
        if not prior.boundary_node_ids:
            prior.boundary_node_ids = [str(item) for item in meta.get("boundary_node_ids", [])]
    return priors


def _parent_task_map(task_ids: set[str], priors: dict[str, TaskPrior]) -> dict[str, str]:
    boundary_owner: dict[str, list[str]] = {}
    for task_id in task_ids:
        prior = priors.get(task_id)
        if prior is None:
            continue
        for node_id in prior.boundary_node_ids:
            boundary_owner.setdefault(str(node_id).strip(), []).append(task_id)
    parent_by_task: dict[str, str] = {}
    for task_id in task_ids:
        prior = priors.get(task_id)
        if prior is None or not prior.task_root_id:
            continue
        candidates = [
            parent_id
            for parent_id in boundary_owner.get(prior.task_root_id, [])
            if parent_id != task_id
        ]
        if candidates:
            parent_by_task[task_id] = sorted(candidates)[0]
    return parent_by_task


def _load_process_states(path: Path) -> dict[str, ProcessState]:
    payload = load_json(path)
    if not isinstance(payload, dict):
        return {}
    return {
        key: ProcessState.from_dict(dict(value))
        for key, value in payload.items()
        if isinstance(value, dict)
    }


def _load_object_states(path: Path) -> dict[str, ObjectState]:
    payload = load_json(path)
    if not isinstance(payload, dict):
        return {}
    return {
        key: ObjectState.from_dict(dict(value))
        for key, value in payload.items()
        if isinstance(value, dict)
    }


def _load_object_versions(path: Path) -> dict[str, list[ObjectVersion]]:
    if not str(path).strip() or not path.is_file():
        return {}
    try:
        payload = load_json(path)
    except Exception:
        return {}
    if not isinstance(payload, list):
        return {}
    grouped: dict[str, list[ObjectVersion]] = {}
    for item in payload:
        if not isinstance(item, dict):
            continue
        version = ObjectVersion.from_dict(item)
        if not version.object_key:
            continue
        grouped.setdefault(version.object_key, []).append(version)
    return grouped


def _load_label_provenance(path: Path) -> list[LabelProvenanceRecord]:
    return load_label_provenance_records(path)


def _clone_process_state_for_task(parent_state: ProcessState, task_id: str, process_guid: str) -> ProcessState:
    cloned = copy.deepcopy(parent_state)
    cloned.task_id = task_id
    cloned.process_guid = process_guid
    cloned.evidence_event_ids = []
    return cloned


def _inherit_parent_split_labels(
    task_id: str,
    process_states: dict[str, ProcessState],
    priors: dict[str, TaskPrior],
    parent_states: dict[str, ProcessState],
) -> None:
    prior = priors.get(task_id)
    if prior is None or not prior.task_root_id:
        return
    split_guid = str(prior.task_root_id).strip()
    parent_state = parent_states.get(split_guid)
    if parent_state is None:
        return
    child_state = process_states.get(split_guid)
    if child_state is None:
        child_state = _clone_process_state_for_task(parent_state, task_id=task_id, process_guid=split_guid)
        process_states[split_guid] = child_state
    child_state.status_labels.update(parent_state.status_labels)
    child_state.behavior_labels.update(parent_state.behavior_labels)
    child_state.aggregate_labels.update(parent_state.aggregate_labels)
    child_state.important_objects.update(parent_state.important_objects)
    child_state.context_ids.update(parent_state.context_ids)
    for label_id in parent_state.label_ids:
        if label_id not in child_state.label_ids:
            child_state.label_ids.append(label_id)
    child_state.prior_score = max(float(child_state.prior_score), float(parent_state.prior_score))
    child_state.score = max(float(child_state.score), float(parent_state.score))
    if not child_state.parent_process_guid and parent_state.parent_process_guid:
        child_state.parent_process_guid = parent_state.parent_process_guid
    if not child_state.process_name and parent_state.process_name:
        child_state.process_name = parent_state.process_name
    if child_state.process_exe is None and parent_state.process_exe is not None:
        child_state.process_exe = parent_state.process_exe
    if child_state.process_cmdline is None and parent_state.process_cmdline is not None:
        child_state.process_cmdline = parent_state.process_cmdline


def _has_execution_stage(stage_set: set[str]) -> bool:
    return "ExecutionStrong" in stage_set or "ExecutionWeak" in stage_set


def _chain_kind_from_stages(stages: set[str] | list[str]) -> str:
    stage_set = {str(item).strip() for item in stages if str(item).strip()}
    has_entry = "Entry" in stage_set
    has_execution = _has_execution_stage(stage_set)
    has_access = "TargetAccess" in stage_set
    has_followup = "FollowUp" in stage_set
    if has_entry and has_execution and has_access and has_followup:
        return "entry_exec_access_followup"
    if has_entry and has_execution and has_access:
        return "entry_exec_access"
    if has_entry and has_access and has_followup:
        return "entry_collection_exfil"
    if has_entry and has_execution:
        return "entry_exec"
    if has_access and has_followup:
        return "collection_followup"
    return "generic_path"


def _event_order_key(event_id: str, event_lookup: dict[str, dict[str, Any]]) -> tuple[int, str]:
    payload = event_lookup.get(event_id)
    if payload is not None:
        return int(payload.get("order_index", 0) or 0), event_id
    suffix = str(event_id).rsplit(":", 1)[-1]
    try:
        return int(suffix), event_id
    except ValueError:
        return 10**9, event_id


def _augment_candidate_support(
    path: CandidatePath,
    process_states: dict[str, ProcessState],
    object_states: dict[str, ObjectState],
    object_versions_by_object: dict[str, list[ObjectVersion]],
    retained_events: list[dict[str, Any]],
) -> None:
    event_lookup: dict[str, dict[str, Any]] = {}
    for event in retained_events:
        event_id = str(event.get("event_id", "")).strip()
        if event_id:
            event_lookup[event_id] = event

    path_process_set = set(path.process_chain)
    support_event_ids: set[str] = set()
    for process_guid in path.process_chain:
        state = process_states.get(process_guid)
        if state is None:
            continue
        for event_id in state.evidence_event_ids:
            text = str(event_id).strip()
            if text:
                support_event_ids.add(text)
    for edge in path.bridge_edges:
        for event_id in (edge.write_event_id, edge.read_or_exec_event_id):
            text = str(event_id).strip()
            if text:
                support_event_ids.add(text)
    for event in retained_events:
        process_guid = str(event.get("process_guid", "")).strip()
        if process_guid not in path_process_set:
            continue
        labels = event.get("path_labels_triggered", []) or event.get("labels_triggered", []) or []
        if not labels:
            continue
        event_id = str(event.get("event_id", "")).strip()
        if event_id:
            support_event_ids.add(event_id)
    ordered_event_ids = sorted(support_event_ids, key=lambda item: _event_order_key(item, event_lookup))

    support_object_keys: set[str] = set()
    for process_guid in path.process_chain:
        state = process_states.get(process_guid)
        if state is None:
            continue
        for object_key in state.important_objects:
            text = str(object_key).strip()
            if text:
                support_object_keys.add(text)
    for edge in path.bridge_edges:
        if str(edge.object_key).strip():
            support_object_keys.add(str(edge.object_key).strip())
    for event_id in ordered_event_ids:
        payload = event_lookup.get(event_id)
        if payload is None:
            continue
        object_key = str(payload.get("object_key", "")).strip()
        if object_key:
            support_object_keys.add(object_key)
    ordered_object_keys = sorted(support_object_keys)

    context_ids: set[str] = set()
    for process_guid in path.process_chain:
        state = process_states.get(process_guid)
        if state is None:
            continue
        context_ids.update({str(item).strip() for item in state.context_ids if str(item).strip()})
    for object_key in ordered_object_keys:
        state = object_states.get(object_key)
        if state is None:
            continue
        context_ids.update({str(item).strip() for item in state.context_ids if str(item).strip()})

    support_relations: list[str] = []
    for edge in path.bridge_edges:
        bridge_summary = (
            f"bridge: {edge.src_process_guid} -> {edge.dst_process_guid} "
            f"via {edge.object_key} [{edge.bridge_type}]"
        )
        if bridge_summary not in support_relations:
            support_relations.append(bridge_summary)
    for object_key in ordered_object_keys:
        versions = object_versions_by_object.get(object_key, [])
        for version in versions:
            if not (
                set(version.writer_processes).intersection(path_process_set)
                or set(version.reader_processes).intersection(path_process_set)
                or set(version.executor_processes).intersection(path_process_set)
            ):
                continue
            relation = (
                f"version: {version.object_key}@{version.version_id} "
                f"writers={len(version.writer_processes)} "
                f"readers={len(version.reader_processes)} "
                f"executors={len(version.executor_processes)}"
            )
            if relation not in support_relations:
                support_relations.append(relation)
            if len(support_relations) >= 12:
                break
        if len(support_relations) >= 12:
            break

    path.support_event_ids = ordered_event_ids
    path.support_object_keys = ordered_object_keys
    path.support_relations = support_relations[:12]
    path.context_ids = sorted(context_ids)
    path.chain_kind = _chain_kind_from_stages(path.stage_coverage)


def _support_compactness_score(path: CandidatePath, retained_events: list[dict[str, Any]]) -> tuple[float, str | None]:
    if len(path.support_event_ids) < 2:
        return 0.0, None
    event_lookup = {
        str(event.get("event_id", "")).strip(): event
        for event in retained_events
        if str(event.get("event_id", "")).strip()
    }
    timestamps = [
        parse_datetime(event_lookup[event_id].get("timestamp"))
        for event_id in path.support_event_ids
        if event_id in event_lookup
    ]
    timestamps = [item for item in timestamps if item is not None]
    if len(timestamps) < 2:
        return 0.0, None
    span_minutes = (max(timestamps) - min(timestamps)).total_seconds() / 60.0
    if span_minutes <= 5.0:
        return 2.0, f"support_compactness: support events stay within {span_minutes:.1f}m"
    if span_minutes <= 15.0:
        return 1.0, f"support_compactness: support events stay within {span_minutes:.1f}m"
    if span_minutes <= 45.0:
        return 0.0, None
    if span_minutes <= 90.0:
        return -1.0, f"support_compactness: support events span {span_minutes:.1f}m"
    if span_minutes <= 180.0:
        return -2.0, f"support_compactness: support events span {span_minutes:.1f}m"
    return -3.0, f"support_compactness: support events span {span_minutes:.1f}m"


def _provenance_density_score(path: CandidatePath, provenance_records: list[LabelProvenanceRecord]) -> tuple[float, str | None]:
    candidate_key_labels = {label for label in path.labels if is_provenance_key_label(label)}
    if not candidate_key_labels:
        return 0.0, None
    process_set = {str(item).strip() for item in path.process_chain if str(item).strip()}
    object_set = {str(item).strip() for item in path.support_object_keys if str(item).strip()}
    relevant_records = [
        record
        for record in provenance_records
        if (
            record.holder_entity_type == "process"
            and record.holder_entity_id in process_set
        )
        or (
            record.holder_entity_type == "object"
            and record.holder_entity_id in object_set
        )
    ]
    supported_key_labels = {
        record.label
        for record in relevant_records
        if record.label in candidate_key_labels and is_provenance_key_label(record.label)
    }
    ratio = len(supported_key_labels) / max(1, len(candidate_key_labels))
    if ratio >= 0.85:
        return 3.0, f"provenance_density: covered {len(supported_key_labels)}/{len(candidate_key_labels)} key labels"
    if ratio >= 0.6:
        return 1.5, f"provenance_density: covered {len(supported_key_labels)}/{len(candidate_key_labels)} key labels"
    if ratio >= 0.35:
        return 0.0, None
    if ratio > 0.0:
        return -1.5, f"provenance_density: covered only {len(supported_key_labels)}/{len(candidate_key_labels)} key labels"
    return -3.0, "provenance_density: no provenance support for path key labels"


def _support_coherence_score(path: CandidatePath) -> tuple[float, str | None]:
    object_count = len(path.support_object_keys)
    relation_count = len(path.support_relations)
    if object_count == 0 and relation_count == 0:
        return 0.0, None
    if object_count <= 3 and relation_count >= 1:
        return 1.0, f"support_coherence: {relation_count} relation(s) tie together {object_count} object(s)"
    if object_count <= 5 and relation_count >= max(1, object_count // 2):
        return 0.5, f"support_coherence: {relation_count} relation(s) tie together {object_count} object(s)"
    if object_count >= 8 and relation_count <= 1:
        return -2.0, f"support_coherence: {object_count} objects but only {relation_count} relation"
    if object_count >= 6 and relation_count <= 2:
        return -1.0, f"support_coherence: {object_count} objects but only {relation_count} relations"
    if object_count > max(1, relation_count) * 3:
        return -1.0, f"support_coherence: {object_count} objects spread across only {relation_count} relations"
    return 0.0, None


def _score_path_support_quality(
    path: CandidatePath,
    provenance_records: list[LabelProvenanceRecord],
    retained_events: list[dict[str, Any]],
    ) -> tuple[float, list[str]]:
    total = 0.0
    reasons: list[str] = []
    for scorer in (
        lambda: _support_compactness_score(path, retained_events),
        lambda: _provenance_density_score(path, provenance_records),
        lambda: _support_coherence_score(path),
    ):
        delta, reason = scorer()
        total += float(delta)
        if reason:
            reasons.append(reason)
    return total, reasons


def _risk_level_from_score(score: float, rules: Any) -> str:
    risk_levels = rules.get("path_search.risk_levels", {}) or {}
    if score >= float(risk_levels.get("high", 80.0) or 80.0):
        return "HIGH"
    if score >= float(risk_levels.get("medium", 50.0) or 50.0):
        return "MEDIUM"
    if score >= float(risk_levels.get("low", 30.0) or 30.0):
        return "LOW"
    return "INFO"


def _rerank_paths_with_provenance(
    paths: list[CandidatePath],
    provenance_records: list[LabelProvenanceRecord],
    retained_events: list[dict[str, Any]],
    rules: Any,
) -> dict[str, dict[str, Any]]:
    metadata: dict[str, dict[str, Any]] = {}
    for path in paths:
        raw_score, reasons = _score_path_support_quality(path, provenance_records, retained_events)
        adjustment = max(-4.0, min(4.0, raw_score))
        path.risk_score = max(0.0, float(path.risk_score) + adjustment)
        path.risk_level = _risk_level_from_score(path.risk_score, rules)
        metadata[path.path_id] = {
            "support_quality_score": float(raw_score),
            "support_quality_adjustment": float(adjustment),
            "support_quality_reasons": list(reasons),
        }
    paths.sort(key=lambda item: (-item.risk_score, -len(item.stage_coverage), item.path_id))
    return metadata


def run_module5_paths(cfg: FusionConfig) -> Dict[str, str]:
    rules = load_path_rules(cfg)
    ensure_dir(cfg.module5_paths_dir)
    ensure_dir(_bridge_dir(cfg))
    ensure_dir(_candidate_dir(cfg))
    compact_rows = _compact_index(cfg)
    priors = _load_priors(cfg)
    compact_row_by_task = {
        str(row.get("task_id", "")).strip(): row
        for row in compact_rows
        if isinstance(row, dict) and str(row.get("task_id", "")).strip()
    }
    parent_by_task = _parent_task_map(set(compact_row_by_task), priors)
    process_summary: list[dict[str, Any]] = []
    object_summary: list[dict[str, Any]] = []
    task_rows: list[dict[str, Any]] = []
    total_paths = 0
    total_bridges = 0
    resolved_process_states: dict[str, dict[str, ProcessState]] = {}
    active_tasks: set[str] = set()

    def process_task(task_id: str) -> None:
        nonlocal total_bridges, total_paths
        if task_id in resolved_process_states:
            return
        if task_id in active_tasks:
            raise ValueError(f"Detected cyclic split-task inheritance around task '{task_id}'")
        row = compact_row_by_task.get(task_id)
        if row is None:
            return
        active_tasks.add(task_id)
        try:
            parent_id = parent_by_task.get(task_id)
            if parent_id:
                process_task(parent_id)
            process_states = _load_process_states(Path(str(row.get("process_states_path", "")).strip()))
            object_states = _load_object_states(Path(str(row.get("object_states_path", "")).strip()))
            object_versions = _load_object_versions(Path(str(row.get("object_versions_path", "")).strip()))
            provenance_records = _load_label_provenance(Path(str(row.get("label_provenance_path", "")).strip()))
            retained_events = load_jsonl(Path(str(row.get("retained_events_path", "")).strip()))
            if parent_id:
                _inherit_parent_split_labels(
                    task_id,
                    process_states,
                    priors,
                    resolved_process_states.get(parent_id, {}),
                )
            event_labels = apply_full_path_labels(retained_events, process_states, object_states, rules)
            for event in retained_events:
                event_id = str(event.get("event_id", "")).strip()
                event["path_labels_triggered"] = sorted(event_labels.get(event_id, set()))
            propagate_status_labels(process_states, rules)
            bridges = build_bridge_edges(task_id, object_states, process_states, rules)
            for bridge in bridges:
                if bridge.object_labels.intersection({"O_FILE_DOWNLOADED", "O_FILE_UPLOADED", "O_SUSPECT_WRITTEN_EXECUTABLE"}):
                    if bridge.src_process_guid in process_states:
                        process_states[bridge.src_process_guid].aggregate_labels.add("A_BRIDGED_BY_SUSPICIOUS_OBJECT")
                    if bridge.dst_process_guid in process_states:
                        process_states[bridge.dst_process_guid].aggregate_labels.add("A_BRIDGED_BY_SUSPICIOUS_OBJECT")
            paths = search_candidate_paths(task_id, process_states, bridges, rules)
            prior = priors.get(task_id, TaskPrior(task_id=task_id, task_score=0.0, task_probability=0.0))
            paths = score_candidate_paths(paths, prior, rules)
            for path in paths:
                _augment_candidate_support(path, process_states, object_states, object_versions, retained_events)
            rerank_meta = _rerank_paths_with_provenance(paths, provenance_records, retained_events, rules)
            path_payloads: list[dict[str, Any]] = []
            markdown_chunks: list[str] = []
            for path in paths:
                dossier = build_path_dossier(cfg, path, process_states, object_states, retained_events)
                meta = rerank_meta.get(path.path_id, {})
                dossier["support_quality_score"] = float(meta.get("support_quality_score", 0.0) or 0.0)
                dossier["support_quality_adjustment"] = float(meta.get("support_quality_adjustment", 0.0) or 0.0)
                dossier["support_quality_reasons"] = list(meta.get("support_quality_reasons", []) or [])
                if not path.summary:
                    path.summary = _auto_summary(dossier)
                payload = path.to_dict()
                payload["support_quality_score"] = float(meta.get("support_quality_score", 0.0) or 0.0)
                payload["support_quality_adjustment"] = float(meta.get("support_quality_adjustment", 0.0) or 0.0)
                payload["support_quality_reasons"] = list(meta.get("support_quality_reasons", []) or [])
                payload["dossier"] = dossier
                path_payloads.append(payload)
                markdown_chunks.append(render_candidate_path_markdown(dossier))
            slug = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in task_id).strip("_") or task_id
            bridge_path = _bridge_dir(cfg) / f"{slug}.json"
            candidate_json_path = _candidate_dir(cfg) / f"{slug}.json"
            candidate_md_path = _candidate_dir(cfg) / f"{slug}.md"
            save_json(bridge_path, [edge.to_dict() for edge in bridges])
            save_json(candidate_json_path, path_payloads)
            candidate_md_path.write_text("\n\n".join(markdown_chunks).strip() + ("\n" if markdown_chunks else ""), encoding="utf-8")
            total_paths += len(paths)
            total_bridges += len(bridges)
            task_rows.append(
                {
                    "task_id": task_id,
                    "bridge_count": len(bridges),
                    "candidate_path_count": len(paths),
                    "bridge_path": str(bridge_path),
                    "candidate_paths_path": str(candidate_json_path),
                    "candidate_paths_markdown_path": str(candidate_md_path),
                }
            )
            process_summary.append(
                {
                    "task_id": task_id,
                    "process_count": len(process_states),
                    "suspicious_process_count": sum(
                        1
                        for state in process_states.values()
                        if state.behavior_labels or state.aggregate_labels or state.status_labels.intersection({"P_UNTRUSTED_CTX", "P_SUSPECT_CTRL_CTX"})
                    ),
                }
            )
            object_summary.append(
                {
                    "task_id": task_id,
                    "object_count": len(object_states),
                    "bridge_allowed_object_count": sum(1 for state in object_states.values() if state.is_bridge_allowed),
                }
            )
            resolved_process_states[task_id] = {
                key: copy.deepcopy(value)
                for key, value in process_states.items()
            }
        finally:
            active_tasks.remove(task_id)

    for row in compact_rows:
        task_id = str(row.get("task_id", "")).strip()
        if not task_id:
            continue
        process_task(task_id)

    save_json(_process_summary_path(cfg), process_summary)
    save_json(_object_summary_path(cfg), object_summary)
    save_json(
        _summary_path(cfg),
        {
            "task_count": len(task_rows),
            "candidate_path_count": total_paths,
            "bridge_count": total_bridges,
            "tasks": task_rows,
            "module4_summary_path": str(_module4_summary_path(cfg)),
        },
    )
    return {
        "summary": str(_summary_path(cfg)),
        "process_summary": str(_process_summary_path(cfg)),
        "object_summary": str(_object_summary_path(cfg)),
        "bridge_dir": str(_bridge_dir(cfg)),
        "candidate_dir": str(_candidate_dir(cfg)),
    }


def _auto_summary(dossier: dict[str, Any]) -> str:
    stages = ", ".join(dossier.get("stage_coverage", []))
    core = ", ".join(str(item.get("name", "")) for item in dossier.get("core_processes", [])[:3])
    if stages and core:
        return f"Candidate attack path covering {stages} through processes: {core}."
    if stages:
        return f"Candidate attack path covering {stages}."
    return "Candidate attack path."

