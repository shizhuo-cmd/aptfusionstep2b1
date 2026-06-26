from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

from ..common import ensure_dir, iter_jsonl, save_json
from ..config import FusionConfig
from .evidence_normalizer import (
    build_task_priors,
    extract_result,
    infer_object_name,
    infer_process_cmdline,
    infer_process_exe,
    infer_process_name,
    infer_semantic_flow_direction,
    infer_syscall_direction,
    normalize_event_type,
    normalize_object_key,
    parse_flow_endpoints,
    timestamp_to_epoch_seconds,
)
from .log_stream import (
    _ProcessAliasState,
    _SubgraphMeta,
    _build_process_alias_state,
    _build_seed_frontier,
    _event_identity,
    _extract_event_with_aliases,
    _extract_json_fragment,
    _extract_node_records_with_aliases,
    _iter_lines,
    _iter_log_files,
    _load_subgraph_meta,
    _match_frontier_subgraphs,
    _render_node,
    _scan_node_attributes_with_aliases,
)
from .object_classifier import classify_object
from .path_rules import load_path_rules
from .path_schemas import NormalizedEvent, TaskLocalEvidenceGraph, TaskPrior, parse_datetime


@dataclass
class _TaskScanState:
    meta: _SubgraphMeta
    path: Path
    handle: Any
    order_index: int = 0
    event_count: int = 0
    dropped_due_to_limit: int = 0
    first_timestamp: datetime | None = None
    last_timestamp: datetime | None = None
    observed_process_guids: set[str] | None = None
    seen_identities: set[tuple[str, str, str, str, str, str]] | None = None

    def __post_init__(self) -> None:
        if self.observed_process_guids is None:
            self.observed_process_guids = set()
        if self.seen_identities is None:
            self.seen_identities = set()


_UUID_LIKE_PATTERN = re.compile(
    r"^[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$"
)


def _task_index_path(cfg: FusionConfig) -> Path:
    return cfg.module3_evidence_dir / "task_index.json"


def _summary_path(cfg: FusionConfig) -> Path:
    return cfg.module3_evidence_dir / "summary.json"


def _priors_path(cfg: FusionConfig) -> Path:
    return cfg.module3_evidence_dir / "priors_by_task.json"


def _id_mapping_path(cfg: FusionConfig) -> Path:
    return cfg.module3_evidence_dir / "id_mapping.json"


def _normalized_events_dir(cfg: FusionConfig) -> Path:
    return cfg.module3_evidence_dir / "normalized_events"


def _entity_index_dir(cfg: FusionConfig) -> Path:
    return cfg.module3_evidence_dir / "entity_index"


def _process_event_index_dir(cfg: FusionConfig) -> Path:
    return cfg.module3_evidence_dir / "process_event_index"


def _object_event_index_dir(cfg: FusionConfig) -> Path:
    return cfg.module3_evidence_dir / "object_event_index"


def _task_evidence_frontier_dir(cfg: FusionConfig) -> Path:
    return cfg.module3_evidence_dir / "task_evidence_frontier"


def _task_local_evidence_graph_dir(cfg: FusionConfig) -> Path:
    return cfg.module3_evidence_dir / "task_local_evidence_graph"

def _task_slug(task_id: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in str(task_id)).strip("_") or "task"


def _node_cache_key(uuid: str) -> str:
    return str(uuid or "").strip()


def _update_time_range(state: _TaskScanState, timestamp: datetime | None) -> None:
    if timestamp is None:
        return
    if state.first_timestamp is None or timestamp < state.first_timestamp:
        state.first_timestamp = timestamp
    if state.last_timestamp is None or timestamp > state.last_timestamp:
        state.last_timestamp = timestamp


def _prepare_task_states(cfg: FusionConfig, metas: List[_SubgraphMeta]) -> dict[int, _TaskScanState]:
    out_dir = _normalized_events_dir(cfg)
    ensure_dir(out_dir)
    for stale in out_dir.glob("*.jsonl"):
        stale.unlink(missing_ok=True)
    states: dict[int, _TaskScanState] = {}
    for meta in metas:
        slug = _task_slug(meta.task_id)
        path = out_dir / f"{slug}.jsonl"
        states[meta.subgraph_id] = _TaskScanState(meta=meta, path=path, handle=path.open("w", encoding="utf-8"))
    return states


def _close_task_states(states: dict[int, _TaskScanState]) -> None:
    for state in states.values():
        state.handle.close()


def _build_task_local_outputs(
    task_id: str,
    path: Path,
    prior: TaskPrior,
) -> tuple[dict[str, Any], dict[str, list[str]], dict[str, list[str]], dict[str, Any], TaskLocalEvidenceGraph]:
    process_nodes: dict[str, dict[str, Any]] = {}
    object_nodes: dict[str, dict[str, Any]] = {}
    process_event_index: dict[str, list[str]] = {}
    object_event_index: dict[str, list[str]] = {}
    event_edges: list[dict[str, Any]] = []

    for payload in iter_jsonl(path):
        event = NormalizedEvent.from_dict(dict(payload))
        process_node = process_nodes.setdefault(
            event.process_guid,
            {
                "process_guid": event.process_guid,
                "process_name": event.process_name,
                "process_exe": event.process_exe,
                "process_cmdline": event.process_cmdline,
                "parent_process_guid": event.parent_process_guid,
                "first_time": event.timestamp.isoformat() if event.timestamp else "",
                "last_time": event.timestamp.isoformat() if event.timestamp else "",
                "event_count": 0,
            },
        )
        process_node["event_count"] = int(process_node.get("event_count", 0) or 0) + 1
        if event.timestamp:
            first_time = str(process_node.get("first_time", "")).strip()
            if not first_time or event.timestamp.isoformat() < first_time:
                process_node["first_time"] = event.timestamp.isoformat()
            last_time = str(process_node.get("last_time", "")).strip()
            if not last_time or event.timestamp.isoformat() > last_time:
                process_node["last_time"] = event.timestamp.isoformat()
        process_event_index.setdefault(event.process_guid, []).append(event.event_id)

        if event.object_type != "process":
            object_node = object_nodes.setdefault(
                event.object_key,
                {
                    "object_key": event.object_key,
                    "object_type": event.object_type,
                    "object_name": event.object_name,
                    "object_class": event.object_class,
                    "first_time": event.timestamp.isoformat() if event.timestamp else "",
                    "last_time": event.timestamp.isoformat() if event.timestamp else "",
                    "event_count": 0,
                },
            )
            object_node["event_count"] = int(object_node.get("event_count", 0) or 0) + 1
            if event.timestamp:
                first_time = str(object_node.get("first_time", "")).strip()
                if not first_time or event.timestamp.isoformat() < first_time:
                    object_node["first_time"] = event.timestamp.isoformat()
                last_time = str(object_node.get("last_time", "")).strip()
                if not last_time or event.timestamp.isoformat() > last_time:
                    object_node["last_time"] = event.timestamp.isoformat()
            object_event_index.setdefault(event.object_key, []).append(event.event_id)

        event_edges.append(
            {
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat() if event.timestamp else "",
                "process_guid": event.process_guid,
                "object_key": event.object_key,
                "object_type": event.object_type,
                "event_type": event.event_type,
                "object_class": event.object_class,
                "semantic_flow_direction": event.semantic_flow_direction,
                "raw_log_id": event.raw_log_id,
            }
        )

    anchor_processes = list(prior.root_process_ids)
    if not anchor_processes and str(prior.task_root_id).strip():
        anchor_processes = [str(prior.task_root_id).strip()]
    frontier = {
        "task_id": task_id,
        "anchor_processes": anchor_processes,
        "boundary_node_ids": list(prior.boundary_node_ids),
        "cross_task_link_refs": (
            [{"kind": "split_root", "process_guid": str(prior.task_root_id).strip()}]
            if str(prior.task_root_id).strip()
            else []
        ),
    }
    graph = TaskLocalEvidenceGraph(
        task_id=task_id,
        process_nodes=sorted(process_nodes),
        object_nodes=sorted(object_nodes),
        event_edges=event_edges,
        anchor_processes=list(frontier["anchor_processes"]),
        boundary_node_ids=list(frontier["boundary_node_ids"]),
        cross_task_link_refs=list(frontier["cross_task_link_refs"]),
    )
    entity_index = {
        "task_id": task_id,
        "processes": [process_nodes[key] for key in sorted(process_nodes)],
        "objects": [object_nodes[key] for key in sorted(object_nodes)],
    }
    return entity_index, process_event_index, object_event_index, frontier, graph


def _raw_parent_process_guid(
    cfg: FusionConfig,
    raw_obj: dict[str, Any],
    alias_state: _ProcessAliasState,
) -> str | None:
    if cfg.dataset_family == "optc":
        value = raw_obj.get("parentSubjectID") or raw_obj.get("parentSubjectId")
        return str(value).strip() if value not in (None, "") else None
    datum = raw_obj.get("datum")
    if not isinstance(datum, dict):
        return None
    subject = datum.get("com.bbn.tc.schema.avro.cdm18.Subject")
    if not isinstance(subject, dict):
        event_subject = None
        event = datum.get("com.bbn.tc.schema.avro.cdm18.Event")
        if isinstance(event, dict) and isinstance(event.get("subject"), dict):
            event_subject = event["subject"].get("com.bbn.tc.schema.avro.cdm18.UUID")
        subject_guid = alias_state.raw_to_canonical.get(str(event_subject or "").strip(), str(event_subject or "").strip())
        return alias_state.canonical_parent.get(subject_guid) if subject_guid else None
    parent = subject.get("parentSubject")
    if not isinstance(parent, dict):
        subject_uuid = subject.get("uuid") or subject.get("com.bbn.tc.schema.avro.cdm18.UUID")
        subject_guid = alias_state.raw_to_canonical.get(str(subject_uuid or "").strip(), str(subject_uuid or "").strip())
        return alias_state.canonical_parent.get(subject_guid) if subject_guid else None
    parent_uuid = parent.get("com.bbn.tc.schema.avro.cdm18.UUID") or parent.get("uuid")
    if isinstance(parent_uuid, dict):
        for value in parent_uuid.values():
            if value:
                parent_uuid = value
                break
    text = str(parent_uuid or "").strip()
    if not text:
        subject_uuid = subject.get("uuid") or subject.get("com.bbn.tc.schema.avro.cdm18.UUID")
        subject_guid = alias_state.raw_to_canonical.get(str(subject_uuid or "").strip(), str(subject_uuid or "").strip())
        return alias_state.canonical_parent.get(subject_guid) if subject_guid else None
    return alias_state.raw_to_canonical.get(text, text)


def _normalized_event_from_match(
    cfg: FusionConfig,
    *,
    task_id: str,
    event: Any,
    line_nodes: dict[str, Any],
    node_cache: dict[str, Any],
    raw_obj: dict[str, Any],
    alias_state: _ProcessAliasState,
    rules: Any,
    order_index: int,
    raw_log_id: str,
) -> NormalizedEvent:
    subject_type, subject_attr = _render_node(
        event.subject_uuid,
        line_nodes.get(event.subject_uuid) or node_cache.get(event.subject_uuid),
        default_type="process",
    )
    object_type, object_attr = _render_node(
        event.object_uuid,
        line_nodes.get(event.object_uuid) or node_cache.get(event.object_uuid),
        default_type=str(event.object_type_hint or "object"),
        fallback_attr=str(event.object_attr_hint or ""),
    )
    event_type = normalize_event_type(event.action, rules)
    process_exe = infer_process_exe(subject_attr)
    process_name = infer_process_name(subject_attr, process_exe)
    process_cmdline = infer_process_cmdline(subject_attr)
    object_key = event.object_uuid if object_type == "process" else normalize_object_key(object_type, object_attr, event.object_uuid)
    object_name = object_attr if object_type == "process" else infer_object_name(object_key)
    object_class = classify_object(object_type, object_key, rules)
    local_ip, local_port, remote_ip, remote_port = parse_flow_endpoints(object_key if object_type == "flow" else object_attr)
    timestamp = _event_time(event.timestamp)
    process_guid = str(event.subject_uuid).strip()
    if process_guid in alias_state.canonical_attr and not str(subject_attr or "").strip():
        subject_attr = alias_state.canonical_attr[process_guid]
        process_exe = infer_process_exe(subject_attr)
        process_name = infer_process_name(subject_attr, process_exe)
        process_cmdline = infer_process_cmdline(subject_attr)
    return NormalizedEvent(
        event_id=f"{task_id}:{order_index:08d}",
        raw_log_id=raw_log_id,
        task_id=task_id,
        host=cfg.host,
        timestamp=timestamp,
        order_index=order_index,
        process_guid=process_guid,
        process_name=process_name,
        process_exe=process_exe,
        process_cmdline=process_cmdline,
        parent_process_guid=_raw_parent_process_guid(cfg, raw_obj, alias_state),
        event_type=event_type,
        object_type=str(object_type).strip(),
        object_key=object_key,
        object_name=object_name,
        object_class=object_class,
        syscall_direction=infer_syscall_direction(event_type, object_type, rules),
        semantic_flow_direction=infer_semantic_flow_direction(event_type, object_type, rules),
        result=extract_result(raw_obj),
        local_ip=local_ip,
        local_port=local_port,
        remote_ip=remote_ip,
        remote_port=remote_port,
        raw_event=raw_obj,
    )


def _event_time(value: Any) -> datetime | None:
    seconds = timestamp_to_epoch_seconds(value)
    if seconds is None:
        return parse_datetime(value)
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


def _looks_like_placeholder_process_name(name: str, process_guid: str) -> bool:
    text = str(name or "").strip()
    guid = str(process_guid or "").strip()
    if not text:
        return True
    if text == guid:
        return True
    return text.isdigit()


def _needs_object_attr_refresh(payload: dict[str, Any]) -> bool:
    object_key = str(payload.get("object_key", "")).strip()
    if not object_key:
        return False
    object_type = str(payload.get("object_type", "")).strip().lower()
    object_class = str(payload.get("object_class", "")).strip().lower()
    if object_type == "process":
        return False
    if object_type in {"object", ""} or object_class in {"object", ""}:
        return True
    return bool(_UUID_LIKE_PATTERN.fullmatch(object_key))


def _collect_needed_node_ids(states: dict[int, _TaskScanState]) -> set[str]:
    needed: set[str] = set()
    for state in states.values():
        if not state.path.exists():
            continue
        for payload in iter_jsonl(state.path):
            process_guid = str(payload.get("process_guid", "")).strip()
            if process_guid:
                needed.add(process_guid)
            object_key = str(payload.get("object_key", "")).strip()
            if _needs_object_attr_refresh(payload) and object_key:
                needed.add(object_key)
    return needed


def _refresh_normalized_events(
    cfg: FusionConfig,
    states: dict[int, _TaskScanState],
    alias_state: _ProcessAliasState,
    rules: Any,
) -> None:
    needed = _collect_needed_node_ids(states)
    if not needed:
        return
    node_cache = _scan_node_attributes_with_aliases(cfg, needed, alias_state)
    for state in states.values():
        if not state.path.exists():
            continue
        temp_path = state.path.with_suffix(".tmp")
        with state.path.open("r", encoding="utf-8") as src, temp_path.open("w", encoding="utf-8") as dst:
            for line in src:
                payload = json.loads(line)
                process_guid = str(payload.get("process_guid", "")).strip()
                process_attr = ""
                process_node = node_cache.get(process_guid)
                if process_node is not None and str(process_node.node_attr or "").strip():
                    process_attr = str(process_node.node_attr).strip()
                elif process_guid in alias_state.canonical_attr:
                    process_attr = str(alias_state.canonical_attr[process_guid]).strip()
                if process_attr:
                    process_exe = infer_process_exe(process_attr)
                    process_name = infer_process_name(process_attr, process_exe)
                    process_cmdline = infer_process_cmdline(process_attr)
                    if _looks_like_placeholder_process_name(str(payload.get("process_name", "")), process_guid):
                        payload["process_name"] = process_name
                    if process_exe and not str(payload.get("process_exe", "")).strip():
                        payload["process_exe"] = process_exe
                    if process_cmdline and not str(payload.get("process_cmdline", "")).strip():
                        payload["process_cmdline"] = process_cmdline
                if not str(payload.get("parent_process_guid", "")).strip():
                    parent_guid = alias_state.canonical_parent.get(process_guid)
                    if parent_guid:
                        payload["parent_process_guid"] = parent_guid

                object_key = str(payload.get("object_key", "")).strip()
                object_node = node_cache.get(object_key)
                if object_node is not None and _needs_object_attr_refresh(payload):
                    object_type = str(object_node.node_type or payload.get("object_type", "")).strip() or "object"
                    object_attr = str(object_node.node_attr or "").strip()
                    new_key = normalize_object_key(object_type, object_attr, object_key)
                    payload["object_type"] = object_type
                    payload["object_key"] = new_key
                    payload["object_name"] = infer_object_name(new_key)
                    payload["object_class"] = classify_object(object_type, new_key, rules)
                    local_ip, local_port, remote_ip, remote_port = parse_flow_endpoints(
                        new_key if object_type == "flow" else object_attr
                    )
                    payload["local_ip"] = local_ip
                    payload["local_port"] = local_port
                    payload["remote_ip"] = remote_ip
                    payload["remote_port"] = remote_port
                dst.write(json.dumps(payload, ensure_ascii=False) + "\n")
        temp_path.replace(state.path)


def _load_task_sidecar_lookups(cfg: FusionConfig) -> tuple[Path, Path, Path]:
    return (
        cfg.module2_dir / "suspicious_tasks.json",
        cfg.module2_dir / "task_meta_rich.json",
        cfg.module2_dir / "task_attribution.json",
    )


def _module1_gt_selection_sidecars_dir(cfg: FusionConfig) -> Path:
    return cfg.module3_evidence_dir / "_module1_gt_selection_sidecars"


def _load_module1_native_bundle(module1_dir: Path) -> dict[str, Any]:
    from ..task_detection.tapas_native_backend import _load_native_bundle

    return _load_native_bundle(module1_dir)


def _normalize_ref_to_process_id(value: Any, process_ids: list[str]) -> str:
    if isinstance(value, int):
        index = int(value)
        if 0 <= index < len(process_ids):
            return process_ids[index]
        return ""
    text = str(value).strip()
    if not text:
        return ""
    if text.isdigit():
        index = int(text)
        if 0 <= index < len(process_ids):
            return process_ids[index]
    if text in process_ids:
        return text
    return ""


def _edge_rows_for_graph(graph: dict[str, Any], process_ids: list[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for edge in graph.get("edges", []) or []:
        if not isinstance(edge, (list, tuple)) or len(edge) < 2:
            continue
        src = _normalize_ref_to_process_id(edge[0], process_ids)
        dst = _normalize_ref_to_process_id(edge[1], process_ids)
        if src and dst:
            rows.append({"src": src, "dst": dst})
    return rows


def _task_root_leaf_ids(
    process_ids: list[str],
    local_edges: list[dict[str, str]],
) -> tuple[list[str], list[str], dict[str, int], dict[str, int], dict[str, set[str]]]:
    indegree = {pid: 0 for pid in process_ids}
    outdegree = {pid: 0 for pid in process_ids}
    neighbors = {pid: set() for pid in process_ids}

    for edge in local_edges:
        src = edge["src"]
        dst = edge["dst"]
        outdegree[src] = outdegree.get(src, 0) + 1
        indegree[dst] = indegree.get(dst, 0) + 1
        neighbors.setdefault(src, set()).add(dst)
        neighbors.setdefault(dst, set()).add(src)

    root_process_ids = sorted([pid for pid in process_ids if outdegree.get(pid, 0) == 0])
    leaf_process_ids = sorted([pid for pid in process_ids if indegree.get(pid, 0) == 0])
    return root_process_ids, leaf_process_ids, indegree, outdegree, neighbors


def _safe_l2(values: Any) -> float:
    total = 0.0
    for value in list(values or []):
        try:
            number = float(value)
        except (TypeError, ValueError):
            continue
        total += number * number
    return total ** 0.5


def _prepare_module1_gt_selection_sidecars(cfg: FusionConfig) -> tuple[Path, Path, Path]:
    bundle = _load_module1_native_bundle(cfg.module1_dir)
    graphs = list(bundle.get("selected_graphs", []))
    metas = list(bundle.get("selected_graph_metas", []))
    sidecar_dir = _module1_gt_selection_sidecars_dir(cfg)
    ensure_dir(sidecar_dir)

    suspicious_rows: list[dict[str, Any]] = []
    meta_rows: list[dict[str, Any]] = []
    attribution_rows: list[dict[str, Any]] = []

    for graph, meta in zip(graphs, metas):
        task_id = str(meta.get("task_id", "")).strip()
        if not task_id or re.search(r"_aug\d{3}$", task_id):
            continue
        label = int(meta.get("label", graph.get("label", 0)) or 0)
        if label != 1:
            continue

        process_ids = [str(node) for node in meta.get("node_ids", [])]
        local_edges = _edge_rows_for_graph(graph, process_ids)
        root_process_ids, leaf_process_ids, indegree, outdegree, neighbors = _task_root_leaf_ids(
            process_ids,
            local_edges,
        )
        degree = {pid: indegree.get(pid, 0) + outdegree.get(pid, 0) for pid in process_ids}
        bridge_degree = {pid: len(neighbors.get(pid, set())) for pid in process_ids}
        raw_nodes = list(graph.get("nodes", []) or [])
        feature_norms = {
            pid: _safe_l2(raw_nodes[index]) if index < len(raw_nodes) else 0.0
            for index, pid in enumerate(process_ids)
        }
        max_feature_norm = max(feature_norms.values(), default=0.0) or 1.0
        max_degree = max(degree.values(), default=0) or 1
        max_bridge = max(bridge_degree.values(), default=0) or 1
        node_scores: dict[str, float] = {}
        for pid in process_ids:
            root_bonus = 1.0 if pid in root_process_ids else 0.0
            node_scores[pid] = (
                0.45 * (feature_norms.get(pid, 0.0) / max_feature_norm)
                + 0.25 * (float(degree.get(pid, 0)) / float(max_degree))
                + 0.15 * (float(bridge_degree.get(pid, 0)) / float(max_bridge))
                + 0.15 * root_bonus
            )

        top_processes = sorted(
            [
                {
                    "process_id": pid,
                    "score": float(node_scores.get(pid, 0.0)),
                    "feature_norm": float(feature_norms.get(pid, 0.0)),
                    "degree": int(degree.get(pid, 0)),
                    "in_degree": int(indegree.get(pid, 0)),
                    "out_degree": int(outdegree.get(pid, 0)),
                    "neighbor_count": int(bridge_degree.get(pid, 0)),
                    "is_root": pid in root_process_ids,
                    "is_leaf": pid in leaf_process_ids,
                }
                for pid in process_ids
            ],
            key=lambda item: (float(item["score"]), item["process_id"]),
            reverse=True,
        )
        top_edges = sorted(
            [
                {
                    "src": edge["src"],
                    "dst": edge["dst"],
                    "score": float(
                        (node_scores.get(edge["src"], 0.0) + node_scores.get(edge["dst"], 0.0)) / 2.0
                    ),
                }
                for edge in local_edges
            ],
            key=lambda item: (float(item["score"]), item["src"], item["dst"]),
            reverse=True,
        )
        task_root_id = str(meta.get("task_root_id", "")).strip() or (root_process_ids[0] if root_process_ids else "")
        graph_density = 0.0
        if len(process_ids) > 1:
            graph_density = float(len(local_edges)) / float(len(process_ids) * (len(process_ids) - 1))

        suspicious_rows.append(
            {
                "task_id": task_id,
                "task_score": 1.0,
                "task_probability": 1.0,
                "graphsage_probability": 1.0,
                "stats_probability": None,
                "task_label": 1,
                "predicted_label": 1,
                "prediction_mode": "ground_truth_direct",
                "task_size": int(meta.get("task_size", len(process_ids))),
                "internal_edge_count": int(meta.get("internal_edge_count", len(local_edges))),
                "graph_edge_source": "tapas_parent_child_edges",
                "task_score_basis": "module1_ground_truth_direct",
                "fusion_weight_stats": 0.0,
                "threshold_used": None,
                "is_suspicious": True,
                "process_ids": process_ids,
            }
        )
        meta_rows.append(
            {
                "task_id": task_id,
                "task_score": 1.0,
                "task_probability": 1.0,
                "graphsage_probability": 1.0,
                "stats_probability": None,
                "task_size": int(meta.get("task_size", len(process_ids))),
                "internal_edge_count": int(meta.get("internal_edge_count", len(local_edges))),
                "graph_task_id": task_id,
                "task_root_id": task_root_id,
                "boundary_node_ids": [str(item) for item in meta.get("boundary_node_ids", [])],
                "process_ids": process_ids,
                "root_process_ids": root_process_ids,
                "leaf_process_ids": leaf_process_ids,
                "local_edges": local_edges,
                "graph_density": graph_density,
                "prediction_mode": "ground_truth_direct",
                "is_suspicious": True,
            }
        )
        attribution_rows.append(
            {
                "task_id": task_id,
                "graph_task_id": task_id,
                "top_processes": top_processes[: min(12, len(top_processes))],
                "top_edges": top_edges[: min(12, len(top_edges))],
                "root_process_ids": root_process_ids,
                "leaf_process_ids": leaf_process_ids,
                "graph_density": graph_density,
            }
        )

    suspicious_path = sidecar_dir / "suspicious_tasks.json"
    task_meta_rich_path = sidecar_dir / "task_meta_rich.json"
    task_attribution_path = sidecar_dir / "task_attribution.json"
    summary_path = sidecar_dir / "summary.json"
    save_json(suspicious_path, suspicious_rows)
    save_json(task_meta_rich_path, meta_rows)
    save_json(task_attribution_path, attribution_rows)
    save_json(
        summary_path,
        {
            "selection_mode": "module1_ground_truth_positive_base_only",
            "task_count": len(suspicious_rows),
            "module1_dir": str(cfg.module1_dir),
            "sidecar_dir": str(sidecar_dir),
        },
    )
    return suspicious_path, task_meta_rich_path, task_attribution_path


def run_module3_evidence(
    cfg: FusionConfig,
    suspicious_tasks_path: Path | None = None,
    task_meta_rich_path: Path | None = None,
    task_attribution_path: Path | None = None,
) -> Dict[str, str]:
    rules = load_path_rules(cfg)
    if str(cfg.module3_task_selection_mode).strip() == "module1_ground_truth_positive_base_only":
        suspicious_tasks_path, task_meta_rich_path, task_attribution_path = _prepare_module1_gt_selection_sidecars(
            cfg
        )
    elif suspicious_tasks_path is None or task_meta_rich_path is None or task_attribution_path is None:
        suspicious_default, rich_default, attr_default = _load_task_sidecar_lookups(cfg)
        suspicious_tasks_path = suspicious_tasks_path or suspicious_default
        task_meta_rich_path = task_meta_rich_path or rich_default
        task_attribution_path = task_attribution_path or attr_default

    out_dir = cfg.module3_evidence_dir
    ensure_dir(out_dir)
    for folder in [
        _entity_index_dir(cfg),
        _process_event_index_dir(cfg),
        _object_event_index_dir(cfg),
        _task_evidence_frontier_dir(cfg),
        _task_local_evidence_graph_dir(cfg),
    ]:
        ensure_dir(folder)
    metas = _load_subgraph_meta(cfg, suspicious_tasks_path)
    priors = build_task_priors(cfg, suspicious_tasks_path, task_meta_rich_path, task_attribution_path)
    if not metas:
        save_json(_task_index_path(cfg), [])
        save_json(_priors_path(cfg), {})
        save_json(_id_mapping_path(cfg), [])
        save_json(
            _summary_path(cfg),
            {
                "task_count": 0,
                "normalized_event_count_total": 0,
                "selected_mode": cfg.module3_task_selection_mode,
                "normalized_events_dir": str(_normalized_events_dir(cfg)),
            },
        )
        return {
            "task_index": str(_task_index_path(cfg)),
            "priors_by_task": str(_priors_path(cfg)),
            "id_mapping": str(_id_mapping_path(cfg)),
            "summary": str(_summary_path(cfg)),
            "normalized_events_dir": str(_normalized_events_dir(cfg)),
            "entity_index_dir": str(_entity_index_dir(cfg)),
            "process_event_index_dir": str(_process_event_index_dir(cfg)),
            "object_event_index_dir": str(_object_event_index_dir(cfg)),
            "task_evidence_frontier_dir": str(_task_evidence_frontier_dir(cfg)),
            "task_local_evidence_graph_dir": str(_task_local_evidence_graph_dir(cfg)),
        }

    states = _prepare_task_states(cfg, metas)
    seed_frontier = _build_seed_frontier(metas)
    alias_state = _build_process_alias_state(cfg)
    node_cache: dict[str, Any] = {}
    meta_map = {meta.subgraph_id: meta for meta in metas}
    frontier_map = {uuid: set(ids) for uuid, ids in seed_frontier.items()}
    include_object_side = bool(cfg.evidence_recover_include_object_side)
    max_events = max(1, int(cfg.evidence_recover_max_events_per_task))
    try:
        for hop_idx in range(max(1, int(cfg.local_context_hops))):
            if not frontier_map:
                break
            next_frontier: dict[str, set[int]] = {}
            for log_file in _iter_log_files(cfg.source_logs, cfg.host):
                for line_no, line in enumerate(_iter_lines(log_file), start=1):
                    event = _extract_event_with_aliases(cfg, line, alias_state.raw_to_canonical)
                    if event is None:
                        continue
                    matched_subgraphs = _match_frontier_subgraphs(
                        event,
                        frontier_map,
                        include_object_side=include_object_side,
                    )
                    if not matched_subgraphs:
                        continue
                    identity = _event_identity(event)
                    raw_obj = _extract_json_fragment(line) or {"raw_line": line[:2000]}
                    line_nodes = {
                        _node_cache_key(uuid): attr
                        for uuid, attr in _extract_node_records_with_aliases(
                            cfg,
                            line,
                            alias_state.raw_to_canonical,
                        )
                    }
                    node_cache.update(line_nodes)
                    raw_log_id = f"{log_file.name}:{line_no}"
                    for subgraph_id in matched_subgraphs:
                        state = states.get(subgraph_id)
                        if state is None:
                            continue
                        if identity in state.seen_identities:
                            continue
                        state.seen_identities.add(identity)
                        if state.event_count >= max_events:
                            state.dropped_due_to_limit += 1
                            continue
                        state.order_index += 1
                        normalized = _normalized_event_from_match(
                            cfg,
                            task_id=state.meta.task_id,
                            event=event,
                            line_nodes=line_nodes,
                            node_cache=node_cache,
                            raw_obj=raw_obj,
                            alias_state=alias_state,
                            rules=rules,
                            order_index=state.order_index,
                            raw_log_id=raw_log_id,
                        )
                        state.handle.write(json.dumps(normalized.to_dict(), ensure_ascii=False) + "\n")
                        state.event_count += 1
                        state.observed_process_guids.add(normalized.process_guid)
                        if normalized.object_type == "process":
                            state.observed_process_guids.add(normalized.object_key)
                        _update_time_range(state, normalized.timestamp)
                        if hop_idx + 1 < max(1, int(cfg.local_context_hops)):
                            for uuid in filter(None, [normalized.process_guid, normalized.object_key if normalized.object_type == "process" else ""]):
                                next_frontier.setdefault(uuid, set()).add(subgraph_id)
            frontier_map = next_frontier
    finally:
        _close_task_states(states)

    _refresh_normalized_events(cfg, states, alias_state, rules)

    task_index_rows: list[dict[str, Any]] = []
    priors_payload: dict[str, Any] = {}
    id_mapping_rows: list[dict[str, Any]] = []
    total_events = 0
    total_unmapped_seed = 0
    total_unmapped_top = 0
    for meta in metas:
        state = states[meta.subgraph_id]
        total_events += state.event_count
        prior = priors.get(meta.task_id, TaskPrior(task_id=meta.task_id, task_score=meta.task_score, task_probability=meta.task_score))
        prior.first_event = state.first_timestamp or prior.first_event
        prior.last_event = state.last_timestamp or prior.last_event
        prior.matched_event_count_total = state.event_count
        priors_payload[meta.task_id] = prior.to_dict()

        process_id_to_guid: dict[str, str] = {}
        unmapped_seed = 0
        for process_id in meta.process_ids:
            if process_id in state.observed_process_guids:
                process_id_to_guid[process_id] = process_id
            else:
                unmapped_seed += 1
        unmapped_top = 0
        top_processes = list(prior.top_processes)
        for item in top_processes:
            process_id = str(item.get("process_id", "")).strip()
            if not process_id:
                continue
            if process_id in process_id_to_guid:
                continue
            if process_id in state.observed_process_guids:
                process_id_to_guid[process_id] = process_id
            else:
                unmapped_top += 1
        total_unmapped_seed += unmapped_seed
        total_unmapped_top += unmapped_top
        id_mapping_rows.append(
            {
                "task_id": meta.task_id,
                "process_id_to_process_guid": process_id_to_guid,
                "unmapped_seed_process_count": unmapped_seed,
                "unmapped_top_process_count": unmapped_top,
            }
        )
        slug = _task_slug(meta.task_id)
        entity_index, process_event_index, object_event_index, frontier, graph = _build_task_local_outputs(
            meta.task_id,
            state.path,
            prior,
        )
        entity_index_path = _entity_index_dir(cfg) / f"{slug}.json"
        process_event_index_path = _process_event_index_dir(cfg) / f"{slug}.json"
        object_event_index_path = _object_event_index_dir(cfg) / f"{slug}.json"
        task_evidence_frontier_path = _task_evidence_frontier_dir(cfg) / f"{slug}.json"
        task_local_evidence_graph_path = _task_local_evidence_graph_dir(cfg) / f"{slug}.json"
        save_json(entity_index_path, entity_index)
        save_json(process_event_index_path, process_event_index)
        save_json(object_event_index_path, object_event_index)
        save_json(task_evidence_frontier_path, frontier)
        save_json(task_local_evidence_graph_path, graph.to_dict())
        task_index_rows.append(
            {
                "subgraph_id": int(meta.subgraph_id),
                "task_id": meta.task_id,
                "task_score": float(meta.task_score),
                "severity_level": meta.severity_level,
                "event_count": int(state.event_count),
                "dropped_due_to_limit": int(state.dropped_due_to_limit),
                "first_timestamp": state.first_timestamp.isoformat() if state.first_timestamp else "",
                "last_timestamp": state.last_timestamp.isoformat() if state.last_timestamp else "",
                "normalized_events_path": str(state.path),
                "observed_process_count": len(state.observed_process_guids),
                "root_process_ids": list(prior.root_process_ids),
                "entity_index_path": str(entity_index_path),
                "process_event_index_path": str(process_event_index_path),
                "object_event_index_path": str(object_event_index_path),
                "task_evidence_frontier_path": str(task_evidence_frontier_path),
                "task_local_evidence_graph_path": str(task_local_evidence_graph_path),
            }
        )

    save_json(_task_index_path(cfg), task_index_rows)
    save_json(_priors_path(cfg), priors_payload)
    save_json(_id_mapping_path(cfg), id_mapping_rows)
    save_json(
        _summary_path(cfg),
        {
            "task_count": len(task_index_rows),
            "normalized_event_count_total": int(total_events),
            "selected_mode": cfg.module3_task_selection_mode,
            "include_object_side": include_object_side,
            "max_events_per_task": max_events,
            "local_context_hops": int(cfg.local_context_hops),
            "normalized_events_dir": str(_normalized_events_dir(cfg)),
            "entity_index_dir": str(_entity_index_dir(cfg)),
            "process_event_index_dir": str(_process_event_index_dir(cfg)),
            "object_event_index_dir": str(_object_event_index_dir(cfg)),
            "task_evidence_frontier_dir": str(_task_evidence_frontier_dir(cfg)),
            "task_local_evidence_graph_dir": str(_task_local_evidence_graph_dir(cfg)),
            "unmapped_seed_process_count_total": int(total_unmapped_seed),
            "unmapped_top_process_count_total": int(total_unmapped_top),
            "rules_path": str(cfg.path_reason_rules_path or ""),
        },
    )
    return {
        "task_index": str(_task_index_path(cfg)),
        "priors_by_task": str(_priors_path(cfg)),
        "id_mapping": str(_id_mapping_path(cfg)),
        "summary": str(_summary_path(cfg)),
        "normalized_events_dir": str(_normalized_events_dir(cfg)),
        "entity_index_dir": str(_entity_index_dir(cfg)),
        "process_event_index_dir": str(_process_event_index_dir(cfg)),
        "object_event_index_dir": str(_object_event_index_dir(cfg)),
        "task_evidence_frontier_dir": str(_task_evidence_frontier_dir(cfg)),
        "task_local_evidence_graph_dir": str(_task_local_evidence_graph_dir(cfg)),
    }

