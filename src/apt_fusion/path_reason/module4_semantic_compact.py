from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

from ..common import ensure_dir, iter_jsonl, save_json, save_jsonl
from ..config import FusionConfig, resolve_attack_eval_gt_json
from .episode_aggregation import aggregate_episodes
from .evidence_normalizer import process_has_download_hint
from .label_provenance import LabelProvenanceBuilder
from .module3_evidence_recover import _priors_path as _module3_priors_path
from .module3_evidence_recover import _summary_path as _module3_summary_path
from .module3_evidence_recover import _task_index_path as _module3_task_index_path
from .object_classifier import path_contains_any_markers, path_is_under_web_root
from .path_rules import load_path_rules
from .path_schemas import NormalizedEvent, ObjectAccessRecord, ObjectState, ObjectVersion, ProcessState, TaskPrior
from .semantic_skip import LatestSemanticTable, event_is_force_kept, make_semantic_key, should_skip_semantically


def _task_index_path(cfg: FusionConfig) -> Path:
    return cfg.module4_compact_dir / "task_index.json"


def _summary_path(cfg: FusionConfig) -> Path:
    return cfg.module4_compact_dir / "compact_summary.json"


def _episodes_dir(cfg: FusionConfig) -> Path:
    return cfg.module4_compact_dir / "episodes"


def _access_records_dir(cfg: FusionConfig) -> Path:
    return cfg.module4_compact_dir / "access_records"


def _process_states_dir(cfg: FusionConfig) -> Path:
    return cfg.module4_compact_dir / "process_states_prepath"


def _object_states_dir(cfg: FusionConfig) -> Path:
    return cfg.module4_compact_dir / "object_states"


def _retained_events_dir(cfg: FusionConfig) -> Path:
    return cfg.module4_compact_dir / "retained_events"


def _object_versions_dir(cfg: FusionConfig) -> Path:
    return cfg.module4_compact_dir / "object_versions"


def _label_provenance_dir(cfg: FusionConfig) -> Path:
    return cfg.module4_compact_dir / "label_provenance"


def _signature(values: Iterable[str]) -> str:
    cleaned = sorted({str(item).strip() for item in values if str(item).strip()})
    return "|".join(cleaned)


def _describe_event(event: NormalizedEvent) -> str:
    process = event.process_name or event.process_guid
    target = event.object_name or event.object_key or event.object_type
    return f"{process} {event.event_type} {target}".strip()


def _new_process_state(task_id: str, event: NormalizedEvent, prior: TaskPrior) -> ProcessState:
    top_score = 0.0
    for item in prior.top_processes:
        if str(item.get("process_id", "")).strip() == event.process_guid:
            top_score = float(item.get("score", 0.0) or 0.0)
            break
    return ProcessState(
        task_id=task_id,
        process_guid=event.process_guid,
        process_name=event.process_name,
        process_exe=event.process_exe,
        process_cmdline=event.process_cmdline,
        start_time=event.timestamp,
        end_time=event.timestamp,
        parent_process_guid=event.parent_process_guid,
        prior_score=top_score,
    )


def _new_object_state(task_id: str, event: NormalizedEvent) -> ObjectState:
    return ObjectState(
        task_id=task_id,
        object_key=event.object_key,
        object_type=event.object_type,
        object_class=event.object_class,
        first_time=event.timestamp,
        last_time=event.timestamp,
    )


def _touch_process_state(state: ProcessState, event: NormalizedEvent) -> None:
    if state.start_time is None or (event.timestamp and event.timestamp < state.start_time):
        state.start_time = event.timestamp
    if state.end_time is None or (event.timestamp and event.timestamp > state.end_time):
        state.end_time = event.timestamp
    if event.parent_process_guid and not state.parent_process_guid:
        state.parent_process_guid = event.parent_process_guid
    if event.event_id and event.event_id not in state.evidence_event_ids:
        state.evidence_event_ids.append(event.event_id)


def _touch_object_state(state: ObjectState, event: NormalizedEvent) -> None:
    if state.first_time is None or (event.timestamp and event.timestamp < state.first_time):
        state.first_time = event.timestamp
    if state.last_time is None or (event.timestamp and event.timestamp > state.last_time):
        state.last_time = event.timestamp
    if event.event_type in {"READ", "OPEN"}:
        state.read_count += 1
    if event.event_type in {"WRITE", "CREATE", "TRUNCATE", "RENAME", "DELETE", "CHMOD", "CHOWN"}:
        state.write_count += 1
    if event.event_type in {"EXEC", "LOAD", "MMAP"}:
        state.exec_count += 1


def _label_type(label: str) -> str:
    text = str(label or "").strip().upper()
    if text.startswith("P_"):
        return "context"
    if text.startswith("O_"):
        return "object"
    if text.startswith("B_"):
        return "behavior"
    if text.startswith("A_"):
        return "aggregate"
    return "unknown"


def _matching_label_ids(
    builder: LabelProvenanceBuilder,
    label_ids: list[str],
    label: str,
) -> list[str]:
    matches: list[str] = []
    for label_id in label_ids:
        record = builder.get(label_id)
        if record is not None and record.label == label and label_id not in matches:
            matches.append(label_id)
    return matches


def _record_label(
    *,
    provenance_builder: LabelProvenanceBuilder,
    task_id: str,
    holder_entity_type: str,
    holder_entity_id: str,
    holder_state: ProcessState | ObjectState,
    label: str,
    rule_id: str,
    event: NormalizedEvent | None,
    source_type: str,
    source_entity_type: str | None = None,
    source_entity_id: str | None = None,
    context_id: str | None = None,
    prev_label_ids: list[str] | None = None,
    segment_id: str | None = None,
) -> str:
    label_id = provenance_builder.add(
        task_id=task_id,
        label=label,
        label_type=_label_type(label),
        holder_entity_type=holder_entity_type,
        holder_entity_id=holder_entity_id,
        created_at=event.timestamp if event is not None else None,
        source_entity_type=source_entity_type,
        source_entity_id=source_entity_id,
        source_type=source_type,
        event_id=event.event_id if event is not None else None,
        event_type=event.event_type if event is not None else None,
        rule_id=rule_id,
        context_id=context_id,
        prev_label_ids=prev_label_ids,
        segment_id=segment_id,
    )
    if label_id not in holder_state.label_ids:
        holder_state.label_ids.append(label_id)
    if context_id:
        holder_state.context_ids.add(str(context_id).strip())
    return label_id


def _update_object_versions(
    task_id: str,
    event: NormalizedEvent,
    object_state: ObjectState,
    object_versions_by_object: dict[str, list[ObjectVersion]],
) -> None:
    if event.object_type == "process" or not str(event.object_key).strip():
        return
    versions = object_versions_by_object.setdefault(event.object_key, [])
    created_now = False
    if not versions:
        versions.append(
            ObjectVersion(
                task_id=task_id,
                object_key=event.object_key,
                version_id="v0001",
                created_by_event_id=event.event_id,
                first_time=event.timestamp,
                last_time=event.timestamp,
                labels=set(object_state.labels),
            )
        )
        object_state.current_version_id = "v0001"
        created_now = True
    advance_events = {"WRITE", "CREATE", "TRUNCATE", "RENAME", "DELETE", "CHMOD", "CHOWN"}
    if event.event_type in advance_events and versions and not created_now:
        next_version_id = f"v{len(versions) + 1:04d}"
        versions.append(
            ObjectVersion(
                task_id=task_id,
                object_key=event.object_key,
                version_id=next_version_id,
                created_by_event_id=event.event_id,
                first_time=event.timestamp,
                last_time=event.timestamp,
                labels=set(object_state.labels),
            )
        )
        object_state.current_version_id = next_version_id
    current_version = versions[-1]
    if current_version.first_time is None or (event.timestamp and event.timestamp < current_version.first_time):
        current_version.first_time = event.timestamp
    if current_version.last_time is None or (event.timestamp and event.timestamp > current_version.last_time):
        current_version.last_time = event.timestamp
    current_version.labels.update(object_state.labels)
    if event.event_type in advance_events:
        current_version.writer_processes.add(event.process_guid)
    if event.event_type in {"READ", "OPEN"}:
        current_version.reader_processes.add(event.process_guid)
    if event.event_type in {"EXEC", "LOAD", "MMAP"}:
        current_version.executor_processes.add(event.process_guid)


def _apply_light_prelabels(
    event: NormalizedEvent,
    process_state: ProcessState,
    object_state: ObjectState,
    rules: Any,
    last_external_connect: dict[str, datetime | None],
    last_external_recv: dict[str, datetime | None],
) -> list[tuple[str, str, str]]:
    triggered: list[tuple[str, str, str]] = []

    def _mark(entity_type: str, label: str, rule_id: str) -> None:
        item = (entity_type, label, rule_id)
        if item not in triggered:
            triggered.append(item)

    process_name = (event.process_name or "").lower()
    if process_name in {str(item).lower() for item in rules.get("process_names.web_services", [])}:
        if "P_WEB_CTX" not in process_state.status_labels:
            process_state.status_labels.add("P_WEB_CTX")
            _mark("process", "P_WEB_CTX", "proc_name.web_service_context")
    if process_name in {str(item).lower() for item in rules.get("process_names.remote_services", [])}:
        if "P_REMOTE_CTX" not in process_state.status_labels:
            process_state.status_labels.add("P_REMOTE_CTX")
            _mark("process", "P_REMOTE_CTX", "proc_name.remote_service_context")

    if event.object_class == "external_ip":
        if "O_NET_EXTERNAL" not in object_state.labels:
            object_state.labels.add("O_NET_EXTERNAL")
            _mark("object", "O_NET_EXTERNAL", "object_class.external_ip")
        if event.event_type in {"CONNECT", "ACCEPT", "SEND", "RECV"} and "P_NET_CTX" not in process_state.status_labels:
            process_state.status_labels.add("P_NET_CTX")
            _mark("process", "P_NET_CTX", "network.external_ip_context")

    object_label_map = {
        "temp_file": "O_FILE_TEMP",
        "credential_file": "O_CREDENTIAL",
        "history_file": "O_HISTORY",
        "business_file": "O_BUSINESS_DATA",
        "persistence_file": "O_PERSISTENCE",
        "privilege_file": "O_PRIV_CONFIG",
    }
    mapped_object_label = object_label_map.get(event.object_class)
    if mapped_object_label and mapped_object_label not in object_state.labels:
        object_state.labels.add(mapped_object_label)
        _mark("object", mapped_object_label, f"object_class.{event.object_class}")

    if event.event_type in {"WRITE", "CREATE"} and path_contains_any_markers(event.object_key, rules):
        if "O_FILE_UPLOADED" not in object_state.labels:
            object_state.labels.add("O_FILE_UPLOADED")
            _mark("object", "O_FILE_UPLOADED", "write.path_marker_upload")
        if "P_WEB_CTX" not in process_state.status_labels and path_is_under_web_root(event.object_key, rules):
            process_state.status_labels.add("P_WEB_CTX")
            _mark("process", "P_WEB_CTX", "write.web_root_context")

    if event.object_class == "temp_file" and event.event_type in {"READ", "OPEN", "EXEC", "LOAD", "MMAP"}:
        if str(event.result or "").upper() in {"ENOENT", "NOT_FOUND"} and "O_FILE_NONEXIST" not in object_state.labels:
            object_state.labels.add("O_FILE_NONEXIST")
            _mark("object", "O_FILE_NONEXIST", "temp_file.not_found")

    if event.event_type in {"WRITE", "CREATE"} and event.object_type == "file":
        recent_connect = last_external_connect.get(event.process_guid)
        recent_recv = last_external_recv.get(event.process_guid)
        recently_networked = _within_seconds(event.timestamp, recent_connect, 120) or _within_seconds(
            event.timestamp,
            recent_recv,
            120,
        )
        if process_has_download_hint(event.process_cmdline) or (
            event.process_name.lower() in {str(item).lower() for item in rules.get("process_names.downloaders", [])}
            and recently_networked
        ) or (event.object_class == "temp_file" and _within_seconds(event.timestamp, recent_recv, 120)):
            if "O_FILE_DOWNLOADED" not in object_state.labels:
                object_state.labels.add("O_FILE_DOWNLOADED")
                _mark("object", "O_FILE_DOWNLOADED", "write.download_hint")

    if event.event_type == "RECV" and event.object_class == "external_ip":
        if "P_UNTRUSTED_CTX" not in process_state.status_labels:
            process_state.status_labels.add("P_UNTRUSTED_CTX")
            _mark("process", "P_UNTRUSTED_CTX", "recv.external_untrusted_context")

    if event.event_type in {"EXEC", "LOAD", "MMAP"} and object_state.labels.intersection(
        {"O_FILE_DOWNLOADED", "O_FILE_UPLOADED", "O_SUSPECT_WRITTEN_EXECUTABLE"}
    ):
        if "P_UNTRUSTED_CTX" not in process_state.status_labels:
            process_state.status_labels.add("P_UNTRUSTED_CTX")
            _mark("process", "P_UNTRUSTED_CTX", "exec.suspicious_object_untrusted_context")
    return triggered


def _within_seconds(current: datetime | None, previous: datetime | None, seconds: int) -> bool:
    if current is None or previous is None:
        return False
    return abs((current - previous).total_seconds()) <= float(seconds)


def _parse_iso_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _load_gt_windows_for_filter(cfg: FusionConfig) -> tuple[list[dict[str, Any]], Path | None]:
    mode = str(cfg.path_reason_gt_window_filter_mode or "none").strip().lower()
    if mode == "none":
        return [], None
    repo_root = Path(__file__).resolve().parents[3]
    gt_path = resolve_attack_eval_gt_json(repo_root, cfg.attack_eval_gt_json_path)
    if not gt_path.exists():
        raise FileNotFoundError(f"GT window filter reference not found: {gt_path}")
    payload = json_load(gt_path)
    raw_windows = payload.get("windows", []) if isinstance(payload, dict) else []
    if not isinstance(raw_windows, list):
        return [], gt_path
    offset_delta = timedelta(minutes=int(cfg.path_reason_gt_time_offset_minutes or 0))
    pad_delta = timedelta(minutes=int(cfg.path_reason_gt_window_filter_pad_minutes or 0))
    host = str(cfg.host or "").strip().upper()
    windows: list[dict[str, Any]] = []
    for item in raw_windows:
        if not isinstance(item, dict):
            continue
        if str(item.get("host", "")).strip().upper() != host:
            continue
        if mode == "confirmed_only" and str(item.get("status", "")).strip().lower() != "confirmed":
            continue
        start_time = _parse_iso_datetime(item.get("start_time"))
        end_time = _parse_iso_datetime(item.get("end_time"))
        if start_time is None or end_time is None:
            continue
        effective_start = start_time + offset_delta - pad_delta
        effective_end = end_time + offset_delta + pad_delta
        windows.append(
            {
                "window_id": str(item.get("window_id", "")).strip(),
                "status": str(item.get("status", "")).strip(),
                "base_start_time": start_time.isoformat(),
                "base_end_time": end_time.isoformat(),
                "effective_start_time": effective_start,
                "effective_end_time": effective_end,
            }
        )
    return windows, gt_path


def _filter_task_index_by_gt_windows(
    cfg: FusionConfig,
    task_index: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    mode = str(cfg.path_reason_gt_window_filter_mode or "none").strip().lower()
    base_meta: dict[str, Any] = {
        "gt_window_filter_mode": mode,
        "gt_window_filter_pad_minutes": int(cfg.path_reason_gt_window_filter_pad_minutes or 0),
        "gt_time_offset_minutes_applied": int(cfg.path_reason_gt_time_offset_minutes or 0),
        "input_task_count": len(task_index),
        "kept_task_ids": [],
        "filtered_out_task_ids": [],
        "filtered_out_reasons": {},
        "window_overlap_counts": {},
        "gt_window_ids": [],
        "gt_json_path": "",
    }
    if mode == "none":
        rows = [dict(row) for row in task_index]
        base_meta["kept_task_ids"] = [
            str(row.get("task_id", "")).strip()
            for row in rows
            if str(row.get("task_id", "")).strip()
        ]
        base_meta["kept_task_count"] = len(rows)
        base_meta["filtered_out_task_count"] = 0
        return rows, base_meta

    windows, gt_path = _load_gt_windows_for_filter(cfg)
    base_meta["gt_json_path"] = str(gt_path) if gt_path is not None else ""
    base_meta["gt_window_ids"] = [str(window["window_id"]) for window in windows if str(window["window_id"]).strip()]
    base_meta["window_overlap_counts"] = {str(window["window_id"]): 0 for window in windows if str(window["window_id"]).strip()}

    filtered_rows: list[dict[str, Any]] = []
    for row in task_index:
        task_id = str(row.get("task_id", "")).strip()
        row_copy = dict(row)
        first_timestamp = _parse_iso_datetime(row.get("first_timestamp"))
        last_timestamp = _parse_iso_datetime(row.get("last_timestamp"))
        if first_timestamp is None or last_timestamp is None:
            if task_id:
                base_meta["filtered_out_task_ids"].append(task_id)
                base_meta["filtered_out_reasons"][task_id] = "missing_task_time_range"
            continue
        overlap_window_ids = [
            str(window["window_id"])
            for window in windows
            if first_timestamp <= window["effective_end_time"] and last_timestamp >= window["effective_start_time"]
        ]
        if not overlap_window_ids:
            if task_id:
                base_meta["filtered_out_task_ids"].append(task_id)
                base_meta["filtered_out_reasons"][task_id] = "no_confirmed_window_overlap"
            continue
        row_copy["gt_overlap_window_ids"] = overlap_window_ids
        row_copy["source_first_timestamp"] = first_timestamp.isoformat()
        row_copy["source_last_timestamp"] = last_timestamp.isoformat()
        filtered_rows.append(row_copy)
        if task_id:
            base_meta["kept_task_ids"].append(task_id)
        for window_id in overlap_window_ids:
            if window_id not in base_meta["window_overlap_counts"]:
                base_meta["window_overlap_counts"][window_id] = 0
            base_meta["window_overlap_counts"][window_id] += 1

    base_meta["kept_task_count"] = len(filtered_rows)
    base_meta["filtered_out_task_count"] = len(base_meta["filtered_out_task_ids"])
    return filtered_rows, base_meta


def _semantic_skip_enabled(cfg: FusionConfig, rules: Any) -> bool:
    return bool(cfg.semantic_skip_enabled) and bool(rules.get("semantic_skip.enabled", True))


def run_module4_compact(cfg: FusionConfig) -> Dict[str, str]:
    rules = load_path_rules(cfg)
    task_index = save_or_load_task_index(cfg)
    task_index, gt_window_filter_meta = _filter_task_index_by_gt_windows(cfg, task_index)
    priors = load_priors(cfg)
    out_dir = cfg.module4_compact_dir
    ensure_dir(out_dir)
    for folder in [
        _episodes_dir(cfg),
        _access_records_dir(cfg),
        _process_states_dir(cfg),
        _object_states_dir(cfg),
        _retained_events_dir(cfg),
        _object_versions_dir(cfg),
        _label_provenance_dir(cfg),
    ]:
        ensure_dir(folder)

    summary_rows: list[dict[str, Any]] = []
    total_raw = 0
    total_retained = 0
    total_episodes = 0
    compact_index: list[dict[str, Any]] = []
    for row in task_index:
        task_id = str(row.get("task_id", "")).strip()
        normalized_path = Path(str(row.get("normalized_events_path", "")).strip())
        if not task_id or not normalized_path.exists():
            continue
        prior = priors.get(task_id, TaskPrior(task_id=task_id, task_score=0.0, task_probability=0.0))
        process_states: dict[str, ProcessState] = {}
        object_states: dict[str, ObjectState] = {}
        object_versions_by_object: dict[str, list[ObjectVersion]] = {}
        access_records: list[ObjectAccessRecord] = []
        retained_events: list[dict[str, Any]] = []
        provenance_builder = LabelProvenanceBuilder()
        recent_external_connect: dict[str, datetime | None] = {}
        recent_external_recv: dict[str, datetime | None] = {}
        lst = LatestSemanticTable(
            max_size=int(cfg.semantic_skip_max_table_size),
            clear_when_full=bool(rules.get("semantic_skip.clear_when_full", True)),
        )
        raw_count = 0
        retained_count = 0
        for payload in iter_jsonl(normalized_path):
            raw_count += 1
            event = NormalizedEvent.from_dict(dict(payload))
            process_state = process_states.setdefault(event.process_guid, _new_process_state(task_id, event, prior))
            if event.parent_process_guid and not process_state.parent_process_guid:
                process_state.parent_process_guid = event.parent_process_guid
            object_state = object_states.setdefault(event.object_key, _new_object_state(task_id, event))
            _touch_process_state(process_state, event)
            _touch_object_state(object_state, event)

            if event.event_type in {"FORK", "CLONE"} and event.object_type == "process" and event.object_key:
                child_state = process_states.get(event.object_key)
                inherited_labels: list[str] = []
                if child_state is None:
                    child_state = ProcessState(
                        task_id=task_id,
                        process_guid=event.object_key,
                        process_name=event.object_name or event.object_key,
                        process_exe=None,
                        process_cmdline=None,
                        start_time=event.timestamp,
                        end_time=event.timestamp,
                        parent_process_guid=event.process_guid,
                        status_labels=set(process_state.status_labels),
                        prior_score=0.0,
                    )
                    process_states[event.object_key] = child_state
                    inherited_labels = sorted(process_state.status_labels)
                else:
                    child_state.parent_process_guid = child_state.parent_process_guid or event.process_guid
                    inherited_labels = sorted(process_state.status_labels.difference(child_state.status_labels))
                    child_state.status_labels.update(process_state.status_labels)
                if inherited_labels:
                    segment_id = provenance_builder.new_segment_id()
                    for inherited_label in inherited_labels:
                        prev_ids = _matching_label_ids(provenance_builder, process_state.label_ids, inherited_label)
                        _record_label(
                            provenance_builder=provenance_builder,
                            task_id=task_id,
                            holder_entity_type="process",
                            holder_entity_id=child_state.process_guid,
                            holder_state=child_state,
                            label=inherited_label,
                            rule_id="fork_clone.inherit_status_label",
                            event=event,
                            source_type="inherit",
                            source_entity_type="process",
                            source_entity_id=event.process_guid,
                            prev_label_ids=prev_ids,
                            segment_id=segment_id,
                    )

            triggered = _apply_light_prelabels(
                event,
                process_state,
                object_state,
                rules,
                recent_external_connect,
                recent_external_recv,
            )
            triggered_labels = {label for _, label, _ in triggered}
            for entity_type, label, rule_id in triggered:
                if entity_type == "process":
                    _record_label(
                        provenance_builder=provenance_builder,
                        task_id=task_id,
                        holder_entity_type="process",
                        holder_entity_id=event.process_guid,
                        holder_state=process_state,
                        label=label,
                        rule_id=rule_id,
                        event=event,
                        source_type="event_rule",
                        source_entity_type="process",
                        source_entity_id=event.process_guid,
                    )
                elif entity_type == "object":
                    _record_label(
                        provenance_builder=provenance_builder,
                        task_id=task_id,
                        holder_entity_type="object",
                        holder_entity_id=event.object_key,
                        holder_state=object_state,
                        label=label,
                        rule_id=rule_id,
                        event=event,
                        source_type="event_rule",
                        source_entity_type="object",
                        source_entity_id=event.object_key,
                    )
            _update_object_versions(task_id, event, object_state, object_versions_by_object)
            process_sig_before = _signature(process_state.status_labels)
            object_sig_before = _signature(object_state.labels)
            proc_epoch_before = int(process_state.process_control_epoch)
            obj_epoch_before = int(object_state.semantic_epoch)
            semantic_key = make_semantic_key(
                task_id=task_id,
                process_guid=event.process_guid,
                event_type=event.event_type,
                object_key=event.object_key,
                object_class=event.object_class,
                semantic_flow_direction=event.semantic_flow_direction,
            )
            is_force_kept = event_is_force_kept(
                event_type=event.event_type,
                object_class=event.object_class,
                remote_ip=event.remote_ip,
                labels_triggered=triggered_labels,
                rules=rules,
                cfg=cfg,
            )
            skip = False
            if _semantic_skip_enabled(cfg, rules) and not is_force_kept:
                skip = should_skip_semantically(
                    lst,
                    semantic_key=semantic_key,
                    timestamp=event.timestamp,
                    process_label_signature=process_sig_before,
                    object_label_signature=object_sig_before,
                    object_semantic_epoch=obj_epoch_before,
                    process_control_epoch=proc_epoch_before,
                    ttl_seconds=int(cfg.semantic_skip_ttl_seconds),
                    ignore_if_timestamp_missing=bool(rules.get("semantic_skip.ignore_if_timestamp_missing", False)),
                )

            if event.event_type in {"WRITE", "CREATE", "TRUNCATE", "CHMOD", "CHOWN", "RENAME", "DELETE"}:
                lst.invalidate_object(event.object_key)
                object_state.semantic_epoch += 1
            if event.event_type == "RECV" and event.object_class == "external_ip":
                lst.invalidate_process(event.process_guid)
                process_state.process_control_epoch += 1
                recent_external_recv[event.process_guid] = event.timestamp
            if event.event_type in {"CONNECT", "SEND"} and event.object_class == "external_ip":
                recent_external_connect[event.process_guid] = event.timestamp
            if event.event_type in {"EXEC", "LOAD", "MMAP"}:
                lst.invalidate_process(event.process_guid)
                process_state.process_control_epoch += 1

            process_sig_after = _signature(process_state.status_labels)
            object_sig_after = _signature(object_state.labels)
            record = ObjectAccessRecord(
                task_id=task_id,
                object_key=event.object_key,
                object_type=event.object_type,
                object_class=event.object_class,
                process_guid=event.process_guid,
                process_name=event.process_name,
                event_type=event.event_type,
                timestamp=event.timestamp,
                order_index=event.order_index,
                event_id=event.event_id,
                raw_log_id=event.raw_log_id,
                syscall_direction=event.syscall_direction,
                semantic_flow_direction=event.semantic_flow_direction,
                process_label_signature_before=process_sig_before,
                process_label_signature_after=process_sig_after,
                object_label_signature_before=object_sig_before,
                object_label_signature_after=object_sig_after,
                object_semantic_epoch_before=obj_epoch_before,
                object_semantic_epoch_after=int(object_state.semantic_epoch),
                process_control_epoch_before=proc_epoch_before,
                process_control_epoch_after=int(process_state.process_control_epoch),
            )
            access_records.append(record)
            object_state.access_records.append(record)
            if triggered_labels or event.object_class in {"credential_file", "history_file", "business_file", "persistence_file"}:
                process_state.important_objects.add(event.object_key)
            lst.remember(
                semantic_key,
                timestamp=event.timestamp,
                process_guid=event.process_guid,
                object_key=event.object_key,
                process_label_signature=process_sig_after,
                object_label_signature=object_sig_after,
                object_semantic_epoch=int(object_state.semantic_epoch),
                process_control_epoch=int(process_state.process_control_epoch),
            )
            if skip:
                continue

            retained_count += 1
            retained_events.append(
                {
                    **event.to_dict(),
                    "description": _describe_event(event),
                    "labels_triggered": sorted(triggered_labels),
                    "process_label_signature": process_sig_after,
                    "object_label_signature": object_sig_after,
                    "object_semantic_epoch": int(object_state.semantic_epoch),
                    "process_control_epoch": int(process_state.process_control_epoch),
                    "is_force_kept": bool(is_force_kept),
                }
            )

        for object_state in object_states.values():
            object_state.is_bridge_allowed = bool(object_state.labels.intersection(set(rules.get("bridging.allow_object_labels", []))))
            if object_state.is_bridge_allowed:
                object_state.bridge_reason = "allowed_by_object_label"
        episodes = aggregate_episodes(
            task_id,
            retained_events,
            bucket_minutes=int(cfg.episode_time_bucket_minutes),
            max_representative_events=int(cfg.episode_max_representative_events),
        )
        total_raw += raw_count
        total_retained += retained_count
        total_episodes += len(episodes)

        slug = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in task_id).strip("_") or task_id
        retained_events_path = _retained_events_dir(cfg) / f"{slug}.jsonl"
        access_records_path = _access_records_dir(cfg) / f"{slug}.jsonl"
        episodes_path = _episodes_dir(cfg) / f"{slug}.json"
        process_states_path = _process_states_dir(cfg) / f"{slug}.json"
        object_states_path = _object_states_dir(cfg) / f"{slug}.json"
        object_versions_path = _object_versions_dir(cfg) / f"{slug}.json"
        label_provenance_path = _label_provenance_dir(cfg) / f"{slug}.jsonl"
        save_jsonl(retained_events_path, retained_events)
        save_jsonl(access_records_path, [record.to_dict() for record in access_records])
        save_json(episodes_path, [episode.to_dict() for episode in episodes])
        save_json(process_states_path, {key: state.to_dict() for key, state in process_states.items()})
        save_json(object_states_path, {key: state.to_dict() for key, state in object_states.items()})
        save_json(
            object_versions_path,
            [version.to_dict() for object_key in sorted(object_versions_by_object) for version in object_versions_by_object[object_key]],
        )
        save_jsonl(label_provenance_path, [record.to_dict() for record in provenance_builder.records])
        compact_index.append(
            {
                "task_id": task_id,
                "source_first_timestamp": str(
                    row.get("source_first_timestamp", row.get("first_timestamp", ""))
                ).strip(),
                "source_last_timestamp": str(
                    row.get("source_last_timestamp", row.get("last_timestamp", ""))
                ).strip(),
                "gt_overlap_window_ids": list(row.get("gt_overlap_window_ids", []) or []),
                "raw_event_count": raw_count,
                "retained_event_count": retained_count,
                "episode_count": len(episodes),
                "retained_events_path": str(retained_events_path),
                "access_records_path": str(access_records_path),
                "episodes_path": str(episodes_path),
                "process_states_path": str(process_states_path),
                "object_states_path": str(object_states_path),
                "object_versions_path": str(object_versions_path),
                "label_provenance_path": str(label_provenance_path),
            }
        )
        summary_rows.append(
            {
                "task_id": task_id,
                "source_first_timestamp": str(
                    row.get("source_first_timestamp", row.get("first_timestamp", ""))
                ).strip(),
                "source_last_timestamp": str(
                    row.get("source_last_timestamp", row.get("last_timestamp", ""))
                ).strip(),
                "gt_overlap_window_ids": list(row.get("gt_overlap_window_ids", []) or []),
                "raw_event_count": raw_count,
                "after_semantic_skip": retained_count,
                "after_episode_aggregation": len(episodes),
                "process_count": len(process_states),
                "object_count": len(object_states),
                "object_version_count": sum(len(versions) for versions in object_versions_by_object.values()),
                "label_provenance_count": len(provenance_builder.records),
            }
        )

    save_json(_task_index_path(cfg), compact_index)
    save_json(
        _summary_path(cfg),
        {
            "task_count": len(compact_index),
            "raw_event_count": total_raw,
            "after_semantic_skip": total_retained,
            "after_episode_aggregation": total_episodes,
            **gt_window_filter_meta,
            "tasks": summary_rows,
            "module3_summary_path": str(_module3_summary_path(cfg)),
            "object_versions_dir": str(_object_versions_dir(cfg)),
            "label_provenance_dir": str(_label_provenance_dir(cfg)),
        },
    )
    return {
        "task_index": str(_task_index_path(cfg)),
        "summary": str(_summary_path(cfg)),
        "episodes_dir": str(_episodes_dir(cfg)),
        "access_records_dir": str(_access_records_dir(cfg)),
        "process_states_dir": str(_process_states_dir(cfg)),
        "object_states_dir": str(_object_states_dir(cfg)),
        "retained_events_dir": str(_retained_events_dir(cfg)),
        "object_versions_dir": str(_object_versions_dir(cfg)),
        "label_provenance_dir": str(_label_provenance_dir(cfg)),
    }


def save_or_load_task_index(cfg: FusionConfig) -> list[dict[str, Any]]:
    path = _module3_task_index_path(cfg)
    if not path.exists():
        raise FileNotFoundError(f"module3 evidence task index not found: {path}. Run module3_evidence first.")
    payload = json_load(path)
    return payload if isinstance(payload, list) else []


def load_priors(cfg: FusionConfig) -> dict[str, TaskPrior]:
    path = _module3_priors_path(cfg)
    if not path.exists():
        return {}
    payload = json_load(path)
    if not isinstance(payload, dict):
        return {}
    return {task_id: TaskPrior.from_dict(dict(value)) for task_id, value in payload.items() if isinstance(value, dict)}


def json_load(path: Path) -> Any:
    return __import__("json").loads(path.read_text(encoding="utf-8"))

