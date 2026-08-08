from __future__ import annotations

import gzip
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

from ..config import FusionConfig

_UUID_KEY = "com.bbn.tc.schema.avro.cdm18.UUID"
_EVENT_KEY = "com.bbn.tc.schema.avro.cdm18.Event"
_SUBJECT_KEY = "com.bbn.tc.schema.avro.cdm18.Subject"

_HOST_ACTIONS: dict[str, list[str]] = {
    "cadets": [
        "execute",
        "unlink",
        "change_principal",
        "modify_file_attributes",
        "rename",
        "link",
        "write",
        "read",
        "sendto",
        "recvfrom",
        "sendmsg",
        "recvmsg",
        "modify_process",
        "connect",
        "mmap",
        "fcntl",
        "fork",
        "truncate",
        "lseek",
        "flows_to",
        "accept",
        "create_object",
        "close",
        "exit",
        "open",
        "bind",
        "signal",
        "other",
    ],
    "fivedirections": [
        "execute",
        "unlink",
        "change_principal",
        "modify_file_attributes",
        "rename",
        "link",
        "write",
        "read",
        "sendto",
        "recvfrom",
        "sendmsg",
        "recvmsg",
        "modify_process",
        "connect",
        "mmap",
        "fcntl",
        "fork",
        "truncate",
        "lseek",
        "flows_to",
        "accept",
        "create_object",
        "close",
        "exit",
        "open",
        "bind",
        "signal",
        "other",
    ],
    "theia": [
        "execute",
        "unlink",
        "modify_file_attributes",
        "write",
        "read",
        "sendto",
        "recvfrom",
        "sendmsg",
        "recvmsg",
        "connect",
        "write_socket_params",
        "read_socket_params",
        "clone",
        "mmap",
        "shm",
        "mprotect",
        "open",
        "boot",
    ],
    "trace": [
        "execute",
        "unlink",
        "change_principal",
        "modify_file_attributes",
        "update",
        "rename",
        "link",
        "write",
        "read",
        "connect",
        "sendmsg",
        "recvmsg",
        "clone",
        "fork",
        "loadlibrary",
        "mmap",
        "mprotect",
        "truncate",
        "accept",
        "create_object",
        "close",
        "exit",
        "open",
        "unit",
    ],
    "SysClient0051": [
        "delete",
        "modify",
        "rename",
        "write",
        "read",
        "create",
        "message_outbound",
        "message_inbound",
        "load",
        "remote_create",
        "open_inbound",
        "open",
        "remove",
        "edit",
        "add",
        "start",
        "terminate",
        "start_inbound",
        "start_outbound",
    ],
    "SysClient0201": [
        "command",
        "delete",
        "modify",
        "rename",
        "write",
        "read",
        "create",
        "message_outbound",
        "message_inbound",
        "load",
        "remote_create",
        "open_inbound",
        "open",
        "remove",
        "edit",
        "add",
        "start",
        "terminate",
        "start_inbound",
        "start_outbound",
    ],
    "SysClient0501": [
        "command",
        "delete",
        "modify",
        "rename",
        "write",
        "read",
        "create",
        "message_outbound",
        "message_inbound",
        "load",
        "remote_create",
        "open_inbound",
        "open",
        "remove",
        "edit",
        "add",
        "start",
        "terminate",
        "start_inbound",
        "start_outbound",
    ],
}

_TIME_FEATURES = [
    "stat_avg_idle_time",
    "stat_max_idle_time",
    "stat_min_idle_time",
    "stat_cumulative_active_time",
    "stat_lifespan",
]


def _iter_log_files(source_logs: Path) -> list[Path]:
    if source_logs.is_file():
        return [source_logs]
    files = [path for path in source_logs.rglob("*") if path.is_file()]
    files.sort()
    return files


def _iter_lines(path: Path) -> Iterable[str]:
    if path.suffix.lower() == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as f:
            yield from f
    else:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            yield from f


def _ordered_action_columns(host: str) -> list[str]:
    actions = _HOST_ACTIONS.get(host)
    if actions is None:
        raise ValueError(f"OCR-style stat features do not support host '{host}'")
    columns: list[str] = []
    for action in actions:
        columns.append(f"stat_out_{action}")
        columns.append(f"stat_in_{action}")
    return columns


def _init_process_row(action_columns: list[str]) -> dict[str, object]:
    row: dict[str, object] = {column: 0.0 for column in action_columns}
    row["_timestamps"] = []
    return row


def _normalize_action(raw_action: object, allowed_actions: set[str]) -> str | None:
    text = str(raw_action or "").strip().lower()
    if not text:
        return None
    if text.startswith("event_"):
        text = text[len("event_") :]
    if text in allowed_actions:
        return text
    if "other" in allowed_actions:
        return "other"
    return None


def _extract_uuid_ref(value: object) -> str | None:
    if isinstance(value, dict):
        if _UUID_KEY in value:
            return str(value[_UUID_KEY])
        if "uuid" in value and value["uuid"] is not None:
            return str(value["uuid"])
    elif value is not None:
        text = str(value).strip()
        if text:
            return text
    return None


def _to_seconds(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, pd.Timestamp):
        return float(value.timestamp())
    if isinstance(value, (int, float, np.integer, np.floating)):
        numeric = float(value)
    else:
        text = str(value).strip()
        if not text:
            return None
        if re.fullmatch(r"-?\d+(\.\d+)?", text):
            numeric = float(text)
        else:
            dt = pd.to_datetime(text, errors="coerce", utc=True)
            if pd.isna(dt):
                return None
            return float(dt.timestamp())
    absolute = abs(numeric)
    if absolute >= 1e18:
        return numeric / 1e9
    if absolute >= 1e15:
        return numeric / 1e6
    if absolute >= 1e12:
        return numeric / 1e3
    return numeric


def _record_process_event(
    process_rows: dict[str, dict[str, object]],
    action_columns: list[str],
    source_id: str | None,
    dest_process_id: str | None,
    action: str | None,
    timestamp_sec: float | None,
    target_process_ids: set[str] | None,
    amount: float = 1.0,
) -> None:
    if action is None:
        return

    def _allowed(process_id: str | None) -> bool:
        return process_id is not None and (target_process_ids is None or process_id in target_process_ids)

    if _allowed(source_id):
        row = process_rows.setdefault(source_id, _init_process_row(action_columns))
        row[f"stat_out_{action}"] = float(row[f"stat_out_{action}"]) + float(amount)
        if timestamp_sec is not None:
            timestamps = row["_timestamps"]
            assert isinstance(timestamps, list)
            timestamps.append(timestamp_sec)
    if _allowed(dest_process_id):
        row = process_rows.setdefault(dest_process_id, _init_process_row(action_columns))
        row[f"stat_in_{action}"] = float(row[f"stat_in_{action}"]) + float(amount)
        if timestamp_sec is not None:
            timestamps = row["_timestamps"]
            assert isinstance(timestamps, list)
            timestamps.append(timestamp_sec)


def _finalize_rows(
    process_rows: dict[str, dict[str, object]],
    action_columns: list[str],
    process_ids: Iterable[str],
    active_threshold_sec: float,
) -> pd.DataFrame:
    ordered_process_ids = sorted({str(process_id) for process_id in process_ids})
    for process_id in ordered_process_ids:
        process_rows.setdefault(process_id, _init_process_row(action_columns))

    rows: list[dict[str, float | str]] = []
    for process_id in ordered_process_ids:
        row = process_rows[process_id]
        timestamps = sorted(float(ts) for ts in row.pop("_timestamps", []))
        if len(timestamps) > 1:
            gaps = np.diff(np.asarray(timestamps, dtype=np.float64))
        else:
            gaps = np.asarray([], dtype=np.float64)
        idle = gaps[gaps >= active_threshold_sec]
        active = gaps[gaps < active_threshold_sec]
        lifespan = float(gaps.sum()) if len(gaps) > 0 else 0.0
        finalized = {"process_id": process_id}
        for column in action_columns:
            finalized[column] = float(row.get(column, 0.0))
        finalized["stat_avg_idle_time"] = float(idle.mean()) if len(idle) > 0 else 0.0
        finalized["stat_max_idle_time"] = float(idle.max()) if len(idle) > 0 else 0.0
        finalized["stat_min_idle_time"] = float(idle.min()) if len(idle) > 0 else 0.0
        finalized["stat_cumulative_active_time"] = float(active.sum()) if len(active) > 0 else 0.0
        finalized["stat_lifespan"] = lifespan
        rows.append(finalized)

    df = pd.DataFrame(rows)
    if df.empty:
        return pd.DataFrame(columns=["process_id", *action_columns, *_TIME_FEATURES])

    action_matrix = df[action_columns].to_numpy(dtype=np.float64)
    norms = np.linalg.norm(action_matrix, axis=1, keepdims=True)
    norms[norms == 0.0] = 1.0
    df[action_columns] = action_matrix / norms

    time_matrix = df[_TIME_FEATURES].to_numpy(dtype=np.float64)
    if len(time_matrix) > 0:
        minimum = time_matrix.min(axis=0)
        maximum = time_matrix.max(axis=0)
        denom = maximum - minimum
        denom[denom == 0.0] = 1.0
        df[_TIME_FEATURES] = (time_matrix - minimum) / denom

    return df.fillna(0.0)


_TC3_EVENT_ID_TO_ACTION = {
    1: "accept",
    2: "connect",
    3: "execute",
    4: "exit",
    5: "read",
    6: "recvfrom",
    7: "recvmsg",
    8: "sendto",
    9: "sendmsg",
    10: "write",
    11: "create_object",
}

_TC3_CORE_ACTIONS = {
    "accept",
    "connect",
    "execute",
    "exit",
    "read",
    "recvfrom",
    "recvmsg",
    "sendto",
    "sendmsg",
    "write",
}

_TC3_SECURITY_ACTION_FAMILIES = {
    "execute": "sem_execution",
    "exit": "sem_process_lifecycle",
    "fork": "sem_process_lifecycle",
    "modify_process": "sem_process_lifecycle",
    "change_principal": "sem_privilege",
    "read": "sem_file_read",
    "write": "sem_file_write",
    "open": "sem_file_open",
    "close": "sem_file_open",
    "unlink": "sem_file_mutation",
    "rename": "sem_file_mutation",
    "link": "sem_file_mutation",
    "modify_file_attributes": "sem_file_mutation",
    "truncate": "sem_file_mutation",
    "create_object": "sem_file_mutation",
    "connect": "sem_network_connect",
    "accept": "sem_network_connect",
    "bind": "sem_network_connect",
    "sendto": "sem_network_send",
    "sendmsg": "sem_network_send",
    "recvfrom": "sem_network_receive",
    "recvmsg": "sem_network_receive",
    "mmap": "sem_memory_control",
    "fcntl": "sem_memory_control",
    "signal": "sem_process_signal",
}
_TC3_SECURITY_SEMANTIC_COLUMNS = [
    "sem_execution",
    "sem_process_lifecycle",
    "sem_privilege",
    "sem_file_read",
    "sem_file_write",
    "sem_file_open",
    "sem_file_mutation",
    "sem_network_connect",
    "sem_network_send",
    "sem_network_receive",
    "sem_memory_control",
    "sem_process_signal",
    "sem_log_total_events",
    "sem_log_security_events",
    "sem_security_event_ratio",
]


def extract_process_stat_features_from_tc3_action_counts(
    cfg: FusionConfig,
    process_ids: Iterable[str],
    action_counts_by_subject: dict[object, object],
    mode: str,
) -> pd.DataFrame:
    """Build canonical TC3 process statistics from one-pass parser action tallies.

    The legacy TAPAS sequence parser only retains ten event types.  This helper
    receives a separate per-canonical-subject tally collected from the same
    stream, so ``core`` and ``extended`` modes can differ only by their event
    coverage while using the same fixed output feature schema.
    """
    if mode not in {"core", "extended", "security_semantic"}:
        raise ValueError("TC3 action-count statistics require a supported action-count mode")

    if mode == "security_semantic":
        return extract_process_semantic_features_from_tc3_action_counts(
            process_ids,
            action_counts_by_subject,
        )

    process_id_set = {str(process_id).strip() for process_id in process_ids if str(process_id).strip()}
    action_columns = _ordered_action_columns(cfg.host)
    allowed_actions = {column[len("stat_out_") :] for column in action_columns if column.startswith("stat_out_")}
    process_rows: dict[str, dict[str, object]] = {}

    for raw_subject_id, raw_counts in action_counts_by_subject.items():
        subject_id = str(raw_subject_id).strip()
        if subject_id not in process_id_set or not isinstance(raw_counts, dict):
            continue
        for raw_action, raw_count in raw_counts.items():
            action_text = str(raw_action or "").strip().lower()
            if action_text.startswith("event_"):
                action_text = action_text[len("event_") :]
            if mode == "core" and action_text not in _TC3_CORE_ACTIONS:
                continue
            action = _normalize_action(action_text, allowed_actions)
            if action is None:
                continue
            try:
                amount = float(raw_count)
            except (TypeError, ValueError):
                amount = 1.0
            if amount <= 0.0:
                continue
            _record_process_event(
                process_rows,
                action_columns,
                subject_id,
                None,
                action,
                timestamp_sec=None,
                target_process_ids=process_id_set,
                amount=amount,
            )

    return _finalize_rows(process_rows, action_columns, process_id_set, cfg.ocr_stat_active_threshold_sec)


def extract_process_semantic_features_from_tc3_action_counts(
    process_ids: Iterable[str],
    action_counts_by_subject: dict[object, object],
) -> pd.DataFrame:
    """Compress broad TC3 actions into security-relevant, magnitude-aware features.

    Raw catch-all events are deliberately excluded.  Each semantic family uses
    ``log1p`` counts, while total volume and the security-action share preserve
    information that per-row L2 normalization would otherwise discard.
    """
    process_id_set = {str(process_id).strip() for process_id in process_ids if str(process_id).strip()}
    rows: list[dict[str, float | str]] = []
    for process_id in sorted(process_id_set):
        raw_counts = action_counts_by_subject.get(process_id, {})
        row: dict[str, float | str] = {"process_id": process_id}
        family_counts = {column: 0.0 for column in _TC3_SECURITY_SEMANTIC_COLUMNS[:12]}
        total_count = 0.0
        security_count = 0.0
        if isinstance(raw_counts, dict):
            for raw_action, raw_count in raw_counts.items():
                action_text = str(raw_action or "").strip().lower()
                if action_text.startswith("event_"):
                    action_text = action_text[len("event_") :]
                try:
                    amount = float(raw_count)
                except (TypeError, ValueError):
                    amount = 0.0
                if amount <= 0.0:
                    continue
                total_count += amount
                family = _TC3_SECURITY_ACTION_FAMILIES.get(action_text)
                if family is None:
                    continue
                family_counts[family] += amount
                security_count += amount
        for column, count in family_counts.items():
            row[column] = float(np.log1p(count))
        row["sem_log_total_events"] = float(np.log1p(total_count))
        row["sem_log_security_events"] = float(np.log1p(security_count))
        row["sem_security_event_ratio"] = float(security_count / total_count) if total_count > 0.0 else 0.0
        rows.append(row)
    return pd.DataFrame(rows, columns=["process_id", *_TC3_SECURITY_SEMANTIC_COLUMNS]).fillna(0.0)


def extract_process_stat_features_from_tc3_event_count(
    cfg: FusionConfig,
    process_ids: Iterable[str],
    event_count: dict[object, object],
    parser_metadata: dict[str, object] | None = None,
) -> pd.DataFrame:
    """Build TC3 stat features from TAPAS parser output instead of rescanning logs.

    The TAPAS TC3 parsers already aggregate events as
    ``(event_type_id, subject_uuid, object_uuid) -> count``.  For large hosts
    such as FiveDirections, re-reading the raw JSON logs just to reconstruct
    these counts is prohibitively expensive.  This helper consumes the parser
    aggregate directly and applies the parser's canonical subject mapping before
    updating process-level in/out action counters.
    """

    process_id_set = {str(process_id).strip() for process_id in process_ids if str(process_id).strip()}
    action_columns = _ordered_action_columns(cfg.host)
    allowed_actions = {column[len("stat_out_") :] for column in action_columns if column.startswith("stat_out_")}
    process_rows: dict[str, dict[str, object]] = {}
    if not process_id_set:
        return _finalize_rows(process_rows, action_columns, process_id_set, cfg.ocr_stat_active_threshold_sec)

    raw_to_canonical: dict[str, str] = {}
    if isinstance(parser_metadata, dict):
        mapping = parser_metadata.get("raw_subject_to_canonical_node")
        if isinstance(mapping, dict):
            raw_to_canonical = {str(key): str(value) for key, value in mapping.items()}

    def _canonical(value: object) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            return None
        return raw_to_canonical.get(text, text)

    for key, raw_count in event_count.items():
        if not isinstance(key, tuple) or len(key) != 3:
            continue
        event_type, subject_id, object_id = key
        try:
            event_id = int(event_type)
        except (TypeError, ValueError):
            continue
        action = _TC3_EVENT_ID_TO_ACTION.get(event_id)
        action = _normalize_action(action, allowed_actions)
        if action is None:
            continue
        try:
            amount = float(raw_count)
        except (TypeError, ValueError):
            amount = 1.0
        if amount <= 0.0:
            continue
        source_id = _canonical(subject_id)
        dest_process_id = _canonical(object_id)
        if dest_process_id not in process_id_set:
            dest_process_id = None
        _record_process_event(
            process_rows,
            action_columns,
            source_id,
            dest_process_id,
            action,
            timestamp_sec=None,
            target_process_ids=process_id_set,
            amount=amount,
        )

    return _finalize_rows(process_rows, action_columns, process_id_set, cfg.ocr_stat_active_threshold_sec)


def _extract_tc3_stats(cfg: FusionConfig, process_ids: set[str]) -> pd.DataFrame:
    action_columns = _ordered_action_columns(cfg.host)
    allowed_actions = {column[len("stat_out_") :] for column in action_columns if column.startswith("stat_out_")}
    process_rows: dict[str, dict[str, object]] = {}
    uuid_to_process_id: dict[str, str] = {}
    trace_subject_rows: dict[str, dict[str, str]] = {}

    for log_file in _iter_log_files(cfg.source_logs):
        for line in _iter_lines(log_file):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            datum = record.get("datum")
            if not isinstance(datum, dict) or _SUBJECT_KEY not in datum:
                continue
            subject = datum[_SUBJECT_KEY]
            if not isinstance(subject, dict):
                continue
            uuid = _extract_uuid_ref(subject.get("uuid"))
            if uuid is None:
                continue
            if cfg.host == "trace":
                process_id = str(subject.get("cid", "")).strip()
                if not process_id:
                    continue
                trace_subject_rows[uuid] = {
                    "cid": process_id,
                    "parent_uuid": _extract_uuid_ref(subject.get("parentSubject")) or "",
                    "subject_type": str(subject.get("type", "")).strip().upper(),
                }
            else:
                process_id = uuid
            if process_id:
                uuid_to_process_id[uuid] = process_id

    if cfg.host == "trace":
        owner_cache: dict[str, str] = {}

        def resolve_trace_owner(subject_uuid: str, trail: set[str] | None = None) -> str:
            subject_uuid = str(subject_uuid)
            if subject_uuid in owner_cache:
                return owner_cache[subject_uuid]
            row = trace_subject_rows.get(subject_uuid)
            if row is None:
                return subject_uuid
            if trail is None:
                trail = set()
            if subject_uuid in trail:
                return str(row.get("cid") or subject_uuid)
            trail.add(subject_uuid)
            if row.get("subject_type") == "SUBJECT_UNIT" and row.get("parent_uuid"):
                owner = resolve_trace_owner(str(row["parent_uuid"]), trail)
            else:
                owner = str(row.get("cid") or subject_uuid)
            trail.remove(subject_uuid)
            owner_cache[subject_uuid] = owner
            return owner

        uuid_to_process_id = {
            subject_uuid: resolve_trace_owner(subject_uuid)
            for subject_uuid in trace_subject_rows
        }

    for log_file in _iter_log_files(cfg.source_logs):
        for line in _iter_lines(log_file):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            datum = record.get("datum")
            if not isinstance(datum, dict) or _EVENT_KEY not in datum:
                continue
            event = datum[_EVENT_KEY]
            if not isinstance(event, dict):
                continue
            action = _normalize_action(event.get("type"), allowed_actions)
            subject_uuid = _extract_uuid_ref(event.get("subject"))
            source_id = uuid_to_process_id.get(subject_uuid or "")
            if source_id is None and cfg.host == "trace":
                thread_id = event.get("threadId")
                if isinstance(thread_id, dict):
                    thread_value = thread_id.get("int")
                    if thread_value is not None:
                        candidate = str(thread_value)
                        if candidate in process_ids:
                            source_id = candidate
            predicate_object = event.get("predicateObject")
            object_uuid = _extract_uuid_ref(predicate_object)
            dest_process_id = uuid_to_process_id.get(object_uuid or "")
            timestamp_sec = _to_seconds(
                event.get("timestampNanos")
                or event.get("timestampMicros")
                or event.get("timestampMillis")
                or event.get("timestamp")
            )
            _record_process_event(
                process_rows,
                action_columns,
                source_id,
                dest_process_id,
                action,
                timestamp_sec,
                process_ids,
            )

    return _finalize_rows(process_rows, action_columns, process_ids, cfg.ocr_stat_active_threshold_sec)


def _extract_optc_field(field: str, text: str) -> str | None:
    match = re.search(rf'"{re.escape(field)}"\s*:\s*"([^"]*)"', text)
    return match.group(1) if match else None


def _extract_optc_stats(cfg: FusionConfig, process_ids: set[str]) -> pd.DataFrame:
    action_columns = _ordered_action_columns(cfg.host)
    allowed_actions = {column[len("stat_out_") :] for column in action_columns if column.startswith("stat_out_")}
    process_rows: dict[str, dict[str, object]] = {}

    for log_file in _iter_log_files(cfg.source_logs):
        for line in _iter_lines(log_file):
            line = line.strip()
            if not line:
                continue
            action_raw = _extract_optc_field("action", line)
            object_type = _extract_optc_field("object", line)
            actor_id = _extract_optc_field("actorID", line)
            object_id = _extract_optc_field("objectID", line)
            timestamp = _extract_optc_field("timestamp", line) or _extract_optc_field("@timestamp", line)
            action = _normalize_action(action_raw, allowed_actions)
            source_id = str(actor_id).strip() if actor_id else None
            dest_process_id = None
            if object_type == "PROCESS" and object_id:
                dest_process_id = str(object_id).strip()
            timestamp_sec = _to_seconds(timestamp)
            _record_process_event(
                process_rows,
                action_columns,
                source_id,
                dest_process_id,
                action,
                timestamp_sec,
                process_ids,
            )

    return _finalize_rows(process_rows, action_columns, process_ids, cfg.ocr_stat_active_threshold_sec)


def extract_process_stat_features(cfg: FusionConfig, process_ids: Iterable[str]) -> pd.DataFrame:
    process_id_set = {str(process_id).strip() for process_id in process_ids if str(process_id).strip()}
    if not process_id_set:
        return pd.DataFrame(columns=["process_id"])
    if cfg.dataset_family == "tc3":
        return _extract_tc3_stats(cfg, process_id_set)
    if cfg.dataset_family == "optc":
        return _extract_optc_stats(cfg, process_id_set)
    raise ValueError(
        "OCR-style process statistics are only supported for TAPAS-native 'tc3' and 'optc' datasets"
    )

