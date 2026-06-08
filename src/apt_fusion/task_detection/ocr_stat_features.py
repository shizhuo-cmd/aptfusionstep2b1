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
) -> None:
    if action is None:
        return

    def _allowed(process_id: str | None) -> bool:
        return process_id is not None and (target_process_ids is None or process_id in target_process_ids)

    if _allowed(source_id):
        row = process_rows.setdefault(source_id, _init_process_row(action_columns))
        row[f"stat_out_{action}"] = float(row[f"stat_out_{action}"]) + 1.0
        if timestamp_sec is not None:
            timestamps = row["_timestamps"]
            assert isinstance(timestamps, list)
            timestamps.append(timestamp_sec)
    if _allowed(dest_process_id):
        row = process_rows.setdefault(dest_process_id, _init_process_row(action_columns))
        row[f"stat_in_{action}"] = float(row[f"stat_in_{action}"]) + 1.0
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


def _extract_tc3_stats(cfg: FusionConfig, process_ids: set[str]) -> pd.DataFrame:
    action_columns = _ordered_action_columns(cfg.host)
    allowed_actions = {column[len("stat_out_") :] for column in action_columns if column.startswith("stat_out_")}
    process_rows: dict[str, dict[str, object]] = {}
    uuid_to_process_id: dict[str, str] = {}

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
            else:
                process_id = uuid
            if process_id:
                uuid_to_process_id[uuid] = process_id

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

