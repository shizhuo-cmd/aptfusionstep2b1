from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from .path_schemas import ObjectAccessRecord, ObjectState, ProcessState


def apply_full_path_labels(
    retained_events: list[dict[str, Any]],
    process_states: dict[str, ProcessState],
    object_states: dict[str, ObjectState],
    rules: Any,
) -> dict[str, set[str]]:
    _mark_suspect_written_executables(object_states)
    event_labels: dict[str, set[str]] = defaultdict(set)
    windows: dict[tuple[str, str], set[str]] = defaultdict(set)
    remote_services = {str(item).lower() for item in rules.get("process_names.remote_services", [])}
    shells = {str(item).lower() for item in rules.get("process_names.shells", [])}
    interpreters = {str(item).lower() for item in rules.get("process_names.interpreters", [])}
    web_services = {str(item).lower() for item in rules.get("process_names.web_services", [])}
    archive_tools = {str(item).lower() for item in rules.get("process_names.archive_tools", [])}

    for event in sorted(retained_events, key=lambda item: int(item.get("order_index", 0) or 0)):
        event_id = str(event.get("event_id", "")).strip()
        process_guid = str(event.get("process_guid", "")).strip()
        object_key = str(event.get("object_key", "")).strip()
        process_state = process_states.get(process_guid)
        object_state = object_states.get(object_key)
        if process_state is None or object_state is None:
            continue
        process_name = (process_state.process_name or "").lower()
        event_type = str(event.get("event_type", "")).upper()
        object_class = str(event.get("object_class", "")).strip()
        if event_type == "RECV" and object_class == "external_ip":
            _add_behavior(process_state, event_labels[event_id], "B_EXTERNAL_RECV")
        if event_type == "SEND" and object_class == "external_ip":
            _add_behavior(process_state, event_labels[event_id], "B_EXTERNAL_SEND")
        if event_type == "EXEC" and object_class == "temp_file":
            _add_behavior(process_state, event_labels[event_id], "B_EXEC_TEMP")
        if event_type in {"EXEC", "LOAD"} and "O_FILE_DOWNLOADED" in object_state.labels:
            _add_behavior(process_state, event_labels[event_id], "B_EXEC_DOWNLOADED")
        if event_type in {"EXEC", "LOAD"} and "O_FILE_UPLOADED" in object_state.labels:
            _add_behavior(process_state, event_labels[event_id], "B_EXEC_UPLOADED")
        if event_type in {"EXEC", "LOAD"} and "O_SUSPECT_WRITTEN_EXECUTABLE" in object_state.labels:
            _add_behavior(process_state, event_labels[event_id], "B_EXEC_SUSPECT_WRITTEN")
        if process_name in shells and _shell_is_suspicious(process_state, event, web_services):
            _add_behavior(process_state, event_labels[event_id], "B_SHELL_SPAWN")
        if process_name in interpreters and _interpreter_is_suspicious(process_state, event):
            _add_behavior(process_state, event_labels[event_id], "B_SCRIPT_EXEC")
        if process_name in interpreters:
            _add_behavior(process_state, event_labels[event_id], "B_INTERPRETER_LAUNCH")
        if event_type == "READ" and object_class == "credential_file":
            process_state.status_labels.add("P_HIGH_VALUE_CTX")
            _add_behavior(process_state, event_labels[event_id], "B_READ_CRED")
        if event_type == "READ" and object_class == "history_file":
            process_state.status_labels.add("P_HIGH_VALUE_CTX")
            _add_behavior(process_state, event_labels[event_id], "B_READ_HISTORY")
        if event_type == "READ" and object_class == "business_file":
            process_state.status_labels.add("P_HIGH_VALUE_CTX")
            _add_behavior(process_state, event_labels[event_id], "B_READ_BUSINESS")
        if event_type in {"WRITE", "CREATE", "RENAME"} and object_class == "persistence_file":
            _add_behavior(process_state, event_labels[event_id], "B_WRITE_PERSISTENCE")
        if event_type in {"WRITE", "CHMOD", "CHOWN"} and object_class == "privilege_file":
            _add_behavior(process_state, event_labels[event_id], "B_WRITE_PRIV_CONFIG")
        if process_name in archive_tools or object_class == "archive_file":
            _add_behavior(process_state, event_labels[event_id], "B_ARCHIVE_DATA")
        if event_type in {"DELETE", "RENAME", "WRITE"} and object_class == "log_file":
            _add_behavior(process_state, event_labels[event_id], "B_DELETE_LOG")
        if event_type in {"CONNECT", "SEND"} and object_class == "internal_ip":
            lateral_ports = {int(item) for item in rules.get("network.lateral_ports", [])}
            remote_port = event.get("remote_port")
            if remote_port not in (None, "") and int(remote_port) in lateral_ports:
                _add_behavior(process_state, event_labels[event_id], "B_LATERAL_CONNECT")
        if process_name in remote_services and event_type in {"ACCEPT", "RECV"}:
            _add_behavior(process_state, event_labels[event_id], "B_REMOTE_LOGIN_SERVICE")
        if event_type in {"WRITE", "CREATE"} and "upload" in object_key.lower():
            _add_behavior(process_state, event_labels[event_id], "B_WEB_WRITE")

        bucket_key = _bucket_key(event.get("timestamp"))
        if bucket_key and event_type == "READ" and object_class in {
            "file",
            "credential_file",
            "history_file",
            "business_file",
        }:
            windows[(process_guid, bucket_key)].add(object_key)

    for (process_guid, _bucket), objects in windows.items():
        if len(objects) >= 100 and process_guid in process_states:
            process_states[process_guid].behavior_labels.add("B_MASS_FILE_ACCESS")
    return event_labels


def _mark_suspect_written_executables(object_states: dict[str, ObjectState]) -> None:
    for object_state in object_states.values():
        if object_state.object_class in {"system_library", "system_resource"}:
            continue
        seen_write = False
        for record in sorted(object_state.access_records, key=lambda item: int(item.order_index)):
            if record.event_type in {"WRITE", "CREATE", "RENAME"}:
                seen_write = True
            if seen_write and record.event_type in {"EXEC", "LOAD", "MMAP"}:
                object_state.labels.add("O_SUSPECT_WRITTEN_EXECUTABLE")
                break


def _add_behavior(process_state: ProcessState, event_labels: set[str], label: str) -> None:
    process_state.behavior_labels.add(label)
    event_labels.add(label)


def _shell_is_suspicious(process_state: ProcessState, event: dict[str, Any], web_services: set[str]) -> bool:
    cmdline = str(process_state.process_cmdline or "").lower()
    parent_labels = set(process_state.status_labels)
    if parent_labels.intersection({"P_WEB_CTX", "P_REMOTE_CTX", "P_SUSPECT_CTRL_CTX"}):
        return True
    if process_state.parent_process_guid:
        if str(event.get("parent_process_name", "")).lower() in web_services:
            return True
    return any(token in cmdline for token in (" -c ", "curl", "wget", "nc ", "socat", "/tmp/", "/dev/shm/"))


def _interpreter_is_suspicious(process_state: ProcessState, event: dict[str, Any]) -> bool:
    cmdline = str(process_state.process_cmdline or "").lower()
    if any(token in cmdline for token in ("http://", "https://", "/tmp/", "/dev/shm/", "-c ")):
        return True
    if process_state.status_labels.intersection({"P_WEB_CTX", "P_REMOTE_CTX", "P_SUSPECT_CTRL_CTX"}):
        return True
    labels = {str(item) for item in event.get("labels_triggered", [])}
    return bool(labels.intersection({"O_FILE_DOWNLOADED", "O_FILE_UPLOADED", "O_SUSPECT_WRITTEN_EXECUTABLE"}))


def _bucket_key(value: Any) -> str:
    if isinstance(value, datetime):
        return value.replace(second=0, microsecond=0).isoformat()[:16]
    text = str(value or "").strip()
    return text[:16] if len(text) >= 16 else ""

