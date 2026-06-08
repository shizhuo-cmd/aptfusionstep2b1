from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

WINDOWS_NODLINK_HOSTS = {"SimulatedW10", "SimulatedWS12"}


@dataclass(frozen=True)
class NodlinkWindowsEvent:
    timestamp_sec: float | None
    action: str | None
    subject_process_id: str | None
    subject_pid: str | None
    subject_name: str
    object_type: str | None
    object_id: str | None
    file_path: str
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str
    remote_ip: str
    remote_port: str
    child_process_id: str | None
    child_pid: str | None
    child_name: str


def is_nodlink_windows_host(host: str) -> bool:
    return host in WINDOWS_NODLINK_HOSTS


def extract_json_fragment(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", line)
    if not match:
        return None
    try:
        obj = json.loads(match.group(0))
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


def _clean_token(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return text.strip("\"'")


def _clean_numeric_token(value: Any) -> str:
    text = _clean_token(value)
    if not text:
        return ""
    return text.replace(",", "")


def _first_non_empty(obj: dict[str, Any], keys: list[str]) -> str:
    for key in keys:
        value = _clean_token(obj.get(key))
        if value:
            return value
    return ""


def _normalize_process_name(raw_name: str) -> str:
    if not raw_name:
        return "unknown"
    normalized = raw_name.replace("\\", "/").rsplit("/", 1)[-1]
    normalized = normalized.strip().lower()
    return normalized or "unknown"


def build_process_id(pid: str, process_name: str) -> str | None:
    pid = _clean_numeric_token(pid)
    if not pid:
        return None
    _ = process_name
    return f"proc::{pid}"


def _parse_msec_to_seconds(value: Any) -> float | None:
    text = _clean_token(value)
    if not text:
        return None
    try:
        return float(text) / 1000.0
    except Exception:
        return None


def _normalize_action(event_name: str) -> tuple[str | None, str | None]:
    lowered = event_name.strip().lower()
    if not lowered:
        return None, None
    if "process/" in lowered and "start" in lowered:
        return "start", "PROCESS"
    if "image/load" in lowered or lowered.endswith("/load"):
        return "load", "FILE"
    if "send" in lowered:
        return "send", "FLOW"
    if "recv" in lowered or "receive" in lowered:
        return "recv", "FLOW"
    if "fileio/" in lowered or "file/" in lowered:
        if any(token in lowered for token in ["read", "query", "open"]):
            return "read", "FILE"
        if any(token in lowered for token in ["write", "create", "rename", "delete", "setinfo", "cleanup"]):
            return "write", "FILE"
    if "read" in lowered:
        return "read", "FILE"
    if any(token in lowered for token in ["write", "create", "rename", "delete"]):
        return "write", "FILE"
    return None, None


def _build_file_id(obj: dict[str, Any], file_path: str) -> str | None:
    key = _first_non_empty(obj, ["FileKey", "FileObject", "Key", "ObjectKey"])
    if key:
        return f"file::{key.lower()}"
    if file_path:
        return f"file::{file_path.lower()}"
    return None


def _build_flow_fields(action: str, obj: dict[str, Any]) -> tuple[str, str, str, str, str, str]:
    src_ip = _first_non_empty(obj, ["saddr", "src_ip", "SourceAddress", "SrcAddress", "LocalAddress"])
    dst_ip = _first_non_empty(obj, ["daddr", "dest_ip", "DestinationAddress", "DstAddress", "RemoteAddress"])
    src_port = _first_non_empty(obj, ["sport", "src_port", "SourcePort", "SrcPort", "LocalPort"])
    dst_port = _first_non_empty(obj, ["dport", "dest_port", "DestinationPort", "DstPort", "RemotePort"])
    if action == "recv":
        remote_ip = src_ip
        remote_port = src_port
    else:
        remote_ip = dst_ip
        remote_port = dst_port
    return src_ip, dst_ip, src_port, dst_port, remote_ip, remote_port


def _build_flow_id(action: str, src_ip: str, dst_ip: str, src_port: str, dst_port: str) -> str | None:
    if not any([src_ip, dst_ip, src_port, dst_port]):
        return None
    return f"flow::{action}::{src_ip}:{src_port}->{dst_ip}:{dst_port}"


def parse_nodlink_windows_event(line: str) -> NodlinkWindowsEvent | None:
    obj = extract_json_fragment(line)
    if obj is None:
        return None

    timestamp_sec = _parse_msec_to_seconds(
        obj.get("MSec")
        or obj.get("Timestamp")
        or obj.get("TimeStamp")
        or obj.get("Time")
    )
    event_name = _first_non_empty(obj, ["EventName", "OpcodeName", "TaskName"])
    action, object_type = _normalize_action(event_name)
    if action is None:
        return None

    subject_pid = _clean_numeric_token(
        _first_non_empty(obj, ["PID", "ProcessId", "ProcessID"])
    )
    subject_name = _first_non_empty(obj, ["PName", "ProcessName", "ImageFileName", "ImageName"])
    subject_process_id = build_process_id(subject_pid, subject_name)
    if subject_process_id is None:
        return None

    child_pid = ""
    child_name = ""
    child_process_id = None
    object_id = None
    file_path = ""
    src_ip = ""
    dst_ip = ""
    src_port = ""
    dst_port = ""
    remote_ip = ""
    remote_port = ""

    if object_type == "PROCESS":
        child_pid = _clean_numeric_token(
            _first_non_empty(
                obj,
                ["NewProcessId", "NewPID", "ChildPID", "ProcessID", "ProcessId", "TargetPID"],
            )
        )
        child_name = _first_non_empty(
            obj,
            ["ImageName", "ProcessName", "TargetProcessName", "NewProcessName"],
        )
        child_process_id = build_process_id(child_pid, child_name)
    elif object_type == "FILE":
        file_path = _first_non_empty(obj, ["FileName", "FilePath", "ImageName", "Path"])
        object_id = _build_file_id(obj, file_path)
    elif object_type == "FLOW":
        src_ip, dst_ip, src_port, dst_port, remote_ip, remote_port = _build_flow_fields(action, obj)
        object_id = _build_flow_id(action, src_ip, dst_ip, src_port, dst_port)

    return NodlinkWindowsEvent(
        timestamp_sec=timestamp_sec,
        action=action,
        subject_process_id=subject_process_id,
        subject_pid=subject_pid or None,
        subject_name=subject_name,
        object_type=object_type,
        object_id=object_id,
        file_path=file_path,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        remote_ip=remote_ip,
        remote_port=remote_port,
        child_process_id=child_process_id,
        child_pid=child_pid or None,
        child_name=child_name,
    )
