from __future__ import annotations

import os
import re
from ipaddress import ip_address
from pathlib import PurePosixPath
from typing import Any

from ..common import load_json
from ..config import FusionConfig
from .log_stream import _to_seconds
from .path_rules import PathRules
from .path_schemas import TaskPrior

_IP_PORT_ARROW_PATTERN = re.compile(
    r"(?P<local_ip>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<local_port>\d{1,5}))?"
    r"->"
    r"(?P<remote_ip>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<remote_port>\d{1,5}))?"
)
_IP_PORT_PATTERN = re.compile(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<port>\d{1,5}))?")
_DOWNLOAD_MARKERS = ("http://", "https://", "ftp://", " -o ", " -o", " -O ", " -O")


def build_task_priors(
    cfg: FusionConfig,
    suspicious_tasks_path: Any,
    task_meta_rich_path: Any,
    task_attribution_path: Any,
) -> dict[str, TaskPrior]:
    suspicious_rows = load_json(suspicious_tasks_path) if suspicious_tasks_path else []
    meta_rows = load_json(task_meta_rich_path) if task_meta_rich_path else []
    attribution_rows = load_json(task_attribution_path) if task_attribution_path else []
    meta_by_task = {
        str(row.get("task_id", "")).strip(): row
        for row in meta_rows
        if isinstance(row, dict) and str(row.get("task_id", "")).strip()
    }
    attribution_by_task = {
        str(row.get("task_id", "")).strip(): row
        for row in attribution_rows
        if isinstance(row, dict) and str(row.get("task_id", "")).strip()
    }
    priors: dict[str, TaskPrior] = {}
    for row in suspicious_rows:
        if not isinstance(row, dict):
            continue
        task_id = str(row.get("task_id", "")).strip()
        if not task_id:
            continue
        meta = meta_by_task.get(task_id, {})
        attribution = attribution_by_task.get(task_id, {})
        prior = TaskPrior(
            task_id=task_id,
            task_score=float(row.get("task_score", 0.0) or 0.0),
            task_probability=float(row.get("task_probability", row.get("task_score", 0.0)) or 0.0),
            root_process_ids=[str(item) for item in meta.get("root_process_ids", [])],
            task_root_id=str(meta.get("task_root_id", "")).strip(),
            boundary_node_ids=[str(item) for item in meta.get("boundary_node_ids", [])],
            top_processes=list(attribution.get("top_processes", [])),
            top_edges=list(attribution.get("top_edges", [])),
            graphsage_probability=(
                None if row.get("graphsage_probability") is None else float(row.get("graphsage_probability"))
            ),
            stats_probability=None if row.get("stats_probability") is None else float(row.get("stats_probability")),
            task_label=None if row.get("task_label") is None else int(row.get("task_label")),
            predicted_label=int(row.get("predicted_label", 0) or 0),
        )
        priors[task_id] = prior
    return priors


def normalize_event_type(raw_event_type: str, rules: PathRules) -> str:
    text = str(raw_event_type or "").strip().upper()
    mapped = rules.get(f"normalization.map_event_types.{text}")
    if mapped:
        return str(mapped).strip().upper()
    aliases = {
        "EXECUTE": "EXEC",
        "CREATE_OBJECT": "CREATE",
        "SENDMSG": "SEND",
        "SENDTO": "SEND",
        "RECVMSG": "RECV",
        "RECVFROM": "RECV",
        "FORK_WITH_SHARED_OPEN_FILE": "FORK",
        "MODIFY_PROCESS": "CHMOD",
    }
    return aliases.get(text, text or str(rules.get("normalization.unknown_event_type", "UNKNOWN")).upper())


def infer_process_name(process_attr: str, process_exe: str | None = None) -> str:
    candidate = process_exe or process_attr
    candidate = str(candidate or "").strip()
    if not candidate:
        return ""
    if " " in candidate:
        candidate = candidate.split(" ", 1)[0]
    return os.path.basename(candidate.rstrip("/\\")) or candidate


def infer_process_exe(process_attr: str) -> str | None:
    text = str(process_attr or "").strip()
    if not text:
        return None
    token = text.split(" ", 1)[0].strip()
    if "/" in token or "\\" in token:
        return token
    return None


def infer_process_cmdline(process_attr: str) -> str | None:
    text = str(process_attr or "").strip()
    if not text or " " not in text:
        return None
    return text


def normalize_object_key(node_type: str, node_attr: str, object_uuid: str) -> str:
    text = str(node_attr or "").strip()
    if text:
        return text
    return str(object_uuid or "").strip()


def infer_object_name(object_key: str) -> str | None:
    text = str(object_key or "").strip()
    if not text:
        return None
    if "->" in text:
        return text
    return os.path.basename(text.rstrip("/\\")) or text


def parse_flow_endpoints(object_key: str) -> tuple[str | None, int | None, str | None, int | None]:
    text = str(object_key or "").strip()
    if not text:
        return None, None, None, None
    match = _IP_PORT_ARROW_PATTERN.search(text)
    if match:
        return (
            match.group("local_ip"),
            _to_int(match.group("local_port")),
            match.group("remote_ip"),
            _to_int(match.group("remote_port")),
        )
    single = _IP_PORT_PATTERN.search(text)
    if single:
        return None, None, single.group("ip"), _to_int(single.group("port"))
    return None, None, None, None


def extract_result(raw_event: dict[str, Any]) -> str | None:
    candidates = [
        raw_event.get("result"),
        raw_event.get("returnValue"),
        raw_event.get("return_value"),
        raw_event.get("status"),
        raw_event.get("statusCode"),
        raw_event.get("errno"),
        raw_event.get("error"),
    ]
    for value in candidates:
        if value in (None, ""):
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def infer_syscall_direction(event_type: str, object_type: str, rules: PathRules) -> str:
    action = str(event_type or "").upper()
    obj = str(object_type or "").lower()
    if action in {"FORK", "CLONE", "EXIT"}:
        return "P_TO_P"
    if action == "ACCEPT" and obj in {"flow", "socket", "network"}:
        return "O_TO_P"
    if obj == "process":
        return "P_TO_P"
    if obj:
        return "P_TO_O"
    return str(rules.get("normalization.default_syscall_direction", "UNKNOWN")).upper()


def infer_semantic_flow_direction(event_type: str, object_type: str, rules: PathRules) -> str:
    action = str(event_type or "").upper()
    obj = str(object_type or "").lower()
    if action in {"READ", "EXEC", "LOAD", "MMAP"}:
        return "O_TO_P"
    if action in {"WRITE", "CREATE", "TRUNCATE", "CHMOD", "CHOWN", "RENAME", "DELETE", "CONNECT", "SEND"}:
        return "P_TO_O"
    if action == "RECV":
        return "O_TO_P"
    if action == "ACCEPT":
        return "O_TO_P"
    if action in {"FORK", "CLONE"} or obj == "process":
        return "P_TO_P"
    if action == "EXIT":
        return "NONE"
    return str(rules.get("normalization.default_semantic_flow_direction", "UNKNOWN")).upper()


def is_external_ip(value: str, rules: PathRules) -> bool:
    ip = _safe_ip(value)
    if ip is None:
        return False
    for cidr in rules.get("network.internal_cidrs", []):
        try:
            if ip in __import__("ipaddress").ip_network(str(cidr), strict=False):
                return False
        except ValueError:
            continue
    return True


def is_internal_ip(value: str, rules: PathRules) -> bool:
    ip = _safe_ip(value)
    if ip is None:
        return False
    for cidr in rules.get("network.internal_cidrs", []):
        try:
            if ip in __import__("ipaddress").ip_network(str(cidr), strict=False):
                return True
        except ValueError:
            continue
    return False


def process_has_download_hint(process_cmdline: str | None) -> bool:
    lower = str(process_cmdline or "").lower()
    return any(marker.strip().lower() in lower for marker in _DOWNLOAD_MARKERS)


def pure_name(text: str) -> str:
    return PurePosixPath(str(text or "").strip()).name


def _safe_ip(value: str) -> Any:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return ip_address(text)
    except ValueError:
        return None


def _to_int(value: Any) -> int | None:
    try:
        if value in (None, ""):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def timestamp_to_epoch_seconds(value: Any) -> float | None:
    return _to_seconds(value)

