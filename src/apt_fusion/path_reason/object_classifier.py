from __future__ import annotations

import fnmatch
import os
import re
from typing import Any

from .evidence_normalizer import is_external_ip, is_internal_ip, parse_flow_endpoints
from .path_rules import PathRules

_PATH_SEP_PATTERN = re.compile(r"[\\/]+")


def normalize_path(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return _PATH_SEP_PATTERN.sub("/", text)


def basename(value: str) -> str:
    text = normalize_path(value)
    return os.path.basename(text.rstrip("/")) or text


def classify_process_type(process_name: str, process_exe: str | None, rules: PathRules) -> str:
    name = (process_name or basename(process_exe or "")).lower().strip()
    if not name:
        return "unknown_binary"
    process_names = rules.get("process_names", {})
    if _in_named_group(name, process_names.get("shells", [])):
        return "shell"
    if _in_named_group(name, process_names.get("interpreters", [])):
        return "interpreter"
    if _in_named_group(name, process_names.get("downloaders", [])):
        return "downloader"
    if _in_named_group(name, process_names.get("network_tools", [])):
        return "network_tool"
    if _in_named_group(name, process_names.get("archive_tools", [])):
        return "archive_tool"
    if _in_named_group(name, process_names.get("web_services", [])):
        return "web_service"
    if _in_named_group(name, process_names.get("remote_services", [])):
        return "remote_service"
    if _in_named_group(name, process_names.get("common_daemons", [])):
        return "common_daemon"
    if process_exe and ("/" in process_exe or "\\" in process_exe):
        return "binary"
    return "unknown_binary"


def classify_object(object_type: str, object_key: str, rules: PathRules) -> str:
    node_type = str(object_type or "").strip().lower()
    key = normalize_path(object_key)
    if not key and node_type:
        return node_type
    if node_type in {"flow", "socket", "network"}:
        return _classify_network_object(key, rules)
    if node_type in {"pipe", "ipc"}:
        return "local_ipc"
    if node_type == "process":
        return "process"
    if _matches_object_class(key, rules.get("object_classes.proc_status", {})):
        return "proc_status"
    if _matches_object_class(key, rules.get("object_classes.temp_file", {})):
        return "temp_file"
    if _matches_object_class(key, rules.get("object_classes.credential_file", {})):
        return "credential_file"
    if _matches_object_class(key, rules.get("object_classes.history_file", {})):
        return "history_file"
    if _matches_object_class(key, rules.get("object_classes.persistence_file", {})):
        return "persistence_file"
    if _matches_object_class(key, rules.get("object_classes.privilege_file", {})):
        return "privilege_file"
    if _matches_object_class(key, rules.get("object_classes.auth_config_file", {})):
        return "auth_config_file"
    if _matches_object_class(key, rules.get("object_classes.log_file", {})):
        return "log_file"
    if _matches_object_class(key, rules.get("object_classes.archive_file", {})):
        return "archive_file"
    if _matches_business_file(key, rules):
        return "business_file"
    if _matches_object_class(key, rules.get("object_classes.system_library", {})):
        return "system_library"
    if _matches_object_class(key, rules.get("object_classes.system_resource", {})):
        return "system_resource"
    if _matches_object_class(key, rules.get("object_classes.local_ipc", {})):
        return "local_ipc"
    if key:
        return "file" if node_type in {"file", "registry"} or key.startswith("/") else node_type or "object"
    return node_type or "object"


def path_contains_any_markers(path: str, rules: PathRules) -> bool:
    lower = normalize_path(path).lower()
    for marker in rules.get("paths.upload_markers", []):
        text = str(marker).strip().lower()
        if text and text in lower:
            return True
    return False


def path_is_under_web_root(path: str, rules: PathRules) -> bool:
    lower = normalize_path(path).lower()
    for prefix in rules.get("paths.web_roots", []):
        candidate = normalize_path(prefix).lower()
        if candidate and lower.startswith(candidate):
            return True
    return False


def _classify_network_object(key: str, rules: PathRules) -> str:
    local_ip, _, remote_ip, _ = parse_flow_endpoints(key)
    for candidate in (remote_ip, local_ip):
        if candidate and is_external_ip(candidate, rules):
            return "external_ip"
    for candidate in (remote_ip, local_ip):
        if candidate and is_internal_ip(candidate, rules):
            return "internal_ip"
    if key.startswith("unix:") or key.startswith("localhost") or key.startswith("127."):
        return "local_ipc"
    return "external_ip" if "->" in key else "network"


def _matches_business_file(key: str, rules: PathRules) -> bool:
    path = normalize_path(key)
    if not path:
        return False
    patterns = rules.get("paths.business_data_paths", [])
    for pattern in patterns:
        token = normalize_path(str(pattern))
        if not token:
            continue
        if "*" in token or "?" in token:
            if fnmatch.fnmatch(path, token):
                return True
            if fnmatch.fnmatch(basename(path), token):
                return True
            continue
        if token.endswith("/"):
            if path.startswith(token):
                return True
            continue
        if token in path or basename(path) == basename(token):
            return True
    return False


def _matches_object_class(key: str, meta: Any) -> bool:
    if not isinstance(meta, dict):
        return False
    path = normalize_path(key)
    for value in meta.get("path_prefixes", []):
        prefix = normalize_path(str(value))
        if prefix and path.startswith(prefix):
            return True
    for value in meta.get("exact_or_prefix", []):
        prefix = normalize_path(str(value))
        if prefix and (path == prefix or path.startswith(prefix)):
            return True
    for value in meta.get("exact_or_contains", []):
        token = normalize_path(str(value))
        if token and (path == token or token in path):
            return True
    for value in meta.get("suffixes", []):
        suffix = str(value).strip().lower()
        if suffix and path.lower().endswith(suffix):
            return True
    return False


def _in_named_group(name: str, values: Any) -> bool:
    lowered = str(name or "").strip().lower()
    return any(lowered == str(item).strip().lower() for item in values or [])

