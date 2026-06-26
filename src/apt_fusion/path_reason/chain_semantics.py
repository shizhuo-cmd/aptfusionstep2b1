from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Iterable

from .path_schemas import parse_datetime

STRONG_PRECURSOR_MARKERS = ("tcexec", "command-not-found", "/dev/pts/3")
WEAK_PRECURSOR_MARKERS = ("python3", "bash", "chmod")
TEMP_EXEC_MARKERS = ("/tmp/", "/var/tmp/", "/dev/shm/", "ztmp")
PLACEHOLDER_OBJECT_KEYS = {"file_object_block"}
SYSTEM_SERVICE_PATH_PREFIXES = (
    "/etc/",
    "/usr/",
    "/usr/local/libexec/",
    "/var/run/",
    "/var/spool/postfix/",
    "/dev/",
)
SYSTEM_SERVICE_PATH_EXCEPTIONS = ("/dev/shm/",)
STAGED_EXEC_OBJECT_LABELS = {
    "O_FILE_DOWNLOADED",
    "O_FILE_UPLOADED",
    "O_SUSPECT_WRITTEN_EXECUTABLE",
    "O_FILE_TEMP",
}
STAGED_EXEC_EVENT_LABELS = {
    "B_EXEC_DOWNLOADED",
    "B_EXEC_UPLOADED",
    "B_EXEC_SUSPECT_WRITTEN",
    "B_EXEC_TEMP",
}
WRITE_LIKE_EVENT_TYPES = {"WRITE", "CREATE", "TRUNCATE", "RENAME"}
CHMOD_LIKE_EVENT_TYPES = {"CHMOD", "MODIFY_FILE_ATTRIBUTES"}
EXEC_LIKE_EVENT_TYPES = {"EXEC", "LOAD", "MMAP"}
DEFAULT_STAGED_WINDOW_MINUTES = 10
GENERIC_EXECUTOR_NAMES = {
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "python",
    "python2",
    "python2.7",
    "python3",
    "perl",
    "ruby",
}


def normalize_semantic_text(*values: Any) -> str:
    return " ".join(str(value or "").strip() for value in values if str(value or "").strip()).lower()


def semantic_item_text(item: Any) -> str:
    return normalize_semantic_text(
        _item_value(item, "description"),
        _item_value(item, "object_key"),
        _item_value(item, "object_class"),
        _item_value(item, "process_name"),
        _item_value(item, "process_exe"),
        _item_value(item, "process_cmdline"),
    )


def item_event_id(item: Any) -> str:
    return str(_item_value(item, "event_id", "")).strip()


def item_object_key(item: Any) -> str:
    return str(_item_value(item, "object_key", "")).strip()


def item_event_type(item: Any) -> str:
    return str(_item_value(item, "event_type", "")).strip().upper()


def item_order_index(item: Any) -> int:
    return int(_item_value(item, "order_index", 0) or 0)


def item_timestamp(item: Any) -> datetime | None:
    return parse_datetime(_item_value(item, "timestamp"))


def item_object_labels(item: Any) -> set[str]:
    raw = _item_value(item, "object_labels", ())
    return {str(value).strip() for value in raw or [] if str(value).strip()}


def item_raw_cmdline(item: Any) -> str:
    raw_event = _item_value(item, "raw_event")
    if not isinstance(raw_event, dict):
        return ""
    datum = raw_event.get("datum")
    if not isinstance(datum, dict):
        return ""
    event_payload = datum.get("com.bbn.tc.schema.avro.cdm18.Event")
    if not isinstance(event_payload, dict):
        return ""
    properties = event_payload.get("properties")
    if not isinstance(properties, dict):
        return ""
    prop_map = properties.get("map")
    if not isinstance(prop_map, dict):
        return ""
    return str(prop_map.get("cmdLine", "") or "").strip()


def item_process_name(item: Any) -> str:
    return str(_item_value(item, "process_name", "")).strip()


def item_event_labels(item: Any) -> set[str]:
    raw = _item_value(item, "labels_triggered", ())
    return {str(value).strip() for value in raw or [] if str(value).strip()}


def is_temp_exec_path(object_key: Any) -> bool:
    text = normalize_semantic_text(object_key)
    return any(marker in text for marker in TEMP_EXEC_MARKERS)


def is_placeholder_object_key(object_key: Any) -> bool:
    return normalize_semantic_text(object_key) in PLACEHOLDER_OBJECT_KEYS


def is_system_service_object_key(object_key: Any) -> bool:
    text = normalize_semantic_text(object_key)
    if not text or is_temp_exec_path(text):
        return False
    if any(text.startswith(prefix) for prefix in SYSTEM_SERVICE_PATH_EXCEPTIONS):
        return False
    return any(text.startswith(prefix) for prefix in SYSTEM_SERVICE_PATH_PREFIXES)


def staged_object_keys_from_bridge_edges(bridge_edges: Iterable[Any]) -> set[str]:
    output: set[str] = set()
    for edge in bridge_edges or ():
        if not item_object_labels(edge).intersection(STAGED_EXEC_OBJECT_LABELS):
            continue
        object_key = normalize_semantic_text(item_object_key(edge))
        if object_key:
            output.add(object_key)
    return output


def collect_precursor_event_ids(
    items: Iterable[Any],
    *,
    suspicious_object_keys: Iterable[str] | None = None,
    limit: int = 8,
) -> list[str]:
    ordered = _ordered_items(items)
    strong_ids: list[str] = []
    weak_ids: list[str] = []
    for item in ordered:
        event_id = item_event_id(item)
        if not event_id:
            continue
        text = semantic_item_text(item)
        if any(marker in text for marker in STRONG_PRECURSOR_MARKERS):
            strong_ids.append(event_id)
            continue
        if any(marker in text for marker in WEAK_PRECURSOR_MARKERS):
            weak_ids.append(event_id)
    if strong_ids:
        return _unique_ids([*strong_ids, *weak_ids])[:limit]
    if len(_unique_ids(weak_ids)) >= 2 and has_exec_staging_signal(items, suspicious_object_keys=suspicious_object_keys):
        return _unique_ids(weak_ids)[:limit]
    return []


def has_exec_staging_signal(
    items: Iterable[Any],
    *,
    suspicious_object_keys: Iterable[str] | None = None,
) -> bool:
    return bool(collect_staged_object_keys(items, suspicious_object_keys=suspicious_object_keys))


def collect_staged_object_keys(
    items: Iterable[Any],
    *,
    suspicious_object_keys: Iterable[str] | None = None,
) -> set[str]:
    suspicious_keys = {normalize_semantic_text(value) for value in suspicious_object_keys or () if normalize_semantic_text(value)}
    output = set(suspicious_keys)
    ordered = _ordered_items(items)
    for item in ordered:
        object_key = normalize_semantic_text(item_object_key(item))
        if not object_key or is_system_service_object_key(object_key):
            continue
        if is_temp_exec_path(object_key):
            output.add(object_key)
            continue
        if item_object_labels(item).intersection(STAGED_EXEC_OBJECT_LABELS):
            output.add(object_key)
    output.update(_object_keys_with_exec_sequence(ordered))
    return output


def collect_staged_chmod_event_ids(
    items: Iterable[Any],
    *,
    suspicious_object_keys: Iterable[str] | None = None,
    limit: int = 8,
) -> list[str]:
    staged_keys = collect_staged_object_keys(items, suspicious_object_keys=suspicious_object_keys)
    output: list[str] = []
    for item in _ordered_items(items):
        event_id = item_event_id(item)
        object_key = normalize_semantic_text(item_object_key(item))
        if not event_id or not object_key or object_key not in staged_keys:
            continue
        if item_event_type(item) in CHMOD_LIKE_EVENT_TYPES or "chmod" in semantic_item_text(item):
            output.append(event_id)
    return _unique_ids(output)[:limit]


def collect_staged_exec_event_ids(
    items: Iterable[Any],
    *,
    suspicious_object_keys: Iterable[str] | None = None,
    limit: int = 8,
) -> list[str]:
    staged_keys = collect_staged_object_keys(items, suspicious_object_keys=suspicious_object_keys)
    output: list[str] = []
    for item in _ordered_items(items):
        event_id = item_event_id(item)
        object_key = normalize_semantic_text(item_object_key(item))
        if not event_id or not object_key or object_key not in staged_keys:
            continue
        if item_event_type(item) in EXEC_LIKE_EVENT_TYPES:
            output.append(event_id)
    return _unique_ids(output)[:limit]


def staged_payload_basenames(
    items: Iterable[Any],
    *,
    suspicious_object_keys: Iterable[str] | None = None,
) -> set[str]:
    basenames: set[str] = set()
    for object_key in collect_staged_exec_paths(items, suspicious_object_keys=suspicious_object_keys):
        basename = object_key.rsplit("/", 1)[-1].strip()
        if basename:
            basenames.add(basename.lower())
    return basenames


def staged_exec_process_names(
    items: Iterable[Any],
    *,
    suspicious_object_keys: Iterable[str] | None = None,
) -> set[str]:
    staged_keys = collect_staged_object_keys(items, suspicious_object_keys=suspicious_object_keys)
    output: set[str] = set()
    for item in _ordered_items(items):
        event_type = item_event_type(item)
        if event_type not in EXEC_LIKE_EVENT_TYPES:
            continue
        process_name = normalize_semantic_text(item_process_name(item))
        if not process_name or process_name in GENERIC_EXECUTOR_NAMES:
            continue
        object_key = normalize_semantic_text(item_object_key(item))
        if object_key and is_system_service_object_key(object_key):
            continue
        labels = item_event_labels(item)
        if (
            object_key in staged_keys
            or object_key in PLACEHOLDER_OBJECT_KEYS
            or bool(labels.intersection(STAGED_EXEC_EVENT_LABELS))
        ):
            output.add(process_name)
    return output


def _extract_cmd_path(cmdline: str) -> str:
    text = str(cmdline or "").strip().strip("'\"")
    if not text:
        return ""
    token = text.split()[0].strip().strip("'\"")
    if token.startswith("/") or token.startswith("./"):
        return normalize_semantic_text(token)
    return ""


def collect_staged_exec_paths(
    items: Iterable[Any],
    *,
    suspicious_object_keys: Iterable[str] | None = None,
) -> set[str]:
    staged_keys = collect_staged_object_keys(items, suspicious_object_keys=suspicious_object_keys)
    output: set[str] = set()
    for item in _ordered_items(items):
        event_type = item_event_type(item)
        if event_type not in EXEC_LIKE_EVENT_TYPES:
            continue
        object_key = normalize_semantic_text(item_object_key(item))
        if object_key and object_key in staged_keys and not is_temp_exec_path(object_key):
            if object_key not in PLACEHOLDER_OBJECT_KEYS:
                output.add(object_key)
                continue
            cmd_path = _extract_cmd_path(item_raw_cmdline(item))
            if cmd_path and not is_temp_exec_path(cmd_path):
                output.add(cmd_path)
    return output


def collect_payload_elevate_event_ids(
    items: Iterable[Any],
    *,
    suspicious_object_keys: Iterable[str] | None = None,
    limit: int = 8,
) -> list[str]:
    staged_keys = collect_staged_object_keys(items, suspicious_object_keys=suspicious_object_keys)
    staged_exec_paths = collect_staged_exec_paths(items, suspicious_object_keys=suspicious_object_keys)
    staged_process_names = staged_exec_process_names(items, suspicious_object_keys=suspicious_object_keys)
    staged_basenames = {
        basename
        for basename in staged_payload_basenames(items, suspicious_object_keys=suspicious_object_keys)
        if basename
        and not any(basename == key.rsplit("/", 1)[-1].strip().lower() for key in staged_exec_paths if is_temp_exec_path(key))
    }
    output: list[str] = []
    for item in _ordered_items(items):
        event_id = item_event_id(item)
        if not event_id:
            continue
        text = semantic_item_text(item)
        object_key = normalize_semantic_text(item_object_key(item))
        has_elevate_text = (
            "elevate" in text
            or "root privileges" in text
            or "as root" in text
            or "root access" in text
        )
        if has_elevate_text and object_key:
            if is_temp_exec_path(object_key):
                continue
            if object_key in staged_keys or object_key in staged_exec_paths:
                output.append(event_id)
                continue
            basename = object_key.rsplit("/", 1)[-1].strip()
            if basename and (basename.lower() in staged_basenames or basename.lower() in staged_process_names):
                output.append(event_id)
                continue
        if has_elevate_text and any(basename in text for basename in staged_basenames.union(staged_process_names)):
            output.append(event_id)
            continue
        if item_event_type(item) == "CLONE" and object_key and not is_temp_exec_path(object_key):
            if object_key in staged_exec_paths:
                output.append(event_id)
                continue
            basename = object_key.rsplit("/", 1)[-1].strip()
            if basename and (basename.lower() in staged_basenames or basename.lower() in staged_process_names):
                output.append(event_id)
    return _unique_ids(output)[:limit]


def _item_value(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def _ordered_items(items: Iterable[Any]) -> list[Any]:
    return sorted(
        list(items),
        key=lambda item: (
            item_order_index(item),
            item_timestamp(item).isoformat() if item_timestamp(item) is not None else "",
            item_event_id(item),
        ),
    )


def _object_keys_with_exec_sequence(items: list[Any]) -> set[str]:
    grouped: dict[str, list[Any]] = defaultdict(list)
    for item in items:
        object_key = normalize_semantic_text(item_object_key(item))
        if not object_key or is_system_service_object_key(object_key):
            continue
        grouped[object_key].append(item)
    output: set[str] = set()
    for object_key, group in grouped.items():
        if _group_has_exec_sequence(group):
            output.add(object_key)
    return output


def _group_has_exec_sequence(group: list[Any]) -> bool:
    last_write: Any | None = None
    last_chmod: Any | None = None
    for item in _ordered_items(group):
        event_type = item_event_type(item)
        if event_type in WRITE_LIKE_EVENT_TYPES:
            last_write = item
            last_chmod = None
            continue
        if event_type in CHMOD_LIKE_EVENT_TYPES or "chmod" in semantic_item_text(item):
            if last_write is not None and _within_staging_window(last_write, item):
                last_chmod = item
            continue
        if event_type in EXEC_LIKE_EVENT_TYPES and last_chmod is not None and _within_staging_window(last_chmod, item):
            return True
    return False


def _within_staging_window(earlier: Any, later: Any) -> bool:
    earlier_ts = item_timestamp(earlier)
    later_ts = item_timestamp(later)
    if earlier_ts is not None and later_ts is not None:
        delta = later_ts - earlier_ts
        return timedelta(0) <= delta <= timedelta(minutes=DEFAULT_STAGED_WINDOW_MINUTES)
    return item_order_index(later) >= item_order_index(earlier)


def _unique_ids(values: Iterable[str]) -> list[str]:
    output: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text not in output:
            output.append(text)
    return output
