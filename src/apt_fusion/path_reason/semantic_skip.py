from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .path_rules import PathRules


@dataclass
class LatestSemanticEntry:
    semantic_key: str
    last_seen: datetime | None
    process_label_signature: str
    object_label_signature: str
    object_semantic_epoch: int
    process_control_epoch: int


class LatestSemanticTable:
    def __init__(self, max_size: int, *, clear_when_full: bool = True) -> None:
        self.max_size = max(1, int(max_size))
        self.clear_when_full = bool(clear_when_full)
        self._entries: dict[str, LatestSemanticEntry] = {}
        self._process_to_keys: dict[str, set[str]] = {}
        self._object_to_keys: dict[str, set[str]] = {}

    def get(self, semantic_key: str) -> LatestSemanticEntry | None:
        return self._entries.get(semantic_key)

    def remember(
        self,
        semantic_key: str,
        *,
        timestamp: datetime | None,
        process_guid: str,
        object_key: str,
        process_label_signature: str,
        object_label_signature: str,
        object_semantic_epoch: int,
        process_control_epoch: int,
    ) -> None:
        self._ensure_capacity()
        self._entries[semantic_key] = LatestSemanticEntry(
            semantic_key=semantic_key,
            last_seen=timestamp,
            process_label_signature=process_label_signature,
            object_label_signature=object_label_signature,
            object_semantic_epoch=int(object_semantic_epoch),
            process_control_epoch=int(process_control_epoch),
        )
        if process_guid:
            self._process_to_keys.setdefault(process_guid, set()).add(semantic_key)
        if object_key:
            self._object_to_keys.setdefault(object_key, set()).add(semantic_key)

    def invalidate_process(self, process_guid: str) -> int:
        return self._invalidate_keys(self._process_to_keys.pop(str(process_guid), set()))

    def invalidate_object(self, object_key: str) -> int:
        return self._invalidate_keys(self._object_to_keys.pop(str(object_key), set()))

    def _invalidate_keys(self, keys: set[str]) -> int:
        count = 0
        for key in list(keys):
            if self._entries.pop(key, None) is not None:
                count += 1
        if count:
            for process_guid, mapped in list(self._process_to_keys.items()):
                mapped.difference_update(keys)
                if not mapped:
                    self._process_to_keys.pop(process_guid, None)
            for object_key, mapped in list(self._object_to_keys.items()):
                mapped.difference_update(keys)
                if not mapped:
                    self._object_to_keys.pop(object_key, None)
        return count

    def _ensure_capacity(self) -> None:
        if len(self._entries) < self.max_size:
            return
        if self.clear_when_full:
            self._entries.clear()
            self._process_to_keys.clear()
            self._object_to_keys.clear()
            return
        oldest_keys = list(self._entries.keys())[: max(1, len(self._entries) // 10)]
        self._invalidate_keys(set(oldest_keys))


def make_semantic_key(
    *,
    task_id: str,
    process_guid: str,
    event_type: str,
    object_key: str,
    object_class: str,
    semantic_flow_direction: str,
) -> str:
    parts = [
        str(task_id).strip(),
        str(process_guid).strip(),
        str(event_type).strip().upper(),
        str(object_key).strip(),
        str(object_class).strip(),
        str(semantic_flow_direction).strip().upper(),
    ]
    return "\x1f".join(parts)


def should_skip_semantically(
    table: LatestSemanticTable,
    *,
    semantic_key: str,
    timestamp: datetime | None,
    process_label_signature: str,
    object_label_signature: str,
    object_semantic_epoch: int,
    process_control_epoch: int,
    ttl_seconds: int,
    ignore_if_timestamp_missing: bool,
) -> bool:
    entry = table.get(semantic_key)
    if entry is None:
        return False
    if (
        entry.process_label_signature != process_label_signature
        or entry.object_label_signature != object_label_signature
        or entry.object_semantic_epoch != int(object_semantic_epoch)
        or entry.process_control_epoch != int(process_control_epoch)
    ):
        return False
    if timestamp is None or entry.last_seen is None:
        return not bool(ignore_if_timestamp_missing)
    delta = abs((timestamp - entry.last_seen).total_seconds())
    return delta <= float(ttl_seconds)


def event_is_force_kept(
    *,
    event_type: str,
    object_class: str,
    remote_ip: str | None,
    labels_triggered: set[str],
    rules: PathRules,
    cfg: Any,
) -> bool:
    action = str(event_type or "").upper()
    if action == "EXEC" and bool(getattr(cfg, "semantic_force_keep_exec", True)):
        return True
    if remote_ip and bool(getattr(cfg, "semantic_force_keep_external_network", True)):
        if action in {"CONNECT", "ACCEPT", "SEND", "RECV"}:
            return True
    if bool(getattr(cfg, "semantic_force_keep_write_sensitive", True)) and action in {
        "WRITE",
        "CREATE",
        "RENAME",
        "CHMOD",
        "CHOWN",
        "DELETE",
    }:
        if object_class in {"temp_file", "persistence_file", "privilege_file", "credential_file", "business_file"}:
            return True
    if action in {str(item).upper() for item in rules.get("semantic_skip.force_keep.event_types", [])}:
        return True
    if object_class in {str(item).strip() for item in rules.get("semantic_skip.force_keep.object_classes", [])}:
        return True
    if labels_triggered:
        return True
    return False

