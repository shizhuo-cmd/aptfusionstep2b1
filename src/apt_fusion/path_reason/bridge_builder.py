from __future__ import annotations

from typing import Any

from .path_schemas import BridgeEdge, ObjectAccessRecord, ObjectState, ProcessState


def build_bridge_edges(
    task_id: str,
    object_states: dict[str, ObjectState],
    process_states: dict[str, ProcessState],
    rules: Any,
) -> list[BridgeEdge]:
    writers = {str(item).upper() for item in rules.get("bridging.writers_event_types", [])}
    readers = {str(item).upper() for item in rules.get("bridging.readers_or_execs_event_types", [])}
    allow_labels = {str(item).strip() for item in rules.get("bridging.allow_object_labels", [])}
    deny_labels = {str(item).strip() for item in rules.get("bridging.deny_object_labels", [])}
    deny_classes = {str(item).strip() for item in rules.get("bridging.deny_object_classes", [])}
    max_gap_minutes = float(rules.get("bridging.max_time_gap_minutes", 30))
    per_object_limit = int(rules.get("bridging.per_object_edge_limit", 20))
    edges: list[BridgeEdge] = []
    for object_key, object_state in object_states.items():
        if object_state.object_class in deny_classes:
            continue
        if object_state.labels.intersection(deny_labels):
            continue
        if not object_state.labels.intersection(allow_labels):
            continue
        grouped = sorted(object_state.access_records, key=lambda item: int(item.order_index))
        created = 0
        for index, record in enumerate(grouped):
            if record.event_type.upper() not in writers:
                continue
            for candidate in grouped[index + 1 :]:
                if candidate.event_type.upper() not in readers:
                    continue
                if record.process_guid == candidate.process_guid:
                    continue
                if not _within_gap(record, candidate, max_gap_minutes):
                    continue
                if record.object_semantic_epoch_after != candidate.object_semantic_epoch_before:
                    continue
                bridge = BridgeEdge(
                    task_id=task_id,
                    src_process_guid=record.process_guid,
                    dst_process_guid=candidate.process_guid,
                    object_key=object_key,
                    object_labels=set(object_state.labels),
                    write_event_id=record.event_id,
                    read_or_exec_event_id=candidate.event_id,
                    write_time=record.timestamp,
                    read_or_exec_time=candidate.timestamp,
                    bridge_type=_bridge_type(object_state, candidate.event_type),
                    confidence=_bridge_confidence(object_state, candidate.event_type),
                    reason=_bridge_reason(object_state, candidate.event_type),
                )
                edges.append(bridge)
                created += 1
                if created >= per_object_limit:
                    break
            if created >= per_object_limit:
                break
    return edges


def _within_gap(source: ObjectAccessRecord, target: ObjectAccessRecord, max_gap_minutes: float) -> bool:
    if source.timestamp is None or target.timestamp is None:
        return True
    if target.timestamp < source.timestamp:
        return False
    return (target.timestamp - source.timestamp).total_seconds() <= max_gap_minutes * 60.0


def _bridge_type(object_state: ObjectState, target_event_type: str) -> str:
    event_type = str(target_event_type or "").upper()
    if event_type in {"EXEC", "LOAD", "MMAP"}:
        return "write_to_exec"
    if "O_PERSISTENCE" in object_state.labels:
        return "persistence_follow_on"
    if "O_ARCHIVE" in object_state.labels:
        return "archive_follow_on"
    return "write_to_read"


def _bridge_confidence(object_state: ObjectState, target_event_type: str) -> float:
    event_type = str(target_event_type or "").upper()
    if event_type in {"EXEC", "LOAD", "MMAP"} and object_state.labels.intersection(
        {"O_FILE_TEMP", "O_FILE_DOWNLOADED", "O_FILE_UPLOADED", "O_SUSPECT_WRITTEN_EXECUTABLE"}
    ):
        return 0.93
    if object_state.labels.intersection({"O_PERSISTENCE", "O_PRIV_CONFIG"}):
        return 0.78
    if object_state.labels.intersection({"O_ARCHIVE"}):
        return 0.66
    return 0.55


def _bridge_reason(object_state: ObjectState, target_event_type: str) -> str:
    event_type = str(target_event_type or "").upper()
    if event_type in {"EXEC", "LOAD", "MMAP"}:
        return "same object was written first and later executed or loaded by another process"
    if "O_PERSISTENCE" in object_state.labels:
        return "same persistence-related object was modified first and later consumed by another process"
    if "O_ARCHIVE" in object_state.labels:
        return "same archive-related object was produced before later access by another process"
    return "same object was modified first and later accessed by another process"

