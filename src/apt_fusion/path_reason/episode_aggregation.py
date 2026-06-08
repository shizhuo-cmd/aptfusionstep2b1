from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timedelta
from typing import Any, Iterable

from .path_schemas import EventEpisode


def aggregate_episodes(
    task_id: str,
    events: Iterable[dict[str, Any]],
    *,
    bucket_minutes: int,
    max_representative_events: int,
) -> list[EventEpisode]:
    buckets: "OrderedDict[str, EventEpisode]" = OrderedDict()
    for event in events:
        timestamp = _parse_timestamp(event.get("timestamp"))
        bucket_start = _bucket_start(timestamp, bucket_minutes)
        key = _episode_key(task_id, event, bucket_start)
        episode = buckets.get(key)
        labels_triggered = {
            str(item).strip()
            for item in event.get("labels_triggered", [])
            if str(item).strip()
        }
        if episode is None:
            episode = EventEpisode(
                episode_id=f"{task_id}_ep_{len(buckets):04d}",
                task_id=task_id,
                process_guid=str(event.get("process_guid", "")).strip(),
                event_type=str(event.get("event_type", "")).strip(),
                object_type=str(event.get("object_type", "")).strip(),
                object_class=str(event.get("object_class", "")).strip(),
                object_key=str(event.get("object_key", "")).strip(),
                semantic_flow_direction=str(event.get("semantic_flow_direction", "")).strip(),
                process_label_signature=str(event.get("process_label_signature", "")).strip(),
                object_label_signature=str(event.get("object_label_signature", "")).strip(),
                object_semantic_epoch=int(event.get("object_semantic_epoch", 0) or 0),
                process_control_epoch=int(event.get("process_control_epoch", 0) or 0),
                count=0,
                first_time=bucket_start or timestamp,
                last_time=timestamp,
                representative_event_ids=[],
                representative_raw_log_ids=[],
                labels_triggered=set(labels_triggered),
                is_force_kept=bool(event.get("is_force_kept", False)),
                summary=str(event.get("description", "")).strip(),
            )
            buckets[key] = episode
        episode.count += 1
        if timestamp is not None:
            if episode.first_time is None or timestamp < episode.first_time:
                episode.first_time = timestamp
            if episode.last_time is None or timestamp > episode.last_time:
                episode.last_time = timestamp
        episode.labels_triggered.update(labels_triggered)
        episode.is_force_kept = episode.is_force_kept or bool(event.get("is_force_kept", False))
        _push_representative(
            episode.representative_event_ids,
            str(event.get("event_id", "")).strip(),
            max_representative_events,
        )
        _push_representative(
            episode.representative_raw_log_ids,
            str(event.get("raw_log_id", "")).strip(),
            max_representative_events,
        )
        if not episode.summary:
            episode.summary = str(event.get("description", "")).strip()
    return list(buckets.values())


def _episode_key(task_id: str, event: dict[str, Any], bucket_start: datetime | None) -> str:
    bucket_text = bucket_start.isoformat() if isinstance(bucket_start, datetime) else "none"
    return "\x1f".join(
        [
            task_id,
            bucket_text,
            str(event.get("process_guid", "")).strip(),
            str(event.get("event_type", "")).strip(),
            str(event.get("object_type", "")).strip(),
            str(event.get("object_class", "")).strip(),
            str(event.get("object_key", "")).strip(),
            str(event.get("semantic_flow_direction", "")).strip(),
            str(event.get("process_label_signature", "")).strip(),
            str(event.get("object_label_signature", "")).strip(),
            str(int(event.get("object_semantic_epoch", 0) or 0)),
            str(int(event.get("process_control_epoch", 0) or 0)),
        ]
    )


def _bucket_start(value: datetime | None, bucket_minutes: int) -> datetime | None:
    if value is None:
        return None
    minute = (value.minute // bucket_minutes) * bucket_minutes
    return value.replace(second=0, microsecond=0, minute=minute)


def _parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text[:19], fmt)
        except ValueError:
            continue
    return None


def _push_representative(values: list[str], item: str, limit: int) -> None:
    if not item:
        return
    if item in values:
        return
    if len(values) < limit:
        values.append(item)
        return
    if len(values) == limit:
        values[-1] = item

