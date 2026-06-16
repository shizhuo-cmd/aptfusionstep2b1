from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


def parse_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(text[:19], fmt)
            except ValueError:
                continue
    return None


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if isinstance(value, datetime) else None


def _sorted_list(values: set[str]) -> list[str]:
    return sorted(str(item) for item in values if str(item).strip())


@dataclass
class TaskPrior:
    task_id: str
    task_score: float
    task_probability: float
    root_process_ids: list[str] = field(default_factory=list)
    task_root_id: str = ""
    boundary_node_ids: list[str] = field(default_factory=list)
    top_processes: list[dict[str, Any]] = field(default_factory=list)
    top_edges: list[dict[str, Any]] = field(default_factory=list)
    first_event: datetime | None = None
    last_event: datetime | None = None
    matched_event_count_total: int = 0
    graphsage_probability: float | None = None
    stats_probability: float | None = None
    task_label: int | None = None
    predicted_label: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "task_score": float(self.task_score),
            "task_probability": float(self.task_probability),
            "root_process_ids": list(self.root_process_ids),
            "task_root_id": str(self.task_root_id),
            "boundary_node_ids": list(self.boundary_node_ids),
            "top_processes": list(self.top_processes),
            "top_edges": list(self.top_edges),
            "first_event": _iso(self.first_event),
            "last_event": _iso(self.last_event),
            "matched_event_count_total": int(self.matched_event_count_total),
            "graphsage_probability": self.graphsage_probability,
            "stats_probability": self.stats_probability,
            "task_label": self.task_label,
            "predicted_label": self.predicted_label,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "TaskPrior":
        return cls(
            task_id=str(payload.get("task_id", "")).strip(),
            task_score=float(payload.get("task_score", 0.0) or 0.0),
            task_probability=float(payload.get("task_probability", 0.0) or 0.0),
            root_process_ids=[str(item) for item in payload.get("root_process_ids", [])],
            task_root_id=str(payload.get("task_root_id", "")).strip(),
            boundary_node_ids=[str(item) for item in payload.get("boundary_node_ids", [])],
            top_processes=list(payload.get("top_processes", [])),
            top_edges=list(payload.get("top_edges", [])),
            first_event=parse_datetime(payload.get("first_event")),
            last_event=parse_datetime(payload.get("last_event")),
            matched_event_count_total=int(payload.get("matched_event_count_total", 0) or 0),
            graphsage_probability=(
                None if payload.get("graphsage_probability") is None else float(payload.get("graphsage_probability"))
            ),
            stats_probability=(
                None if payload.get("stats_probability") is None else float(payload.get("stats_probability"))
            ),
            task_label=None if payload.get("task_label") is None else int(payload.get("task_label")),
            predicted_label=(
                None if payload.get("predicted_label") is None else int(payload.get("predicted_label"))
            ),
        )


@dataclass
class NormalizedEvent:
    event_id: str
    raw_log_id: str
    task_id: str
    host: str

    timestamp: datetime | None
    order_index: int

    process_guid: str
    process_name: str
    process_exe: str | None
    process_cmdline: str | None
    parent_process_guid: str | None

    event_type: str
    object_type: str
    object_key: str
    object_name: str | None
    object_class: str

    syscall_direction: str
    semantic_flow_direction: str

    result: str | None
    local_ip: str | None
    local_port: int | None
    remote_ip: str | None
    remote_port: int | None

    raw_event: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["timestamp"] = _iso(self.timestamp)
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "NormalizedEvent":
        return cls(
            event_id=str(payload.get("event_id", "")).strip(),
            raw_log_id=str(payload.get("raw_log_id", "")).strip(),
            task_id=str(payload.get("task_id", "")).strip(),
            host=str(payload.get("host", "")).strip(),
            timestamp=parse_datetime(payload.get("timestamp")),
            order_index=int(payload.get("order_index", 0) or 0),
            process_guid=str(payload.get("process_guid", "")).strip(),
            process_name=str(payload.get("process_name", "")).strip(),
            process_exe=(
                None if payload.get("process_exe") in (None, "") else str(payload.get("process_exe")).strip()
            ),
            process_cmdline=(
                None if payload.get("process_cmdline") in (None, "") else str(payload.get("process_cmdline")).strip()
            ),
            parent_process_guid=(
                None
                if payload.get("parent_process_guid") in (None, "")
                else str(payload.get("parent_process_guid")).strip()
            ),
            event_type=str(payload.get("event_type", "")).strip(),
            object_type=str(payload.get("object_type", "")).strip(),
            object_key=str(payload.get("object_key", "")).strip(),
            object_name=None if payload.get("object_name") in (None, "") else str(payload.get("object_name")).strip(),
            object_class=str(payload.get("object_class", "")).strip(),
            syscall_direction=str(payload.get("syscall_direction", "")).strip(),
            semantic_flow_direction=str(payload.get("semantic_flow_direction", "")).strip(),
            result=None if payload.get("result") in (None, "") else str(payload.get("result")).strip(),
            local_ip=None if payload.get("local_ip") in (None, "") else str(payload.get("local_ip")).strip(),
            local_port=None if payload.get("local_port") in (None, "") else int(payload.get("local_port")),
            remote_ip=None if payload.get("remote_ip") in (None, "") else str(payload.get("remote_ip")).strip(),
            remote_port=None if payload.get("remote_port") in (None, "") else int(payload.get("remote_port")),
            raw_event=dict(payload.get("raw_event", {}) or {}),
        )


@dataclass
class ObjectAccessRecord:
    task_id: str
    object_key: str
    object_type: str
    object_class: str

    process_guid: str
    process_name: str

    event_type: str
    timestamp: datetime | None
    order_index: int
    event_id: str
    raw_log_id: str

    syscall_direction: str
    semantic_flow_direction: str

    process_label_signature_before: str
    process_label_signature_after: str

    object_label_signature_before: str
    object_label_signature_after: str

    object_semantic_epoch_before: int
    object_semantic_epoch_after: int
    process_control_epoch_before: int
    process_control_epoch_after: int

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["timestamp"] = _iso(self.timestamp)
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ObjectAccessRecord":
        return cls(
            task_id=str(payload.get("task_id", "")).strip(),
            object_key=str(payload.get("object_key", "")).strip(),
            object_type=str(payload.get("object_type", "")).strip(),
            object_class=str(payload.get("object_class", "")).strip(),
            process_guid=str(payload.get("process_guid", "")).strip(),
            process_name=str(payload.get("process_name", "")).strip(),
            event_type=str(payload.get("event_type", "")).strip(),
            timestamp=parse_datetime(payload.get("timestamp")),
            order_index=int(payload.get("order_index", 0) or 0),
            event_id=str(payload.get("event_id", "")).strip(),
            raw_log_id=str(payload.get("raw_log_id", "")).strip(),
            syscall_direction=str(payload.get("syscall_direction", "")).strip(),
            semantic_flow_direction=str(payload.get("semantic_flow_direction", "")).strip(),
            process_label_signature_before=str(payload.get("process_label_signature_before", "")).strip(),
            process_label_signature_after=str(payload.get("process_label_signature_after", "")).strip(),
            object_label_signature_before=str(payload.get("object_label_signature_before", "")).strip(),
            object_label_signature_after=str(payload.get("object_label_signature_after", "")).strip(),
            object_semantic_epoch_before=int(payload.get("object_semantic_epoch_before", 0) or 0),
            object_semantic_epoch_after=int(payload.get("object_semantic_epoch_after", 0) or 0),
            process_control_epoch_before=int(payload.get("process_control_epoch_before", 0) or 0),
            process_control_epoch_after=int(payload.get("process_control_epoch_after", 0) or 0),
        )


@dataclass
class TaskLocalEvidenceGraph:
    task_id: str
    process_nodes: list[str] = field(default_factory=list)
    object_nodes: list[str] = field(default_factory=list)
    event_edges: list[dict[str, Any]] = field(default_factory=list)
    anchor_processes: list[str] = field(default_factory=list)
    boundary_node_ids: list[str] = field(default_factory=list)
    cross_task_link_refs: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "process_nodes": list(self.process_nodes),
            "object_nodes": list(self.object_nodes),
            "event_edges": list(self.event_edges),
            "anchor_processes": list(self.anchor_processes),
            "boundary_node_ids": list(self.boundary_node_ids),
            "cross_task_link_refs": list(self.cross_task_link_refs),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "TaskLocalEvidenceGraph":
        return cls(
            task_id=str(payload.get("task_id", "")).strip(),
            process_nodes=[str(item) for item in payload.get("process_nodes", [])],
            object_nodes=[str(item) for item in payload.get("object_nodes", [])],
            event_edges=[dict(item) for item in payload.get("event_edges", []) if isinstance(item, dict)],
            anchor_processes=[str(item) for item in payload.get("anchor_processes", [])],
            boundary_node_ids=[str(item) for item in payload.get("boundary_node_ids", [])],
            cross_task_link_refs=[dict(item) for item in payload.get("cross_task_link_refs", []) if isinstance(item, dict)],
        )


@dataclass
class ObjectVersion:
    task_id: str
    object_key: str
    version_id: str
    created_by_event_id: str | None = None
    first_time: datetime | None = None
    last_time: datetime | None = None
    labels: set[str] = field(default_factory=set)
    writer_processes: set[str] = field(default_factory=set)
    reader_processes: set[str] = field(default_factory=set)
    executor_processes: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "object_key": self.object_key,
            "version_id": self.version_id,
            "created_by_event_id": self.created_by_event_id,
            "first_time": _iso(self.first_time),
            "last_time": _iso(self.last_time),
            "labels": _sorted_list(self.labels),
            "writer_processes": _sorted_list(self.writer_processes),
            "reader_processes": _sorted_list(self.reader_processes),
            "executor_processes": _sorted_list(self.executor_processes),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ObjectVersion":
        return cls(
            task_id=str(payload.get("task_id", "")).strip(),
            object_key=str(payload.get("object_key", "")).strip(),
            version_id=str(payload.get("version_id", "")).strip(),
            created_by_event_id=(
                None if payload.get("created_by_event_id") in (None, "") else str(payload.get("created_by_event_id")).strip()
            ),
            first_time=parse_datetime(payload.get("first_time")),
            last_time=parse_datetime(payload.get("last_time")),
            labels={str(item).strip() for item in payload.get("labels", []) if str(item).strip()},
            writer_processes={str(item).strip() for item in payload.get("writer_processes", []) if str(item).strip()},
            reader_processes={str(item).strip() for item in payload.get("reader_processes", []) if str(item).strip()},
            executor_processes={str(item).strip() for item in payload.get("executor_processes", []) if str(item).strip()},
        )


@dataclass
class LabelProvenanceRecord:
    label_id: str
    task_id: str
    label: str
    label_type: str
    holder_entity_type: str
    holder_entity_id: str
    created_at: datetime | None = None
    source_entity_type: str | None = None
    source_entity_id: str | None = None
    source_type: str = ""
    event_id: str | None = None
    event_type: str | None = None
    rule_id: str = ""
    context_id: str | None = None
    prev_label_ids: list[str] = field(default_factory=list)
    segment_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "label_id": self.label_id,
            "task_id": self.task_id,
            "label": self.label,
            "label_type": self.label_type,
            "holder_entity_type": self.holder_entity_type,
            "holder_entity_id": self.holder_entity_id,
            "created_at": _iso(self.created_at),
            "source_entity_type": self.source_entity_type,
            "source_entity_id": self.source_entity_id,
            "source_type": self.source_type,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "rule_id": self.rule_id,
            "context_id": self.context_id,
            "prev_label_ids": list(self.prev_label_ids),
            "segment_id": self.segment_id,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "LabelProvenanceRecord":
        return cls(
            label_id=str(payload.get("label_id", "")).strip(),
            task_id=str(payload.get("task_id", "")).strip(),
            label=str(payload.get("label", "")).strip(),
            label_type=str(payload.get("label_type", "")).strip(),
            holder_entity_type=str(payload.get("holder_entity_type", "")).strip(),
            holder_entity_id=str(payload.get("holder_entity_id", "")).strip(),
            created_at=parse_datetime(payload.get("created_at")),
            source_entity_type=(
                None if payload.get("source_entity_type") in (None, "") else str(payload.get("source_entity_type")).strip()
            ),
            source_entity_id=(
                None if payload.get("source_entity_id") in (None, "") else str(payload.get("source_entity_id")).strip()
            ),
            source_type=str(payload.get("source_type", "")).strip(),
            event_id=None if payload.get("event_id") in (None, "") else str(payload.get("event_id")).strip(),
            event_type=None if payload.get("event_type") in (None, "") else str(payload.get("event_type")).strip(),
            rule_id=str(payload.get("rule_id", "")).strip(),
            context_id=None if payload.get("context_id") in (None, "") else str(payload.get("context_id")).strip(),
            prev_label_ids=[str(item) for item in payload.get("prev_label_ids", [])],
            segment_id=None if payload.get("segment_id") in (None, "") else str(payload.get("segment_id")).strip(),
        )


@dataclass
class ProcessState:
    task_id: str
    process_guid: str
    process_name: str
    process_exe: str | None
    process_cmdline: str | None
    start_time: datetime | None
    end_time: datetime | None
    parent_process_guid: str | None = None

    status_labels: set[str] = field(default_factory=set)
    behavior_labels: set[str] = field(default_factory=set)
    aggregate_labels: set[str] = field(default_factory=set)

    process_control_epoch: int = 0
    score: float = 0.0
    prior_score: float = 0.0

    evidence_event_ids: list[str] = field(default_factory=list)
    important_objects: set[str] = field(default_factory=set)
    context_ids: set[str] = field(default_factory=set)
    label_ids: list[str] = field(default_factory=list)

    def all_labels(self) -> set[str]:
        return set(self.status_labels) | set(self.behavior_labels) | set(self.aggregate_labels)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "process_guid": self.process_guid,
            "process_name": self.process_name,
            "process_exe": self.process_exe,
            "process_cmdline": self.process_cmdline,
            "start_time": _iso(self.start_time),
            "end_time": _iso(self.end_time),
            "parent_process_guid": self.parent_process_guid,
            "status_labels": _sorted_list(self.status_labels),
            "behavior_labels": _sorted_list(self.behavior_labels),
            "aggregate_labels": _sorted_list(self.aggregate_labels),
            "process_control_epoch": int(self.process_control_epoch),
            "score": float(self.score),
            "prior_score": float(self.prior_score),
            "evidence_event_ids": list(self.evidence_event_ids),
            "important_objects": _sorted_list(self.important_objects),
            "context_ids": _sorted_list(self.context_ids),
            "label_ids": list(self.label_ids),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ProcessState":
        return cls(
            task_id=str(payload.get("task_id", "")).strip(),
            process_guid=str(payload.get("process_guid", "")).strip(),
            process_name=str(payload.get("process_name", "")).strip(),
            process_exe=None if payload.get("process_exe") in (None, "") else str(payload.get("process_exe")).strip(),
            process_cmdline=(
                None if payload.get("process_cmdline") in (None, "") else str(payload.get("process_cmdline")).strip()
            ),
            start_time=parse_datetime(payload.get("start_time")),
            end_time=parse_datetime(payload.get("end_time")),
            parent_process_guid=(
                None
                if payload.get("parent_process_guid") in (None, "")
                else str(payload.get("parent_process_guid")).strip()
            ),
            status_labels={str(item).strip() for item in payload.get("status_labels", []) if str(item).strip()},
            behavior_labels={str(item).strip() for item in payload.get("behavior_labels", []) if str(item).strip()},
            aggregate_labels={str(item).strip() for item in payload.get("aggregate_labels", []) if str(item).strip()},
            process_control_epoch=int(payload.get("process_control_epoch", 0) or 0),
            score=float(payload.get("score", 0.0) or 0.0),
            prior_score=float(payload.get("prior_score", 0.0) or 0.0),
            evidence_event_ids=[str(item) for item in payload.get("evidence_event_ids", [])],
            important_objects={str(item).strip() for item in payload.get("important_objects", []) if str(item).strip()},
            context_ids={str(item).strip() for item in payload.get("context_ids", []) if str(item).strip()},
            label_ids=[str(item) for item in payload.get("label_ids", [])],
        )


@dataclass
class ObjectState:
    task_id: str
    object_key: str
    object_type: str
    object_class: str

    labels: set[str] = field(default_factory=set)
    semantic_epoch: int = 0

    access_records: list[ObjectAccessRecord] = field(default_factory=list)

    first_time: datetime | None = None
    last_time: datetime | None = None

    is_bridge_allowed: bool = False
    bridge_reason: str | None = None

    read_count: int = 0
    write_count: int = 0
    exec_count: int = 0
    current_version_id: str = ""
    context_ids: set[str] = field(default_factory=set)
    label_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "object_key": self.object_key,
            "object_type": self.object_type,
            "object_class": self.object_class,
            "labels": _sorted_list(self.labels),
            "semantic_epoch": int(self.semantic_epoch),
            "access_records": [record.to_dict() for record in self.access_records],
            "first_time": _iso(self.first_time),
            "last_time": _iso(self.last_time),
            "is_bridge_allowed": bool(self.is_bridge_allowed),
            "bridge_reason": self.bridge_reason,
            "read_count": int(self.read_count),
            "write_count": int(self.write_count),
            "exec_count": int(self.exec_count),
            "current_version_id": self.current_version_id,
            "context_ids": _sorted_list(self.context_ids),
            "label_ids": list(self.label_ids),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ObjectState":
        return cls(
            task_id=str(payload.get("task_id", "")).strip(),
            object_key=str(payload.get("object_key", "")).strip(),
            object_type=str(payload.get("object_type", "")).strip(),
            object_class=str(payload.get("object_class", "")).strip(),
            labels={str(item).strip() for item in payload.get("labels", []) if str(item).strip()},
            semantic_epoch=int(payload.get("semantic_epoch", 0) or 0),
            access_records=[ObjectAccessRecord.from_dict(item) for item in payload.get("access_records", [])],
            first_time=parse_datetime(payload.get("first_time")),
            last_time=parse_datetime(payload.get("last_time")),
            is_bridge_allowed=bool(payload.get("is_bridge_allowed", False)),
            bridge_reason=(
                None if payload.get("bridge_reason") in (None, "") else str(payload.get("bridge_reason")).strip()
            ),
            read_count=int(payload.get("read_count", 0) or 0),
            write_count=int(payload.get("write_count", 0) or 0),
            exec_count=int(payload.get("exec_count", 0) or 0),
            current_version_id=str(payload.get("current_version_id", "")).strip(),
            context_ids={str(item).strip() for item in payload.get("context_ids", []) if str(item).strip()},
            label_ids=[str(item) for item in payload.get("label_ids", [])],
        )


@dataclass
class EventEpisode:
    episode_id: str
    task_id: str
    process_guid: str
    event_type: str
    object_type: str
    object_class: str
    object_key: str

    semantic_flow_direction: str
    process_label_signature: str
    object_label_signature: str
    object_semantic_epoch: int
    process_control_epoch: int

    count: int
    first_time: datetime | None
    last_time: datetime | None

    representative_event_ids: list[str] = field(default_factory=list)
    representative_raw_log_ids: list[str] = field(default_factory=list)
    labels_triggered: set[str] = field(default_factory=set)
    is_force_kept: bool = False
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "episode_id": self.episode_id,
            "task_id": self.task_id,
            "process_guid": self.process_guid,
            "event_type": self.event_type,
            "object_type": self.object_type,
            "object_class": self.object_class,
            "object_key": self.object_key,
            "semantic_flow_direction": self.semantic_flow_direction,
            "process_label_signature": self.process_label_signature,
            "object_label_signature": self.object_label_signature,
            "object_semantic_epoch": int(self.object_semantic_epoch),
            "process_control_epoch": int(self.process_control_epoch),
            "count": int(self.count),
            "first_time": _iso(self.first_time),
            "last_time": _iso(self.last_time),
            "representative_event_ids": list(self.representative_event_ids),
            "representative_raw_log_ids": list(self.representative_raw_log_ids),
            "labels_triggered": _sorted_list(self.labels_triggered),
            "is_force_kept": bool(self.is_force_kept),
            "summary": self.summary,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "EventEpisode":
        return cls(
            episode_id=str(payload.get("episode_id", "")).strip(),
            task_id=str(payload.get("task_id", "")).strip(),
            process_guid=str(payload.get("process_guid", "")).strip(),
            event_type=str(payload.get("event_type", "")).strip(),
            object_type=str(payload.get("object_type", "")).strip(),
            object_class=str(payload.get("object_class", "")).strip(),
            object_key=str(payload.get("object_key", "")).strip(),
            semantic_flow_direction=str(payload.get("semantic_flow_direction", "")).strip(),
            process_label_signature=str(payload.get("process_label_signature", "")).strip(),
            object_label_signature=str(payload.get("object_label_signature", "")).strip(),
            object_semantic_epoch=int(payload.get("object_semantic_epoch", 0) or 0),
            process_control_epoch=int(payload.get("process_control_epoch", 0) or 0),
            count=int(payload.get("count", 0) or 0),
            first_time=parse_datetime(payload.get("first_time")),
            last_time=parse_datetime(payload.get("last_time")),
            representative_event_ids=[str(item) for item in payload.get("representative_event_ids", [])],
            representative_raw_log_ids=[str(item) for item in payload.get("representative_raw_log_ids", [])],
            labels_triggered={str(item).strip() for item in payload.get("labels_triggered", []) if str(item).strip()},
            is_force_kept=bool(payload.get("is_force_kept", False)),
            summary=str(payload.get("summary", "")).strip(),
        )


@dataclass
class BridgeEdge:
    task_id: str
    src_process_guid: str
    dst_process_guid: str
    object_key: str
    object_labels: set[str]

    write_event_id: str
    read_or_exec_event_id: str
    write_time: datetime | None
    read_or_exec_time: datetime | None

    bridge_type: str
    confidence: float
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "src_process_guid": self.src_process_guid,
            "dst_process_guid": self.dst_process_guid,
            "object_key": self.object_key,
            "object_labels": _sorted_list(self.object_labels),
            "write_event_id": self.write_event_id,
            "read_or_exec_event_id": self.read_or_exec_event_id,
            "write_time": _iso(self.write_time),
            "read_or_exec_time": _iso(self.read_or_exec_time),
            "bridge_type": self.bridge_type,
            "confidence": float(self.confidence),
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "BridgeEdge":
        return cls(
            task_id=str(payload.get("task_id", "")).strip(),
            src_process_guid=str(payload.get("src_process_guid", "")).strip(),
            dst_process_guid=str(payload.get("dst_process_guid", "")).strip(),
            object_key=str(payload.get("object_key", "")).strip(),
            object_labels={str(item).strip() for item in payload.get("object_labels", []) if str(item).strip()},
            write_event_id=str(payload.get("write_event_id", "")).strip(),
            read_or_exec_event_id=str(payload.get("read_or_exec_event_id", "")).strip(),
            write_time=parse_datetime(payload.get("write_time")),
            read_or_exec_time=parse_datetime(payload.get("read_or_exec_time")),
            bridge_type=str(payload.get("bridge_type", "")).strip(),
            confidence=float(payload.get("confidence", 0.0) or 0.0),
            reason=str(payload.get("reason", "")).strip(),
        )


@dataclass
class CandidatePath:
    path_id: str
    task_id: str

    process_chain: list[str]
    bridge_edges: list[BridgeEdge]
    stage_coverage: list[str]
    labels: list[str]

    risk_score: float
    risk_level: str
    path_type: str

    time_range: tuple[datetime | None, datetime | None]
    evidence_timeline: list[dict[str, Any]]
    summary: str
    warnings: list[str] = field(default_factory=list)
    support_event_ids: list[str] = field(default_factory=list)
    support_object_keys: list[str] = field(default_factory=list)
    support_relations: list[str] = field(default_factory=list)
    context_ids: list[str] = field(default_factory=list)
    chain_kind: str = ""
    family_tags: list[str] = field(default_factory=list)
    precursor_event_ids: list[str] = field(default_factory=list)
    followup_event_ids: list[str] = field(default_factory=list)
    network_support_summary: str = ""
    object_lineage_summary: str = ""
    holmes_matched_atoms: list[str] = field(default_factory=list)
    missed_truth_like_hints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path_id": self.path_id,
            "task_id": self.task_id,
            "process_chain": list(self.process_chain),
            "bridge_edges": [item.to_dict() for item in self.bridge_edges],
            "stage_coverage": list(self.stage_coverage),
            "labels": list(self.labels),
            "risk_score": float(self.risk_score),
            "risk_level": self.risk_level,
            "path_type": self.path_type,
            "time_range": {
                "start": _iso(self.time_range[0]),
                "end": _iso(self.time_range[1]),
            },
            "evidence_timeline": list(self.evidence_timeline),
            "summary": self.summary,
            "warnings": list(self.warnings),
            "support_event_ids": list(self.support_event_ids),
            "support_object_keys": list(self.support_object_keys),
            "support_relations": list(self.support_relations),
            "context_ids": list(self.context_ids),
            "chain_kind": self.chain_kind,
            "family_tags": list(self.family_tags),
            "precursor_event_ids": list(self.precursor_event_ids),
            "followup_event_ids": list(self.followup_event_ids),
            "network_support_summary": self.network_support_summary,
            "object_lineage_summary": self.object_lineage_summary,
            "holmes_matched_atoms": list(self.holmes_matched_atoms),
            "missed_truth_like_hints": list(self.missed_truth_like_hints),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CandidatePath":
        time_range = payload.get("time_range", {}) if isinstance(payload.get("time_range"), dict) else {}
        return cls(
            path_id=str(payload.get("path_id", "")).strip(),
            task_id=str(payload.get("task_id", "")).strip(),
            process_chain=[str(item) for item in payload.get("process_chain", [])],
            bridge_edges=[BridgeEdge.from_dict(item) for item in payload.get("bridge_edges", [])],
            stage_coverage=[str(item) for item in payload.get("stage_coverage", [])],
            labels=[str(item) for item in payload.get("labels", [])],
            risk_score=float(payload.get("risk_score", 0.0) or 0.0),
            risk_level=str(payload.get("risk_level", "")).strip(),
            path_type=str(payload.get("path_type", "")).strip(),
            time_range=(parse_datetime(time_range.get("start")), parse_datetime(time_range.get("end"))),
            evidence_timeline=list(payload.get("evidence_timeline", [])),
            summary=str(payload.get("summary", "")).strip(),
            warnings=[str(item) for item in payload.get("warnings", [])],
            support_event_ids=[str(item) for item in payload.get("support_event_ids", [])],
            support_object_keys=[str(item) for item in payload.get("support_object_keys", [])],
            support_relations=[str(item) for item in payload.get("support_relations", [])],
            context_ids=[str(item) for item in payload.get("context_ids", [])],
            chain_kind=str(payload.get("chain_kind", "")).strip(),
            family_tags=[str(item) for item in payload.get("family_tags", [])],
            precursor_event_ids=[str(item) for item in payload.get("precursor_event_ids", [])],
            followup_event_ids=[str(item) for item in payload.get("followup_event_ids", [])],
            network_support_summary=str(payload.get("network_support_summary", "")).strip(),
            object_lineage_summary=str(payload.get("object_lineage_summary", "")).strip(),
            holmes_matched_atoms=[str(item) for item in payload.get("holmes_matched_atoms", [])],
            missed_truth_like_hints=[str(item) for item in payload.get("missed_truth_like_hints", [])],
        )

