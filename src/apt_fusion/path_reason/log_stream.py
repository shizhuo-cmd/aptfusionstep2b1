from __future__ import annotations

import csv
import gzip
import heapq
import json
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Sequence

from ..common import ensure_dir, save_json
from ..config import FusionConfig
from .nodlink_windows_raw import is_nodlink_windows_host, parse_nodlink_windows_event

UUID_KEY = "com.bbn.tc.schema.avro.cdm18.UUID"
EVENT_KEY = "com.bbn.tc.schema.avro.cdm18.Event"
DATUM_KEY = "datum"
_AUGMENTED_TASK_ID_PATTERN = re.compile(r"_aug\d{3}$")


@dataclass
class _SubgraphMeta:
    subgraph_id: int
    task_id: str
    task_score: float
    process_ids: List[str]
    severity_level: str
    event_count: int = 0
    dropped_event_count: int = 0
    first_timestamp: str = ""
    last_timestamp: str = ""
    n_nodes: int = 0
    n_actions: int = 0
    time_window_dropped_count: int = 0
    topk_dropped_count: int = 0


@dataclass
class _EventRecord:
    subject_uuid: str
    object_uuid: str
    action: str
    timestamp: str
    object_type_hint: str
    object_attr_hint: str


@dataclass
class _NodeAttr:
    node_type: str
    node_attr: str


@dataclass
class _ProcessAliasState:
    raw_to_canonical: Dict[str, str]
    canonical_parent: Dict[str, str] = field(default_factory=dict)
    canonical_attr: Dict[str, str] = field(default_factory=dict)


class _TaskEventWriterCache:
    def __init__(self, base_dir: Path, max_open_files: int) -> None:
        self.base_dir = base_dir
        self.max_open_files = max_open_files
        self._handles: OrderedDict[int, tuple[Path, object]] = OrderedDict()
        ensure_dir(base_dir)

    def _path_for(self, shard_id: int) -> Path:
        return self.base_dir / f"shard_{shard_id:04d}.jsonl"

    def write(self, shard_id: int, payload: Dict[str, str]) -> None:
        if shard_id in self._handles:
            path, handle = self._handles.pop(shard_id)
            self._handles[shard_id] = (path, handle)
        else:
            if len(self._handles) >= self.max_open_files:
                _, (_, oldest) = self._handles.popitem(last=False)
                oldest.close()
            path = self._path_for(shard_id)
            handle = path.open("a", encoding="utf-8")
            self._handles[shard_id] = (path, handle)
        _, active_handle = self._handles[shard_id]
        active_handle.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def close(self) -> None:
        for _, handle in self._handles.values():
            handle.close()
        self._handles.clear()


def _model_stem(model_name: str) -> str:
    return model_name.replace(".model", "")


def _iter_log_files(source_logs: Path, host: str) -> List[Path]:
    if source_logs.is_file():
        return [source_logs]
    files = [p for p in source_logs.rglob("*") if p.is_file()]
    files.sort()
    if host.startswith("SysClient"):
        match = re.search(r"(\d{4})", host)
        if match:
            hostid = match.group(1)
            host_filtered = [p for p in files if hostid in p.name]
            if host_filtered:
                return host_filtered
    return files


def _iter_lines(path: Path) -> Iterator[str]:
    if path.suffix.lower() == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as f:
            yield from f
    else:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            yield from f


def _optc_line_matches_host(line: str, host: str) -> bool:
    if not host.startswith("SysClient"):
        return True
    match = re.search(r"(\d{4})", host)
    if not match:
        return True
    return f"sysclient{match.group(1)}" in line.lower()


def _extract_json_fragment(line: str) -> Dict[str, object] | None:
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


def _unwrap_scalar(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        scalar_keys = [
            "string",
            "int",
            "long",
            "float",
            "double",
            "boolean",
            "uuid",
            "id",
            "name",
            "key",
            "path",
            "value",
            "ipAddress",
        ]
        for key in scalar_keys:
            if key in value:
                return _unwrap_scalar(value[key])
        if len(value) == 1:
            _, only_value = next(iter(value.items()))
            return _unwrap_scalar(only_value)
        return ""
    if isinstance(value, list):
        for item in value:
            rendered = _unwrap_scalar(item)
            if rendered:
                return rendered
        return ""
    return ""


def _first_non_empty(values: Sequence[object]) -> str:
    for value in values:
        rendered = _unwrap_scalar(value)
        if rendered:
            return rendered
    return ""


def _normalize_action(action: str) -> str:
    return action.replace("EVENT_", "").upper()


def _to_seconds(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        raw = float(value)
    else:
        text = str(value).strip()
        if not text:
            return None
        if re.fullmatch(r"[-+]?\d+(\.\d+)?", text):
            raw = float(text)
        else:
            normalized = text.replace("Z", "+00:00")
            try:
                dt = datetime.fromisoformat(normalized)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.timestamp()
            except ValueError:
                if len(text) >= 19 and "-" in text:
                    candidate = text[:19].replace("T", " ")
                    try:
                        dt = datetime.strptime(candidate, "%Y-%m-%d %H:%M:%S").replace(
                            tzinfo=timezone.utc
                        )
                        return dt.timestamp()
                    except ValueError:
                        return None
                return None

    digits = len(str(int(abs(raw)))) if raw != 0 else 1
    if digits >= 18:
        return raw / 1e9
    if digits >= 15:
        return raw / 1e6
    if digits >= 12:
        return raw / 1e3
    return raw


def _format_timestamp(value: object) -> str:
    sec = _to_seconds(value)
    if sec is None:
        return ""
    dt = datetime.fromtimestamp(sec, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _extract_darpa_event(obj: Dict[str, object]) -> _EventRecord | None:
    datum = obj.get(DATUM_KEY)
    if not isinstance(datum, dict) or EVENT_KEY not in datum:
        return None
    event = datum[EVENT_KEY]
    if not isinstance(event, dict):
        return None

    subject = event.get("subject")
    predicate_object = event.get("predicateObject")
    if not isinstance(subject, dict) or not isinstance(predicate_object, dict):
        return None
    subject_uuid = _unwrap_scalar(subject.get(UUID_KEY))
    object_uuid = _unwrap_scalar(predicate_object.get(UUID_KEY))
    if not subject_uuid or not object_uuid:
        return None

    action = _normalize_action(str(event.get("type", "EVENT_OTHER")))
    timestamp = _format_timestamp(
        event.get("timestampNanos")
        or event.get("timestampMicros")
        or event.get("timestampMillis")
        or event.get("timestamp")
    )
    object_attr_hint = _first_non_empty(
        [event.get("predicateObjectPath"), event.get("predicateObject2Path")]
    )
    return _EventRecord(
        subject_uuid=subject_uuid,
        object_uuid=object_uuid,
        action=action,
        timestamp=timestamp,
        object_type_hint="object",
        object_attr_hint=object_attr_hint,
    )


def _extract_darpa_event_with_aliases(
    obj: Dict[str, object],
    process_aliases: Dict[str, str],
) -> _EventRecord | None:
    event = _extract_darpa_event(obj)
    if event is None:
        return None
    return _EventRecord(
        subject_uuid=process_aliases.get(event.subject_uuid, event.subject_uuid),
        object_uuid=process_aliases.get(event.object_uuid, event.object_uuid),
        action=event.action,
        timestamp=event.timestamp,
        object_type_hint=event.object_type_hint,
        object_attr_hint=event.object_attr_hint,
    )


def _extract_optc_event(line: str) -> _EventRecord | None:
    obj = _extract_json_fragment(line)
    if obj is None:
        return None
    action = _first_non_empty([obj.get("action"), obj.get("eventType"), obj.get("type")])
    subject_uuid = _first_non_empty([obj.get("actorID"), obj.get("actorId"), obj.get("subjectID")])
    object_uuid = _first_non_empty([obj.get("objectID"), obj.get("objectId"), obj.get("targetID")])
    if not action or not subject_uuid or not object_uuid:
        return None

    object_type_hint = _first_non_empty([obj.get("object"), obj.get("objectType")]).lower() or "object"
    timestamp = _format_timestamp(
        obj.get("timestamp")
        or obj.get("time")
        or obj.get("@timestamp")
        or obj.get("eventTime")
    )
    object_attr_hint = _first_non_empty(
        [
            obj.get("objectPath"),
            obj.get("path"),
            obj.get("file_path"),
            obj.get("image_path"),
            obj.get("remoteAddress"),
            obj.get("destinationAddress"),
        ]
    )
    return _EventRecord(
        subject_uuid=subject_uuid,
        object_uuid=object_uuid,
        action=_normalize_action(action),
        timestamp=timestamp,
        object_type_hint=object_type_hint,
        object_attr_hint=object_attr_hint,
    )


def _extract_nodlink_raw_event(line: str) -> _EventRecord | None:
    event = parse_nodlink_windows_event(line)
    if event is None or not event.subject_process_id:
        return None

    object_uuid = event.child_process_id if event.object_type == "PROCESS" else event.object_id
    if not object_uuid:
        return None

    object_type_hint = (event.object_type or "object").lower()
    if object_type_hint == "process":
        object_attr_hint = event.child_name or event.child_pid or object_uuid
    elif object_type_hint == "file":
        object_attr_hint = event.file_path or object_uuid
    elif object_type_hint == "flow":
        remote = (
            f"{event.remote_ip}:{event.remote_port}"
            if event.remote_ip and event.remote_port
            else event.remote_ip or event.remote_port
        )
        object_attr_hint = remote or object_uuid
    else:
        object_attr_hint = object_uuid

    return _EventRecord(
        subject_uuid=event.subject_process_id,
        object_uuid=object_uuid,
        action=_normalize_action(event.action or "OTHER"),
        timestamp=_format_timestamp(event.timestamp_sec),
        object_type_hint=object_type_hint,
        object_attr_hint=object_attr_hint,
    )


def _extract_event(cfg: FusionConfig, line: str) -> _EventRecord | None:
    return _extract_event_with_aliases(cfg, line, {})


def _extract_event_with_aliases(
    cfg: FusionConfig,
    line: str,
    process_aliases: Dict[str, str],
) -> _EventRecord | None:
    if cfg.dataset_family == "nodlink" and is_nodlink_windows_host(cfg.host):
        return _extract_nodlink_raw_event(line)
    if cfg.dataset_family in {"tc3", "nodlink"}:
        if EVENT_KEY not in line:
            return None
        obj = _extract_json_fragment(line)
        if obj is None:
            return None
        return _extract_darpa_event_with_aliases(obj, process_aliases)
    if cfg.dataset_family == "optc":
        if cfg.source_logs.is_file() and not _optc_line_matches_host(line, cfg.host):
            return None
        return _extract_optc_event(line)
    return None


def _normalize_node_type(label: str) -> str:
    text = label.lower()
    if "process" in text or "subject" in text:
        return "process"
    if "netflow" in text or "flow" in text or "net" == text:
        return "flow"
    if "registry" in text:
        return "file"
    if "file" in text or "srcsink" in text:
        return "file"
    if "memory" in text:
        return "memory"
    if "pipe" in text or "socket" in text:
        return "pipe"
    if not text:
        return "object"
    return text


def _extract_netflow_attr(payload: Dict[str, object]) -> str:
    src_ip = _first_non_empty([payload.get("localAddress"), payload.get("srcAddress"), payload.get("srcIp")])
    src_port = _first_non_empty([payload.get("localPort"), payload.get("srcPort")])
    dst_ip = _first_non_empty([payload.get("remoteAddress"), payload.get("dstAddress"), payload.get("destIp")])
    dst_port = _first_non_empty([payload.get("remotePort"), payload.get("dstPort"), payload.get("destPort")])
    src = f"{src_ip}:{src_port}" if src_ip and src_port else src_ip
    dst = f"{dst_ip}:{dst_port}" if dst_ip and dst_port else dst_ip
    if src and dst:
        return f"{src}->{dst}"
    return src or dst


def _extract_subject_node_attr(payload: Dict[str, object]) -> str:
    properties = payload.get("properties")
    prop_map = properties.get("map", {}) if isinstance(properties, dict) else {}
    if not isinstance(prop_map, dict):
        prop_map = {}
    return _first_non_empty(
        [
            payload.get("cmdLine"),
            prop_map.get("cmdLine"),
            prop_map.get("path"),
            payload.get("path"),
            payload.get("name"),
            prop_map.get("name"),
            payload.get("cid"),
        ]
    )


def _extract_darpa_node_records(obj: Dict[str, object]) -> List[tuple[str, _NodeAttr]]:
    datum = obj.get(DATUM_KEY)
    if not isinstance(datum, dict):
        return []

    records: List[tuple[str, _NodeAttr]] = []
    for key, payload in datum.items():
        if key == EVENT_KEY:
            continue
        if not isinstance(payload, dict):
            continue
        uuid = _first_non_empty([payload.get("uuid"), payload.get(UUID_KEY)])
        if not uuid:
            continue

        short_name = key.split(".")[-1]
        if short_name == "Subject":
            node_type = "process"
            node_attr = _extract_subject_node_attr(payload)
        elif short_name == "FileObject":
            node_type = "file"
            node_attr = _first_non_empty(
                [
                    payload.get("path"),
                    payload.get("filename"),
                    payload.get("fileDescriptor"),
                    payload.get("type"),
                ]
            )
        elif short_name == "RegistryKeyObject":
            node_type = "file"
            node_attr = _first_non_empty([payload.get("key"), payload.get("path")])
        elif short_name == "NetFlowObject":
            node_type = "flow"
            node_attr = _extract_netflow_attr(payload)
        elif short_name == "SrcSinkObject":
            node_type = "file"
            node_attr = _first_non_empty([payload.get("fileDescriptor"), payload.get("path"), payload.get("type")])
        elif short_name == "Host":
            node_type = "host"
            node_attr = _first_non_empty([payload.get("hostName"), payload.get("uuid")])
        elif short_name == "Principal":
            node_type = "principal"
            node_attr = _first_non_empty([payload.get("username"), payload.get("userId"), payload.get("name")])
        else:
            node_type = _normalize_node_type(short_name)
            node_attr = _first_non_empty(
                [
                    payload.get("path"),
                    payload.get("name"),
                    payload.get("key"),
                    payload.get("type"),
                ]
            )

        records.append((uuid, _NodeAttr(node_type=node_type, node_attr=node_attr)))
    return records


def _extract_darpa_node_records_with_aliases(
    obj: Dict[str, object],
    process_aliases: Dict[str, str],
) -> List[tuple[str, _NodeAttr]]:
    records = _extract_darpa_node_records(obj)
    normalized: List[tuple[str, _NodeAttr]] = []
    for uuid, attr in records:
        if attr.node_type == "process":
            normalized.append((process_aliases.get(uuid, uuid), attr))
        else:
            normalized.append((uuid, attr))
    return normalized


def _extract_optc_node_records(line: str) -> List[tuple[str, _NodeAttr]]:
    obj = _extract_json_fragment(line)
    if obj is None:
        return []
    records: List[tuple[str, _NodeAttr]] = []
    subject_uuid = _first_non_empty([obj.get("actorID"), obj.get("actorId"), obj.get("subjectID")])
    if subject_uuid:
        subject_attr = _first_non_empty(
            [
                obj.get("actorProcessName"),
                obj.get("actorImagePath"),
                obj.get("actorCmdLine"),
            ]
        )
        records.append((subject_uuid, _NodeAttr(node_type="process", node_attr=subject_attr)))

    object_uuid = _first_non_empty([obj.get("objectID"), obj.get("objectId"), obj.get("targetID")])
    if object_uuid:
        raw_type = _first_non_empty([obj.get("object"), obj.get("objectType")])
        node_type = _normalize_node_type(raw_type)
        node_attr = _first_non_empty(
            [
                obj.get("objectPath"),
                obj.get("path"),
                obj.get("file_path"),
                obj.get("image_path"),
                obj.get("remoteAddress"),
                obj.get("destinationAddress"),
                obj.get("targetProcessName"),
            ]
        )
        records.append((object_uuid, _NodeAttr(node_type=node_type, node_attr=node_attr)))
    return records


def _extract_nodlink_raw_node_records(line: str) -> List[tuple[str, _NodeAttr]]:
    event = parse_nodlink_windows_event(line)
    if event is None or not event.subject_process_id:
        return []

    records: List[tuple[str, _NodeAttr]] = []
    subject_attr = event.subject_name or event.subject_pid or event.subject_process_id
    records.append(
        (
            event.subject_process_id,
            _NodeAttr(node_type="process", node_attr=subject_attr),
        )
    )

    if event.object_type == "PROCESS" and event.child_process_id:
        child_attr = event.child_name or event.child_pid or event.child_process_id
        records.append(
            (
                event.child_process_id,
                _NodeAttr(node_type="process", node_attr=child_attr),
            )
        )
    elif event.object_type == "FILE" and event.object_id:
        records.append(
            (
                event.object_id,
                _NodeAttr(node_type="file", node_attr=event.file_path or event.object_id),
            )
        )
    elif event.object_type == "FLOW" and event.object_id:
        flow_attr = (
            f"{event.src_ip}:{event.src_port}->{event.dst_ip}:{event.dst_port}"
            if any([event.src_ip, event.src_port, event.dst_ip, event.dst_port])
            else event.remote_ip or event.remote_port or event.object_id
        )
        records.append(
            (
                event.object_id,
                _NodeAttr(node_type="flow", node_attr=flow_attr),
            )
        )
    return records


def _extract_node_records(cfg: FusionConfig, line: str) -> List[tuple[str, _NodeAttr]]:
    return _extract_node_records_with_aliases(cfg, line, {})


def _extract_node_records_with_aliases(
    cfg: FusionConfig,
    line: str,
    process_aliases: Dict[str, str],
) -> List[tuple[str, _NodeAttr]]:
    if cfg.dataset_family == "nodlink" and is_nodlink_windows_host(cfg.host):
        return _extract_nodlink_raw_node_records(line)
    if cfg.dataset_family in {"tc3", "nodlink"}:
        if DATUM_KEY not in line:
            return []
        obj = _extract_json_fragment(line)
        if obj is None:
            return []
        return _extract_darpa_node_records_with_aliases(obj, process_aliases)
    if cfg.dataset_family == "optc":
        if cfg.source_logs.is_file() and not _optc_line_matches_host(line, cfg.host):
            return []
        return _extract_optc_node_records(line)
    return []


def _severity_from_percentile(percentile: float) -> str:
    if percentile >= 99:
        return "Critical"
    if percentile >= 97:
        return "Significant"
    if percentile >= 95:
        return "Moderate"
    if percentile >= 90:
        return "Minor"
    return "Negligible"


def _to_percentile(score: float, sorted_scores: Sequence[float]) -> float:
    if not sorted_scores:
        return 0.0
    lo, hi = 0, len(sorted_scores)
    while lo < hi:
        mid = (lo + hi) // 2
        if sorted_scores[mid] <= score:
            lo = mid + 1
        else:
            hi = mid
    return (float(lo) / float(len(sorted_scores))) * 100.0


def _build_process_alias_state(cfg: FusionConfig) -> _ProcessAliasState:
    raw_to_canonical: Dict[str, str] = {}
    canonical_parent: Dict[str, str] = {}
    canonical_attr: Dict[str, str] = {}

    if cfg.dataset_family == "nodlink" and is_nodlink_windows_host(cfg.host):
        for log_file in _iter_log_files(cfg.source_logs, cfg.host):
            for line in _iter_lines(log_file):
                event = parse_nodlink_windows_event(line)
                if event is None:
                    continue
                if event.subject_process_id:
                    raw_to_canonical.setdefault(event.subject_process_id, event.subject_process_id)
                if event.child_process_id:
                    raw_to_canonical.setdefault(event.child_process_id, event.child_process_id)
        return _ProcessAliasState(
            raw_to_canonical=raw_to_canonical,
            canonical_parent=canonical_parent,
            canonical_attr=canonical_attr,
        )

    if cfg.dataset_family == "optc":
        for log_file in _iter_log_files(cfg.source_logs, cfg.host):
            for line in _iter_lines(log_file):
                if cfg.source_logs.is_file() and not _optc_line_matches_host(line, cfg.host):
                    continue
                obj = _extract_json_fragment(line)
                if obj is None:
                    continue
                subject_uuid = _first_non_empty(
                    [obj.get("actorID"), obj.get("actorId"), obj.get("subjectID")]
                )
                if subject_uuid:
                    raw_to_canonical.setdefault(subject_uuid, subject_uuid)
                object_uuid = _first_non_empty(
                    [obj.get("objectID"), obj.get("objectId"), obj.get("targetID")]
                )
                object_type = _first_non_empty([obj.get("object"), obj.get("objectType")]).lower()
                if object_uuid and "process" in object_type:
                    raw_to_canonical.setdefault(object_uuid, object_uuid)
        return _ProcessAliasState(
            raw_to_canonical=raw_to_canonical,
            canonical_parent=canonical_parent,
            canonical_attr=canonical_attr,
        )

    if cfg.dataset_family not in {"tc3", "nodlink"}:
        return _ProcessAliasState(
            raw_to_canonical=raw_to_canonical,
            canonical_parent=canonical_parent,
            canonical_attr=canonical_attr,
        )

    theia_tgid_map: Dict[str, str] = {}
    for log_file in _iter_log_files(cfg.source_logs, cfg.host):
        for line in _iter_lines(log_file):
            if DATUM_KEY not in line:
                continue
            obj = _extract_json_fragment(line)
            if obj is None:
                continue
            datum = obj.get(DATUM_KEY)
            if not isinstance(datum, dict):
                continue
            subject = datum.get("com.bbn.tc.schema.avro.cdm18.Subject")
            if not isinstance(subject, dict):
                continue

            subject_uuid = _first_non_empty([subject.get("uuid"), subject.get(UUID_KEY)])
            if not subject_uuid:
                continue

            if cfg.host == "trace":
                cid = _first_non_empty([subject.get("cid")])
                if not cid:
                    continue
                raw_to_canonical.setdefault(subject_uuid, cid)
                raw_to_canonical.setdefault(cid, cid)
                subject_attr = _extract_subject_node_attr(subject)
                if subject_attr:
                    canonical_attr.setdefault(cid, subject_attr)
                properties = subject.get("properties")
                prop_map = properties.get("map", {}) if isinstance(properties, dict) else {}
                if isinstance(prop_map, dict):
                    ppid = _first_non_empty([prop_map.get("ppid")])
                    if ppid and ppid != "0":
                        canonical_parent.setdefault(cid, ppid)
                if cid not in canonical_parent:
                    parent_uuid = (
                        _unwrap_scalar(subject["parentSubject"].get(UUID_KEY))
                        if isinstance(subject.get("parentSubject"), dict)
                        else ""
                    )
                    parent_canonical = raw_to_canonical.get(parent_uuid, parent_uuid)
                    if parent_canonical:
                        canonical_parent.setdefault(cid, parent_canonical)
                continue

            if cfg.host == "theia":
                parent_uuid = (
                    _unwrap_scalar(subject["parentSubject"].get(UUID_KEY))
                    if isinstance(subject.get("parentSubject"), dict)
                    else "Unknow"
                )
                props = subject.get("properties", {}).get("map", {})
                subtgid = str(props.get("tgid", "Unknown"))
                subpath = str(props.get("path", "Unknown"))
                key = str((parent_uuid, subtgid, subpath))
                canonical = theia_tgid_map.get(key)
                if canonical is None:
                    canonical = subject_uuid
                    theia_tgid_map[key] = canonical
                raw_to_canonical[subject_uuid] = canonical
                raw_to_canonical.setdefault(canonical, canonical)
                subject_attr = _extract_subject_node_attr(subject)
                if subject_attr:
                    canonical_attr.setdefault(canonical, subject_attr)
                continue

            raw_to_canonical.setdefault(subject_uuid, subject_uuid)
            subject_attr = _extract_subject_node_attr(subject)
            if subject_attr:
                canonical_attr.setdefault(subject_uuid, subject_attr)

    return _ProcessAliasState(
        raw_to_canonical=raw_to_canonical,
        canonical_parent=canonical_parent,
        canonical_attr=canonical_attr,
    )


def _is_augmented_task_id(task_id: str) -> bool:
    return bool(_AUGMENTED_TASK_ID_PATTERN.search(str(task_id).strip()))


def _select_task_rows(rows: List[dict], cfg: FusionConfig) -> List[dict]:
    mode = str(cfg.module3_task_selection_mode).strip() or "predicted_positive"
    selected: List[dict] = []
    for row in rows:
        task_id = str(row.get("task_id", "")).strip()
        if not task_id:
            continue
        include = False
        if mode == "predicted_positive":
            include = bool(row.get("is_suspicious", False))
        elif mode == "ground_truth_positive":
            include = int(row.get("task_label", 0) or 0) == 1
        elif mode == "ground_truth_positive_base_only":
            include = int(row.get("task_label", 0) or 0) == 1 and not _is_augmented_task_id(task_id)
        if include:
            selected.append(row)
    return selected


def _load_subgraph_meta(cfg: FusionConfig, suspicious_tasks_path: Path) -> List[_SubgraphMeta]:
    rows = json.loads(suspicious_tasks_path.read_text(encoding="utf-8"))
    all_scores = [float(row.get("task_score", 0.0)) for row in rows]
    all_scores_sorted = sorted(all_scores)

    selected_rows = _select_task_rows(rows, cfg)
    selected_rows.sort(key=lambda row: float(row.get("task_score", 0.0)), reverse=True)
    metas: List[_SubgraphMeta] = []
    for idx, row in enumerate(selected_rows):
        task_score = float(row.get("task_score", 0.0))
        percentile = _to_percentile(task_score, all_scores_sorted)
        severity = _severity_from_percentile(percentile)
        if severity in {"Minor", "Negligible"}:
            severity = "Moderate"
        metas.append(
            _SubgraphMeta(
                subgraph_id=idx,
                task_id=str(row.get("task_id")),
                task_score=task_score,
                process_ids=[str(pid) for pid in row.get("process_ids", [])],
                severity_level=severity,
            )
        )
    return metas


def _build_seed_frontier(metas: Sequence[_SubgraphMeta]) -> Dict[str, set[int]]:
    frontier: Dict[str, set[int]] = {}
    for meta in metas:
        for process_id in meta.process_ids:
            frontier.setdefault(process_id, set()).add(meta.subgraph_id)
    return frontier


def _match_frontier_subgraphs(
    event: _EventRecord,
    frontier_map: Dict[str, set[int]],
    *,
    include_object_side: bool,
) -> set[int]:
    matched = set(frontier_map.get(str(event.subject_uuid), set()))
    if include_object_side:
        matched.update(frontier_map.get(str(event.object_uuid), set()))
    return matched


def _event_identity(event: _EventRecord) -> tuple[str, str, str, str, str, str]:
    return (
        str(event.subject_uuid or ""),
        str(event.object_uuid or ""),
        str(event.action or ""),
        str(event.timestamp or ""),
        str(event.object_type_hint or ""),
        str(event.object_attr_hint or ""),
    )


def _scan_node_attributes_with_aliases(
    cfg: FusionConfig,
    needed_uuids: set[str],
    alias_state: _ProcessAliasState,
) -> Dict[str, _NodeAttr]:
    node_cache: Dict[str, _NodeAttr] = {}
    if not needed_uuids:
        return node_cache
    unresolved = set(needed_uuids)
    for log_file in _iter_log_files(cfg.source_logs, cfg.host):
        for line in _iter_lines(log_file):
            records = _extract_node_records_with_aliases(
                cfg,
                line,
                alias_state.raw_to_canonical,
            )
            if not records:
                continue
            for uuid, attr in records:
                if uuid in unresolved and uuid not in node_cache:
                    node_cache[uuid] = attr
                    unresolved.remove(uuid)
            if not unresolved:
                return node_cache
    return node_cache


def _render_node(uuid: str, attr: _NodeAttr | None, default_type: str, fallback_attr: str = "") -> tuple[str, str]:
    node_type = default_type
    node_attr = fallback_attr
    if attr is not None:
        node_type = attr.node_type or node_type
        if attr.node_attr:
            node_attr = attr.node_attr
    if not node_attr:
        node_attr = uuid
    return node_type, node_attr


