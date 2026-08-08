from __future__ import annotations

import collections
import copy
import json
import math
from pathlib import Path
from typing import Any, Iterable, Mapping

import numpy as np


_FORK_EVENTS = {"EVENT_FORK", "EVENT_CLONE"}
_PROCESS_INPUT_EVENTS = {
    "EVENT_READ",
    "EVENT_OPEN",
    "EVENT_EXECUTE",
    "EVENT_MMAP",
    "EVENT_RECVFROM",
    "EVENT_RECVMSG",
    "EVENT_ACCEPT",
}
_WRITE_DELETE_EVENTS = {
    "EVENT_WRITE",
    "EVENT_UNLINK",
    "EVENT_RENAME",
    "EVENT_TRUNCATE",
    "EVENT_CREATE_OBJECT",
    "EVENT_MODIFY_FILE_ATTRIBUTES",
}
_NETWORK_EVENTS = {
    "EVENT_ACCEPT",
    "EVENT_CONNECT",
    "EVENT_SENDTO",
    "EVENT_SENDMSG",
    "EVENT_RECVFROM",
    "EVENT_RECVMSG",
    "EVENT_BIND",
}


def _unwrap(value: Any) -> Any:
    current = value
    while isinstance(current, dict) and len(current) == 1:
        current = next(iter(current.values()))
    return current


def _uuid(value: Any) -> str:
    current = _unwrap(value)
    if isinstance(current, dict):
        return str(current.get("com.bbn.tc.schema.avro.cdm18.UUID", current.get("uuid", ""))).strip()
    return "" if current is None else str(current).strip()


def _text(value: Any) -> str:
    current = _unwrap(value)
    return "" if current is None else str(current).strip()


def _datum(record: dict[str, Any], suffix: str) -> dict[str, Any] | None:
    payload = record.get("datum", {})
    if not isinstance(payload, dict):
        return None
    for key, value in payload.items():
        if key.endswith(suffix) and isinstance(value, dict):
            return value
    return None


def _subject_owner_map(rows: list[dict[str, Any]]) -> dict[str, str]:
    subjects = {str(row["uuid"]): row for row in rows if str(row.get("uuid", "")).strip()}
    cache: dict[str, str] = {}

    def resolve(subject_id: str, trail: set[str] | None = None) -> str:
        if subject_id in cache:
            return cache[subject_id]
        row = subjects.get(subject_id)
        if row is None:
            cache[subject_id] = subject_id
            return subject_id
        trail = set() if trail is None else trail
        if subject_id in trail:
            cache[subject_id] = subject_id
            return subject_id
        trail.add(subject_id)
        parent = str(row.get("parent", ""))
        tgid = str(row.get("tgid", ""))
        owner = subject_id
        parent_row = subjects.get(parent)
        if str(row.get("type", "")) == "SUBJECT_UNIT" and parent_row is not None:
            owner = resolve(parent, trail)
        elif parent_row is not None and tgid and tgid == str(parent_row.get("tgid", "")):
            owner = resolve(parent, trail)
        cache[subject_id] = owner
        return owner

    return {subject_id: resolve(subject_id) for subject_id in subjects}


def _read_cdm18_metadata(source_logs: str | Path) -> tuple[dict[str, str], dict[str, dict[str, str]], dict[str, dict[str, str]]]:
    """Read subject ownership plus the entity attributes required by ProvGRP fE."""
    subject_rows: list[dict[str, Any]] = []
    file_names: dict[str, str] = {}
    net_names: dict[str, str] = {}
    for path in sorted(Path(source_logs).glob("*.json")):
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                subject = _datum(record, ".Subject")
                if subject is not None:
                    properties = subject.get("properties", {})
                    mapping = properties.get("map", {}) if isinstance(properties, dict) else {}
                    parent = _uuid(subject.get("parentSubject"))
                    process_name = str(mapping.get("name", "")).strip() if isinstance(mapping, dict) else ""
                    subject_rows.append(
                        {
                            "uuid": _uuid(subject.get("uuid")),
                            "parent": parent,
                            "tgid": str(mapping.get("tgid", "")).strip() if isinstance(mapping, dict) else "",
                            "type": str(subject.get("type", "")).strip(),
                            "name": _text(subject.get("cmdLine")) or process_name,
                            "pid": str(subject.get("cid", "")).strip(),
                        }
                    )
                    continue
                file_object = _datum(record, ".FileObject")
                if file_object is not None:
                    object_id = _uuid(file_object.get("uuid"))
                    path_value = _text(file_object.get("path"))
                    if object_id:
                        file_names.setdefault(object_id, path_value)
                    continue
                net_object = _datum(record, ".NetFlowObject")
                if net_object is not None:
                    object_id = _uuid(net_object.get("uuid"))
                    remote = _text(net_object.get("remoteAddress"))
                    port = _text(net_object.get("remotePort"))
                    if object_id:
                        net_names.setdefault(object_id, f"{remote}:{port}" if remote and port else remote)
    owners = _subject_owner_map(subject_rows)
    descriptors: dict[str, dict[str, str]] = {}
    for row in subject_rows:
        raw_id = str(row.get("uuid", ""))
        owner = owners.get(raw_id, raw_id)
        if not owner:
            continue
        candidate = {"name": str(row.get("name", "")), "pid": str(row.get("pid", ""))}
        previous = descriptors.get(owner)
        if previous is None or (not previous.get("name") and candidate["name"]):
            descriptors[owner] = candidate
    return owners, descriptors, {"file": file_names, "net": net_names}


def _event_entity(
    event: dict[str, Any],
    event_type: str,
    counterpart_raw: str,
    counterpart: str,
    descriptors: dict[str, dict[str, str]],
    object_names: dict[str, dict[str, str]],
) -> tuple[str, str]:
    if event_type in _FORK_EVENTS or counterpart in descriptors:
        descriptor = descriptors.get(counterpart, {})
        process_name = str(descriptor.get("name", "")).strip()
        pid = str(descriptor.get("pid", "")).strip()
        return "process", f"{process_name}_{pid}" if process_name else counterpart
    path = _text(event.get("predicateObjectPath")) or object_names["file"].get(counterpart_raw, "")
    if path or counterpart_raw in object_names["file"]:
        return "file", path or counterpart_raw
    remote = object_names["net"].get(counterpart_raw, "")
    if remote or counterpart_raw in object_names["net"]:
        return "net", remote or counterpart_raw
    return "other", counterpart or counterpart_raw


def _event_direction(event_type: str, root_is_subject: bool) -> str:
    if not root_is_subject:
        return "in"
    return "in" if event_type in _PROCESS_INPUT_EVENTS else "out"


def _collect_root_dependencies(
    source_logs: str | Path,
    roots: set[str],
    owners: dict[str, str],
    descriptors: dict[str, dict[str, str]],
    object_names: dict[str, dict[str, str]],
    root_direct_children: Mapping[str, Iterable[str]] | None = None,
) -> tuple[dict[str, dict[str, list[dict[str, Any]]]], dict[str, Any], dict[str, dict[str, int]]]:
    dependencies = {root: {"in": [], "out": []} for root in roots}
    child_roots = {
        str(root): {str(child) for child in children}
        for root, children in (root_direct_children or {}).items()
    }
    child_to_roots: dict[str, set[str]] = collections.defaultdict(set)
    for root, children in child_roots.items():
        for child in children:
            child_to_roots[child].add(root)
    child_first_event_timestamps = {root: {} for root in roots}
    included_event_types: collections.Counter[str] = collections.Counter()
    included_entity_kinds: collections.Counter[str] = collections.Counter()
    ignored_event_types: collections.Counter[str] = collections.Counter()
    for path in sorted(Path(source_logs).glob("*.json")):
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                try:
                    event = _datum(json.loads(line), ".Event")
                except json.JSONDecodeError:
                    continue
                if event is None:
                    continue
                event_type = str(event.get("type", "")).strip()
                timestamp = event.get("timestampNanos")
                source_raw = _uuid(event.get("subject"))
                target_raw = _uuid(event.get("predicateObject"))
                if not event_type or timestamp is None or not source_raw or not target_raw:
                    continue
                source = owners.get(source_raw, source_raw)
                target = owners.get(target_raw, target_raw)
                timestamp_ns = int(timestamp)
                for process_id in {source, target}:
                    for root in child_to_roots.get(process_id, set()):
                        current = child_first_event_timestamps[root].get(process_id)
                        if current is None or timestamp_ns < current:
                            child_first_event_timestamps[root][process_id] = timestamp_ns
                for root, is_subject, counterpart_raw, counterpart in (
                    (source, True, target_raw, target),
                    (target, False, source_raw, source),
                ):
                    if root not in roots:
                        continue
                    kind, name = _event_entity(
                        event, event_type, counterpart_raw, counterpart, descriptors, object_names
                    )
                    if kind not in {"process", "file", "net"}:
                        ignored_event_types[event_type] += 1
                        continue
                    dependencies[root][_event_direction(event_type, is_subject)].append(
                        {
                            "event_id": _uuid(event.get("uuid")),
                            "timestamp_ns": timestamp_ns,
                            "event_type": event_type,
                            "entity_kind": kind,
                            "entity_name": name,
                            "fork_child": counterpart if is_subject and event_type in _FORK_EVENTS else "",
                        }
                    )
                    included_event_types[event_type] += 1
                    included_entity_kinds[kind] += 1
    for root in dependencies:
        for direction in ("in", "out"):
            dependencies[root][direction].sort(
                key=lambda item: (int(item["timestamp_ns"]), str(item["event_id"]))
            )
    return dependencies, {
        "included_event_type_counts": dict(sorted(included_event_types.items())),
        "included_entity_kind_counts": dict(sorted(included_entity_kinds.items())),
        "ignored_non_process_file_net_event_type_counts": dict(sorted(ignored_event_types.items())),
    }, child_first_event_timestamps


def _path_similarity(left: str, right: str) -> float:
    first = [token for token in left.replace("\\", "/").split("/") if token]
    second = [token for token in right.replace("\\", "/").split("/") if token]
    if not first or not second:
        return float(first == second and bool(first))
    same = 0
    for left_token, right_token in zip(first, second):
        if left_token != right_token:
            break
        same += 1
    return same / max(len(first), len(second))


def _ip_similarity(left: str, right: str) -> float:
    left_ip = left.rsplit(":", 1)[0] if ":" in left else left
    right_ip = right.rsplit(":", 1)[0] if ":" in right else right
    try:
        left_bits = "".join(f"{int(value):08b}" for value in left_ip.split("."))
        right_bits = "".join(f"{int(value):08b}" for value in right_ip.split("."))
    except ValueError:
        return float(left == right and bool(left))
    same = next((index for index, pair in enumerate(zip(left_bits, right_bits)) if pair[0] != pair[1]), 32)
    return same / 32.0


def _entity_similarity(left: dict[str, Any], right: dict[str, Any]) -> float:
    if left["entity_kind"] != right["entity_kind"]:
        return 0.0
    kind = str(left["entity_kind"])
    if kind == "file":
        return _path_similarity(str(left["entity_name"]), str(right["entity_name"]))
    if kind == "net":
        return _ip_similarity(str(left["entity_name"]), str(right["entity_name"]))
    return float(left["entity_name"] == right["entity_name"] and bool(left["entity_name"]))


def _operation_similarity(left: str, right: str) -> float:
    if left == right:
        return 1.0
    if left in _WRITE_DELETE_EVENTS and right in _WRITE_DELETE_EVENTS:
        return 1.0
    if left in _FORK_EVENTS and right in _FORK_EVENTS:
        return 1.0
    return 0.0


def _confidence(left: dict[str, Any], right: dict[str, Any], start: int, end: int) -> float:
    delta = abs(int(left["timestamp_ns"]) - int(right["timestamp_ns"])) / max(1, end - start)
    alpha = 0.001
    time_value = (2.0 * math.atan(max(0.0, 1.0 - delta) / (delta + alpha))) / math.pi
    return (0.5 * time_value) + (0.4 * _entity_similarity(left, right)) + (
        0.1 * _operation_similarity(str(left["event_type"]), str(right["event_type"]))
    )


def _event_identity(event: Mapping[str, Any]) -> tuple[str, ...]:
    event_id = str(event.get("event_id", "")).strip()
    if event_id:
        return ("event", event_id)
    return (
        "fallback",
        str(event.get("timestamp_ns", "")),
        str(event.get("event_type", "")),
        str(event.get("entity_kind", "")),
        str(event.get("entity_name", "")),
        str(event.get("fork_child", "")),
    )


class _UnionFind:
    def __init__(self, size: int) -> None:
        self._parents = list(range(size))

    def find(self, item: int) -> int:
        while self._parents[item] != item:
            self._parents[item] = self._parents[self._parents[item]]
            item = self._parents[item]
        return item

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self._parents[right_root] = left_root


def _cluster_events(
    events: list[dict[str, Any]],
    *,
    min_cluster_size: int,
    min_samples: int,
    max_events_per_matrix: int,
    batch_overlap_events: int,
    prefix: str,
) -> list[dict[str, Any]]:
    if not events:
        return []
    try:
        import hdbscan
    except ImportError as exc:
        raise RuntimeError("ProvGRP paper partition requires hdbscan") from exc
    if batch_overlap_events < 0 or batch_overlap_events >= max_events_per_matrix:
        raise ValueError("batch_overlap_events must be >= 0 and smaller than max_events_per_matrix")
    records: list[dict[str, Any]] = []
    records_by_batch: list[list[int]] = []
    step = max_events_per_matrix - batch_overlap_events
    # Every event is retained. Splitting only bounds the quadratic all-pairs
    # matrix for service roots whose event count exceeds available memory. The
    # overlap lets one logical execution cluster cross a matrix boundary.
    batch_index = 0
    start_index = 0
    while start_index < len(events):
        batch = events[start_index : start_index + max_events_per_matrix]
        records_by_batch.append([])
        if len(batch) < min_cluster_size:
            labels = [-1] * len(batch)
        else:
            start = int(batch[0]["timestamp_ns"])
            end = int(batch[-1]["timestamp_ns"])
            distances = np.zeros((len(batch), len(batch)), dtype=np.float64)
            for left_index in range(len(batch)):
                for right_index in range(left_index + 1, len(batch)):
                    value = 1.0 - _confidence(batch[left_index], batch[right_index], start, end)
                    distances[left_index, right_index] = value
                    distances[right_index, left_index] = value
            labels = hdbscan.HDBSCAN(
                metric="precomputed",
                min_cluster_size=min_cluster_size,
                min_samples=min_samples,
                cluster_selection_method="eom",
            ).fit_predict(distances).tolist()
        grouped: dict[int, list[dict[str, Any]]] = collections.defaultdict(list)
        for event_index, label in enumerate(labels):
            # HDBSCAN outliers remain independent execution partitions so no
            # fork/clone branch disappears during the graph split.
            key = int(label) if int(label) >= 0 else -(event_index + 1)
            grouped[key].append(batch[event_index])
        for label, members in grouped.items():
            records.append(
                {
                    "cluster_id": f"{prefix}{batch_index}_{label}",
                    "events": members,
                    "start_ns": min(int(item["timestamp_ns"]) for item in members),
                    "end_ns": max(int(item["timestamp_ns"]) for item in members),
                    "batch_index": batch_index,
                    "is_noise": int(label) < 0,
                }
            )
            records_by_batch[batch_index].append(len(records) - 1)
        if start_index + max_events_per_matrix >= len(events):
            break
        start_index += step
        batch_index += 1

    if batch_overlap_events == 0:
        return sorted(
            [{key: value for key, value in record.items() if key not in {"batch_index", "is_noise"}} for record in records],
            key=lambda item: (int(item["start_ns"]), str(item["cluster_id"])),
        )

    union_find = _UnionFind(len(records))
    for batch_index in range(len(records_by_batch) - 1):
        current = [index for index in records_by_batch[batch_index] if not records[index]["is_noise"]]
        following = [index for index in records_by_batch[batch_index + 1] if not records[index]["is_noise"]]
        by_event: dict[tuple[str, ...], list[int]] = collections.defaultdict(list)
        for record_index in current:
            for event in records[record_index]["events"]:
                by_event[_event_identity(event)].append(record_index)
        for record_index in following:
            shared = {
                _event_identity(event)
                for event in records[record_index]["events"]
                if _event_identity(event) in by_event
            }
            for event_id in shared:
                for previous_index in by_event[event_id]:
                    union_find.union(previous_index, record_index)

    merged_events: dict[int, dict[tuple[str, ...], dict[str, Any]]] = collections.defaultdict(dict)
    merged_ids: dict[int, list[str]] = collections.defaultdict(list)
    positive_event_ids: set[tuple[str, ...]] = set()
    for record_index, record in enumerate(records):
        if record["is_noise"]:
            continue
        root = union_find.find(record_index)
        merged_ids[root].append(str(record["cluster_id"]))
        for event in record["events"]:
            event_id = _event_identity(event)
            positive_event_ids.add(event_id)
            merged_events[root].setdefault(event_id, event)

    groups: list[dict[str, Any]] = []
    for root, members_by_id in merged_events.items():
        members = list(members_by_id.values())
        groups.append(
            {
                "cluster_id": f"{prefix}merged_{min(merged_ids[root])}",
                "events": members,
                "start_ns": min(int(item["timestamp_ns"]) for item in members),
                "end_ns": max(int(item["timestamp_ns"]) for item in members),
            }
        )
    # A duplicated overlap event may be labelled as noise in one batch and as a
    # valid cluster in its neighbour. The valid cluster owns it in that case.
    for record in records:
        if not record["is_noise"]:
            continue
        members = [event for event in record["events"] if _event_identity(event) not in positive_event_ids]
        if not members:
            continue
        groups.append(
            {
                "cluster_id": str(record["cluster_id"]),
                "events": members,
                "start_ns": min(int(item["timestamp_ns"]) for item in members),
                "end_ns": max(int(item["timestamp_ns"]) for item in members),
            }
        )
    return sorted(groups, key=lambda item: (int(item["start_ns"]), str(item["cluster_id"])))


def _children_map(component: dict[str, Any]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = collections.defaultdict(list)
    for edge in component.get("edges", []):
        if len(edge) >= 2 and str(edge[0]) and str(edge[1]):
            result[str(edge[0])].append(str(edge[1]))
    return result


def _subtree(root: str, children: dict[str, list[str]]) -> set[str]:
    result: set[str] = set()
    pending = [root]
    while pending:
        node = pending.pop()
        if node in result:
            continue
        result.add(node)
        pending.extend(children.get(node, []))
    return result


def _time_distance_to_cluster(timestamp_ns: int, cluster: Mapping[str, Any]) -> int:
    start = int(cluster["start_ns"])
    end = int(cluster["end_ns"])
    if start <= timestamp_ns <= end:
        return 0
    return min(abs(timestamp_ns - start), abs(timestamp_ns - end))


def _execution_groups(
    incoming: list[dict[str, Any]],
    outgoing: list[dict[str, Any]],
    direct_children: list[str],
    child_first_event_timestamps: Mapping[str, int] | None = None,
) -> list[dict[str, Any]]:
    direct_child_set = set(direct_children)
    first_event_timestamps = {str(child): int(timestamp) for child, timestamp in (child_first_event_timestamps or {}).items()}
    assigned: set[str] = set()
    cluster_members: list[list[str]] = []
    cluster_sources: list[collections.Counter[str]] = []
    for outgoing_cluster in outgoing:
        members: list[str] = []
        sources: collections.Counter[str] = collections.Counter()
        for event in outgoing_cluster["events"]:
            child = str(event.get("fork_child", ""))
            if child in direct_child_set and child not in assigned:
                members.append(child)
                assigned.add(child)
                sources["fork_clone"] += 1
        cluster_members.append(members)
        cluster_sources.append(sources)

    for child in sorted(direct_child_set - assigned):
        timestamp_ns = first_event_timestamps.get(child)
        if timestamp_ns is None or not outgoing:
            continue
        nearest_index = min(
            range(len(outgoing)),
            key=lambda index: (
                _time_distance_to_cluster(timestamp_ns, outgoing[index]),
                int(outgoing[index]["start_ns"]),
                str(outgoing[index]["cluster_id"]),
            ),
        )
        cluster_members[nearest_index].append(child)
        cluster_sources[nearest_index]["first_event_nearest_cluster"] += 1
        assigned.add(child)

    groups: list[dict[str, Any]] = []
    for outgoing_cluster, members, sources in zip(outgoing, cluster_members, cluster_sources):
        if not members:
            continue
        prior = [item for item in incoming if int(item["end_ns"]) <= int(outgoing_cluster["start_ns"])]
        incoming_cluster = max(prior, key=lambda item: int(item["end_ns"])) if prior else None
        groups.append(
            {
                "incoming_cluster_id": incoming_cluster["cluster_id"] if incoming_cluster else None,
                "outgoing_cluster_id": outgoing_cluster["cluster_id"],
                "incoming_event_count": len(incoming_cluster["events"]) if incoming_cluster else 0,
                "outgoing_event_count": len(outgoing_cluster["events"]),
                "child_roots": members,
                "child_assignment_counts": dict(sorted(sources.items())),
            }
        )
    unassigned = [child for child in direct_children if child not in assigned]
    if unassigned:
        groups.append(
            {
                "incoming_cluster_id": None,
                "outgoing_cluster_id": "unmatched_fork_clone",
                "incoming_event_count": 0,
                "outgoing_event_count": 0,
                "child_roots": unassigned,
                "child_assignment_counts": {"missing_first_event_or_outgoing_cluster": len(unassigned)},
            }
        )
    return groups


def apply_provgrp_paper_partition(
    components: Iterable[dict[str, Any]],
    *,
    source_logs: str | Path,
    raw_subject_to_canonical_node: dict[str, str] | None = None,
    min_direct_children: int = 10,
    min_cluster_size: int = 5,
    min_samples: int = 2,
    max_events_per_matrix: int = 512,
    batch_overlap_events: int = 64,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Apply ProvGRP Section 4.2 to CADETS long-running task roots."""
    original = [copy.deepcopy(component) for component in components]
    eligible = {
        str(component.get("task_root", "")): _children_map(component).get(str(component.get("task_root", "")), [])
        for component in original
    }
    eligible = {root: children for root, children in eligible.items() if root and len(children) > min_direct_children}
    summary: dict[str, Any] = {
        "method": "provgrp_section_4_2_in_out_dependency_partition",
        "eligible_root_count": len(eligible),
        "min_direct_children": min_direct_children,
        "min_cluster_size": min_cluster_size,
        "min_samples": min_samples,
        "max_events_per_matrix": max_events_per_matrix,
        "batch_overlap_events": batch_overlap_events,
        "refined_root_count": 0,
        "generated_component_count": 0,
        "root_summaries": [],
    }
    if not eligible:
        return original, summary
    owners, descriptors, object_names = _read_cdm18_metadata(source_logs)
    if raw_subject_to_canonical_node:
        original_owners = dict(owners)
        owners = {
            raw_id: str(raw_subject_to_canonical_node.get(raw_id, owner_id))
            for raw_id, owner_id in owners.items()
        }
        remapped_descriptors: dict[str, dict[str, str]] = {}
        for raw_id, original_owner in original_owners.items():
            canonical_id = owners.get(raw_id, original_owner)
            candidate = descriptors.get(original_owner, {})
            if canonical_id and (canonical_id not in remapped_descriptors or candidate.get("name")):
                remapped_descriptors[canonical_id] = candidate
        descriptors = remapped_descriptors
    dependencies, dependency_filter_stats, child_first_event_timestamps = _collect_root_dependencies(
        source_logs,
        set(eligible),
        owners,
        descriptors,
        object_names,
        root_direct_children=eligible,
    )
    summary["dependency_filter"] = dependency_filter_stats
    refined: list[dict[str, Any]] = []
    for component in original:
        root = str(component.get("task_root", ""))
        direct_children = eligible.get(root)
        if direct_children is None:
            refined.append(component)
            continue
        incoming = _cluster_events(
            dependencies[root]["in"], min_cluster_size=min_cluster_size, min_samples=min_samples,
            max_events_per_matrix=max_events_per_matrix, batch_overlap_events=batch_overlap_events, prefix="in_",
        )
        outgoing = _cluster_events(
            dependencies[root]["out"], min_cluster_size=min_cluster_size, min_samples=min_samples,
            max_events_per_matrix=max_events_per_matrix, batch_overlap_events=batch_overlap_events, prefix="out_",
        )
        groups = _execution_groups(
            incoming,
            outgoing,
            direct_children,
            child_first_event_timestamps=child_first_event_timestamps.get(root, {}),
        )
        if len(groups) < 2:
            refined.append(component)
            continue
        children = _children_map(component)
        component_nodes = {str(value) for value in component.get("nodes", [])}
        for index, group in enumerate(groups):
            nodes = {root}
            for child in group["child_roots"]:
                nodes.update(_subtree(child, children))
            nodes &= component_nodes
            updated = copy.deepcopy(component)
            updated["nodes"] = sorted(nodes)
            updated["edges"] = [list(edge) for edge in component.get("edges", []) if str(edge[0]) in nodes and str(edge[1]) in nodes]
            updated["boundary_nodes"] = [root]
            updated.update(
                {
                    "provgrp_paper_partition_applied": True,
                    "provgrp_paper_parent_task_root": root,
                    "provgrp_paper_partition_index": index,
                    "provgrp_paper_partition_count": len(groups),
                    "provgrp_paper_incoming_cluster_id": group["incoming_cluster_id"],
                    "provgrp_paper_outgoing_cluster_id": group["outgoing_cluster_id"],
                    "provgrp_paper_incoming_event_count": group["incoming_event_count"],
                    "provgrp_paper_outgoing_event_count": group["outgoing_event_count"],
                    "provgrp_paper_member_child_roots": group["child_roots"],
                    "provgrp_paper_member_child_count": len(group["child_roots"]),
                    "provgrp_paper_child_assignment_counts": dict(group.get("child_assignment_counts", {})),
                    "provgrp_paper_original_root_child_count": len(direct_children),
                }
            )
            refined.append(updated)
        summary["refined_root_count"] += 1
        summary["generated_component_count"] += len(groups)
        summary["root_summaries"].append(
            {
                "root": root,
                "incoming_dependency_count": len(dependencies[root]["in"]),
                "outgoing_dependency_count": len(dependencies[root]["out"]),
                "incoming_cluster_count": len(incoming),
                "outgoing_cluster_count": len(outgoing),
                "execution_partition_count": len(groups),
                "output_child_counts": [len(group["child_roots"]) for group in groups],
                "child_assignment_counts": dict(
                    sorted(
                        collections.Counter(
                            assignment
                            for group in groups
                            for assignment, count in group.get("child_assignment_counts", {}).items()
                            for _ in range(int(count))
                        ).items()
                    )
                ),
            }
        )
    return refined, summary


def apply_provgrp_paper_partition_to_edge_list(
    edge_list: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any]:
    """Apply the paper partition while preserving the TAPAS edge-list contract."""
    if (
        not isinstance(edge_list, dict)
        or not isinstance(edge_list.get("task_components"), list)
        or not edge_list.get("task_components")
    ):
        return edge_list
    components, summary = apply_provgrp_paper_partition(edge_list["task_components"], **kwargs)
    seen: set[tuple[str, str]] = set()
    edges: list[list[str]] = []
    for component in components:
        for edge in component.get("edges", []):
            if not isinstance(edge, (list, tuple)) or len(edge) < 2:
                continue
            pair = (str(edge[0]), str(edge[1]))
            if pair not in seen:
                seen.add(pair)
                edges.append([pair[0], pair[1]])
    updated = dict(edge_list)
    updated["task_components"] = components
    updated["edge_list"] = edges
    updated["provgrp_paper_partition_summary"] = summary
    return updated
