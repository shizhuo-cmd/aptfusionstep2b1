from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from statistics import median
from typing import Any, Iterable

from apt_fusion.path_reason.log_stream import (
    DATUM_KEY,
    EVENT_KEY,
    UUID_KEY,
    _extract_darpa_node_records,
    _extract_json_fragment,
    _first_non_empty,
    _iter_lines,
    _iter_log_files,
    _unwrap_scalar,
)

SUBJECT_KEY = "com.bbn.tc.schema.avro.cdm18.Subject"


@dataclass
class SubjectInfo:
    uuid: str
    cid: str
    parent_uuid: str
    name: str
    cmdline: str
    ppid: str
    seen_time: str


@dataclass
class EntityInfo:
    uuid: str
    entity_type: str
    entity_attr: str


@dataclass
class TaskInfo:
    task_id: str
    process_cids: set[str]
    gt_hit_cids: set[str] = field(default_factory=set)
    gt_hit_process_uuids: set[str] = field(default_factory=set)
    matched_event_count: int = 0
    first_ts: int | None = None
    last_ts: int | None = None
    event_types: Counter[str] = field(default_factory=Counter)
    gt_neighbor_uuids: set[str] = field(default_factory=set)
    gt_nonprocess_neighbor_uuids: set[str] = field(default_factory=set)


@dataclass
class GTNodeStat:
    uuid: str
    entity_type: str = "unknown"
    entity_attr: str = ""
    cid: str = ""
    is_gt_process_uuid: bool = False
    is_direct_task_process_member: bool = False
    is_onehop_recovered: bool = False
    malicious_task_ids: set[str] = field(default_factory=set)
    occurrence_count: int = 0
    roles: Counter[str] = field(default_factory=Counter)
    event_types: Counter[str] = field(default_factory=Counter)
    touched_seed_cids: set[str] = field(default_factory=set)
    first_ts: int | None = None
    last_ts: int | None = None


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze how ground-truth malicious UUIDs are distributed around the 1-hop event "
            "neighborhood of GT-hit malicious trace task graphs."
        )
    )
    parser.add_argument("--logs-dir", required=True, help="Trace logs directory")
    parser.add_argument("--ground-truth", required=True, help="Ground truth UUID list")
    parser.add_argument("--task-subgraphs", required=True, help="module1 task_subgraphs.json path")
    parser.add_argument("--out-dir", required=True, help="Output directory")
    parser.add_argument(
        "--include-object-side",
        action="store_true",
        default=False,
        help="Also treat events as matched when predicateObject is a task-process UUID (optional override; mainline is now subject-side only).",
    )
    return parser.parse_args()


def _load_ground_truth(path: Path) -> set[str]:
    gt: set[str] = set()
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            value = line.strip()
            if value:
                gt.add(value)
    return gt


def _load_task_subgraphs(path: Path) -> list[TaskInfo]:
    rows = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise ValueError(f"task_subgraphs must be a JSON list: {path}")
    tasks: list[TaskInfo] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        task_id = str(row.get("task_id", "")).strip()
        process_ids = {str(pid) for pid in row.get("process_ids", []) if str(pid).strip()}
        if not task_id or not process_ids:
            continue
        tasks.append(TaskInfo(task_id=task_id, process_cids=process_ids))
    return tasks


def _to_nanos(value: Any) -> int | None:
    text = _unwrap_scalar(value)
    if not text:
        return None
    try:
        raw = int(float(text))
    except ValueError:
        return None
    digits = len(str(abs(raw))) if raw else 1
    if digits >= 18:
        return raw
    if digits >= 15:
        return raw * 1000
    if digits >= 12:
        return raw * 1000000
    return raw * 1000000000


def _format_ts(nanos: int | None) -> str:
    if nanos is None:
        return ""
    seconds = nanos / 1_000_000_000.0
    from datetime import datetime, timezone

    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _parse_subject_info(obj: dict[str, Any]) -> SubjectInfo | None:
    datum = obj.get(DATUM_KEY)
    if not isinstance(datum, dict):
        return None
    payload = datum.get(SUBJECT_KEY)
    if not isinstance(payload, dict):
        return None
    subject_uuid = _first_non_empty([payload.get("uuid"), payload.get(UUID_KEY)])
    cid = _first_non_empty([payload.get("cid")])
    if not subject_uuid or not cid:
        return None
    parent_uuid = ""
    parent = payload.get("parentSubject")
    if isinstance(parent, dict):
        parent_uuid = _unwrap_scalar(parent.get(UUID_KEY))
    props = payload.get("properties", {}).get("map", {}) if isinstance(payload.get("properties"), dict) else {}
    return SubjectInfo(
        uuid=subject_uuid,
        cid=str(cid),
        parent_uuid=parent_uuid,
        name=str(props.get("name", "") or ""),
        cmdline=str(payload.get("cmdLine") or ""),
        ppid=str(props.get("ppid", "") or ""),
        seen_time=str(props.get("seen time", "") or ""),
    )


def _parse_event_info(obj: dict[str, Any]) -> dict[str, Any] | None:
    datum = obj.get(DATUM_KEY)
    if not isinstance(datum, dict):
        return None
    payload = datum.get(EVENT_KEY)
    if not isinstance(payload, dict):
        return None
    subject = payload.get("subject")
    pobj = payload.get("predicateObject")
    if not isinstance(subject, dict) or not isinstance(pobj, dict):
        return None
    subject_uuid = _unwrap_scalar(subject.get(UUID_KEY))
    object_uuid = _unwrap_scalar(pobj.get(UUID_KEY))
    if not subject_uuid or not object_uuid:
        return None
    pobj2 = payload.get("predicateObject2")
    object2_uuid = _unwrap_scalar(pobj2.get(UUID_KEY)) if isinstance(pobj2, dict) else ""
    event_uuid = _first_non_empty([payload.get("uuid"), payload.get(UUID_KEY)])
    ts = _to_nanos(
        payload.get("timestampNanos")
        or payload.get("timestampMicros")
        or payload.get("timestampMillis")
        or payload.get("timestamp")
    )
    action = str(payload.get("type", "EVENT_OTHER")).replace("EVENT_", "").upper()
    return {
        "event_uuid": event_uuid,
        "subject_uuid": subject_uuid,
        "object_uuid": object_uuid,
        "object2_uuid": object2_uuid,
        "timestamp_nanos": ts,
        "event_type": action,
        "predicate_object_path": _unwrap_scalar(payload.get("predicateObjectPath")),
        "predicate_object2_path": _unwrap_scalar(payload.get("predicateObject2Path")),
    }


def _entity_info_for_gt_uuid(
    gt_uuid: str,
    *,
    event_info: dict[str, Any],
    entity_info: dict[str, EntityInfo],
    subject_uuid_to_cid: dict[str, str],
) -> tuple[str, str, str]:
    if gt_uuid == event_info.get("event_uuid"):
        return "event", event_info.get("event_type", ""), ""
    info = entity_info.get(gt_uuid)
    if info is not None:
        cid = subject_uuid_to_cid.get(gt_uuid, "")
        return info.entity_type, info.entity_attr, cid
    cid = subject_uuid_to_cid.get(gt_uuid, "")
    if cid:
        return "process", "", cid
    return "unknown", "", ""


def _time_bin(delta_sec: float) -> str:
    if delta_sec < 60:
        return "lt_1m"
    if delta_sec < 5 * 60:
        return "1m_to_5m"
    if delta_sec < 15 * 60:
        return "5m_to_15m"
    if delta_sec < 60 * 60:
        return "15m_to_60m"
    return "ge_60m"


def _top_counter(counter: Counter[str], limit: int = 15) -> list[dict[str, Any]]:
    return [{"key": key, "count": count} for key, count in counter.most_common(limit)]


def _write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> None:
    args = _parse_args()
    logs_dir = Path(args.logs_dir)
    gt_path = Path(args.ground_truth)
    task_path = Path(args.task_subgraphs)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    gt_set = _load_ground_truth(gt_path)
    tasks = _load_task_subgraphs(task_path)

    subject_uuid_to_cid: dict[str, str] = {}
    cid_to_subject_uuids: dict[str, set[str]] = defaultdict(set)
    subject_infos: dict[str, SubjectInfo] = {}

    print("[pass1] scanning subjects for UUID<->CID mapping...")
    for log_file in _iter_log_files(logs_dir, "trace"):
        for line in _iter_lines(log_file):
            if SUBJECT_KEY not in line:
                continue
            obj = _extract_json_fragment(line)
            if obj is None:
                continue
            subject_info = _parse_subject_info(obj)
            if subject_info is None:
                continue
            subject_uuid_to_cid[subject_info.uuid] = subject_info.cid
            cid_to_subject_uuids[subject_info.cid].add(subject_info.uuid)
            subject_infos.setdefault(subject_info.uuid, subject_info)

    gt_process_uuids = {uuid for uuid in gt_set if uuid in subject_uuid_to_cid}
    gt_process_cids = {subject_uuid_to_cid[uuid] for uuid in gt_process_uuids}

    malicious_tasks: list[TaskInfo] = []
    malicious_task_ids: set[str] = set()
    malicious_task_process_cids: set[str] = set()
    malicious_task_process_uuids: set[str] = set()
    process_uuid_to_task_ids: dict[str, set[str]] = defaultdict(set)
    task_to_process_uuids: dict[str, set[str]] = {}

    for task in tasks:
        task.gt_hit_cids = set(task.process_cids & gt_process_cids)
        task.gt_hit_process_uuids = {
            uuid
            for cid in task.gt_hit_cids
            for uuid in cid_to_subject_uuids.get(cid, set())
            if uuid in gt_process_uuids
        }
        if not task.gt_hit_cids:
            continue
        malicious_tasks.append(task)
        malicious_task_ids.add(task.task_id)
        malicious_task_process_cids.update(task.process_cids)
        proc_uuids = {
            uuid
            for cid in task.process_cids
            for uuid in cid_to_subject_uuids.get(cid, set())
        }
        task_to_process_uuids[task.task_id] = proc_uuids
        malicious_task_process_uuids.update(proc_uuids)
        for uuid in proc_uuids:
            process_uuid_to_task_ids[uuid].add(task.task_id)

    entity_info: dict[str, EntityInfo] = {}
    for uuid, info in subject_infos.items():
        entity_info[uuid] = EntityInfo(uuid=uuid, entity_type="process", entity_attr=info.name or info.cmdline or info.cid)

    gt_node_stats: dict[str, GTNodeStat] = {uuid: GTNodeStat(uuid=uuid) for uuid in gt_set}
    onehop_occurrences: list[dict[str, Any]] = []
    role_counter: Counter[str] = Counter()
    event_type_counter: Counter[str] = Counter()
    entity_type_counter: Counter[str] = Counter()
    pattern_counter: Counter[str] = Counter()

    task_lookup = {task.task_id: task for task in malicious_tasks}

    print("[pass2] scanning events and GT-node neighborhoods around malicious task processes...")
    for log_file in _iter_log_files(logs_dir, "trace"):
        for line in _iter_lines(log_file):
            obj = _extract_json_fragment(line)
            if obj is None:
                continue
            for uuid, attr in _extract_darpa_node_records(obj):
                if uuid in gt_set or uuid in malicious_task_process_uuids:
                    current = entity_info.get(uuid)
                    if current is None or (not current.entity_attr and attr.node_attr):
                        entity_info[uuid] = EntityInfo(uuid=uuid, entity_type=attr.node_type, entity_attr=attr.node_attr)

            event_info = _parse_event_info(obj)
            if event_info is None:
                continue

            subject_uuid = event_info["subject_uuid"]
            object_uuid = event_info["object_uuid"]
            subject_task_ids = process_uuid_to_task_ids.get(subject_uuid, set())
            object_task_ids = process_uuid_to_task_ids.get(object_uuid, set()) if args.include_object_side else set()
            matched_task_ids = set(subject_task_ids) | set(object_task_ids)
            if not matched_task_ids:
                continue

            for task_id in sorted(matched_task_ids):
                task = task_lookup[task_id]
                task.matched_event_count += 1
                ts = event_info["timestamp_nanos"]
                if ts is not None:
                    if task.first_ts is None or ts < task.first_ts:
                        task.first_ts = ts
                    if task.last_ts is None or ts > task.last_ts:
                        task.last_ts = ts
                task.event_types[event_info["event_type"]] += 1

                task_process_uuids = task_to_process_uuids[task_id]
                seed_cids = set()
                if subject_uuid in task_process_uuids:
                    cid = subject_uuid_to_cid.get(subject_uuid)
                    if cid:
                        seed_cids.add(cid)
                if object_uuid in task_process_uuids:
                    cid = subject_uuid_to_cid.get(object_uuid)
                    if cid:
                        seed_cids.add(cid)

                endpoint_rows = [
                    ("event_uuid", event_info.get("event_uuid", "")),
                    ("subject_uuid", subject_uuid),
                    ("predicate_object", object_uuid),
                    ("predicate_object2", event_info.get("object2_uuid", "")),
                ]
                for endpoint_role, gt_uuid in endpoint_rows:
                    if not gt_uuid or gt_uuid not in gt_set:
                        continue
                    direct_member = gt_uuid in task_process_uuids
                    role = endpoint_role
                    if endpoint_role == "subject_uuid" and direct_member:
                        role = "task_process_subject"
                    elif endpoint_role == "predicate_object" and direct_member:
                        role = "task_process_object"
                    elif endpoint_role == "subject_uuid" and not direct_member:
                        role = "subject_nonseed"

                    entity_type, entity_attr, cid = _entity_info_for_gt_uuid(
                        gt_uuid,
                        event_info=event_info,
                        entity_info=entity_info,
                        subject_uuid_to_cid=subject_uuid_to_cid,
                    )
                    stat = gt_node_stats[gt_uuid]
                    stat.entity_type = entity_type or stat.entity_type
                    if entity_attr and not stat.entity_attr:
                        stat.entity_attr = entity_attr
                    if cid and not stat.cid:
                        stat.cid = cid
                    stat.is_gt_process_uuid = gt_uuid in gt_process_uuids
                    stat.is_direct_task_process_member = stat.is_direct_task_process_member or direct_member
                    if not direct_member:
                        stat.is_onehop_recovered = True
                        task.gt_neighbor_uuids.add(gt_uuid)
                        if entity_type != "process":
                            task.gt_nonprocess_neighbor_uuids.add(gt_uuid)
                    stat.malicious_task_ids.add(task_id)
                    stat.occurrence_count += 1
                    stat.roles[role] += 1
                    stat.event_types[event_info["event_type"]] += 1
                    stat.touched_seed_cids.update(seed_cids)
                    if ts is not None:
                        if stat.first_ts is None or ts < stat.first_ts:
                            stat.first_ts = ts
                        if stat.last_ts is None or ts > stat.last_ts:
                            stat.last_ts = ts

                    if not direct_member:
                        role_counter[role] += 1
                        event_type_counter[event_info["event_type"]] += 1
                        entity_type_counter[entity_type] += 1
                        pattern_counter[f"{role}|{entity_type}|{event_info['event_type']}"] += 1

                    onehop_occurrences.append(
                        {
                            "task_id": task_id,
                            "gt_uuid": gt_uuid,
                            "gt_entity_type": entity_type,
                            "gt_entity_attr": entity_attr,
                            "gt_cid": cid,
                            "role": role,
                            "is_direct_task_process_member": int(direct_member),
                            "event_uuid": event_info.get("event_uuid", ""),
                            "event_type": event_info["event_type"],
                            "timestamp_nanos": ts or "",
                            "timestamp": _format_ts(ts),
                            "subject_uuid": subject_uuid,
                            "object_uuid": object_uuid,
                            "object2_uuid": event_info.get("object2_uuid", ""),
                            "seed_cids": ";".join(sorted(seed_cids)),
                        }
                    )

    time_bin_counter: Counter[str] = Counter()
    for row in onehop_occurrences:
        if int(row["is_direct_task_process_member"]):
            continue
        task = task_lookup[row["task_id"]]
        ts = row["timestamp_nanos"]
        if not ts or task.first_ts is None:
            continue
        delta_sec = max(0.0, (int(ts) - int(task.first_ts)) / 1_000_000_000.0)
        row["delta_from_task_start_sec"] = round(delta_sec, 3)
        row["delta_bin"] = _time_bin(delta_sec)
        time_bin_counter[row["delta_bin"]] += 1

    gt_entity_distribution: Counter[str] = Counter()
    for uuid in gt_set:
        entity_type, entity_attr, cid = _entity_info_for_gt_uuid(
            uuid,
            event_info={"event_uuid": "", "event_type": ""},
            entity_info=entity_info,
            subject_uuid_to_cid=subject_uuid_to_cid,
        )
        stat = gt_node_stats[uuid]
        if entity_type and stat.entity_type == "unknown":
            stat.entity_type = entity_type
        if entity_attr and not stat.entity_attr:
            stat.entity_attr = entity_attr
        if cid and not stat.cid:
            stat.cid = cid
        gt_entity_distribution[stat.entity_type] += 1

    covered_direct = sum(1 for stat in gt_node_stats.values() if stat.is_direct_task_process_member)
    covered_onehop = sum(1 for stat in gt_node_stats.values() if stat.is_onehop_recovered)
    covered_any = sum(1 for stat in gt_node_stats.values() if stat.is_direct_task_process_member or stat.is_onehop_recovered)
    covered_nonprocess_onehop = sum(
        1
        for stat in gt_node_stats.values()
        if stat.is_onehop_recovered and stat.entity_type != "process"
    )

    task_rows: list[dict[str, Any]] = []
    for task in sorted(malicious_tasks, key=lambda item: item.task_id):
        task_rows.append(
            {
                "task_id": task.task_id,
                "process_cid_count": len(task.process_cids),
                "gt_hit_cid_count": len(task.gt_hit_cids),
                "gt_hit_process_uuid_count": len(task.gt_hit_process_uuids),
                "matched_event_count": task.matched_event_count,
                "task_first_timestamp": _format_ts(task.first_ts),
                "task_last_timestamp": _format_ts(task.last_ts),
                "task_span_minutes": round(((task.last_ts - task.first_ts) / 60_000_000_000.0), 3) if task.first_ts and task.last_ts and task.last_ts >= task.first_ts else 0.0,
                "gt_neighbor_uuid_count": len(task.gt_neighbor_uuids),
                "gt_nonprocess_neighbor_uuid_count": len(task.gt_nonprocess_neighbor_uuids),
                "top_event_types": json.dumps(_top_counter(task.event_types, limit=10), ensure_ascii=False),
                "gt_hit_cids": ";".join(sorted(task.gt_hit_cids)),
            }
        )

    gt_rows: list[dict[str, Any]] = []
    for uuid, stat in sorted(gt_node_stats.items(), key=lambda item: (item[1].entity_type, item[0])):
        gt_rows.append(
            {
                "uuid": uuid,
                "entity_type": stat.entity_type,
                "entity_attr": stat.entity_attr,
                "cid": stat.cid,
                "is_gt_process_uuid": int(stat.is_gt_process_uuid),
                "is_direct_task_process_member": int(stat.is_direct_task_process_member),
                "is_onehop_recovered": int(stat.is_onehop_recovered),
                "malicious_task_count": len(stat.malicious_task_ids),
                "occurrence_count": stat.occurrence_count,
                "first_timestamp": _format_ts(stat.first_ts),
                "last_timestamp": _format_ts(stat.last_ts),
                "roles": json.dumps(_top_counter(stat.roles, limit=10), ensure_ascii=False),
                "event_types": json.dumps(_top_counter(stat.event_types, limit=10), ensure_ascii=False),
                "seed_cids": ";".join(sorted(stat.touched_seed_cids)),
                "task_ids": ";".join(sorted(stat.malicious_task_ids)),
            }
        )

    summary = {
        "ground_truth_total_unique_uuids": len(gt_set),
        "ground_truth_process_uuid_count": len(gt_process_uuids),
        "ground_truth_process_cid_count": len(gt_process_cids),
        "malicious_task_count": len(malicious_tasks),
        "malicious_task_ids": [task.task_id for task in malicious_tasks],
        "malicious_task_process_cid_count": len(malicious_task_process_cids),
        "direct_task_process_member_gt_uuid_count": covered_direct,
        "onehop_recovered_gt_uuid_count_excluding_direct": covered_onehop,
        "onehop_recovered_nonprocess_gt_uuid_count": covered_nonprocess_onehop,
        "covered_any_gt_uuid_count": covered_any,
        "covered_any_ratio": round((covered_any / len(gt_set)), 6) if gt_set else 0.0,
        "gt_entity_type_distribution": dict(gt_entity_distribution.most_common()),
        "onehop_role_distribution": dict(role_counter.most_common()),
        "onehop_entity_type_distribution": dict(entity_type_counter.most_common()),
        "onehop_event_type_distribution": dict(event_type_counter.most_common(25)),
        "onehop_time_bin_distribution": dict(time_bin_counter.most_common()),
        "top_role_entity_event_patterns": [{"pattern": key, "count": count} for key, count in pattern_counter.most_common(30)],
        "task_gt_neighbor_count_summary": {
            "min": min((len(task.gt_neighbor_uuids) for task in malicious_tasks), default=0),
            "max": max((len(task.gt_neighbor_uuids) for task in malicious_tasks), default=0),
            "median": median([len(task.gt_neighbor_uuids) for task in malicious_tasks]) if malicious_tasks else 0,
        },
    }

    markdown_lines = [
        "# Trace GT 1-hop Neighborhood Analysis",
        "",
        "## Scope",
        "",
        "This analysis is independent from the mainline reasoning path. It starts from the trace ground-truth UUID list, maps GT process UUIDs to task-graph process CIDs, identifies GT-hit malicious task graphs, and then scans the full raw logs to study which GT UUIDs appear in the 1-hop event neighborhood of those malicious task-process nodes.",
        "",
        "## Key Counts",
        "",
        f"- Ground-truth unique UUIDs: {summary['ground_truth_total_unique_uuids']}",
        f"- GT process UUIDs: {summary['ground_truth_process_uuid_count']}",
        f"- GT process CIDs: {summary['ground_truth_process_cid_count']}",
        f"- Malicious task count: {summary['malicious_task_count']}",
        f"- Direct GT process members inside malicious task graphs: {summary['direct_task_process_member_gt_uuid_count']}",
        f"- Additional GT UUIDs recovered from 1-hop event neighborhoods: {summary['onehop_recovered_gt_uuid_count_excluding_direct']}",
        f"- Additional non-process GT UUIDs recovered from 1-hop event neighborhoods: {summary['onehop_recovered_nonprocess_gt_uuid_count']}",
        f"- Overall GT coverage by direct task membership or 1-hop recovery: {summary['covered_any_gt_uuid_count']} ({summary['covered_any_ratio']:.2%})",
        "",
        "## Most Common 1-hop GT Roles",
        "",
    ]
    for key, count in role_counter.most_common(10):
        markdown_lines.append(f"- {key}: {count}")
    markdown_lines.extend(["", "## Most Common 1-hop GT Entity Types", ""])
    for key, count in entity_type_counter.most_common(10):
        markdown_lines.append(f"- {key}: {count}")
    markdown_lines.extend(["", "## Most Common Event Types Around Recovered GT Nodes", ""])
    for key, count in event_type_counter.most_common(15):
        markdown_lines.append(f"- {key}: {count}")
    markdown_lines.extend(["", "## Time-Bin Distribution For Recovered 1-hop GT Nodes", ""])
    for key, count in time_bin_counter.most_common():
        markdown_lines.append(f"- {key}: {count}")
    markdown_lines.extend(["", "## Top Role / Entity / Event Patterns", ""])
    for item in summary["top_role_entity_event_patterns"][:15]:
        markdown_lines.append(f"- {item['pattern']}: {item['count']}")
    markdown_lines.extend(["", "## Files", ""])
    markdown_lines.extend([
        "- `summary.json`: compact machine-readable summary",
        "- `malicious_tasks.csv`: per-malicious-task counts and spans",
        "- `gt_node_stats.csv`: per-GT-node aggregate view",
        "- `gt_occurrences.csv`: task/event-level GT occurrence rows",
    ])

    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "summary.md").write_text("\n".join(markdown_lines) + "\n", encoding="utf-8")
    _write_csv(
        out_dir / "malicious_tasks.csv",
        task_rows,
        [
            "task_id",
            "process_cid_count",
            "gt_hit_cid_count",
            "gt_hit_process_uuid_count",
            "matched_event_count",
            "task_first_timestamp",
            "task_last_timestamp",
            "task_span_minutes",
            "gt_neighbor_uuid_count",
            "gt_nonprocess_neighbor_uuid_count",
            "top_event_types",
            "gt_hit_cids",
        ],
    )
    _write_csv(
        out_dir / "gt_node_stats.csv",
        gt_rows,
        [
            "uuid",
            "entity_type",
            "entity_attr",
            "cid",
            "is_gt_process_uuid",
            "is_direct_task_process_member",
            "is_onehop_recovered",
            "malicious_task_count",
            "occurrence_count",
            "first_timestamp",
            "last_timestamp",
            "roles",
            "event_types",
            "seed_cids",
            "task_ids",
        ],
    )
    _write_csv(
        out_dir / "gt_occurrences.csv",
        onehop_occurrences,
        [
            "task_id",
            "gt_uuid",
            "gt_entity_type",
            "gt_entity_attr",
            "gt_cid",
            "role",
            "is_direct_task_process_member",
            "event_uuid",
            "event_type",
            "timestamp_nanos",
            "timestamp",
            "delta_from_task_start_sec",
            "delta_bin",
            "subject_uuid",
            "object_uuid",
            "object2_uuid",
            "seed_cids",
        ],
    )

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"[done] wrote outputs to {out_dir}")


if __name__ == "__main__":
    main()
