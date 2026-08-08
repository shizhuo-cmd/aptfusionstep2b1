"""Read-only audit of TC3 parser assumptions before task-graph construction."""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path
from typing import Any


LEGACY_EVENT_TYPES = {
    "EVENT_ACCEPT",
    "EVENT_CONNECT",
    "EVENT_EXECUTE",
    "EVENT_EXIT",
    "EVENT_READ",
    "EVENT_RECVFROM",
    "EVENT_RECVMSG",
    "EVENT_SENDTO",
    "EVENT_SENDMSG",
    "EVENT_WRITE",
}
TRACE_EXTRA_EVENT_TYPES = {"EVENT_RENAME", "EVENT_CREATE_OBJECT"}


def _payload(record: dict[str, Any], short_name: str) -> dict[str, Any] | None:
    datum = record.get("datum", {})
    if not isinstance(datum, dict):
        return None
    for key, value in datum.items():
        if key == short_name or key.endswith(f".{short_name}"):
            return value if isinstance(value, dict) else None
    return None


def _scalar(value: Any) -> str:
    if isinstance(value, str):
        return value
    if not isinstance(value, dict):
        return ""
    for key in ("UUID", "string", "long", "int"):
        if key in value:
            return _scalar(value[key])
    for key, nested in value.items():
        if key.endswith(".UUID"):
            return _scalar(nested)
    if len(value) == 1:
        return _scalar(next(iter(value.values())))
    return ""


def _properties(subject: dict[str, Any]) -> dict[str, Any]:
    value = subject.get("properties", {})
    return value.get("map", {}) if isinstance(value, dict) and isinstance(value.get("map", {}), dict) else {}


def _event_object_ids(event: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for field in ("predicateObject", "predicateObject2"):
        value = _scalar(event.get(field))
        if value:
            values.add(value)
    return values


def _top(counter: collections.Counter[str], count: int = 20) -> dict[str, int]:
    return {key: int(value) for key, value in counter.most_common(count)}


def audit(logs: Path, ground_truth: Path, dataset: str) -> dict[str, Any]:
    gt = {line.strip() for line in ground_truth.read_text(encoding="utf-8").splitlines() if line.strip()}
    allowed = set(LEGACY_EVENT_TYPES)
    if dataset == "trace":
        allowed |= TRACE_EXTRA_EVENT_TYPES

    subject_rows: dict[str, dict[str, str]] = {}
    subject_type_counts: collections.Counter[str] = collections.Counter()
    raw_event_types: collections.Counter[str] = collections.Counter()
    accepted_event_types: collections.Counter[str] = collections.Counter()
    gt_event_types_all: collections.Counter[str] = collections.Counter()
    gt_event_types_accepted: collections.Counter[str] = collections.Counter()
    event_subjects: set[str] = set()
    gt_event_subjects_all: set[str] = set()
    gt_event_subjects_accepted: set[str] = set()
    gt_predicate_objects: set[str] = set()
    file_object_ids: set[str] = set()
    netflow_object_ids: set[str] = set()
    malformed_allowed_events: collections.Counter[str] = collections.Counter()
    record_counts: collections.Counter[str] = collections.Counter()

    files = sorted(logs.glob("*.json"))
    for path in files:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    record_counts["invalid_json"] += 1
                    continue
                event = _payload(record, "Event")
                if event is not None:
                    record_counts["Event"] += 1
                    event_type = str(event.get("type", ""))
                    raw_event_types[event_type] += 1
                    subject_uuid = _scalar(event.get("subject"))
                    object_ids = _event_object_ids(event)
                    if subject_uuid:
                        event_subjects.add(subject_uuid)
                    if subject_uuid in gt:
                        gt_event_subjects_all.add(subject_uuid)
                        gt_event_types_all[event_type] += 1
                    if object_ids.intersection(gt):
                        gt_predicate_objects.update(object_ids.intersection(gt))
                    if event_type in allowed:
                        if not subject_uuid or not object_ids:
                            malformed_allowed_events[event_type] += 1
                            continue
                        accepted_event_types[event_type] += 1
                        if subject_uuid in gt:
                            gt_event_subjects_accepted.add(subject_uuid)
                            gt_event_types_accepted[event_type] += 1
                    continue
                subject = _payload(record, "Subject")
                if subject is not None:
                    record_counts["Subject"] += 1
                    uuid = _scalar(subject.get("uuid"))
                    if not uuid:
                        continue
                    props = _properties(subject)
                    subject_rows[uuid] = {
                        "parent": _scalar(subject.get("parentSubject")) or "Unknow",
                        "tgid": str(props.get("tgid", "")).strip(),
                        "path": str(props.get("path", "Unknown")).strip() or "Unknown",
                        "cid": str(subject.get("cid", "")).strip(),
                        "type": str(subject.get("type", "")).strip(),
                    }
                    subject_type_counts[subject_rows[uuid]["type"] or "<missing>"] += 1
                    continue
                file_object = _payload(record, "FileObject")
                if file_object is not None:
                    record_counts["FileObject"] += 1
                    uuid = _scalar(file_object.get("uuid"))
                    if uuid:
                        file_object_ids.add(uuid)
                    continue
                netflow = _payload(record, "NetFlowObject")
                if netflow is not None:
                    record_counts["NetFlowObject"] += 1
                    uuid = _scalar(netflow.get("uuid"))
                    if uuid:
                        netflow_object_ids.add(uuid)
                    continue
                record_counts["other"] += 1

    expected_threads = {
        uuid
        for uuid, row in subject_rows.items()
        if row["parent"] in subject_rows
        and row["tgid"]
        and subject_rows[row["parent"]]["tgid"]
        and row["tgid"] == subject_rows[row["parent"]]["tgid"]
    }
    typed_threads = {uuid for uuid, row in subject_rows.items() if row["type"].upper() == "SUBJECT_THREAD"}
    legacy_groups: dict[tuple[str, str, str], list[str]] = collections.defaultdict(list)
    for uuid, row in subject_rows.items():
        legacy_groups[(row["parent"], row["tgid"] or "Unknown", row["path"] or "Unknown")].append(uuid)
    collision_groups = [members for members in legacy_groups.values() if len(members) > 1]
    cid_groups: dict[str, list[str]] = collections.defaultdict(list)
    for uuid, row in subject_rows.items():
        if row["cid"]:
            cid_groups[row["cid"]].append(uuid)
    cid_collisions = [members for members in cid_groups.values() if len(members) > 1]

    gt_subjects = gt.intersection(subject_rows)
    gt_files = gt.intersection(file_object_ids)
    gt_netflows = gt.intersection(netflow_object_ids)
    return {
        "dataset": dataset,
        "log_file_count": len(files),
        "ground_truth_count": len(gt),
        "record_counts": {key: int(value) for key, value in sorted(record_counts.items())},
        "raw_event_type_counts": _top(raw_event_types, 50),
        "legacy_sequence_event_type_counts": _top(accepted_event_types, 50),
        "legacy_sequence_retained_event_count": int(sum(accepted_event_types.values())),
        "raw_event_count": int(sum(raw_event_types.values())),
        "legacy_sequence_retained_fraction": float(sum(accepted_event_types.values()) / max(1, sum(raw_event_types.values()))),
        "malformed_legacy_event_counts": {key: int(value) for key, value in sorted(malformed_allowed_events.items())},
        "subject_count": len(subject_rows),
        "subject_type_counts": {key: int(value) for key, value in sorted(subject_type_counts.items())},
        "subjects_missing_tgid": int(sum(1 for row in subject_rows.values() if not row["tgid"])),
        "event_subject_count": len(event_subjects),
        "event_subjects_without_subject_record": int(len(event_subjects - set(subject_rows))),
        "gt_entity_matches": {
            "subject": len(gt_subjects),
            "file_object": len(gt_files),
            "netflow_object": len(gt_netflows),
            "predicate_object_only": len(gt_predicate_objects - gt_subjects - gt_files - gt_netflows),
            "unmatched": len(gt - gt_subjects - gt_files - gt_netflows - gt_predicate_objects),
        },
        "gt_subject_event_coverage": {
            "gt_subject_count": len(gt_subjects),
            "with_any_raw_event": len(gt_event_subjects_all),
            "with_retained_legacy_event": len(gt_event_subjects_accepted),
            "raw_event_type_counts": _top(gt_event_types_all, 50),
            "retained_event_type_counts": _top(gt_event_types_accepted, 50),
        },
        "thread_rule_audit": {
            "typed_subject_thread_count": len(typed_threads),
            "parent_known_same_tgid_count": len(expected_threads),
            "typed_threads_not_parent_same_tgid": len(typed_threads - expected_threads),
            "legacy_parent_tgid_path_collision_group_count": len(collision_groups),
            "legacy_parent_tgid_path_collapsed_subject_count": int(sum(len(group) - 1 for group in collision_groups)),
            "largest_legacy_collision_groups": sorted((len(group) for group in collision_groups), reverse=True)[:20],
            "cid_collision_group_count": len(cid_collisions),
            "cid_collapsed_subject_count_if_used_as_identity": int(sum(len(group) - 1 for group in cid_collisions)),
            "largest_cid_collision_groups": sorted((len(group) for group in cid_collisions), reverse=True)[:20],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", choices=("theia", "trace"), required=True)
    parser.add_argument("--logs", type=Path, required=True)
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.logs, args.ground_truth, args.dataset)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
