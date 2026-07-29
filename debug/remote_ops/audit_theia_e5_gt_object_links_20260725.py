"""Audit E5 GT entity types and trace GT file/netflow UUIDs back to Subjects.

The ORTHRUS CSV mixes Subject, FileObject, and NetFlowObject UUIDs.  TAPAS
task graphs contain process Subjects only, so object UUIDs must be translated
through their observed Event subjects before they can label a task graph.
"""

from __future__ import annotations

import argparse
import ast
import collections
import csv
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def _uuid(value: Any) -> str:
    if isinstance(value, str):
        return value.strip().upper()
    if not isinstance(value, dict):
        return ""
    for key, nested in value.items():
        if key == "UUID" or key.endswith(".UUID"):
            return _uuid(nested)
    if len(value) == 1:
        return _uuid(next(iter(value.values())))
    return ""


def _datum(record: dict[str, Any], name: str) -> dict[str, Any] | None:
    value = record.get("datum", {})
    if not isinstance(value, dict):
        return None
    for key, payload in value.items():
        if key == name or key.endswith(f".{name}"):
            return payload if isinstance(payload, dict) else None
    return None


def _load_gt(path: Path) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    entity_kind: dict[str, str] = {}
    attributes: dict[str, dict[str, str]] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.reader(handle):
            if not row or not row[0].strip():
                continue
            uuid = row[0].strip().upper()
            raw_attributes = row[1] if len(row) > 1 else "{}"
            try:
                parsed = ast.literal_eval(raw_attributes)
            except (SyntaxError, ValueError):
                parsed = {}
            parsed = parsed if isinstance(parsed, dict) else {}
            kind = next(iter(parsed), "unknown").strip().lower()
            entity_kind[uuid] = kind
            attributes[uuid] = {str(key): str(value) for key, value in parsed.items()}
    return entity_kind, attributes


def _read_canonical_map(module1_graphs: Path) -> dict[str, str]:
    import torch

    bundle = torch.load(module1_graphs, map_location="cpu", weights_only=False)
    metadata = bundle.get("thread_merge_metadata", {})
    raw_map = metadata.get("raw_subject_to_canonical_node", {})
    return {str(key).upper(): str(value).upper() for key, value in raw_map.items()}


def run(args: argparse.Namespace) -> dict[str, Any]:
    entity_kind, attributes = _load_gt(args.gt_csv)
    object_ids = sorted(
        uuid for uuid, kind in entity_kind.items() if kind in {"file", "netflow"}
    )
    canonical_map = _read_canonical_map(args.module1_graphs)
    subject_ids = {uuid for uuid, kind in entity_kind.items() if kind == "subject"}

    object_subjects: dict[str, collections.Counter[str]] = {
        uuid: collections.Counter() for uuid in object_ids
    }
    event_types: dict[str, collections.Counter[str]] = {
        uuid: collections.Counter() for uuid in object_ids
    }
    observed_object_declarations: dict[str, collections.Counter[str]] = {
        uuid: collections.Counter() for uuid in object_ids
    }

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        pattern_path = Path(handle.name)
        handle.write("\n".join(object_ids))
        handle.write("\n")
    try:
        # Cloud images do not consistently include ripgrep. grep -R is slower,
        # but keeps this audit bounded to the six non-Subject GT UUIDs.
        command = [
            "grep",
            "-R",
            "-h",
            "--binary-files=text",
            "--ignore-case",
            "--fixed-strings",
            "-f",
            str(pattern_path),
            str(args.logs),
        ]
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert process.stdout is not None
        matched_lines = 0
        for text in process.stdout:
            try:
                record = json.loads(text)
            except json.JSONDecodeError:
                continue
            matched_lines += 1
            for entity_name in ("FileObject", "NetFlowObject"):
                payload = _datum(record, entity_name)
                if payload is None:
                    continue
                entity_uuid = _uuid(payload.get("uuid"))
                if entity_uuid in observed_object_declarations:
                    observed_object_declarations[entity_uuid][entity_name] += 1
            event = _datum(record, "Event")
            if event is None:
                continue
            subject_uuid = _uuid(event.get("subject"))
            event_type = str(event.get("type", "EVENT_OTHER"))
            candidate_objects = {
                _uuid(event.get("predicateObject")),
                _uuid(event.get("predicateObject2")),
            }
            for object_uuid in candidate_objects & set(object_ids):
                if subject_uuid:
                    object_subjects[object_uuid][subject_uuid] += 1
                    event_types[object_uuid][event_type] += 1
        stderr = process.stderr.read() if process.stderr is not None else ""
        return_code = process.wait()
        if return_code not in {0, 1}:  # rg uses 1 when no line matches.
            raise RuntimeError(f"rg failed with code {return_code}: {stderr[-500:]}")
    finally:
        pattern_path.unlink(missing_ok=True)

    canonical_subjects_by_object = {
        uuid: sorted(
            {
                canonical_map.get(subject_uuid, subject_uuid)
                for subject_uuid in counter
                if subject_uuid in canonical_map
            }
        )
        for uuid, counter in object_subjects.items()
    }
    direct_canonical_subjects = {
        canonical_map[uuid] for uuid in subject_ids if uuid in canonical_map
    }
    object_linked_canonical_subjects = set().union(*map(set, canonical_subjects_by_object.values()))
    result = {
        "gt_uuid_count": len(entity_kind),
        "gt_entity_type_counts": dict(collections.Counter(entity_kind.values())),
        "gt_subject_uuid_count": len(subject_ids),
        "gt_object_uuid_count": len(object_ids),
        "subject_uuid_mapped_to_canonical_count": sum(uuid in canonical_map for uuid in subject_ids),
        "direct_canonical_subject_count": len(direct_canonical_subjects),
        "object_linked_canonical_subject_count": len(object_linked_canonical_subjects),
        "combined_canonical_task_label_subject_count": len(
            direct_canonical_subjects | object_linked_canonical_subjects
        ),
        "matched_log_lines_for_object_gt": matched_lines,
        "objects": {
            uuid: {
                "gt_attributes": attributes[uuid],
                "raw_subject_event_count": int(sum(object_subjects[uuid].values())),
                "raw_subject_count": len(object_subjects[uuid]),
                "top_raw_subjects": object_subjects[uuid].most_common(20),
                "canonical_subjects": canonical_subjects_by_object[uuid],
                "event_types": dict(event_types[uuid]),
                "raw_entity_declarations": dict(observed_object_declarations[uuid]),
            }
            for uuid in object_ids
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gt-csv", type=Path, required=True)
    parser.add_argument("--logs", type=Path, required=True)
    parser.add_argument("--module1-graphs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
