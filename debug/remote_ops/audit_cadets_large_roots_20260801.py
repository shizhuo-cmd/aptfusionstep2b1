"""Targeted raw-log audit of the largest CADETS task-component roots.

The original full JSON parser was deliberately replaced with a single native
ripgrep pass.  It examines only records mentioning one of the selected roots,
which is sufficient to establish whether the roots are missing-parent
synthetic aggregators without re-parsing the full audit stream.
"""

from __future__ import annotations

import collections
import json
import re
import subprocess
from pathlib import Path


REPO = Path("/root/autodl-tmp/APT-Fusionstep2b1")
ARTIFACTS = REPO / "artifacts_cadets_normal_only_root_temporal_baseline_20260801"
LOG_DIR = Path("/root/autodl-tmp/data/cadets/logs")
OUT = REPO / "debug" / "remote_ops" / "out" / "cadets_root_audit_20260801" / "large_root_audit.json"
TOP_TASKS = 8


def _uuid(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    return str(value.get("com.bbn.tc.schema.avro.cdm18.UUID", "")).strip()


def _root_rows() -> dict[str, dict]:
    task_rows = json.loads((ARTIFACTS / "module1" / "task_subgraphs.json").read_text(encoding="utf-8"))
    diagnostics = json.loads((ARTIFACTS / "module1" / "task_component_diagnostics.json").read_text(encoding="utf-8"))
    diag_by_task = {str(row["task_id"]): row for row in diagnostics}
    candidates = sorted(task_rows, key=lambda row: len(row.get("process_ids", [])), reverse=True)[:TOP_TASKS]
    rows: dict[str, dict] = {}
    for task in candidates:
        task_id = str(task["task_id"])
        diagnostic = diag_by_task.get(task_id, {})
        root = str(diagnostic.get("task_root_id") or task.get("process_ids", [""])[0])
        rows[root] = {
            "task_id": task_id,
            "task_root_id": root,
            "task_process_count": len(task.get("process_ids", [])),
            "task_component_diagnostics": diagnostic,
            "root_subject": None,
            "direct_child_subject_count": 0,
            "direct_child_samples": [],
            "subject_type_counts": collections.Counter(),
            "root_event_type_counts": collections.Counter(),
        }
    return rows


def main() -> None:
    rows = _root_rows()
    pattern = "|".join(re.escape(root) for root in rows)
    # One streaming raw-text pass avoids full JSON decoding of hundreds of GB.
    # The cloud image provides GNU grep but not necessarily ripgrep.
    command = ["grep", "-E", "-i", "-h", pattern, *[str(path) for path in sorted(LOG_DIR.glob("*.json"))]]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    assert process.stdout is not None
    for match in process.stdout:
        try:
            record = json.loads(match)
            datum = record.get("datum", {})
            subject = datum.get("com.bbn.tc.schema.avro.cdm18.Subject")
            if isinstance(subject, dict):
                subject_id = str(subject.get("uuid", "")).strip()
                parent = _uuid(subject.get("parentSubject"))
                if subject_id in rows:
                    rows[subject_id]["root_subject"] = {
                        "uuid": subject_id,
                        "type": subject.get("type"),
                        "cid": subject.get("cid"),
                        "parent_subject": parent or None,
                        "start_timestamp_nanos": subject.get("startTimestampNanos"),
                        "properties": subject.get("properties", {}),
                    }
                if parent in rows:
                    row = rows[parent]
                    row["direct_child_subject_count"] += 1
                    row["subject_type_counts"][str(subject.get("type", ""))] += 1
                    if len(row["direct_child_samples"]) < 20:
                        row["direct_child_samples"].append(
                            {
                                "uuid": subject_id,
                                "type": subject.get("type"),
                                "cid": subject.get("cid"),
                                "start_timestamp_nanos": subject.get("startTimestampNanos"),
                                "properties": subject.get("properties", {}),
                            }
                        )
                continue
            event = datum.get("com.bbn.tc.schema.avro.cdm18.Event")
            if isinstance(event, dict):
                subject_id = _uuid(event.get("subject"))
                if subject_id in rows:
                    rows[subject_id]["root_event_type_counts"][str(event.get("type", ""))] += 1
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
    stderr = process.stderr.read() if process.stderr is not None else ""
    returncode = process.wait()
    if returncode not in (0, 1):
        raise RuntimeError(f"targeted ripgrep root audit failed ({returncode}): {stderr[-1000:]}")

    for row in rows.values():
        row["subject_type_counts"] = dict(row["subject_type_counts"])
        row["root_event_type_counts"] = dict(row["root_event_type_counts"].most_common())
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"top_task_count": TOP_TASKS, "tasks": rows}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(OUT)


if __name__ == "__main__":
    main()
