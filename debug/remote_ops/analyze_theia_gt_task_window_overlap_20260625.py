from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import median
from typing import Any


_THIS_FILE = Path(__file__).resolve()
_REPO_ROOT = _THIS_FILE.parents[2]


@dataclass(frozen=True)
class _Window:
    window_id: str
    host: str
    status: str
    start_time: datetime | None
    end_time: datetime | None
    report_section_id: str
    report_section_title: str


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze THEIA GT-positive task overlap against GT windows.")
    parser.add_argument("--artifacts-root", type=Path, required=True)
    parser.add_argument(
        "--gt-json",
        type=Path,
        default=_REPO_ROOT / "docs" / "darpa_attack_eval_ground_truth_e3_report_enriched_20260618.json",
    )
    parser.add_argument(
        "--gt-node-path",
        type=Path,
        default=Path("/root/autodl-tmp/data/theia/theia_ground_truth.txt"),
    )
    parser.add_argument("--host", type=str, default="THEIA")
    parser.add_argument("--gt-time-offset-minutes", type=int, default=240)
    parser.add_argument("--output-dir", type=Path, default=None)
    return parser.parse_args()


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            return value.astimezone(timezone.utc).replace(tzinfo=None)
        return value
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        parsed = None
        for fmt, width in (("%Y-%m-%d %H:%M:%S", 19), ("%Y-%m-%dT%H:%M:%S", 19), ("%Y-%m-%d %H:%M", 16)):
            try:
                parsed = datetime.strptime(text[:width], fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        return None
    if parsed.tzinfo is not None:
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _iso(dt: datetime | None) -> str:
    return dt.isoformat() if isinstance(dt, datetime) else ""


def _load_gt_windows(gt_json_path: Path, *, host: str, offset_minutes: int) -> list[_Window]:
    payload = _load_json(gt_json_path)
    rows = payload.get("windows", []) if isinstance(payload, dict) else []
    offset = timedelta(minutes=int(offset_minutes))
    output: list[_Window] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("host", "")).strip().upper() != host.upper():
            continue
        start_time = _parse_datetime(row.get("start_time"))
        end_time = _parse_datetime(row.get("end_time"))
        if start_time is not None:
            start_time = start_time + offset
        if end_time is not None:
            end_time = end_time + offset
        output.append(
            _Window(
                window_id=str(row.get("window_id", "")).strip(),
                host=str(row.get("host", "")).strip(),
                status=str(row.get("status", "")).strip(),
                start_time=start_time,
                end_time=end_time,
                report_section_id=str(row.get("report_section_id", "")).strip(),
                report_section_title=str(row.get("report_section_title", "")).strip(),
            )
        )
    output.sort(key=lambda item: (item.start_time or datetime.min, item.window_id))
    return output


def _load_uuid_set(path: Path) -> set[str]:
    return {
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip()
    }


def _span_minutes(start: datetime | None, end: datetime | None) -> float | None:
    if start is None or end is None:
        return None
    seconds = max(0.0, (end - start).total_seconds())
    return seconds / 60.0


def _overlap_window_ids(start: datetime | None, end: datetime | None, windows: list[_Window]) -> list[str]:
    if start is None or end is None:
        return []
    output: list[str] = []
    for window in windows:
        if window.start_time is None or window.end_time is None:
            continue
        if start <= window.end_time and end >= window.start_time:
            output.append(window.window_id)
    return output


def _summarize_numeric(values: list[float]) -> dict[str, float | int | None]:
    if not values:
        return {"count": 0, "min": None, "median": None, "p90": None, "max": None}
    ordered = sorted(values)
    p90_idx = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * 0.9))))
    return {
        "count": len(ordered),
        "min": round(float(ordered[0]), 3),
        "median": round(float(median(ordered)), 3),
        "p90": round(float(ordered[p90_idx]), 3),
        "max": round(float(ordered[-1]), 3),
    }


def _classify_nonoverlap_root_cause(
    row: dict[str, Any],
    *,
    shared_with_confirmed: bool,
) -> str:
    if row["overlap_attempted_window_ids"]:
        return "gt_node_outside_confirmed_windows"
    if shared_with_confirmed:
        return "shared_gt_node_cross_window"
    span_minutes = float(row.get("span_minutes", 0.0) or 0.0)
    process_node_count = int(row.get("process_node_count", 0) or 0)
    boundary_node_count = int(row.get("boundary_node_count", 0) or 0)
    if span_minutes >= 120.0 or (span_minutes >= 60.0 and process_node_count >= 50):
        return "long_lived_root_glue"
    if span_minutes >= 30.0 and process_node_count <= 12 and boundary_node_count <= 2:
        return "wide_subject_alias_epoch"
    return "unknown"


def _render_markdown(
    summary: dict[str, Any],
    by_window: list[dict[str, Any]],
    nonoverlap: list[dict[str, Any]],
) -> str:
    lines = [
        "# THEIA GT task overlap summary",
        "",
        f"- host: {summary.get('host', '')}",
        f"- gt_time_offset_minutes_applied: {summary.get('gt_time_offset_minutes_applied', 0)}",
        f"- total_gt_positive_base_task_count: {summary.get('total_gt_positive_base_task_count', 0)}",
        f"- confirmed_window_overlap_unique_task_count: {summary.get('confirmed_window_overlap_unique_task_count', 0)}",
        f"- attempted_window_overlap_unique_task_count: {summary.get('attempted_window_overlap_unique_task_count', 0)}",
        f"- nonoverlap_task_count: {summary.get('nonoverlap_task_count', 0)}",
        "",
        "## Confirmed Windows",
        "",
    ]
    for row in by_window:
        lines.extend(
            [
                f"### {row.get('window_id', '')}",
                "",
                f"- status: {row.get('status', '')}",
                f"- report_section_id: {row.get('report_section_id', '')}",
                f"- report_section_title: {row.get('report_section_title', '')}",
                f"- overlap_task_count: {row.get('overlap_task_count', 0)}",
                f"- overlap_task_ids: {', '.join(row.get('overlap_task_ids', [])) or 'none'}",
                "",
            ]
        )
    lines.extend(["## Non-overlap Tasks", ""])
    for row in nonoverlap[:25]:
        lines.extend(
            [
                f"- {row.get('task_id', '')}: {row.get('nonoverlap_root_cause', '')}, "
                f"span={row.get('span_minutes', '')}, gt_nodes={row.get('gt_node_count', 0)}, "
                f"processes={row.get('process_node_count', 0)}",
            ]
        )
    return "\n".join(lines).strip() + "\n"


def main() -> None:
    args = _parse_args()
    artifacts_root = args.artifacts_root.resolve()
    output_dir = (args.output_dir or (artifacts_root / "diagnostics_theia_gt_task_overlap_20260625")).resolve()
    module3_dir = artifacts_root / "module3_evidence"
    task_index_path = module3_dir / "task_index.json"
    task_meta_path = module3_dir / "_module1_gt_selection_sidecars" / "task_meta_rich.json"

    task_index_rows = _load_json(task_index_path)
    task_meta_rows = _load_json(task_meta_path)
    malicious_uuid_set = _load_uuid_set(args.gt_node_path)
    windows = _load_gt_windows(
        args.gt_json,
        host=str(args.host).strip(),
        offset_minutes=int(args.gt_time_offset_minutes),
    )
    confirmed_windows = [row for row in windows if row.status == "confirmed"]
    attempted_windows = [row for row in windows if row.status != "confirmed"]

    meta_by_task = {
        str(row.get("task_id", "")).strip(): row
        for row in task_meta_rows
        if isinstance(row, dict) and str(row.get("task_id", "")).strip()
    }

    overlap_confirmed_counter: dict[str, list[str]] = defaultdict(list)
    overlap_attempted_counter: dict[str, list[str]] = defaultdict(list)
    rows: list[dict[str, Any]] = []
    gt_tasks_by_node: dict[str, set[str]] = defaultdict(set)
    confirmed_overlap_tasks: set[str] = set()

    for task_index_row in task_index_rows:
        if not isinstance(task_index_row, dict):
            continue
        task_id = str(task_index_row.get("task_id", "")).strip()
        if not task_id:
            continue
        meta_row = meta_by_task.get(task_id, {})
        process_ids = [str(item).strip() for item in meta_row.get("process_ids", []) if str(item).strip()]
        gt_process_ids = sorted(set(process_ids).intersection(malicious_uuid_set))
        for node_id in gt_process_ids:
            gt_tasks_by_node[node_id].add(task_id)

        first_timestamp = _parse_datetime(task_index_row.get("first_timestamp"))
        last_timestamp = _parse_datetime(task_index_row.get("last_timestamp"))
        confirmed_ids = _overlap_window_ids(first_timestamp, last_timestamp, confirmed_windows)
        attempted_ids = _overlap_window_ids(first_timestamp, last_timestamp, attempted_windows)
        for window_id in confirmed_ids:
            overlap_confirmed_counter[window_id].append(task_id)
        for window_id in attempted_ids:
            overlap_attempted_counter[window_id].append(task_id)
        if confirmed_ids:
            confirmed_overlap_tasks.add(task_id)
        rows.append(
            {
                "task_id": task_id,
                "task_root_id": str(meta_row.get("task_root_id", "")).strip(),
                "process_node_count": len(process_ids),
                "boundary_node_count": len(meta_row.get("boundary_node_ids", []) or []),
                "first_timestamp": _iso(first_timestamp),
                "last_timestamp": _iso(last_timestamp),
                "span_minutes": _span_minutes(first_timestamp, last_timestamp),
                "gt_node_count": len(gt_process_ids),
                "gt_node_ids": gt_process_ids,
                "overlap_confirmed_window_ids": confirmed_ids,
                "overlap_attempted_window_ids": attempted_ids,
                "nonoverlap_root_cause": "",
            }
        )

    for row in rows:
        if row["overlap_confirmed_window_ids"]:
            continue
        shared_with_confirmed = any(
            any(other_task_id in confirmed_overlap_tasks for other_task_id in gt_tasks_by_node.get(node_id, set()))
            for node_id in row["gt_node_ids"]
        )
        row["nonoverlap_root_cause"] = _classify_nonoverlap_root_cause(row, shared_with_confirmed=shared_with_confirmed)

    confirmed_overlap_unique = sorted(
        {task_id for task_ids in overlap_confirmed_counter.values() for task_id in task_ids}
    )
    attempted_overlap_unique = sorted(
        {task_id for task_ids in overlap_attempted_counter.values() for task_id in task_ids}
    )
    nonoverlap_rows = [row for row in rows if not row["overlap_confirmed_window_ids"]]

    by_window_rows: list[dict[str, Any]] = []
    for window in confirmed_windows + attempted_windows:
        task_ids = (
            overlap_confirmed_counter.get(window.window_id, [])
            if window.status == "confirmed"
            else overlap_attempted_counter.get(window.window_id, [])
        )
        by_window_rows.append(
            {
                "window_id": window.window_id,
                "status": window.status,
                "start_time": _iso(window.start_time),
                "end_time": _iso(window.end_time),
                "report_section_id": window.report_section_id,
                "report_section_title": window.report_section_title,
                "overlap_task_count": len(task_ids),
                "overlap_task_ids": sorted(task_ids),
            }
        )

    span_all = [float(value["span_minutes"]) for value in rows if value["span_minutes"] is not None]
    span_confirmed = [float(value["span_minutes"]) for value in rows if value["overlap_confirmed_window_ids"] and value["span_minutes"] is not None]
    span_nonoverlap = [float(value["span_minutes"]) for value in nonoverlap_rows if value["span_minutes"] is not None]

    summary = {
        "host": str(args.host).strip().upper(),
        "gt_json_path": str(args.gt_json.resolve()),
        "gt_node_path": str(args.gt_node_path),
        "artifacts_root": str(artifacts_root),
        "module3_task_index_path": str(task_index_path),
        "module3_task_meta_path": str(task_meta_path),
        "gt_time_offset_minutes_applied": int(args.gt_time_offset_minutes),
        "total_gt_positive_base_task_count": len(rows),
        "confirmed_window_count": len(confirmed_windows),
        "attempted_window_count": len(attempted_windows),
        "confirmed_window_overlap_unique_task_count": len(confirmed_overlap_unique),
        "attempted_window_overlap_unique_task_count": len(attempted_overlap_unique),
        "nonoverlap_task_count": len(nonoverlap_rows),
        "nonoverlap_root_cause_counts": dict(
            sorted(Counter(row["nonoverlap_root_cause"] for row in nonoverlap_rows).items())
        ),
        "window_overlap_counts_confirmed": {
            window_id: len(task_ids) for window_id, task_ids in sorted(overlap_confirmed_counter.items())
        },
        "window_overlap_counts_attempted": {
            window_id: len(task_ids) for window_id, task_ids in sorted(overlap_attempted_counter.items())
        },
    }

    span_stats = {
        "all_tasks_span_minutes": _summarize_numeric(span_all),
        "confirmed_overlap_tasks_span_minutes": _summarize_numeric(span_confirmed),
        "nonoverlap_tasks_span_minutes": _summarize_numeric(span_nonoverlap),
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    _write_json(output_dir / "theia_gt_task_window_overlap_summary.json", summary)
    _write_json(output_dir / "theia_gt_task_window_overlap_by_window.json", by_window_rows)
    _write_json(output_dir / "theia_gt_task_nonoverlap_autopsy.json", nonoverlap_rows)
    _write_json(output_dir / "theia_gt_task_span_stats.json", span_stats)
    (output_dir / "theia_gt_task_window_overlap_summary.md").write_text(
        _render_markdown(summary, by_window_rows, nonoverlap_rows),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
