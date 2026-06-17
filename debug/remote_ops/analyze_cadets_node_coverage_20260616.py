from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from typing import Any

_THIS_FILE = Path(__file__).resolve()
_THIS_DIR = _THIS_FILE.parent
_REPO_ROOT = _THIS_FILE.parents[2]
_SRC_ROOT = _REPO_ROOT / "src"
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from analyze_cadets_eventid_fix_20260615 import (  # noqa: E402
    _as_naive_utc,
    _load_confirmed_windows,
    _load_malicious_uuid_set,
    _load_selected_task_ids,
    _load_task_meta_by_id,
    _normalized_event_range,
    _parse_datetime,
    _ranges_overlap,
    _task_slug,
    _time_span_minutes,
    _write_json,
)
from apt_fusion.path_reason.log_stream import (  # noqa: E402
    _extract_event_with_aliases,
    _iter_lines,
    _iter_log_files,
)


def _load_task_records(artifacts_root: Path) -> dict[str, dict[str, Any]]:
    selected_task_ids = _load_selected_task_ids(artifacts_root)
    task_meta_by_id = _load_task_meta_by_id(artifacts_root)
    records: dict[str, dict[str, Any]] = {}
    for task_id in selected_task_ids:
        slug = _task_slug(task_id)
        normalized_events_path = artifacts_root / "module3_evidence" / "normalized_events" / f"{slug}.jsonl"
        task_meta = task_meta_by_id.get(task_id, {})
        task_process_ids = sorted(
            {
                str(value).strip()
                for value in task_meta.get("process_ids", []) or []
                if str(value).strip()
            }
        )
        start_time, end_time = _normalized_event_range(normalized_events_path)
        records[task_id] = {
            "task_id": task_id,
            "task_process_ids": task_process_ids,
            "start_time": start_time,
            "end_time": end_time,
            "time_span_minutes": _time_span_minutes(start_time, end_time),
        }
    return records


def _build_window_seed_specs(
    windows: list[Any],
    task_records: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    specs: dict[str, dict[str, Any]] = {}
    for window in windows:
        window_id = str(window.window_id)
        window_start = _as_naive_utc(window.start_time)
        window_end = _as_naive_utc(window.end_time)
        overlap_task_ids = [
            task_id
            for task_id, record in task_records.items()
            if _ranges_overlap(window_start, window_end, record.get("start_time"), record.get("end_time"))
        ]
        overlap_task_ids.sort()
        seed_process_ids: set[str] = set()
        max_task_time_span_minutes = 0.0
        for task_id in overlap_task_ids:
            record = task_records[task_id]
            seed_process_ids.update(record.get("task_process_ids", []))
            max_task_time_span_minutes = max(
                max_task_time_span_minutes,
                float(record.get("time_span_minutes", 0.0) or 0.0),
            )
        specs[window_id] = {
            "window_id": window_id,
            "window_start": window_start,
            "window_end": window_end,
            "overlap_task_ids": overlap_task_ids,
            "seed_process_ids": seed_process_ids,
            "max_task_time_span_minutes": max_task_time_span_minutes,
        }
    return specs


def _scan_onehop_objects(
    *,
    source_logs: Path,
    window_seed_specs: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    cfg = SimpleNamespace(dataset_family="tc3", host="cadets", source_logs=source_logs)
    specs: list[tuple[str, Any, Any, set[str]]] = []
    state_by_window: dict[str, dict[str, Any]] = {}
    for window_id, spec in window_seed_specs.items():
        start_time = spec.get("window_start")
        end_time = spec.get("window_end")
        seed_process_ids = set(spec.get("seed_process_ids", set()) or set())
        if start_time is None or end_time is None:
            continue
        specs.append((window_id, start_time, end_time, seed_process_ids))
        state_by_window[window_id] = {
            "seed_process_ids": seed_process_ids,
            "onehop_object_ids": set(),
            "seed_event_count": 0,
            "top_seed_actions": [],
            "_action_counter": Counter(),
            "object_type_counter": Counter(),
        }

    for log_file in _iter_log_files(source_logs, "cadets"):
        for line in _iter_lines(log_file):
            event = _extract_event_with_aliases(cfg, line, {})
            if event is None or not event.timestamp:
                continue
            timestamp = _parse_datetime(event.timestamp)
            subject_uuid = str(event.subject_uuid).strip()
            object_uuid = str(event.object_uuid).strip()
            object_type = str(event.object_type_hint or "").strip().lower()
            if timestamp is None or not subject_uuid:
                continue
            matched_window_ids = [
                window_id
                for window_id, start_time, end_time, seed_process_ids in specs
                if start_time <= timestamp <= end_time and subject_uuid in seed_process_ids
            ]
            if not matched_window_ids:
                continue
            for window_id in matched_window_ids:
                state = state_by_window[window_id]
                state["seed_event_count"] = int(state.get("seed_event_count", 0) or 0) + 1
                state["_action_counter"][str(event.action or "").strip() or "OTHER"] += 1
                if object_uuid and object_type != "process":
                    state["onehop_object_ids"].add(object_uuid)
                    state["object_type_counter"][object_type or "unknown"] += 1

    for state in state_by_window.values():
        action_counter = state.pop("_action_counter", Counter())
        object_type_counter = state.pop("object_type_counter", Counter())
        state["top_seed_actions"] = [
            {"action": action, "count": count}
            for action, count in action_counter.most_common(12)
        ]
        state["onehop_object_type_counts"] = {
            key: int(value)
            for key, value in sorted(object_type_counter.items())
        }
    return state_by_window


def _row_for_window(
    window: Any,
    seed_spec: dict[str, Any],
    onehop_state: dict[str, Any],
    malicious_uuids: set[str],
) -> dict[str, Any]:
    window_id = str(window.window_id)
    seed_process_ids = set(seed_spec.get("seed_process_ids", set()) or set())
    onehop_object_ids = set(onehop_state.get("onehop_object_ids", set()) or set())
    hit_seed_process_ids = sorted(seed_process_ids.intersection(malicious_uuids))
    hit_onehop_object_ids = sorted(onehop_object_ids.intersection(malicious_uuids))
    hit_union_ids = sorted((seed_process_ids | onehop_object_ids).intersection(malicious_uuids))
    window_start = _as_naive_utc(window.start_time)
    window_end = _as_naive_utc(window.end_time)
    gt_tactics = sorted(
        {
            str(value).strip()
            for value in getattr(window, "confirmed_tactics", []) or []
            if str(value).strip()
        }
    )
    malicious_total = len(malicious_uuids)
    return {
        "window_id": window_id,
        "window_start": window_start.isoformat() if window_start else "",
        "window_end": window_end.isoformat() if window_end else "",
        "window_span_minutes": _time_span_minutes(window_start, window_end),
        "gt_tactics": gt_tactics,
        "overlap_task_ids": list(seed_spec.get("overlap_task_ids", []) or []),
        "overlap_task_count": len(seed_spec.get("overlap_task_ids", []) or []),
        "seed_process_count": len(seed_process_ids),
        "seed_event_count": int(onehop_state.get("seed_event_count", 0) or 0),
        "onehop_object_count": len(onehop_object_ids),
        "onehop_object_type_counts": dict(onehop_state.get("onehop_object_type_counts", {}) or {}),
        "malicious_list_total": malicious_total,
        "hit_seed_process_count": len(hit_seed_process_ids),
        "hit_onehop_object_count": len(hit_onehop_object_ids),
        "hit_union_count": len(hit_union_ids),
        "hit_seed_process_ids": hit_seed_process_ids,
        "hit_onehop_object_ids": hit_onehop_object_ids,
        "hit_union_ids": hit_union_ids,
        "hit_seed_process_rate_vs_full_gt": float(len(hit_seed_process_ids) / malicious_total) if malicious_total else 0.0,
        "hit_onehop_object_rate_vs_full_gt": float(len(hit_onehop_object_ids) / malicious_total) if malicious_total else 0.0,
        "hit_union_rate_vs_full_gt": float(len(hit_union_ids) / malicious_total) if malicious_total else 0.0,
        "hit_seed_process_ids_sample": hit_seed_process_ids[:50],
        "hit_onehop_object_ids_sample": hit_onehop_object_ids[:50],
        "hit_union_ids_sample": hit_union_ids[:50],
        "top_seed_actions": list(onehop_state.get("top_seed_actions", []) or []),
        "max_overlap_task_time_span_minutes": float(seed_spec.get("max_task_time_span_minutes", 0.0) or 0.0),
    }


def _render_summary(rows: list[dict[str, Any]], overall: dict[str, Any]) -> str:
    lines = [
        "# CADETS Task-Graph Seed + 1-Hop Object ID Hit Summary",
        "",
        f"- confirmed window count: {int(overall.get('confirmed_window_count', 0) or 0)}",
        f"- malicious list total: {int(overall.get('malicious_list_total', 0) or 0)}",
        f"- macro average seed-process hit rate vs full gt: {float(overall.get('macro_average_seed_process_hit_rate_vs_full_gt', 0.0) or 0.0):.6f}",
        f"- macro average onehop-object hit rate vs full gt: {float(overall.get('macro_average_onehop_object_hit_rate_vs_full_gt', 0.0) or 0.0):.6f}",
        f"- macro average union hit rate vs full gt: {float(overall.get('macro_average_union_hit_rate_vs_full_gt', 0.0) or 0.0):.6f}",
        f"- overall union hit count: {int(overall.get('overall_union_hit_count', 0) or 0)}",
        f"- overall union hit rate vs full gt: {float(overall.get('overall_union_hit_rate_vs_full_gt', 0.0) or 0.0):.6f}",
        "",
    ]
    for row in rows:
        lines.extend(
            [
                f"## {row['window_id']}",
                f"- overlap_task_ids: {', '.join(row.get('overlap_task_ids', [])) or 'none'}",
                f"- seed_process_count: {int(row.get('seed_process_count', 0) or 0)}",
                f"- seed_event_count: {int(row.get('seed_event_count', 0) or 0)}",
                f"- onehop_object_count: {int(row.get('onehop_object_count', 0) or 0)}",
                f"- hit_seed_process_count: {int(row.get('hit_seed_process_count', 0) or 0)}",
                f"- hit_onehop_object_count: {int(row.get('hit_onehop_object_count', 0) or 0)}",
                f"- hit_union_count: {int(row.get('hit_union_count', 0) or 0)}",
                f"- hit_union_rate_vs_full_gt: {float(row.get('hit_union_rate_vs_full_gt', 0.0) or 0.0):.6f}",
                f"- onehop_object_type_counts: {json.dumps(row.get('onehop_object_type_counts', {}), ensure_ascii=False)}",
                "",
            ]
        )
    return "\n".join(lines).strip() + "\n"


def run_cadets_node_coverage_diagnostics(
    *,
    artifacts_root: Path,
    gt_node_path: Path,
    source_logs: Path,
    gt_json_path: Path,
) -> dict[str, str]:
    artifacts_root = Path(artifacts_root)
    gt_node_path = Path(gt_node_path)
    source_logs = Path(source_logs)
    gt_json_path = Path(gt_json_path)
    output_dir = artifacts_root / "cadets_taskgraph_onehop_coverage_20260616"
    output_dir.mkdir(parents=True, exist_ok=True)

    windows, offset_info = _load_confirmed_windows(gt_json_path)
    malicious_uuids = _load_malicious_uuid_set(gt_node_path)
    task_records = _load_task_records(artifacts_root)
    window_seed_specs = _build_window_seed_specs(windows, task_records)
    onehop_by_window = _scan_onehop_objects(
        source_logs=source_logs,
        window_seed_specs=window_seed_specs,
    )
    rows = [
        _row_for_window(
            window,
            window_seed_specs.get(str(window.window_id), {}),
            onehop_by_window.get(str(window.window_id), {}),
            malicious_uuids,
        )
        for window in windows
    ]

    overall_union_hits: set[str] = set()
    for row in rows:
        overall_union_hits.update(row.get("hit_union_ids", []))
    overall = {
        "confirmed_window_count": len(rows),
        "malicious_list_total": len(malicious_uuids),
        "macro_average_seed_process_hit_rate_vs_full_gt": (
            float(sum(float(row["hit_seed_process_rate_vs_full_gt"]) for row in rows) / len(rows)) if rows else 0.0
        ),
        "macro_average_onehop_object_hit_rate_vs_full_gt": (
            float(sum(float(row["hit_onehop_object_rate_vs_full_gt"]) for row in rows) / len(rows)) if rows else 0.0
        ),
        "macro_average_union_hit_rate_vs_full_gt": (
            float(sum(float(row["hit_union_rate_vs_full_gt"]) for row in rows) / len(rows)) if rows else 0.0
        ),
        "overall_union_hit_count": len(overall_union_hits),
        "overall_union_hit_rate_vs_full_gt": float(len(overall_union_hits) / len(malicious_uuids)) if malicious_uuids else 0.0,
    }

    by_window_path = output_dir / "taskgraph_seed_onehop_hits_by_window.json"
    overall_path = output_dir / "taskgraph_seed_onehop_hits_overall.json"
    summary_path = output_dir / "hit_summary.md"
    diagnostics_path = output_dir / "diagnostics_summary.json"

    _write_json(by_window_path, rows)
    _write_json(overall_path, overall)
    summary_path.write_text(_render_summary(rows, overall), encoding="utf-8")
    outputs = {
        "taskgraph_seed_onehop_hits_by_window": str(by_window_path),
        "taskgraph_seed_onehop_hits_overall": str(overall_path),
        "hit_summary": str(summary_path),
    }
    _write_json(
        diagnostics_path,
        {
            "artifacts_root": str(artifacts_root),
            "gt_node_path": str(gt_node_path),
            "source_logs": str(source_logs),
            "gt_json_path": str(gt_json_path),
            "analysis_mode": "task_graph_processes_plus_raw_onehop_object_ids_vs_full_gt_list",
            "gt_time_alignment": offset_info,
            "outputs": outputs,
            "overall": overall,
        },
    )
    outputs["diagnostics_summary"] = str(diagnostics_path)
    return outputs


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 4:
        raise SystemExit(
            "Usage: analyze_cadets_node_coverage_20260616.py <artifacts_root> <gt_node_path> <source_logs> <gt_json_path>"
        )
    outputs = run_cadets_node_coverage_diagnostics(
        artifacts_root=Path(argv[0]),
        gt_node_path=Path(argv[1]),
        source_logs=Path(argv[2]),
        gt_json_path=Path(argv[3]),
    )
    print(json.dumps(outputs, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
