from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_THIS_FILE = Path(__file__).resolve()
_REPO_ROOT = _THIS_FILE.parents[2]
_SRC_ROOT = _REPO_ROOT / "src"
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from apt_fusion.path_reason.log_stream import DATUM_KEY, EVENT_KEY, UUID_KEY, _extract_json_fragment, _iter_lines, _iter_log_files


@dataclass
class _KeyStats:
    parent_uuid: str
    tgid: str
    normalized_path: str
    uuid_set: set[str] = field(default_factory=set)
    path_variants: set[str] = field(default_factory=set)
    raw_files: set[str] = field(default_factory=set)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    task_ids_hit: set[str] = field(default_factory=set)
    window_ids_hit: set[str] = field(default_factory=set)
    nonoverlap_task_ids_hit: set[str] = field(default_factory=set)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze THEIA subject alias over-merge risk by (parent, tgid, path) key.")
    parser.add_argument("--artifacts-root", type=Path, required=True)
    parser.add_argument(
        "--source-logs",
        type=Path,
        default=Path("/root/autodl-tmp/data/theia/logs"),
    )
    parser.add_argument(
        "--gt-node-path",
        type=Path,
        default=Path("/root/autodl-tmp/data/theia/theia_ground_truth.txt"),
    )
    parser.add_argument(
        "--overlap-output-dir",
        type=Path,
        default=None,
        help="Directory containing theia_gt_task_window_overlap_*.json outputs. Defaults to the sibling step0 output dir.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_REPO_ROOT / "debug" / "remote_ops" / "out" / "theia_alias_epoch_diag_20260625",
    )
    return parser.parse_args()


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _parse_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _to_seconds(value: object) -> float | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        raw = float(value)
    else:
        text = str(value).strip()
        if not text:
            return None
        try:
            raw = float(text)
        except ValueError:
            normalized = text.replace("Z", "+00:00")
            try:
                dt = datetime.fromisoformat(normalized)
            except ValueError:
                return None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
    digits = len(str(int(abs(raw)))) if raw != 0 else 1
    if digits >= 18:
        return raw / 1e9
    if digits >= 15:
        return raw / 1e6
    if digits >= 12:
        return raw / 1e3
    return raw


def _event_datetime(event: dict[str, Any]) -> datetime | None:
    raw = (
        event.get("timestampNanos")
        or event.get("timestampMicros")
        or event.get("timestampMillis")
        or event.get("timestamp")
    )
    seconds = _to_seconds(raw)
    if seconds is None:
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(tzinfo=None)
    except (OverflowError, OSError, ValueError):
        return None


def _unwrap_uuid_field(payload: Any) -> str:
    if isinstance(payload, dict):
        return str(payload.get(UUID_KEY) or payload.get("uuid") or "").strip()
    return str(payload or "").strip()


def _normalize_subject_path(path: str) -> str:
    text = str(path or "").strip()
    if text.endswith(" (deleted)"):
        text = text[: -len(" (deleted)")].rstrip()
    return text


def _relative_log_name(path: Path, source_logs: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(source_logs.resolve().parent))
    except ValueError:
        return str(resolved)


def _load_uuid_set(path: Path) -> set[str]:
    return {
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip()
    }


def _build_task_maps(overlap_output_dir: Path) -> tuple[dict[str, dict[str, Any]], dict[str, set[str]], set[str]]:
    nonoverlap_rows = _load_json(overlap_output_dir / "theia_gt_task_nonoverlap_autopsy.json")
    by_window_rows = _load_json(overlap_output_dir / "theia_gt_task_window_overlap_by_window.json")
    task_rows: dict[str, dict[str, Any]] = {}
    task_to_windows: dict[str, set[str]] = defaultdict(set)
    nonoverlap_task_ids: set[str] = set()

    for row in nonoverlap_rows:
        if not isinstance(row, dict):
            continue
        task_id = str(row.get("task_id", "")).strip()
        if not task_id:
            continue
        task_rows[task_id] = row
        nonoverlap_task_ids.add(task_id)

    for row in by_window_rows:
        if not isinstance(row, dict):
            continue
        window_id = str(row.get("window_id", "")).strip()
        for task_id in row.get("overlap_task_ids", []) or []:
            task_text = str(task_id).strip()
            if task_text:
                task_to_windows[task_text].add(window_id)
    return task_rows, task_to_windows, nonoverlap_task_ids


def _load_task_processes(artifacts_root: Path) -> dict[str, list[str]]:
    task_meta_path = artifacts_root / "module3_evidence" / "_module1_gt_selection_sidecars" / "task_meta_rich.json"
    rows = _load_json(task_meta_path)
    return {
        str(row.get("task_id", "")).strip(): [str(item).strip() for item in row.get("process_ids", []) if str(item).strip()]
        for row in rows
        if isinstance(row, dict) and str(row.get("task_id", "")).strip()
    }


def _scan_theia_subject_aliases(
    *,
    source_logs: Path,
    task_processes: dict[str, list[str]],
    task_to_windows: dict[str, set[str]],
    nonoverlap_task_ids: set[str],
) -> dict[str, _KeyStats]:
    process_to_tasks: dict[str, set[str]] = defaultdict(set)
    for task_id, process_ids in task_processes.items():
        for process_id in process_ids:
            process_to_tasks[process_id].add(task_id)

    key_stats: dict[str, _KeyStats] = {}
    uuid_to_key: dict[str, str] = {}
    uuid_event_first: dict[str, datetime] = {}
    uuid_event_last: dict[str, datetime] = {}
    uuid_event_files: dict[str, set[str]] = defaultdict(set)

    for log_file in _iter_log_files(source_logs, "theia"):
        rel_name = _relative_log_name(log_file, source_logs)
        for line in _iter_lines(log_file):
            obj = _extract_json_fragment(line)
            if obj is None:
                continue
            datum = obj.get(DATUM_KEY)
            if not isinstance(datum, dict):
                continue

            subject_payload = datum.get("com.bbn.tc.schema.avro.cdm18.Subject")
            if isinstance(subject_payload, dict):
                subject_uuid = str(subject_payload.get("uuid") or subject_payload.get(UUID_KEY) or "").strip()
                if subject_uuid:
                    parent_uuid = _unwrap_uuid_field(subject_payload.get("parentSubject")) or "Unknow"
                    properties = subject_payload.get("properties")
                    prop_map = properties.get("map", {}) if isinstance(properties, dict) else {}
                    if not isinstance(prop_map, dict):
                        prop_map = {}
                    tgid = str(prop_map.get("tgid", "Unknown"))
                    subpath = str(prop_map.get("path", "Unknown"))
                    normalized_path = _normalize_subject_path(subpath or "Unknown") or "Unknown"
                    key = str((parent_uuid, tgid, normalized_path))
                    uuid_to_key[subject_uuid] = key
                    stats = key_stats.get(key)
                    if stats is None:
                        stats = _KeyStats(parent_uuid=parent_uuid, tgid=tgid, normalized_path=normalized_path)
                        key_stats[key] = stats
                    stats.uuid_set.add(subject_uuid)
                    stats.path_variants.add(subpath or "Unknown")
                    stats.raw_files.add(rel_name)

            event_payload = datum.get(EVENT_KEY)
            if isinstance(event_payload, dict):
                event_dt = _event_datetime(event_payload)
                subject_uuid = _unwrap_uuid_field(event_payload.get("subject"))
                if subject_uuid and event_dt is not None:
                    if subject_uuid not in uuid_event_first or event_dt < uuid_event_first[subject_uuid]:
                        uuid_event_first[subject_uuid] = event_dt
                    if subject_uuid not in uuid_event_last or event_dt > uuid_event_last[subject_uuid]:
                        uuid_event_last[subject_uuid] = event_dt
                    uuid_event_files[subject_uuid].add(rel_name)

    for subject_uuid, key in uuid_to_key.items():
        stats = key_stats[key]
        first_dt = uuid_event_first.get(subject_uuid)
        last_dt = uuid_event_last.get(subject_uuid)
        if first_dt is not None and (stats.first_seen is None or first_dt < stats.first_seen):
            stats.first_seen = first_dt
        if last_dt is not None and (stats.last_seen is None or last_dt > stats.last_seen):
            stats.last_seen = last_dt
        stats.raw_files.update(uuid_event_files.get(subject_uuid, set()))
        for task_id in process_to_tasks.get(subject_uuid, set()):
            stats.task_ids_hit.add(task_id)
            stats.window_ids_hit.update(task_to_windows.get(task_id, set()))
            if task_id in nonoverlap_task_ids:
                stats.nonoverlap_task_ids_hit.add(task_id)

    return key_stats


def _span_minutes(first_seen: datetime | None, last_seen: datetime | None) -> float:
    if first_seen is None or last_seen is None:
        return 0.0
    return max(0.0, (last_seen - first_seen).total_seconds() / 60.0)


def _wide_key_reasons(stats: _KeyStats) -> list[str]:
    reasons: list[str] = []
    span_minutes = _span_minutes(stats.first_seen, stats.last_seen)
    uuid_count = len(stats.uuid_set)
    file_count = len(stats.raw_files)
    nonoverlap_task_hits = len(stats.nonoverlap_task_ids_hit)
    if uuid_count >= 8 and span_minutes >= 30.0:
        reasons.append("uuid_ge_8_and_span_ge_30m")
    if uuid_count >= 5 and file_count >= 2 and span_minutes >= 20.0:
        reasons.append("uuid_ge_5_file_ge_2_span_ge_20m")
    if nonoverlap_task_hits >= 3:
        reasons.append("hits_ge_3_nonoverlap_tasks")
    return reasons


def _key_sort_tuple(item: tuple[str, _KeyStats]) -> tuple[int, int, float, int, str]:
    key, stats = item
    return (
        len(stats.nonoverlap_task_ids_hit),
        len(stats.task_ids_hit),
        _span_minutes(stats.first_seen, stats.last_seen),
        len(stats.uuid_set),
        key,
    )


def _render_markdown(summary: dict[str, Any], top_wide_keys: list[dict[str, Any]]) -> str:
    lines = [
        "# THEIA alias epoch diagnostics",
        "",
        f"- nonoverlap_task_count: {summary.get('nonoverlap_task_count', 0)}",
        f"- wide_key_count: {summary.get('wide_key_count', 0)}",
        f"- nonoverlap_task_count_hit_by_wide_key: {summary.get('nonoverlap_task_count_hit_by_wide_key', 0)}",
        f"- nonoverlap_task_fraction_hit_by_wide_key: {summary.get('nonoverlap_task_fraction_hit_by_wide_key', 0.0)}",
        f"- top20_wide_key_task_coverage_count: {summary.get('top20_wide_key_task_coverage_count', 0)}",
        f"- top20_wide_key_task_coverage_fraction: {summary.get('top20_wide_key_task_coverage_fraction', 0.0)}",
        f"- step3b_recommended: {summary.get('step3b_recommended', False)}",
        "",
        "## Top Wide Keys",
        "",
    ]
    for row in top_wide_keys[:20]:
        lines.extend(
            [
                f"- key={row.get('key', '')}",
                f"  uuid_count={row.get('uuid_count', 0)}, span_minutes={row.get('span_minutes', 0.0)}, "
                f"file_count={row.get('file_count', 0)}, nonoverlap_task_hit_count={row.get('nonoverlap_task_hit_count', 0)}, "
                f"reasons={', '.join(row.get('wide_key_reasons', [])) or 'none'}",
            ]
        )
    return "\n".join(lines).strip() + "\n"


def main() -> None:
    args = _parse_args()
    artifacts_root = args.artifacts_root.resolve()
    overlap_output_dir = (
        args.overlap_output_dir.resolve()
        if args.overlap_output_dir is not None
        else (_REPO_ROOT / "debug" / "remote_ops" / "out" / "theia_gt_task_overlap_step12_20260625").resolve()
    )
    task_rows, task_to_windows, nonoverlap_task_ids = _build_task_maps(overlap_output_dir)
    task_processes = _load_task_processes(artifacts_root)
    key_stats = _scan_theia_subject_aliases(
        source_logs=args.source_logs,
        task_processes=task_processes,
        task_to_windows=task_to_windows,
        nonoverlap_task_ids=nonoverlap_task_ids,
    )

    wide_key_rows: list[dict[str, Any]] = []
    nonoverlap_tasks_hit_by_wide_keys: set[str] = set()
    for key, stats in sorted(key_stats.items(), key=_key_sort_tuple, reverse=True):
        reasons = _wide_key_reasons(stats)
        if not reasons:
            continue
        nonoverlap_tasks_hit_by_wide_keys.update(stats.nonoverlap_task_ids_hit)
        wide_key_rows.append(
            {
                "key": key,
                "parent_uuid": stats.parent_uuid,
                "tgid": stats.tgid,
                "normalized_path": stats.normalized_path,
                "uuid_count": len(stats.uuid_set),
                "uuid_examples": sorted(stats.uuid_set)[:12],
                "span_minutes": round(_span_minutes(stats.first_seen, stats.last_seen), 3),
                "first_seen": stats.first_seen.isoformat() if stats.first_seen else "",
                "last_seen": stats.last_seen.isoformat() if stats.last_seen else "",
                "file_count": len(stats.raw_files),
                "file_examples": sorted(stats.raw_files)[:8],
                "path_variants": sorted(stats.path_variants)[:12],
                "task_hit_count": len(stats.task_ids_hit),
                "task_ids_hit": sorted(stats.task_ids_hit),
                "window_hit_count": len(stats.window_ids_hit),
                "window_ids_hit": sorted(stats.window_ids_hit),
                "nonoverlap_task_hit_count": len(stats.nonoverlap_task_ids_hit),
                "nonoverlap_task_ids_hit": sorted(stats.nonoverlap_task_ids_hit),
                "wide_key_reasons": reasons,
            }
        )

    top20_task_coverage: set[str] = set()
    for row in wide_key_rows[:20]:
        top20_task_coverage.update(row["nonoverlap_task_ids_hit"])

    nonoverlap_task_count = len(nonoverlap_task_ids)
    hit_fraction = (
        float(len(nonoverlap_tasks_hit_by_wide_keys)) / float(nonoverlap_task_count)
        if nonoverlap_task_count
        else 0.0
    )
    top20_fraction = (
        float(len(top20_task_coverage)) / float(nonoverlap_task_count)
        if nonoverlap_task_count
        else 0.0
    )
    step3b_recommended = bool(hit_fraction >= 0.20 or top20_fraction >= 0.25)

    cause_counter: Counter[str] = Counter()
    for task_id in nonoverlap_tasks_hit_by_wide_keys:
        cause = str(task_rows.get(task_id, {}).get("nonoverlap_root_cause", "")).strip() or "unknown"
        cause_counter[cause] += 1

    summary = {
        "host": "THEIA",
        "artifacts_root": str(artifacts_root),
        "source_logs": str(args.source_logs),
        "gt_node_path": str(args.gt_node_path),
        "overlap_output_dir": str(overlap_output_dir),
        "nonoverlap_task_count": nonoverlap_task_count,
        "wide_key_count": len(wide_key_rows),
        "nonoverlap_task_count_hit_by_wide_key": len(nonoverlap_tasks_hit_by_wide_keys),
        "nonoverlap_task_fraction_hit_by_wide_key": round(hit_fraction, 4),
        "top20_wide_key_task_coverage_count": len(top20_task_coverage),
        "top20_wide_key_task_coverage_fraction": round(top20_fraction, 4),
        "step3b_recommended": step3b_recommended,
        "step3b_thresholds": {
            "nonoverlap_task_fraction_hit_by_wide_key_ge": 0.20,
            "top20_wide_key_task_coverage_fraction_ge": 0.25,
        },
        "wide_key_definition": {
            "uuid_ge_8_and_span_ge_30m": True,
            "uuid_ge_5_file_ge_2_span_ge_20m": True,
            "hits_ge_3_nonoverlap_tasks": True,
        },
        "covered_nonoverlap_root_cause_counts": dict(sorted(cause_counter.items())),
    }

    diagnostics = {
        "summary": summary,
        "top_wide_keys": wide_key_rows[:100],
        "all_wide_key_count": len(wide_key_rows),
    }

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_json(output_dir / "theia_alias_epoch_diagnostics.json", diagnostics)
    _write_json(output_dir / "theia_alias_epoch_wide_keys_top100.json", wide_key_rows[:100])
    (output_dir / "theia_alias_epoch_summary.md").write_text(
        _render_markdown(summary, wide_key_rows[:20]),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
