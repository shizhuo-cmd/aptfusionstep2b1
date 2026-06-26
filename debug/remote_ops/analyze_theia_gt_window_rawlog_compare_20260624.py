from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

_THIS_FILE = Path(__file__).resolve()
_REPO_ROOT = _THIS_FILE.parents[2]
_SRC_ROOT = _REPO_ROOT / "src"
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from apt_fusion.evaluation.path_reason_eval import load_gt_reference  # noqa: E402
from apt_fusion.path_reason.log_stream import _extract_event, _iter_lines, _iter_log_files  # noqa: E402

DEFAULT_OFFSETS = (0, 240)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare THEIA raw-log GT node hits for offset 0 and +240.")
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
    parser.add_argument(
        "--source-logs",
        type=Path,
        default=Path("/root/autodl-tmp/data/theia"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_REPO_ROOT / "debug" / "remote_ops" / "out" / "theia_gt_window_rawlog_compare_20260624",
    )
    return parser.parse_args()


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


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _load_uuid_set(path: Path) -> set[str]:
    return {
        text
        for text in (line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines())
        if text
    }


def _raw_window_map(gt_json_path: Path) -> dict[str, dict[str, Any]]:
    payload = json.loads(gt_json_path.read_text(encoding="utf-8"))
    output: dict[str, dict[str, Any]] = {}
    for item in payload.get("windows", []) if isinstance(payload, dict) else []:
        if isinstance(item, dict):
            window_id = str(item.get("window_id", "")).strip()
            if window_id:
                output[window_id] = item
    return output


def _top_actions(counter: Counter[str], limit: int = 12) -> list[dict[str, Any]]:
    return [{"action": action, "count": int(count)} for action, count in counter.most_common(limit)]


def _load_windows(gt_json_path: Path) -> list[Any]:
    windows, _, _ = load_gt_reference(gt_json_path, host_filter="THEIA")
    windows.sort(key=lambda item: (_parse_datetime(item.start_time) or datetime.min, str(item.window_id)))
    return windows


def _scan_offsets(
    *,
    source_logs: Path,
    windows: list[Any],
    malicious_uuids: set[str],
    offsets: tuple[int, ...],
) -> dict[int, dict[str, Any]]:
    cfg = SimpleNamespace(dataset_family="tc3", host="theia", source_logs=source_logs)
    specs: list[tuple[int, str, datetime, datetime]] = []
    per_offset_state: dict[int, dict[str, dict[str, Any]]] = {}
    for offset in offsets:
        delta = timedelta(minutes=int(offset))
        per_offset_state[offset] = {}
        for window in windows:
            start = _parse_datetime(window.start_time)
            end = _parse_datetime(window.end_time)
            if start is None or end is None:
                continue
            per_offset_state[offset][str(window.window_id)] = {
                "subject_hit_ids": set(),
                "any_role_hit_ids": set(),
                "subject_event_count": 0,
                "any_role_event_count": 0,
                "subject_action_counter": Counter(),
                "any_role_action_counter": Counter(),
            }
            specs.append((offset, str(window.window_id), start + delta, end + delta))

    for log_file in _iter_log_files(source_logs, "theia"):
        for line in _iter_lines(log_file):
            event = _extract_event(cfg, line)
            if event is None or not event.timestamp:
                continue
            timestamp = _parse_datetime(event.timestamp)
            if timestamp is None:
                continue
            subject_uuid = str(event.subject_uuid or "").strip()
            object_uuid = str(event.object_uuid or "").strip()
            action = str(event.action or "").strip() or "OTHER"
            for offset, window_id, start, end in specs:
                if not (start <= timestamp <= end):
                    continue
                state = per_offset_state[offset][window_id]
                subject_hit = bool(subject_uuid) and subject_uuid in malicious_uuids
                object_hit = bool(object_uuid) and object_uuid in malicious_uuids
                if subject_hit:
                    state["subject_hit_ids"].add(subject_uuid)
                    state["subject_event_count"] += 1
                    state["subject_action_counter"][action] += 1
                if subject_hit or object_hit:
                    if subject_hit:
                        state["any_role_hit_ids"].add(subject_uuid)
                    if object_hit:
                        state["any_role_hit_ids"].add(object_uuid)
                    state["any_role_event_count"] += 1
                    state["any_role_action_counter"][action] += 1

    results: dict[int, dict[str, Any]] = {}
    for offset in offsets:
        rows: list[dict[str, Any]] = []
        for window in windows:
            window_id = str(window.window_id)
            base_start = _parse_datetime(window.start_time)
            base_end = _parse_datetime(window.end_time)
            state = per_offset_state[offset][window_id]
            rows.append(
                {
                    "window_id": window_id,
                    "status": str(window.status),
                    "confirmed_tactics": list(getattr(window, "confirmed_tactics", []) or []),
                    "attempted_tactics": list(getattr(window, "attempted_tactics", []) or []),
                    "base_start_time": base_start.isoformat() if base_start else "",
                    "base_end_time": base_end.isoformat() if base_end else "",
                    "applied_offset_minutes": int(offset),
                    "effective_start_time": (base_start + timedelta(minutes=int(offset))).isoformat() if base_start else "",
                    "effective_end_time": (base_end + timedelta(minutes=int(offset))).isoformat() if base_end else "",
                    "gt_uuid_total": len(malicious_uuids),
                    "subject_hit_ids": sorted(state["subject_hit_ids"]),
                    "subject_hit_count": len(state["subject_hit_ids"]),
                    "subject_hit_event_count": int(state["subject_event_count"]),
                    "any_role_hit_ids": sorted(state["any_role_hit_ids"]),
                    "any_role_hit_count": len(state["any_role_hit_ids"]),
                    "any_role_hit_event_count": int(state["any_role_event_count"]),
                    "object_side_only_ids": sorted(set(state["any_role_hit_ids"]).difference(state["subject_hit_ids"])),
                    "top_actions_subject": _top_actions(state["subject_action_counter"]),
                    "top_actions_any_role": _top_actions(state["any_role_action_counter"]),
                }
            )
        results[offset] = {"host": "THEIA", "applied_offset_minutes": int(offset), "windows": rows}
    return results


def _render_markdown(compare_payload: dict[str, Any]) -> str:
    lines = [
        "# THEIA raw-log GT window hit comparison",
        "",
        f"- offsets: {', '.join(str(value) for value in DEFAULT_OFFSETS)}",
        "",
    ]
    windows = compare_payload.get("windows", {})
    for window_id in sorted(windows):
        offset0 = windows[window_id]["offset_0"]
        offset240 = windows[window_id]["offset_240"]
        lines.extend(
            [
                f"## {window_id}",
                "",
                f"- gt tactics: {', '.join(offset0.get('confirmed_tactics', [])) or 'none'}",
                f"- base window: `{offset0.get('base_start_time', '')}` -> `{offset0.get('base_end_time', '')}`",
                f"- offset 0 subject hits: {offset0.get('subject_hit_count', 0)}",
                f"- offset 240 subject hits: {offset240.get('subject_hit_count', 0)}",
                f"- offset 0 any-role hits: {offset0.get('any_role_hit_count', 0)}",
                f"- offset 240 any-role hits: {offset240.get('any_role_hit_count', 0)}",
                "",
            ]
        )
    return "\n".join(lines).strip() + "\n"


def main() -> None:
    args = _parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    malicious_uuids = _load_uuid_set(args.gt_node_path)
    windows = _load_windows(args.gt_json)
    raw_map = _raw_window_map(args.gt_json)
    results = _scan_offsets(
        source_logs=args.source_logs,
        windows=windows,
        malicious_uuids=malicious_uuids,
        offsets=DEFAULT_OFFSETS,
    )

    compare_payload = {"host": "THEIA", "windows": {}}
    for window in windows:
        window_id = str(window.window_id)
        compare_payload["windows"][window_id] = {
            "offset_0": next(item for item in results[0]["windows"] if item["window_id"] == window_id),
            "offset_240": next(item for item in results[240]["windows"] if item["window_id"] == window_id),
            "report_section_id": str(raw_map.get(window_id, {}).get("report_section_id", "")).strip(),
            "report_section_title": str(raw_map.get(window_id, {}).get("report_section_title", "")).strip(),
        }

    _write_json(args.output_dir / "window_hits_offset_0.json", results[0])
    _write_json(args.output_dir / "window_hits_offset_240.json", results[240])
    _write_json(args.output_dir / "window_hits_compare.json", compare_payload)
    (args.output_dir / "window_hits_compare.md").write_text(_render_markdown(compare_payload), encoding="utf-8")
    (args.output_dir / "provenance_summary.json").write_text(
        json.dumps(
            {
                "gt_json_path": str(args.gt_json),
                "gt_node_path": str(args.gt_node_path),
                "source_logs": str(args.source_logs),
                "offsets": list(DEFAULT_OFFSETS),
                "window_count": len(windows),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(json.dumps({"output_dir": str(args.output_dir), "window_count": len(windows)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
