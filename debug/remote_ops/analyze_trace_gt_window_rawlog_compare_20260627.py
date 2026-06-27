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

DEFAULT_OFFSET = 240
DEFAULT_WINDOW_IDS = (
    "TRACE_20180410_0946_1109_01",
    "TRACE_20180410_1228_1230_02",
    "TRACE_20180412_1336_1336_03",
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare TRACE raw-log GT node hits for zero-tactic windows with +240 offset."
    )
    parser.add_argument(
        "--gt-json",
        type=Path,
        default=_REPO_ROOT / "docs" / "darpa_attack_eval_ground_truth_e3_report_enriched_20260618.json",
    )
    parser.add_argument(
        "--gt-node-path",
        type=Path,
        default=Path("/root/autodl-tmp/data/trace_train/trace_train_ground_truth.txt"),
    )
    parser.add_argument(
        "--source-logs",
        type=Path,
        default=Path("/root/autodl-tmp/data/trace_train/logs"),
    )
    parser.add_argument(
        "--window-id",
        action="append",
        dest="window_ids",
        default=[],
        help="Optional repeated window ids. Defaults to the current zero-tactic TRACE windows.",
    )
    parser.add_argument("--offset-minutes", type=int, default=DEFAULT_OFFSET)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_REPO_ROOT / "debug" / "remote_ops" / "out" / "trace_gt_window_rawlog_compare_20260627",
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
            if window_id and str(item.get("host", "")).strip().upper() == "TRACE":
                output[window_id] = item
    return output


def _top_actions(counter: Counter[str], limit: int = 12) -> list[dict[str, Any]]:
    return [{"action": action, "count": int(count)} for action, count in counter.most_common(limit)]


def _load_windows(gt_json_path: Path, *, window_ids: list[str]) -> list[Any]:
    windows, _, _ = load_gt_reference(gt_json_path, host_filter="TRACE")
    selected = []
    wanted = {item.strip() for item in window_ids if item.strip()}
    for item in windows:
        if not wanted or str(item.window_id) in wanted:
            selected.append(item)
    selected.sort(key=lambda item: (_parse_datetime(item.start_time) or datetime.min, str(item.window_id)))
    return selected


def _scan(
    *,
    source_logs: Path,
    windows: list[Any],
    malicious_uuids: set[str],
    offset_minutes: int,
) -> dict[str, Any]:
    cfg = SimpleNamespace(dataset_family="tc3", host="trace", source_logs=source_logs)
    state: dict[str, dict[str, Any]] = {}
    specs: list[tuple[str, datetime, datetime]] = []
    delta = timedelta(minutes=int(offset_minutes))
    for item in windows:
        start_dt = _parse_datetime(item.start_time)
        end_dt = _parse_datetime(item.end_time)
        if start_dt is None or end_dt is None:
            continue
        effective_start = start_dt + delta
        effective_end = end_dt + delta
        window_id = str(item.window_id)
        specs.append((window_id, effective_start, effective_end))
        state[window_id] = {
            "window_id": window_id,
            "base_start_time": start_dt.isoformat(),
            "base_end_time": end_dt.isoformat(),
            "applied_offset_minutes": int(offset_minutes),
            "effective_start_time": effective_start.isoformat(),
            "effective_end_time": effective_end.isoformat(),
            "subject_hit_ids": set(),
            "any_role_hit_ids": set(),
            "subject_action_counter": Counter(),
            "any_role_action_counter": Counter(),
            "subject_hit_event_count": 0,
            "any_role_hit_event_count": 0,
        }

    for log_path in _iter_log_files(source_logs, "trace"):
        for line in _iter_lines(log_path):
            event = _extract_event(cfg, line)
            if event is None or event.timestamp is None:
                continue
            event_ts = _parse_datetime(event.timestamp)
            if event_ts is None:
                continue
            subject_uuid = str(event.subject_uuid or "").strip()
            object_uuid = str(event.object_uuid or "").strip()
            action = str(event.action or "").strip() or "UNKNOWN"
            for window_id, start_dt, end_dt in specs:
                if event_ts < start_dt or event_ts > end_dt:
                    continue
                row = state[window_id]
                subject_hit = bool(subject_uuid and subject_uuid in malicious_uuids)
                any_role_hit = subject_hit or bool(object_uuid and object_uuid in malicious_uuids)
                if subject_hit:
                    row["subject_hit_ids"].add(subject_uuid)
                    row["subject_action_counter"][action] += 1
                    row["subject_hit_event_count"] += 1
                if any_role_hit:
                    if subject_hit:
                        row["any_role_hit_ids"].add(subject_uuid)
                    if object_uuid and object_uuid in malicious_uuids:
                        row["any_role_hit_ids"].add(object_uuid)
                    row["any_role_action_counter"][action] += 1
                    row["any_role_hit_event_count"] += 1

    output: dict[str, Any] = {}
    for window_id, row in state.items():
        subject_hit_ids = sorted(row["subject_hit_ids"])
        any_role_hit_ids = sorted(row["any_role_hit_ids"])
        output[window_id] = {
            "window_id": window_id,
            "base_start_time": row["base_start_time"],
            "base_end_time": row["base_end_time"],
            "applied_offset_minutes": row["applied_offset_minutes"],
            "effective_start_time": row["effective_start_time"],
            "effective_end_time": row["effective_end_time"],
            "gt_uuid_total": len(malicious_uuids),
            "subject_hit_ids": subject_hit_ids,
            "subject_hit_count": len(subject_hit_ids),
            "subject_hit_event_count": int(row["subject_hit_event_count"]),
            "any_role_hit_ids": any_role_hit_ids,
            "any_role_hit_count": len(any_role_hit_ids),
            "any_role_hit_event_count": int(row["any_role_hit_event_count"]),
            "object_side_only_ids": [item for item in any_role_hit_ids if item not in subject_hit_ids],
            "top_actions_subject": _top_actions(row["subject_action_counter"]),
            "top_actions_any_role": _top_actions(row["any_role_action_counter"]),
        }
    return output


def _render_markdown(compare_payload: dict[str, Any]) -> str:
    lines = [
        "# TRACE raw-log GT window compare",
        "",
        f"- offset minutes: `{compare_payload['offset_minutes']}`",
        f"- gt node path: `{compare_payload['gt_node_path']}`",
        f"- source logs: `{compare_payload['source_logs']}`",
        "",
    ]
    for window_id, row in compare_payload["windows"].items():
        lines.extend(
            [
                f"## {window_id}",
                "",
                f"- base window: `{row['base_start_time']} -> {row['base_end_time']}`",
                f"- effective window: `{row['effective_start_time']} -> {row['effective_end_time']}`",
                f"- subject hits: `{row['subject_hit_count']}` / `{row['gt_uuid_total']}`",
                f"- any-role hits: `{row['any_role_hit_count']}` / `{row['gt_uuid_total']}`",
                f"- subject hit events: `{row['subject_hit_event_count']}`",
                f"- any-role hit events: `{row['any_role_hit_event_count']}`",
                f"- object-side-only ids: `{len(row['object_side_only_ids'])}`",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def main() -> None:
    args = _parse_args()
    window_ids = args.window_ids or list(DEFAULT_WINDOW_IDS)
    malicious_uuids = _load_uuid_set(args.gt_node_path)
    windows = _load_windows(args.gt_json, window_ids=window_ids)
    compare_windows = _scan(
        source_logs=args.source_logs,
        windows=windows,
        malicious_uuids=malicious_uuids,
        offset_minutes=args.offset_minutes,
    )
    raw_window_map = _raw_window_map(args.gt_json)
    compare_payload = {
        "host": "TRACE",
        "offset_minutes": int(args.offset_minutes),
        "gt_json": str(args.gt_json),
        "gt_node_path": str(args.gt_node_path),
        "source_logs": str(args.source_logs),
        "windows": {
            window_id: {
                **row,
                "report_section_title": raw_window_map.get(window_id, {}).get("report_section_title", ""),
                "expected_tactics": raw_window_map.get(window_id, {}).get("confirmed_tactics", []),
            }
            for window_id, row in compare_windows.items()
        },
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    _write_json(args.output_dir / "window_hits_compare.json", compare_payload)
    (args.output_dir / "window_hits_compare.md").write_text(_render_markdown(compare_payload), encoding="utf-8")
    print(
        json.dumps(
            {
                "output_dir": str(args.output_dir),
                "window_count": len(compare_payload["windows"]),
                "window_ids": list(compare_payload["windows"].keys()),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
