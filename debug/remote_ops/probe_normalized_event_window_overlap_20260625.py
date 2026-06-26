from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable


@dataclass
class Window:
    window_id: str
    status: str
    start: datetime
    end: datetime


def _parse_iso8601(text: str) -> datetime:
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _load_windows(gt_path: Path, host: str, offset_minutes: int) -> list[Window]:
    payload = json.loads(gt_path.read_text(encoding="utf-8"))
    offset = timedelta(minutes=offset_minutes)
    windows: list[Window] = []
    for item in payload.get("windows", []):
        if str(item.get("host", "")).lower() != host.lower():
            continue
        start_text = item.get("start_time")
        end_text = item.get("end_time")
        if not start_text or not end_text:
            continue
        windows.append(
            Window(
                window_id=str(item.get("window_id")),
                status=str(item.get("status", "")),
                start=_parse_iso8601(start_text) + offset,
                end=_parse_iso8601(end_text) + offset,
            )
        )
    return windows


def _iter_task_files(module3_dir: Path) -> Iterable[Path]:
    norm_dir = module3_dir / "normalized_events"
    if not norm_dir.is_dir():
        return []
    return sorted(norm_dir.glob("task_*.jsonl"))


def _task_time_range(task_file: Path) -> tuple[datetime | None, datetime | None, int]:
    first_ts: datetime | None = None
    last_ts: datetime | None = None
    line_count = 0
    with task_file.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            line_count += 1
            record = json.loads(line)
            timestamp_text = record.get("timestamp")
            if not timestamp_text:
                continue
            ts = _parse_iso8601(timestamp_text)
            if first_ts is None or ts < first_ts:
                first_ts = ts
            if last_ts is None or ts > last_ts:
                last_ts = ts
    return first_ts, last_ts, line_count


def _overlap(a_start: datetime, a_end: datetime, b_start: datetime, b_end: datetime) -> bool:
    return a_start <= b_end and b_start <= a_end


def _load_selected_task_ids(module3_dir: Path) -> set[str]:
    suspicious_path = module3_dir / "_module1_gt_selection_sidecars" / "suspicious_tasks.json"
    if not suspicious_path.is_file():
        return set()
    payload = json.loads(suspicious_path.read_text(encoding="utf-8"))
    return {str(item.get("task_id")) for item in payload}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--gt-path", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--offset-minutes", type=int, default=0)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    artifact_root = Path(args.artifact_root)
    module3_dir = artifact_root / "module3_evidence"
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    windows = _load_windows(Path(args.gt_path), args.host, args.offset_minutes)
    confirmed_windows = [w for w in windows if w.status == "confirmed"]
    attempted_windows = [w for w in windows if w.status == "attempted_failed"]
    selected_task_ids = _load_selected_task_ids(module3_dir)

    tasks = []
    confirmed_union: set[str] = set()
    attempted_union: set[str] = set()
    confirmed_by_window: dict[str, list[str]] = {w.window_id: [] for w in confirmed_windows}
    attempted_by_window: dict[str, list[str]] = {w.window_id: [] for w in attempted_windows}
    spans: list[float] = []

    for task_file in _iter_task_files(module3_dir):
        task_id = task_file.stem
        if selected_task_ids and task_id not in selected_task_ids:
            continue
        first_ts, last_ts, event_count = _task_time_range(task_file)
        confirmed_hits: list[str] = []
        attempted_hits: list[str] = []
        span_minutes: float | None = None
        if first_ts and last_ts:
            span_minutes = max(0.0, (last_ts - first_ts).total_seconds() / 60.0)
            spans.append(span_minutes)
            for window in confirmed_windows:
                if _overlap(first_ts, last_ts, window.start, window.end):
                    confirmed_hits.append(window.window_id)
                    confirmed_by_window[window.window_id].append(task_id)
                    confirmed_union.add(task_id)
            for window in attempted_windows:
                if _overlap(first_ts, last_ts, window.start, window.end):
                    attempted_hits.append(window.window_id)
                    attempted_by_window[window.window_id].append(task_id)
                    attempted_union.add(task_id)
        tasks.append(
            {
                "task_id": task_id,
                "event_count": event_count,
                "first_timestamp": first_ts.isoformat() if first_ts else None,
                "last_timestamp": last_ts.isoformat() if last_ts else None,
                "span_minutes": span_minutes,
                "overlap_confirmed_window_ids": confirmed_hits,
                "overlap_attempted_window_ids": attempted_hits,
            }
        )

    spans.sort()

    def _pct(frac: float) -> float | None:
        if not spans:
            return None
        idx = min(len(spans) - 1, max(0, int(round((len(spans) - 1) * frac))))
        return spans[idx]

    result = {
        "artifact_root": str(artifact_root),
        "host": args.host,
        "offset_minutes": args.offset_minutes,
        "selected_task_count": len(selected_task_ids) if selected_task_ids else len(tasks),
        "normalized_event_task_count": len(tasks),
        "confirmed_window_overlap_unique_task_count": len(confirmed_union),
        "attempted_window_overlap_unique_task_count": len(attempted_union),
        "confirmed_window_overlap_by_window": {
            key: {
                "task_count": len(value),
                "task_ids": value,
            }
            for key, value in confirmed_by_window.items()
        },
        "attempted_window_overlap_by_window": {
            key: {
                "task_count": len(value),
                "task_ids": value,
            }
            for key, value in attempted_by_window.items()
        },
        "span_stats_minutes": {
            "median": _pct(0.5),
            "p90": _pct(0.9),
            "max": spans[-1] if spans else None,
        },
        "tasks": tasks,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
