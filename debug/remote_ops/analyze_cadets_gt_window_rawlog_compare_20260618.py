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
from apt_fusion.path_reason.log_stream import (  # noqa: E402
    _extract_event_with_aliases,
    _iter_lines,
    _iter_log_files,
)

TARGET_WINDOW_IDS = (
    "CADETS_20180406_1121_1208_01",
    "CADETS_20180411_1508_1515_02",
)
DEFAULT_OFFSETS = (0, 240)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare CADETS raw-log malicious UUID hits for raw-time and +240 minute windows."
    )
    parser.add_argument(
        "--gt-json",
        type=Path,
        default=_REPO_ROOT / "docs" / "darpa_attack_eval_ground_truth_e3_report_enriched_20260618.json",
        help="Path to the enriched GT JSON.",
    )
    parser.add_argument(
        "--gt-node-path",
        type=Path,
        default=Path("/root/autodl-tmp/data/cadets/cadets.txt"),
        help="Path to the CADETS malicious UUID list.",
    )
    parser.add_argument(
        "--source-logs",
        type=Path,
        default=Path("/root/autodl-tmp/data/cadets/logs"),
        help="Path to the CADETS raw log directory.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_REPO_ROOT / "debug" / "remote_ops" / "out" / "cadets_gt_window_rawlog_compare_20260618",
        help="Directory for analysis outputs.",
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
        for fmt, width in (
            ("%Y-%m-%d %H:%M:%S", 19),
            ("%Y-%m-%dT%H:%M:%S", 19),
            ("%Y-%m-%d %H:%M", 16),
        ):
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


def _load_malicious_uuid_set(gt_node_path: Path) -> set[str]:
    uuids: set[str] = set()
    for line in gt_node_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        text = str(line).strip()
        if text:
            uuids.add(text)
    return uuids


def _load_raw_gt_window_map(gt_json_path: Path) -> dict[str, dict[str, Any]]:
    payload = json.loads(gt_json_path.read_text(encoding="utf-8"))
    windows_payload = payload.get("windows", []) if isinstance(payload, dict) else []
    output: dict[str, dict[str, Any]] = {}
    for item in windows_payload:
        if not isinstance(item, dict):
            continue
        window_id = str(item.get("window_id", "")).strip()
        if window_id:
            output[window_id] = item
    return output


def _load_target_windows(gt_json_path: Path) -> list[Any]:
    windows, _, _ = load_gt_reference(gt_json_path, host_filter="CADETS")
    selected = [
        window
        for window in windows
        if str(window.window_id).strip() in TARGET_WINDOW_IDS
    ]
    selected.sort(key=lambda item: (_parse_datetime(item.start_time) or datetime.min, str(item.window_id)))
    missing = [window_id for window_id in TARGET_WINDOW_IDS if window_id not in {str(item.window_id) for item in selected}]
    if missing:
        raise ValueError(f"Missing target windows in GT JSON: {missing}")
    return selected


def _top_actions(counter: Counter[str], limit: int = 12) -> list[dict[str, Any]]:
    return [
        {"action": action, "count": int(count)}
        for action, count in counter.most_common(limit)
    ]


def _build_window_row(
    *,
    window: Any,
    raw_window: dict[str, Any],
    offset_minutes: int,
    subject_hit_ids: set[str],
    any_role_hit_ids: set[str],
    subject_event_count: int,
    any_role_event_count: int,
    subject_action_counter: Counter[str],
    any_role_action_counter: Counter[str],
    gt_uuid_total: int,
) -> dict[str, Any]:
    base_start = _parse_datetime(window.start_time)
    base_end = _parse_datetime(window.end_time)
    delta = timedelta(minutes=int(offset_minutes))
    effective_start = base_start + delta if base_start is not None else None
    effective_end = base_end + delta if base_end is not None else None
    subject_ids = sorted(subject_hit_ids)
    any_role_ids = sorted(any_role_hit_ids)
    subject_only_extra_ids = sorted(set(subject_ids).difference(any_role_ids))
    object_side_only_ids = sorted(set(any_role_ids).difference(subject_ids))
    return {
        "window_id": str(window.window_id),
        "host": str(window.host),
        "status": str(window.status),
        "confirmed_tactics": list(getattr(window, "confirmed_tactics", []) or []),
        "attempted_tactics": list(getattr(window, "attempted_tactics", []) or []),
        "base_start_time": base_start.isoformat() if base_start else "",
        "base_end_time": base_end.isoformat() if base_end else "",
        "applied_offset_minutes": int(offset_minutes),
        "effective_start_time": effective_start.isoformat() if effective_start else "",
        "effective_end_time": effective_end.isoformat() if effective_end else "",
        "gt_uuid_total": int(gt_uuid_total),
        "report_section_id": str(raw_window.get("report_section_id", "")).strip(),
        "report_section_title": str(raw_window.get("report_section_title", "")).strip(),
        "source_markdown_path": str(raw_window.get("source_markdown_path", "")).strip(),
        "source_markdown_line_span": raw_window.get("source_markdown_line_span", {}) if isinstance(raw_window.get("source_markdown_line_span", {}), dict) else {},
        "subject_hit_ids": subject_ids,
        "subject_hit_count": len(subject_ids),
        "subject_hit_event_count": int(subject_event_count),
        "any_role_hit_ids": any_role_ids,
        "any_role_hit_count": len(any_role_ids),
        "any_role_hit_event_count": int(any_role_event_count),
        "subject_only_extra_ids": subject_only_extra_ids,
        "object_side_only_ids": object_side_only_ids,
        "top_actions_subject": _top_actions(subject_action_counter),
        "top_actions_any_role": _top_actions(any_role_action_counter),
    }


def _scan_all_offsets(
    *,
    source_logs: Path,
    target_windows: list[Any],
    raw_window_map: dict[str, dict[str, Any]],
    malicious_uuids: set[str],
    offsets: tuple[int, ...],
) -> dict[int, dict[str, Any]]:
    cfg = SimpleNamespace(dataset_family="tc3", host="cadets", source_logs=source_logs)
    specs: list[tuple[int, str, datetime, datetime]] = []
    per_offset_state: dict[int, dict[str, dict[str, Any]]] = {}
    for offset_minutes in offsets:
        delta = timedelta(minutes=int(offset_minutes))
        per_offset_state[offset_minutes] = {}
        for window in target_windows:
            base_start = _parse_datetime(window.start_time)
            base_end = _parse_datetime(window.end_time)
            if base_start is None or base_end is None:
                continue
            effective_start = base_start + delta
            effective_end = base_end + delta
            window_id = str(window.window_id)
            specs.append((offset_minutes, window_id, effective_start, effective_end))
            per_offset_state[offset_minutes][window_id] = {
                "subject_hit_ids": set(),
                "any_role_hit_ids": set(),
                "subject_event_count": 0,
                "any_role_event_count": 0,
                "subject_action_counter": Counter(),
                "any_role_action_counter": Counter(),
            }

    for log_file in _iter_log_files(source_logs, "cadets"):
        for line in _iter_lines(log_file):
            event = _extract_event_with_aliases(cfg, line, {})
            if event is None or not event.timestamp:
                continue
            timestamp = _parse_datetime(event.timestamp)
            if timestamp is None:
                continue
            subject_uuid = str(event.subject_uuid or "").strip()
            object_uuid = str(event.object_uuid or "").strip()
            action = str(event.action or "").strip() or "OTHER"
            for offset_minutes, window_id, effective_start, effective_end in specs:
                if not (effective_start <= timestamp <= effective_end):
                    continue
                state = per_offset_state[offset_minutes][window_id]
                subject_hit = bool(subject_uuid) and subject_uuid in malicious_uuids
                object_hit = bool(object_uuid) and object_uuid in malicious_uuids
                if subject_hit:
                    state["subject_hit_ids"].add(subject_uuid)
                    state["subject_event_count"] = int(state["subject_event_count"]) + 1
                    state["subject_action_counter"][action] += 1
                if subject_hit or object_hit:
                    if subject_hit:
                        state["any_role_hit_ids"].add(subject_uuid)
                    if object_hit:
                        state["any_role_hit_ids"].add(object_uuid)
                    state["any_role_event_count"] = int(state["any_role_event_count"]) + 1
                    state["any_role_action_counter"][action] += 1

    offset_results: dict[int, dict[str, Any]] = {}
    for offset_minutes in offsets:
        windows_payload: list[dict[str, Any]] = []
        for window in target_windows:
            window_id = str(window.window_id)
            raw_window = raw_window_map.get(window_id, {})
            state = per_offset_state[offset_minutes][window_id]
            windows_payload.append(
                _build_window_row(
                    window=window,
                    raw_window=raw_window,
                    offset_minutes=offset_minutes,
                    subject_hit_ids=state["subject_hit_ids"],
                    any_role_hit_ids=state["any_role_hit_ids"],
                    subject_event_count=state["subject_event_count"],
                    any_role_event_count=state["any_role_event_count"],
                    subject_action_counter=state["subject_action_counter"],
                    any_role_action_counter=state["any_role_action_counter"],
                    gt_uuid_total=len(malicious_uuids),
                )
            )
        offset_results[offset_minutes] = {
            "host": "CADETS",
            "applied_offset_minutes": int(offset_minutes),
            "window_count": len(windows_payload),
            "windows": windows_payload,
        }
    return offset_results


def _render_compare_markdown(
    *,
    compare_payload: dict[str, Any],
    gt_json_path: Path,
    gt_node_path: Path,
    source_logs: Path,
) -> str:
    lines = [
        "# CADETS 两窗原始时间 vs +240 分钟恶意节点回查",
        "",
        f"- GT 文件: `{gt_json_path}`",
        f"- GT UUID 名单: `{gt_node_path}`",
        f"- 原始日志目录: `{source_logs}`",
        f"- 分析窗口: `{', '.join(TARGET_WINDOW_IDS)}`",
        f"- offset 列表: `{', '.join(str(value) for value in DEFAULT_OFFSETS)}`",
        f"- 命中口径: `subject/process` 与 `any_role(subject or object)`",
        "",
    ]
    for window_id in TARGET_WINDOW_IDS:
        row = compare_payload.get("windows", {}).get(window_id, {})
        offset0 = row.get("offset_0", {})
        offset240 = row.get("offset_240", {})
        lines.extend(
            [
                f"## {window_id}",
                "",
                f"- GT tactics: {', '.join(offset0.get('confirmed_tactics', [])) or 'none'}",
                f"- 原始时间窗口: `{offset0.get('base_start_time', '')}` -> `{offset0.get('base_end_time', '')}`",
                f"- `+240` 时间窗口: `{offset240.get('effective_start_time', '')}` -> `{offset240.get('effective_end_time', '')}`",
                "",
                "### offset = 0",
                f"- subject_hit_count: {int(offset0.get('subject_hit_count', 0) or 0)}",
                f"- any_role_hit_count: {int(offset0.get('any_role_hit_count', 0) or 0)}",
                f"- object_side_only_ids: {', '.join(offset0.get('object_side_only_ids', [])) or 'none'}",
                f"- top_actions_subject: {json.dumps(offset0.get('top_actions_subject', []), ensure_ascii=False)}",
                f"- top_actions_any_role: {json.dumps(offset0.get('top_actions_any_role', []), ensure_ascii=False)}",
                "",
                "### offset = 240",
                f"- subject_hit_count: {int(offset240.get('subject_hit_count', 0) or 0)}",
                f"- any_role_hit_count: {int(offset240.get('any_role_hit_count', 0) or 0)}",
                f"- object_side_only_ids: {', '.join(offset240.get('object_side_only_ids', [])) or 'none'}",
                f"- top_actions_subject: {json.dumps(offset240.get('top_actions_subject', []), ensure_ascii=False)}",
                f"- top_actions_any_role: {json.dumps(offset240.get('top_actions_any_role', []), ensure_ascii=False)}",
                "",
                "### 结论性对照",
                f"- 原始时间命中的 subject UUID: {', '.join(offset0.get('subject_hit_ids', [])) or 'none'}",
                f"- `+240` 命中的 subject UUID: {', '.join(offset240.get('subject_hit_ids', [])) or 'none'}",
                f"- 原始时间命中的 any_role UUID: {', '.join(offset0.get('any_role_hit_ids', [])) or 'none'}",
                f"- `+240` 命中的 any_role UUID: {', '.join(offset240.get('any_role_hit_ids', [])) or 'none'}",
                "",
            ]
        )
    return "\n".join(lines).strip() + "\n"


def run_compare(
    *,
    gt_json_path: Path,
    gt_node_path: Path,
    source_logs: Path,
    output_dir: Path,
) -> dict[str, str]:
    gt_json_path = Path(gt_json_path)
    gt_node_path = Path(gt_node_path)
    source_logs = Path(source_logs)
    output_dir = Path(output_dir)

    if not gt_json_path.exists():
        raise FileNotFoundError(f"GT JSON not found: {gt_json_path}")
    if not gt_node_path.exists():
        raise FileNotFoundError(f"GT node list not found: {gt_node_path}")
    if not source_logs.exists():
        raise FileNotFoundError(f"Source logs path not found: {source_logs}")
    if source_logs.is_dir() and not any(source_logs.iterdir()):
        raise FileNotFoundError(f"Source logs directory is empty: {source_logs}")

    output_dir.mkdir(parents=True, exist_ok=True)
    target_windows = _load_target_windows(gt_json_path)
    raw_window_map = _load_raw_gt_window_map(gt_json_path)
    malicious_uuids = _load_malicious_uuid_set(gt_node_path)

    offset_results = _scan_all_offsets(
        source_logs=source_logs,
        target_windows=target_windows,
        raw_window_map=raw_window_map,
        malicious_uuids=malicious_uuids,
        offsets=DEFAULT_OFFSETS,
    )

    window_hits_offset_0_path = output_dir / "window_hits_offset_0.json"
    window_hits_offset_240_path = output_dir / "window_hits_offset_240.json"
    _write_json(window_hits_offset_0_path, offset_results[0])
    _write_json(window_hits_offset_240_path, offset_results[240])

    compare_payload = {
        "host": "CADETS",
        "gt_uuid_total": len(malicious_uuids),
        "windows": {},
    }
    for window_id in TARGET_WINDOW_IDS:
        offset0_row = next(
            row
            for row in offset_results[0]["windows"]
            if str(row.get("window_id", "")).strip() == window_id
        )
        offset240_row = next(
            row
            for row in offset_results[240]["windows"]
            if str(row.get("window_id", "")).strip() == window_id
        )
        compare_payload["windows"][window_id] = {
            "offset_0": offset0_row,
            "offset_240": offset240_row,
        }

    window_hits_compare_path = output_dir / "window_hits_compare.json"
    _write_json(window_hits_compare_path, compare_payload)

    compare_markdown = _render_compare_markdown(
        compare_payload=compare_payload,
        gt_json_path=gt_json_path,
        gt_node_path=gt_node_path,
        source_logs=source_logs,
    )
    window_hits_compare_md_path = output_dir / "window_hits_compare.md"
    window_hits_compare_md_path.write_text(compare_markdown, encoding="utf-8")

    provenance_summary = {
        "gt_json_path": str(gt_json_path),
        "gt_node_path": str(gt_node_path),
        "source_logs": str(source_logs),
        "window_ids": list(TARGET_WINDOW_IDS),
        "offset_minutes": list(DEFAULT_OFFSETS),
        "hit_modes": ["subject", "any_role"],
    }
    provenance_summary_path = output_dir / "provenance_summary.json"
    _write_json(provenance_summary_path, provenance_summary)

    return {
        "window_hits_offset_0_json": str(window_hits_offset_0_path),
        "window_hits_offset_240_json": str(window_hits_offset_240_path),
        "window_hits_compare_json": str(window_hits_compare_path),
        "window_hits_compare_markdown": str(window_hits_compare_md_path),
        "provenance_summary_json": str(provenance_summary_path),
    }


def main() -> None:
    args = _parse_args()
    outputs = run_compare(
        gt_json_path=args.gt_json,
        gt_node_path=args.gt_node_path,
        source_logs=args.source_logs,
        output_dir=args.output_dir,
    )
    print(json.dumps(outputs, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
