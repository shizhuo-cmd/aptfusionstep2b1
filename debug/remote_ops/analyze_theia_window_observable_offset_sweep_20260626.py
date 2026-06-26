from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

_THIS_FILE = Path(__file__).resolve()
_REPO_ROOT = _THIS_FILE.parents[2]
_SRC_ROOT = _REPO_ROOT / "src"
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from apt_fusion.path_reason.log_stream import _extract_event, _extract_node_records, _iter_lines, _iter_log_files  # noqa: E402


@dataclass(frozen=True)
class ObservableHit:
    timestamp: datetime
    key: str
    observable_type: str
    value: str
    hit_kind: str
    subject_uuid: str
    object_uuid: str
    node_uuid: str
    node_attr: str
    action: str


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sweep THEIA report-observable hits across candidate GT time offsets."
    )
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
        default=Path("/root/autodl-tmp/data/theia/logs"),
    )
    parser.add_argument("--window-id", required=True)
    parser.add_argument("--offset-minutes-start", type=int, default=-360)
    parser.add_argument("--offset-minutes-end", type=int, default=600)
    parser.add_argument("--offset-step-minutes", type=int, default=30)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_REPO_ROOT / "debug" / "remote_ops" / "out" / "theia_window_observable_offset_sweep_20260626",
    )
    return parser.parse_args()


def _parse_iso8601(text: str) -> datetime:
    normalized = text.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is not None:
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _load_window(gt_json_path: Path, window_id: str) -> dict[str, Any]:
    payload = json.loads(gt_json_path.read_text(encoding="utf-8"))
    for item in payload.get("windows", []):
        if str(item.get("window_id", "")).strip() == window_id:
            return item
    raise KeyError(f"window_id not found in GT: {window_id}")


def _load_observables(window_payload: dict[str, Any]) -> list[tuple[str, str]]:
    observables: list[tuple[str, str]] = []
    for item in window_payload.get("explicit_observables", []):
        observable_type = str(item.get("observable_type", "")).strip()
        value = str(item.get("value", "")).strip()
        if not value:
            continue
        if observable_type in {"process_name", "file_path", "domain", "ip_port"}:
            observables.append((observable_type, value))
    observables.extend(
        [
            ("command", "whoami"),
            ("command", "ps"),
            ("command", "elevate"),
            ("command", "putfile"),
            ("command", "inject"),
        ]
    )
    deduped: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in observables:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped


def _load_uuid_set(path: Path) -> set[str]:
    return {
        value
        for value in (line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines())
        if value
    }


def _event_matches(observable_type: str, value: str, text: str) -> bool:
    probe = value.lower()
    haystack = text.lower()
    if observable_type == "ip_port":
        ip = probe.split(":", 1)[0]
        return probe in haystack or ip in haystack
    return probe in haystack


def _scan_hits(
    *,
    source_logs: Path,
    observables: list[tuple[str, str]],
    malicious_uuids: set[str],
) -> list[ObservableHit]:
    cfg = SimpleNamespace(dataset_family="tc3", host="theia", source_logs=source_logs)
    hits: list[ObservableHit] = []
    for log_file in _iter_log_files(source_logs, "theia"):
        for line in _iter_lines(log_file):
            event = _extract_event(cfg, line)
            if event is None or not event.timestamp:
                continue
            try:
                timestamp = _parse_iso8601(event.timestamp.replace(" ", "T"))
            except ValueError:
                continue

            event_text = " ".join(
                [
                    str(event.action or ""),
                    str(event.object_attr_hint or ""),
                    str(event.subject_uuid or ""),
                    str(event.object_uuid or ""),
                ]
            )
            for observable_type, value in observables:
                if not _event_matches(observable_type, value, event_text):
                    continue
                hits.append(
                    ObservableHit(
                        timestamp=timestamp,
                        key=f"{observable_type}:{value}",
                        observable_type=observable_type,
                        value=value,
                        hit_kind="event",
                        subject_uuid=str(event.subject_uuid or ""),
                        object_uuid=str(event.object_uuid or ""),
                        node_uuid="",
                        node_attr=str(event.object_attr_hint or ""),
                        action=str(event.action or ""),
                    )
                )

            for node_uuid, attr in _extract_node_records(cfg, line):
                if not getattr(attr, "node_attr", ""):
                    continue
                node_text = f"{attr.node_type} {attr.node_attr}"
                for observable_type, value in observables:
                    if observable_type == "command":
                        continue
                    if not _event_matches(observable_type, value, node_text):
                        continue
                    hits.append(
                        ObservableHit(
                            timestamp=timestamp,
                            key=f"{observable_type}:{value}",
                            observable_type=observable_type,
                            value=value,
                            hit_kind=f"node:{attr.node_type}",
                            subject_uuid="",
                            object_uuid="",
                            node_uuid=str(node_uuid),
                            node_attr=str(attr.node_attr),
                            action="",
                        )
                    )
    return hits


def _summarize_offset(
    *,
    hits: list[ObservableHit],
    malicious_uuids: set[str],
    base_start: datetime,
    base_end: datetime,
    offset_minutes: int,
) -> dict[str, Any]:
    delta = timedelta(minutes=offset_minutes)
    start = base_start + delta
    end = base_end + delta
    in_window = [hit for hit in hits if start <= hit.timestamp <= end]
    subject_uuids = {hit.subject_uuid for hit in in_window if hit.subject_uuid}
    object_uuids = {hit.object_uuid for hit in in_window if hit.object_uuid}
    node_uuids = {hit.node_uuid for hit in in_window if hit.node_uuid}
    all_uuids = subject_uuids | object_uuids | node_uuids
    term_counter = Counter(hit.key for hit in in_window)
    action_counter = Counter(hit.action for hit in in_window if hit.action)
    kind_counter = Counter(hit.hit_kind for hit in in_window)
    gt_uuids = sorted(all_uuids & malicious_uuids)
    return {
        "offset_minutes": int(offset_minutes),
        "effective_start_time": start.isoformat(),
        "effective_end_time": end.isoformat(),
        "hit_count": len(in_window),
        "distinct_term_count": len(term_counter),
        "distinct_subject_uuid_count": len(subject_uuids),
        "distinct_object_uuid_count": len(object_uuids),
        "distinct_node_uuid_count": len(node_uuids),
        "distinct_gt_uuid_count": len(gt_uuids),
        "gt_uuids_top20": gt_uuids[:20],
        "terms_top20": [{"key": key, "count": int(count)} for key, count in term_counter.most_common(20)],
        "actions_top20": [{"action": key, "count": int(count)} for key, count in action_counter.most_common(20)],
        "hit_kinds": [{"kind": key, "count": int(count)} for key, count in kind_counter.most_common()],
    }


def _render_markdown(
    *,
    window_id: str,
    report_section_title: str,
    base_start: datetime,
    base_end: datetime,
    summaries: list[dict[str, Any]],
) -> str:
    lines = [
        f"# THEIA observable offset sweep: {window_id}",
        "",
        f"- report section: {report_section_title}",
        f"- base window: `{base_start.isoformat()}` -> `{base_end.isoformat()}`",
        "",
        "| offset_min | hits | distinct_terms | gt_uuid_hits | top_terms |",
        "| ---: | ---: | ---: | ---: | --- |",
    ]
    for row in summaries:
        top_terms = ", ".join(item["key"] for item in row.get("terms_top20", [])[:5]) or "-"
        lines.append(
            f"| {row['offset_minutes']} | {row['hit_count']} | {row['distinct_term_count']} | "
            f"{row['distinct_gt_uuid_count']} | {top_terms} |"
        )
    lines.append("")
    return "\n".join(lines)


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> None:
    args = _parse_args()
    window = _load_window(args.gt_json, args.window_id)
    observables = _load_observables(window)
    malicious_uuids = _load_uuid_set(args.gt_node_path)
    hits = _scan_hits(
        source_logs=args.source_logs,
        observables=observables,
        malicious_uuids=malicious_uuids,
    )

    base_start = _parse_iso8601(str(window["start_time"]))
    base_end = _parse_iso8601(str(window["end_time"]))
    offsets = range(args.offset_minutes_start, args.offset_minutes_end + 1, args.offset_step_minutes)
    summaries = [
        _summarize_offset(
            hits=hits,
            malicious_uuids=malicious_uuids,
            base_start=base_start,
            base_end=base_end,
            offset_minutes=offset,
        )
        for offset in offsets
    ]
    summaries.sort(key=lambda row: (row["hit_count"], row["distinct_term_count"], row["distinct_gt_uuid_count"]), reverse=True)

    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    result = {
        "window_id": args.window_id,
        "report_section_title": str(window.get("report_section_title", "")),
        "base_start_time": base_start.isoformat(),
        "base_end_time": base_end.isoformat(),
        "observable_count": len(observables),
        "scan_hit_count": len(hits),
        "top_offsets": summaries[:20],
        "all_offsets": summaries,
    }
    _write_json(output_dir / f"{args.window_id}_offset_sweep.json", result)
    (output_dir / f"{args.window_id}_offset_sweep.md").write_text(
        _render_markdown(
            window_id=args.window_id,
            report_section_title=str(window.get("report_section_title", "")),
            base_start=base_start,
            base_end=base_end,
            summaries=summaries[:20],
        ),
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
