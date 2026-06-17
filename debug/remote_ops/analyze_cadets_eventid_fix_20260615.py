from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

_THIS_FILE = Path(__file__).resolve()
_REPO_ROOT = _THIS_FILE.parents[2]
_SRC_ROOT = _REPO_ROOT / "src"
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from apt_fusion.common import iter_jsonl
from apt_fusion.evaluation.path_reason_eval import (
    _canonical_tactic_name,
    apply_gt_time_offset,
    load_gt_reference,
)
from apt_fusion.path_reason.log_stream import (
    _extract_event_with_aliases,
    _iter_lines,
    _iter_log_files,
)

DEFAULT_CADETS_GT_TIME_OFFSET_MINUTES = 240


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _task_slug(task_id: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in str(task_id)).strip("_") or "task"


def _parse_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                parsed = datetime.strptime(text[:19], fmt)
                break
            except ValueError:
                parsed = None
        if parsed is None:
            return None
    if parsed.tzinfo is not None:
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _as_naive_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _time_span_minutes(start: datetime | None, end: datetime | None) -> float:
    if start is None or end is None:
        return 0.0
    return max(0.0, float((end - start).total_seconds()) / 60.0)


def _ranges_overlap(
    left_start: datetime | None,
    left_end: datetime | None,
    right_start: datetime | None,
    right_end: datetime | None,
) -> bool:
    if left_start is None or left_end is None or right_start is None or right_end is None:
        return False
    return left_start <= right_end and left_end >= right_start


def _resolve_cadets_gt_offset_minutes(metadata: dict[str, Any]) -> tuple[int, str]:
    offsets = metadata.get("recommended_gt_time_offset_minutes_by_host", {})
    if isinstance(offsets, dict) and "CADETS" in offsets:
        try:
            return int(offsets["CADETS"]), "metadata"
        except (TypeError, ValueError):
            pass
    return DEFAULT_CADETS_GT_TIME_OFFSET_MINUTES, "default_cadets_plus_4h"


def _load_confirmed_windows(gt_json_path: Path) -> tuple[list[Any], dict[str, Any]]:
    strict_windows, _, metadata = load_gt_reference(gt_json_path, host_filter="CADETS")
    offset_minutes, offset_source = _resolve_cadets_gt_offset_minutes(metadata)
    if offset_minutes:
        apply_gt_time_offset(strict_windows, minutes=offset_minutes)
    windows = [item for item in strict_windows if str(item.status).strip().lower() == "confirmed"]
    windows.sort(key=lambda item: (_as_naive_utc(item.start_time) or datetime.min, str(item.window_id)))
    return windows, {
        "host": "CADETS",
        "applied_offset_minutes": int(offset_minutes),
        "offset_source": offset_source,
    }


def _load_malicious_uuid_set(gt_node_path: Path) -> set[str]:
    uuids: set[str] = set()
    for line in gt_node_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        text = str(line).strip()
        if text:
            uuids.add(text)
    return uuids


def _scan_window_gt_processes(
    source_logs: Path,
    windows: list[Any],
    malicious_uuids: set[str],
) -> tuple[dict[str, set[str]], dict[str, dict[str, Any]]]:
    cfg = SimpleNamespace(dataset_family="tc3", host="cadets", source_logs=source_logs)
    window_specs: list[tuple[str, datetime, datetime]] = []
    gt_processes_by_window: dict[str, set[str]] = {}
    raw_meta_by_window: dict[str, dict[str, Any]] = {}
    for window in windows:
        start_time = _as_naive_utc(window.start_time)
        end_time = _as_naive_utc(window.end_time)
        if start_time is None or end_time is None:
            continue
        window_id = str(window.window_id)
        window_specs.append((window_id, start_time, end_time))
        gt_processes_by_window[window_id] = set()
        raw_meta_by_window[window_id] = {
            "raw_malicious_event_count": 0,
            "top_raw_actions": [],
            "_action_counter": Counter(),
        }
    for log_file in _iter_log_files(source_logs, "cadets"):
        for line in _iter_lines(log_file):
            event = _extract_event_with_aliases(cfg, line, {})
            if event is None or not event.timestamp:
                continue
            subject_uuid = str(event.subject_uuid).strip()
            if not subject_uuid or subject_uuid not in malicious_uuids:
                continue
            timestamp = _parse_datetime(event.timestamp)
            if timestamp is None:
                continue
            for window_id, start_time, end_time in window_specs:
                if start_time <= timestamp <= end_time:
                    gt_processes_by_window[window_id].add(subject_uuid)
                    meta = raw_meta_by_window[window_id]
                    meta["raw_malicious_event_count"] = int(meta.get("raw_malicious_event_count", 0) or 0) + 1
                    meta["_action_counter"][str(event.action or "").strip() or "OTHER"] += 1
    for window_id, meta in raw_meta_by_window.items():
        counter = meta.pop("_action_counter", Counter())
        meta["top_raw_actions"] = [
            {"action": action, "count": count}
            for action, count in counter.most_common(12)
        ]
    return gt_processes_by_window, raw_meta_by_window


def _load_selected_task_ids(artifacts_root: Path) -> list[str]:
    path = artifacts_root / "module3_evidence" / "task_index.json"
    rows = _load_json(path) if path.exists() else []
    output: list[str] = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        task_id = str(row.get("task_id", "")).strip()
        if task_id:
            output.append(task_id)
    return output


def _load_task_meta_by_id(artifacts_root: Path) -> dict[str, dict[str, Any]]:
    path = artifacts_root / "module2" / "task_meta_rich.json"
    rows = _load_json(path) if path.exists() else []
    output: dict[str, dict[str, Any]] = {}
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        task_id = str(row.get("task_id", "")).strip()
        if task_id:
            output[task_id] = row
    return output


def _load_suspicious_rows_by_id(artifacts_root: Path) -> dict[str, dict[str, Any]]:
    path = artifacts_root / "module2" / "suspicious_tasks.json"
    rows = _load_json(path) if path.exists() else []
    output: dict[str, dict[str, Any]] = {}
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        task_id = str(row.get("task_id", "")).strip()
        if task_id:
            output[task_id] = row
    return output


def _load_id_mapping_by_task(artifacts_root: Path) -> dict[str, dict[str, Any]]:
    path = artifacts_root / "module3_evidence" / "id_mapping.json"
    rows = _load_json(path) if path.exists() else []
    output: dict[str, dict[str, Any]] = {}
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        task_id = str(row.get("task_id", "")).strip()
        if task_id:
            output[task_id] = row
    return output


def _normalized_event_range(path: Path) -> tuple[datetime | None, datetime | None]:
    start_time: datetime | None = None
    end_time: datetime | None = None
    if not path.exists():
        return start_time, end_time
    for row in iter_jsonl(path):
        timestamp = _parse_datetime(row.get("timestamp"))
        if timestamp is None:
            continue
        if start_time is None or timestamp < start_time:
            start_time = timestamp
        if end_time is None or timestamp > end_time:
            end_time = timestamp
    return start_time, end_time


def _load_report_items_by_task(artifacts_root: Path) -> dict[str, list[dict[str, Any]]]:
    report_index_path = artifacts_root / "module6_reason" / "report_index.json"
    if not report_index_path.exists():
        return {}
    rows = _load_json(report_index_path)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        task_id = str(row.get("task_id", "")).strip()
        if not task_id:
            continue
        report_path = Path(str(row.get("report_path", "")).strip())
        dossier_path = Path(str(row.get("dossier_path", "")).strip())
        if not report_path.exists() or not dossier_path.exists():
            continue
        report = _load_json(report_path)
        dossier = _load_json(dossier_path)
        grouped.setdefault(task_id, []).append(
            {
                "path_id": str(row.get("path_id", "")).strip(),
                "report": report if isinstance(report, dict) else {},
                "dossier": dossier if isinstance(dossier, dict) else {},
            }
        )
    for task_id, items in grouped.items():
        items.sort(
            key=lambda item: (
                -float(item["report"].get("risk_score", 0.0) or 0.0),
                str(item["path_id"]),
            )
        )
    return grouped


def _load_task_records(artifacts_root: Path) -> dict[str, dict[str, Any]]:
    selected_task_ids = _load_selected_task_ids(artifacts_root)
    task_meta_by_id = _load_task_meta_by_id(artifacts_root)
    suspicious_by_id = _load_suspicious_rows_by_id(artifacts_root)
    id_mapping_by_task = _load_id_mapping_by_task(artifacts_root)
    reports_by_task = _load_report_items_by_task(artifacts_root)
    records: dict[str, dict[str, Any]] = {}
    for task_id in selected_task_ids:
        slug = _task_slug(task_id)
        graph_path = artifacts_root / "module3_evidence" / "task_local_evidence_graph" / f"{slug}.json"
        normalized_events_path = artifacts_root / "module3_evidence" / "normalized_events" / f"{slug}.jsonl"
        candidate_path_path = artifacts_root / "module5_paths" / "candidate_paths" / f"{slug}.json"
        graph = _load_json(graph_path) if graph_path.exists() else {}
        task_meta = task_meta_by_id.get(task_id, {})
        suspicious_row = suspicious_by_id.get(task_id, {})
        task_process_ids = [
            str(value).strip()
            for value in task_meta.get("process_ids", suspicious_row.get("process_ids", [])) or []
            if str(value).strip()
        ]
        evidence_process_ids = [
            str(value).strip()
            for value in graph.get("process_nodes", []) or []
            if str(value).strip()
        ]
        start_time, end_time = _normalized_event_range(normalized_events_path)
        candidate_paths = _load_json(candidate_path_path) if candidate_path_path.exists() else []
        records[task_id] = {
            "task_id": task_id,
            "task_process_ids": sorted(set(task_process_ids)),
            "evidence_process_ids": sorted(set(evidence_process_ids)),
            "start_time": start_time,
            "end_time": end_time,
            "time_span_minutes": _time_span_minutes(start_time, end_time),
            "candidate_path_count": len(candidate_paths) if isinstance(candidate_paths, list) else 0,
            "id_mapping": id_mapping_by_task.get(task_id, {}),
            "reports": reports_by_task.get(task_id, []),
        }
    return records


def _canonical_tactics_from_report(report: dict[str, Any]) -> list[str]:
    output: list[str] = []
    for mapping in report.get("attack_mappings", []) or []:
        if not isinstance(mapping, dict):
            continue
        tactic = _canonical_tactic_name(str(mapping.get("tactic_id", "")).strip())
        if not tactic:
            tactic = _canonical_tactic_name(str(mapping.get("tactic", "")).strip())
        if tactic and tactic not in output:
            output.append(tactic)
    return output


def _candidate_tactics_from_report(report: dict[str, Any]) -> list[str]:
    output: list[str] = []
    for candidate in (report.get("attack_candidates", {}) or {}).get("tactics", []) or []:
        if not isinstance(candidate, dict):
            continue
        tactic = _canonical_tactic_name(str(candidate.get("external_id", "")).strip())
        if not tactic:
            tactic = _canonical_tactic_name(str(candidate.get("name", "")).strip())
        if tactic and tactic not in output:
            output.append(tactic)
    return output


def _mapping_validation_totals(report_items: list[dict[str, Any]]) -> dict[str, int]:
    totals: Counter[str] = Counter()
    for item in report_items:
        report = item.get("report", {}) or {}
        summary = report.get("mapping_validation_summary", {}) or {}
        if not isinstance(summary, dict):
            continue
        for key, value in summary.items():
            if isinstance(value, (int, float)):
                totals[key] += int(value)
    return {key: int(value) for key, value in sorted(totals.items())}


def _window_row(
    window: Any,
    task_records: dict[str, dict[str, Any]],
    gt_processes: set[str],
    raw_meta: dict[str, Any],
) -> dict[str, Any]:
    window_id = str(window.window_id)
    window_start = _as_naive_utc(window.start_time)
    window_end = _as_naive_utc(window.end_time)
    overlap_task_ids = [
        task_id
        for task_id, record in task_records.items()
        if _ranges_overlap(window_start, window_end, record.get("start_time"), record.get("end_time"))
    ]
    overlap_task_ids.sort()
    task_graph_processes: set[str] = set()
    evidence_processes: set[str] = set()
    predicted_tactics: list[str] = []
    candidate_tactics: list[str] = []
    family_tags_union: set[str] = set()
    claim_behaviors_union: set[str] = set()
    matched_atoms_union: set[str] = set()
    network_support_values: list[str] = []
    claim_statement_values: list[str] = []
    mapping_validation = Counter()
    candidate_path_count = 0
    report_count_considered = 0
    unmapped_seed_total = 0
    unmapped_top_total = 0
    max_task_time_span_minutes = 0.0
    top_path_ids: list[str] = []
    for task_id in overlap_task_ids:
        record = task_records[task_id]
        task_graph_processes.update(record.get("task_process_ids", []))
        evidence_processes.update(record.get("evidence_process_ids", []))
        candidate_path_count += int(record.get("candidate_path_count", 0) or 0)
        max_task_time_span_minutes = max(max_task_time_span_minutes, float(record.get("time_span_minutes", 0.0) or 0.0))
        id_mapping = record.get("id_mapping", {}) or {}
        unmapped_seed_total += int(id_mapping.get("unmapped_seed_process_count", 0) or 0)
        unmapped_top_total += int(id_mapping.get("unmapped_top_process_count", 0) or 0)
        report_items = list(record.get("reports", []))[:5]
        report_count_considered += len(report_items)
        for item in report_items:
            path_id = str(item.get("path_id", "")).strip()
            if path_id:
                top_path_ids.append(path_id)
            report = item.get("report", {}) or {}
            dossier = item.get("dossier", {}) or {}
            for tactic in _canonical_tactics_from_report(report):
                if tactic and tactic not in predicted_tactics:
                    predicted_tactics.append(tactic)
            for tactic in _candidate_tactics_from_report(report):
                if tactic and tactic not in candidate_tactics:
                    candidate_tactics.append(tactic)
            for value in dossier.get("family_tags", []) or []:
                text = str(value).strip()
                if text:
                    family_tags_union.add(text)
            for claim in report.get("claims", []) or []:
                if not isinstance(claim, dict):
                    continue
                behavior = str(claim.get("behavior_type", "")).strip()
                statement = str(claim.get("statement", "")).strip()
                if behavior:
                    claim_behaviors_union.add(behavior)
                if statement:
                    claim_statement_values.append(statement.lower())
            diagnostics = (report.get("claim_graph", {}) or {}).get("diagnostics", {}) or {}
            for value in diagnostics.get("matched_atoms", []) or []:
                text = str(value).strip()
                if text:
                    matched_atoms_union.add(text)
            network_support = str(dossier.get("network_support_summary", "")).strip()
            if network_support:
                network_support_values.append(network_support.lower())
            for key, value in _mapping_validation_totals([item]).items():
                mapping_validation[key] += int(value)
    gt_task_covered = sorted(set(gt_processes).intersection(task_graph_processes))
    gt_evidence_covered = sorted(set(gt_processes).intersection(evidence_processes))
    gt_process_count = len(gt_processes)
    gt_task_coverage = float(len(gt_task_covered) / gt_process_count) if gt_process_count else 0.0
    gt_evidence_coverage = float(len(gt_evidence_covered) / gt_process_count) if gt_process_count else 0.0
    gt_tactics = sorted(
        {
            _canonical_tactic_name(tactic)
            for tactic in getattr(window, "confirmed_tactics", []) or []
            if _canonical_tactic_name(tactic)
        }
    )
    matched_tactics = [tactic for tactic in gt_tactics if tactic in predicted_tactics]
    return {
        "window_id": window_id,
        "window_start": window_start.isoformat() if window_start else "",
        "window_end": window_end.isoformat() if window_end else "",
        "window_span_minutes": _time_span_minutes(window_start, window_end),
        "gt_tactics": gt_tactics,
        "overlap_task_ids": overlap_task_ids,
        "overlap_task_count": len(overlap_task_ids),
        "gt_process_uuid_count": gt_process_count,
        "gt_process_uuids": sorted(gt_processes),
        "task_graph_process_uuid_count": len(task_graph_processes),
        "task_graph_process_uuids": sorted(task_graph_processes),
        "task_graph_covered_gt_process_uuids": gt_task_covered,
        "task_graph_gt_process_coverage": gt_task_coverage,
        "evidence_process_uuid_count": len(evidence_processes),
        "evidence_process_uuids": sorted(evidence_processes),
        "evidence_covered_gt_process_uuids": gt_evidence_covered,
        "evidence_gt_process_coverage": gt_evidence_coverage,
        "predicted_tactics_union_top_n": predicted_tactics,
        "candidate_tactics_union_top_n": candidate_tactics,
        "matched_tactics": matched_tactics,
        "missed_tactics": [tactic for tactic in gt_tactics if tactic not in matched_tactics],
        "extra_tactics": [tactic for tactic in predicted_tactics if tactic not in matched_tactics],
        "candidate_path_count": candidate_path_count,
        "report_count_considered": report_count_considered,
        "family_tags_union": sorted(family_tags_union),
        "claim_behaviors_union": sorted(claim_behaviors_union),
        "matched_atoms_union": sorted(matched_atoms_union),
        "claim_statement_blob": " ".join(claim_statement_values).strip(),
        "network_support_blob": " ".join(network_support_values).strip(),
        "mapping_validation_overall": {key: int(value) for key, value in sorted(mapping_validation.items())},
        "unmapped_seed_process_count_total": unmapped_seed_total,
        "unmapped_top_process_count_total": unmapped_top_total,
        "max_overlap_task_time_span_minutes": max_task_time_span_minutes,
        "top_path_ids": top_path_ids[:10],
        "raw_malicious_event_count": int(raw_meta.get("raw_malicious_event_count", 0) or 0),
        "top_raw_actions": list(raw_meta.get("top_raw_actions", [])),
    }


def _expected_signal_hits(row: dict[str, Any], tactic: str) -> list[str]:
    family_tags = set(str(value).strip() for value in row.get("family_tags_union", []) if str(value).strip())
    claim_behaviors = set(str(value).strip() for value in row.get("claim_behaviors_union", []) if str(value).strip())
    matched_atoms = set(str(value).strip() for value in row.get("matched_atoms_union", []) if str(value).strip())
    claim_blob = str(row.get("claim_statement_blob", "")).lower()
    network_blob = str(row.get("network_support_blob", "")).lower()
    action_blob = " ".join(str(item.get("action", "")).lower() for item in row.get("top_raw_actions", []) if isinstance(item, dict))
    hits: list[str] = []
    if tactic == "INITIAL_ACCESS":
        if family_tags.intersection({"initial_or_drop_exec", "attachment_or_tcexec_exec"}):
            hits.append("family_tag")
        if claim_behaviors.intersection({"make_file_exec", "untrusted_read", "attachment_user_exec", "untrusted_file_exec", "interpreter_precursor_chain"}):
            hits.append("claim_behavior")
    elif tactic == "COMMAND_AND_CONTROL":
        if "callback_c2" in family_tags:
            hits.append("family_tag")
        if claim_behaviors.intersection({"cnc_communication", "remote_send", "sensitive_leak"}):
            hits.append("claim_behavior")
        if "external" in network_blob:
            hits.append("network_support")
    elif tactic == "DISCOVERY":
        if "scan_discovery" in family_tags:
            hits.append("family_tag")
        if claim_behaviors.intersection({"network_service_discovery", "sensitive_command", "send_internal"}):
            hits.append("claim_behavior")
        if any(keyword in claim_blob or keyword in action_blob for keyword in ("whoami", " ps ", "scan", "connect")):
            hits.append("raw_or_statement_keyword")
    elif tactic == "DEFENSE_EVASION":
        if "cleanup_delete" in family_tags:
            hits.append("family_tag")
        if claim_behaviors.intersection({"clear_logs", "sensitive_temp_rm", "untrusted_file_rm"}):
            hits.append("claim_behavior")
        if any(keyword in claim_blob or keyword in action_blob for keyword in ("delete", "unlink", "clear log", "rm")):
            hits.append("raw_or_statement_keyword")
    for value in matched_atoms:
        if value in {"make_file_exec", "untrusted_read", "attachment_user_exec", "untrusted_file_exec", "interpreter_precursor_chain"} and tactic == "INITIAL_ACCESS":
            hits.append("matched_atom")
        if value in {"cnc_communication"} and tactic == "COMMAND_AND_CONTROL":
            hits.append("matched_atom")
        if value in {"network_service_discovery", "sensitive_command"} and tactic == "DISCOVERY":
            hits.append("matched_atom")
        if value in {"clear_logs", "sensitive_temp_rm", "untrusted_file_rm"} and tactic == "DEFENSE_EVASION":
            hits.append("matched_atom")
    unique_hits: list[str] = []
    for value in hits:
        if value not in unique_hits:
            unique_hits.append(value)
    return unique_hits


def _classify_missing_tactic(row: dict[str, Any], tactic: str) -> dict[str, Any]:
    overlap_task_ids = row.get("overlap_task_ids", []) or []
    task_graph_coverage = float(row.get("task_graph_gt_process_coverage", 0.0) or 0.0)
    evidence_coverage = float(row.get("evidence_gt_process_coverage", 0.0) or 0.0)
    unmapped_seed_total = int(row.get("unmapped_seed_process_count_total", 0) or 0)
    max_task_span = float(row.get("max_overlap_task_time_span_minutes", 0.0) or 0.0)
    window_span = max(1.0, float(row.get("window_span_minutes", 0.0) or 0.0))
    signal_hits = _expected_signal_hits(row, tactic)
    candidate_tactics = set(str(value).strip() for value in row.get("candidate_tactics_union_top_n", []) if str(value).strip())
    if not overlap_task_ids:
        return {
            "tactic": tactic,
            "category": "split_or_task_selection",
            "reason": "window has no overlapping GT-selected task",
            "signal_hits": signal_hits,
        }
    if task_graph_coverage < 0.8 or max_task_span > max(window_span * 3.0, 180.0):
        return {
            "tactic": tactic,
            "category": "split_or_task_selection",
            "reason": "selected task graph covers too little of the malicious process set or is much broader than the attack window",
            "signal_hits": signal_hits,
        }
    if evidence_coverage + 0.1 < task_graph_coverage or unmapped_seed_total > 0:
        return {
            "tactic": tactic,
            "category": "evidence_recovery",
            "reason": "task graph keeps the malicious process UUIDs but module3 evidence recovery drops them or leaves seeds unmapped",
            "signal_hits": signal_hits,
        }
    if tactic in candidate_tactics or signal_hits:
        return {
            "tactic": tactic,
            "category": "mapping_or_validation",
            "reason": "candidate tactics or claim-level signals already support the tactic, but final attack_mappings still miss it",
            "signal_hits": signal_hits,
        }
    return {
        "tactic": tactic,
        "category": "chain_label",
        "reason": "evidence graph covers the malicious process set, but the preserved candidate paths/claims do not retain enough tactic-specific support",
        "signal_hits": signal_hits,
    }


def _classify_extra_tactic(row: dict[str, Any], tactic: str) -> dict[str, Any]:
    signal_hits = _expected_signal_hits(row, tactic)
    candidate_tactics = set(str(value).strip() for value in row.get("candidate_tactics_union_top_n", []) if str(value).strip())
    if tactic in candidate_tactics or signal_hits:
        return {
            "tactic": tactic,
            "category": "chain_label",
            "reason": "the extra tactic is already present in candidate_tactics_union_top_n or claim-level support, so the path/claim layer is already skewed toward it",
            "signal_hits": signal_hits,
        }
    return {
        "tactic": tactic,
        "category": "mapping_or_validation",
        "reason": "the extra tactic appears only in final attack_mappings and is not backed by candidate_tactics_union_top_n",
        "signal_hits": signal_hits,
    }


def _render_window_tactic_table(rows: list[dict[str, Any]]) -> str:
    lines = [
        "| 窗口 | GT 战术 | 命中战术 | 漏掉战术 | 误报战术 | 证据图恶意进程覆盖率 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        lines.append(
            "| {window_id} | {gt} | {matched} | {missed} | {extra} | {coverage:.3f} |".format(
                window_id=row["window_id"],
                gt=", ".join(row.get("gt_tactics", [])) or "-",
                matched=", ".join(row.get("matched_tactics", [])) or "-",
                missed=", ".join(row.get("missed_tactics", [])) or "-",
                extra=", ".join(row.get("extra_tactics", [])) or "-",
                coverage=float(row.get("evidence_gt_process_coverage", 0.0) or 0.0),
            )
        )
    return "\n".join(lines).strip() + "\n"


def _render_coverage_bottleneck(rows: list[dict[str, Any]], overall: dict[str, Any]) -> str:
    lines = [
        "# CADETS Coverage Bottleneck Summary",
        "",
        f"- confirmed window macro average coverage: {float(overall.get('macro_average_coverage', 0.0) or 0.0):.3f}",
        f"- overall union coverage: {float(overall.get('overall_union_coverage', 0.0) or 0.0):.3f}",
        "",
    ]
    for row in rows:
        top_raw_actions = ", ".join(
            f"{str(item.get('action', '')).strip()}:{int(item.get('count', 0) or 0)}"
            for item in row.get("top_raw_actions", [])
            if isinstance(item, dict)
        ) or "none"
        lines.extend(
            [
                f"## {row['window_id']}",
                f"- overlap_task_ids: {', '.join(row.get('overlap_task_ids', [])) or 'none'}",
                f"- task_graph_gt_process_coverage: {float(row.get('task_graph_gt_process_coverage', 0.0) or 0.0):.3f}",
                f"- evidence_gt_process_coverage: {float(row.get('evidence_gt_process_coverage', 0.0) or 0.0):.3f}",
                f"- unmapped_seed_process_count_total: {int(row.get('unmapped_seed_process_count_total', 0) or 0)}",
                f"- unmapped_top_process_count_total: {int(row.get('unmapped_top_process_count_total', 0) or 0)}",
                f"- max_overlap_task_time_span_minutes: {float(row.get('max_overlap_task_time_span_minutes', 0.0) or 0.0):.1f}",
                f"- top_raw_actions: {top_raw_actions}",
                "",
            ]
        )
    return "\n".join(lines).strip() + "\n"


def _render_root_cause_summary(rows: list[dict[str, Any]], overall: dict[str, Any], attribution: list[dict[str, Any]]) -> str:
    by_window = {str(item.get("window_id", "")): item for item in attribution}
    lines = [
        "# CADETS Tactic Error Attribution",
        "",
        f"- confirmed window macro average coverage: {float(overall.get('macro_average_coverage', 0.0) or 0.0):.3f}",
        f"- overall union coverage: {float(overall.get('overall_union_coverage', 0.0) or 0.0):.3f}",
        "",
    ]
    for row in rows:
        detail = by_window.get(str(row["window_id"]), {})
        lines.extend(
            [
                f"## {row['window_id']}",
                f"- overlap_task_ids: {', '.join(row.get('overlap_task_ids', [])) or 'none'}",
                f"- matched_tactics: {', '.join(row.get('matched_tactics', [])) or 'none'}",
                f"- missed_tactics: {', '.join(row.get('missed_tactics', [])) or 'none'}",
                f"- extra_tactics: {', '.join(row.get('extra_tactics', [])) or 'none'}",
                f"- task_graph_gt_process_coverage: {float(row.get('task_graph_gt_process_coverage', 0.0) or 0.0):.3f}",
                f"- evidence_gt_process_coverage: {float(row.get('evidence_gt_process_coverage', 0.0) or 0.0):.3f}",
            ]
        )
        for miss in detail.get("missed_tactic_attribution", []) or []:
            lines.append(f"- missed::{miss['tactic']} -> {miss['category']} ({miss['reason']})")
        for extra in detail.get("extra_tactic_attribution", []) or []:
            lines.append(f"- extra::{extra['tactic']} -> {extra['category']} ({extra['reason']})")
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def run_cadets_eventid_fix_diagnostics(
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
    output_dir = artifacts_root / "cadets_eventid_fix_diagnostics"
    output_dir.mkdir(parents=True, exist_ok=True)

    windows, offset_info = _load_confirmed_windows(gt_json_path)
    malicious_uuids = _load_malicious_uuid_set(gt_node_path)
    gt_processes_by_window, raw_meta_by_window = _scan_window_gt_processes(source_logs, windows, malicious_uuids)
    task_records = _load_task_records(artifacts_root)
    rows = [
        _window_row(
            window,
            task_records,
            gt_processes_by_window.get(str(window.window_id), set()),
            raw_meta_by_window.get(str(window.window_id), {}),
        )
        for window in windows
    ]

    tactic_diff_rows = [
        {
            "window_id": row["window_id"],
            "gt_tactics": row["gt_tactics"],
            "predicted_tactics_union_top_n": row["predicted_tactics_union_top_n"],
            "candidate_tactics_union_top_n": row["candidate_tactics_union_top_n"],
            "matched_tactics": row["matched_tactics"],
            "missed_tactics": row["missed_tactics"],
            "extra_tactics": row["extra_tactics"],
            "overlap_task_ids": row["overlap_task_ids"],
            "top_path_ids": row["top_path_ids"],
        }
        for row in rows
    ]
    coverage_rows = [
        {
            "window_id": row["window_id"],
            "gt_process_uuid_count": row["gt_process_uuid_count"],
            "task_graph_process_uuid_count": row["task_graph_process_uuid_count"],
            "task_graph_gt_process_coverage": row["task_graph_gt_process_coverage"],
            "evidence_process_uuid_count": row["evidence_process_uuid_count"],
            "evidence_gt_process_coverage": row["evidence_gt_process_coverage"],
            "covered_gt_process_uuid_count": len(row["evidence_covered_gt_process_uuids"]),
            "overlap_task_ids": row["overlap_task_ids"],
            "raw_malicious_event_count": row["raw_malicious_event_count"],
            "top_raw_actions": row["top_raw_actions"],
        }
        for row in rows
    ]
    covered_rows = [
        {
            "window_id": row["window_id"],
            "covered_gt_process_uuids": row["evidence_covered_gt_process_uuids"],
        }
        for row in rows
    ]
    missed_rows = [
        {
            "window_id": row["window_id"],
            "missed_gt_process_uuids": [
                uuid for uuid in row["gt_process_uuids"] if uuid not in set(row["evidence_covered_gt_process_uuids"])
            ],
        }
        for row in rows
    ]
    union_gt = set().union(*(set(row["gt_process_uuids"]) for row in rows)) if rows else set()
    union_covered = set().union(*(set(row["evidence_covered_gt_process_uuids"]) for row in rows)) if rows else set()
    macro_average_coverage = float(
        sum(float(row["evidence_gt_process_coverage"]) for row in rows) / len(rows)
    ) if rows else 0.0
    overall_coverage = float(len(union_covered) / len(union_gt)) if union_gt else 0.0
    overall = {
        "confirmed_window_count": len(rows),
        "macro_average_coverage": macro_average_coverage,
        "overall_union_gt_process_count": len(union_gt),
        "overall_union_covered_process_count": len(union_covered),
        "overall_union_coverage": overall_coverage,
        "coverage_gate_threshold": 0.8,
        "coverage_gate_passed": macro_average_coverage >= 0.8,
    }

    tactic_diff_path = output_dir / "tactic_diff_by_window.json"
    window_tactic_table_path = output_dir / "window_tactic_table.md"
    coverage_by_window_path = output_dir / "evidence_gt_process_coverage_by_window.json"
    coverage_overall_path = output_dir / "evidence_gt_process_coverage_overall.json"
    missed_processes_path = output_dir / "missed_gt_processes_by_window.json"
    covered_processes_path = output_dir / "covered_gt_processes_by_window.json"
    summary_path = output_dir / "diagnostics_summary.json"

    _write_json(tactic_diff_path, tactic_diff_rows)
    window_tactic_table_path.write_text(_render_window_tactic_table(rows), encoding="utf-8")
    _write_json(coverage_by_window_path, coverage_rows)
    _write_json(coverage_overall_path, overall)
    _write_json(missed_processes_path, missed_rows)
    _write_json(covered_processes_path, covered_rows)

    outputs: dict[str, str] = {
        "tactic_diff_by_window": str(tactic_diff_path),
        "window_tactic_table": str(window_tactic_table_path),
        "evidence_gt_process_coverage_by_window": str(coverage_by_window_path),
        "evidence_gt_process_coverage_overall": str(coverage_overall_path),
        "missed_gt_processes_by_window": str(missed_processes_path),
        "covered_gt_processes_by_window": str(covered_processes_path),
    }

    if macro_average_coverage < 0.8:
        coverage_bottleneck_path = output_dir / "coverage_bottleneck_summary.md"
        coverage_bottleneck_path.write_text(_render_coverage_bottleneck(rows, overall), encoding="utf-8")
        outputs["coverage_bottleneck_summary"] = str(coverage_bottleneck_path)
    else:
        attribution_rows = []
        for row in rows:
            attribution_rows.append(
                {
                    "window_id": row["window_id"],
                    "matched_tactics": row["matched_tactics"],
                    "missed_tactic_attribution": [
                        _classify_missing_tactic(row, tactic)
                        for tactic in row.get("missed_tactics", [])
                    ],
                    "extra_tactic_attribution": [
                        _classify_extra_tactic(row, tactic)
                        for tactic in row.get("extra_tactics", [])
                    ],
                }
            )
        attribution_path = output_dir / "tactic_error_attribution.json"
        root_cause_summary_path = output_dir / "root_cause_summary.md"
        _write_json(attribution_path, attribution_rows)
        root_cause_summary_path.write_text(
            _render_root_cause_summary(rows, overall, attribution_rows),
            encoding="utf-8",
        )
        outputs["tactic_error_attribution"] = str(attribution_path)
        outputs["root_cause_summary"] = str(root_cause_summary_path)

    _write_json(
        summary_path,
        {
            "artifacts_root": str(artifacts_root),
            "gt_node_path": str(gt_node_path),
            "source_logs": str(source_logs),
            "gt_json_path": str(gt_json_path),
            "gt_time_alignment": offset_info,
            "coverage_overall": overall,
            "outputs": outputs,
        },
    )
    outputs["diagnostics_summary"] = str(summary_path)
    return outputs


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 4:
        raise SystemExit(
            "Usage: analyze_cadets_eventid_fix_20260615.py <artifacts_root> <gt_node_path> <source_logs> <gt_json_path>"
        )
    outputs = run_cadets_eventid_fix_diagnostics(
        artifacts_root=Path(argv[0]),
        gt_node_path=Path(argv[1]),
        source_logs=Path(argv[2]),
        gt_json_path=Path(argv[3]),
    )
    print(json.dumps(outputs, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
