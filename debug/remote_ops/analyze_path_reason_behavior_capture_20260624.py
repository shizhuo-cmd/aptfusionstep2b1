from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

_THIS_FILE = Path(__file__).resolve()
_REPO_ROOT = _THIS_FILE.parents[2]
_SRC_ROOT = _REPO_ROOT / "src"
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from apt_fusion.evaluation.path_reason_eval import (
    _canonical_tactic_name,
    apply_gt_time_offset,
    load_gt_reference,
)

TACTIC_TO_FAMILY_HINTS: dict[str, set[str]] = {
    "INITIAL_ACCESS": {"initial_or_drop_exec", "attachment_or_tcexec_exec", "short_lived_precursor"},
    "EXECUTION": {"initial_or_drop_exec", "attachment_or_tcexec_exec", "short_lived_precursor"},
    "PRIVILEGE_ESCALATION": {"short_lived_precursor"},
    "COMMAND_AND_CONTROL": {"callback_c2"},
    "DISCOVERY": {"scan_discovery"},
    "DEFENSE_EVASION": {"cleanup_delete"},
    "CREDENTIAL_ACCESS": {"mail_browser_context_tail"},
    "COLLECTION": {"mail_browser_context_tail"},
    "EXFILTRATION": {"callback_c2", "mail_browser_context_tail"},
}

TACTIC_TO_CLAIM_HINTS: dict[str, set[str]] = {
    "INITIAL_ACCESS": {"untrusted_read", "attachment_user_exec", "make_file_exec", "untrusted_file_exec"},
    "EXECUTION": {"shell_exec", "make_file_exec", "make_mem_exec", "untrusted_file_exec"},
    "PRIVILEGE_ESCALATION": {"sudo_exec", "switch_su"},
    "COMMAND_AND_CONTROL": {"cnc_communication", "send_internal"},
    "DISCOVERY": {"network_service_discovery", "sensitive_command"},
    "DEFENSE_EVASION": {"clear_logs", "untrusted_file_rm", "sensitive_temp_rm"},
    "CREDENTIAL_ACCESS": {"sensitive_read"},
    "COLLECTION": {"sensitive_read"},
    "EXFILTRATION": {"sensitive_leak"},
}

BEHAVIOR_ACTION_TO_TACTICS: dict[str, set[str]] = {
    "exploit_delivery": {"INITIAL_ACCESS"},
    "payload_execute": {"EXECUTION"},
    "payload_elevate": {"PRIVILEGE_ESCALATION"},
    "c2_callback": {"COMMAND_AND_CONTROL"},
    "scan": {"DISCOVERY"},
    "process_discovery": {"DISCOVERY"},
    "service_discovery": {"DISCOVERY"},
    "network_recon": {"DISCOVERY"},
    "file_delete": {"DEFENSE_EVASION"},
    "clear_logs": {"DEFENSE_EVASION"},
    "credential_submit": {"CREDENTIAL_ACCESS"},
    "credential_read": {"CREDENTIAL_ACCESS"},
    "file_read": {"COLLECTION"},
    "data_collection": {"COLLECTION"},
    "data_exfil": {"EXFILTRATION"},
    "exfiltrate": {"EXFILTRATION"},
}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _canonical_tactic_values(values: Iterable[Any]) -> list[str]:
    output: list[str] = []
    for value in values:
        text = _canonical_tactic_name(str(value or "").strip())
        if text and text not in output:
            output.append(text)
    return output


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


def _path_task_id(path_id: str) -> str:
    text = str(path_id or "").strip()
    marker = "_path_"
    return text.split(marker, 1)[0] if marker in text else ""


def _unique_strings(values: Iterable[Any]) -> list[str]:
    output: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in output:
            output.append(text)
    return output


def _raw_windows_by_id(gt_json_path: Path, *, host: str) -> dict[str, dict[str, Any]]:
    payload = _load_json(gt_json_path)
    output: dict[str, dict[str, Any]] = {}
    for row in payload.get("windows", []) if isinstance(payload, dict) else []:
        if not isinstance(row, dict):
            continue
        if str(row.get("host", "")).strip().upper() != host.upper():
            continue
        window_id = str(row.get("window_id", "")).strip()
        if window_id:
            output[window_id] = row
    return output


def _strict_windows(gt_json_path: Path, *, host: str, gt_time_offset_minutes: int) -> list[Any]:
    strict_windows, _, _ = load_gt_reference(gt_json_path, host_filter=host.upper())
    if gt_time_offset_minutes:
        apply_gt_time_offset(strict_windows, minutes=gt_time_offset_minutes)
    strict_windows.sort(
        key=lambda item: (
            _parse_datetime(getattr(item, "start_time", None) or ""),
            str(getattr(item, "window_id", "")),
        )
    )
    return strict_windows


def _coverage_rows_by_window(eval_dir: Path) -> dict[str, dict[str, Any]]:
    path = eval_dir / "candidate_tactic_coverage_by_task.json"
    if not path.exists():
        return {}
    output: dict[str, dict[str, Any]] = {}
    for row in _load_json(path):
        if not isinstance(row, dict):
            continue
        window_id = str(row.get("window_id", "")).strip()
        if window_id:
            output[window_id] = row
    return output


def _window_metrics_by_window(eval_dir: Path) -> dict[str, dict[str, Any]]:
    path = eval_dir / "window_level_metrics.json"
    if not path.exists():
        return {}
    output: dict[str, dict[str, Any]] = {}
    for row in _load_json(path):
        if not isinstance(row, dict):
            continue
        window_id = str(row.get("window_id", "")).strip()
        if window_id:
            output[window_id] = row
    return output


def _attack_candidate_tactics(report: dict[str, Any]) -> list[str]:
    attack_candidates = report.get("attack_candidates", {})
    tactics = attack_candidates.get("tactics", []) if isinstance(attack_candidates, dict) else []
    return _canonical_tactic_values(
        (item.get("name") or item.get("external_id") or item.get("tactic"))
        for item in tactics
        if isinstance(item, dict)
    )


def _predicted_tactics(report: dict[str, Any]) -> list[str]:
    return _canonical_tactic_values(
        item.get("tactic") or item.get("tactic_id")
        for item in report.get("attack_mappings", []) or []
        if isinstance(item, dict)
    )


def _claim_behavior_types(report: dict[str, Any]) -> list[str]:
    return _unique_strings(
        item.get("behavior_type")
        for item in report.get("claims", []) or []
        if isinstance(item, dict)
    )


def _family_tags(report: dict[str, Any]) -> list[str]:
    return _unique_strings(report.get("family_tags", []) or [])


def _supporting_paths_by_task(artifacts_root: Path) -> dict[str, list[dict[str, Any]]]:
    report_index_path = artifacts_root / "module6_reason" / "report_index.json"
    if not report_index_path.exists():
        return {}
    output: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in _load_json(report_index_path):
        if not isinstance(row, dict):
            continue
        task_id = str(row.get("task_id", "")).strip()
        report_path = Path(str(row.get("report_path", "")).strip())
        dossier_path = Path(str(row.get("dossier_path", "")).strip())
        claim_graph_path = Path(str(row.get("claim_graph_path", "")).strip())
        llm_input_path = Path(str(row.get("llm_input_path", "")).strip())
        if not task_id or not report_path.exists():
            continue
        report = _load_json(report_path)
        dossier = _load_json(dossier_path) if dossier_path.exists() else {}
        claim_graph = _load_json(claim_graph_path) if claim_graph_path.exists() else {}
        llm_input = _load_json(llm_input_path) if llm_input_path.exists() else {}
        output[task_id].append(
            {
                "task_id": task_id,
                "path_id": str(row.get("path_id", "")).strip(),
                "risk_score": float(report.get("risk_score", 0.0) or 0.0),
                "report": report,
                "dossier": dossier,
                "claim_graph": claim_graph,
                "llm_input": llm_input,
                "predicted_tactics": _predicted_tactics(report),
                "candidate_tactics": _attack_candidate_tactics(report),
                "claim_types": _claim_behavior_types(report),
                "family_tags": _family_tags(report),
            }
        )
    for rows in output.values():
        rows.sort(key=lambda item: (-float(item.get("risk_score", 0.0) or 0.0), str(item.get("path_id", ""))))
    return dict(output)


def _window_task_ids(coverage_row: dict[str, Any], metrics_row: dict[str, Any]) -> list[str]:
    task_ids = _unique_strings(coverage_row.get("matched_task_ids", []) or [])
    if task_ids:
        return task_ids
    path_ids = _unique_strings(metrics_row.get("matched_path_ids", []) or [])
    return _unique_strings(_path_task_id(path_id) for path_id in path_ids)


def _top_reports_for_window(
    task_ids: list[str],
    reports_by_task: dict[str, list[dict[str, Any]]],
    *,
    limit_top_paths_per_window: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for task_id in task_ids:
        rows.extend(reports_by_task.get(task_id, []))
    rows.sort(key=lambda item: (-float(item.get("risk_score", 0.0) or 0.0), str(item.get("path_id", ""))))
    return rows[:limit_top_paths_per_window]


def _union_from_reports(reports: list[dict[str, Any]], key: str) -> list[str]:
    output: list[str] = []
    for row in reports:
        for value in row.get(key, []) or []:
            text = str(value or "").strip()
            if text and text not in output:
                output.append(text)
    return output


def _behavior_tactic_hints(behavior: dict[str, Any], gt_tactics: list[str]) -> list[str]:
    action = str(behavior.get("action", "")).strip().lower()
    mapped = sorted(BEHAVIOR_ACTION_TO_TACTICS.get(action, set()))
    return mapped or list(gt_tactics)


def _tactic_hint_sets(tactic_names: Iterable[str]) -> tuple[set[str], set[str]]:
    family_hints: set[str] = set()
    claim_hints: set[str] = set()
    for tactic in tactic_names:
        canon = _canonical_tactic_name(tactic)
        family_hints.update(TACTIC_TO_FAMILY_HINTS.get(canon, set()))
        claim_hints.update(TACTIC_TO_CLAIM_HINTS.get(canon, set()))
    return family_hints, claim_hints


def _root_cause_for_missed_tactic(
    tactic: str,
    *,
    task_ids: list[str],
    candidate_tactics: list[str],
    predicted_tactics: list[str],
    family_tags: list[str],
    claim_types: list[str],
) -> str:
    if not task_ids:
        return "task_selection_or_split"
    canon = _canonical_tactic_name(tactic)
    family_hints, claim_hints = _tactic_hint_sets([canon])
    family_hit = bool(family_hints.intersection(family_tags))
    claim_hit = bool(claim_hints.intersection(claim_types))
    candidate_hit = canon in candidate_tactics
    predicted_hit = canon in predicted_tactics
    if predicted_hit:
        return "captured"
    if candidate_hit and not predicted_hit:
        return "mapping_or_validation"
    if claim_hit and not candidate_hit:
        return "attack_candidate_retrieval"
    if family_hit and not claim_hit:
        return "claim_generation"
    return "candidate_path_or_family_tag"


def _root_cause_for_extra_tactic(
    tactic: str,
    *,
    candidate_tactics: list[str],
    claim_types: list[str],
) -> str:
    canon = _canonical_tactic_name(tactic)
    if canon not in candidate_tactics:
        return "mapping_or_validation"
    _, claim_hints = _tactic_hint_sets([canon])
    if claim_hints.intersection(claim_types):
        return "claim_generation"
    return "candidate_path_or_family_tag"


def _service_heavy_flag(dossier: dict[str, Any]) -> bool:
    summary = str(dossier.get("service_context_summary", "")).strip().lower()
    if "system_objects=" in summary or "service_object" in summary:
        return True
    support_objects = " ".join(str(value).strip().lower() for value in dossier.get("support_object_keys", []) or [])
    return any(
        marker in support_objects
        for marker in ("/etc/", "/usr/", "/var/run/", "/var/spool/postfix/", "/dev/")
    )


def _path_autopsy_entry(path_row: dict[str, Any]) -> dict[str, Any]:
    dossier = path_row.get("dossier", {}) if isinstance(path_row.get("dossier"), dict) else {}
    report = path_row.get("report", {}) if isinstance(path_row.get("report"), dict) else {}
    return {
        "task_id": path_row.get("task_id"),
        "path_id": path_row.get("path_id"),
        "risk_score": path_row.get("risk_score"),
        "family_tags": path_row.get("family_tags", []),
        "claim_types": path_row.get("claim_types", []),
        "predicted_tactics": path_row.get("predicted_tactics", []),
        "candidate_tactics": path_row.get("candidate_tactics", []),
        "service_heavy": _service_heavy_flag(dossier),
        "support_object_keys": _unique_strings(dossier.get("support_object_keys", []) or [])[:20],
        "process_chain": _unique_strings(dossier.get("process_chain", []) or report.get("process_chain", []) or [])[:20],
        "service_context_summary": str(dossier.get("service_context_summary", "")).strip(),
        "sensitive_object_summary": str(dossier.get("sensitive_object_summary", "")).strip(),
        "cleanup_object_summary": str(dossier.get("cleanup_object_summary", "")).strip(),
        "summary": str(report.get("summary", "")).strip(),
    }


def _claim_rule_trace_entry(path_row: dict[str, Any]) -> dict[str, Any]:
    report = path_row.get("report", {}) if isinstance(path_row.get("report"), dict) else {}
    claim_graph = path_row.get("claim_graph", {}) if isinstance(path_row.get("claim_graph"), dict) else {}
    claims = []
    for claim in report.get("claims", []) or []:
        if not isinstance(claim, dict):
            continue
        claims.append(
            {
                "claim_id": str(claim.get("claim_id", "")).strip(),
                "behavior_type": str(claim.get("behavior_type", "")).strip(),
                "apt_stage": str(claim.get("apt_stage", "")).strip(),
                "claim_source": str(claim.get("claim_source", "")).strip(),
                "confidence": float(claim.get("confidence", 0.0) or 0.0),
                "support_signals": _unique_strings(claim.get("support_signals", []) or []),
                "evidence_event_ids": _unique_strings(claim.get("evidence_event_ids", []) or []),
                "prerequisite_claim_ids": _unique_strings(claim.get("prerequisite_claim_ids", []) or []),
            }
        )
    return {
        "task_id": path_row.get("task_id"),
        "path_id": path_row.get("path_id"),
        "risk_score": path_row.get("risk_score"),
        "matched_atoms": _unique_strings(claim_graph.get("diagnostics", {}).get("matched_atoms", []) or []),
        "missing_expected_atoms": _unique_strings(claim_graph.get("diagnostics", {}).get("missing_expected_atoms", []) or []),
        "claims": claims,
    }


def _family_tag_trace_entry(path_row: dict[str, Any]) -> dict[str, Any]:
    dossier = path_row.get("dossier", {}) if isinstance(path_row.get("dossier"), dict) else {}
    return {
        "task_id": path_row.get("task_id"),
        "path_id": path_row.get("path_id"),
        "risk_score": path_row.get("risk_score"),
        "family_tags": _unique_strings(dossier.get("family_tags", []) or []),
        "precursor_event_ids": _unique_strings(dossier.get("precursor_event_ids", []) or []),
        "followup_event_ids": _unique_strings(dossier.get("followup_event_ids", []) or []),
        "network_support_summary": str(dossier.get("network_support_summary", "")).strip(),
        "object_lineage_summary": str(dossier.get("object_lineage_summary", "")).strip(),
        "service_context_summary": str(dossier.get("service_context_summary", "")).strip(),
        "sensitive_object_summary": str(dossier.get("sensitive_object_summary", "")).strip(),
        "cleanup_object_summary": str(dossier.get("cleanup_object_summary", "")).strip(),
        "missed_truth_like_hints": _unique_strings(dossier.get("missed_truth_like_hints", []) or []),
    }


def _mapping_constraint_trace_entry(path_row: dict[str, Any]) -> dict[str, Any]:
    report = path_row.get("report", {}) if isinstance(path_row.get("report"), dict) else {}
    attack_candidates_retrieved = report.get("attack_candidates_retrieved", {})
    attack_candidates_post_priors = report.get("attack_candidates_post_priors", {})
    attack_candidates_post_context_guard = report.get("attack_candidates_post_context_guard", {})
    attack_candidates_post_scope = report.get("attack_candidates", {})
    validation = report.get("mapping_validation_summary", {}) if isinstance(report.get("mapping_validation_summary"), dict) else {}
    return {
        "task_id": path_row.get("task_id"),
        "path_id": path_row.get("path_id"),
        "risk_score": path_row.get("risk_score"),
        "claim_attack_prior_mode": str(report.get("claim_attack_prior_mode", "")).strip(),
        "attack_mapping_scope": str(report.get("attack_mapping_scope", "")).strip(),
        "tactic_mapping_mode": str(report.get("tactic_mapping_mode", "")).strip(),
        "retrieved_tactics": _canonical_tactic_values(
            (item.get("name") or item.get("external_id") or item.get("tactic"))
            for item in attack_candidates_retrieved.get("tactics", [])
            if isinstance(item, dict)
        ),
        "post_prior_tactics": _canonical_tactic_values(
            (item.get("name") or item.get("external_id") or item.get("tactic"))
            for item in attack_candidates_post_priors.get("tactics", [])
            if isinstance(item, dict)
        ),
        "post_context_guard_tactics": _canonical_tactic_values(
            (item.get("name") or item.get("external_id") or item.get("tactic"))
            for item in attack_candidates_post_context_guard.get("tactics", [])
            if isinstance(item, dict)
        ),
        "post_scope_tactics": _canonical_tactic_values(
            (item.get("name") or item.get("external_id") or item.get("tactic"))
            for item in attack_candidates_post_scope.get("tactics", [])
            if isinstance(item, dict)
        ),
        "context_prune_reason": str(report.get("attack_candidate_context_prune_reason", "")).strip(),
        "predicted_tactics": _canonical_tactic_values(
            item.get("tactic") or item.get("tactic_id")
            for item in report.get("attack_mappings", []) or []
            if isinstance(item, dict)
        ),
        "mapping_validation_summary": validation,
    }


def build_behavior_capture(
    *,
    artifacts_root: Path,
    gt_json_path: Path,
    host: str,
    gt_time_offset_minutes: int,
    limit_top_paths_per_window: int,
) -> dict[str, Any]:
    eval_dir = artifacts_root / "path_reason_eval_tactics_only_llm"
    raw_windows = _raw_windows_by_id(gt_json_path, host=host)
    strict_windows = _strict_windows(gt_json_path, host=host, gt_time_offset_minutes=gt_time_offset_minutes)
    coverage_by_window = _coverage_rows_by_window(eval_dir)
    metrics_by_window = _window_metrics_by_window(eval_dir)
    reports_by_task = _supporting_paths_by_task(artifacts_root)

    window_rows: list[dict[str, Any]] = []
    false_positive_rows: list[dict[str, Any]] = []
    false_negative_rows: list[dict[str, Any]] = []
    claim_rule_rows: list[dict[str, Any]] = []
    family_tag_rows: list[dict[str, Any]] = []
    mapping_constraint_rows: list[dict[str, Any]] = []
    root_cause_counter: Counter[str] = Counter()

    for window in strict_windows:
        window_id = str(getattr(window, "window_id", "")).strip()
        raw_window = raw_windows.get(window_id, {})
        coverage_row = coverage_by_window.get(window_id, {})
        metrics_row = metrics_by_window.get(window_id, {})
        gt_tactics = _canonical_tactic_values(
            raw_window.get("confirmed_tactics", []) or getattr(window, "confirmed_tactics", []) or []
        )
        attempted_tactics = _canonical_tactic_values(
            raw_window.get("attempted_tactics", []) or getattr(window, "attempted_tactics", []) or []
        )
        task_ids = _window_task_ids(coverage_row, metrics_row)
        top_reports = _top_reports_for_window(
            task_ids,
            reports_by_task,
            limit_top_paths_per_window=limit_top_paths_per_window,
        )
        claim_rule_rows.append(
            {
                "window_id": window_id,
                "host": host.upper(),
                "matched_task_ids": task_ids,
                "top_paths": [_claim_rule_trace_entry(row) for row in top_reports],
            }
        )
        family_tag_rows.append(
            {
                "window_id": window_id,
                "host": host.upper(),
                "matched_task_ids": task_ids,
                "top_paths": [_family_tag_trace_entry(row) for row in top_reports],
            }
        )
        mapping_constraint_rows.append(
            {
                "window_id": window_id,
                "host": host.upper(),
                "matched_task_ids": task_ids,
                "top_paths": [_mapping_constraint_trace_entry(row) for row in top_reports],
            }
        )
        candidate_tactics = _canonical_tactic_values(
            coverage_row.get("candidate_tactics_union_top_n", [])
            or _union_from_reports(top_reports, "candidate_tactics")
        )
        predicted_tactics = _canonical_tactic_values(_union_from_reports(top_reports, "predicted_tactics"))
        family_tags = _unique_strings(_union_from_reports(top_reports, "family_tags"))
        claim_types = _unique_strings(_union_from_reports(top_reports, "claim_types"))
        matched_tactics = [t for t in gt_tactics if t in predicted_tactics]
        missed_tactics = [t for t in gt_tactics if t not in predicted_tactics]
        extra_tactics = [t for t in predicted_tactics if t not in gt_tactics]

        behavior_rows: list[dict[str, Any]] = []
        for behavior in raw_window.get("behavior_chain", []) if isinstance(raw_window, dict) else []:
            if not isinstance(behavior, dict):
                continue
            hint_tactics = _behavior_tactic_hints(behavior, gt_tactics)
            family_hints, claim_hints = _tactic_hint_sets(hint_tactics)
            family_hits = sorted(family_hints.intersection(family_tags))
            claim_hits = sorted(claim_hints.intersection(claim_types))
            candidate_hits = sorted(set(hint_tactics).intersection(candidate_tactics))
            predicted_hits = sorted(set(hint_tactics).intersection(predicted_tactics))
            if not task_ids:
                root_cause = "task_selection_or_split"
            elif predicted_hits:
                root_cause = "captured"
            elif candidate_hits:
                root_cause = "mapping_or_validation"
            elif claim_hits:
                root_cause = "attack_candidate_retrieval"
            elif family_hits:
                root_cause = "claim_generation"
            else:
                root_cause = "candidate_path_or_family_tag"
            root_cause_counter[root_cause] += 1
            behavior_rows.append(
                {
                    "behavior_id": str(behavior.get("behavior_id", "")).strip(),
                    "action": str(behavior.get("action", "")).strip(),
                    "judgment": str(behavior.get("judgment", "")).strip(),
                    "mapped_tactics": hint_tactics,
                    "evidence_ids": _unique_strings(behavior.get("evidence_ids", []) or []),
                    "task_ids": task_ids,
                    "top_path_ids": [row.get("path_id") for row in top_reports],
                    "family_hits": family_hits,
                    "claim_hits": claim_hits,
                    "candidate_tactic_hits": candidate_hits,
                    "predicted_tactic_hits": predicted_hits,
                    "root_cause": root_cause,
                }
            )

        for tactic in extra_tactics:
            support_rows = [row for row in top_reports if tactic in row.get("predicted_tactics", [])]
            root_cause = _root_cause_for_extra_tactic(
                tactic,
                candidate_tactics=candidate_tactics,
                claim_types=claim_types,
            )
            root_cause_counter[root_cause] += 1
            false_positive_rows.append(
                {
                    "window_id": window_id,
                    "tactic": tactic,
                    "root_cause": root_cause,
                    "matched_task_ids": task_ids,
                    "candidate_tactics_union_top_n": candidate_tactics,
                    "support_paths": [_path_autopsy_entry(row) for row in support_rows],
                }
            )

        for tactic in missed_tactics:
            root_cause = _root_cause_for_missed_tactic(
                tactic,
                task_ids=task_ids,
                candidate_tactics=candidate_tactics,
                predicted_tactics=predicted_tactics,
                family_tags=family_tags,
                claim_types=claim_types,
            )
            root_cause_counter[root_cause] += 1
            false_negative_rows.append(
                {
                    "window_id": window_id,
                    "tactic": tactic,
                    "root_cause": root_cause,
                    "matched_task_ids": task_ids,
                    "candidate_tactics_union_top_n": candidate_tactics,
                    "family_tags_union": family_tags,
                    "claim_types_union": claim_types,
                    "top_paths": [_path_autopsy_entry(row) for row in top_reports],
                }
            )

        window_rows.append(
            {
                "window_id": window_id,
                "host": host.upper(),
                "status": str(getattr(window, "status", "")).strip(),
                "base_start_time": str(raw_window.get("start_time", "")).strip(),
                "base_end_time": str(raw_window.get("end_time", "")).strip(),
                "effective_start_time": str(getattr(window, "start_time", "") or ""),
                "effective_end_time": str(getattr(window, "end_time", "") or ""),
                "gt_tactics": gt_tactics,
                "attempted_tactics": attempted_tactics,
                "matched_task_ids": task_ids,
                "top_path_ids": [row.get("path_id") for row in top_reports],
                "candidate_tactics_union_top_n": candidate_tactics,
                "predicted_tactics_union_top_n": predicted_tactics,
                "matched_tactics": matched_tactics,
                "missed_tactics": missed_tactics,
                "extra_tactics": extra_tactics,
                "family_tags_union": family_tags,
                "claim_types_union": claim_types,
                "window_metrics": metrics_row,
                "behavior_rows": behavior_rows,
            }
        )

    return {
        "artifacts_root": str(artifacts_root),
        "gt_json_path": str(gt_json_path),
        "host": host.upper(),
        "gt_time_offset_minutes_applied": int(gt_time_offset_minutes),
        "limit_top_paths_per_window": int(limit_top_paths_per_window),
        "windows": window_rows,
        "false_positive_rows": false_positive_rows,
        "false_negative_rows": false_negative_rows,
        "claim_rule_rows": claim_rule_rows,
        "family_tag_rows": family_tag_rows,
        "mapping_constraint_rows": mapping_constraint_rows,
        "root_cause_counts": dict(root_cause_counter),
    }


def _markdown_table(result: dict[str, Any]) -> str:
    lines = [
        f"# {result['host']} Window Tactic Table",
        "",
        f"- gt_time_offset_minutes_applied: `{result['gt_time_offset_minutes_applied']}`",
        "",
        "| window_id | status | gt_tactics | matched | missed | extra | tasks | top_paths |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in result.get("windows", []):
        lines.append(
            "| {window_id} | {status} | {gt} | {matched} | {missed} | {extra} | {tasks} | {paths} |".format(
                window_id=row.get("window_id", ""),
                status=row.get("status", ""),
                gt=", ".join(row.get("gt_tactics", [])) or "-",
                matched=", ".join(row.get("matched_tactics", [])) or "-",
                missed=", ".join(row.get("missed_tactics", [])) or "-",
                extra=", ".join(row.get("extra_tactics", [])) or "-",
                tasks=", ".join(row.get("matched_task_ids", [])) or "-",
                paths=", ".join(row.get("top_path_ids", [])) or "-",
            )
        )
    lines.extend(["", "## Root Cause Counts", ""])
    for root_cause, count in sorted((result.get("root_cause_counts", {}) or {}).items()):
        lines.append(f"- `{root_cause}`: {count}")
    lines.append("")
    return "\n".join(lines)


def _root_cause_markdown(result: dict[str, Any]) -> str:
    lines = [
        f"# {result['host']} Rule-Level Root Cause Summary",
        "",
        f"- artifacts_root: `{result['artifacts_root']}`",
        f"- gt_time_offset_minutes_applied: `{result['gt_time_offset_minutes_applied']}`",
        "",
        "## Missed Tactics",
        "",
    ]
    for row in result.get("false_negative_rows", []):
        lines.extend(
            [
                f"- `{row['window_id']}` / `{row['tactic']}` -> `{row['root_cause']}`",
                f"  tasks={', '.join(row.get('matched_task_ids', [])) or '-'}",
                f"  candidate_tactics={', '.join(row.get('candidate_tactics_union_top_n', [])) or '-'}",
                f"  family_tags={', '.join(row.get('family_tags_union', [])) or '-'}",
                f"  claim_types={', '.join(row.get('claim_types_union', [])) or '-'}",
            ]
        )
    lines.extend(["", "## Extra Tactics", ""])
    for row in result.get("false_positive_rows", []):
        lines.extend(
            [
                f"- `{row['window_id']}` / `{row['tactic']}` -> `{row['root_cause']}`",
                f"  tasks={', '.join(row.get('matched_task_ids', [])) or '-'}",
                f"  candidate_tactics={', '.join(row.get('candidate_tactics_union_top_n', [])) or '-'}",
            ]
        )
        for path in row.get("support_paths", [])[:3]:
            lines.append(
                f"  support_path={path.get('path_id')} families={', '.join(path.get('family_tags', [])) or '-'} "
                f"claims={', '.join(path.get('claim_types', [])) or '-'} service_heavy={path.get('service_heavy')}"
            )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze path-reason behavior capture and tactic errors.")
    parser.add_argument("--artifacts-dir", required=True)
    parser.add_argument("--gt-json-path", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--gt-time-offset-minutes", type=int, default=0)
    parser.add_argument("--top-n-paths-per-window", type=int, default=5)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    result = build_behavior_capture(
        artifacts_root=Path(args.artifacts_dir),
        gt_json_path=Path(args.gt_json_path),
        host=str(args.host).strip(),
        gt_time_offset_minutes=int(args.gt_time_offset_minutes),
        limit_top_paths_per_window=max(1, int(args.top_n_paths_per_window)),
    )

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    matrix_path = output_dir / "window_behavior_capture_matrix.json"
    fp_path = output_dir / "false_positive_path_autopsy.json"
    fn_path = output_dir / "false_negative_behavior_autopsy.json"
    claim_path = output_dir / "claim_rule_trace.json"
    family_path = output_dir / "family_tag_trace.json"
    mapping_path = output_dir / "mapping_constraint_trace.json"
    summary_md_path = output_dir / "window_behavior_capture_summary.md"
    root_md_path = output_dir / "rule_level_root_cause_summary.md"

    _write_json(matrix_path, result.get("windows", []))
    _write_json(fp_path, result.get("false_positive_rows", []))
    _write_json(fn_path, result.get("false_negative_rows", []))
    _write_json(claim_path, result.get("claim_rule_rows", []))
    _write_json(family_path, result.get("family_tag_rows", []))
    _write_json(mapping_path, result.get("mapping_constraint_rows", []))
    summary_md_path.write_text(_markdown_table(result), encoding="utf-8")
    root_md_path.write_text(_root_cause_markdown(result), encoding="utf-8")

    print(
        json.dumps(
            {
                "window_behavior_capture_matrix": str(matrix_path),
                "false_positive_path_autopsy": str(fp_path),
                "false_negative_behavior_autopsy": str(fn_path),
                "claim_rule_trace": str(claim_path),
                "family_tag_trace": str(family_path),
                "mapping_constraint_trace": str(mapping_path),
                "window_behavior_capture_summary": str(summary_md_path),
                "rule_level_root_cause_summary": str(root_md_path),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
