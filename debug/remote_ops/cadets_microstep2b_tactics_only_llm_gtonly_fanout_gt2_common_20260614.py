from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_THIS_FILE = Path(__file__).resolve()
_REPO_ROOT = _THIS_FILE.parents[2]
_SRC_ROOT = _REPO_ROOT / "src"
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from apt_fusion.common import iter_jsonl, load_json, save_json
from apt_fusion.config import FusionConfig, load_config, resolve_attack_eval_gt_json
from apt_fusion.evaluation.path_reason_eval import (
    _canonical_tactic_name,
    apply_gt_time_offset,
    load_gt_reference,
    run_evaluation,
)
from apt_fusion.path_reason.module3_evidence_recover import run_module3_evidence
from apt_fusion.path_reason.module4_semantic_compact import run_module4_compact
from apt_fusion.path_reason.module5_path_finder import run_module5_paths
from apt_fusion.path_reason.module6_attack_reason import run_module6_reason
from apt_fusion.task_detection.module1_online_graph import run_module1
from apt_fusion.task_detection.module2_online_detection import run_module2


LOCAL_REPO_ROOT = Path(r"D:\daima\APT-Fusionstep2b1")
REMOTE_REPO_ROOT = Path("/root/autodl-tmp/APT-Fusionstep2b1")
GT_JSON_PATH = resolve_attack_eval_gt_json(REMOTE_REPO_ROOT)
CADETS_LOGS_RAR = Path("/root/autodl-tmp/data/cadets/logs.rar")
CADETS_LOGS_DIR = Path("/root/autodl-tmp/data/cadets/logs")
EVAL_DIR_NAME = "path_reason_eval_tactics_only_llm"
_AUGMENTED_TASK_ID_PATTERN = re.compile(r"_aug\d{3}$", re.IGNORECASE)


def _resolve_repo_path(path: str | Path) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    return REMOTE_REPO_ROOT / candidate


def _clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _resolve_metrics_summary(root: Path) -> Path:
    direct = root / "metrics_summary.json"
    if direct.exists():
        return direct
    candidates = sorted(root.rglob("metrics_summary.json"), key=lambda item: (len(item.parts), str(item)))
    if not candidates:
        raise FileNotFoundError(f"metrics_summary.json not found under: {root}")
    return candidates[0]


def _load_metrics(path: Path) -> dict[str, Any]:
    return _load_json(path)


def _has_log_files(directory: Path) -> bool:
    if not directory.exists() or not directory.is_dir():
        return False
    for item in directory.rglob("*"):
        if item.is_file():
            return True
    return False


def _run_subprocess(command: list[str], *, cwd: Path | None = None) -> None:
    subprocess.run(command, check=True, cwd=str(cwd) if cwd is not None else None)


def _normalize_extracted_cadets_layout() -> None:
    if _has_log_files(CADETS_LOGS_DIR):
        return
    parent_dir = CADETS_LOGS_DIR.parent
    extracted_files = sorted(parent_dir.glob("ta1-cadets-e3-official-*.json"))
    if not extracted_files:
        return
    CADETS_LOGS_DIR.mkdir(parents=True, exist_ok=True)
    for path in extracted_files:
        shutil.move(str(path), str(CADETS_LOGS_DIR / path.name))


def ensure_cadets_logs_ready() -> dict[str, Any]:
    preexisting = _has_log_files(CADETS_LOGS_DIR)
    extracted_this_run = False
    extract_tool = ""
    if preexisting:
        return {
            "cadets_logs_rar_path": str(CADETS_LOGS_RAR),
            "cadets_logs_dir": str(CADETS_LOGS_DIR),
            "cadets_logs_preexisting": True,
            "cadets_logs_extracted_this_run": False,
            "cadets_logs_ready": True,
            "cadets_extract_tool": "",
        }
    if not CADETS_LOGS_RAR.exists():
        raise FileNotFoundError(f"CADETS logs archive not found: {CADETS_LOGS_RAR}")
    if CADETS_LOGS_DIR.exists():
        shutil.rmtree(CADETS_LOGS_DIR)
    parent_dir = CADETS_LOGS_DIR.parent
    parent_dir.mkdir(parents=True, exist_ok=True)
    unrar_path = shutil.which("unrar")
    seven_zip_path = shutil.which("7z")
    if unrar_path:
        extract_tool = "unrar"
        command = [unrar_path, "x", "-o+", str(CADETS_LOGS_RAR), str(parent_dir)]
    elif seven_zip_path:
        extract_tool = "7z"
        command = [seven_zip_path, "x", "-y", f"-o{parent_dir}", str(CADETS_LOGS_RAR)]
    else:
        raise FileNotFoundError("Neither 'unrar' nor '7z' is available on the remote server.")
    _run_subprocess(command, cwd=parent_dir)
    extracted_this_run = True
    _normalize_extracted_cadets_layout()
    ready = _has_log_files(CADETS_LOGS_DIR)
    if not ready:
        raise FileNotFoundError(f"CADETS logs directory is still empty after extraction: {CADETS_LOGS_DIR}")
    return {
        "cadets_logs_rar_path": str(CADETS_LOGS_RAR),
        "cadets_logs_dir": str(CADETS_LOGS_DIR),
        "cadets_logs_preexisting": False,
        "cadets_logs_extracted_this_run": extracted_this_run,
        "cadets_logs_ready": ready,
        "cadets_extract_tool": extract_tool,
    }


def _load_gt(host: str) -> tuple[list[Any], dict[str, list[str]]]:
    strict_windows, technique_defs, metadata = load_gt_reference(GT_JSON_PATH, host_filter=host)
    offsets = metadata.get("recommended_gt_time_offset_minutes_by_host", {})
    if isinstance(offsets, dict):
        offset = offsets.get(host)
        if offset:
            apply_gt_time_offset(strict_windows, minutes=int(offset))
    return strict_windows, technique_defs


def _evaluate(cfg: FusionConfig) -> tuple[dict[str, Any], dict[str, str]]:
    strict_windows, technique_defs = _load_gt(cfg.host.upper())
    output_dir = cfg.artifacts_dir / EVAL_DIR_NAME
    outputs = run_evaluation(
        artifacts_dir=cfg.artifacts_dir,
        strict_windows=strict_windows,
        technique_defs=technique_defs,
        output_dir=output_dir,
        host=cfg.host.upper(),
        match_top_n=5,
        pad_minutes=5,
        near_miss_minutes=5,
    )
    return _load_metrics(Path(outputs["metrics_summary"])), outputs


def _stringify_paths(payload: dict[str, Any]) -> dict[str, str]:
    return {key: str(value) for key, value in payload.items()}


def run_single_experiment(config_path: str | Path) -> dict[str, Any]:
    config_path = _resolve_repo_path(config_path)
    logs_provenance = ensure_cadets_logs_ready()
    cfg = load_config(config_path)
    _clean_dir(cfg.artifacts_dir)
    cfg.artifacts_dir.mkdir(parents=True, exist_ok=True)

    out1 = run_module1(cfg)
    out2 = run_module2(
        cfg=cfg,
        embeddings_path=out1["process_embeddings"],
        task_path=out1["task_subgraphs"],
        segmentation_edges_path=out1["process_segmentation_edges"],
    )
    out3 = run_module3_evidence(
        cfg,
        suspicious_tasks_path=Path(out2["suspicious_tasks"]),
        task_meta_rich_path=Path(out2["task_meta_rich"]),
        task_attribution_path=Path(out2["task_attribution"]),
    )
    out4 = run_module4_compact(cfg)
    out5 = run_module5_paths(cfg)
    out6 = run_module6_reason(cfg)
    metrics, eval_outputs = _evaluate(cfg)

    provenance = {
        "local_repo_root": str(LOCAL_REPO_ROOT),
        "remote_repo_root": str(REMOTE_REPO_ROOT),
        "config_path": str(config_path),
        "artifacts_dir": str(cfg.artifacts_dir),
        "task_component_split_mode": cfg.task_component_split_mode,
        "task_component_child_threshold": int(cfg.task_component_child_threshold),
        "task_component_count_segmented_children_upstream": bool(
            cfg.task_component_count_segmented_children_upstream
        ),
        "task_tapas_augmentation_enabled": bool(cfg.task_tapas_augmentation_enabled),
        "claim_attack_prior_mode": str(cfg.claim_attack_prior_mode),
        "attack_mapping_scope": str(cfg.attack_mapping_scope),
        "tactic_mapping_mode": str(cfg.tactic_mapping_mode),
        **logs_provenance,
        "module1_outputs": _stringify_paths(out1),
        "module2_outputs": _stringify_paths(out2),
        "module3_outputs": _stringify_paths(out3),
        "module4_outputs": _stringify_paths(out4),
        "module5_outputs": _stringify_paths(out5),
        "module6_outputs": _stringify_paths(out6),
        "eval_outputs": eval_outputs,
    }
    provenance_path = cfg.artifacts_dir / "provenance_summary.json"
    decision_path = cfg.artifacts_dir / "decision_summary.json"
    _write_json(provenance_path, provenance)
    summary = {
        "provenance_summary": str(provenance_path),
        "metrics": metrics,
        "module1_outputs": _stringify_paths(out1),
        "module2_outputs": _stringify_paths(out2),
        "module3_outputs": _stringify_paths(out3),
        "module4_outputs": _stringify_paths(out4),
        "module5_outputs": _stringify_paths(out5),
        "module6_outputs": _stringify_paths(out6),
        "eval_outputs": eval_outputs,
    }
    _write_json(decision_path, summary)
    return summary


def _task_slug(task_id: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in str(task_id)).strip("_") or "task"


def _is_augmented_task_id(task_id: str) -> bool:
    return bool(_AUGMENTED_TASK_ID_PATTERN.search(str(task_id).strip()))


def _parse_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is not None:
            return parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except ValueError:
        return None


def _time_span_minutes(start: datetime | None, end: datetime | None) -> float:
    if start is None or end is None:
        return 0.0
    return max(0.0, float((end - start).total_seconds()) / 60.0)


def _task_meta_by_id(artifacts_root: Path) -> dict[str, dict[str, Any]]:
    path = artifacts_root / "module2" / "task_meta_rich.json"
    rows = _load_json(path)
    return {
        str(row.get("task_id", "")).strip(): row
        for row in rows
        if isinstance(row, dict) and str(row.get("task_id", "")).strip()
    }


def _gt_positive_base_task_ids(artifacts_root: Path) -> list[str]:
    path = artifacts_root / "module2" / "suspicious_tasks.json"
    rows = _load_json(path)
    output: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        task_id = str(row.get("task_id", "")).strip()
        if not task_id or _is_augmented_task_id(task_id):
            continue
        if int(row.get("task_label", 0) or 0) != 1:
            continue
        output.append(task_id)
    return output


def _task_graph_counts(artifacts_root: Path, task_id: str) -> dict[str, Any]:
    slug = _task_slug(task_id)
    graph_path = artifacts_root / "module3_evidence" / "task_local_evidence_graph" / f"{slug}.json"
    normalized_events_path = artifacts_root / "module3_evidence" / "normalized_events" / f"{slug}.jsonl"
    graph = _load_json(graph_path) if graph_path.exists() else {}
    start_time: datetime | None = None
    end_time: datetime | None = None
    if normalized_events_path.exists():
        for row in iter_jsonl(normalized_events_path):
            timestamp = _parse_datetime(row.get("timestamp"))
            if timestamp is None:
                continue
            if start_time is None or timestamp < start_time:
                start_time = timestamp
            if end_time is None or timestamp > end_time:
                end_time = timestamp
    return {
        "process_node_count": len(graph.get("process_nodes", []) or []),
        "object_node_count": len(graph.get("object_nodes", []) or []),
        "event_edge_count": len(graph.get("event_edges", []) or []),
        "start_time": start_time.isoformat() if start_time else "",
        "end_time": end_time.isoformat() if end_time else "",
        "time_span_minutes": _time_span_minutes(start_time, end_time),
    }


def _reports_by_task(artifacts_root: Path) -> dict[str, list[dict[str, Any]]]:
    report_index_path = artifacts_root / "module6_reason" / "report_index.json"
    if not report_index_path.exists():
        return {}
    rows = _load_json(report_index_path)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        task_id = str(row.get("task_id", "")).strip()
        report_path = Path(str(row.get("report_path", "")).strip())
        dossier_path = Path(str(row.get("dossier_path", "")).strip())
        if not task_id or not report_path.exists() or not dossier_path.exists():
            continue
        report = _load_json(report_path)
        dossier = _load_json(dossier_path)
        grouped.setdefault(task_id, []).append(
            {
                "path_id": str(row.get("path_id", "")).strip(),
                "report": report,
                "dossier": dossier,
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


def _task_candidate_path_count(artifacts_root: Path, task_id: str) -> int:
    candidate_path = artifacts_root / "module5_paths" / "candidate_paths" / f"{_task_slug(task_id)}.json"
    if not candidate_path.exists():
        return 0
    payload = _load_json(candidate_path)
    return len(payload) if isinstance(payload, list) else 0


def _windows_for_task(
        task_time_range: tuple[datetime | None, datetime | None],
        strict_windows: list[Any],
        *,
        pad_minutes: int = 5,
) -> list[Any]:
    start_time, end_time = task_time_range
    if start_time is None or end_time is None:
        return []
    if start_time.tzinfo is not None:
        start_time = start_time.astimezone(timezone.utc).replace(tzinfo=None)
    if end_time.tzinfo is not None:
        end_time = end_time.astimezone(timezone.utc).replace(tzinfo=None)
    padding = timedelta(minutes=int(pad_minutes))
    matches: list[Any] = []
    for window in strict_windows:
        if str(window.status).strip().lower() != "confirmed":
            continue
        window_start = window.start_time
        window_end = window.end_time
        if window_start.tzinfo is not None:
            window_start = window_start.astimezone(timezone.utc).replace(tzinfo=None)
        if window_end.tzinfo is not None:
            window_end = window_end.astimezone(timezone.utc).replace(tzinfo=None)
        window_start = window_start - padding
        window_end = window_end + padding
        if start_time <= window_end and end_time >= window_start:
            matches.append(window)
    return matches


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


def _task_chain_diagnostics(artifacts_root: Path, strict_windows: list[Any]) -> list[dict[str, Any]]:
    meta_by_task = _task_meta_by_id(artifacts_root)
    reports_by_task = _reports_by_task(artifacts_root)
    diagnostics: list[dict[str, Any]] = []
    for task_id in _gt_positive_base_task_ids(artifacts_root):
        graph_counts = _task_graph_counts(artifacts_root, task_id)
        start_time = _parse_datetime(graph_counts.get("start_time", ""))
        end_time = _parse_datetime(graph_counts.get("end_time", ""))
        matched_windows = _windows_for_task((start_time, end_time), strict_windows)
        matched_window_ids = [str(window.window_id) for window in matched_windows]
        gt_tactics = sorted(
            {
                _canonical_tactic_name(tactic)
                for window in matched_windows
                for tactic in getattr(window, "confirmed_tactics", []) or []
                if _canonical_tactic_name(tactic)
            }
        )
        report_items = list(reports_by_task.get(task_id, []))[:5]
        predicted_tactics: list[str] = []
        family_tags_union: set[str] = set()
        support_event_ids_union: set[str] = set()
        has_precursor = False
        has_followup = False
        has_network_support = False
        has_object_lineage = False
        coverage_flags = {
            "family_tags": False,
            "support_event_ids": False,
            "precursor_event_ids": False,
            "followup_event_ids": False,
            "network_support_summary": False,
            "object_lineage_summary": False,
        }
        top5_path_ids: list[str] = []
        for item in report_items:
            dossier = item.get("dossier", {}) or {}
            report = item.get("report", {}) or {}
            path_id = str(item.get("path_id", "")).strip()
            if path_id:
                top5_path_ids.append(path_id)
            for tactic in _canonical_tactics_from_report(report):
                if tactic and tactic not in predicted_tactics:
                    predicted_tactics.append(tactic)
            family_tags = [str(value).strip() for value in dossier.get("family_tags", []) or [] if str(value).strip()]
            support_event_ids = [
                str(value).strip() for value in dossier.get("support_event_ids", []) or [] if str(value).strip()
            ]
            precursor_event_ids = [
                str(value).strip() for value in dossier.get("precursor_event_ids", []) or [] if str(value).strip()
            ]
            followup_event_ids = [
                str(value).strip() for value in dossier.get("followup_event_ids", []) or [] if str(value).strip()
            ]
            network_support_summary = str(dossier.get("network_support_summary", "")).strip()
            object_lineage_summary = str(dossier.get("object_lineage_summary", "")).strip()
            family_tags_union.update(family_tags)
            support_event_ids_union.update(support_event_ids)
            has_precursor = has_precursor or bool(precursor_event_ids)
            has_followup = has_followup or bool(followup_event_ids)
            has_network_support = has_network_support or bool(network_support_summary)
            has_object_lineage = has_object_lineage or bool(object_lineage_summary)
            coverage_flags["family_tags"] = coverage_flags["family_tags"] or bool(family_tags)
            coverage_flags["support_event_ids"] = coverage_flags["support_event_ids"] or bool(support_event_ids)
            coverage_flags["precursor_event_ids"] = coverage_flags["precursor_event_ids"] or bool(precursor_event_ids)
            coverage_flags["followup_event_ids"] = coverage_flags["followup_event_ids"] or bool(followup_event_ids)
            coverage_flags["network_support_summary"] = coverage_flags["network_support_summary"] or bool(
                network_support_summary
            )
            coverage_flags["object_lineage_summary"] = coverage_flags["object_lineage_summary"] or bool(
                object_lineage_summary
            )
        matched_tactics = [item for item in gt_tactics if item in predicted_tactics]
        diagnostics.append(
            {
                "task_id": task_id,
                "matched_window_ids": matched_window_ids,
                "gt_tactics": gt_tactics,
                "predicted_tactics_union_top5": predicted_tactics,
                "matched_tactics": matched_tactics,
                "missed_tactics": [item for item in gt_tactics if item not in matched_tactics],
                "extra_tactics": [item for item in predicted_tactics if item not in matched_tactics],
                "candidate_path_count": _task_candidate_path_count(artifacts_root, task_id),
                "top5_path_ids": top5_path_ids,
                "family_tags_union": sorted(family_tags_union),
                "support_event_count_union": len(support_event_ids_union),
                "has_precursor": has_precursor,
                "has_followup": has_followup,
                "has_network_support": has_network_support,
                "has_object_lineage": has_object_lineage,
                "evidence_section_coverage_top5": float(sum(1 for value in coverage_flags.values() if value) / 6.0),
            }
        )
    diagnostics.sort(key=lambda item: item["task_id"])
    return diagnostics


def _split_meta_summary(artifacts_root: Path) -> dict[str, dict[str, Any]]:
    meta_by_task = _task_meta_by_id(artifacts_root)
    output: dict[str, dict[str, Any]] = {}
    for task_id in _gt_positive_base_task_ids(artifacts_root):
        meta = meta_by_task.get(task_id, {})
        graph_counts = _task_graph_counts(artifacts_root, task_id)
        boundary_nodes = [str(item).strip() for item in meta.get("boundary_node_ids", []) if str(item).strip()]
        output[task_id] = {
            "task_id": task_id,
            "task_root_id": str(meta.get("task_root_id", "")).strip(),
            "boundary_node_count": len(boundary_nodes),
            "process_node_count": int(graph_counts.get("process_node_count", 0) or 0),
            "object_node_count": int(graph_counts.get("object_node_count", 0) or 0),
            "event_edge_count": int(graph_counts.get("event_edge_count", 0) or 0),
            "time_span_minutes": float(graph_counts.get("time_span_minutes", 0.0) or 0.0),
            "segmented_ancestor_count": len(boundary_nodes),
        }
    return output


def build_split_meta_compare(exclude_root: Path, include_root: Path) -> list[dict[str, Any]]:
    exclude_meta = _split_meta_summary(exclude_root)
    include_meta = _split_meta_summary(include_root)
    task_ids = sorted(set(exclude_meta) | set(include_meta))
    rows: list[dict[str, Any]] = []
    numeric_keys = [
        "boundary_node_count",
        "process_node_count",
        "object_node_count",
        "event_edge_count",
        "time_span_minutes",
        "segmented_ancestor_count",
    ]
    for task_id in task_ids:
        exclude_row = exclude_meta.get(task_id, {"task_id": task_id})
        include_row = include_meta.get(task_id, {"task_id": task_id})
        delta = {
            key: float(include_row.get(key, 0.0) or 0.0) - float(exclude_row.get(key, 0.0) or 0.0)
            for key in numeric_keys
        }
        rows.append(
            {
                "task_id": task_id,
                "exclude_segmented": exclude_row,
                "include_segmented": include_row,
                "delta": delta,
            }
        )
    return rows


def _mean_evidence_coverage(rows: list[dict[str, Any]]) -> float:
    if not rows:
        return 0.0
    return float(sum(float(row.get("evidence_section_coverage_top5", 0.0) or 0.0) for row in rows) / len(rows))


def select_better_variant(
        exclude_metrics: dict[str, Any],
        include_metrics: dict[str, Any],
        exclude_diag: list[dict[str, Any]],
        include_diag: list[dict[str, Any]],
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    exclude_window_recall = float(exclude_metrics.get("confirmed_window_recall", 0.0) or 0.0)
    include_window_recall = float(include_metrics.get("confirmed_window_recall", 0.0) or 0.0)
    if abs(exclude_window_recall - include_window_recall) > 1e-9:
        selected = "exclude_segmented" if exclude_window_recall > include_window_recall else "include_segmented"
        reasons.append("selected by confirmed_window_recall")
        return selected, reasons
    reasons.append("confirmed_window_recall tie")

    exclude_tactic_recall = float(exclude_metrics.get("strict_tactic_recall_macro", 0.0) or 0.0)
    include_tactic_recall = float(include_metrics.get("strict_tactic_recall_macro", 0.0) or 0.0)
    if abs(exclude_tactic_recall - include_tactic_recall) > 0.01:
        selected = "exclude_segmented" if exclude_tactic_recall > include_tactic_recall else "include_segmented"
        reasons.append("selected by strict_tactic_recall_macro")
        return selected, reasons
    reasons.append("strict_tactic_recall_macro within 0.01")

    exclude_noise = float(exclude_metrics.get("off_window_high_risk_rate", 0.0) or 0.0)
    include_noise = float(include_metrics.get("off_window_high_risk_rate", 0.0) or 0.0)
    if abs(exclude_noise - include_noise) > 1e-9:
        selected = "exclude_segmented" if exclude_noise < include_noise else "include_segmented"
        reasons.append("selected by lower off_window_high_risk_rate")
        return selected, reasons
    reasons.append("off_window_high_risk_rate tie")

    exclude_coverage = _mean_evidence_coverage(exclude_diag)
    include_coverage = _mean_evidence_coverage(include_diag)
    if abs(exclude_coverage - include_coverage) > 1e-9:
        selected = "exclude_segmented" if exclude_coverage > include_coverage else "include_segmented"
        reasons.append("selected by evidence_section_coverage_top5 mean")
        return selected, reasons
    reasons.append("evidence_section_coverage_top5 mean tie")
    reasons.append("fallback to current default exclude_segmented")
    return "exclude_segmented", reasons
