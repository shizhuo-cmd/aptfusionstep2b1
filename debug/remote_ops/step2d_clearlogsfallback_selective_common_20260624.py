from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

_THIS_FILE = Path(__file__).resolve()
_REPO_ROOT = _THIS_FILE.parents[2]
_SRC_ROOT = _REPO_ROOT / "src"
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from apt_fusion.config import FusionConfig, load_config
from apt_fusion.evaluation.path_reason_eval import apply_gt_time_offset, load_gt_reference, run_evaluation
from apt_fusion.path_reason.holmes_claims import build_holmes_claim_graph
from apt_fusion.path_reason.module6_attack_reason import _slugify, run_module6_reason


def _clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def _link_dir(source: Path, target: Path) -> None:
    if not source.exists():
        raise FileNotFoundError(f"Missing reused artifact directory: {source}")
    if target.exists():
        shutil.rmtree(target)
    target.symlink_to(source, target_is_directory=True)


def _copy_dir(source: Path, target: Path) -> None:
    if not source.exists():
        raise FileNotFoundError(f"Missing source directory: {source}")
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target)


def _git_text(repo_root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip()


def working_tree_fingerprint(repo_root: Path) -> dict[str, Any]:
    status_lines = [line for line in _git_text(repo_root, "status", "--short").splitlines() if line.strip()]
    return {
        "code_baseline": "local_working_tree_snapshot",
        "head_commit": _git_text(repo_root, "rev-parse", "HEAD"),
        "git_status_short": status_lines,
        "git_status_count": len(status_lines),
    }


def find_affected_tasks(reused_source_root: Path) -> dict[str, Any]:
    candidate_dir = reused_source_root / "module5_paths" / "candidate_paths"
    reports_dir = reused_source_root / "module6_reason" / "reports"
    affected: list[dict[str, Any]] = []
    per_task: dict[str, dict[str, Any]] = {}
    for candidate_file in sorted(candidate_dir.glob("*.json")):
        payload = json.loads(candidate_file.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            continue
        for item in payload:
            if not isinstance(item, dict):
                continue
            dossier = item.get("dossier", {})
            if not isinstance(dossier, dict):
                continue
            task_id = str(dossier.get("task_id", "")).strip()
            path_id = str(dossier.get("path_id", "")).strip()
            if not task_id or not path_id:
                continue
            report_path = reports_dir / f"{_slugify(path_id)}.report.json"
            if not report_path.exists():
                continue
            report = json.loads(report_path.read_text(encoding="utf-8"))
            old_behavior_types = {
                str(claim.get("behavior_type", "")).strip()
                for claim in report.get("claims", [])
                if isinstance(claim, dict) and str(claim.get("behavior_type", "")).strip()
            }
            new_behavior_types = {
                str(claim.get("behavior_type", "")).strip()
                for claim in build_holmes_claim_graph(dossier).get("claims", [])
                if isinstance(claim, dict) and str(claim.get("behavior_type", "")).strip()
            }
            if "clear_logs" not in new_behavior_types or "clear_logs" in old_behavior_types:
                continue
            record = {
                "task_id": task_id,
                "path_id": path_id,
                "candidate_file": str(candidate_file),
                "report_path": str(report_path),
                "family_tags": [str(tag) for tag in dossier.get("family_tags", []) if str(tag).strip()],
                "followup_event_count": len([x for x in dossier.get("followup_event_ids", []) if str(x).strip()]),
                "cleanup_object_summary": str(dossier.get("cleanup_object_summary", "")).strip(),
                "object_lineage_summary": str(dossier.get("object_lineage_summary", "")).strip(),
            }
            affected.append(record)
            bucket = per_task.setdefault(
                task_id,
                {"task_id": task_id, "candidate_file": str(candidate_file), "path_ids": []},
            )
            bucket["path_ids"].append(path_id)
    return {
        "artifacts_root": str(reused_source_root),
        "affected_path_count": len(affected),
        "affected_task_count": len(per_task),
        "affected_tasks": list(per_task.values()),
        "affected_paths": affected,
    }


def _copy_selected_candidate_files(source_root: Path, dest_root: Path, candidate_files: Iterable[str]) -> None:
    candidate_dir = dest_root / "module5_paths" / "candidate_paths"
    candidate_dir.mkdir(parents=True, exist_ok=True)
    for path_str in candidate_files:
        source_path = Path(path_str)
        if not source_path.exists():
            raise FileNotFoundError(f"Missing candidate file for selective rerun: {source_path}")
        shutil.copy2(source_path, candidate_dir / source_path.name)
    summary_src = source_root / "module5_paths" / "summary.json"
    if summary_src.exists():
        shutil.copy2(summary_src, dest_root / "module5_paths" / "summary.json")


def _overlay_dir(source_dir: Path, target_dir: Path) -> None:
    if not source_dir.exists():
        return
    target_dir.mkdir(parents=True, exist_ok=True)
    for source_path in source_dir.glob("*"):
        if source_path.is_dir():
            continue
        shutil.copy2(source_path, target_dir / source_path.name)


def _rebuild_report_index(target_root: Path) -> None:
    module6_root = target_root / "module6_reason"
    reports_dir = module6_root / "reports"
    dossiers_dir = module6_root / "dossiers"
    markdown_dir = module6_root / "markdown"
    llm_inputs_dir = module6_root / "llm_inputs"
    claim_graphs_dir = module6_root / "claim_graphs"
    report_index: list[dict[str, Any]] = []
    for report_path in sorted(reports_dir.glob("*.report.json")):
        report = json.loads(report_path.read_text(encoding="utf-8"))
        path_id = str(report.get("path_id", "")).strip()
        task_id = str(report.get("task_id", "")).strip()
        if not path_id or not task_id:
            continue
        slug = _slugify(path_id)
        report_index.append(
            {
                "task_id": task_id,
                "path_id": path_id,
                "report_path": str(report_path),
                "dossier_path": str(dossiers_dir / f"{slug}.json"),
                "markdown_path": str(markdown_dir / f"{slug}.md"),
                "llm_input_path": str(llm_inputs_dir / f"{slug}.input.json"),
                "claim_graph_path": str(claim_graphs_dir / f"{slug}.claim_graph.json"),
            }
        )
    (module6_root / "report_index.json").write_text(
        json.dumps(report_index, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    summary = {
        "report_count": len(report_index),
        "reports_dir": str(reports_dir),
        "dossiers_dir": str(dossiers_dir),
        "markdown_dir": str(markdown_dir),
        "llm_inputs_dir": str(llm_inputs_dir),
        "claim_graphs_dir": str(claim_graphs_dir),
        "selective_refresh": True,
    }
    (module6_root / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")


def _evaluate(cfg: FusionConfig, gt_json_path: Path, gt_time_offset_minutes: int) -> tuple[dict[str, Any], dict[str, str]]:
    strict_windows, technique_defs, _ = load_gt_reference(gt_json_path, host_filter=cfg.host.upper())
    apply_gt_time_offset(strict_windows, minutes=gt_time_offset_minutes)
    output_dir = cfg.artifacts_dir / "path_reason_eval_tactics_only_llm"
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
    metrics = json.loads(Path(outputs["metrics_summary"]).read_text(encoding="utf-8"))
    return metrics, outputs


def run_selective_refresh(
    *,
    local_repo_root: Path,
    remote_repo_root: Path,
    config_path: Path,
    reused_source_root: Path,
    target_root: Path,
    gt_json_path: Path,
    gt_time_offset_minutes: int,
    analysis_script: Path,
    analysis_output_dir: Path,
    host_name: str,
    experiment_step: str,
) -> dict[str, Any]:
    affected = find_affected_tasks(reused_source_root)
    _clean_dir(target_root)
    target_root.mkdir(parents=True, exist_ok=True)
    _link_dir(reused_source_root / "module5_paths", target_root / "module5_paths")
    _copy_dir(reused_source_root / "module6_reason", target_root / "module6_reason")

    selected_candidate_files = [row["candidate_file"] for row in affected["affected_tasks"]]
    temp_root = target_root / "_selective_rerun"
    selective_outputs: dict[str, Any] = {}
    if selected_candidate_files:
        _clean_dir(temp_root)
        _copy_selected_candidate_files(reused_source_root, temp_root, selected_candidate_files)
        cfg_rerun = load_config(config_path)
        cfg_rerun.artifacts_dir = temp_root
        selective_outputs = run_module6_reason(cfg_rerun)
        rerun_module6_root = temp_root / "module6_reason"
        for name in ("reports", "dossiers", "markdown", "llm_inputs", "claim_graphs"):
            _overlay_dir(rerun_module6_root / name, target_root / "module6_reason" / name)
    _rebuild_report_index(target_root)

    cfg = load_config(config_path)
    cfg.artifacts_dir = target_root
    _clean_dir(cfg.artifacts_dir / "path_reason_eval_tactics_only_llm")
    metrics, eval_outputs = _evaluate(cfg, gt_json_path, gt_time_offset_minutes)

    _clean_dir(analysis_output_dir)
    analysis_output_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            sys.executable,
            str(analysis_script),
            "--artifacts-dir",
            str(target_root),
            "--gt-json-path",
            str(gt_json_path),
            "--host",
            host_name,
            "--gt-time-offset-minutes",
            str(gt_time_offset_minutes),
            "--output-dir",
            str(analysis_output_dir),
        ],
        check=True,
    )
    _clean_dir(temp_root)

    provenance = {
        "experiment_step": experiment_step,
        "local_repo_root": str(local_repo_root),
        "remote_repo_root": str(remote_repo_root),
        "config_template_path": str(config_path),
        "artifacts_dir": str(target_root),
        "gt_json_path": str(gt_json_path),
        "gt_time_offset_minutes_applied": gt_time_offset_minutes,
        "reused_source_root": str(reused_source_root),
        "reused_dir_names": ["module5_paths", "module6_reason"],
        "selective_refresh": True,
        "affected_summary": affected,
        "selected_candidate_file_count": len(selected_candidate_files),
        "rerun_modules": ["module6_reason(selected_tasks_only)", "path_reason_eval"],
        "analysis_script": str(analysis_script),
        "analysis_output_dir": str(analysis_output_dir),
        "module6_outputs": {key: str(value) for key, value in selective_outputs.items()},
        "eval_outputs": eval_outputs,
        "metrics": metrics,
    }
    (target_root / "provenance_summary.json").write_text(
        json.dumps(provenance, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (target_root / "working_tree_fingerprint.json").write_text(
        json.dumps(working_tree_fingerprint(remote_repo_root), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return provenance
