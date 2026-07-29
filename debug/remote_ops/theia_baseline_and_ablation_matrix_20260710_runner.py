from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
import traceback
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator

_THIS_FILE = Path(__file__).resolve()
_REPO_ROOT = _THIS_FILE.parents[2]
_SRC_ROOT = _REPO_ROOT / "src"
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from apt_fusion.config import load_config
from apt_fusion.evaluation.path_reason_eval import apply_gt_time_offset, load_gt_reference, run_evaluation
from apt_fusion.path_reason import module3_evidence_recover as module3_impl
from apt_fusion.path_reason import module4_semantic_compact as module4_impl
from apt_fusion.path_reason import module5_path_finder as module5_impl
from apt_fusion.path_reason import module6_attack_reason as module6_impl
from apt_fusion.task_detection.module1_online_graph import run_module1

EVAL_DIR_LLM = "path_reason_eval_tactics_only_llm"
EVAL_DIR_DETERMINISTIC = "path_reason_eval_tactics_only_deterministic"
MODULE3_PATH_FIELDS = [
    "normalized_events_path",
    "entity_index_path",
    "process_event_index_path",
    "object_event_index_path",
    "task_evidence_frontier_path",
    "task_local_evidence_graph_path",
]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run THEIA baseline and post-reason ablations.")
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--config-path", required=True)
    parser.add_argument("--gt-json-path", required=True)
    parser.add_argument("--gt-time-offset-minutes", type=int, default=240)
    parser.add_argument("--baseline-root", required=True)
    parser.add_argument("--variant-root-template", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--code-label", required=True)
    parser.add_argument("--baseline-mode", choices=["wait", "fresh"], required=True)
    parser.add_argument("--baseline-pid-file", default="")
    parser.add_argument("--wait-timeout-minutes", type=int, default=720)
    parser.add_argument("--poll-seconds", type=int, default=120)
    parser.add_argument("--local-repo-root", default=r"D:\daima\APT-Fusionstep2b1")
    return parser.parse_args()


def _clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def _copy_tree(source: Path, target: Path) -> None:
    if not source.exists():
        raise FileNotFoundError(f"Missing reused artifact directory: {source}")
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target)


def _symlink_dir(source: Path, target: Path) -> None:
    if not source.exists():
        raise FileNotFoundError(f"Missing reused artifact directory: {source}")
    if target.exists() or target.is_symlink():
        if target.is_symlink() or target.is_file():
            target.unlink()
        else:
            shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.symlink_to(source, target_is_directory=True)


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _save_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _git_text(repo_root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip()


def _working_tree_fingerprint(repo_root: Path, code_label: str) -> dict[str, Any]:
    status_lines = [line for line in _git_text(repo_root, "status", "--short").splitlines() if line.strip()]
    return {
        "code_baseline": code_label,
        "head_commit": _git_text(repo_root, "rev-parse", "HEAD"),
        "git_status_short": status_lines,
        "git_status_count": len(status_lines),
    }


def _rewrite_module3_task_index_paths(module3_dir: Path) -> dict[str, Any]:
    task_index_path = module3_dir / "task_index.json"
    rows = _load_json(task_index_path)
    rewritten = 0
    for row in rows:
        task_id = str(row.get("task_id", "")).strip()
        if not task_id:
            continue
        for field in MODULE3_PATH_FIELDS:
            original = str(row.get(field, "")).strip()
            if not original:
                continue
            suffix = Path(original).suffix or (".jsonl" if "normalized_events" in field else ".json")
            dirname = field.removesuffix("_path")
            row[field] = str(module3_dir / dirname / f"{task_id}{suffix}")
            rewritten += 1
    _save_json(task_index_path, rows)
    return {
        "task_index_path": str(task_index_path),
        "task_count": len(rows),
        "rewritten_field_count": rewritten,
    }


def _baseline_complete(baseline_root: Path) -> bool:
    metrics = baseline_root / EVAL_DIR_LLM / "metrics_summary.json"
    provenance = baseline_root / "provenance_summary.json"
    return metrics.exists() and provenance.exists()


def _baseline_pid_alive(pid_file: Path) -> bool:
    if not pid_file.exists():
        return False
    pid_text = pid_file.read_text(encoding="utf-8").strip()
    if not pid_text:
        return False
    proc = subprocess.run(["bash", "-lc", f"kill -0 {pid_text} >/dev/null 2>&1"], check=False)
    return proc.returncode == 0


def _wait_for_baseline(baseline_root: Path, pid_file: Path | None, timeout_minutes: int, poll_seconds: int) -> None:
    started = time.time()
    while not _baseline_complete(baseline_root):
        if pid_file and pid_file.exists() and not _baseline_pid_alive(pid_file):
            raise RuntimeError(f"Baseline process exited before completion: {pid_file}")
        if time.time() - started > timeout_minutes * 60:
            raise TimeoutError(f"Timed out waiting for baseline completion: {baseline_root}")
        time.sleep(max(5, poll_seconds))


def _evaluate(cfg, gt_json_path: Path, gt_time_offset_minutes: int, eval_dir_name: str, *, match_top_n: int) -> tuple[dict[str, Any], dict[str, str]]:
    strict_windows, technique_defs, _ = load_gt_reference(gt_json_path, host_filter=cfg.host.upper())
    if gt_time_offset_minutes:
        apply_gt_time_offset(strict_windows, minutes=gt_time_offset_minutes)
    output_dir = cfg.artifacts_dir / eval_dir_name
    outputs = run_evaluation(
        artifacts_dir=cfg.artifacts_dir,
        strict_windows=strict_windows,
        technique_defs=technique_defs,
        output_dir=output_dir,
        host=cfg.host.upper(),
        match_top_n=match_top_n,
        pad_minutes=5,
        near_miss_minutes=5,
    )
    metrics = _load_json(Path(outputs["metrics_summary"]))
    return metrics, outputs


def _prepare_from_baseline(baseline_root: Path, target_root: Path, *, include_module5: bool, include_module6: bool) -> dict[str, Any]:
    _clean_dir(target_root)
    target_root.mkdir(parents=True, exist_ok=True)
    copied = ["module1", "module3_evidence", "module4_compact"]
    if include_module5:
        copied.append("module5_paths")
    if include_module6:
        copied.append("module6_reason")
    rewrite_meta: dict[str, Any] | None = None
    for name in copied:
        source_dir = baseline_root / name
        target_dir = target_root / name
        _symlink_dir(source_dir, target_dir)
        if name == "module3_evidence":
            rewrite_meta = {
                "task_index_path": str(source_dir / "task_index.json"),
                "task_count": len(_load_json(source_dir / "task_index.json")),
                "rewritten_field_count": 0,
                "reuse_mode": "symlink_to_baseline",
            }
    return {
        "baseline_root": str(baseline_root),
        "reused_dir_names": copied,
        "reuse_link_mode": "symlink",
        "module3_task_index_rewrite": rewrite_meta or {},
    }


def _variant_specs() -> list[dict[str, Any]]:
    return [
        {
            "variant": "attack_prior_full",
            "reuse_module5": True,
            "reuse_module6": False,
            "claim_attack_prior_mode": "full",
            "tactic_mapping_mode": "llm",
            "path_top_k": 20,
            "reason_top_paths_per_task": 5,
            "eval_match_top_n": 5,
            "no_claims_direct_mapping": False,
        },
        {
            "variant": "deterministic_mapping",
            "reuse_module5": True,
            "reuse_module6": False,
            "claim_attack_prior_mode": "disabled",
            "tactic_mapping_mode": "deterministic",
            "path_top_k": 20,
            "reason_top_paths_per_task": 5,
            "eval_match_top_n": 5,
            "no_claims_direct_mapping": False,
        },
        {
            "variant": "no_claims_direct_mapping",
            "reuse_module5": True,
            "reuse_module6": False,
            "claim_attack_prior_mode": "disabled",
            "tactic_mapping_mode": "llm",
            "path_top_k": 20,
            "reason_top_paths_per_task": 5,
            "eval_match_top_n": 5,
            "no_claims_direct_mapping": True,
        },
        {
            "variant": "path_width_narrow",
            "reuse_module5": False,
            "reuse_module6": False,
            "claim_attack_prior_mode": "disabled",
            "tactic_mapping_mode": "llm",
            "path_top_k": 10,
            "reason_top_paths_per_task": 5,
            "eval_match_top_n": 5,
            "no_claims_direct_mapping": False,
        },
        {
            "variant": "path_width_wide",
            "reuse_module5": False,
            "reuse_module6": False,
            "claim_attack_prior_mode": "disabled",
            "tactic_mapping_mode": "llm",
            "path_top_k": 24,
            "reason_top_paths_per_task": 5,
            "eval_match_top_n": 5,
            "no_claims_direct_mapping": False,
        },
        {
            "variant": "window_agg_top3",
            "reuse_module5": True,
            "reuse_module6": True,
            "claim_attack_prior_mode": "disabled",
            "tactic_mapping_mode": "llm",
            "path_top_k": 20,
            "reason_top_paths_per_task": 5,
            "eval_match_top_n": 3,
            "no_claims_direct_mapping": False,
        },
        {
            "variant": "window_agg_top8",
            "reuse_module5": True,
            "reuse_module6": True,
            "claim_attack_prior_mode": "disabled",
            "tactic_mapping_mode": "llm",
            "path_top_k": 20,
            "reason_top_paths_per_task": 5,
            "eval_match_top_n": 8,
            "no_claims_direct_mapping": False,
        },
    ]


@contextmanager
def _claims_disabled_monkeypatch(enabled: bool) -> Iterator[dict[str, Any]]:
    if not enabled:
        yield {"claims_disabled_monkeypatch": False}
        return

    original_call = module6_impl._call_ollama_json
    original_graph = module6_impl.build_holmes_claim_graph
    original_fallback = module6_impl._fallback_claims

    def _empty_call(*_args, **_kwargs):
        return {
            "summary": "",
            "claims": [],
            "iocs": [],
            "gaps": ["claims disabled by runner monkeypatch"],
        }

    def _empty_graph(*_args, **_kwargs):
        return {
            "claims": [],
            "edges": [],
            "diagnostics": {
                "matched_atoms": [],
                "missing_expected_atoms": [],
                "claims_disabled": True,
            },
            "atom_catalog_version": "claims_disabled_runner_monkeypatch_v1",
        }

    def _no_fallback(_dossier, claims, **_kwargs):
        return list(claims or [])

    module6_impl._call_ollama_json = _empty_call
    module6_impl.build_holmes_claim_graph = _empty_graph
    module6_impl._fallback_claims = _no_fallback
    try:
        yield {
            "claims_disabled_monkeypatch": True,
            "claims_disabled_reason": "skip claim extraction and Holmes fallback; map tactics from dossier-driven candidates only",
        }
    finally:
        module6_impl._call_ollama_json = original_call
        module6_impl.build_holmes_claim_graph = original_graph
        module6_impl._fallback_claims = original_fallback


def _load_baseline_result(baseline_root: Path) -> dict[str, Any]:
    provenance = _load_json(baseline_root / "provenance_summary.json")
    metrics = _load_json(baseline_root / EVAL_DIR_LLM / "metrics_summary.json")
    return {
        "variant": "baseline_current",
        "status": "ok",
        "artifacts_dir": str(baseline_root),
        "metrics": metrics,
        "eval_outputs": provenance.get("eval_outputs", {}),
        "provenance_summary": str(baseline_root / "provenance_summary.json"),
    }


def _mark_failed(target_root: Path) -> Path:
    if not target_root.exists():
        return target_root
    failed_root = target_root.parent / f"{target_root.name}_failed_"
    counter = 1
    while failed_root.exists():
        failed_root = target_root.parent / f"{target_root.name}_failed_{counter}"
        counter += 1
    target_root.rename(failed_root)
    return failed_root


def _run_baseline_fresh(
    repo_root: Path,
    local_repo_root: Path,
    config_path: Path,
    gt_json_path: Path,
    gt_time_offset_minutes: int,
    baseline_root: Path,
    code_label: str,
) -> dict[str, Any]:
    cfg = load_config(config_path)
    cfg.artifacts_dir = baseline_root
    cfg.attack_eval_gt_json_path = str(gt_json_path)
    cfg.path_reason_gt_time_offset_minutes = int(gt_time_offset_minutes)
    _clean_dir(cfg.artifacts_dir)

    module1_outputs = run_module1(cfg)
    module3_outputs = module3_impl.run_module3_evidence(cfg)
    module4_outputs = module4_impl.run_module4_compact(cfg)
    module5_outputs = module5_impl.run_module5_paths(cfg)
    module6_outputs = module6_impl.run_module6_reason(cfg)
    metrics, eval_outputs = _evaluate(
        cfg,
        gt_json_path,
        gt_time_offset_minutes,
        EVAL_DIR_LLM,
        match_top_n=5,
    )
    provenance = {
        "dataset": "theia",
        "variant": "baseline_current",
        "local_repo_root": str(local_repo_root),
        "remote_repo_root": str(repo_root),
        "config_template_path": str(config_path),
        "artifacts_dir": str(cfg.artifacts_dir),
        "gt_json_path": str(gt_json_path),
        "gt_time_offset_minutes_applied": int(gt_time_offset_minutes),
        "module3_task_selection_mode": str(getattr(cfg, "module3_task_selection_mode", "")),
        "claim_attack_prior_mode": str(getattr(cfg, "claim_attack_prior_mode", "")),
        "attack_mapping_scope": str(getattr(cfg, "attack_mapping_scope", "")),
        "tactic_mapping_mode": str(getattr(cfg, "tactic_mapping_mode", "")),
        "path_top_k": int(getattr(cfg, "path_top_k", 20) or 20),
        "reason_top_paths_per_task": int(getattr(cfg, "reason_top_paths_per_task", 5) or 5),
        "module1_outputs": {key: str(value) for key, value in module1_outputs.items()},
        "module3_outputs": {key: str(value) for key, value in module3_outputs.items()},
        "module4_outputs": {key: str(value) for key, value in module4_outputs.items()},
        "module5_outputs": {key: str(value) for key, value in module5_outputs.items()},
        "module6_outputs": {key: str(value) for key, value in module6_outputs.items()},
        "eval_outputs": eval_outputs,
        "metrics": metrics,
    }
    _save_json(cfg.artifacts_dir / "provenance_summary.json", provenance)
    _save_json(cfg.artifacts_dir / "working_tree_fingerprint.json", _working_tree_fingerprint(repo_root, code_label))
    return _load_baseline_result(cfg.artifacts_dir)


def _run_variant(
    repo_root: Path,
    local_repo_root: Path,
    config_path: Path,
    gt_json_path: Path,
    gt_time_offset_minutes: int,
    baseline_root: Path,
    variant_root_template: str,
    code_label: str,
    variant_spec: dict[str, Any],
) -> dict[str, Any]:
    target_root = Path(variant_root_template.format(variant=variant_spec["variant"]))
    eval_dir_name = (
        EVAL_DIR_DETERMINISTIC
        if variant_spec["tactic_mapping_mode"] == "deterministic"
        else EVAL_DIR_LLM
    )
    metrics_path = target_root / eval_dir_name / "metrics_summary.json"
    provenance_path = target_root / "provenance_summary.json"
    if metrics_path.exists() and provenance_path.exists():
        provenance = _load_json(provenance_path)
        metrics = _load_json(metrics_path)
        return {
            "variant": variant_spec["variant"],
            "status": "ok",
            "artifacts_dir": str(target_root),
            "metrics": metrics,
            "eval_outputs": provenance.get("eval_outputs", {}),
            "resumed_existing_artifact": True,
        }

    cfg = load_config(config_path)
    cfg.artifacts_dir = target_root
    cfg.attack_eval_gt_json_path = str(gt_json_path)
    cfg.path_reason_gt_time_offset_minutes = int(gt_time_offset_minutes)
    cfg.module3_task_selection_mode = "module1_ground_truth_positive_base_only"
    cfg.task_tapas_augmentation_enabled = False
    cfg.task_tapas_augmentation_divisor = 0
    cfg.claim_attack_prior_mode = variant_spec["claim_attack_prior_mode"]
    cfg.attack_mapping_scope = "tactics_only"
    cfg.tactic_mapping_mode = variant_spec["tactic_mapping_mode"]
    cfg.path_top_k = int(variant_spec["path_top_k"])
    cfg.reason_top_paths_per_task = int(variant_spec["reason_top_paths_per_task"])

    try:
        reuse_meta = _prepare_from_baseline(
            baseline_root,
            target_root,
            include_module5=bool(variant_spec["reuse_module5"]),
            include_module6=bool(variant_spec["reuse_module6"]),
        )
        module5_outputs: dict[str, str] = {}
        module6_outputs: dict[str, str] = {}

        if not variant_spec["reuse_module5"]:
            _clean_dir(cfg.module5_paths_dir)
            _clean_dir(cfg.module6_reason_dir)
            module5_outputs = module5_impl.run_module5_paths(cfg)
            with _claims_disabled_monkeypatch(bool(variant_spec["no_claims_direct_mapping"])) as claim_meta:
                module6_outputs = module6_impl.run_module6_reason(cfg)
        elif not variant_spec["reuse_module6"]:
            _clean_dir(cfg.module6_reason_dir)
            with _claims_disabled_monkeypatch(bool(variant_spec["no_claims_direct_mapping"])) as claim_meta:
                module6_outputs = module6_impl.run_module6_reason(cfg)
        else:
            claim_meta = {"claims_disabled_monkeypatch": False}

        _clean_dir(cfg.artifacts_dir / eval_dir_name)
        metrics, eval_outputs = _evaluate(
            cfg,
            gt_json_path,
            gt_time_offset_minutes,
            eval_dir_name,
            match_top_n=int(variant_spec["eval_match_top_n"]),
        )
        provenance = {
            "dataset": "theia",
            "variant": variant_spec["variant"],
            "local_repo_root": str(local_repo_root),
            "remote_repo_root": str(repo_root),
            "config_template_path": str(config_path),
            "artifacts_dir": str(cfg.artifacts_dir),
            "gt_json_path": str(gt_json_path),
            "gt_time_offset_minutes_applied": int(gt_time_offset_minutes),
            "claim_attack_prior_mode": cfg.claim_attack_prior_mode,
            "attack_mapping_scope": cfg.attack_mapping_scope,
            "tactic_mapping_mode": cfg.tactic_mapping_mode,
            "path_top_k": int(cfg.path_top_k),
            "reason_top_paths_per_task": int(cfg.reason_top_paths_per_task),
            "eval_match_top_n": int(variant_spec["eval_match_top_n"]),
            "module3_task_selection_mode": cfg.module3_task_selection_mode,
            **claim_meta,
            **reuse_meta,
            "module5_outputs": {key: str(value) for key, value in module5_outputs.items()},
            "module6_outputs": {key: str(value) for key, value in module6_outputs.items()},
            "eval_outputs": eval_outputs,
            "metrics": metrics,
        }
        _save_json(cfg.artifacts_dir / "provenance_summary.json", provenance)
        _save_json(cfg.artifacts_dir / "working_tree_fingerprint.json", _working_tree_fingerprint(repo_root, code_label))
        return {
            "variant": variant_spec["variant"],
            "status": "ok",
            "artifacts_dir": str(target_root),
            "metrics": metrics,
            "eval_outputs": eval_outputs,
        }
    except Exception as exc:
        failed_root = _mark_failed(target_root)
        failure = {
            "variant": variant_spec["variant"],
            "status": "failed",
            "artifacts_dir": str(failed_root),
            "error": str(exc),
            "traceback": traceback.format_exc(),
        }
        failed_root.mkdir(parents=True, exist_ok=True)
        _save_json(failed_root / "failure_summary.json", failure)
        return failure


def main() -> None:
    args = _parse_args()
    repo_root = Path(args.repo_root).resolve()
    config_path = Path(args.config_path).resolve()
    gt_json_path = Path(args.gt_json_path).resolve()
    baseline_root = Path(args.baseline_root).resolve()
    output_root = Path(args.output_root).resolve()
    local_repo_root = Path(args.local_repo_root)
    pid_file = Path(args.baseline_pid_file).resolve() if args.baseline_pid_file else None

    output_root.mkdir(parents=True, exist_ok=True)
    progress_path = output_root / "progress.json"
    summary_path = output_root / "comparison_summary.json"

    if args.baseline_mode == "wait":
        _wait_for_baseline(
            baseline_root,
            pid_file,
            timeout_minutes=int(args.wait_timeout_minutes),
            poll_seconds=int(args.poll_seconds),
        )
        baseline_result = _load_baseline_result(baseline_root)
    else:
        baseline_result = _run_baseline_fresh(
            repo_root,
            local_repo_root,
            config_path,
            gt_json_path,
            int(args.gt_time_offset_minutes),
            baseline_root,
            args.code_label,
        )

    results = [baseline_result]
    _save_json(progress_path, {"baseline": baseline_result, "variants": []})

    for variant_spec in _variant_specs():
        result = _run_variant(
            repo_root,
            local_repo_root,
            config_path,
            gt_json_path,
            int(args.gt_time_offset_minutes),
            baseline_root,
            args.variant_root_template,
            args.code_label,
            variant_spec,
        )
        results.append(result)
        _save_json(progress_path, {"baseline": baseline_result, "variants": results[1:]})

    summary = {
        "code_label": args.code_label,
        "repo_root": str(repo_root),
        "config_path": str(config_path),
        "gt_json_path": str(gt_json_path),
        "gt_time_offset_minutes": int(args.gt_time_offset_minutes),
        "baseline_mode": args.baseline_mode,
        "baseline_root": str(baseline_root),
        "variant_root_template": args.variant_root_template,
        "results": results,
    }
    _save_json(summary_path, summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
