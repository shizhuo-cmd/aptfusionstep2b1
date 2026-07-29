from __future__ import annotations

import json
import shutil
import subprocess
import sys
import traceback
from pathlib import Path
from typing import Any

import yaml

_THIS_FILE = Path(__file__).resolve()
_REPO_ROOT = _THIS_FILE.parents[2]
_SRC_ROOT = _REPO_ROOT / "src"
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from apt_fusion.config import load_config, resolve_attack_eval_gt_json
from apt_fusion.evaluation.path_reason_eval import apply_gt_time_offset, load_gt_reference, run_evaluation
from apt_fusion.path_reason.module3_evidence_recover import run_module3_evidence
from apt_fusion.path_reason.module4_semantic_compact import run_module4_compact
from apt_fusion.path_reason.module5_path_finder import run_module5_paths
from apt_fusion.path_reason.module6_attack_reason import run_module6_reason

LOCAL_REPO_ROOT = Path(r"D:\daima\APT-Fusionstep2b1")
REPO_ROOT = Path("/root/autodl-tmp/APT-Fusionstep2b1")
GT_JSON_PATH = resolve_attack_eval_gt_json(REPO_ROOT)
GT_TIME_OFFSET_MINUTES = 240
OUTPUT_ROOT = REPO_ROOT / "debug" / "remote_ops" / "out" / "tc3_path_reason_ablation_matrix_step7bwidth_module1gt_20260708"

TRACE_CONFIG_PATH = (
    REPO_ROOT
    / "configs"
    / "fusion_cloud_trace_train_stats_latefusion_bonus1_llama31_microstep2b_truthgap_tactics_only_llm_worktree_e3gt_gtonly_20260624.yaml"
)
TRACE_SOURCE_ROOT = (
    REPO_ROOT
    / "artifacts_trace_train_stats_latefusion_llama31_module12_ablation_baseline_current_20260707"
)

CADETS_CONFIG_PATH = (
    REPO_ROOT
    / "configs"
    / "fusion_cloud_cadets_train_stats_latefusion_llama31_microstep2b_module1_gtbase_tactics_only_llm_fanout_gt2_e3gt_plus240_baseline_20260628.yaml"
)
CADETS_SOURCE_ROOT = (
    REPO_ROOT
    / "artifacts_cadets_train_stats_latefusion_llama31_microstep2b_module1_gtbase_tactics_only_llm_fanout_gt2_e3gt_plus240_step8i_theia_cleanup_bridge_failed_20260701"
)

MODULE3_PATH_FIELDS = [
    "normalized_events_path",
    "entity_index_path",
    "process_event_index_path",
    "object_event_index_path",
    "task_evidence_frontier_path",
    "task_local_evidence_graph_path",
]


def _clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def _copy_tree(source: Path, target: Path) -> None:
    if not source.exists():
        raise FileNotFoundError(f"Missing reused artifact directory: {source}")
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target)


def _git_text(*args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip()


def _working_tree_fingerprint() -> dict[str, Any]:
    status_lines = [line for line in _git_text("status", "--short").splitlines() if line.strip()]
    return {
        "code_baseline": "local_working_tree_snapshot_synced_to_remote_subset",
        "head_commit": _git_text("rev-parse", "HEAD"),
        "git_status_short": status_lines,
        "git_status_count": len(status_lines),
    }


def _rewrite_module3_task_index_paths(module3_dir: Path) -> dict[str, Any]:
    task_index_path = module3_dir / "task_index.json"
    rows = json.loads(task_index_path.read_text(encoding="utf-8"))
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
    task_index_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "task_index_path": str(task_index_path),
        "task_count": len(rows),
        "rewritten_field_count": rewritten,
    }


def _evaluate(cfg, eval_dir_name: str) -> tuple[dict[str, Any], dict[str, str]]:
    strict_windows, technique_defs, _ = load_gt_reference(GT_JSON_PATH, host_filter=cfg.host.upper())
    apply_gt_time_offset(strict_windows, minutes=GT_TIME_OFFSET_MINUTES)
    output_dir = cfg.artifacts_dir / eval_dir_name
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


def _prepare_runtime_path_rules(dataset: str) -> tuple[Path, dict[str, Any]]:
    source_path = REPO_ROOT / "configs" / "path_reason_default.yaml"
    return source_path, {
        "path_rules_profile": "default_step7bwidth",
        "path_rules_source": str(source_path),
        "path_search_overrides": {
            "max_depth": 6,
            "top_k": 20,
        },
    }


def _variant_artifact_root(dataset: str, variant: str) -> Path:
    if dataset == "trace":
        return REPO_ROOT / (
            f"artifacts_trace_train_stats_latefusion_bonus1_microstep2b_truthgap_tactics_only_"
            f"ablation_{variant}_step7bwidth_module1gt_e3gt_plus240_gtonly_20260708"
        )
    if dataset == "cadets":
        return REPO_ROOT / (
            f"artifacts_cadets_train_stats_latefusion_llama31_microstep2b_module1_gtbase_tactics_only_"
            f"ablation_{variant}_step7bwidth_module1gt_e3gt_plus240_20260708"
        )
    raise ValueError(f"Unsupported dataset: {dataset}")


def _dataset_spec(dataset: str) -> dict[str, Any]:
    if dataset == "trace":
        return {
            "dataset": dataset,
            "host": "trace",
            "config_path": TRACE_CONFIG_PATH,
            "source_root": TRACE_SOURCE_ROOT,
            "reuse_from_source": ["module1"],
        }
    if dataset == "cadets":
        return {
            "dataset": dataset,
            "host": "cadets",
            "config_path": CADETS_CONFIG_PATH,
            "source_root": CADETS_SOURCE_ROOT,
            "reuse_from_source": ["module1"],
        }
    raise ValueError(f"Unsupported dataset: {dataset}")


def _baseline_variant_specs(dataset: str) -> list[dict[str, Any]]:
    baseline_reuse_mode = "source_module1"
    followup_reuse_mode = "baseline_module4"
    return [
        {
            "variant": "baseline_current",
            "reuse_mode": baseline_reuse_mode,
            "split_parent_inherit": True,
            "family_preserve": True,
            "claim_attack_prior_mode": "disabled",
            "tactic_mapping_mode": "llm",
        },
        {
            "variant": "split_parent_inherit_off",
            "reuse_mode": followup_reuse_mode,
            "split_parent_inherit": False,
            "family_preserve": True,
            "claim_attack_prior_mode": "disabled",
            "tactic_mapping_mode": "llm",
        },
        {
            "variant": "family_preserve_off_risk_topk",
            "reuse_mode": followup_reuse_mode,
            "split_parent_inherit": True,
            "family_preserve": False,
            "claim_attack_prior_mode": "disabled",
            "tactic_mapping_mode": "llm",
        },
        {
            "variant": "attack_prior_full",
            "reuse_mode": "baseline_module5",
            "split_parent_inherit": True,
            "family_preserve": True,
            "claim_attack_prior_mode": "full",
            "tactic_mapping_mode": "llm",
        },
        {
            "variant": "deterministic_mapping",
            "reuse_mode": "baseline_module5",
            "split_parent_inherit": True,
            "family_preserve": True,
            "claim_attack_prior_mode": "disabled",
            "tactic_mapping_mode": "deterministic",
        },
    ]


def _prepare_from_source(spec: dict[str, Any], target_root: Path, reuse_mode: str) -> dict[str, Any]:
    _clean_dir(target_root)
    target_root.mkdir(parents=True, exist_ok=True)
    copied: list[str] = []
    rewrite_meta: dict[str, Any] | None = None
    for name in spec["reuse_from_source"]:
        source_dir = spec["source_root"] / name
        target_dir = target_root / name
        _copy_tree(source_dir, target_dir)
        copied.append(name)
        if name == "module3_evidence":
            rewrite_meta = _rewrite_module3_task_index_paths(target_dir)
    return {
        "reuse_mode": reuse_mode,
        "reused_source_root": str(spec["source_root"]),
        "reused_dir_names": copied,
        "module3_task_index_rewrite": rewrite_meta or {},
    }


def _prepare_from_baseline(spec: dict[str, Any], baseline_root: Path, target_root: Path, reuse_mode: str) -> dict[str, Any]:
    _clean_dir(target_root)
    target_root.mkdir(parents=True, exist_ok=True)
    copied = ["module3_evidence", "module4_compact"]
    if reuse_mode == "baseline_module5":
        copied.append("module5_paths")
    for optional_name in ("module1", "module2"):
        if (baseline_root / optional_name).exists() and optional_name not in copied:
            copied.insert(0, optional_name)
    for name in copied:
        _copy_tree(baseline_root / name, target_root / name)
    return {
        "reuse_mode": reuse_mode,
        "baseline_root": str(baseline_root),
        "reused_dir_names": copied,
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


def _run_variant(dataset: str, variant_spec: dict[str, Any], baseline_root: Path | None) -> dict[str, Any]:
    spec = _dataset_spec(dataset)
    target_root = _variant_artifact_root(dataset, variant_spec["variant"])
    cfg = load_config(spec["config_path"])
    cfg.artifacts_dir = target_root
    cfg.attack_eval_gt_json_path = GT_JSON_PATH
    cfg.path_reason_gt_time_offset_minutes = GT_TIME_OFFSET_MINUTES
    cfg.claim_attack_prior_mode = variant_spec["claim_attack_prior_mode"]
    cfg.attack_mapping_scope = "tactics_only"
    cfg.tactic_mapping_mode = variant_spec["tactic_mapping_mode"]
    cfg.module3_task_selection_mode = "module1_ground_truth_positive_base_only"
    cfg.task_tapas_augmentation_enabled = False
    cfg.task_tapas_augmentation_divisor = 0
    rules_path, rules_meta = _prepare_runtime_path_rules(dataset)
    cfg.path_reason_rules_path = rules_path
    setattr(cfg, "path_split_parent_label_inheritance_enabled", variant_spec["split_parent_inherit"])
    setattr(cfg, "path_family_preserve_enabled", variant_spec["family_preserve"])
    eval_dir_name = (
        "path_reason_eval_tactics_only_deterministic"
        if variant_spec["tactic_mapping_mode"] == "deterministic"
        else "path_reason_eval_tactics_only_llm"
    )
    try:
        if variant_spec["reuse_mode"] == "source_module1":
            module3_outputs = {}
            reuse_meta = _prepare_from_source(spec, target_root, variant_spec["reuse_mode"])
            _clean_dir(cfg.module3_evidence_dir)
            _clean_dir(cfg.module4_compact_dir)
            _clean_dir(cfg.module5_paths_dir)
            _clean_dir(cfg.module6_reason_dir)
            _clean_dir(cfg.artifacts_dir / eval_dir_name)
            module3_outputs = run_module3_evidence(cfg)
            module4_outputs = run_module4_compact(cfg)
            module5_outputs = run_module5_paths(cfg)
            module6_outputs = run_module6_reason(cfg)
        elif variant_spec["reuse_mode"] == "source_module4":
            module3_outputs = {}
            reuse_meta = _prepare_from_source(spec, target_root, variant_spec["reuse_mode"])
            _clean_dir(cfg.module5_paths_dir)
            _clean_dir(cfg.module6_reason_dir)
            _clean_dir(cfg.artifacts_dir / eval_dir_name)
            module4_outputs = {}
            module5_outputs = run_module5_paths(cfg)
            module6_outputs = run_module6_reason(cfg)
        else:
            if baseline_root is None:
                raise FileNotFoundError(f"Baseline root required before running variant '{variant_spec['variant']}'")
            reuse_meta = _prepare_from_baseline(spec, baseline_root, target_root, variant_spec["reuse_mode"])
            module3_outputs = {}
            _clean_dir(cfg.module5_paths_dir)
            _clean_dir(cfg.module6_reason_dir)
            _clean_dir(cfg.artifacts_dir / eval_dir_name)
            module4_outputs = {}
            if variant_spec["reuse_mode"] == "baseline_module4":
                module5_outputs = run_module5_paths(cfg)
                module6_outputs = run_module6_reason(cfg)
            else:
                module5_outputs = {}
                module6_outputs = run_module6_reason(cfg)
        metrics, eval_outputs = _evaluate(cfg, eval_dir_name)
        provenance = {
            "dataset": dataset,
            "variant": variant_spec["variant"],
            "local_repo_root": str(LOCAL_REPO_ROOT),
            "remote_repo_root": str(REPO_ROOT),
            "config_template_path": str(spec["config_path"]),
            "artifacts_dir": str(cfg.artifacts_dir),
            "gt_json_path": str(GT_JSON_PATH),
            "gt_time_offset_minutes_applied": GT_TIME_OFFSET_MINUTES,
            "path_split_parent_label_inheritance_enabled": variant_spec["split_parent_inherit"],
            "path_family_preserve_enabled": variant_spec["family_preserve"],
            "claim_attack_prior_mode": variant_spec["claim_attack_prior_mode"],
            "attack_mapping_scope": cfg.attack_mapping_scope,
            "tactic_mapping_mode": variant_spec["tactic_mapping_mode"],
            "module3_task_selection_mode": cfg.module3_task_selection_mode,
            "task_tapas_augmentation_enabled": cfg.task_tapas_augmentation_enabled,
            "task_tapas_augmentation_divisor": cfg.task_tapas_augmentation_divisor,
            **rules_meta,
            **reuse_meta,
            "module3_outputs": {key: str(value) for key, value in module3_outputs.items()},
            "module4_outputs": {key: str(value) for key, value in module4_outputs.items()},
            "module5_outputs": {key: str(value) for key, value in module5_outputs.items()},
            "module6_outputs": {key: str(value) for key, value in module6_outputs.items()},
            "eval_outputs": eval_outputs,
            "metrics": metrics,
        }
        (cfg.artifacts_dir / "provenance_summary.json").write_text(
            json.dumps(provenance, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (cfg.artifacts_dir / "working_tree_fingerprint.json").write_text(
            json.dumps(_working_tree_fingerprint(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return {
            "dataset": dataset,
            "variant": variant_spec["variant"],
            "status": "ok",
            "artifacts_dir": str(cfg.artifacts_dir),
            "metrics": metrics,
            "eval_outputs": eval_outputs,
        }
    except Exception as exc:
        failed_root = _mark_failed(target_root)
        failure = {
            "dataset": dataset,
            "variant": variant_spec["variant"],
            "status": "failed",
            "artifacts_dir": str(failed_root),
            "error": str(exc),
            "traceback": traceback.format_exc(),
        }
        failed_root.mkdir(parents=True, exist_ok=True)
        (failed_root / "failure_summary.json").write_text(
            json.dumps(failure, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return failure


def main() -> None:
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    all_results: dict[str, list[dict[str, Any]]] = {}
    for dataset in ("trace", "cadets"):
        dataset_results: list[dict[str, Any]] = []
        baseline_root: Path | None = None
        for variant_spec in _baseline_variant_specs(dataset):
            result = _run_variant(dataset, variant_spec, baseline_root)
            dataset_results.append(result)
            if result["status"] == "ok" and variant_spec["variant"] == "baseline_current":
                baseline_root = Path(result["artifacts_dir"])
        all_results[dataset] = dataset_results
    summary_path = OUTPUT_ROOT / "matrix_summary.remote.json"
    summary_path.write_text(json.dumps(all_results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(all_results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
