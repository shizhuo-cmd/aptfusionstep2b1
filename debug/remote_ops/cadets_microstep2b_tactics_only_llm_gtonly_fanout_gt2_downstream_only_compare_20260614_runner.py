from __future__ import annotations

import json
from pathlib import Path

from cadets_microstep2b_tactics_only_llm_gtonly_fanout_gt2_common_20260614 import (
    EVAL_DIR_NAME,
    LOCAL_REPO_ROOT,
    REMOTE_REPO_ROOT,
    _clean_dir,
    _evaluate,
    _load_gt,
    _load_metrics,
    _resolve_metrics_summary,
    _resolve_repo_path,
    _stringify_paths,
    _task_chain_diagnostics,
    _write_json,
    build_split_meta_compare,
    ensure_cadets_logs_ready,
    run_module2,
    run_module3_evidence,
    run_module4_compact,
    run_module5_paths,
    run_module6_reason,
)
from apt_fusion.config import load_config


EXCLUDE_CONFIG_PATH = Path(
    "configs/fusion_cloud_cadets_train_stats_latefusion_llama31_microstep2b_tactics_only_llm_gtonly_fanout_gt2_exclude_segmented_20260614.yaml"
)
INCLUDE_CONFIG_PATH = Path(
    "configs/fusion_cloud_cadets_train_stats_latefusion_llama31_microstep2b_tactics_only_llm_gtonly_fanout_gt2_include_segmented_20260614.yaml"
)
EXCLUDE_ROOT = REMOTE_REPO_ROOT / "artifacts_cadets_train_stats_latefusion_llama31_microstep2b_tactics_only_llm_gtonly_fanout_gt2_exclude_segmented_20260614"
INCLUDE_ROOT = REMOTE_REPO_ROOT / "artifacts_cadets_train_stats_latefusion_llama31_microstep2b_tactics_only_llm_gtonly_fanout_gt2_include_segmented_20260614"
OUTPUT_DIR = (
    REMOTE_REPO_ROOT
    / "debug"
    / "remote_ops"
    / "cadets_microstep2b_tactics_only_llm_gtonly_fanout_gt2_compare_20260614_outputs"
)


def _module1_outputs(artifacts_dir: Path) -> dict[str, Path]:
    module1_dir = artifacts_dir / "module1"
    outputs = {
        "process_embeddings": module1_dir / "process_embeddings.csv",
        "task_subgraphs": module1_dir / "task_subgraphs.json",
        "process_segmentation_edges": module1_dir / "process_segmentation_edges.csv",
        "tapas_native_graphs": module1_dir / "tapas_native_graphs.pt",
        "tapas_native_summary": module1_dir / "tapas_native_module1_summary.json",
    }
    missing = [str(path) for path in outputs.values() if not path.exists()]
    if missing:
        raise FileNotFoundError(f"module1 outputs missing under {module1_dir}: {missing}")
    return outputs


def _clean_downstream_outputs(artifacts_dir: Path) -> None:
    for name in [
        "module2",
        "module3_evidence",
        "module4_compact",
        "module5_paths",
        "module6_reason",
        EVAL_DIR_NAME,
    ]:
        _clean_dir(artifacts_dir / name)
    for name in [
        "provenance_summary.json",
        "decision_summary.json",
    ]:
        path = artifacts_dir / name
        if path.exists():
            path.unlink()


def run_downstream_from_existing_module1(config_path: str | Path) -> dict[str, object]:
    config_path = _resolve_repo_path(config_path)
    logs_provenance = ensure_cadets_logs_ready()
    cfg = load_config(config_path)
    cfg.artifacts_dir.mkdir(parents=True, exist_ok=True)
    out1 = _module1_outputs(cfg.artifacts_dir)
    _clean_downstream_outputs(cfg.artifacts_dir)

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
        "task_tapas_augmentation_divisor": int(cfg.task_tapas_augmentation_divisor),
        "task_tapas_augmentation_before_split": bool(cfg.task_tapas_augmentation_before_split),
        "claim_attack_prior_mode": str(cfg.claim_attack_prior_mode),
        "attack_mapping_scope": str(cfg.attack_mapping_scope),
        "tactic_mapping_mode": str(cfg.tactic_mapping_mode),
        "module1_reused": True,
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
        "module1_reused": True,
    }
    _write_json(decision_path, summary)
    return summary


def main() -> None:
    exclude_summary = run_downstream_from_existing_module1(EXCLUDE_CONFIG_PATH)
    include_summary = run_downstream_from_existing_module1(INCLUDE_CONFIG_PATH)

    exclude_metrics = _load_metrics(_resolve_metrics_summary(EXCLUDE_ROOT / EVAL_DIR_NAME))
    include_metrics = _load_metrics(_resolve_metrics_summary(INCLUDE_ROOT / EVAL_DIR_NAME))
    strict_windows, _ = _load_gt("CADETS")
    exclude_diag = _task_chain_diagnostics(EXCLUDE_ROOT, strict_windows)
    include_diag = _task_chain_diagnostics(INCLUDE_ROOT, strict_windows)
    split_meta_compare = build_split_meta_compare(EXCLUDE_ROOT, INCLUDE_ROOT)

    from cadets_microstep2b_tactics_only_llm_gtonly_fanout_gt2_common_20260614 import select_better_variant

    selected_variant, selection_reasons = select_better_variant(
        exclude_metrics,
        include_metrics,
        exclude_diag,
        include_diag,
    )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    provenance_summary = {
        "local_repo_root": str(LOCAL_REPO_ROOT),
        "remote_repo_root": str(REMOTE_REPO_ROOT),
        "exclude_config_path": str(REMOTE_REPO_ROOT / EXCLUDE_CONFIG_PATH),
        "include_config_path": str(REMOTE_REPO_ROOT / INCLUDE_CONFIG_PATH),
        "exclude_root": str(EXCLUDE_ROOT),
        "include_root": str(INCLUDE_ROOT),
        "claim_attack_prior_mode": "disabled",
        "attack_mapping_scope": "tactics_only",
        "tactic_mapping_mode": "llm",
        "task_tapas_augmentation_enabled": False,
        "task_tapas_augmentation_divisor": 0,
        "task_tapas_augmentation_before_split": False,
        "runner_mode": "downstream_only_compare",
        "module1_reused": True,
    }
    split_meta_compare_path = OUTPUT_DIR / "split_meta_compare.json"
    gt_hit_chain_diagnostics_path = OUTPUT_DIR / "gt_hit_chain_diagnostics.json"
    comparison_summary_path = OUTPUT_DIR / "comparison_summary.json"
    provenance_summary_path = OUTPUT_DIR / "provenance_summary.json"

    _write_json(
        gt_hit_chain_diagnostics_path,
        {
            "exclude_segmented": exclude_diag,
            "include_segmented": include_diag,
        },
    )
    _write_json(split_meta_compare_path, split_meta_compare)
    _write_json(provenance_summary_path, provenance_summary)
    _write_json(
        comparison_summary_path,
        {
            "provenance_summary": str(provenance_summary_path),
            "exclude_run_summary": exclude_summary,
            "include_run_summary": include_summary,
            "exclude_metrics": exclude_metrics,
            "include_metrics": include_metrics,
            "selected_variant": selected_variant,
            "selection_reasons": selection_reasons,
            "split_meta_compare": str(split_meta_compare_path),
            "gt_hit_chain_diagnostics": str(gt_hit_chain_diagnostics_path),
        },
    )
    print(
        json.dumps(
            {
                "provenance_summary": str(provenance_summary_path),
                "comparison_summary": str(comparison_summary_path),
                "split_meta_compare": str(split_meta_compare_path),
                "gt_hit_chain_diagnostics": str(gt_hit_chain_diagnostics_path),
                "selected_variant": selected_variant,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
