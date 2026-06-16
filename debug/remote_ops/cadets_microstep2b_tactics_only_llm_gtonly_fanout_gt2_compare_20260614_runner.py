from __future__ import annotations

import json
from pathlib import Path

from cadets_microstep2b_tactics_only_llm_gtonly_fanout_gt2_common_20260614 import (
    LOCAL_REPO_ROOT,
    REMOTE_REPO_ROOT,
    _load_gt,
    _load_metrics,
    _resolve_metrics_summary,
    _write_json,
    build_split_meta_compare,
    run_single_experiment,
    select_better_variant,
    _task_chain_diagnostics,
)


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


def main() -> None:
    exclude_summary = run_single_experiment(EXCLUDE_CONFIG_PATH)
    include_summary = run_single_experiment(INCLUDE_CONFIG_PATH)

    exclude_metrics = _load_metrics(_resolve_metrics_summary(EXCLUDE_ROOT / "path_reason_eval_tactics_only_llm"))
    include_metrics = _load_metrics(_resolve_metrics_summary(INCLUDE_ROOT / "path_reason_eval_tactics_only_llm"))
    strict_windows, _ = _load_gt("CADETS")
    exclude_diag = _task_chain_diagnostics(EXCLUDE_ROOT, strict_windows)
    include_diag = _task_chain_diagnostics(INCLUDE_ROOT, strict_windows)
    split_meta_compare = build_split_meta_compare(EXCLUDE_ROOT, INCLUDE_ROOT)
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
