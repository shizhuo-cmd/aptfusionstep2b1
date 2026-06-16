from __future__ import annotations

from pathlib import Path

from cadets_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_eventid_fix_common_20260615 import (
    LOCAL_REPO_ROOT,
    OLD_EXCLUDE_ROOT,
    OLD_INCLUDE_ROOT,
    REMOTE_REPO_ROOT,
    build_old_vs_new_comparison,
    build_split_meta_compare,
    print_json,
    run_eventid_fix_experiment,
)
from cadets_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_common_20260615 import (
    _write_json,
)


EXCLUDE_CONFIG_PATH = Path(
    "configs/fusion_cloud_cadets_train_stats_latefusion_llama31_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_exclude_segmented_eventid_fix_20260615.yaml"
)
INCLUDE_CONFIG_PATH = Path(
    "configs/fusion_cloud_cadets_train_stats_latefusion_llama31_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_include_segmented_eventid_fix_20260615.yaml"
)
NEW_EXCLUDE_ROOT = (
    REMOTE_REPO_ROOT
    / "artifacts_cadets_train_stats_latefusion_llama31_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_exclude_segmented_eventid_fix_20260615"
)
NEW_INCLUDE_ROOT = (
    REMOTE_REPO_ROOT
    / "artifacts_cadets_train_stats_latefusion_llama31_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_include_segmented_eventid_fix_20260615"
)
OUTPUT_DIR = (
    REMOTE_REPO_ROOT
    / "debug"
    / "remote_ops"
    / "cadets_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_eventid_fix_compare_20260615_outputs"
)


def main() -> None:
    exclude_summary = run_eventid_fix_experiment(EXCLUDE_CONFIG_PATH)
    include_summary = run_eventid_fix_experiment(INCLUDE_CONFIG_PATH)
    comparison = build_old_vs_new_comparison(
        old_exclude_root=OLD_EXCLUDE_ROOT,
        new_exclude_root=NEW_EXCLUDE_ROOT,
        old_include_root=OLD_INCLUDE_ROOT,
        new_include_root=NEW_INCLUDE_ROOT,
    )
    split_meta_compare = build_split_meta_compare(NEW_EXCLUDE_ROOT, NEW_INCLUDE_ROOT)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    comparison_summary_path = OUTPUT_DIR / "comparison_summary.json"
    provenance_summary_path = OUTPUT_DIR / "provenance_summary.json"
    split_meta_compare_path = OUTPUT_DIR / "split_meta_compare.json"

    _write_json(
        provenance_summary_path,
        {
            "local_repo_root": str(LOCAL_REPO_ROOT),
            "remote_repo_root": str(REMOTE_REPO_ROOT),
            "exclude_old_root": str(OLD_EXCLUDE_ROOT),
            "exclude_eventid_fix_root": str(NEW_EXCLUDE_ROOT),
            "include_old_root": str(OLD_INCLUDE_ROOT),
            "include_eventid_fix_root": str(NEW_INCLUDE_ROOT),
            "exclude_config_path": str(REMOTE_REPO_ROOT / EXCLUDE_CONFIG_PATH),
            "include_config_path": str(REMOTE_REPO_ROOT / INCLUDE_CONFIG_PATH),
            "module6_bug_fix": "normalize event_id evidence_claim_ids into claim_id references before mapping validation",
        },
    )
    _write_json(split_meta_compare_path, split_meta_compare)
    _write_json(
        comparison_summary_path,
        {
            "provenance_summary": str(provenance_summary_path),
            "old_vs_eventid_fix_metrics": comparison,
            "exclude_eventid_fix_run": exclude_summary,
            "include_eventid_fix_run": include_summary,
            "split_meta_compare": str(split_meta_compare_path),
        },
    )
    print_json(
        {
            "provenance_summary": str(provenance_summary_path),
            "comparison_summary": str(comparison_summary_path),
            "split_meta_compare": str(split_meta_compare_path),
        }
    )


if __name__ == "__main__":
    main()
