from __future__ import annotations

import json
from pathlib import Path

from step2d_clearlogsfallback_selective_common_20260624 import run_selective_refresh

LOCAL_REPO_ROOT = Path(r"D:\daima\APT-Fusionstep2b1")
REPO_ROOT = Path("/root/autodl-tmp/APT-Fusionstep2b1")
CONFIG_PATH = (
    REPO_ROOT
    / "configs"
    / "fusion_cloud_trace_train_stats_latefusion_bonus1_llama31_microstep2b_truthgap_tactics_only_llm_worktree_e3gt_gtonly_20260624.yaml"
)
REUSED_SOURCE_ROOT = (
    REPO_ROOT
    / "artifacts_trace_train_stats_latefusion_bonus1_microstep2b_truthgap_tactics_only_llm_worktree_step2b_browsercredguard_e3gt_plus240_gtonly_20260624"
)
TARGET_ROOT = (
    REPO_ROOT
    / "artifacts_trace_train_stats_latefusion_bonus1_microstep2b_truthgap_tactics_only_llm_worktree_step2d_clearlogsfallback_e3gt_plus240_gtonly_20260624"
)
GT_JSON_PATH = REPO_ROOT / "docs" / "darpa_attack_eval_ground_truth_e3_report_enriched_20260618.json"
GT_TIME_OFFSET_MINUTES = 240
ANALYSIS_SCRIPT = REPO_ROOT / "debug" / "remote_ops" / "analyze_path_reason_behavior_capture_20260624.py"
ANALYSIS_OUTPUT_DIR = REPO_ROOT / "debug" / "remote_ops" / "out" / "trace_behavior_capture_step2d_clearlogsfallback_20260624"


def main() -> None:
    provenance = run_selective_refresh(
        local_repo_root=LOCAL_REPO_ROOT,
        remote_repo_root=REPO_ROOT,
        config_path=CONFIG_PATH,
        reused_source_root=REUSED_SOURCE_ROOT,
        target_root=TARGET_ROOT,
        gt_json_path=GT_JSON_PATH,
        gt_time_offset_minutes=GT_TIME_OFFSET_MINUTES,
        analysis_script=ANALYSIS_SCRIPT,
        analysis_output_dir=ANALYSIS_OUTPUT_DIR,
        host_name="TRACE",
        experiment_step="step2d_clearlogsfallback_selective",
    )
    print(json.dumps(provenance, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
