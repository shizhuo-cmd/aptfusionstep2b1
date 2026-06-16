from __future__ import annotations

from pathlib import Path

from cadets_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_eventid_fix_common_20260615 import (
    print_json,
    run_eventid_fix_experiment,
)


CONFIG_PATH = Path(
    "configs/fusion_cloud_cadets_train_stats_latefusion_llama31_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_exclude_segmented_eventid_fix_20260615.yaml"
)


def main() -> None:
    print_json(run_eventid_fix_experiment(CONFIG_PATH))


if __name__ == "__main__":
    main()
