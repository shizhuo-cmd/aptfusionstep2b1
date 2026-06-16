from __future__ import annotations

import json
from pathlib import Path

from cadets_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_common_20260615 import (
    run_single_experiment,
)


CONFIG_PATH = Path(
    "configs/fusion_cloud_cadets_train_stats_latefusion_llama31_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_exclude_segmented_20260615.yaml"
)


def main() -> None:
    print(json.dumps(run_single_experiment(CONFIG_PATH), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
