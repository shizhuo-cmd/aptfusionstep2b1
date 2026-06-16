#!/usr/bin/env bash
set -euo pipefail
cd /root/autodl-tmp/APT-Fusionstep2b1
export PYTHONPATH="/root/autodl-tmp/APT-Fusionstep2b1/src:${PYTHONPATH:-}"
python debug/remote_ops/cadets_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_compare_20260615_runner.py \
  | tee /root/autodl-tmp/cadets_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_compare_20260615.log
