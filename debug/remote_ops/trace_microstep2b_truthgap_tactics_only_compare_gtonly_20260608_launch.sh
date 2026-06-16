#!/usr/bin/env bash
set -euo pipefail
cd /root/autodl-tmp/APT-Fusionstep2b1
export PYTHONPATH="/root/autodl-tmp/APT-Fusionstep2b1/src:${PYTHONPATH:-}"
python debug/remote_ops/trace_microstep2b_truthgap_tactics_only_compare_gtonly_20260608_runner.py \
  | tee /root/autodl-tmp/trace_microstep2b_truthgap_tactics_only_compare_gtonly_20260608.log
