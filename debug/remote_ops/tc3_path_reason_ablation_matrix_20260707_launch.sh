#!/usr/bin/env bash
set -euo pipefail

cd /root/autodl-tmp/APT-Fusionstep2b1
source /root/miniconda3/etc/profile.d/conda.sh
conda activate fusion

mkdir -p debug/remote_ops/out/tc3_path_reason_ablation_matrix_20260707
LOG_PATH="debug/remote_ops/out/tc3_path_reason_ablation_matrix_20260707_run.log"
rm -f "${LOG_PATH}"
touch "${LOG_PATH}"
rm -f debug/remote_ops/out/tc3_path_reason_ablation_matrix_20260707/matrix_summary.remote.json

exec /root/miniconda3/envs/fusion/bin/python \
  debug/remote_ops/tc3_path_reason_ablation_matrix_20260707_runner.py \
  >> "${LOG_PATH}" 2>&1
