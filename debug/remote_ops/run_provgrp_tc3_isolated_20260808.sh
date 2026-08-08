#!/usr/bin/env bash
set -u

REPO=/root/autodl-tmp/APT-Fusionstep2b1
PYTHON=/root/miniconda3/envs/fusion/bin/python
RUNNER="$REPO/debug/remote_ops/run_provgrp_tc3_isolated_20260808.py"
OUT="$REPO/debug/remote_ops/out/provgrp_tc3_isolated_20260808"
mkdir -p "$OUT"

run_route() {
  local label="$1"
  shift
  echo "[$(date -Is)] START $label" | tee -a "$OUT/master.log"
  CUDA_LAUNCH_BLOCKING=1 "$PYTHON" "$RUNNER" "$@" >"$OUT/${label}.log" 2>&1
  local status=$?
  echo "[$(date -Is)] END $label status=$status" | tee -a "$OUT/master.log"
}

# Each call runs in a separate Python process so an individual CUDA failure
# cannot poison the CUDA context used by later datasets or detector routes.
run_route cadets_undirected \
  --dataset cadets --route undirected --suffix retry20260808 \
  --reuse-module1 "$REPO/artifacts_cadets_provgrp_g0_20260808/module1"
run_route cadets_directed \
  --dataset cadets --route directed --suffix retry20260808 \
  --reuse-module1 "$REPO/artifacts_cadets_provgrp_g0_20260808/module1"

run_route trace_g0 --dataset trace --route g0 --suffix retry20260808
run_route trace_undirected \
  --dataset trace --route undirected --suffix retry20260808 \
  --reuse-module1 "$REPO/artifacts_trace_provgrp_g0_retry20260808/module1"
run_route trace_directed \
  --dataset trace --route directed --suffix retry20260808 \
  --reuse-module1 "$REPO/artifacts_trace_provgrp_g0_retry20260808/module1"

run_route theia_g0 --dataset theia --route g0 --suffix retry20260808
run_route theia_undirected \
  --dataset theia --route undirected --suffix retry20260808 \
  --reuse-module1 "$REPO/artifacts_theia_provgrp_g0_retry20260808/module1"
run_route theia_directed \
  --dataset theia --route directed --suffix retry20260808 \
  --reuse-module1 "$REPO/artifacts_theia_provgrp_g0_retry20260808/module1"

echo "[$(date -Is)] ALL ROUTES FINISHED" | tee -a "$OUT/master.log"
