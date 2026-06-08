#!/usr/bin/env bash
set -euo pipefail

cd /root/autodl-tmp/APT-Fusionstep2b1

/root/miniconda3/envs/fusion/bin/python \
  debug/remote_ops/trace_microstep2b_no_attack_priors_gtonly_20260608_runner.py \
  | tee /root/autodl-tmp/trace_microstep2b_no_attack_priors_gtonly_20260608.log
