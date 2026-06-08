# APT-Fusion

APT-Fusion currently keeps one supported mainline:

```text
module0 -> module1 -> module2 -> module3_evidence -> module4_compact -> module5_paths -> module6_reason
```

The front half builds TAPAS-native task graphs and task-level anomaly scores.  
The back half reconstructs task evidence, compresses it into candidate attack paths, and uses local ATT&CK retrieval plus LLM reasoning for tactic/technique analysis.

## Current Layout

```text
src/apt_fusion/
  cli.py
  config.py
  pipeline.py
  common.py
  task_detection/
  path_reason/
  evaluation/
```

- `task_detection/`
  - TAPAS-native task construction and detection
  - includes `module0_preprocess.py`, `module1_online_graph.py`, `module2_online_detection.py`, `tapas_native_backend.py`
- `path_reason/`
  - evidence recovery, semantic compaction, candidate path search, ATT&CK reasoning
- `evaluation/`
  - official-window-based DARPA evaluation utilities

Old `full / full_local / full_reason` routes and their code were removed from the active repository surface.

## Supported Stages

The CLI now supports only these stages:

- `module0`
- `module1`
- `module2`
- `module3_evidence`
- `module4_compact`
- `module5_paths`
- `module6_reason`
- `full_path_reason`

Recommended end-to-end command:

```powershell
python -m apt_fusion.cli run --config .\configs\fusion_cloud_trace_train_stats_latefusion_bonus1_llama31.yaml --stage full_path_reason
```

## Key Configs

- `configs/path_reason_default.yaml`
- `configs/fusion_cloud_trace_train_stats_latefusion_bonus1_llama31.yaml`
- `configs/fusion_cloud_trace_train_stats_latefusion_bonus1_llama31_split_gt3.yaml`
- `configs/fusion_cloud_trace_train_stats_latefusion_bonus1_llama31_split_connected.yaml`
- `configs/fusion_cloud_theia_train_stats_latefusion_llama31_taskcomponents.yaml`
- `configs/fusion_cloud_cadets_train_stats_latefusion_llama31_taskcomponents.yaml`
- `configs/fusion_config.example.yaml`

## Evaluation

ATT&CK/path evaluation code is in:

- `src/apt_fusion/evaluation/path_reason_eval.py`

Unified DARPA GT reference files are in:

- `docs/darpa_attack_eval_ground_truth_2026-05-26.json`
- `docs/darpa_attack_eval_ground_truth_2026-05-26_zh.md`

## Tests

Current unit tests cover the active path-reason utilities:

```powershell
python -m unittest discover -s .\tests -p "test_*.py"
```
