# Architecture

## Current Shape

The repository is now organized around a TAPAS-native detection front half and a local investigation / LLM back half.

```text
module1 (TAPAS-native export)
    -> module2 (TAPAS-native train / infer)
    -> module3_local (streaming investigation)
    -> module4 (LLM reporting)
```

## Module 1

`module1` no longer uses the older hybrid APT-Fusion feature stack.

It now:
- runs the official TAPAS parsing / encoding / task-cutting logic for supported datasets
- can optionally append OCR-style per-process statistical features to the TAPAS sequence embeddings
- exports compatibility files for the rest of the project
- saves a native graph payload used directly by `module2`

Key files:
- `src/apt_fusion/module1_online_graph.py`
- `src/apt_fusion/tapas_native_backend.py`

Outputs:
- `process_embeddings.csv`
- `task_subgraphs.json`
- `process_segmentation_edges.csv`
- `tapas_native_graphs.pt`

## Module 2

`module2` now uses TAPAS-native training and inference only.

It no longer builds task graphs with the removed custom detector path. Instead, it:
- loads the native graph payload emitted by `module1`
- applies TAPAS augmentation
- trains or loads the TAPAS GraphSAGE model
- predicts with `argmax`
- reports `macro` metrics
- exports compatibility files for `module3_local`

Key files:
- `src/apt_fusion/module2_online_detection.py`
- `src/apt_fusion/tapas_native_backend.py`

Outputs:
- `task_scores.csv`
- `task_subgraph_summary.json`
- `tapas_native_model.pt`
- `suspicious_tasks.json`
- `process_scores.csv`
- `run_0_raised_alarms.csv`

## Module 3 Local

`module3_local` still serves as the evidence backfill stage. It consumes:
- `suspicious_tasks.json`
- `process_scores.csv`
- `run_0_raised_alarms.csv`
- raw source logs

Key file:
- `src/apt_fusion/module3_local_stream.py`

## Module 4

`module4` still performs local LLM-driven summarization and ATT&CK-style reporting.

Key files:
- `src/apt_fusion/module4_llm_report.py`
- `src/apt_fusion/module4_local_report.py`

## Supported Detection Datasets

### `dataset_family: tc3`

Supported hosts:
- `trace`
- `cadets`
- `fivedirections`
- `theia`

### `dataset_family: optc`

Supported hosts:
- `SysClient0051`
- `SysClient0201`
- `SysClient0501`

## Removed Detection Path

The older approximate TAPAS implementation was removed from the code entrypoints. The deleted implementation files include:
- `tapas_adapter.py`
- `tapas_runtime.py`
- `task_subgraph_detector.py`

`ocr_stat_features.py` now exists again, but only as an optional additive feature branch on top of TAPAS-native `module1`. It is not a separate detector path.

The remaining pipeline is intentionally narrower and cleaner: TAPAS-native detection feeding local investigation and LLM reporting.
