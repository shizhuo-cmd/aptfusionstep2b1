# Repo Handoff For LLM

## What Is Active

This repository keeps one supported pipeline:

```text
module0
-> module1
-> module2
-> module3_evidence
-> module4_compact
-> module5_paths
-> module6_reason
```

Do not reason from the removed `full / full_local / full_reason` mental model.

## Folder Map

### `src/apt_fusion/task_detection`

Purpose:
- TAPAS-native parsing
- task graph construction
- task-level anomaly detection

Read first:
1. `src/apt_fusion/task_detection/tapas_native_backend.py`
2. `src/apt_fusion/task_detection/module1_online_graph.py`
3. `src/apt_fusion/task_detection/module2_online_detection.py`

### `src/apt_fusion/path_reason`

Purpose:
- recover raw-log evidence for detected tasks
- build process/object state
- compact noisy events
- search candidate attack paths
- run ATT&CK-oriented LLM reasoning

Read first:
1. `src/apt_fusion/path_reason/module3_evidence_recover.py`
2. `src/apt_fusion/path_reason/module4_semantic_compact.py`
3. `src/apt_fusion/path_reason/module5_path_finder.py`
4. `src/apt_fusion/path_reason/module6_attack_reason.py`
5. `src/apt_fusion/path_reason/attack_kb.py`
6. `src/apt_fusion/path_reason/path_rules.py`
7. `src/apt_fusion/path_reason/path_schemas.py`

Important helpers:
- `log_stream.py`: raw-log scanning, frontier matching, alias handling, event identity
- `evidence_normalizer.py`: event normalization + `TaskPrior` construction
- `object_classifier.py`: process/object semantic classes
- `semantic_skip.py`: de-duplication
- `bridge_builder.py`: write/read-exec bridge edges
- `path_search.py`: candidate path search
- `path_report.py`: dossier construction for path candidates
- `llm_io.py`: Ollama JSON call + exact request/response capture

### `src/apt_fusion/evaluation`

Purpose:
- official attack-window-based DARPA evaluation

Read:
1. `src/apt_fusion/evaluation/path_reason_eval.py`
2. `docs/darpa_attack_eval_ground_truth_2026-05-26.json`

## Current CLI Surface

Supported stages:
- `module0`
- `module1`
- `module2`
- `module3_evidence`
- `module4_compact`
- `module5_paths`
- `module6_reason`
- `full_path_reason`

Main entry files:
- `src/apt_fusion/cli.py`
- `src/apt_fusion/pipeline.py`
- `src/apt_fusion/config.py`

Important stage semantics in `pipeline.py`:
- `module2` reruns `module0 -> module1 -> module2`
- `module5_paths` reruns `module3_evidence -> module4_compact -> module5_paths`
- `module6_reason` reruns `module3_evidence -> module4_compact -> module5_paths -> module6_reason`

Practical consequence:
- the CLI stage flag is cumulative, not isolated
- if an experiment wants to reuse old `module3/module4/module5` artifacts and only rerun one back-half stage, call that stage function directly from Python instead of using the CLI stage wrapper

## Critical Defaults

- `module3_task_selection_mode` default is `predicted_positive`
- `ground_truth_positive_base_only` is supported, but it only works over rows that actually exist in `module2/suspicious_tasks.json`
- `task_component_split_mode` default is `fanout`
- supported split modes are `fanout`, `connected`, and threshold changes through `task_component_child_threshold`
- `path_top_k` default is `20`
- `reason_top_paths_per_task` default is `5`
- `reason_top_paths_per_task` is a real output cap: `module6` only sends the top N paths of each task to the LLM
- for current TRACE experiments, `fanout` with child-threshold `2` remains the working default

## How The Back Half Works

### `module3_evidence`

- selects tasks from `module2/suspicious_tasks.json`
- rescans raw logs around task process seeds
- normalizes events into `NormalizedEvent`
- writes `TaskPrior` rows that now include split metadata such as `task_root_id` and `boundary_node_ids`

Outputs:
- `module3_evidence/normalized_events/*.jsonl`
- `module3_evidence/task_index.json`
- `module3_evidence/priors_by_task.json`

### `module4_compact`

- applies light process/object labels
- performs semantic skip
- builds `ProcessState`, `ObjectState`, `ObjectAccessRecord`
- aggregates episodes

Outputs:
- `module4_compact/retained_events/*.jsonl`
- `module4_compact/process_states_prepath/*.json`
- `module4_compact/object_states/*.json`
- `module4_compact/episodes/*.json`

### `module5_paths`

- adds full `B_*` behavior labels
- propagates selected `P_*` status labels
- builds bridge edges
- searches candidate paths using process-tree edges + bridge edges
- scores and summarizes candidates

Current split-aware behavior:
- `TaskPrior` now carries `task_root_id` and `boundary_node_ids`
- `module5` backfills missing split metadata from `module1/tapas_native_graphs.pt` when older artifacts do not already contain those fields
- child tasks are processed after their parent task when a split relationship can be reconstructed
- the split-root process in a child task inherits the parent task's status labels, behavior labels, aggregate labels, important objects, and max score before path labeling runs

Why this matters:
- older TRACE `fanout > 2` artifacts could produce split child tasks with zero chains because the downstream copy of the split-root process lost the upstream labels that made the chain suspicious
- current `module5` explicitly preserves those labels across split boundaries

Outputs:
- `module5_paths/bridge_edges/*.json`
- `module5_paths/candidate_paths/*.json`
- `module5_paths/candidate_paths/*.md`
- `module5_paths/process_summary.json`
- `module5_paths/object_summary.json`

### `module6_reason`

- compresses each candidate path into a dossier
- calls the LLM twice:
  1. behavior/claim extraction
  2. ATT&CK mapping
- validates claims and mappings locally
- stores the exact LLM inputs actually sent

Current prompt format:
- the LLM is no longer fed large pretty-printed dossier JSON as the main context
- extract prompts now render a compact OCR-style text block with sections such as `PATH`, `PROCESSES`, `BRIDGES`, `TIMELINE`, and optional `WARNINGS`
- mapping prompts render a compact text block with `CLAIMS`, `CLAIM_HINTS`, `TACTIC_CANDIDATES`, and `TECHNIQUE_CANDIDATES`
- `claim_attack_hints` runtime shape is `list[dict]`; the renderer also accepts legacy dict-shaped hints

Practical consequence:
- the same token budget now carries more path semantics than the old raw-JSON prompt style
- debugging should look at `module6_reason/llm_inputs/*.input.json`, because those files contain the exact compact prompt text and the exact JSON response that the model saw

Important limit:
- `run_module6_reason()` iterates only over `payload[: cfg.reason_top_paths_per_task]`
- if `module5` emits 20 candidate paths for a task and `reason_top_paths_per_task = 5`, only the top 5 reach the LLM and can become reports

Outputs:
- `module6_reason/dossiers/*.json`
- `module6_reason/llm_inputs/*.input.json`
- `module6_reason/reports/*.report.json`
- `module6_reason/report_index.json`

## Module2 Semantics That Cause Confusion

Current `task_detection/tapas_native_backend.py` behavior:

### `task_detector_mode = fit_predict`

- `module1` builds the full task set
- `module2` trains on one split and writes only the evaluation split rows to `module2/suspicious_tasks.json`
- therefore `module1.task_count` can be much larger than `module2.task_count`
- `module2.summary.train_task_count` and `train_positive_count` are often the only place where GT-positive tasks in the training split are still visible

Important consequence:
- `module2/suspicious_tasks.json` is not an all-task inventory under `fit_predict`
- if a TRACE run shows `task_label == 1` count equal to zero in `suspicious_tasks.json`, that does not prove the run produced no malicious task graphs; it can simply mean all GT-positive graphs landed in the training split

### `task_detector_mode = load_and_predict`

- `module2` loads an existing model and predicts over all selected graphs
- summary field `prediction_adapter_mode` becomes `all_graphs_no_split`
- this is the current code path to use when downstream GT-only reasoning needs visibility over all selected task graphs

Current `module2` sidecar exports:
- `task_meta_rich.json` now carries `task_root_id` and `boundary_node_ids`
- `task_attribution.json` remains the per-task source/score attribution table used by `module3`

## TRACE Labeling Caveat

TRACE task graphs are built over process `cid` values, not raw subject UUID strings.

Relevant chain:
- `vendor/tapas/darpa.py::parser_trace()` rewrites subject nodes to `cid` / `parentcid`
- `task_detection/tapas_native_backend.py::_decompose_tc3_metadata()` then computes `task_label` by counting GT hits over `node_ids` from those task components

Practical reading rule:
- when interpreting current code, think of TRACE task-node identity as `cid`
- when interpreting old documents or older preserved artifacts, do not assume UUID-based and cid-based labels are directly comparable without checking the exact code path

## Historical Artifact Warning

Some preserved artifact directories were produced by older branches before the current cleanup.

Most important example:
- the preserved TRACE artifact `artifacts_trace_train_stats_latefusion_bonus1` contains `module2/suspicious_tasks.json` rows with `task_score_basis = ground_truth_membership` and `matched_ground_truth_process_ids`

That behavior is not generated by the current `task_detection/tapas_native_backend.py` code path. Treat such artifacts as historical experiment outputs, not as proof that the current code still emits the same row semantics.

Current compatibility behavior for old artifacts:
- if older `module2/module3` outputs do not already contain split metadata, current `module5` can recover it from `module1/tapas_native_graphs.pt`
- this is why preserved TRACE artifacts can still be rerun through the current `module5/module6` code without regenerating `module1-4`

## Evaluation Files

Unified GT:
- `docs/darpa_attack_eval_ground_truth_2026-05-26.json`
- `docs/darpa_attack_eval_ground_truth_2026-05-26_zh.md`

Typical TRACE eval output:
- `artifacts_trace_.../path_reason_eval_*/metrics_summary.json`
- `artifacts_trace_.../path_reason_eval_*/window_level_metrics.json`
- `artifacts_trace_.../path_reason_eval_*/technique_comparison.json`

## Recent Split-Mode Findings

### TRACE `fanout > 2`

This remains the working baseline.

Observed behavior:
- produces multiple smaller GT-hit tasks instead of one monolithic connected component
- reaches non-zero window recall and non-zero ATT&CK recall
- this is still the split mode to keep unless a future replacement clearly beats it

Current rerun finding after split-label inheritance landed:
- copied baseline artifacts into a fresh directory and reused `module1 -> module4`
- reran current `module5_paths` and `module6_reason`
- `task_0558` recovered from `0` candidate paths to `9`
- total `module5` candidate paths increased from `34` to `43`
- total `module6` reports increased from `10` to `15`
- official metrics did not move because the new recovered task landed in a window that was already covered and `module6` still caps each task at `5` reports
- remaining blocker is `task_0546`, which still produces `0` chains under the current path search logic

Practical consequence:
- if the goal is to improve current TRACE `fanout > 2`, inspect `task_0546` first
- if the goal is to inspect more recovered paths from already-working tasks, raise `reason_top_paths_per_task` and rerun only `module6_reason` plus evaluation

### TRACE `connected`

The repository now contains a real connected-components implementation in:
- `vendor/tapas/darpa.py`

This replaced the older pseudo-connected behavior that merely disabled fanout splitting.

Observed behavior on current true-connected TRACE reruns:
- `load_and_predict` can export all 14 task graphs, but GT-positive tasks collapse into one giant connected task
- GT-only downstream reasoning over that giant task quickly hits the event budget ceiling
- a current GT-only rerun with `evidence_recover_max_events_per_task = 600000` still produced only one selected task, `20` candidate paths, and `5` reports
- official window evaluation remained a failure

Interpretation:
- connected TRACE still over-merges normal and malicious context into giant components
- the downstream path reasoner then spends its budget on noisy context or off-window material
- do not use `task_component_split_mode = connected` for current TRACE experiments unless the goal is specifically to study this failure mode

### TRACE `fanout > 3`

This was also tried and did not beat the `fanout > 2` baseline.

Practical conclusion:
- keep `fanout` with child-threshold `2` as the current TRACE default

## What Was Removed

These routes are no longer part of the supported repo surface:
- old GraphDB / `module3` route
- old `module3_local -> module4` route
- old `module3_index -> module3_bundle -> module4_reason -> module5_campaign` route

If you need historical design context, read the documents in `docs/`, but do not treat those removed modules as current implementation targets.
