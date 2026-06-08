# TRACE / THEIA / CADETS Cross-Dataset Evaluation (2026-05-20)

## Purpose

This note consolidates the current ATT&CK evaluation status across:

- TRACE
- THEIA
- CADETS

It focuses on:

1. Current task-level ATT&CK precision/recall against uploaded attack reports.
2. What went right or wrong in each dataset.
3. Cross-dataset patterns that can guide the next noise-reduction and evidence-selection changes.

## Inputs

- TRACE report alignment baseline:
  - [trace_report_task_alignment_2026-05-19.md](D:/daima/APT-Fusion/docs/trace_report_task_alignment_2026-05-19.md)
- Multi-host attack report windows:
  - [ALL_HOSTS_ATTACK_ATTCK_MAPPING.md](D:/download/ALL_HOSTS_ATTACK_ATTCK_MAPPING.md)
- Parsed report windows:
  - `D:\daima\APT-Fusion\debug\report_alignment\all_hosts_report_windows.json`
- THEIA selected-window reports:
  - `D:\daima\APT-Fusion\debug\report_alignment\theia_window0412_reports`
- CADETS full GT-hit reports:
  - `D:\daima\APT-Fusion\debug\report_alignment\cadets_full_reports`

## Current Dataset-Level Result Snapshot

| Dataset | Evaluation Unit | Predicted Technique Union | Expected Technique Union | Precision | Recall | Main Failure Mode |
|---|---|---|---|---:|---:|---|
| TRACE | 3 high-confidence task/report alignments (`0345`, `0557`, `0558`) | 5 mappings total; 4 strict report-supported matches | report-supported per aligned segment | `80%` | low | good on scan/deletion, weak on delivery/exploit/callback/tool-transfer |
| THEIA | 13 GT-hit tasks aligned to `2018-04-12` browser-extension window | `T1053`, `T1102.001`, `T1584.001` | `T1189`, `T1203`, `T1033`, `T1057`, `T1055`, `T1068`, `T1105`, `T1046`, `T1071.001`, `T1070.004` | `0.00` | `0.00` | GT-hit task fragments are too local and miss the real technique-bearing context |
| CADETS | 4 GT-hit tasks vs union of high-confidence CADETS windows | `T1046`, `T1053.005`, `T1071.001` | `T1190`, `T1068`, `T1046`, `T1105`, `T1055`, `T1071.001`, `T1070.004`, `T1057` | `0.667` | `0.25` | tasks are too broad and merge long time spans / multiple attack phases |

## TRACE

Reference:

- [trace_report_task_alignment_2026-05-19.md](D:/daima/APT-Fusion/docs/trace_report_task_alignment_2026-05-19.md)

Current best interpretation:

- The pipeline can now recover:
  - `T1046 Network Service Discovery`
  - `T1070.004 File Deletion`
- It does this with decent precision on the emitted mappings.
- It still under-recovers:
  - `T1189`
  - `T1203`
  - `T1566.001`
  - `T1204.002`
  - `T1071.001`
  - `T1105`

What TRACE taught us:

- Malicious non-process objects cluster very strongly around a few subject processes:
  - `ztmp`
  - `tceexec`
- `0557/0558` are scan-heavy network bursts.
- `0345` is mixed scan + temp-file / cleanup.
- `0546` is browser / mail / file-heavy and needs a different compression strategy.

## THEIA

### Window Used for Evaluation

- `theia_2018_04_12_browser_extension_micro_apt`
- Expected techniques:
  - `T1189`
  - `T1203`
  - `T1033`
  - `T1057`
  - `T1055`
  - `T1068`
  - `T1105`
  - `T1046`
  - `T1071.001`
  - `T1070.004`

### Current Prediction Union

- `T1053`
- `T1102.001`
- `T1584.001`

### Result

- Precision: `0 / 3 = 0.00`
- Recall: `0 / 10 = 0.00`

### Why THEIA Failed

This is the most important finding from THEIA:

1. The selected GT-hit tasks were all short, local fragments around:
   - `fluxbox`
   - `/usr/bin/firefox`
2. For all 13 selected tasks:
   - `network_digest.total_network_events = 0`
3. Re-running THEIA with:
   - `local_context_include_object_side: true`
   did **not** recover network digest coverage for those selected tasks.

Interpretation:

- The issue is not just `subject-only` vs `object-side`.
- The bigger issue is that the GT-hit task fragments themselves do not align with the full attack-bearing context in the report window.
- In other words:
  - **THEIA currently fails because the right attack window is not being represented by the right task graph slice.**

### Practical Meaning

If we keep evaluating THEIA strictly at the current GT-hit task-fragment level:

- ATT&CK mapping quality will remain poor
- no amount of small prompt tuning is likely to fix it

THEIA needs:

1. report-window aggregation
2. neighboring-task / sibling-task expansion
3. or attack-window-level reasoning instead of single-fragment reasoning

## CADETS

### High-Confidence Expected Technique Union

From the uploaded report windows, the high-confidence CADETS technique union is:

- `T1190`
- `T1068`
- `T1046`
- `T1105`
- `T1055`
- `T1071.001`
- `T1070.004`
- `T1057`

### Current Prediction Union

- `T1046`
- `T1053.005`
- `T1071.001`

### Result

- Precision: `2 / 3 = 0.667`
- Recall: `2 / 8 = 0.25`

### Per-Task Pattern

- `task_0010`
  - predicted `T1046`
- `task_0015`
  - predicted `T1071.001`
- `task_0017`
  - predicted `T1071.001`
- `task_0007`
  - predicted `T1053.005`

### What CADETS Taught Us

CADETS differs from TRACE and THEIA in an important way:

- GT-hit tasks are very broad and multi-day.
- Example windows span:
  - `2018-04-11 20:37` to `2018-04-13 21:11`
- So unlike TRACE:
  - CADETS does not fail because tasks are too fine.
- Instead:
  - **CADETS fails because tasks are too coarse and merge multiple phases into giant broad components.**

This explains the pattern:

- it can recover broad network semantics like:
  - `T1046`
  - `T1071.001`
- but misses:
  - `T1190`
  - `T1105`
  - `T1055`
  - `T1068`
  - `T1070.004`
  - `T1057`

## Cross-Dataset Patterns

The three datasets are not failing for the same reason.

### Pattern 1: TRACE

- tasks are reasonably aligned to real attack bursts
- noise is high, but the task slices are usable
- best next step:
  - improve evidence compression and claim specificity

### Pattern 2: THEIA

- tasks are too fragmented
- selected GT-hit slices miss the attack-bearing network/callback context
- best next step:
  - attack-window-level aggregation
  - sibling-task expansion
  - not just better prompting

### Pattern 3: CADETS

- tasks are too broad
- one task may cover multiple hours or days
- best next step:
  - time-window segmentation inside a GT-hit task
  - anchor-process / anchor-time-bucket reasoning

## The Most Actionable Optimization Directions

### 1. Stop using one evidence-selection strategy for every dataset

We now have clear evidence that:

- TRACE wants burst-aware compression
- THEIA wants task aggregation
- CADETS wants time-window splitting

### 2. Add dataset-specific "task usability diagnosis" before LLM reasoning

Before running ATT&CK mapping, classify a GT-hit task as:

- `burst-aligned`
- `too-fragmented`
- `too-broad`

Then switch reasoning strategy accordingly.

### 3. Prioritize task/window restructuring before more prompt tuning

Prompt compression already helped stability.

But now the dominant remaining problem is structural:

- wrong task slice in THEIA
- over-merged task slice in CADETS

### 4. Keep the current TRACE-style lane/digest pipeline for TRACE

TRACE is still the clearest proof that the current bundle + digest + OCR-style compact prompt direction is valid.

The lesson is not to throw that away.

The lesson is:

- keep it for TRACE-like burst tasks
- add different pre-reasoning restructuring for THEIA and CADETS

## Recommended Next Step

If we want the next big gain in cross-dataset ATT&CK accuracy, the most valuable change is:

1. add a **window / sub-window restructuring layer before `module4_reason`**
2. use it differently by dataset:
   - TRACE:
     - keep current GT-hit tasks, just improve summaries
   - THEIA:
     - merge neighboring GT-hit fragments into attack-window contexts
   - CADETS:
     - split broad GT-hit tasks into high-activity attack windows

That should improve accuracy much more than another round of small prompt edits.
