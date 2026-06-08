# TRACE Attack Report vs Task-Graph Alignment (2026-05-19)

## Purpose

This note aligns the uploaded TRACE attack report with the current four GT-hit malicious task graphs, so we can compare:

1. Which task graph corresponds to which report segment.
2. Which ATT&CK techniques are expected from the report.
3. Which ATT&CK techniques our current pipeline actually detected.

The goal here is not to train the model from the report, but to create a clean comparison baseline for precision/recall analysis.

## Inputs

- Attack report:
  - [TRACE_ATTACK_ATTCK_MAPPING.md](D:/download/TRACE_ATTACK_ATTCK_MAPPING.md)
- Current final task-level outputs on cloud:
  - `/root/autodl-tmp/APT-Fusion/artifacts_trace_train_stats_latefusion_bonus1/module4_reason/per_bundle_runs_20260518_final_best/reports`
- Current task bundles on cloud:
  - `/root/autodl-tmp/APT-Fusion/artifacts_trace_train_stats_latefusion_bonus1/module3_bundle`

## Important Caveat

There is a visible clock-offset issue between the uploaded report timeline and the task-bundle timestamps.

For example:

- Report segment: `2018-04-13 12:43-12:53`
- Best-matching task: `task_0345`, bundle time: `2018-04-13 16:43:01-16:53:30`

This is too behaviorally specific to be a coincidence, so for alignment we use:

1. Same calendar date.
2. Strong behavior and artifact overlap.
3. Time proximity after allowing for a consistent offset.

Because of that, the alignment below is primarily behavior-driven, with time used as a supporting signal rather than the only signal.

## Report Segments

For comparison, the most relevant report segments are:

1. `2018-04-13 12:43-12:53`
   - Browser/allstate chain obtains shell.
   - `ps`, `elevate ztmp`, file execution.
   - Micro APT callback.
   - Port scan.
   - Delete `/tmp/ztmp`.
   - `netrecon`.
   - Report ATT&CK:
     - `T1189`
     - `T1203`
     - `T1057`
     - `T1046`
     - `T1071.001`
     - `T1105`
     - `T1070.004`

2. `2018-04-13 13:50-14:28`
   - Spearphishing attachment / Pine chain.
   - `tcexec` failure, vulnerable `pine`, fake `tcexec`.
   - Micro APT callback.
   - Port scan.
   - Shell attempts fail.
   - Report ATT&CK:
     - `T1566.001`
     - `T1204.002`
     - `T1071.001`
     - `T1046`
     - weak/optional: `T1114` or `T1005`

## Task-to-Report Alignment

| Task | Bundle Time Window | Strongest Observed Evidence | Best-Matching Report Segment | Confidence |
|---|---|---|---|---|
| `task_0345` | `2018-04-13 16:43:01-16:53:30` | `/tmp/ztmp`, `./gtcache`, single-bucket 721-port scan to `128.55.12.73`, callback traffic to `146.153.68.151:80` and `162.66.239.75:80`, file activity on `/tmp/ztmp` | `2018-04-13 12:43-12:53` | High |
| `task_0557` | `2018-04-13 18:16:16-18:29:41` | `tcexec`, `pine`, `./pine`, huge multi-host port scan burst, callback-like traffic to `162.66.239.75:80`, shell/file traces including `/usr/bin/rsh ... /etc/rimapd` | `2018-04-13 13:50-14:28` | High |
| `task_0558` | `2018-04-13 18:20:18-18:28:09` | `tcexec`, extremely dense network burst, 10 remote hosts, repeated 5978-port sweeps, callback-like traffic to `162.66.239.75:80` | `2018-04-13 13:50-14:28` | High |
| `task_0546` | `2018-04-13 14:22:12-20:55:53` | `firefox`, `thunderbird`, `www.boston.com`, `www.builder.com`, `command-not-found -- tcexec`, long-span mixed browser/mail/file activity, no clean dominant attack burst | likely supporting context around `2018-04-13 13:50-14:28`, but not a clean 1:1 attack segment | Medium-Low |

## Current Detected ATT&CK per Task

### task_0345

- Detected:
  - `T1059 Command and Scripting Interpreter`
  - `T1046 Network Service Discovery`
  - `T1070.004 File Deletion`
- Best-matched report segment expected:
  - `T1189`
  - `T1203`
  - `T1057`
  - `T1046`
  - `T1071.001`
  - `T1105`
  - `T1070.004`

Assessment:

- Strong matches:
  - `T1046`
  - `T1070.004`
- Semantically plausible but not report-labeled:
  - `T1059`
- Missed from report:
  - `T1189`
  - `T1203`
  - `T1057`
  - `T1071.001`
  - `T1105`

Interpretation:

- The system correctly captures the scan burst and cleanup/deletion behavior.
- It does not yet recover the browser exploit / initial access / callback / transfer chain from this task.

### task_0557

- Detected:
  - `T1046 Network Service Discovery`
- Best-matched report segment expected:
  - `T1566.001`
  - `T1204.002`
  - `T1071.001`
  - `T1046`

Assessment:

- Strong match:
  - `T1046`
- Missed from report:
  - `T1566.001`
  - `T1204.002`
  - `T1071.001`

Interpretation:

- The system reliably finds the port-scan part.
- It does not yet identify the attachment/open chain or the callback channel as ATT&CK techniques.

### task_0558

- Detected:
  - `T1046 Network Service Discovery`
- Best-matched report segment expected:
  - `T1566.001`
  - `T1204.002`
  - `T1071.001`
  - `T1046`

Assessment:

- Strong match:
  - `T1046`
- Missed from report:
  - `T1566.001`
  - `T1204.002`
  - `T1071.001`

Interpretation:

- This task is essentially the network-scan core of the same attack burst.
- The mapping is precise but narrow.

### task_0546

- Detected:
  - none
- Plausible report relation:
  - browser/mail/supporting activity around the `2018-04-13` afternoon attack

Assessment:

- No ATT&CK mapped.
- Current behavior extraction is too weak and too mixed for confident alignment.

Interpretation:

- This task likely contains useful precursor or surrounding context.
- It is not yet being converted into actionable behavior claims.

## Precision-Oriented Summary

If we score only the three high-confidence task/report alignments (`0345`, `0557`, `0558`):

- Total detected mappings: `5`
- Report-supported strict matches: `4`
  - `T1046` on `0345`
  - `T1070.004` on `0345`
  - `T1046` on `0557`
  - `T1046` on `0558`
- Strict precision: `4 / 5 = 80%`

This is encouraging: the current system is no longer wildly hallucinating ATT&CK.

But recall is still low:

- `task_0345` covers only the scan and deletion parts of the noon web/extension attack.
- `task_0557/0558` cover only the scan part of the afternoon email/Pine chain.
- `task_0546` still contributes no mapped ATT&CK.

So the current state is:

- Precision: decent on the techniques it does emit.
- Recall: still poor for initial access, client execution, callback/web-protocol C2, and tool transfer.

## What This Tells Us About Current Weaknesses

### 1. We are good at scan-heavy discovery signals

The system now reliably recovers:

- `T1046 Network Service Discovery`

This matches what we already know from the data:

- network bursts dominate the provenance evidence
- `tcexec` scan behavior is extremely easy to summarize

### 2. We can recover explicit cleanup/file-removal when the artifact is strong enough

`task_0345` successfully recovered:

- `T1070.004 File Deletion`

This is a meaningful improvement because it aligns with the report's `/tmp/ztmp` deletion step.

### 3. We still miss the front half of the attack chain

What remains weak:

- `T1189 Drive-by Compromise`
- `T1203 Exploitation for Client Execution`
- `T1566.001 Spearphishing Attachment`
- `T1204.002 User Execution: Malicious File`
- `T1071.001 Web Protocols`
- `T1105 Ingress Tool Transfer`

These misses suggest a common root cause:

- our current task-level evidence packets are strong on bursty observable effects
- but still weak on causal chain reconstruction for browser/email -> payload -> callback -> transfer

## Practical Next-Step Guidance

This alignment suggests the next optimization targets are:

1. **Recover callback and transfer as first-class behavior claims**
   - Especially for:
     - `146.153.68.151:80`
     - `162.66.239.75:80`
   - We currently summarize them, but the claim schema still prefers scan behavior over callback/transfer behavior.

2. **Add browser/mail execution-chain summaries**
   - We need explicit behavior summaries for:
     - browser-triggered execution
     - mail-client-triggered attachment execution
     - fake executable / renamed executable execution

3. **Treat `0557` and `0558` as one attack burst during evaluation**
   - They are behaviorally the same report segment split across two task graphs.
   - Scoring them independently undervalues what the pipeline is already reconstructing.

4. **Use `0546` as the main file/browser/mail improvement target**
   - It contains the right ecosystem:
     - `firefox`
     - `thunderbird`
     - `www.boston.com`
     - `www.builder.com`
     - `tcexec`
   - But our current claims are still too generic to map confidently.

## Bottom Line

The current pipeline has reached a useful intermediate stage:

- It can now map the scan-heavy and deletion-heavy parts of the TRACE attacks with decent precision.
- It still under-detects the initial access, client execution, callback, and tool-transfer portions described in the report.

So if we use the uploaded report as the comparison baseline, the most accurate short summary is:

**Current ATT&CK precision is acceptable on emitted mappings, but recall is still concentrated on the "loud middle" of the attack chain rather than the full chain from delivery/exploitation to callback and payload transfer.**
