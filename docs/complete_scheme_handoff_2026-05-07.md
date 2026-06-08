# Complete Scheme Handoff (2026-05-07)

## Innovation Summary

The current APT-Fusion scheme is no longer a plain TAPAS detector or a plain OCR-APT-style LLM investigator. Its main innovation is that it uses TAPAS task graphs as the front-half detection unit, then reconstructs a structured evidence layer around each suspicious task, and finally lets the LLM reason over evidence bundles instead of raw logs or opaque graph tensors. In practice, this means we now have a task-centered pipeline that connects process-task detection, evidence indexing, IOC extraction, threat-claim construction, ATT&CK mapping, and cross-task campaign aggregation into one chain. The key value is not only better modularity, but also that low-level process relations, event evidence, IOC candidates, semantic claims, and ATT&CK tactics/techniques are explicitly linked step by step, so the final analysis is more verifiable than direct free-form LLM summarization and more semantically expressive than a pure graph classifier.

## 1. Current Implemented Pipeline

As of this handoff, the effective pipeline is:

```text
module1
-> module2
-> module3_index
-> module3_bundle
-> module4_reason
-> module5_campaign
```

There are older `module3_local` and `module4` paths in the repository, but the active attack-technique analysis path is now the indexed / bundled / reasoned path above.

### 1.1 Module 1: TAPAS-native task-graph export

Responsibilities:

- parse raw logs with official TAPAS-style dataset parsers
- encode per-process historical behavior into sequence embeddings
- cut task relations from process parent-child structure
- decompose the resulting relation graph into task graphs
- optionally append OCR-style per-process statistical features
- export a native graph payload for downstream detection

Outputs:

- `process_embeddings.csv`
- `task_subgraphs.json`
- `process_segmentation_edges.csv`
- `tapas_native_graphs.pt`
- `tapas_native_module1_summary.json`

Important truth:

- the actual task graph is a process-only graph
- nodes are process behavior vectors
- edges are parent-child task edges
- files / netflows / raw events are not preserved as graph nodes in the final training graph

### 1.2 Module 2: TAPAS-native detection and task-sidecar export

Responsibilities:

- load `tapas_native_graphs.pt`
- optionally augment malicious task graphs
- train or load TAPAS GraphSAGE
- optionally fuse OCR-style graph-stat features through XGBoost late fusion
- score task graphs and export suspicious tasks
- export sidecar data needed by later investigation and reporting stages

Core outputs:

- `task_scores.csv`
- `task_subgraph_summary.json`
- `tapas_native_model.pt`
- `suspicious_tasks.json`
- `process_scores.csv`
- `run_0_raised_alarms.csv`
- `task_meta_rich.json`
- `task_attribution.json`

Important truth:

- `suspicious_tasks.json` is the main task-level detection export
- `task_meta_rich.json` and `task_attribution.json` are not cosmetic; they are now part of the core downstream reasoning chain
- augmented tasks like `task_xxxx_augNNN` can now fall back to the base task graph for sidecar generation

### 1.3 Module 3 Index: evidence indexing

Responsibilities:

- load suspicious task rows from module2
- load task sidecars
- rescan raw logs
- write task-related evidence into a local SQLite evidence index

Outputs:

- `module3_index/evidence_index.sqlite`
- `module3_index/task_index.json`
- `module3_index/summary.json`

The index stores:

- task rows
- task processes
- nodes
- events
- task-event mappings
- optional FTS entries

This stage is important because later investigation does not need to rescan the full raw dataset repeatedly.

### 1.4 Module 3 Bundle: task evidence bundles

Responsibilities:

- read task-level evidence from the index
- select and compress key events
- build episodes
- collect IOC candidates
- package all evidence into one task bundle

Outputs:

- `module3_bundle/bundles/bundle_*.json`
- `module3_bundle/markdown/bundle_*.md`
- `module3_bundle/bundle_index.json`
- `module3_bundle/summary.json`

Bundle fields include:

- task identifiers and scores
- process IDs
- task detection summary
- task meta sidecars
- task attribution sidecars
- selected events
- episodes
- IOC candidates
- retrieval statistics

This is the main bridge from graph detection to LLM reasoning.

### 1.5 Module 4 Reason: task-level LLM reasoning

Responsibilities:

- read bundle JSON
- construct a compact LLM context
- run stage-1 extraction
- validate claims and IOCs
- load local ATT&CK KB candidates
- run stage-2 ATT&CK mapping
- validate mappings
- write task reports

Outputs:

- `module4_reason/reports/task_report_*.json`
- `module4_reason/markdown/task_report_*.md`
- `module4_reason/report_index.json`
- `module4_reason/summary.json`

The implemented reasoning is two-stage:

1. extract:
   - `summary`
   - `claims`
   - `iocs`
   - `gaps`

2. map:
   - `attack_mappings`
   - `gaps`

Important truth:

- claims and IOCs are produced by the LLM but are not trusted blindly
- they are validated against real `event_id` / `episode_id`
- local ATT&CK STIX is used to narrow ATT&CK candidates before mapping
- fallback logic now fills in missing summary / claims / IOCs when the LLM returns over-conservative empty output
- per-task timeout/failure handling now allows the batch to continue instead of killing the whole stage

### 1.6 Module 5 Campaign: cross-task aggregation

Responsibilities:

- read task reports
- compute report similarity
- cluster related tasks
- write campaign-level outputs

Outputs:

- `module5_campaign/clusters/cluster_*.json`
- `module5_campaign/markdown/cluster_*.md`
- `module5_campaign/cluster_index.json`
- `module5_campaign/pair_scores.json`
- `module5_campaign/summary.json`
- `module5_campaign/global_campaign_report.md`

Current truth:

- this is still a rule-based clustering stage, not a full LLM campaign summarizer
- similarity mainly uses shared IOCs, shared ATT&CK IDs, shared process IDs, and time proximity

## 2. Threat-Semantic Association: What the Scheme Actually Emphasizes

The threat-semantic core of the scheme is:

```text
task graph
-> evidence bundle
-> claims
-> ATT&CK mappings
-> campaign clusters
```

This means the method does not stop at "which IOC appeared" or "which task scored high."

Instead, it progressively upgrades low-level evidence into semantic structure:

- task graph says which processes belong to the same suspicious unit
- bundle says which events, episodes, and IOCs are the key evidence around that unit
- claims say what behavior those events imply
- ATT&CK mappings say what TTP family those behaviors correspond to
- campaign clustering says which task reports likely belong to the same attack storyline

This is the main semantic advantage over both:

- pure TAPAS-style graph classification
- direct document-style LLM summarization

## 3. Task Graph Segmentation: What the Code Really Does

This point was investigated carefully and is important enough to record explicitly.

### 3.1 Current code truth

The current code does **not** implement the full threshold-based segmentation procedure described in the TAPAS paper algorithm.

What the code actually does is:

1. extract parent-child process relations
2. clean inconsistent parent-child assignments
3. build task edges as `child -> parent`
4. split the resulting relation graph by weakly connected components
5. drop empty-edge components and single-node components

So the real segmentation rule in code is:

```text
parent-child edge cleaning
-> connected-component decomposition
```

### 3.2 What is not implemented

The paper algorithm includes signals such as:

- parent-child merges with `tgid`
- `ChildNum`
- `Listseg`
- `children > 2`
- ancestry propagation / update

After checking:

- `TAPAS_release`
- `TAPAS-artifact`
- `vendor/tapas`

the full `children > 2` threshold segmentation is not present in the actual code paths used for:

- `trace`
- `cadets`
- `fivedirections`
- `theia`
- `optc`

`theia` does contain a `tgid`-based subject merge in an older path, but even there the full `ChildNum / Listseg / ancestry` segmentation logic is absent.

### 3.3 Consequence

The current implementation should be described honestly as:

```text
a simplified TAPAS-style task graph segmentation
based on cleaned parent-child process relations and connected components
```

not as a faithful end-to-end implementation of the paper pseudocode.

## 4. What a Real Training/Test Task Graph Looks Like

The training/test task graph is not a provenance graph with mixed node types.

It is a process-only graph of the form:

```json
{
  "nodes": [process_feature_vector, ...],
  "edges": [[src_index, dst_index], ...],
  "label": 0_or_1,
  "attacknum": integer
}
```

Then it is converted into:

```python
Data(x=x, edge_index=edge_index, y=y)
```

Meaning:

- `x`: node feature matrix
- `edge_index`: graph edges in PyG format
- `y`: graph label

### 4.1 Important identity detail

The naked graph tensor does not embed human-readable process IDs in each node.

Instead, the mapping is positional:

```text
node_ids[j] <-> graph["nodes"][j]
```

APT-Fusion preserves this mapping through `selected_graph_metas[*]["node_ids"]`, which is essential for later explainability and reporting.

### 4.2 Example shape

For a graph like `task_1349`, the real structure is:

- 4 process nodes
- 3 parent-child edges
- 95-dimensional node vectors in the current local run
- label = malicious

This is the object used in both training and testing. The train/test difference is split membership, not graph format.

## 5. What the LLM Actually Sees Later

The LLM does not see the raw `Data(x, edge_index, y)` graph.

Instead, it sees a task evidence bundle context containing:

- task IDs and scores
- process IDs
- task detection summary
- task meta sidecar
- task attribution sidecar
- IOC candidates
- selected events
- episodes

So the LLM-facing object is a structured JSON evidence package, not the training graph tensor.

This distinction matters:

- the detector learns from numeric graph structure
- the LLM reasons over reconstructed evidence and semantic summaries

## 6. IOC Strategy: Current Implementation vs Full Intended Design

### 6.1 Current implementation

Current IOC handling is:

```text
events
-> regex / rule-based ioc_candidates
-> LLM outputs iocs
-> programmatic validation
-> fallback if output is empty
```

This means:

- `ioc_candidates` are not directly produced by the LLM
- the LLM selects or refines report-worthy IOCs from evidence context
- final IOCs are still constrained by evidence presence

### 6.2 Why this differs from OCR-APT

OCR-APT is closer to:

```text
documentized subgraph
-> LLM retrieves IOC list
-> post-hoc hallucination filtering
```

APT-Fusion is closer to:

```text
structured evidence
-> deterministic IOC candidates
-> LLM semantic selection
-> validation
```

This improves control and verifiability, but can reduce IOC recall if the extraction layer is too conservative.

### 6.3 Full intended IOC pipeline

The complete target design discussed earlier is richer than the current implementation:

```text
structured evidence
-> deterministic IOC extraction
-> normalization / deduplication
-> local TI / rule enrichment
-> LLM IOC and claim refinement
-> validation
-> IOC-driven second-pass context expansion
-> final all_iocs + report_iocs
```

This full version has not yet been completely implemented.

## 7. ATT&CK Knowledge Integration

Current scheme already integrates a local ATT&CK knowledge base through STIX.

This is used for:

- tactic / technique candidate narrowing
- more stable ATT&CK mapping in `module4_reason`

Important truth:

- this is ATT&CK knowledge support
- it is not a general IOC threat-intelligence enrichment system such as MISP or OpenCTI

## 8. Recent Confirmed Fixes and Important Local Deviations

These details were confirmed during debugging and are worth preserving.

### 8.1 Trace parser parent resolution fix

The trace parser was adjusted so that parent processes that appear later in the log do not automatically become `Unknow`.

The fix is a two-pass idea:

1. collect all subject UUID -> cid mappings
2. resolve parent UUID -> parent cid afterwards

This is important for trace correctness and means trace should be rerun from `module1` when this parser logic changes.

### 8.2 Trace augmentation bonus

A trace-only augmentation bonus was added so the effective malicious-graph augmentation factor can become:

```text
count // 2000 + bonus
```

This is a project-side local modification and not part of original TAPAS.

### 8.3 Augmented task sidecars

Augmented tasks like `task_xxxx_augNNN` originally could appear in detection results without getting downstream sidecars.

This was fixed by allowing sidecar generation to fall back to the base graph task while still recording the augmented task ID.

### 8.4 Module4 reason robustness

The current reasoning stage includes:

- deterministic fallback for missing summary / claims / IOCs
- corrected evidence support rate handling for empty outputs
- per-task failure continuation

These are project-side robustness improvements beyond the older direct-report flow.

## 9. Known Gaps

The following items remain true and should not be overstated:

1. The full paper-style threshold segmentation logic is not implemented.
2. The current IOC pipeline is still lighter than the intended complete version.
3. Campaign summarization is still mostly rule-based clustering, not full LLM storytelling.
4. The LLM back half is evidence-aware and structured, but still sensitive to bundle quality and timeout behavior.

## 10. Recommended Short Description for External Communication

If we need one accurate short external description, the safest version is:

> APT-Fusion currently combines TAPAS-native task-graph detection with a structured evidence-and-LLM investigation pipeline. The front half detects suspicious process-task graphs, while the back half rebuilds task-centered evidence bundles, extracts validated claims and IOCs, maps them to ATT&CK with local knowledge support, and clusters related task reports into campaign-level results. The current task segmentation implementation is based on cleaned parent-child process relations and connected-component decomposition rather than the full threshold-based pseudocode shown in the TAPAS paper.
