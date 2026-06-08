# Core Task Relevance Filter Design

## Purpose
This note records the current idea for improving the trace-task LLM reasoning pipeline so we can come back later and immediately know:

1. why the change is needed,
2. what to change,
3. where to change it,
4. what alternative designs were considered.

The idea below is based on the recent GT-seed trace experiments on the cloud server, where we intentionally used original ground-truth-hit task graphs rather than augmentation-detected tasks.

## Problem We Observed
We verified that task-graph segmentation alone is not enough to stabilize task-level LLM reasoning.

### What we ran
- Original GT-seed trace set: 5 ground-truth-hit tasks
- Paper-branch segmented GT-seed trace set: 8 segmented tasks
- Model: `llama3_1_8b_instruct_ms_q3km`

### What happened
Under the default reasoning context size:
- all 5 original GT-seed bundles timed out;
- all 8 segmented bundles also timed out.

That means:
- the failure is not only caused by "task graph too large";
- even after segmenting the graph, the bundle can still remain too noisy or too bloated.

### Why segmentation alone did not solve it
The most important finding was this:
- graph segmentation reduced process-node count for some tasks,
- but `module3_bundle` still retrieved too many events, episodes, and IOC candidates around those processes.

Example pattern we repeatedly saw:
- task graph became small,
- but bundle still contained around `200` events,
- close to `200` episodes,
- and very noisy IOC candidates such as hundreds of `ports`.

This means the main issue is not only graph size. It is also the quality of the 1-hop evidence selection around core processes.

## Key Experimental Conclusion
Two different levers behaved differently:

### 1. Tightening the reasoning prompt helps immediately
When we forced smaller reasoning inputs such as:
- `max_events = 20`
- `max_episodes = 20`
- `max_iocs_per_type = 6`

the results improved substantially:
- 4/5 original GT-seed bundles succeeded;
- all 8 segmented bundles succeeded.

### 2. Segmentation still matters, but mainly for semantically messy tasks
Segmentation was especially useful for tasks like the original `task_0198`, which still failed as one bundle under tighter caps but succeeded after being split into smaller branches.

So the current understanding is:

- prompt compression is necessary;
- graph segmentation is useful;
- but the next important missing layer is a graph-aware relevance filter for 1-hop evidence.

## Core Idea
Instead of sending "all 1-hop information around all task processes" into the bundle, we should keep only the 1-hop evidence most related to the core task.

In short:

```text
task graph
-> choose core process seeds
-> collect 1-hop candidates
-> score/filter them by task relevance
-> build filtered bundle
-> run LLM reasoning
```

This is the main idea we want to preserve.

## Why This Change Makes Sense
From the graph point of view, the current bundle-building logic is still too recall-heavy:
- it retrieves a broad neighborhood,
- merges in many repeated or weakly related events,
- and passes a lot of low-value context to the LLM.

That broad retrieval is useful for not missing evidence, but it becomes harmful when:
- repeated events dominate,
- temporary or low-value neighbors flood the context,
- large port lists explode,
- and semantically central actions become buried.

The change we want is therefore not "use more hops" or "split more aggressively everywhere". It is:

**seed-centered, path-aware, core-task-focused 1-hop filtering.**

## Proposed Change

### New layer to introduce
Add a new layer between `module3_bundle` and `module4_reason`:

```text
module3_bundle
-> Core Task Relevance Filter
-> filtered bundle fields
-> module4_reason
```

### New concept
The filter should rank candidate events, nodes, and IOC candidates by how strongly they support the core task represented by the task graph.

### Seed selection
Do not treat every process equally.

Use a small set of seed processes, preferably:
- the top `1-3` processes from `task_attribution.top_processes`,
- or root/bridge processes within a segmented subtask,
- or, in a future stronger version, nodes selected by a graph explainer.

### Candidate set
For each seed process, collect a local 1-hop candidate pool:
- directly related events,
- directly touched files/paths,
- directly connected flows/endpoints,
- directly spawned/parent processes,
- nearby episodes.

This stage remains recall-oriented.

### Then filter aggressively
This is the new part.

We should remove or down-rank:
- repeated near-identical events,
- temporary or low-value transient objects,
- objects not lying on relevant attack paths,
- high-frequency low-information ports,
- events too far from the task’s key time window,
- nodes not structurally tied to the task’s core processes.

## Recommended Scoring Model
Use a relevance score such as:

```text
Relevance
= alpha * structural_contribution
+ beta  * path_contribution
+ gamma * semantic_risk
+ delta * temporal_proximity
+ epsilon * local_proximity
- lambda * redundancy_penalty
```

### 1. Structural contribution
Higher if a candidate is:
- directly attached to a top-ranked process,
- connected through a top-ranked edge,
- or located inside the compact subgraph most responsible for the task score.

### 2. Path contribution
Higher if the candidate lies on a meaningful path such as:
- process -> executable file,
- process -> shell,
- process -> external connection,
- process -> suspicious write -> execution.

This keeps us closer to attack-relevant information flow rather than raw neighborhood size.

### 3. Semantic risk
Higher for actions like:
- `EXECUTE`
- `CONNECT`
- executable `WRITE`
- `MMAP`
- `LOAD`
- shell/process creation patterns

Lower for low-information actions like:
- repetitive `READ`
- `CLOSE`
- repetitive metadata-only accesses

### 4. Temporal proximity
Higher if the event is close in time to the task’s core suspicious behavior.

### 5. Local proximity
Higher if the candidate is locally central to the seed process neighborhood.

Possible future implementations:
- Personalized PageRank,
- local centrality,
- shallow community relevance.

### 6. Redundancy penalty
Strongly penalize:
- repeated ports,
- repeated event templates,
- duplicated object accesses that add bulk but not new semantics.

## How We Should Modify the Current Code

### Recommended implementation order
Start with a simple rule-driven version before moving to explainers.

### Phase 1: practical rule-based filter
Add a first implementation that uses only what the current pipeline already has:
- `task_attribution.top_processes`
- `task_meta_rich.local_edges`
- bundle `events`
- bundle `episodes`
- bundle `ioc_candidates`

Suggested implementation steps:
1. pick seed processes from `top_processes`;
2. group and deduplicate repeated events;
3. score events by action type and temporal proximity;
4. strongly compress `ports`;
5. keep only top-ranked events and IOC candidates per seed and per type.

This version is the best first target because it is cheap and directly grounded in current artifacts.

### Phase 2: path-aware filter
Extend the filter so candidates must lie on or near attack-relevant paths from the seed process to:
- external communication,
- executable artifacts,
- shell activity,
- persistence-like objects.

This is the next best upgrade if Phase 1 still leaves too much noise.

### Phase 3: explainer-enhanced filter
Later, add a graph explanation component so the filter is informed by the actual task classifier’s decision basis:
- GNNExplainer,
- PGExplainer,
- SubgraphX,
- or another compact subgraph explainer.

Then the filter would prioritize evidence attached to the explanation subgraph rather than only to top-degree/top-score processes.

## Where the Code Should Change
The cleanest place is to introduce a new helper layer and keep the existing pipeline structure intact.

### Most likely files
- `D:\daima\APT-Fusion\src\apt_fusion\module3_bundle.py`
- `D:\daima\APT-Fusion\src\apt_fusion\module4_reason.py`
- `D:\daima\APT-Fusion\src\apt_fusion\config.py`

### Suggested new module
Create something like:

- `D:\daima\APT-Fusion\src\apt_fusion\core_task_relevance.py`

Possible responsibilities:
- seed extraction,
- event deduplication,
- path-aware scoring,
- IOC compression,
- filtered bundle field generation.

### Suggested bundle additions
Instead of replacing current fields immediately, add filtered fields alongside raw ones:

```json
{
  "events": [...],
  "episodes": [...],
  "ioc_candidates": {...},
  "core_events": [...],
  "supporting_events": [...],
  "filtered_ioc_candidates": {...},
  "dropped_noise_summary": {...}
}
```

This lets us compare old vs new behavior without losing traceability.

## What To Preserve From the Current Pipeline
We should keep:
- task-graph-based detection,
- GT-seed style task selection for evaluation,
- segmentation as an optional preprocessing step,
- two-stage LLM reasoning,
- ATT&CK candidate restriction,
- explicit evidence validation.

The new filter should improve the quality of bundle context, not replace the whole pipeline.

## Alternative Designs We Considered

### Option A: only shrink prompt caps
This works partially and gave the fastest improvement.

Pros:
- no new graph logic,
- immediate improvement,
- easy to control.

Cons:
- still blind to semantic relevance,
- risks dropping critical evidence arbitrarily,
- does not solve noisy retrieval itself.

Conclusion:
- necessary as a safety cap,
- not enough as the long-term fix.

### Option B: only do paper-style graph segmentation
This helped on some complex tasks, especially branch-heavy ones.

Pros:
- reduces task semantic mixing,
- helps isolate smaller branches.

Cons:
- did not reduce bundle noise enough by itself,
- many segmented bundles still kept nearly the same event/episode clutter.

Conclusion:
- useful,
- but insufficient by itself.

### Option C: full graph explainer first
This is attractive but heavier.

Pros:
- closer to model-driven interpretability,
- stronger theory for "what really mattered".

Cons:
- more engineering complexity,
- higher runtime overhead,
- harder to debug as a first implementation.

Conclusion:
- good later-stage upgrade,
- not the best first step.

### Option D: seed-centered rule/path filter first
This is the current recommended path.

Pros:
- directly addresses the observed failure mode,
- low engineering risk,
- can be implemented incrementally,
- can later absorb path scoring and explainers.

Conclusion:
- this is the best current plan.

## Recommended Next Implementation Order
If we pick this work back up later, the recommended order is:

1. keep segmented and unsegmented GT-seed experiment setups;
2. add bundle-level filtered fields in `module3_bundle`;
3. strongly compress repeated ports and repeated events;
4. feed `core_events` / `filtered_ioc_candidates` to `module4_reason`;
5. compare success rate against the current `20/20/6` prompt-cap baseline;
6. only then consider adding path scoring or graph explainers.

## One-Sentence Summary
The main improvement we want is:

**do not send all 1-hop neighborhood information into reasoning; instead, use the task graph to identify core processes and keep only the 1-hop evidence most relevant to the core task, with segmentation and prompt caps acting as supporting mechanisms rather than the sole solution.**
