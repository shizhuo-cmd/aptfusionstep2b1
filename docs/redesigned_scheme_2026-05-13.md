# Redesigned Scheme (2026-05-13)

## Positioning

This document replaces the current APT-Fusion implementation direction with a new design optimized for:

1. detection quality,
2. evidence-grounded ATT&CK analysis,
3. operational feasibility on large audit streams.

It explicitly does **not** optimize for minimal code changes.

The redesign is informed by:

- the local research note at `D:\download\deep-research-report.md`,
- recent provenance-graph compression and partitioning work,
- recent provenance-based detection and scenario reconstruction work,
- and the observed failures in the current APT-Fusion trace pipeline.

## What is wrong with the current scheme

The current implementation has six structural problems:

1. It cuts task graphs too early and too mechanically.
   - Detection and investigation share the same segmented graph objects.
   - This creates either tiny fragmented tasks or very large boundary-node collector graphs.

2. It uses weak evidence selection for LLM reasoning.
   - `core_events` and `filtered_events` are better than raw events, but the final `20/20/6` policy is still just truncation.
   - A few repetitive network events can still dominate the bundle.

3. Its ATT&CK candidate retrieval is shallow.
   - Query terms are polluted by IP fragments, port numbers, and generic words.
   - ATT&CK candidates are therefore often available but semantically weak.

4. Its ATT&CK mapping stage is under-constrained.
   - The model still has too much freedom to hallucinate or produce tactic/technique mismatches.
   - When constraints are increased, recall collapses to zero.

5. It mixes stage analysis and ATT&CK analysis in the wrong order.
   - The earlier trace-stage logic inflated apparent phase coverage.
   - The later free ATT&CK version removed that inflation but revealed that raw ATT&CK quality is poor.

6. It uses the LLM too late in some places and too early in others.
   - Too early: mapping noisy evidence directly to ATT&CK.
   - Too late: no strong semantic reranking before candidate mapping.

## New design principles

The new scheme should follow five principles:

1. **Detect first at process/component level; investigate later at evidence level.**
2. **Do not let task-graph segmentation dictate the investigation unit.**
3. **Use hybrid exact + sparse + semantic retrieval before any LLM reasoning.**
4. **Treat ATT&CK mapping as constrained evidence alignment, not free text generation.**
5. **Treat APT stages as a downstream interpretation layer, not a prompt-side prior.**

## The new end-to-end architecture

```text
raw audit stream
-> normalized event store
-> online process-state encoder
-> process/edge anomaly scoring
-> alert seed selection
-> alert-centric component builder
-> evidence retrieval and denoising
-> claim extraction
-> ATT&CK candidate retrieval + reranking
-> constrained ATT&CK alignment
-> stage graph inference
-> cross-alert campaign correlation
```

## Layer 1: Data and storage

Do not use GraphDB in the primary path.

Use four storage layers instead:

1. **append-only normalized event table**
   - one row per event
   - includes host, timestamp, subject, object, action, normalized text fields, raw reference

2. **entity/process state table**
   - current hidden state per process
   - rolling counters, last actions, recent object interaction summaries

3. **adjacency and temporal indexes**
   - process -> children
   - process -> touched files
   - process -> touched network endpoints
   - endpoint/file/process -> recent events

4. **investigation retrieval layer**
   - sparse lexical index over normalized event descriptions and episode summaries
   - vector index over minute-level evidence chunks and claim-like summaries
   - metadata filters by host, time range, entity type, action family

This keeps the fast path operationally simple while retaining enough structure for provenance-style investigation.

## Layer 2: Detection should not rely on task-graph segmentation as the primary unit

The current architecture makes the task graph the central object too early.

The redesign should separate:

1. **online scoring unit** = process / edge / micro-component
2. **investigation unit** = alert-centric evidence component

### 2.1 Online scoring

Use three detectors in parallel:

1. **process-state detector**
   - encode each process as a temporal state vector
   - score sudden deviations from benign behavioral trajectory

2. **typed edge anomaly detector**
   - score process-file, process-flow, process-process interactions separately
   - this is where OCR-APT-style type-specific modeling is most valuable

3. **micro-component classifier**
   - construct a small temporal component around suspicious processes
   - classify whether this component is likely malicious

Fuse the three scores with calibration, rather than relying on a single graph score.

### 2.2 What to keep from TAPAS

Keep:

- process-history encoding,
- low-cost online process state updates,
- parent-child structure as one structural source.

Do not keep:

- making the parent-child-derived task graph the only main object for downstream reasoning.

## Layer 3: Build alert-centric components after alerting, not before

This is the biggest architectural change.

Instead of pre-cutting the whole dataset into task graphs and then hoping those are the right investigation units, do this:

1. detect suspicious processes / edges,
2. use them as **alert seeds**,
3. build investigation components around those seeds.

### 3.1 Component builder

For each alert seed:

1. collect:
   - nearest suspicious ancestor processes,
   - descendant execution chain,
   - touched files,
   - outbound and inbound network objects,
   - cross-entity bridging processes,
   - bounded time window around the seed.

2. score local nodes and edges by:
   - temporal proximity,
   - anomaly contribution,
   - causal path importance,
   - rarity,
   - suspicious action type.

3. produce an **overlapping alert-centric component**
   - overlap is allowed
   - no need to force one global partition first

This borrows the useful part of provenance partitioning research while avoiding the current “global segmentation before investigation” failure mode.

## Layer 4: Evidence packet construction should be lane-based, not top-N truncation

The current `20/20/6` policy should be replaced.

Instead of one shared event ranking followed by truncation, build an **evidence packet** with semantic lanes:

1. **execution lane**
   - exec/fork/load/open-create-exec chain

2. **file/persistence lane**
   - write/rename/truncate/permission/path modification

3. **network/C2 lane**
   - connect/send/recv with endpoint clustering

4. **recon lane**
   - enumeration commands, process listing, network discovery, file discovery

5. **pivot lane**
   - events that connect suspicious processes to suspicious files or endpoints

For each lane, keep a quota.

Example:

```text
execution: 8 events
file/persistence: 8 events
network/C2: 8 events
recon: 6 events
pivot/path evidence: 6 events
```

Then generate:

- lane summaries,
- cross-lane evidence links,
- minute-level episode summaries.

This is much stronger than letting port-heavy bundles monopolize the prompt budget.

## Layer 5: ATT&CK candidate retrieval should be a real retrieval subsystem

The new ATT&CK subsystem should have three stages.

### 5.1 Query generation

Do **not** query ATT&CK with raw:

- port numbers,
- IP fragments,
- generic token noise.

Build ATT&CK queries only from:

1. normalized action families
   - execution, write, load, connect, enumerate, schedule, modify

2. command lexemes
   - executable names, shell invocations, LOLBins, script interpreters

3. object semantics
   - startup file, shell config, cron-like artifact, remote endpoint, archive artifact

4. extracted claims
   - these should become the highest-value ATT&CK retrieval input

### 5.2 Candidate retrieval

From the local STIX file:

- build a sparse lexical index over tactic and technique names + descriptions,
- build a vector index over the same entries,
- retrieve top candidates with hybrid search,
- rerank candidates with an evidence-aware reranker.

The reranker should prioritize:

- action-family compatibility,
- object-type compatibility,
- operating-system compatibility,
- temporal coherence with the evidence packet.

### 5.3 Candidate output

The model should not see the full STIX.

It should only see a compact candidate table such as:

```text
candidate_id | tactic | technique | short evidence fit note
```

with maybe top 5-10 techniques and top 5 tactics.

## Layer 6: Split claim extraction from ATT&CK mapping

The current scheme asks the model to jump too early to ATT&CK.

Instead use:

### Step A: claim extraction

Input:

- evidence packet
- lane summaries

Output:

- atomic claims
- each claim has event evidence
- each claim has one behavioral type

Example claim types:

- remote connection establishment
- suspicious interpreter execution
- shell configuration modification
- file discovery behavior
- process spawning chain

### Step B: ATT&CK alignment

Input:

- claims
- ATT&CK candidates

Output:

- tactic name
- technique name (optional)
- evidence claim ids
- confidence

Crucially:

- the model outputs names only,
- IDs are resolved from the local ATT&CK KB after generation,
- technique-tactic compatibility is enforced by code,
- unsupported mappings are dropped.

This is far more robust than the current “model generates tactic + technique + IDs freely”.

## Layer 7: Stage inference should be downstream and graph-based

Do not force the model to think in your target phase set during mapping.

Instead:

1. infer ATT&CK mappings first,
2. then map ATT&CK + evidence order into an **APT stage graph**.

For the trace evaluation labels, use a stage layer like:

- Initial Compromise
- Internal Reconnaissance
- Command and Control
- Maintain Persistence

but generate them **after** ATT&CK alignment and evidence ordering.

The stage inference module should use:

- ATT&CK tactic set,
- claim order,
- event timestamps,
- lane co-occurrence,
- host-local causal path order.

This avoids the two bad extremes we already observed:

- prompt-forced stage inflation,
- or zero-stage output after removing stage priors.

## Layer 8: Campaign correlation across alerts

The current design stops too early at single-task reports.

A stronger scheme should correlate alerts across:

- shared endpoint clusters,
- shared executable or file artifacts,
- repeated command lexemes,
- shared ATT&CK claims,
- temporal proximity.

The campaign layer should produce:

1. alert clusters,
2. campaign-level ATT&CK graph,
3. campaign-level stage progression,
4. host-to-host pivot hints.

## What model stack is most feasible

For performance + effect + feasibility, the best stack is:

1. **small/medium learned detectors** for online scoring
2. **hybrid sparse + vector retrieval** for evidence
3. **mid-size local instruct model** for claim and ATT&CK reasoning
4. **strict code-side validation** after model output

Avoid:

- using the LLM as the primary detector,
- feeding the full STIX file into the prompt,
- relying on prompt wording alone to guarantee ATT&CK correctness.

## Why this new design should outperform the current one

Compared with the current implementation, this redesign should be better because:

1. detection is no longer bottlenecked by brittle global task-graph segmentation;
2. evidence packets are balanced by semantic lanes instead of crude truncation;
3. ATT&CK retrieval is driven by behavior semantics, not polluted raw tokens;
4. ATT&CK mapping is constrained by local KB structure, not free-form generation;
5. APT stage labels become a downstream interpretation product, not a prompt prior;
6. campaign-level context is restored without forcing GraphDB into the hot path.

## Recommended implementation order

Even though this document does not optimize for low migration cost, the best build order is still:

1. replace ATT&CK candidate retrieval,
2. replace evidence packet construction,
3. split claim extraction from ATT&CK alignment,
4. replace global segmentation-first investigation with alert-centric components,
5. add campaign correlation,
6. only then revisit detector architecture if needed.

## Sources

- Local report: `D:\download\deep-research-report.md`
- A multi-source log semantic analysis-based attack investigation approach (Computers & Security, 2025): https://doi.org/10.1016/j.cose.2024.104303
- PDCleaner: A multi-view collaborative data compression method for provenance graph-based APT detection systems (Computers & Security, 2025): https://doi.org/10.1016/j.cose.2025.104359
- FineGCP: Fine-grained dependency graph community partitioning for attack investigation (Computers & Security, 2025): https://doi.org/10.1016/j.cose.2024.104311
- MGDA: A provenance graph-based framework for threat detection and attack scenario reconstruction (Computer Networks, 2025/2026 issue): https://doi.org/10.1016/j.comnet.2025.111806
- A dynamic provenance graph-based detector for advanced persistent threats (Expert Systems with Applications, 2025): https://doi.org/10.1016/j.eswa.2024.125877
- Angus: efficient active learning strategies for provenance based intrusion detection (Cybersecurity, 2025): https://doi.org/10.1186/s42400-024-00311-y
