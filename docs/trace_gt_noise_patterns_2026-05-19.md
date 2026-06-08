# TRACE GT Noise-Reduction Patterns (2026-05-19)

## Goal

Use ground-truth malicious-node distributions to identify stable patterns that can guide event-noise reduction without relying on ground truth at inference time.

The key question is:

- Are malicious nodes concentrated around a few subject processes?
- Are they concentrated in specific time windows?
- Do the linked event types follow stable patterns?

If yes, we should build bundle summaries around those concentrations instead of sampling the whole task graph uniformly.

## Core Findings

### 1. Malicious non-process nodes are usually concentrated on very few subject processes

Per-task non-process GT occurrence concentration:

| Task | Top-1 subject share | Top-3 subject share | Interpretation |
|---|---:|---:|---|
| `task_0345` | `94.22%` | `97.17%` | Almost all malicious non-process nodes hang off one process |
| `task_0557` | `98.18%` | `98.59%` | Essentially one dominant malicious process |
| `task_0558` | `99.97%` | `99.99%` | Nearly pure single-anchor burst |
| `task_0546` | `13.92%` | `32.76%` | Malicious objects are much more distributed |

This is the strongest pattern in the data.

### 2. Most malicious non-process nodes appear as object-side nodes, not process nodes

For all four tasks together:

- non-process GT nodes are overwhelmingly `predicate_object`
- only a tiny fraction appear as `event_uuid` or `predicate_object2`

This means the main evidence is usually:

`important subject process -> suspicious object`

rather than:

- suspicious event node itself
- or process-process structure alone

### 3. The dominant malicious object type depends on task family

#### `task_0557` / `task_0558`

- dominant GT non-process type: `flow`
- dominant events:
  - `CONNECT`
  - `CLOSE`

These are classic network-burst tasks.

#### `task_0345`

- dominant GT non-process type: `flow`
- but with meaningful secondary:
  - `file`
  - `pipe`
  - `memory`
- dominant events:
  - `CONNECT`
  - then callback/file/memory support

This is a mixed scan + staging task.

#### `task_0546`

- dominant GT non-process type: `file`
- dominant events:
  - `MMAP`
  - `OPEN`
  - `CLOSE`
  - `READ`
  - `LOADLIBRARY`

This is not a flow-burst task. It is much more browser/mail/file/memory heavy.

### 4. Time distributions are strongly task-type dependent

#### `task_0345`

- `5m_to_15m`: `803 / 883`
- strong delayed burst after task start

#### `task_0557`

- `5m_to_15m`: `134497 / 137039`
- again a strong delayed burst

#### `task_0558`

- `1m_to_5m`: `122486 / 134582`
- very early burst

#### `task_0546`

- `>=60m`: `453 / 467`
- clearly long-span, not a short burst

So there is no single universal time rule, but there is a strong **task-family pattern**:

- burst-type tasks: evidence collapses into a small early/mid window
- long-span tasks: evidence stays diffuse over much longer time

### 5. GT process nodes are not all equally useful

For `task_0345`, the GT process cluster clearly has a structural center:

- `CID 19482 (ztmp)` is the strongest graph/process anchor
- most malicious non-process nodes attach to that anchor

For `task_0557` and `task_0558`, the event evidence shows the same thing for:

- `tcexec`

For `task_0546`, there is no single dominant graph/process anchor at the same level; instead the evidence is spread across:

- `firefox`
- `thunderbird`
- `command-not-fou*`
- `chmod`
- `tcexec`

## Practical Implications

### A. Uniform sampling across the whole task graph is the wrong default

For three of the four malicious tasks, malicious evidence is highly concentrated around one process anchor.

So instead of:

- sampling the task uniformly

we should prefer:

- anchor-process-centered summaries

### B. There are at least three task families that need different noise-reduction strategies

#### 1. Single-anchor network burst

Examples:

- `task_0557`
- `task_0558`

Properties:

- top-1 subject share > `0.95`
- flow-dominated
- `CONNECT/CLOSE` dominate
- narrow or bursty time concentration

Best reduction strategy:

- summarize around the top anchor subject only
- compress network evidence by:
  - remote IP
  - remote IP:port
  - a few representative events
- aggressively suppress repeated raw `CONNECT/CLOSE`

#### 2. Mixed scan + staging

Example:

- `task_0345`

Properties:

- top-1 subject share still very high
- network dominates, but file/memory side evidence matters
- one process anchor plus a few support processes

Best reduction strategy:

- keep the main anchor subject
- preserve one scan burst summary
- preserve one callback summary
- preserve one temp-file summary

#### 3. Long-span browser/mail/file-heavy

Example:

- `task_0546`

Properties:

- no single dominant subject anchor
- mostly file/memory/browser/mail style evidence
- long time span

Best reduction strategy:

- do not treat as a network task
- split by time buckets and subject families
- focus on:
  - browser/mail clients
  - `command-not-found`
  - `tcexec`
  - file/memory transitions

### C. The best runtime proxy is not “all task processes”, but “malicious-object anchor processes”

At inference time we do not have GT labels.

But GT shows what a good proxy should look like:

- the subject that touches the most suspicious objects
- the subject that creates the largest remote-port diversity
- the subject tied to temp files, browser/mail chain, or repeated file-memory actions

So the next runtime heuristic should aim to approximate:

`which subject process behaves like the GT anchor`

## Recommended Optimization Directions

### 1. Add anchor-subject detection before evidence compression

For each task, score subject processes by:

- remote host count
- remote port diversity
- repeated temp-path access
- file/write/delete density
- browser/mail executable family
- memory map + open/close bursts

Then choose:

- top-1 anchor for burst tasks
- top-2 or top-3 anchors for diffuse tasks

### 2. Build time windows around anchors, not around the whole task

Instead of one global task window:

- compute per-anchor time-bucket summaries
- keep the highest-density anchor windows

This should work especially well for:

- `0557`
- `0558`
- `0345`

### 3. Use different bundle templates by task family

#### Network burst template

- remote IP summary
- remote IP:port summary
- representative scan events
- callback endpoints

#### Mixed scan + staging template

- scan burst summary
- temp-file summary
- callback summary
- interpreter/process chain summary

#### Browser/mail/file template

- browser/mail process chain
- file and memory object digest
- command-helper and spawned executable digest
- selected supporting network evidence only

### 4. Suppress low-value support processes in burst tasks

In tasks like `0557` and `0558`, once the main anchor is found, many other processes should be treated as support only.

That means:

- they may remain in digests
- but they should not get the same event budget as the anchor process

## Bottom Line

The strongest GT-backed regularity is:

**malicious non-process evidence is usually concentrated around a very small number of subject processes, and the time concentration depends strongly on task family.**

So the main noise-reduction direction should be:

1. detect anchor subject processes
2. classify task family
3. summarize evidence around anchor-specific high-density windows
4. stop treating all task processes and all raw events as equally important

That should preserve more attack information while cutting much more noise than the current broad task-level event pooling.
