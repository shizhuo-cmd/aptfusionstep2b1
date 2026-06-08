# Module3 Local Streaming

This mode replaces the external GraphDB-based `module3` route with a low-memory local pipeline.

## Goal

Use `module2` suspicious tasks and raw logs to build investigation outputs:

- `results/<exp>/<model>/run0_<inv>_correlated_subgraphs_statistics.csv`
- `investigation/<exp>/<model>/run0_<inv>_attack_description_subgraph_<id>.csv`

Those files are directly consumable by `module4`.

## Why it is low-memory

- Stream logs line-by-line.
- Keep only suspicious-task related events.
- Store task events to fixed shard JSONL files on disk.
- Scan logs a second time only to fill attributes for UUIDs seen in suspicious tasks.

## Config knobs

```yaml
local_max_events_per_subgraph: 200000
local_max_open_event_files: 32
local_task_event_shards: 64
local_report_max_events_per_subgraph: 3000
local_report_time_window_minutes: 0
```

`local_task_event_shards`:
- Intermediate task events are written to fixed shard files (`shard_0000.jsonl`, ...).
- This avoids creating one JSONL file per suspicious task when task count is very large.

`local_report_time_window_minutes`:
- `0` means disabled.
- `>0` keeps only recent events in that trailing window before Top-K.

`local_report_max_events_per_subgraph`:
- Final cap of report events per suspicious task after optional time-window filtering.
- Ranking combines process anomaly probability, recency, and action signal.

## Run

```powershell
python -m apt_fusion.cli run --config .\configs\fusion_config.yaml --stage module3_local
python -m apt_fusion.cli run --config .\configs\fusion_config.yaml --stage module4
```

Or run everything in local mode:

```powershell
python -m apt_fusion.cli run --config .\configs\fusion_config.yaml --stage full_local
```
