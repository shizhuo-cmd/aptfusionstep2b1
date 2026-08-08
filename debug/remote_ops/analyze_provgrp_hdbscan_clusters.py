"""Diagnose the HDBSCAN partitions behind a ProvGRP-refined TC3 root.

This is intentionally read-only: it reconstructs the exact dependency input
and HDBSCAN settings used by ``provgrp_paper_partition.py`` and writes a JSON
report.  It does not rebuild task graphs or modify an experiment artifact.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path
from typing import Any

import hdbscan
import numpy as np
import torch


def _histogram(values: list[int]) -> dict[str, int]:
    return {str(key): count for key, count in sorted(collections.Counter(values).items())}


def _cluster_batch(
    events: list[dict[str, Any]],
    *,
    min_cluster_size: int,
    min_samples: int,
) -> list[int]:
    from apt_fusion.task_detection.provgrp_paper_partition import _confidence

    if len(events) < min_cluster_size:
        return [-1] * len(events)
    start = int(events[0]["timestamp_ns"])
    end = int(events[-1]["timestamp_ns"])
    distances = np.zeros((len(events), len(events)), dtype=np.float64)
    for left in range(len(events)):
        for right in range(left + 1, len(events)):
            distances[left, right] = 1.0 - _confidence(events[left], events[right], start, end)
            distances[right, left] = distances[left, right]
    return hdbscan.HDBSCAN(
        metric="precomputed",
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
        cluster_selection_method="eom",
    ).fit_predict(distances).tolist()


def _event_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    timestamps = [int(event["timestamp_ns"]) for event in events]
    fork_events = [event for event in events if event.get("fork_child")]
    return {
        "event_count": len(events),
        "fork_clone_event_count": len(fork_events),
        "unique_fork_child_count": len({str(event["fork_child"]) for event in fork_events}),
        "event_types": dict(sorted(collections.Counter(str(event["event_type"]) for event in events).items())),
        "entity_kinds": dict(sorted(collections.Counter(str(event["entity_kind"]) for event in events).items())),
        "start_ns": min(timestamps),
        "end_ns": max(timestamps),
        "span_ms": (max(timestamps) - min(timestamps)) / 1_000_000.0,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--module1", type=Path, required=True)
    parser.add_argument("--source-logs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--root", default="", help="Canonical root UUID; defaults to the most-split root.")
    parser.add_argument("--max-events-per-matrix", type=int, default=512)
    parser.add_argument("--min-cluster-size", type=int, default=5)
    parser.add_argument("--min-samples", type=int, default=2)
    parser.add_argument("--sample-count", type=int, default=20)
    args = parser.parse_args()

    sys.path.insert(0, str(args.repo / "src"))
    from apt_fusion.task_detection.provgrp_paper_partition import (
        _collect_root_dependencies,
        _read_cdm18_metadata,
    )

    bundle = torch.load(args.module1 / "tapas_native_graphs.pt", map_location="cpu", weights_only=False)
    partition = bundle.get("provgrp_paper_partition_summary", {})
    root_summaries = partition.get("root_summaries", [])
    if not root_summaries:
        raise RuntimeError("The module1 artifact has no ProvGRP root summaries.")
    requested_root = str(args.root).strip()
    root_summary = next((row for row in root_summaries if str(row.get("root", "")) == requested_root), None)
    if root_summary is None:
        root_summary = max(root_summaries, key=lambda row: int(row.get("execution_partition_count", 0)))
    root = str(root_summary["root"])

    owners, descriptors, object_names = _read_cdm18_metadata(args.source_logs)
    raw_to_canonical = bundle.get("thread_merge_metadata", {}).get("raw_subject_to_canonical_node", {})
    if raw_to_canonical:
        original_owners = dict(owners)
        owners = {raw_id: str(raw_to_canonical.get(raw_id, owner)) for raw_id, owner in owners.items()}
        remapped_descriptors: dict[str, dict[str, str]] = {}
        for raw_id, original_owner in original_owners.items():
            canonical = owners.get(raw_id, original_owner)
            candidate = descriptors.get(original_owner, {})
            if canonical and (canonical not in remapped_descriptors or candidate.get("name")):
                remapped_descriptors[canonical] = candidate
        descriptors = remapped_descriptors

    dependencies, filter_stats, _ = _collect_root_dependencies(
        args.source_logs, {root}, owners, descriptors, object_names
    )
    events = dependencies[root]["out"]
    positive_cluster_sizes: list[int] = []
    noise_event_count = 0
    all_group_sizes: list[int] = []
    exact_ten_samples: list[dict[str, Any]] = []
    per_batch: list[dict[str, Any]] = []

    for batch_index, start_index in enumerate(range(0, len(events), args.max_events_per_matrix)):
        batch = events[start_index : start_index + args.max_events_per_matrix]
        labels = _cluster_batch(
            batch,
            min_cluster_size=args.min_cluster_size,
            min_samples=args.min_samples,
        )
        by_label: dict[int, list[dict[str, Any]]] = collections.defaultdict(list)
        for event, label in zip(batch, labels):
            by_label[int(label)].append(event)
        label_sizes = []
        for label, members in by_label.items():
            summary = _event_summary(members)
            if label < 0:
                noise_event_count += len(members)
            else:
                positive_cluster_sizes.append(len(members))
                all_group_sizes.append(int(summary["unique_fork_child_count"]))
                if len(members) == 10 and len(exact_ten_samples) < args.sample_count:
                    exact_ten_samples.append(
                        {
                            "batch_index": batch_index,
                            "label": label,
                            **summary,
                            "first_child_ids": [str(item["fork_child"]) for item in members[:5] if item.get("fork_child")],
                        }
                    )
            label_sizes.append(len(members))
        per_batch.append(
            {
                "batch_index": batch_index,
                "event_count": len(batch),
                "positive_cluster_count": sum(label >= 0 for label in by_label),
                "noise_event_count": sum(len(items) for label, items in by_label.items() if label < 0),
                "positive_cluster_size_histogram": _histogram(
                    [len(items) for label, items in by_label.items() if label >= 0]
                ),
                "all_label_size_histogram": _histogram(label_sizes),
            }
        )

    report = {
        "root": root,
        "root_summary_from_artifact": root_summary,
        "parameters": {
            "min_cluster_size": args.min_cluster_size,
            "min_samples": args.min_samples,
            "max_events_per_matrix": args.max_events_per_matrix,
        },
        "outgoing_dependency_count": len(events),
        "dependency_filter": filter_stats,
        "hdbscan": {
            "positive_cluster_count": len(positive_cluster_sizes),
            "noise_event_count": noise_event_count,
            "positive_cluster_size_histogram": _histogram(positive_cluster_sizes),
            "positive_cluster_unique_fork_child_histogram": _histogram(all_group_sizes),
            "exact_ten_cluster_samples": exact_ten_samples,
            "per_batch": per_batch,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "root": root,
        "outgoing_dependency_count": len(events),
        "positive_cluster_size_histogram": report["hdbscan"]["positive_cluster_size_histogram"],
        "noise_event_count": noise_event_count,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
