"""Audit bounded child-start temporal task splitting without running module0/1/2.

Each dataset is parsed once.  Every route then reuses the same TAPAS parent-child
components, so the comparison isolates task construction rather than model noise.
"""

from __future__ import annotations

import copy
import gc
import json
import sys
from pathlib import Path

import numpy as np

REPO = Path("/root/autodl-tmp/APT-Fusionstep2b1")
OUT_DIR = REPO / "debug" / "remote_ops" / "out" / "cadets_trace_temporal_episode_audit_20260805"
sys.path.insert(0, str(REPO / "src"))

from apt_fusion.task_detection.tapas_native_backend import (  # noqa: E402
    _apply_temporal_episode_split,
    _canonicalize_ground_truth_nodes,
    _decompose_tc3_metadata,
    _load_ground_truth,
    _load_vendor_module,
    _normalize_tc3_source_logs,
    _temporary_cwd,
    _vendor_tapas_root,
)


DATASETS = {
    "cadets": {
        "logs": Path("/root/autodl-tmp/data/cadets/logs"),
        "ground_truth": Path("/root/autodl-tmp/data/cadets/cadets.txt"),
    },
    "trace": {
        "logs": Path("/root/autodl-tmp/data/trace/logs"),
        "ground_truth": Path("/root/autodl-tmp/data/trace/trace.txt"),
    },
}

ROUTES = {
    "baseline": None,
    "parent_missing_fixed30_bounded": {
        "parent_missing_only": True,
        "min_task_nodes": 500,
        "min_direct_children": 64,
        "min_span_minutes": 60,
        "gap_mode": "fixed",
        "fixed_gap_minutes": 30,
        "gap_quantile": 0.90,
        "mad_multiplier": 3.0,
        "min_children_per_episode": 16,
        "max_episodes": 8,
        "budget_strategy": "adjacent_greedy",
    },
    "all_parents_fixed30_bounded": {
        "parent_missing_only": False,
        "min_task_nodes": 200,
        "min_direct_children": 16,
        "min_span_minutes": 60,
        "gap_mode": "fixed",
        "fixed_gap_minutes": 30,
        "gap_quantile": 0.90,
        "mad_multiplier": 3.0,
        "min_children_per_episode": 8,
        "max_episodes": 8,
        "budget_strategy": "adjacent_greedy",
    },
    "all_parents_quantile90_bounded": {
        "parent_missing_only": False,
        "min_task_nodes": 200,
        "min_direct_children": 16,
        "min_span_minutes": 60,
        "gap_mode": "quantile",
        "fixed_gap_minutes": 30,
        "gap_quantile": 0.90,
        "mad_multiplier": 3.0,
        "min_children_per_episode": 8,
        "max_episodes": 8,
        "budget_strategy": "adjacent_greedy",
    },
    "all_parents_median_mad3_bounded": {
        "parent_missing_only": False,
        "min_task_nodes": 200,
        "min_direct_children": 16,
        "min_span_minutes": 60,
        "gap_mode": "median_mad",
        "fixed_gap_minutes": 30,
        "gap_quantile": 0.90,
        "mad_multiplier": 3.0,
        "min_children_per_episode": 8,
        "max_episodes": 8,
        "budget_strategy": "adjacent_greedy",
    },
    "all_parents_quantile90_balanced": {
        "parent_missing_only": False,
        "min_task_nodes": 200,
        "min_direct_children": 16,
        "min_span_minutes": 60,
        "gap_mode": "quantile",
        "fixed_gap_minutes": 30,
        "gap_quantile": 0.90,
        "mad_multiplier": 3.0,
        "min_children_per_episode": 8,
        "max_episodes": 8,
        "budget_strategy": "balanced_child_count",
    },
}


def _quantiles(values: list[int]) -> dict[str, int]:
    if not values:
        return {key: 0 for key in ("min", "median", "p90", "p95", "p99", "max")}
    array = np.asarray(values, dtype=np.int64)
    return {
        "min": int(array.min()),
        "median": int(np.quantile(array, 0.50)),
        "p90": int(np.quantile(array, 0.90)),
        "p95": int(np.quantile(array, 0.95)),
        "p99": int(np.quantile(array, 0.99)),
        "max": int(array.max()),
    }


def _summarize(route: str, edge_list: dict, canonical_ground_truth: set[str]) -> dict:
    metas = _decompose_tc3_metadata(edge_list, canonical_ground_truth)
    sizes = [int(meta["task_size"]) for meta in metas]
    positive = [meta for meta in metas if int(meta["label"]) == 1]
    positive_sizes = [int(meta["task_size"]) for meta in positive]
    positive_nodes = {str(node) for meta in positive for node in meta["node_ids"]}
    split_summary = edge_list.get("temporal_episode_split_summary", {})
    return {
        "route": route,
        "task_count": len(metas),
        "positive_task_count": len(positive),
        "ground_truth_node_coverage": len(positive_nodes & canonical_ground_truth),
        "ground_truth_node_total": len(canonical_ground_truth),
        "all_task_size": _quantiles(sizes),
        "positive_task_size": _quantiles(positive_sizes),
        "all_tasks_size_le_3": sum(size <= 3 for size in sizes),
        "all_tasks_size_le_5": sum(size <= 5 for size in sizes),
        "positive_tasks_size_le_3": sum(size <= 3 for size in positive_sizes),
        "positive_tasks_size_le_5": sum(size <= 5 for size in positive_sizes),
        "all_tasks_gt_500": sum(size > 500 for size in sizes),
        "all_tasks_gt_1000": sum(size > 1000 for size in sizes),
        "positive_tasks_gt_500": sum(size > 500 for size in positive_sizes),
        "positive_tasks_gt_1000": sum(size > 1000 for size in positive_sizes),
        "positive_tasks": [
            {
                "task_id": str(meta["task_id"]),
                "task_root_id": str(meta.get("task_root_id", "")),
                "task_size": int(meta["task_size"]),
                "attacknum": int(meta["attacknum"]),
                "temporal_episode_split_applied": bool(meta.get("temporal_episode_split_applied", False)),
                "temporal_episode_parent_task_root": str(meta.get("temporal_episode_parent_task_root", "")),
                "temporal_episode_index": meta.get("temporal_episode_index"),
                "temporal_episode_count": meta.get("temporal_episode_count"),
            }
            for meta in positive
        ],
        "temporal_episode_split_summary": split_summary,
    }


def _parse(dataset: str):
    spec = DATASETS[dataset]
    vendor = _load_vendor_module(f"tapas_vendor_temporal_episode_audit_{dataset}", _vendor_tapas_root() / "darpa.py")
    with _temporary_cwd(OUT_DIR):
        logs = _normalize_tc3_source_logs(spec["logs"])
        if dataset == "cadets":
            subject_list, _, _, metadata = vendor.parser_cadets(logs, collect_subject_object_ids=False)
        else:
            subject_list, _, _, metadata = vendor.parser_trace(logs, collect_subject_object_ids=False)
        edge_list = vendor.cut_task(
            subject_list,
            return_task_components=True,
            child_threshold=2,
            split_mode="fanout",
            count_segmented_children_upstream=False,
        )
    edge_list = dict(edge_list)
    edge_list["subject_time_ranges"] = metadata.get("canonical_subject_time_ranges", {})
    canonical_ground_truth = _canonicalize_ground_truth_nodes(
        _load_ground_truth(spec["ground_truth"]),
        metadata,
    )
    return edge_list, canonical_ground_truth


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    output: dict[str, object] = {"experiment": "cadets_trace_temporal_episode_audit_20260805", "module0_called": False, "datasets": {}}
    for dataset in DATASETS:
        print(f"[PARSE] {dataset}: module0/module1/module2 are not called", flush=True)
        edge_list, canonical_ground_truth = _parse(dataset)
        routes: list[dict] = []
        for route, params in ROUTES.items():
            print(f"[AUDIT] {dataset}/{route}", flush=True)
            candidate = edge_list
            if params is not None:
                candidate = _apply_temporal_episode_split(edge_list, **params)
            routes.append(_summarize(route, candidate, canonical_ground_truth))
            gc.collect()
        output["datasets"][dataset] = {
            "canonical_ground_truth_count": len(canonical_ground_truth),
            "routes": routes,
        }
        (OUT_DIR / "audit_summary.json").write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
        del edge_list
        gc.collect()
    print("[DONE] audit", flush=True)


if __name__ == "__main__":
    main()
