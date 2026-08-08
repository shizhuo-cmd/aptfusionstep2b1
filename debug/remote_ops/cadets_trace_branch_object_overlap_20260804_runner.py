"""Compare current task components with root-child object-overlap splitting.

This runner intentionally executes module1 and module2 only.  It keeps the
normal-only detector fixed and changes only the post-segmentation component
pass, making CADETS and TRACE results directly comparable.
"""

from __future__ import annotations

import copy
import json
import shutil
import sys
import traceback
from pathlib import Path
from statistics import mean, median

import torch

REPO = Path("/root/autodl-tmp/APT-Fusionstep2b1")
OUT_DIR = REPO / "debug" / "remote_ops" / "out" / "cadets_trace_branch_object_overlap_20260804"
sys.path.insert(0, str(REPO / "src"))

from apt_fusion.config import load_config  # noqa: E402
from apt_fusion.task_detection.module1_online_graph import run_module1  # noqa: E402
from apt_fusion.task_detection.module2_online_detection import run_module2  # noqa: E402


BASE_CONFIGS = {
    "cadets": REPO / "configs" / "fusion_cloud_cadets_normal_only_eventstats_core_20260731.yaml",
    "trace": REPO / "configs" / "fusion_cloud_trace_normal_only_multimodal_20260730.yaml",
}
DATASET_INPUTS = {
    "cadets": {
        "source_logs": Path("/root/autodl-tmp/data/cadets/logs"),
        "ground_truth": Path("/root/autodl-tmp/data/cadets/cadets.txt"),
    },
    "trace": {
        "source_logs": Path("/root/autodl-tmp/data/trace/logs"),
        "ground_truth": Path("/root/autodl-tmp/data/trace/trace.txt"),
    },
}
ROUTES = (("baseline", False), ("branch_object_overlap", True))


def _json_ready(value: object) -> object:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    return value


def _percentile(values: list[int], fraction: float) -> int:
    if not values:
        return 0
    return sorted(values)[min(len(values) - 1, int((len(values) - 1) * fraction))]


def _size_summary(values: list[int]) -> dict[str, float | int]:
    return {
        "count": len(values),
        "mean": round(mean(values), 3) if values else 0.0,
        "median": float(median(values)) if values else 0.0,
        "p95": _percentile(values, 0.95),
        "max": max(values, default=0),
    }


def _configure(dataset: str, route: str, enabled: bool):
    cfg = copy.copy(load_config(BASE_CONFIGS[dataset]))
    inputs = DATASET_INPUTS[dataset]
    cfg.host = dataset
    cfg.source_logs = inputs["source_logs"]
    cfg.task_ground_truth_path = inputs["ground_truth"]
    cfg.artifacts_dir = REPO / f"artifacts_{dataset}_normal_only_branch_object_overlap_{route}_20260804"
    cfg.ocr_runtime_root = (
        REPO / "runtime" / "darpa_tc3" / f"{dataset}_normal_only_branch_object_overlap_{route}_20260804" / "experiments"
    )
    cfg.ocr_model_name = f"normal_only_{dataset}_branch_object_overlap_{route}_20260804.pkl"
    cfg.task_detector_model_output = cfg.artifacts_dir / "module2" / "normal_only_model.pkl"
    cfg.task_tapas_augmentation_enabled = False
    cfg.task_component_split_mode = "fanout"
    cfg.task_component_child_threshold = 2
    cfg.task_component_count_segmented_children_upstream = False
    cfg.task_component_root_temporal_split_enabled = False
    cfg.task_component_synthetic_root_isolation_enabled = False
    cfg.task_component_synthetic_root_selective_isolation_enabled = False
    cfg.task_component_branch_object_overlap_split_enabled = enabled
    # Hold the current normal-only detector configuration fixed for both routes.
    cfg.use_sequence_embeddings = True
    cfg.use_ocr_stat_features = True
    cfg.graphsage_append_ocr_stat_features = False
    cfg.task_graph_stat_late_fusion_enabled = False
    cfg.task_tc3_event_stats_mode = "security_semantic"
    cfg.task_normal_only_local_top_k_mode = "sqrt"
    cfg.task_normal_only_local_top_k_max = 16
    cfg.task_normal_only_global_model = "kmeans"
    cfg.task_normal_only_global_knn_neighbors = 5
    cfg.path_reason_enabled = False
    return cfg


def _module1_details(cfg) -> dict:
    summary = json.loads((cfg.module1_dir / "tapas_native_module1_summary.json").read_text(encoding="utf-8"))
    bundle = torch.load(cfg.module1_dir / "tapas_native_graphs.pt", map_location="cpu", weights_only=False)
    metas = list(bundle.get("selected_graph_metas", []))
    task_sizes = [int(meta.get("task_size", 0) or 0) for meta in metas]
    positive_metas = [meta for meta in metas if int(meta.get("label", 0) or 0) == 1]
    positive_sizes = [int(meta.get("task_size", 0) or 0) for meta in positive_metas]
    return {
        "task_count": len(metas),
        "gt_positive_task_count": len(positive_metas),
        "gt_positive_process_node_occurrences": sum(int(meta.get("attacknum", 0) or 0) for meta in positive_metas),
        "all_task_size": _size_summary(task_sizes),
        "gt_positive_task_size": _size_summary(positive_sizes),
        "large_task_count_gt_500": sum(1 for size in task_sizes if size > 500),
        "large_task_count_gt_1000": sum(1 for size in task_sizes if size > 1000),
        "gt_positive_task_ids": [str(meta.get("task_id", "")) for meta in positive_metas],
        "branch_object_overlap_split_summary": summary.get("branch_object_overlap_split_summary", {}),
    }


def _module2_details(outputs: dict) -> dict:
    thresholds = json.loads(Path(outputs["task_thresholds"]).read_text(encoding="utf-8"))
    backend = thresholds.get("backend_summary", {})
    rows = json.loads(Path(outputs["suspicious_tasks"]).read_text(encoding="utf-8"))
    predicted = [row for row in rows if int(row.get("predicted_label", 0) or 0) == 1]
    return {
        "threshold": backend.get("decision_threshold"),
        "metrics": backend.get("evaluation_metrics", {}),
        "normal_only": backend.get("normal_only", {}),
        "true_positive_task_ids": [row["task_id"] for row in predicted if int(row.get("task_label", 0) or 0) == 1],
        "false_positive_task_ids": [row["task_id"] for row in predicted if int(row.get("task_label", 0) or 0) == 0],
        "missed_positive_task_ids": [
            row["task_id"]
            for row in rows
            if int(row.get("task_label", 0) or 0) == 1 and int(row.get("predicted_label", 0) or 0) == 0
        ],
    }


def _mark_failed(cfg, reason: str) -> str | None:
    artifact_dir = Path(cfg.artifacts_dir)
    if not artifact_dir.exists():
        return None
    failed_dir = artifact_dir.with_name(f"{artifact_dir.name}_failed_{reason}")
    if failed_dir.exists():
        shutil.rmtree(failed_dir)
    artifact_dir.rename(failed_dir)
    return str(failed_dir)


def _completed_record_if_reusable(dataset: str, route: str, cfg) -> dict | None:
    """Resume after a failed later route without touching completed baselines."""
    module1_graphs = Path(cfg.artifacts_dir) / "module1" / "tapas_native_graphs.pt"
    task_thresholds = Path(cfg.artifacts_dir) / "module2" / "task_thresholds.json"
    suspicious_tasks = Path(cfg.artifacts_dir) / "module2" / "suspicious_tasks.json"
    if not all(path.exists() for path in (module1_graphs, task_thresholds, suspicious_tasks)):
        return None
    return {
        "dataset": dataset,
        "route": route,
        "status": "completed",
        "reused_completed_artifact": True,
        "module0_called": False,
        "config": _json_ready(cfg.__dict__),
        "module1": _module1_details(cfg),
        "module2": _module2_details(
            {"task_thresholds": task_thresholds, "suspicious_tasks": suspicious_tasks}
        ),
    }


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    for dataset in ("cadets", "trace"):
        for route, enabled in ROUTES:
            cfg = _configure(dataset, route, enabled)
            print(f"[START] {dataset}/{route}: module1 -> module2; module0 is disabled", flush=True)
            try:
                record = _completed_record_if_reusable(dataset, route, cfg)
                if record is not None:
                    print(f"[REUSED] {dataset}/{route}", flush=True)
                else:
                    module1 = run_module1(cfg)
                    module2 = run_module2(
                        cfg,
                        module1["process_embeddings"],
                        module1["task_subgraphs"],
                        module1["process_segmentation_edges"],
                    )
                    record = {
                        "dataset": dataset,
                        "route": route,
                        "status": "completed",
                        "module0_called": False,
                        "config": _json_ready(cfg.__dict__),
                        "module1": _module1_details(cfg),
                        "module2": _module2_details(module2),
                    }
                    print(f"[DONE] {dataset}/{route}", flush=True)
            except Exception as exc:
                traceback.print_exc()
                record = {
                    "dataset": dataset,
                    "route": route,
                    "status": "failed",
                    "module0_called": False,
                    "config": _json_ready(cfg.__dict__),
                    "error": repr(exc),
                    "failed_artifact_dir": _mark_failed(cfg, "runtime_error"),
                }
                print(f"[FAILED] {dataset}/{route}: {exc!r}", flush=True)
            results.append(record)
            (OUT_DIR / "matrix_summary.json").write_text(
                json.dumps({"experiment": "cadets_trace_branch_object_overlap_20260804", "routes": results}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
    print(json.dumps({"experiment": "cadets_trace_branch_object_overlap_20260804", "routes": results}, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
