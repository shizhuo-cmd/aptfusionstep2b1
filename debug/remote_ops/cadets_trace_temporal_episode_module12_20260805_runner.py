"""Run final bounded child-start temporal episode candidates without module0."""

from __future__ import annotations

import copy
import json
import shutil
import sys
import traceback
from pathlib import Path

import numpy as np
import torch

REPO = Path("/root/autodl-tmp/APT-Fusionstep2b1")
OUT_DIR = REPO / "debug" / "remote_ops" / "out" / "cadets_trace_temporal_episode_module12_20260805"
sys.path.insert(0, str(REPO / "src"))

from apt_fusion.config import load_config  # noqa: E402
from apt_fusion.task_detection.module1_online_graph import run_module1  # noqa: E402
from apt_fusion.task_detection.module2_online_detection import run_module2  # noqa: E402


BASE_CONFIGS = {
    "cadets": REPO / "configs" / "fusion_cloud_cadets_normal_only_eventstats_core_20260731.yaml",
    "trace": REPO / "configs" / "fusion_cloud_trace_normal_only_multimodal_20260730.yaml",
}
DATASET_INPUTS = {
    "cadets": (Path("/root/autodl-tmp/data/cadets/logs"), Path("/root/autodl-tmp/data/cadets/cadets.txt")),
    "trace": (Path("/root/autodl-tmp/data/trace/logs"), Path("/root/autodl-tmp/data/trace/trace.txt")),
}
ROUTES = {
    "quantile90_adjacent_greedy": "adjacent_greedy",
    "quantile90_balanced_child_count": "balanced_child_count",
}


def _json_ready(value: object) -> object:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    return value


def _configure(dataset: str, route: str, budget_strategy: str):
    cfg = copy.copy(load_config(BASE_CONFIGS[dataset]))
    logs, ground_truth = DATASET_INPUTS[dataset]
    suffix = f"{dataset}_temporal_episode_{route}_20260805"
    cfg.host = dataset
    cfg.source_logs = logs
    cfg.task_ground_truth_path = ground_truth
    cfg.artifacts_dir = REPO / f"artifacts_{suffix}"
    cfg.ocr_runtime_root = REPO / "runtime" / "darpa_tc3" / suffix / "experiments"
    cfg.ocr_model_name = f"normal_only_{suffix}.pkl"
    cfg.task_detector_model_output = cfg.artifacts_dir / "module2" / "normal_only_model.pkl"
    cfg.task_tapas_augmentation_enabled = False
    cfg.task_component_split_mode = "fanout"
    cfg.task_component_child_threshold = 2
    cfg.task_component_count_segmented_children_upstream = False
    cfg.task_component_root_temporal_split_enabled = False
    cfg.task_component_branch_object_overlap_split_enabled = False
    cfg.task_component_temporal_episode_split_enabled = True
    cfg.task_component_temporal_episode_parent_missing_only = False
    cfg.task_component_temporal_episode_min_task_nodes = 200
    cfg.task_component_temporal_episode_min_direct_children = 16
    cfg.task_component_temporal_episode_min_span_minutes = 60
    cfg.task_component_temporal_episode_gap_mode = "quantile"
    cfg.task_component_temporal_episode_gap_quantile = 0.90
    cfg.task_component_temporal_episode_min_children_per_episode = 8
    cfg.task_component_temporal_episode_max_episodes = 8
    cfg.task_component_temporal_episode_budget_strategy = budget_strategy
    cfg.path_reason_enabled = False
    return cfg


def _quantiles(values: list[int]) -> dict[str, int]:
    if not values:
        return {key: 0 for key in ("min", "median", "p90", "p95", "p99", "max")}
    array = np.asarray(values, dtype=np.int64)
    return {key: int(np.quantile(array, q)) for key, q in {"min": 0.0, "median": 0.5, "p90": 0.9, "p95": 0.95, "p99": 0.99, "max": 1.0}.items()}


def _details(cfg, module2_outputs: dict) -> dict:
    bundle = torch.load(cfg.module1_dir / "tapas_native_graphs.pt", map_location="cpu", weights_only=False)
    thresholds = json.loads(Path(module2_outputs["task_thresholds"]).read_text(encoding="utf-8"))
    rows = json.loads(Path(module2_outputs["suspicious_tasks"]).read_text(encoding="utf-8"))
    metas = bundle["selected_graph_metas"]
    sizes = [int(meta["task_size"]) for meta in metas]
    positives = [meta for meta in metas if int(meta["label"]) == 1]
    positive_sizes = [int(meta["task_size"]) for meta in positives]
    return {
        "module1": {
            "task_count": len(metas),
            "positive_task_count": len(positives),
            "all_task_size": _quantiles(sizes),
            "positive_task_size": _quantiles(positive_sizes),
            "positive_tasks_size_le_3": sum(size <= 3 for size in positive_sizes),
            "positive_tasks_size_le_5": sum(size <= 5 for size in positive_sizes),
            "all_tasks_gt_500": sum(size > 500 for size in sizes),
            "all_tasks_gt_1000": sum(size > 1000 for size in sizes),
            "temporal_episode_split_summary": bundle.get("temporal_episode_split_summary", {}),
        },
        "module2": {
            "metrics": thresholds.get("backend_summary", {}).get("evaluation_metrics", {}),
            "true_positive_task_ids": [row["task_id"] for row in rows if int(row.get("task_label", 0)) == 1 and int(row.get("predicted_label", 0)) == 1],
            "false_positive_task_ids": [row["task_id"] for row in rows if int(row.get("task_label", 0)) == 0 and int(row.get("predicted_label", 0)) == 1],
            "missed_positive_task_ids": [row["task_id"] for row in rows if int(row.get("task_label", 0)) == 1 and int(row.get("predicted_label", 0)) == 0],
        },
    }


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    routes: list[dict] = []
    for dataset in ("cadets", "trace"):
        for route, strategy in ROUTES.items():
            cfg = _configure(dataset, route, strategy)
            try:
                print(f"[START] {dataset}/{route}: module1 -> module2; module0 is disabled", flush=True)
                module1 = run_module1(cfg)
                module2 = run_module2(
                    cfg,
                    module1["process_embeddings"],
                    module1["task_subgraphs"],
                    module1["process_segmentation_edges"],
                )
                routes.append({
                    "dataset": dataset,
                    "route": route,
                    "status": "completed",
                    "module0_called": False,
                    "config": _json_ready(cfg.__dict__),
                    **_details(cfg, module2),
                })
                print(f"[DONE] {dataset}/{route}", flush=True)
            except Exception as exc:
                traceback.print_exc()
                failed = cfg.artifacts_dir.with_name(f"{cfg.artifacts_dir.name}_failed_runtime_error")
                if cfg.artifacts_dir.exists():
                    if failed.exists():
                        shutil.rmtree(failed)
                    cfg.artifacts_dir.rename(failed)
                routes.append({
                    "dataset": dataset,
                    "route": route,
                    "status": "failed",
                    "module0_called": False,
                    "error": repr(exc),
                    "failed_artifact_dir": str(failed),
                })
            (OUT_DIR / "matrix_summary.json").write_text(
                json.dumps({"experiment": "cadets_trace_temporal_episode_module12_20260805", "routes": routes}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )


if __name__ == "__main__":
    main()
