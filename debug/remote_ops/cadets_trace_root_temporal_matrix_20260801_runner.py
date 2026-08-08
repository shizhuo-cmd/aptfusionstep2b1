"""Run root-aware task-segmentation ablations for CADETS and TRACE without module0."""

from __future__ import annotations

import copy
import json
import shutil
import sys
import traceback
from pathlib import Path

import torch

REPO = Path("/root/autodl-tmp/APT-Fusionstep2b1")
OUT_DIR = REPO / "debug" / "remote_ops" / "out" / "cadets_trace_root_temporal_matrix_20260801"
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
ROUTES = (
    ("baseline", False, False, 0),
    ("fanout_count_segmented", True, False, 0),
    ("root_session_gap", False, True, 0),
    ("root_session_cap60", False, True, 60),
)


def _json_ready(value: object) -> object:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    return value


def _configure(dataset: str, route: str, count_segmented: bool, root_temporal: bool, session_cap: int):
    cfg = copy.copy(load_config(BASE_CONFIGS[dataset]))
    inputs = DATASET_INPUTS[dataset]
    cfg.host = dataset
    cfg.source_logs = inputs["source_logs"]
    cfg.task_ground_truth_path = inputs["ground_truth"]
    cfg.artifacts_dir = REPO / f"artifacts_{dataset}_normal_only_root_temporal_{route}_20260801"
    cfg.ocr_runtime_root = REPO / "runtime" / "darpa_tc3" / f"{dataset}_normal_only_root_temporal_{route}_20260801" / "experiments"
    cfg.ocr_model_name = f"normal_only_{dataset}_root_temporal_{route}_20260801.pkl"
    cfg.task_detector_model_output = cfg.artifacts_dir / "module2" / "normal_only_model.pkl"
    cfg.task_tapas_augmentation_enabled = False
    cfg.task_component_split_mode = "fanout"
    cfg.task_component_child_threshold = 2
    cfg.task_component_count_segmented_children_upstream = count_segmented
    cfg.task_component_root_temporal_split_enabled = root_temporal
    cfg.task_component_root_temporal_min_task_nodes = 500
    cfg.task_component_root_temporal_min_direct_children = 64
    cfg.task_component_root_temporal_max_span_minutes = 45
    cfg.task_component_root_temporal_branch_gap_minutes = 10
    cfg.task_component_root_temporal_session_max_minutes = session_cap
    # Keep the best previous normal-only feature/detector route fixed across segmentation variants.
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
    task_sizes = [int(meta.get("task_size", 0)) for meta in bundle.get("selected_graph_metas", [])]
    return {
        "task_count": summary.get("task_count"),
        "process_count": summary.get("process_count"),
        "feature_dim": summary.get("graphsage_feature_dim"),
        "gt_positive_task_ids": [
            str(meta.get("task_id")) for meta in bundle.get("selected_graph_metas", []) if int(meta.get("label", 0)) == 1
        ],
        "task_size_max": max(task_sizes, default=0),
        "task_size_p95": sorted(task_sizes)[int(0.95 * (len(task_sizes) - 1))] if task_sizes else 0,
        "root_temporal_split_summary": summary.get("root_temporal_split_summary", {}),
        "large_task_count_gt_500": summary.get("large_task_count_gt_500"),
        "large_task_count_gt_1000": summary.get("large_task_count_gt_1000"),
    }


def _module2_details(outputs: dict) -> dict:
    thresholds = json.loads(Path(outputs["task_thresholds"]).read_text(encoding="utf-8"))
    backend = thresholds.get("backend_summary", {})
    rows = json.loads(Path(outputs["suspicious_tasks"]).read_text(encoding="utf-8"))
    predicted = [row for row in rows if int(row.get("predicted_label", 0)) == 1]
    return {
        "threshold": backend.get("decision_threshold"),
        "metrics": backend.get("evaluation_metrics", {}),
        "normal_only": backend.get("normal_only", {}),
        "true_positive_task_ids": [row["task_id"] for row in predicted if int(row.get("task_label", 0)) == 1],
        "false_positive_task_ids": [row["task_id"] for row in predicted if int(row.get("task_label", 0)) == 0],
        "missed_positive_task_ids": [
            row["task_id"] for row in rows if int(row.get("task_label", 0)) == 1 and int(row.get("predicted_label", 0)) == 0
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


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    for dataset in ("cadets", "trace"):
        for route, count_segmented, root_temporal, session_cap in ROUTES:
            cfg = _configure(dataset, route, count_segmented, root_temporal, session_cap)
            print(f"[START] {dataset}/{route}: module1 -> module2; module0 is disabled", flush=True)
            try:
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
            except Exception as exc:  # Keep later routes runnable and preserve the failed artifact explicitly.
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
                json.dumps({"experiment": "cadets_trace_root_temporal_matrix_20260801", "routes": results}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
    print(json.dumps({"experiment": "cadets_trace_root_temporal_matrix_20260801", "routes": results}, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
