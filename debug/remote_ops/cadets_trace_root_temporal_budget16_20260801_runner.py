"""Validate bounded root-session task splitting for CADETS and TRACE without module0."""

from __future__ import annotations

import copy
import json
import shutil
import sys
import traceback
from pathlib import Path

import torch

REPO = Path("/root/autodl-tmp/APT-Fusionstep2b1")
OUT_DIR = REPO / "debug" / "remote_ops" / "out" / "cadets_trace_root_temporal_budget16_20260801"
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


def _json_ready(value: object) -> object:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    return value


def _configure(dataset: str):
    cfg = copy.copy(load_config(BASE_CONFIGS[dataset]))
    source_logs, ground_truth = DATASET_INPUTS[dataset]
    cfg.host = dataset
    cfg.source_logs = source_logs
    cfg.task_ground_truth_path = ground_truth
    cfg.artifacts_dir = REPO / f"artifacts_{dataset}_normal_only_root_temporal_gap_budget16_20260801"
    cfg.ocr_runtime_root = REPO / "runtime" / "darpa_tc3" / f"{dataset}_normal_only_root_temporal_gap_budget16_20260801" / "experiments"
    cfg.ocr_model_name = f"normal_only_{dataset}_root_temporal_gap_budget16_20260801.pkl"
    cfg.task_detector_model_output = cfg.artifacts_dir / "module2" / "normal_only_model.pkl"
    cfg.task_tapas_augmentation_enabled = False
    cfg.task_component_split_mode = "fanout"
    cfg.task_component_child_threshold = 2
    cfg.task_component_count_segmented_children_upstream = False
    cfg.task_component_root_temporal_split_enabled = True
    cfg.task_component_root_temporal_min_task_nodes = 500
    cfg.task_component_root_temporal_min_direct_children = 64
    cfg.task_component_root_temporal_max_span_minutes = 45
    cfg.task_component_root_temporal_branch_gap_minutes = 10
    cfg.task_component_root_temporal_session_max_minutes = 0
    cfg.task_component_root_temporal_max_sessions = 16
    cfg.use_sequence_embeddings = True
    cfg.use_ocr_stat_features = True
    cfg.graphsage_append_ocr_stat_features = False
    cfg.task_graph_stat_late_fusion_enabled = False
    cfg.task_tc3_event_stats_mode = "security_semantic"
    cfg.task_normal_only_local_top_k_mode = "sqrt"
    cfg.task_normal_only_local_top_k_max = 16
    cfg.task_normal_only_global_model = "kmeans"
    cfg.path_reason_enabled = False
    return cfg


def _details(cfg, module2_outputs: dict) -> dict:
    summary = json.loads((cfg.module1_dir / "tapas_native_module1_summary.json").read_text(encoding="utf-8"))
    bundle = torch.load(cfg.module1_dir / "tapas_native_graphs.pt", map_location="cpu", weights_only=False)
    thresholds = json.loads(Path(module2_outputs["task_thresholds"]).read_text(encoding="utf-8"))
    rows = json.loads(Path(module2_outputs["suspicious_tasks"]).read_text(encoding="utf-8"))
    predicted = [row for row in rows if int(row.get("predicted_label", 0)) == 1]
    task_sizes = [int(meta.get("task_size", 0)) for meta in bundle.get("selected_graph_metas", [])]
    return {
        "module1": {
            "task_count": summary.get("task_count"),
            "gt_positive_task_ids": [
                str(meta.get("task_id")) for meta in bundle.get("selected_graph_metas", []) if int(meta.get("label", 0)) == 1
            ],
            "task_size_max": max(task_sizes, default=0),
            "root_temporal_split_summary": summary.get("root_temporal_split_summary", {}),
        },
        "module2": {
            "metrics": thresholds.get("backend_summary", {}).get("evaluation_metrics", {}),
            "true_positive_task_ids": [row["task_id"] for row in predicted if int(row.get("task_label", 0)) == 1],
            "false_positive_task_ids": [row["task_id"] for row in predicted if int(row.get("task_label", 0)) == 0],
            "missed_positive_task_ids": [
                row["task_id"] for row in rows if int(row.get("task_label", 0)) == 1 and int(row.get("predicted_label", 0)) == 0
            ],
        },
    }


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    routes = []
    for dataset in ("cadets", "trace"):
        cfg = _configure(dataset)
        try:
            print(f"[START] {dataset}/root_session_gap_budget16: module1 -> module2; module0 is disabled", flush=True)
            module1 = run_module1(cfg)
            module2 = run_module2(cfg, module1["process_embeddings"], module1["task_subgraphs"], module1["process_segmentation_edges"])
            routes.append({"dataset": dataset, "route": "root_session_gap_budget16", "status": "completed", "module0_called": False, "config": _json_ready(cfg.__dict__), **_details(cfg, module2)})
            print(f"[DONE] {dataset}/root_session_gap_budget16", flush=True)
        except Exception as exc:
            traceback.print_exc()
            failed = cfg.artifacts_dir.with_name(f"{cfg.artifacts_dir.name}_failed_runtime_error")
            if cfg.artifacts_dir.exists():
                if failed.exists():
                    shutil.rmtree(failed)
                cfg.artifacts_dir.rename(failed)
            routes.append({"dataset": dataset, "route": "root_session_gap_budget16", "status": "failed", "module0_called": False, "error": repr(exc), "failed_artifact_dir": str(failed)})
            print(f"[FAILED] {dataset}: {exc!r}", flush=True)
        (OUT_DIR / "matrix_summary.json").write_text(json.dumps({"experiment": "cadets_trace_root_temporal_budget16_20260801", "routes": routes}, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
