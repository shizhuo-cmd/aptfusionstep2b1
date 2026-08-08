"""Run CADETS normal-only semantic-stat and detector-model ablations without module0."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import torch

REPO = Path("/root/autodl-tmp/APT-Fusionstep2b1")
OUT_DIR = REPO / "debug" / "remote_ops" / "out" / "cadets_normal_only_semantic_model_matrix_20260731"
sys.path.insert(0, str(REPO / "src"))

from apt_fusion.config import load_config  # noqa: E402
from apt_fusion.task_detection.module1_online_graph import run_module1  # noqa: E402
from apt_fusion.task_detection.module2_online_detection import run_module2  # noqa: E402


BASE_CONFIG = REPO / "configs" / "fusion_cloud_cadets_normal_only_eventstats_core_20260731.yaml"


def _json_ready(value: object) -> object:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    return value


def _configure(name: str, *, stats_mode: str, local_mode: str, global_model: str):
    cfg = copy.copy(load_config(BASE_CONFIG))
    cfg.artifacts_dir = REPO / f"artifacts_cadets_normal_only_semantic_model_{name}_20260731"
    cfg.ocr_runtime_root = REPO / "runtime" / "darpa_tc3" / f"cadets_normal_only_semantic_model_{name}_20260731" / "experiments"
    cfg.ocr_model_name = f"normal_only_cadets_{name}_20260731.pkl"
    cfg.task_detector_model_output = cfg.artifacts_dir / "module2" / "normal_only_model.pkl"
    cfg.task_tc3_event_stats_mode = stats_mode
    cfg.task_normal_only_local_top_k_mode = local_mode
    cfg.task_normal_only_local_top_k_max = 16
    cfg.task_normal_only_global_model = global_model
    cfg.task_normal_only_global_knn_neighbors = 5
    return cfg


def _module1_details(cfg) -> dict:
    summary = json.loads((cfg.module1_dir / "tapas_native_module1_summary.json").read_text(encoding="utf-8"))
    bundle = torch.load(cfg.module1_dir / "tapas_native_graphs.pt", map_location="cpu", weights_only=False)
    metadata = bundle.get("thread_merge_metadata", {})
    type_counts = metadata.get("raw_event_type_counts", {}) if isinstance(metadata, dict) else {}
    return {
        "task_count": summary.get("task_count"),
        "process_count": summary.get("process_count"),
        "feature_dim": summary.get("graphsage_feature_dim"),
        "stat_feature_dim": summary.get("stat_feature_dim"),
        "stat_feature_source": summary.get("stat_feature_source"),
        "gt_positive_task_ids": [
            str(meta.get("task_id"))
            for meta in bundle.get("selected_graph_metas", [])
            if int(meta.get("label", 0)) == 1
        ],
        "raw_event_type_counts": type_counts,
    }


def _module2_details(module2_outputs: dict) -> dict:
    thresholds = json.loads(Path(module2_outputs["task_thresholds"]).read_text(encoding="utf-8"))
    backend = thresholds.get("backend_summary", {})
    rows = json.loads(Path(module2_outputs["suspicious_tasks"]).read_text(encoding="utf-8"))
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


def _run_full(name: str, cfg) -> tuple[dict, dict]:
    print(f"[START] {name}: module1 -> module2; module0 is disabled", flush=True)
    module1 = run_module1(cfg)
    module2 = run_module2(cfg, module1["process_embeddings"], module1["task_subgraphs"], module1["process_segmentation_edges"])
    print(f"[DONE] {name}", flush=True)
    return _module1_details(cfg), _module2_details(module2)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    routes: list[dict] = []

    core_cfg = _configure("core_raw_fixed", stats_mode="core", local_mode="fixed", global_model="kmeans")
    core_m1, core_m2 = _run_full("core_raw_fixed", core_cfg)
    routes.append({"name": "core_raw_fixed", "module0_called": False, "config": _json_ready(core_cfg.__dict__), "module1": core_m1, "module2": core_m2})

    semantic_cfg = _configure("security_semantic_fixed", stats_mode="security_semantic", local_mode="fixed", global_model="kmeans")
    semantic_m1, semantic_m2 = _run_full("security_semantic_fixed", semantic_cfg)
    routes.append({"name": "security_semantic_fixed", "module0_called": False, "config": _json_ready(semantic_cfg.__dict__), "module1": semantic_m1, "module2": semantic_m2})

    adaptive_cfg = _configure("security_semantic_adaptive", stats_mode="security_semantic", local_mode="sqrt", global_model="kmeans")
    adaptive_m1, adaptive_m2 = _run_full("security_semantic_adaptive", adaptive_cfg)
    routes.append({"name": "security_semantic_adaptive", "module0_called": False, "config": _json_ready(adaptive_cfg.__dict__), "module1": adaptive_m1, "module2": adaptive_m2})

    knn_cfg = _configure("security_semantic_adaptive_knn", stats_mode="security_semantic", local_mode="sqrt", global_model="knn")
    print("[START] security_semantic_adaptive_knn: module2 only, reusing adaptive module1; module0 is disabled", flush=True)
    knn_m2_outputs = run_module2(
        knn_cfg,
        adaptive_cfg.module1_dir / "process_embeddings.csv",
        adaptive_cfg.module1_dir / "task_subgraphs.json",
        adaptive_cfg.module1_dir / "process_segmentation_edges.csv",
    )
    print("[DONE] security_semantic_adaptive_knn", flush=True)
    routes.append(
        {
            "name": "security_semantic_adaptive_knn",
            "module0_called": False,
            "module1_reused_from": str(adaptive_cfg.module1_dir),
            "config": _json_ready(knn_cfg.__dict__),
            "module1": adaptive_m1,
            "module2": _module2_details(knn_m2_outputs),
        }
    )

    matrix = {
        "experiment": "cadets_normal_only_semantic_model_matrix_20260731",
        "module0_called": False,
        "routes": routes,
    }
    (OUT_DIR / "matrix_summary.json").write_text(json.dumps(matrix, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(matrix, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
