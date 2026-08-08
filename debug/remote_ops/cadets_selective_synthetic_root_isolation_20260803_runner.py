"""Evaluate selective CADETS collector-root branch isolation without module0."""

from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path

import torch


REPO = Path("/root/autodl-tmp/APT-Fusionstep2b1")
OUT_DIR = REPO / "debug" / "remote_ops" / "out" / "cadets_selective_synthetic_root_isolation_20260803"
BASE_CONFIG = REPO / "configs" / "fusion_cloud_cadets_normal_only_eventstats_core_20260731.yaml"
BASELINE_SUMMARY = (
    REPO / "debug" / "remote_ops" / "out" / "cadets_synthetic_root_isolation_start0_20260803" / "matrix_summary.json"
)
sys.path.insert(0, str(REPO / "src"))

from apt_fusion.config import load_config  # noqa: E402
from apt_fusion.task_detection.module1_online_graph import run_module1  # noqa: E402
from apt_fusion.task_detection.module2_online_detection import run_module2  # noqa: E402


def _configure():
    cfg = load_config(BASE_CONFIG)
    cfg.host = "cadets"
    cfg.source_logs = Path("/root/autodl-tmp/data/cadets/logs")
    cfg.task_ground_truth_path = Path("/root/autodl-tmp/data/cadets/cadets.txt")
    cfg.artifacts_dir = REPO / "artifacts_cadets_selective_synthetic_root_isolation_20260803"
    cfg.ocr_runtime_root = REPO / "runtime" / "darpa_tc3" / "cadets_selective_synthetic_root_isolation_20260803" / "experiments"
    cfg.ocr_model_name = "normal_only_cadets_selective_synthetic_root_isolation_20260803.pkl"
    cfg.task_detector_model_output = cfg.artifacts_dir / "module2" / "normal_only_model.pkl"
    cfg.task_tapas_augmentation_enabled = False
    cfg.path_reason_enabled = False
    cfg.task_component_root_temporal_split_enabled = False
    cfg.task_component_synthetic_root_isolation_enabled = False
    cfg.task_component_synthetic_root_selective_isolation_enabled = True
    cfg.task_component_synthetic_root_isolation_min_task_nodes = 500
    cfg.task_component_synthetic_root_isolation_min_direct_children = 64
    cfg.task_component_synthetic_root_selective_max_exec_target_frequency = 3
    return cfg


def _details(cfg, outputs):
    bundle = torch.load(cfg.module1_dir / "tapas_native_graphs.pt", map_location="cpu", weights_only=False)
    summary = json.loads((cfg.module1_dir / "tapas_native_module1_summary.json").read_text(encoding="utf-8"))
    thresholds = json.loads(Path(outputs["task_thresholds"]).read_text(encoding="utf-8"))
    backend = thresholds.get("backend_summary", {})
    suspicious = json.loads(Path(outputs["suspicious_tasks"]).read_text(encoding="utf-8"))
    predicted = [row for row in suspicious if int(row.get("predicted_label", 0)) == 1]
    task_sizes = [int(meta.get("task_size", 0)) for meta in bundle.get("selected_graph_metas", [])]
    labels = {str(meta.get("task_id")): int(meta.get("label", 0)) for meta in bundle.get("selected_graph_metas", [])}
    return {
        "task_count": len(task_sizes),
        "gt_positive_task_count": sum(labels.values()),
        "gt_positive_task_ids": [task_id for task_id, label in labels.items() if label == 1],
        "task_size_max": max(task_sizes, default=0),
        "task_size_p95": sorted(task_sizes)[int(0.95 * (len(task_sizes) - 1))] if task_sizes else 0,
        "threshold": backend.get("decision_threshold"),
        "metrics": backend.get("evaluation_metrics", {}),
        "true_positive_task_ids": [row["task_id"] for row in predicted if labels.get(str(row["task_id"]), 0) == 1],
        "false_positive_count": sum(labels.get(str(row["task_id"]), 0) == 0 for row in predicted),
        "missed_positive_task_ids": [
            task_id for task_id, label in labels.items() if label == 1 and task_id not in {row["task_id"] for row in predicted}
        ],
        "selective_isolation_summary": summary.get("synthetic_root_selective_isolation_summary", {}),
    }


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cfg = _configure()
    try:
        print("[START] selective synthetic-root isolation; module0 disabled", flush=True)
        module1 = run_module1(cfg)
        module2 = run_module2(cfg, module1["process_embeddings"], module1["task_subgraphs"], module1["process_segmentation_edges"])
        record = {"status": "completed", "module0_called": False, "details": _details(cfg, module2)}
        print("[DONE] selective synthetic-root isolation", flush=True)
    except Exception as exc:
        traceback.print_exc()
        record = {"status": "failed", "module0_called": False, "error": repr(exc)}
    baseline = json.loads(BASELINE_SUMMARY.read_text(encoding="utf-8")).get("baseline_g0", {})
    (OUT_DIR / "matrix_summary.json").write_text(
        json.dumps(
            {
                "experiment": "cadets_selective_synthetic_root_isolation_20260803",
                "baseline_g0": baseline,
                "selective_synthetic_root_isolation": record,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    if record["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
