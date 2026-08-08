"""Compare benign-only threshold calibration choices on fixed TC3 task graphs.

Every route reuses the same Module 1 graph bundle for its dataset.  The held
out labels are never used to select a route: only chronological benign graphs
determine the fitted prototypes and the alert threshold.
"""

from __future__ import annotations

import copy
import json
import shutil
import sys
import traceback
from pathlib import Path


REPO = Path("/root/autodl-tmp/APT-Fusionstep2b1")
OUT_DIR = REPO / "debug" / "remote_ops" / "out" / "cadets_trace_normal_only_calibration_matrix_20260801"
sys.path.insert(0, str(REPO / "src"))

from apt_fusion.config import load_config  # noqa: E402
from apt_fusion.task_detection.module2_online_detection import run_module2  # noqa: E402


BASE_CONFIGS = {
    "cadets": REPO / "configs" / "fusion_cloud_cadets_normal_only_eventstats_core_20260731.yaml",
    "trace": REPO / "configs" / "fusion_cloud_trace_normal_only_multimodal_20260730.yaml",
}
MODULE1_DIRS = {
    "cadets": REPO / "artifacts_cadets_normal_only_root_temporal_baseline_20260801" / "module1",
    "trace": REPO / "artifacts_trace_normal_only_root_temporal_baseline_20260801" / "module1",
}
GROUND_TRUTH = {
    "cadets": Path("/root/autodl-tmp/data/cadets/cadets.txt"),
    "trace": Path("/root/autodl-tmp/data/trace/trace.txt"),
}
# (route name, benign training fraction, benign calibration fraction, target FPR)
ROUTES = (
    ("baseline_70_15_fpr01", 0.70, 0.15, 0.01),
    ("same_split_fpr02", 0.70, 0.15, 0.02),
    ("same_split_fpr05", 0.70, 0.15, 0.05),
    ("larger_calibration_55_30_fpr01", 0.55, 0.30, 0.01),
    ("larger_calibration_55_30_fpr02", 0.55, 0.30, 0.02),
)


def _json_ready(value: object) -> object:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    return value


def _configure(dataset: str, route: str, train_fraction: float, validation_fraction: float, fpr: float):
    cfg = copy.copy(load_config(BASE_CONFIGS[dataset]))
    cfg.host = dataset
    cfg.task_ground_truth_path = GROUND_TRUTH[dataset]
    cfg.artifacts_dir = REPO / f"artifacts_{dataset}_normal_only_calibration_{route}_20260801"
    cfg.ocr_runtime_root = REPO / "runtime" / "darpa_tc3" / f"{dataset}_normal_only_calibration_{route}_20260801" / "experiments"
    cfg.ocr_model_name = f"normal_only_{dataset}_calibration_{route}_20260801.pkl"
    cfg.task_detector_model_output = cfg.artifacts_dir / "module2" / "normal_only_model.pkl"
    cfg.task_tapas_augmentation_enabled = False
    cfg.task_normal_only_train_fraction = train_fraction
    cfg.task_normal_only_validation_fraction = validation_fraction
    cfg.task_normal_only_validation_fpr = fpr
    cfg.path_reason_enabled = False
    return cfg


def _details(outputs: dict) -> dict:
    threshold_data = json.loads(Path(outputs["task_thresholds"]).read_text(encoding="utf-8"))
    backend = threshold_data.get("backend_summary", {})
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
    records: list[dict] = []
    for dataset in ("cadets", "trace"):
        module1_dir = MODULE1_DIRS[dataset]
        required = ("tapas_native_graphs.pt", "process_embeddings.csv", "task_subgraphs.json", "process_segmentation_edges.csv")
        missing = [name for name in required if not (module1_dir / name).exists()]
        if missing:
            raise FileNotFoundError(f"{dataset} reusable Module 1 is incomplete: {missing}")
        for route, train_fraction, validation_fraction, fpr in ROUTES:
            cfg = _configure(dataset, route, train_fraction, validation_fraction, fpr)
            print(f"[START] {dataset}/{route}: module2 only on fixed module1; module0 disabled", flush=True)
            try:
                outputs = run_module2(
                    cfg,
                    module1_dir / "process_embeddings.csv",
                    module1_dir / "task_subgraphs.json",
                    module1_dir / "process_segmentation_edges.csv",
                )
                record = {
                    "dataset": dataset,
                    "route": route,
                    "status": "completed",
                    "module0_called": False,
                    "module1_reused": str(module1_dir),
                    "config": _json_ready(cfg.__dict__),
                    "module2": _details(outputs),
                }
                print(f"[DONE] {dataset}/{route}", flush=True)
            except Exception as exc:
                traceback.print_exc()
                record = {
                    "dataset": dataset,
                    "route": route,
                    "status": "failed",
                    "module0_called": False,
                    "module1_reused": str(module1_dir),
                    "config": _json_ready(cfg.__dict__),
                    "error": repr(exc),
                    "failed_artifact_dir": _mark_failed(cfg, "runtime_error"),
                }
                print(f"[FAILED] {dataset}/{route}: {exc!r}", flush=True)
            records.append(record)
            (OUT_DIR / "matrix_summary.json").write_text(
                json.dumps({"experiment": "cadets_trace_normal_only_calibration_matrix_20260801", "routes": records}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
    print(json.dumps({"experiment": "cadets_trace_normal_only_calibration_matrix_20260801", "routes": records}, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
