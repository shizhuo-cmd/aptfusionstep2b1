"""Run the G1 undirected-GIN versus directed-GIN normal-only comparison.

The runner deliberately reuses the paper-aligned G0 module1 bundles.  G1 only
changes module2's graph detector, so rebuilding raw logs would add runtime but
not a new experimental variable.  Module0 is never invoked.
"""

from __future__ import annotations

import copy
import json
import shutil
import sys
import traceback
from pathlib import Path

import torch

REPO = Path("/root/autodl-tmp/APT-Fusionstep2b1")
OUT_DIR = REPO / "debug" / "remote_ops" / "out" / "cadets_trace_g1_directional_gin_20260803"
sys.path.insert(0, str(REPO / "src"))

from apt_fusion.config import load_config  # noqa: E402
from apt_fusion.task_detection.module2_online_detection import run_module2  # noqa: E402


BASE_CONFIGS = {
    "cadets": REPO / "configs" / "fusion_cloud_cadets_normal_only_eventstats_core_20260731.yaml",
    "trace": REPO / "configs" / "fusion_cloud_trace_normal_only_multimodal_20260730.yaml",
}
BASE_ARTIFACTS = {
    "cadets": REPO / "artifacts_cadets_normal_only_tapas_paper_baseline_20260802",
    "trace": REPO / "artifacts_trace_normal_only_tapas_paper_baseline_20260802",
}


def _configure(dataset: str, route: str):
    cfg = copy.copy(load_config(BASE_CONFIGS[dataset]))
    cfg.host = dataset
    cfg.artifacts_dir = REPO / f"artifacts_{dataset}_normal_only_g1_{route}_20260803"
    cfg.ocr_runtime_root = REPO / "runtime" / "darpa_tc3" / f"{dataset}_normal_only_g1_{route}_20260803" / "experiments"
    cfg.ocr_model_name = f"normal_only_{dataset}_g1_{route}_20260803.pkl"
    cfg.task_detector_model_output = cfg.artifacts_dir / "module2" / "normal_only_model.pkl"
    cfg.task_detector_mode = "normal_only"
    cfg.task_normal_only_detector = "gin_autoencoder"
    cfg.task_normal_only_gnn_direction_mode = route
    cfg.task_normal_only_gnn_hidden_dim = 64
    cfg.task_normal_only_gnn_num_layers = 2
    cfg.task_normal_only_gnn_dropout = 0.10
    cfg.task_normal_only_gnn_epochs = 20
    cfg.task_normal_only_gnn_batch_size = 4
    cfg.task_normal_only_gnn_learning_rate = 0.001
    cfg.task_normal_only_gnn_weight_decay = 0.0001
    cfg.task_normal_only_train_fraction = 0.70
    cfg.task_normal_only_validation_fraction = 0.15
    cfg.task_normal_only_validation_fpr = 0.02
    cfg.task_normal_only_global_model = "kmeans"
    cfg.task_normal_only_local_top_k_mode = "sqrt"
    cfg.task_normal_only_local_top_k_max = 16
    cfg.task_normal_only_global_weight = 0.40
    cfg.task_tapas_augmentation_enabled = False
    cfg.path_reason_enabled = False
    return cfg


def _prepare_module1(cfg, baseline_root: Path) -> Path:
    source = baseline_root / "module1"
    if not (source / "tapas_native_graphs.pt").exists():
        raise FileNotFoundError(f"Missing immutable G0 module1 bundle: {source}")
    cfg.artifacts_dir.mkdir(parents=True, exist_ok=True)
    target = cfg.artifacts_dir / "module1"
    if target.exists() or target.is_symlink():
        if target.resolve() != source.resolve():
            raise RuntimeError(f"Refusing to overwrite existing module1 target: {target}")
    else:
        target.symlink_to(source, target_is_directory=True)
    return target


def _details(cfg, outputs: dict) -> dict:
    bundle = torch.load(cfg.module1_dir / "tapas_native_graphs.pt", map_location="cpu", weights_only=False)
    thresholds = json.loads(Path(outputs["task_thresholds"]).read_text(encoding="utf-8"))
    backend = thresholds.get("backend_summary", {})
    rows = json.loads(Path(outputs["suspicious_tasks"]).read_text(encoding="utf-8"))
    predicted = [row for row in rows if int(row.get("predicted_label", 0)) == 1]
    return {
        "module1_reused_from": str(BASE_ARTIFACTS[cfg.host] / "module1"),
        "task_count": len(bundle["selected_graph_metas"]),
        "gt_positive_task_ids": [str(meta["task_id"]) for meta in bundle["selected_graph_metas"] if int(meta.get("label", 0)) == 1],
        "feature_dim": int(bundle.get("sequence_feature_dim", 0)) + len(bundle.get("stat_feature_columns", [])),
        "module2_metrics": backend.get("evaluation_metrics", {}),
        "threshold": backend.get("decision_threshold"),
        "normal_only": backend.get("normal_only", {}),
        "true_positive_task_ids": [row["task_id"] for row in predicted if int(row.get("task_label", 0)) == 1],
        "false_positive_task_ids": [row["task_id"] for row in predicted if int(row.get("task_label", 0)) == 0],
        "missed_positive_task_ids": [
            row["task_id"] for row in rows if int(row.get("task_label", 0)) == 1 and int(row.get("predicted_label", 0)) == 0
        ],
    }


def _mark_failed(path: Path) -> str | None:
    if not path.exists():
        return None
    target = path.with_name(f"{path.name}_failed_runtime_error")
    if target.exists():
        shutil.rmtree(target)
    path.rename(target)
    return str(target)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    records: list[dict] = []
    for dataset in ("cadets", "trace"):
        for route in ("undirected", "directed"):
            cfg = _configure(dataset, route)
            try:
                module1_dir = _prepare_module1(cfg, BASE_ARTIFACTS[dataset])
                print(f"[START] {dataset}/{route}: reuse module1, run G1 module2 only; module0 disabled", flush=True)
                outputs = run_module2(
                    cfg,
                    module1_dir / "process_embeddings.csv",
                    module1_dir / "task_subgraphs.json",
                    module1_dir / "process_segmentation_edges.csv",
                )
                records.append({
                    "dataset": dataset,
                    "route": f"g1_{route}_gin_autoencoder",
                    "status": "completed",
                    "module0_called": False,
                    "module1_reused": True,
                    "details": _details(cfg, outputs),
                })
                print(f"[DONE] {dataset}/{route}", flush=True)
            except Exception as exc:
                traceback.print_exc()
                records.append({
                    "dataset": dataset,
                    "route": f"g1_{route}_gin_autoencoder",
                    "status": "failed",
                    "module0_called": False,
                    "module1_reused": True,
                    "error": repr(exc),
                    "failed_artifact_dir": _mark_failed(cfg.artifacts_dir),
                })
            (OUT_DIR / "matrix_summary.json").write_text(
                json.dumps({"experiment": "cadets_trace_g1_directional_gin_20260803", "routes": records}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
    print(json.dumps({"experiment": "cadets_trace_g1_directional_gin_20260803", "routes": records}, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
