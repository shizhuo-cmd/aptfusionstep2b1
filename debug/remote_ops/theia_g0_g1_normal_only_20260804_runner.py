"""Run a THEIA G0/G1 task-graph detection comparison without module0.

G0 rebuilds the THEIA task graphs and uses the normal-only prototype detector.
Both G1 variants reuse that exact module1 bundle, changing only the module2
normal-only GIN autoencoder and its edge-direction treatment.
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
OUT_DIR = REPO / "debug" / "remote_ops" / "out" / "theia_g0_g1_normal_only_20260804"
BASE_CONFIG = REPO / "configs" / "fusion_cloud_theia_train_stats_latefusion_llama31_taskcomponents.yaml"
SOURCE_LOGS = Path("/root/autodl-tmp/data/theia/logs")
GROUND_TRUTH = Path("/root/autodl-tmp/data/theia/theia_ground_truth.txt")
G0_ARTIFACTS = REPO / "artifacts_theia_normal_only_g0_tapas_paper_baseline_20260804"

sys.path.insert(0, str(REPO / "src"))

from apt_fusion.config import load_config  # noqa: E402
from apt_fusion.task_detection.module1_online_graph import run_module1  # noqa: E402
from apt_fusion.task_detection.module2_online_detection import run_module2  # noqa: E402


def _configure(route: str):
    cfg = copy.copy(load_config(BASE_CONFIG))
    cfg.host = "theia"
    cfg.source_logs = SOURCE_LOGS
    cfg.task_ground_truth_path = GROUND_TRUTH
    cfg.artifacts_dir = REPO / f"artifacts_theia_normal_only_{route}_20260804"
    cfg.ocr_runtime_root = REPO / "runtime" / "darpa_tc3" / f"theia_normal_only_{route}_20260804" / "experiments"
    cfg.ocr_model_name = f"normal_only_theia_{route}_20260804.pkl"
    cfg.task_detector_model_output = cfg.artifacts_dir / "module2" / "normal_only_model.pkl"
    cfg.task_detector_mode = "normal_only"
    cfg.task_normal_only_train_fraction = 0.70
    cfg.task_normal_only_validation_fraction = 0.15
    cfg.task_normal_only_validation_fpr = 0.02
    cfg.task_normal_only_global_model = "kmeans"
    cfg.task_normal_only_local_top_k_mode = "sqrt"
    cfg.task_normal_only_local_top_k_max = 16
    cfg.task_normal_only_global_weight = 0.40
    cfg.task_tapas_augmentation_enabled = False
    cfg.task_component_root_temporal_split_enabled = False
    cfg.task_component_branch_object_overlap_split_enabled = False
    cfg.task_tc3_event_stats_mode = "security_semantic"
    cfg.use_sequence_embeddings = True
    cfg.use_ocr_stat_features = True
    cfg.graphsage_append_ocr_stat_features = True
    cfg.task_graph_stat_late_fusion_enabled = False
    cfg.path_reason_enabled = False

    if route == "g0_tapas_paper_baseline":
        cfg.task_normal_only_detector = "prototype"
    else:
        cfg.task_normal_only_detector = "gin_autoencoder"
        cfg.task_normal_only_gnn_direction_mode = route.removeprefix("g1_").removesuffix("_gin")
        cfg.task_normal_only_gnn_hidden_dim = 64
        cfg.task_normal_only_gnn_num_layers = 2
        cfg.task_normal_only_gnn_dropout = 0.10
        cfg.task_normal_only_gnn_epochs = 20
        cfg.task_normal_only_gnn_batch_size = 4
        cfg.task_normal_only_gnn_learning_rate = 0.001
        cfg.task_normal_only_gnn_weight_decay = 0.0001
    return cfg


def _prepare_module1(cfg) -> Path:
    source = G0_ARTIFACTS / "module1"
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


def _quantiles(values: list[int]) -> dict[str, float | int]:
    if not values:
        return {"count": 0, "min": 0, "median": 0, "p90": 0, "max": 0}
    ordered = sorted(values)

    def pick(fraction: float) -> int:
        return ordered[min(len(ordered) - 1, int(round((len(ordered) - 1) * fraction)))]

    return {"count": len(ordered), "min": ordered[0], "median": pick(0.5), "p90": pick(0.9), "max": ordered[-1]}


def _details(cfg, outputs: dict, module1_reused: bool) -> dict:
    bundle = torch.load(cfg.module1_dir / "tapas_native_graphs.pt", map_location="cpu", weights_only=False)
    thresholds = json.loads(Path(outputs["task_thresholds"]).read_text(encoding="utf-8"))
    backend = thresholds.get("backend_summary", {})
    rows = json.loads(Path(outputs["suspicious_tasks"]).read_text(encoding="utf-8"))
    metas = list(bundle["selected_graph_metas"])
    positives = [meta for meta in metas if int(meta.get("label", 0)) == 1]
    predicted = [row for row in rows if int(row.get("predicted_label", 0)) == 1]
    return {
        "module1_reused_from_g0": module1_reused,
        "task_count": len(metas),
        "gt_positive_task_count": len(positives),
        "gt_positive_task_ids": [str(meta["task_id"]) for meta in positives],
        "all_task_node_count": _quantiles([len(meta.get("node_ids", [])) for meta in metas]),
        "gt_positive_task_node_count": _quantiles([len(meta.get("node_ids", [])) for meta in positives]),
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


def _write_summary(records: list[dict]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "matrix_summary.json").write_text(
        json.dumps({"experiment": "theia_g0_g1_normal_only_20260804", "routes": records}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    records: list[dict] = []
    g0_cfg = _configure("g0_tapas_paper_baseline")
    try:
        print("[START] theia/G0: module1 -> module2; module0 disabled", flush=True)
        module1 = run_module1(g0_cfg)
        outputs = run_module2(
            g0_cfg,
            module1["process_embeddings"],
            module1["task_subgraphs"],
            module1["process_segmentation_edges"],
        )
        records.append({"route": "g0_prototype", "status": "completed", "module0_called": False, "details": _details(g0_cfg, outputs, False)})
        print("[DONE] theia/G0", flush=True)
    except Exception as exc:
        traceback.print_exc()
        records.append({"route": "g0_prototype", "status": "failed", "module0_called": False, "error": repr(exc), "failed_artifact_dir": _mark_failed(g0_cfg.artifacts_dir)})
        _write_summary(records)
        return
    _write_summary(records)

    for route in ("g1_undirected_gin", "g1_directed_gin"):
        cfg = _configure(route)
        try:
            module1_dir = _prepare_module1(cfg)
            print(f"[START] theia/{route}: reuse G0 module1 -> module2; module0 disabled", flush=True)
            outputs = run_module2(
                cfg,
                module1_dir / "process_embeddings.csv",
                module1_dir / "task_subgraphs.json",
                module1_dir / "process_segmentation_edges.csv",
            )
            records.append({"route": route, "status": "completed", "module0_called": False, "details": _details(cfg, outputs, True)})
            print(f"[DONE] theia/{route}", flush=True)
        except Exception as exc:
            traceback.print_exc()
            records.append({"route": route, "status": "failed", "module0_called": False, "error": repr(exc), "failed_artifact_dir": _mark_failed(cfg.artifacts_dir)})
        _write_summary(records)
    print(json.dumps({"experiment": "theia_g0_g1_normal_only_20260804", "routes": records}, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
