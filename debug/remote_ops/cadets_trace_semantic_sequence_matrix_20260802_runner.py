"""Run E1/E2/E3 normal-only sequence-input ablations without module0.

E1 keeps the legacy LSTM-GRU and adds the established security-statistics
side channel. E2 retrains the semantic sequence encoder from benign temporal
training graphs only. E3 reuses the E2 checkpoint and adds the same side
channel, isolating the representation-versus-statistics contribution.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import sys
import traceback
from pathlib import Path

import torch

REPO = Path("/root/autodl-tmp/APT-Fusionstep2b1")
OUT_DIR = REPO / "debug" / "remote_ops" / "out" / "cadets_trace_semantic_sequence_matrix_20260802"
sys.path.insert(0, str(REPO / "src"))

from apt_fusion.config import load_config  # noqa: E402
from apt_fusion.task_detection.module1_online_graph import run_module1  # noqa: E402
from apt_fusion.task_detection.module2_online_detection import run_module2  # noqa: E402


BASE_CONFIGS = {
    "cadets": REPO / "configs" / "fusion_cloud_cadets_normal_only_eventstats_core_20260731.yaml",
    "trace": REPO / "configs" / "fusion_cloud_trace_normal_only_multimodal_20260730.yaml",
}
INPUTS = {
    "cadets": (Path("/root/autodl-tmp/data/cadets/logs"), Path("/root/autodl-tmp/data/cadets/cadets.txt")),
    "trace": (Path("/root/autodl-tmp/data/trace/logs"), Path("/root/autodl-tmp/data/trace/trace.txt")),
}
ROUTES = ("E1_legacy_plus_stats", "E2_semantic_sequence", "E3_semantic_plus_stats")


def _json_ready(value: object) -> object:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    return value


def _configure(dataset: str, route: str):
    cfg = copy.copy(load_config(BASE_CONFIGS[dataset]))
    source_logs, ground_truth = INPUTS[dataset]
    cfg.host = dataset
    cfg.source_logs = source_logs
    cfg.task_ground_truth_path = ground_truth
    cfg.artifacts_dir = REPO / f"artifacts_{dataset}_normal_only_{route}_20260802"
    cfg.ocr_runtime_root = REPO / "runtime" / "darpa_tc3" / f"{dataset}_normal_only_{route}_20260802" / "experiments"
    cfg.ocr_model_name = f"normal_only_{dataset}_{route}_20260802.pkl"
    cfg.task_detector_model_output = cfg.artifacts_dir / "module2" / "normal_only_model.pkl"
    cfg.task_tapas_augmentation_enabled = False
    cfg.task_component_root_temporal_split_enabled = False
    cfg.task_sequence_encoder_mode = "semantic_v1" if route in {"E2_semantic_sequence", "E3_semantic_plus_stats"} else "legacy"
    cfg.task_semantic_sequence_epochs = 5
    cfg.task_semantic_sequence_batch_size = 512
    cfg.task_semantic_sequence_learning_rate = 1e-3
    cfg.task_normal_only_train_fraction = 0.70
    cfg.task_normal_only_validation_fraction = 0.15
    cfg.task_normal_only_validation_fpr = 0.02
    cfg.task_normal_only_global_model = "kmeans"
    cfg.task_normal_only_local_top_k_mode = "sqrt"
    cfg.task_normal_only_local_top_k_max = 16
    cfg.task_tc3_event_stats_mode = "security_semantic"
    cfg.use_sequence_embeddings = True
    cfg.use_ocr_stat_features = route in {"E1_legacy_plus_stats", "E3_semantic_plus_stats"}
    cfg.graphsage_append_ocr_stat_features = cfg.use_ocr_stat_features
    cfg.task_graph_stat_late_fusion_enabled = False
    cfg.path_reason_enabled = False
    if route == "E3_semantic_plus_stats":
        checkpoint = REPO / f"artifacts_{dataset}_normal_only_E2_semantic_sequence_20260802" / "module1" / "semantic_sequence_encoder.pt"
        if not checkpoint.exists():
            raise FileNotFoundError(f"E3 requires completed E2 checkpoint: {checkpoint}")
        cfg.task_semantic_sequence_pretrained_path = checkpoint
    else:
        cfg.task_semantic_sequence_pretrained_path = None
    return cfg


def _module1_details(cfg) -> dict:
    summary = json.loads((cfg.module1_dir / "tapas_native_module1_summary.json").read_text(encoding="utf-8"))
    bundle = torch.load(cfg.module1_dir / "tapas_native_graphs.pt", map_location="cpu", weights_only=False)
    return {
        "task_count": summary.get("task_count"),
        "process_count": summary.get("process_count"),
        "feature_dim": summary.get("graphsage_feature_dim"),
        "base_sequence_feature_dim": bundle.get("base_sequence_feature_dim"),
        "stat_feature_columns": bundle.get("stat_feature_columns", []),
        "stat_feature_source": bundle.get("stat_feature_source", ""),
        "semantic_sequence_encoder": bundle.get("thread_merge_metadata", {}).get("semantic_sequence_encoder", {}),
        "gt_positive_task_ids": [
            str(meta.get("task_id")) for meta in bundle.get("selected_graph_metas", []) if int(meta.get("label", 0)) == 1
        ],
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
    directory = Path(cfg.artifacts_dir)
    if not directory.exists():
        return None
    target = directory.with_name(f"{directory.name}_failed_{reason}")
    if target.exists():
        shutil.rmtree(target)
    directory.rename(target)
    return str(target)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    selected_routes = tuple(filter(None, os.environ.get("APT_FUSION_ONLY_ROUTES", "").split(","))) or ROUTES
    records_by_key: dict[tuple[str, str], dict] = {}
    summary_path = OUT_DIR / "matrix_summary.json"
    if summary_path.exists():
        try:
            existing = json.loads(summary_path.read_text(encoding="utf-8"))
            records_by_key = {
                (str(record["dataset"]), str(record["route"])): record
                for record in existing.get("routes", [])
            }
        except (json.JSONDecodeError, KeyError, TypeError):
            # A partial or manually inspected summary must not block a targeted retry.
            records_by_key = {}
    for dataset in ("cadets", "trace"):
        for route in selected_routes:
            cfg = _configure(dataset, route)
            print(f"[START] {dataset}/{route}: module1 -> module2; module0 disabled", flush=True)
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
            records_by_key[(dataset, route)] = record
            ordered_records = [
                records_by_key[(ordered_dataset, ordered_route)]
                for ordered_dataset in ("cadets", "trace")
                for ordered_route in ROUTES
                if (ordered_dataset, ordered_route) in records_by_key
            ]
            summary_path.write_text(
                json.dumps(
                    {"experiment": "cadets_trace_semantic_sequence_matrix_20260802", "routes": ordered_records},
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
    ordered_records = [
        records_by_key[(ordered_dataset, ordered_route)]
        for ordered_dataset in ("cadets", "trace")
        for ordered_route in ROUTES
        if (ordered_dataset, ordered_route) in records_by_key
    ]
    print(json.dumps({"experiment": "cadets_trace_semantic_sequence_matrix_20260802", "routes": ordered_records}, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
