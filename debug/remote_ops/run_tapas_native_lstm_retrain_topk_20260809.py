"""Compare frozen and benign-only retrained TAPAS process encoders on TC3.

The experiment keeps the TAPAS task graph and ProvGRP partition fixed within
each route.  It fits the next-event LSTM-GRU only on process histories from
the temporal benign-training partition, then evaluates process KMeans distance
and Top-K task aggregation without using attack labels for fitting or tuning.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import traceback
from pathlib import Path
from typing import Any

import torch


REPO = Path("/root/autodl-tmp/APT-Fusionstep2b1")
sys.path.insert(0, str(REPO / "src"))

from apt_fusion.config import load_config
from apt_fusion.task_detection.module1_online_graph import run_module1
from apt_fusion.task_detection.module2_online_detection import run_module2
from apt_fusion.task_detection.tapas_native_backend import _normal_only_temporal_split


SPECS = {
    "cadets": {
        "config": REPO / "configs/fusion_cloud_cadets_normal_only_eventstats_core_20260731.yaml",
        "logs": Path("/root/autodl-tmp/data/cadets/logs"),
        "ground_truth": Path("/root/autodl-tmp/data/cadets/cadets.txt"),
    },
    "trace": {
        "config": REPO / "configs/fusion_cloud_trace_normal_only_multimodal_20260730.yaml",
        "logs": Path("/root/autodl-tmp/data/trace/logs"),
        "ground_truth": Path("/root/autodl-tmp/data/trace/trace.txt"),
    },
    "theia": {
        "config": REPO / "configs/fusion_cloud_theia_train_stats_latefusion_llama31_taskcomponents.yaml",
        "logs": Path("/root/autodl-tmp/data/theia/logs"),
        "ground_truth": Path("/root/autodl-tmp/data/theia/theia_ground_truth.txt"),
    },
}


def _load_pretrainer() -> Any:
    path = REPO / "scripts" / "train_tc3_stackedlstm_pretrain_20260707.py"
    spec = importlib.util.spec_from_file_location("tapas_native_pretrainer_20260809", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to import pretrainer: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _config(dataset: str, route: str, *, checkpoint: Path | None = None, global_weight: float = 0.0):
    spec = SPECS[dataset]
    cfg = copy.copy(load_config(spec["config"]))
    cfg.host = dataset
    cfg.source_logs = spec["logs"]
    cfg.task_ground_truth_path = spec["ground_truth"]
    cfg.artifacts_dir = REPO / f"artifacts_{dataset}_tapas_lstm_topk_{route}_20260809"
    cfg.ocr_runtime_root = REPO / "runtime" / "darpa_tc3" / f"{dataset}_tapas_lstm_topk_{route}_20260809"
    cfg.ocr_model_name = f"{dataset}_tapas_lstm_topk_{route}_20260809.pkl"
    cfg.task_detector_model_output = cfg.artifacts_dir / "module2" / "normal_only_model.pkl"
    cfg.task_sequence_model_path = checkpoint
    cfg.task_detector_mode = "normal_only"
    cfg.task_normal_only_detector = "prototype"
    cfg.task_normal_only_node_feature_mode = "sequence_only"
    cfg.task_normal_only_node_audit_enabled = True
    cfg.task_normal_only_train_fraction = 0.70
    cfg.task_normal_only_validation_fraction = 0.15
    cfg.task_normal_only_validation_fpr = 0.02
    cfg.task_normal_only_global_model = "kmeans"
    cfg.task_normal_only_local_top_k_mode = "sqrt"
    cfg.task_normal_only_local_top_k_max = 16
    cfg.task_normal_only_global_weight = global_weight
    cfg.task_tapas_augmentation_enabled = False
    cfg.path_reason_enabled = False

    # Keep the already selected paper-faithful ProvGRP task partition and do
    # not combine this encoder experiment with earlier temporal splitters.
    cfg.task_component_provgrp_behavior_partition_enabled = True
    cfg.task_component_provgrp_min_direct_children = 10
    cfg.task_component_provgrp_min_cluster_size = 5
    cfg.task_component_provgrp_min_samples = 2
    cfg.task_component_provgrp_max_events_per_matrix = 512
    cfg.task_component_provgrp_batch_overlap_events = 64
    cfg.task_component_root_temporal_split_enabled = False
    cfg.task_component_temporal_episode_split_enabled = False
    cfg.task_component_theia_temporal_split_enabled = False
    cfg.task_component_synthetic_root_isolation_enabled = False
    cfg.task_component_synthetic_root_selective_isolation_enabled = False
    cfg.task_component_branch_object_overlap_split_enabled = False
    return cfg


def _load_bundle(module1_dir: Path) -> dict[str, Any]:
    return torch.load(module1_dir / "tapas_native_graphs.pt", map_location="cpu", weights_only=False)


def _normal_training_process_ids(cfg) -> tuple[set[str], dict[str, Any]]:
    bundle = _load_bundle(cfg.module1_dir)
    split = _normal_only_temporal_split(cfg, bundle["selected_graphs"], bundle["selected_graph_metas"])
    identifiers = {
        str(process_id)
        for index in split["train_indices"]
        for process_id in bundle["selected_graph_metas"][index].get("node_ids", [])
    }
    return identifiers, dict(split["summary"])


def _evaluate(cfg, module1: dict[str, Path], global_weight: float) -> dict[str, Any]:
    eval_cfg = copy.copy(cfg)
    eval_cfg.artifacts_dir = cfg.artifacts_dir.with_name(f"{cfg.artifacts_dir.name}_gw{global_weight:g}")
    eval_cfg.task_detector_model_output = eval_cfg.artifacts_dir / "module2" / "normal_only_model.pkl"
    eval_cfg.task_normal_only_global_weight = global_weight
    target = eval_cfg.artifacts_dir / "module1"
    eval_cfg.artifacts_dir.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        target.symlink_to(cfg.module1_dir, target_is_directory=True)
    outputs = run_module2(
        eval_cfg,
        target / "process_embeddings.csv",
        target / "task_subgraphs.json",
        target / "process_segmentation_edges.csv",
    )
    thresholds = json.loads(Path(outputs["task_thresholds"]).read_text(encoding="utf-8"))
    backend = thresholds.get("backend_summary", {})
    return {
        "global_weight": global_weight,
        "task_metrics": backend.get("evaluation_metrics", {}),
        "node_audit": backend.get("normal_only", {}).get("node_audit_metrics", {}),
        "outputs": {key: str(value) for key, value in outputs.items()},
    }


def _task_size_summary(bundle: dict[str, Any]) -> dict[str, int]:
    sizes = sorted(len(meta.get("node_ids", [])) for meta in bundle["selected_graph_metas"])
    if not sizes:
        return {"count": 0}
    return {
        "count": len(sizes),
        "median": sizes[len(sizes) // 2],
        "p90": sizes[min(len(sizes) - 1, round((len(sizes) - 1) * 0.9))],
        "max": sizes[-1],
    }


def _run_dataset(dataset: str) -> dict[str, Any]:
    pretrainer = _load_pretrainer()
    baseline_cfg = _config(dataset, "frozen")
    print(f"[START] {dataset}: rebuild module1 with frozen TAPAS checkpoint", flush=True)
    baseline_module1 = run_module1(baseline_cfg)
    allowed_ids, split_summary = _normal_training_process_ids(baseline_cfg)
    allowed_path = baseline_cfg.module1_dir / "normal_only_training_process_ids.json"
    allowed_path.write_text(json.dumps(sorted(allowed_ids), indent=2), encoding="utf-8")
    baseline_bundle = _load_bundle(baseline_cfg.module1_dir)
    baseline_result = {
        "module1": {key: str(value) for key, value in baseline_module1.items()},
        "task_size": _task_size_summary(baseline_bundle),
        "normal_training_process_count": len(allowed_ids),
        "normal_split": split_summary,
        "evaluations": [_evaluate(baseline_cfg, baseline_module1, weight) for weight in (0.0, 0.4)],
    }

    retrained_cfg = _config(dataset, "retrained")
    print(f"[START] {dataset}: benign-only TAPAS next-event pretraining", flush=True)
    kwargs = {
        "trace_logs": SPECS["trace"]["logs"],
        "cadets_logs": SPECS["cadets"]["logs"],
        "theia_logs": SPECS["theia"]["logs"],
        "output_dir": retrained_cfg.artifacts_dir / "sequence_pretrain",
        "hosts": (dataset,),
        "allowed_subject_ids_by_host": {dataset: allowed_ids},
        "epochs": 70,
        "batch_size": 256,
        "lr": 0.1,
        "lr_decay_factor": 0.1,
        "lr_decay_rate": 500,
        "max_optimizer_steps": 1500,
        "max_seq_len": 128,
        "val_fraction": 0.10,
        "max_trace_sequences": None,
        "max_cadets_sequences": None,
        "max_theia_sequences": None,
        "seed": 173,
    }
    manifest = pretrainer.run_pretraining(**kwargs)
    checkpoint = Path(manifest["best_model_path"])
    retrained_cfg = _config(dataset, "retrained", checkpoint=checkpoint)
    print(f"[START] {dataset}: rebuild module1 with benign-only checkpoint", flush=True)
    retrained_module1 = run_module1(retrained_cfg)
    retrained_bundle = _load_bundle(retrained_cfg.module1_dir)
    return {
        "dataset": dataset,
        "status": "completed",
        "frozen": baseline_result,
        "retrained": {
            "pretraining": manifest,
            "module1": {key: str(value) for key, value in retrained_module1.items()},
            "task_size": _task_size_summary(retrained_bundle),
            "evaluations": [_evaluate(retrained_cfg, retrained_module1, weight) for weight in (0.0, 0.4)],
        },
    }


def main() -> None:
    output_dir = REPO / "debug" / "remote_ops" / "out" / "tapas_native_lstm_retrain_topk_20260809"
    output_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for dataset in ("trace", "cadets", "theia"):
        try:
            records.append(_run_dataset(dataset))
        except Exception as exc:  # Keep later datasets runnable if one is unavailable.
            traceback.print_exc()
            records.append({"dataset": dataset, "status": "failed", "error": repr(exc)})
        (output_dir / "summary.json").write_text(
            json.dumps({"experiment": "tapas_native_lstm_retrain_topk_20260809", "records": records}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    print(json.dumps({"experiment": "tapas_native_lstm_retrain_topk_20260809", "records": records}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
